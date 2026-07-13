package requery

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/go-chi/chi/v5"
	"github.com/miekg/dns"
)

const (
	PluginType           = "requery"
	maxSchedulerDuration = time.Duration(1<<63 - 1)
)

// ----------------------------------------------------------------------------
// 1. Plugin Registration and Initialization
// ----------------------------------------------------------------------------

func init() {
	coremain.RegNewPluginFunc(PluginType, newRequery, func() any { return new(Args) })
}

// Args is the plugin's configuration arguments from the main YAML config.
type Args struct {
	File string `yaml:"file"` // Path to the requeryconfig.json file
}

// newRequery is the plugin's initialization function.
func newRequery(bp *coremain.BP, args any) (any, error) {
	cfg := args.(*Args)
	if cfg.File == "" {
		return nil, errors.New("requery: 'file' for config json must be specified")
	}

	dir := filepath.Dir(cfg.File)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("requery: failed to create directory %s: %w", dir, err)
	}

	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	p := &Requery{
		filePath:        cfg.File,
		httpClient:      &http.Client{Timeout: 30 * time.Second},
		lifecycleCtx:    lifecycleCtx,
		lifecycleCancel: lifecycleCancel,
		scheduleChanged: make(chan struct{}, 1),
		now:             time.Now,
		newTimer: func(delay time.Duration) schedulerTimer {
			return &realSchedulerTimer{Timer: time.NewTimer(delay)}
		},
	}
	p.taskRunner = p.runTask

	if err := p.loadConfig(); err != nil {
		lifecycleCancel()
		return nil, fmt.Errorf("requery: failed to load initial config from %s: %w", p.filePath, err)
	}

	// Resiliency check: If mosdns was stopped while a task was running, mark it as failed.
	p.mu.Lock()
	if p.config.Status.TaskState == "running" {
		log.Println("[requery] WARN: Found task in 'running' state on startup. Marking as 'failed'.")
		p.config.Status.TaskState = "failed"
		p.config.Status.LastRunEndTime = time.Now().UTC()
		_ = p.saveConfigUnlocked() // Attempt to save the updated state
	}
	p.mu.Unlock()

	p.startScheduler()
	log.Println("[requery] Scheduler started.")

	bp.RegAPI(p.api())

	log.Printf("[requery] plugin instance created for config file: %s", p.filePath)
	return p, nil
}

// ----------------------------------------------------------------------------
// 2. Main Plugin Struct and Configuration Structs
// ----------------------------------------------------------------------------

// Requery is the main struct for the plugin.
type Requery struct {
	mu         sync.RWMutex
	filePath   string
	config     *Config
	httpClient *http.Client
	taskRunner func(context.Context, requeryTaskConfig)
	now        func() time.Time
	newTimer   func(time.Duration) schedulerTimer

	lifecycleCtx       context.Context
	lifecycleCancel    context.CancelFunc
	scheduleChanged    chan struct{}
	scheduleGeneration uint64
	closed             bool
	taskRunning        bool
	taskCancel         context.CancelFunc

	wg        sync.WaitGroup
	closeOnce sync.Once
}

type schedulerTimer interface {
	Chan() <-chan time.Time
	Stop() bool
}

type realSchedulerTimer struct {
	*time.Timer
}

func (t *realSchedulerTimer) Chan() <-chan time.Time {
	return t.C
}

type requeryTaskConfig struct {
	domainProcessing  DomainProcessing
	urlActions        URLActions
	executionSettings ExecutionSettings
}

var (
	errRequeryClosed   = errors.New("requery is closed")
	errTaskRunning     = errors.New("a requery task is already running")
	errScheduleChanged = errors.New("requery schedule changed")
)

var _ io.Closer = (*Requery)(nil)

// Config maps directly to the requeryconfig.json file structure.
type Config struct {
	DomainProcessing  DomainProcessing  `json:"domain_processing"`
	URLActions        URLActions        `json:"url_actions"`
	Scheduler         SchedulerConfig   `json:"scheduler"`
	ExecutionSettings ExecutionSettings `json:"execution_settings"`
	Status            Status            `json:"status"`
}

type DomainProcessing struct {
	SourceFiles []SourceFile `json:"source_files"`
	// OutputFile 已删除
}

type SourceFile struct {
	Alias string `json:"alias"`
	Path  string `json:"path"`
}

type URLActions struct {
	SaveRules  []string `json:"save_rules"`
	FlushRules []string `json:"flush_rules"`
}

type SchedulerConfig struct {
	Enabled         bool   `json:"enabled"`
	StartDatetime   string `json:"start_datetime"` // ISO 8601 format
	IntervalMinutes int    `json:"interval_minutes"`
}

type ExecutionSettings struct {
	QueriesPerSecond int    `json:"queries_per_second"`
	ResolverAddress  string `json:"resolver_address"`
	URLCallDelayMS   int    `json:"url_call_delay_ms"`
	DateRangeDays    int    `json:"date_range_days"` // 新增配置项：日期范围
}

type Status struct {
	TaskState          string    `json:"task_state"` // "idle", "running", "failed", "cancelled"
	LastRunStartTime   time.Time `json:"last_run_start_time,omitempty"`
	LastRunEndTime     time.Time `json:"last_run_end_time,omitempty"`
	LastRunDomainCount int       `json:"last_run_domain_count"`
	Progress           Progress  `json:"progress"`
}

type Progress struct {
	Processed int64 `json:"processed"`
	Total     int64 `json:"total"`
}

func (p *Requery) taskConfigSnapshotLocked() requeryTaskConfig {
	return requeryTaskConfig{
		domainProcessing: DomainProcessing{
			SourceFiles: append([]SourceFile(nil), p.config.DomainProcessing.SourceFiles...),
		},
		urlActions: URLActions{
			SaveRules:  append([]string(nil), p.config.URLActions.SaveRules...),
			FlushRules: append([]string(nil), p.config.URLActions.FlushRules...),
		},
		executionSettings: p.config.ExecutionSettings,
	}
}

// startTask atomically claims the single task slot before launching a
// goroutine. expectedScheduleGeneration is nil for manual triggers.
func (p *Requery) startTask(expectedScheduleGeneration *uint64) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return errRequeryClosed
	}
	if expectedScheduleGeneration != nil {
		if *expectedScheduleGeneration != p.scheduleGeneration || !p.config.Scheduler.Enabled {
			p.mu.Unlock()
			return errScheduleChanged
		}
	}
	if p.taskRunning {
		p.mu.Unlock()
		return errTaskRunning
	}

	taskCtx, taskCancel := context.WithCancel(p.lifecycleCtx)
	taskCfg := p.taskConfigSnapshotLocked()
	runner := p.taskRunner
	if runner == nil {
		runner = p.runTask
	}

	p.taskRunning = true
	p.taskCancel = taskCancel
	p.config.Status.TaskState = "running"
	p.config.Status.LastRunStartTime = time.Now().UTC()
	p.config.Status.LastRunEndTime = time.Time{}
	p.config.Status.Progress.Processed = 0
	p.config.Status.Progress.Total = 0
	if err := p.saveConfigUnlocked(); err != nil {
		log.Printf("[requery] WARN: Failed to persist task start state: %v", err)
	}

	p.wg.Add(1)
	p.mu.Unlock()

	go func() {
		defer p.wg.Done()
		defer taskCancel()
		runner(taskCtx, taskCfg)
	}()
	return nil
}

// Close stops scheduling, cancels the active task, and waits until every
// requery-owned goroutine has exited. It is safe to call more than once.
func (p *Requery) Close() error {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.closed = true
		p.scheduleGeneration++
		taskCancel := p.taskCancel
		p.mu.Unlock()

		if p.lifecycleCancel != nil {
			p.lifecycleCancel()
		}
		if taskCancel != nil {
			taskCancel()
		}
		p.notifyScheduleChanged()
		p.wg.Wait()
		if p.httpClient != nil {
			p.httpClient.CloseIdleConnections()
		}
	})
	return nil
}

// ----------------------------------------------------------------------------
// 3. Core Task Workflow
// ----------------------------------------------------------------------------

// runTask executes the entire requery workflow. startTask owns the runtime
// lifecycle and guarantees that only one invocation can run at a time.
func (p *Requery) runTask(ctx context.Context, cfg requeryTaskConfig) {
	defer func() {
		recovered := recover()
		p.mu.Lock()

		if p.config.Status.TaskState == "running" {
			if ctx.Err() != nil {
				p.config.Status.TaskState = "cancelled"
			} else {
				p.config.Status.TaskState = "idle"
			}
		}

		if recovered != nil {
			log.Printf("[requery] FATAL: Task panicked: %v", recovered)
			p.config.Status.TaskState = "failed"
		}

		p.config.Status.LastRunEndTime = time.Now().UTC()
		_ = p.saveConfigUnlocked()

		p.taskCancel = nil
		p.taskRunning = false
		p.mu.Unlock()

		log.Println("[requery] Task finished, triggering background memory release...")
		coremain.ManualGC()
	}()

	log.Println("[requery] Starting a new task.")

	// Step 1: Save current rules
	log.Println("[requery] Step 1: Saving rules...")
	if err := p.callURLs(ctx, cfg.urlActions.SaveRules, cfg.executionSettings.URLCallDelayMS); err != nil {
		p.setTaskError(ctx, "failed during save_rules step", err)
		return
	}

	// Step 2 & 3: Consolidate domains (Merge only, no backup read/write)
	log.Println("[requery] Step 2 & 3: Merging domains from source files...")
	domains, err := p.mergeAndFilterDomains(ctx, cfg.domainProcessing.SourceFiles, cfg.executionSettings.DateRangeDays)
	if err != nil {
		p.setTaskError(ctx, "failed during domain merge", err)
		return
	}
	if len(domains) == 0 {
		log.Println("[requery] No domains found to process. Task finished.")
		return
	}

	// Step 4: Flush old rules
	log.Println("[requery] Step 4: Flushing old rules...")
	if err := p.callURLs(ctx, cfg.urlActions.FlushRules, cfg.executionSettings.URLCallDelayMS); err != nil {
		p.setTaskError(ctx, "failed during flush_rules step", err)
		return
	}

	// Update status with total domain count
	p.mu.Lock()
	p.config.Status.LastRunDomainCount = len(domains)
	p.config.Status.Progress.Total = int64(len(domains))
	p.mu.Unlock()

	// Step 6: Re-query domains
	log.Printf("[requery] Step 6: Re-querying %d domains...", len(domains))
	err = p.resendDNSQueries(ctx, domains, cfg.executionSettings)
	if err != nil {
		// The error (e.g., cancellation) is handled inside resendDNSQueries by setting the state.
		log.Printf("[requery] Task stopped during DNS query phase: %v", err)
		return
	}

	// Step 7 (Final): Save rules again after requery
	log.Println("[requery] Step 7: Performing final save of rules...")
	if err := p.callURLs(ctx, cfg.urlActions.SaveRules, cfg.executionSettings.URLCallDelayMS); err != nil {
		p.setTaskError(ctx, "failed during final save_rules step", err)
		return
	}

	log.Println("[requery] Task completed successfully.")
}

// mergeAndFilterDomains handles reading source files, parsing formats, and filtering by date.
// It no longer reads or writes the backup file.
func (p *Requery) mergeAndFilterDomains(ctx context.Context, sourceFiles []SourceFile, limitDays int) ([]string, error) {
	// 初始化域名集合，用于去重
	domainSet := make(map[string]struct{})

	// 准备正则：匹配 full: 开头
	domainPattern := regexp.MustCompile(`^full:(.+)`)

	// 获取日期过滤配置，默认为 30 天
	if limitDays <= 0 {
		limitDays = 30
	}

	processedCount := 0

	for _, sourceFile := range sourceFiles {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		file, err := os.Open(sourceFile.Path)
		if err != nil {
			if os.IsNotExist(err) {
				log.Printf("[requery] Source file not found, skipping: %s", sourceFile.Path)
				continue
			}
			return nil, fmt.Errorf("failed to open source file %s: %w", sourceFile.Path, err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}

			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			// 判断格式
			if strings.HasPrefix(line, "full:") {
				// 格式 1: full:moxie.foxnews.com
				matches := domainPattern.FindStringSubmatch(line)
				if len(matches) > 1 {
					domain := strings.TrimSpace(matches[1])
					domainSet[domain] = struct{}{}
				}
			} else if len(line) > 0 && line[0] >= '0' && line[0] <= '9' {
				// 格式 2: 0000000004 2025-12-18 moxie.foxnews.com (数字开头)
				// 解析字段：[0]=次数 [1]=日期 [2]=域名
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					dateStr := fields[1]
					domain := fields[2]

					// 检查日期是否过期
					parsedTime, err := time.Parse("2006-01-02", dateStr)
					if err == nil {
						// 计算距离今天有多少天
						// 如果 time.Since(parsedTime) > limitDays * 24h，则过期
						daysDiff := time.Since(parsedTime).Hours() / 24
						if daysDiff <= float64(limitDays) {
							domainSet[domain] = struct{}{}
						}
						// 如果超过天数，则忽略不加载
					} else {
						// 日期解析失败，保守起见如果不是合法日期则忽略，或者选择记录日志
						// 这里选择忽略该条目
					}
				}
			}
			processedCount++
		}

		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("error reading source file %s: %w", sourceFile.Path, err)
		}
	}

	log.Printf("[requery] Processed source files. Total unique domains loaded (within %d days): %d.", limitDays, len(domainSet))

	if len(domainSet) == 0 {
		return []string{}, nil
	}

	domains := make([]string, 0, len(domainSet))
	for domain := range domainSet {
		domains = append(domains, domain)
	}
	domainSet = nil
	// 此时不再写入 output_file (requery_backup.txt)

	return domains, nil
}

// resendDNSQueries handles step 6 of the workflow.
func (p *Requery) resendDNSQueries(ctx context.Context, domains []string, settings ExecutionSettings) error {
	var wg sync.WaitGroup
	// 确保 QueriesPerSecond 大于 0，防止除以零 panic
	qps := settings.QueriesPerSecond
	if qps <= 0 {
		qps = 100
	}
	ticker := time.NewTicker(time.Second / time.Duration(qps))
	defer ticker.Stop()

	dnsClient := new(dns.Client)
	// 设置超时，防止请求挂起
	dnsClient.Timeout = 2 * time.Second

	for i := 0; i < len(domains); i++ {
		rawDomainStr := domains[i] // 这里的字符串可能带后缀，也可能不带

		select {
		case <-ticker.C:
		case <-ctx.Done():
			wg.Wait()
			p.setCancelledState("task cancelled by user")
			return ctx.Err()
		}

		// --- 新增逻辑：解析域名和 Flags ---
		// 1. 分割字符串
		parts := strings.Split(rawDomainStr, "|")
		realDomain := parts[0] // 始终是域名部分

		// 2. 解析 Flags
		var useAD, useCD, useDO bool
		if len(parts) > 1 {
			for _, flag := range parts[1:] {
				switch flag {
				case "AD":
					useAD = true
				case "CD":
					useCD = true
				case "DO":
					useDO = true
				}
			}
		}

		// 3. 辅助函数：创建带正确 Flag 的消息
		createMsg := func(qtype uint16) *dns.Msg {
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(realDomain), qtype)

			// 还原原始请求的 Flags
			m.AuthenticatedData = useAD
			m.CheckingDisabled = useCD
			if useDO {
				m.SetEdns0(4096, true)
			}
			// 建议开启递归查询，模拟普通客户端行为
			m.RecursionDesired = true
			return m
		}
		// ----------------------------------

		wg.Add(2)

		// 发送 A 记录
		go func() {
			defer wg.Done()
			msg := createMsg(dns.TypeA)
			_, _, _ = dnsClient.ExchangeContext(ctx, msg, settings.ResolverAddress)
		}()

		// 发送 AAAA 记录
		go func() {
			defer wg.Done()
			msg := createMsg(dns.TypeAAAA)
			_, _, _ = dnsClient.ExchangeContext(ctx, msg, settings.ResolverAddress)
		}()

		newProcessed := int64(i + 1)
		p.mu.Lock()
		p.config.Status.Progress.Processed = newProcessed
		// 减少保存频率，优化 IO
		if newProcessed%100 == 0 || int(newProcessed) == len(domains) {
			_ = p.saveConfigUnlocked()
		}
		p.mu.Unlock()
	}

	wg.Wait()
	return nil
}

// ----------------------------------------------------------------------------
// 4. API Handlers
// ----------------------------------------------------------------------------

func (p *Requery) api() *chi.Mux {
	r := chi.NewRouter()

	r.Get("/", p.handleGetConfig)
	r.Get("/status", p.handleGetStatus)
	r.Post("/trigger", p.handleTriggerTask)
	r.Post("/cancel", p.handleCancelTask)
	r.Post("/scheduler/config", p.handleUpdateScheduler)
	r.Get("/stats/source_file_counts", p.handleGetSourceFileCounts)
	return r
}

func (p *Requery) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	p.jsonResponse(w, p.config, http.StatusOK)
}

func (p *Requery) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	p.jsonResponse(w, p.config.Status, http.StatusOK)
}

func (p *Requery) handleTriggerTask(w http.ResponseWriter, r *http.Request) {
	err := p.startTask(nil)
	switch {
	case errors.Is(err, errTaskRunning):
		p.jsonError(w, "A task is already running.", http.StatusConflict)
		return
	case errors.Is(err, errRequeryClosed):
		p.jsonError(w, "The requery plugin is shutting down.", http.StatusServiceUnavailable)
		return
	case err != nil:
		p.jsonError(w, "Failed to start task: "+err.Error(), http.StatusInternalServerError)
		return
	}

	p.jsonResponse(w, map[string]string{"status": "success", "message": "A new task has been started."}, http.StatusOK)
}

func (p *Requery) handleCancelTask(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	if !p.taskRunning || p.taskCancel == nil {
		p.mu.Unlock()
		p.jsonError(w, "No running task to cancel.", http.StatusNotFound)
		return
	}
	taskCancel := p.taskCancel
	p.mu.Unlock()

	taskCancel()
	log.Println("[requery] Task cancellation requested via API.")

	p.jsonResponse(w, map[string]string{"status": "success", "message": "Task cancellation initiated."}, http.StatusOK)
}

func (p *Requery) handleUpdateScheduler(w http.ResponseWriter, r *http.Request) {
	// [修改] 定义一个扩展的结构体来接收包含 date_range_days 的 JSON
	type SchedulerUpdatePayload struct {
		SchedulerConfig     // 嵌入原有的 SchedulerConfig 字段 (Enabled, StartDatetime, IntervalMinutes)
		DateRangeDays   int `json:"date_range_days"` // 新增字段
	}

	var payload SchedulerUpdatePayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		p.jsonError(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		p.jsonError(w, "The requery plugin is shutting down.", http.StatusServiceUnavailable)
		return
	}

	// [修改] 分别更新 Scheduler 和 ExecutionSettings
	oldScheduler := p.config.Scheduler
	oldDateRangeDays := p.config.ExecutionSettings.DateRangeDays
	p.config.Scheduler = payload.SchedulerConfig

	// 只有当传入了有效天数时才更新 (防止意外归零)
	if payload.DateRangeDays > 0 {
		p.config.ExecutionSettings.DateRangeDays = payload.DateRangeDays
	}

	if err := p.saveConfigUnlocked(); err != nil {
		p.config.Scheduler = oldScheduler
		p.config.ExecutionSettings.DateRangeDays = oldDateRangeDays
		p.mu.Unlock()
		p.jsonError(w, "Failed to save updated config", http.StatusInternalServerError)
		return
	}
	p.scheduleGeneration++
	p.mu.Unlock()
	p.notifyScheduleChanged()
	p.jsonResponse(w, map[string]string{"status": "success", "message": "Scheduler configuration updated successfully."}, http.StatusOK)
}

// [已删除] handleClearBackupFile
// [已删除] handleGetBackupFileCount

func (p *Requery) handleGetSourceFileCounts(w http.ResponseWriter, r *http.Request) {
	log.Println("[requery] API: Getting source file counts...")
	p.mu.RLock()
	saveRules := append([]string(nil), p.config.URLActions.SaveRules...)
	sourceFiles := append([]SourceFile(nil), p.config.DomainProcessing.SourceFiles...)
	urlCallDelayMS := p.config.ExecutionSettings.URLCallDelayMS
	p.mu.RUnlock()

	if err := p.callURLs(r.Context(), saveRules, urlCallDelayMS); err != nil {
		p.jsonError(w, "Failed to save rules before counting: "+err.Error(), http.StatusInternalServerError)
		return
	}

	type fileCount struct {
		Alias string `json:"alias"`
		Count int    `json:"count"`
	}

	counts := make([]fileCount, 0, len(sourceFiles))
	domainPattern := regexp.MustCompile(`^full:(.+)`)

	for _, sourceFile := range sourceFiles {
		count := 0
		file, err := os.Open(sourceFile.Path)
		if err != nil {
			if os.IsNotExist(err) {
				counts = append(counts, fileCount{Alias: sourceFile.Alias, Count: 0})
				continue
			}
			p.jsonError(w, "Failed to read source file "+sourceFile.Path+": "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if domainPattern.MatchString(scanner.Text()) {
				count++
			}
		}
		if err := scanner.Err(); err != nil {
			p.jsonError(w, "Error while scanning file "+sourceFile.Path+": "+err.Error(), http.StatusInternalServerError)
			return
		}
		counts = append(counts, fileCount{Alias: sourceFile.Alias, Count: count})
	}

	p.jsonResponse(w, map[string]any{"status": "success", "data": counts}, http.StatusOK)
}

// ----------------------------------------------------------------------------
// 5. Helper and Utility Functions
// ----------------------------------------------------------------------------

func (p *Requery) loadConfig() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	dataBytes, err := os.ReadFile(p.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[requery] config file %s not found, initializing with default empty config.", p.filePath)
			p.config = &Config{Status: Status{TaskState: "idle"}}
			// 设置默认值
			p.config.ExecutionSettings.DateRangeDays = 30
			return p.saveConfigUnlocked()
		}
		return err
	}

	var cfg Config
	if err := json.Unmarshal(dataBytes, &cfg); err != nil {
		return fmt.Errorf("failed to parse json from config file %s: %w", p.filePath, err)
	}
	p.config = &cfg

	// 检查并设置默认值，如果有变更则需要回写配置
	configChanged := false

	if p.config.Status.TaskState == "" {
		p.config.Status.TaskState = "idle"
		configChanged = true // 严格来说这只是内存状态修正，但也可以保存
	}
	if p.config.ExecutionSettings.URLCallDelayMS == 0 {
		p.config.ExecutionSettings.URLCallDelayMS = 50 // Default value
		configChanged = true
	}
	if p.config.ExecutionSettings.QueriesPerSecond == 0 {
		p.config.ExecutionSettings.QueriesPerSecond = 100 // Default value
		configChanged = true
	}
	if p.config.ExecutionSettings.DateRangeDays <= 0 {
		p.config.ExecutionSettings.DateRangeDays = 30 // Default value (Requirement 4)
		configChanged = true
	}

	if configChanged {
		log.Println("[requery] Configuration defaults applied, saving updated config.")
		if err := p.saveConfigUnlocked(); err != nil {
			return fmt.Errorf("failed to save config after applying defaults: %w", err)
		}
	}

	return nil
}

func (p *Requery) saveConfigUnlocked() error {
	dataBytes, err := json.MarshalIndent(p.config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config to json: %w", err)
	}

	tmpFile := p.filePath + ".tmp"
	if err := os.WriteFile(tmpFile, dataBytes, 0644); err != nil {
		return fmt.Errorf("failed to write to temporary config file: %w", err)
	}
	if err := os.Rename(tmpFile, p.filePath); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to rename temporary config file: %w", err)
	}

	return nil
}

func (p *Requery) startScheduler() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.wg.Add(1)
	p.mu.Unlock()

	go func() {
		defer p.wg.Done()
		p.schedulerLoop()
	}()
}

func (p *Requery) notifyScheduleChanged() {
	select {
	case p.scheduleChanged <- struct{}{}:
	default:
	}
}

func (p *Requery) schedulerSnapshot() (SchedulerConfig, uint64, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.config.Scheduler, p.scheduleGeneration, p.closed
}

func nextScheduledRun(now time.Time, cfg SchedulerConfig) (time.Time, bool, error) {
	if !cfg.Enabled || cfg.IntervalMinutes <= 0 {
		return time.Time{}, false, nil
	}
	if cfg.StartDatetime == "" {
		return time.Time{}, false, errors.New("start_datetime is required when scheduler is enabled")
	}

	startTime, err := time.Parse(time.RFC3339, cfg.StartDatetime)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("invalid start_datetime %q: %w", cfg.StartDatetime, err)
	}
	if int64(cfg.IntervalMinutes) > int64(maxSchedulerDuration/time.Minute) {
		return time.Time{}, false, errors.New("interval_minutes is too large")
	}
	if startTime.After(now) {
		return startTime, true, nil
	}
	if startTime.Before(now.Add(-maxSchedulerDuration)) {
		return time.Time{}, false, errors.New("start_datetime is too far in the past")
	}

	interval := time.Duration(cfg.IntervalMinutes) * time.Minute
	elapsed := now.Sub(startTime)
	remainder := elapsed % interval
	return now.Add(interval - remainder), true, nil
}

func stopAndDrainTimer(timer schedulerTimer) {
	if timer == nil || timer.Stop() {
		return
	}
	select {
	case <-timer.Chan():
	default:
	}
}

// schedulerLoop is the sole owner of the scheduling timer. Configuration
// changes wake this loop, stop the old timer, and build exactly one new timer.
func (p *Requery) schedulerLoop() {
	for {
		cfg, generation, closed := p.schedulerSnapshot()
		if closed {
			return
		}

		now := p.now()
		nextRun, enabled, err := nextScheduledRun(now, cfg)
		if err != nil {
			log.Printf("[requery] WARN: Scheduler is not active: %v", err)
		}
		if err != nil || !enabled {
			select {
			case <-p.lifecycleCtx.Done():
				return
			case <-p.scheduleChanged:
				continue
			}
		}

		delay := nextRun.Sub(now)
		if delay < 0 {
			delay = 0
		}
		log.Printf("[requery] Next scheduled run will be at %v (in %v).", nextRun.Local(), delay.Round(time.Second))
		timer := p.newTimer(delay)

		select {
		case <-p.lifecycleCtx.Done():
			stopAndDrainTimer(timer)
			return
		case <-p.scheduleChanged:
			stopAndDrainTimer(timer)
			continue
		case <-timer.Chan():
			err := p.startTask(&generation)
			switch {
			case err == nil:
				log.Println("[requery] Scheduler triggered a task.")
			case errors.Is(err, errTaskRunning):
				log.Println("[requery] Scheduler skipped: previous task is still running.")
			case errors.Is(err, errScheduleChanged):
				log.Println("[requery] Scheduler ignored an obsolete timer.")
			case errors.Is(err, errRequeryClosed):
				return
			default:
				log.Printf("[requery] WARN: Scheduler failed to start task: %v", err)
			}
		}
	}
}

func (p *Requery) callURLs(ctx context.Context, urls []string, delayMS int) error {
	delay := time.Duration(delayMS) * time.Millisecond
	for i, url := range urls {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return fmt.Errorf("failed to create request for %s: %w", url, err)
		}

		resp, err := p.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to call URL %s: %w", url, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("bad response from URL %s: status %d, body: %s", url, resp.StatusCode, string(body))
		}

		_, _ = io.Copy(io.Discard, resp.Body)

		if i < len(urls)-1 {
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return nil
}

func (p *Requery) setFailedState(format string, args ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config.Status.TaskState = "failed"
	log.Printf("[requery] ERROR: Task failed: "+format, args...)
}

func (p *Requery) setTaskError(ctx context.Context, step string, err error) {
	if ctx.Err() != nil {
		p.setCancelledState(step + ": " + ctx.Err().Error())
		return
	}
	p.setFailedState("%s: %v", step, err)
}

func (p *Requery) setCancelledState(reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config.Status.TaskState = "cancelled"
	log.Println("[requery] INFO: Task cancelled:", reason)
}

func (p *Requery) jsonResponse(w http.ResponseWriter, data any, code int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("[requery] ERROR: failed to encode response: %v", err)
	}
}

func (p *Requery) jsonError(w http.ResponseWriter, message string, code int) {
	p.jsonResponse(w, map[string]string{"status": "error", "message": message}, code)
}
