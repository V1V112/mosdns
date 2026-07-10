package cache

import (
	"bytes"
	"container/heap"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/maphash"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe" // 性能补丁引入，用于零拷贝极速匹配

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/cache"
	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
	domain_set "github.com/IrineSistiana/mosdns/v5/plugin/data_provider/domain_set"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/go-chi/chi/v5"
	"github.com/klauspost/compress/gzip"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"golang.org/x/exp/constraints"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"
)

const (
	PluginType = "cache"
)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
	sequence.MustRegExecQuickSetup(PluginType, quickSetupCache)
}

const (
	defaultLazyUpdateTimeout = time.Second * 5
	expiredMsgTtl            = 5

	minimumChangesToDump   = 1024
	dumpHeader             = "mosdns_cache_v3"
	dumpBlockSize          = 128
	dumpMaximumBlockLength = 1 << 20 // 1M block. 8kb pre entry. Should be enough.
	dumpMaximumTotalLength = 256 << 20

	shardCount   = 256   // 256分段锁，平衡锁竞争与内存开销
	l1TotalCap   = 51200 // L1 总容量限制
	shardMaxSize = 200   // 每个分段桶的配额 (51200/shardCount)

	// 后台异步任务池参数
	maxConcurrentLazyUpdate = 256
	lazyTaskQueueCapacity   = 8192

	defaultActiveRefreshThreshold      = 60
	defaultActiveRefreshInterval       = 30
	defaultActiveRefreshRequeryTimeout = 5000
	defaultActiveRefreshWorkers        = 16
	defaultActiveRefreshMaxScan        = 256
	defaultActiveRefreshMaxIdleTime    = 3600
	defaultActiveRefreshMinInterval    = 30
	defaultFallbackProbeTimeout        = 60
	defaultFallbackProbeStaleExtendTTL = 60
	defaultFallbackProbeMaxStale       = 300
	activeRefreshTaskQueueCapacity     = 4096
	maxActiveRefreshWorkers            = 256
)

const (
	adBit = 1 << iota
	cdBit
	doBit
	rdBit
)

var _ sequence.RecursiveExecutable = (*Cache)(nil)

// keyBufferPool 用于复用生成 Key 时的字节缓冲区，显著降低内存分配压力
var keyBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 256)
		return &b
	},
}

// 复用 dns.Msg 对象用于 Unpack 解包过程
var dnsMsgPool = sync.Pool{
	New: func() any {
		return new(dns.Msg)
	},
}

type key string

var seed = maphash.MakeSeed()

func (k key) Sum() uint64 {
	return maphash.String(seed, string(k))
}

type item struct {
	resp           []byte
	storedTime     time.Time
	expirationTime time.Time
	lazyDeadline   time.Time
	domainSet      string
	upstreamOpt    *dns.OPT
	staleDeadline  time.Time
	isStale        bool
	isTransient    bool
}

type l1Item struct {
	msg            *dns.Msg
	storedTime     time.Time
	expirationTime time.Time
	domainSet      string
	upstreamOpt    *dns.OPT
	source         *item
}

type l1Shard struct {
	sync.RWMutex
	items map[key]*l1Item
	order []key
	pos   int
	ref   map[key]bool
}

type ActiveRefreshDomainArgs struct {
	Exps       []string `yaml:"exps"`
	DomainSets []string `yaml:"domain_sets"`
	Files      []string `yaml:"files"`
}

type FallbackProbeArgs struct {
	Enabled        bool     `yaml:"enabled"`
	TimeoutMS      int      `yaml:"timeout_ms"`
	StaleExtendTTL int      `yaml:"stale_extend_ttl"`
	MaxStale       int      `yaml:"max_stale"`
	Probes         []string `yaml:"probes"`
}

type fallbackProbeArgsRaw struct {
	Enabled        bool        `yaml:"enabled"`
	TimeoutMS      int         `yaml:"timeout_ms"`
	StaleExtendTTL int         `yaml:"stale_extend_ttl"`
	MaxStale       int         `yaml:"max_stale"`
	Probes         interface{} `yaml:"probes"`
}

func (a *FallbackProbeArgs) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		var enabled bool
		if err := node.Decode(&enabled); err != nil {
			return err
		}
		a.Enabled = enabled
		return nil
	}

	var raw fallbackProbeArgsRaw
	if err := node.Decode(&raw); err != nil {
		return err
	}
	a.Enabled = raw.Enabled
	a.TimeoutMS = raw.TimeoutMS
	a.StaleExtendTTL = raw.StaleExtendTTL
	a.MaxStale = raw.MaxStale

	probes, err := stringListFromRaw(raw.Probes, "active_refresh.fallback_probe.probes")
	if err != nil {
		return err
	}
	a.Probes = probes
	return nil
}

type ActiveRefreshArgs struct {
	Enabled            bool                    `yaml:"enabled"`
	RefreshSequence    string                  `yaml:"refresh_sequence"`
	Threshold          int                     `yaml:"threshold"`
	Interval           int                     `yaml:"interval"`
	RequeryTimeoutMS   int                     `yaml:"requery_timeout_ms"`
	Workers            int                     `yaml:"workers"`
	MaxEntriesPerScan  int                     `yaml:"max_entries_per_scan"`
	MaxRefreshTimes    int                     `yaml:"max_refresh_times"`
	MaxIdleTime        int                     `yaml:"max_idle_time"`
	MinRefreshInterval int                     `yaml:"min_refresh_interval"`
	ExcludeIPs         []string                `yaml:"exclude_ip"`
	ExcludeDomain      ActiveRefreshDomainArgs `yaml:"exclude_domain"`
	FallbackProbe      FallbackProbeArgs       `yaml:"fallback_probe"`
}

type activeRefreshArgsRaw struct {
	Enabled            bool                    `yaml:"enabled"`
	RefreshSequence    string                  `yaml:"refresh_sequence"`
	Threshold          int                     `yaml:"threshold"`
	Interval           int                     `yaml:"interval"`
	RequeryTimeoutMS   int                     `yaml:"requery_timeout_ms"`
	Workers            int                     `yaml:"workers"`
	MaxEntriesPerScan  int                     `yaml:"max_entries_per_scan"`
	MaxRefreshTimes    int                     `yaml:"max_refresh_times"`
	MaxIdleTime        int                     `yaml:"max_idle_time"`
	MinRefreshInterval int                     `yaml:"min_refresh_interval"`
	ExcludeIP          interface{}             `yaml:"exclude_ip"`
	ExcludeDomain      ActiveRefreshDomainArgs `yaml:"exclude_domain"`
	FallbackProbe      FallbackProbeArgs       `yaml:"fallback_probe"`
}

func (a *ActiveRefreshArgs) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		var enabled bool
		if err := node.Decode(&enabled); err != nil {
			return err
		}
		a.Enabled = enabled
		return nil
	}

	var raw activeRefreshArgsRaw
	if err := node.Decode(&raw); err != nil {
		return err
	}
	a.Enabled = raw.Enabled
	a.RefreshSequence = raw.RefreshSequence
	a.Threshold = raw.Threshold
	a.Interval = raw.Interval
	a.RequeryTimeoutMS = raw.RequeryTimeoutMS
	a.Workers = raw.Workers
	a.MaxEntriesPerScan = raw.MaxEntriesPerScan
	a.MaxRefreshTimes = raw.MaxRefreshTimes
	a.MaxIdleTime = raw.MaxIdleTime
	a.MinRefreshInterval = raw.MinRefreshInterval
	a.ExcludeDomain = raw.ExcludeDomain
	a.FallbackProbe = raw.FallbackProbe

	excludeIPs, err := stringListFromRaw(raw.ExcludeIP, "active_refresh.exclude_ip")
	if err != nil {
		return err
	}
	a.ExcludeIPs = excludeIPs
	return nil
}

type Args struct {
	Size          int               `yaml:"size"`
	LazyCacheTTL  int               `yaml:"lazy_cache_ttl"`
	EnableECS     bool              `yaml:"enable_ecs"`
	ExcludeIPs    []string          `yaml:"exclude_ip"`
	DumpFile      string            `yaml:"dump_file"`
	DumpInterval  int               `yaml:"dump_interval"`
	ActiveRefresh ActiveRefreshArgs `yaml:"active_refresh"`
}

type argsRaw struct {
	Size          int               `yaml:"size"`
	LazyCacheTTL  int               `yaml:"lazy_cache_ttl"`
	EnableECS     bool              `yaml:"enable_ecs"`
	ExcludeIP     interface{}       `yaml:"exclude_ip"`
	DumpFile      string            `yaml:"dump_file"`
	DumpInterval  int               `yaml:"dump_interval"`
	ActiveRefresh ActiveRefreshArgs `yaml:"active_refresh"`
}

func (a *Args) UnmarshalYAML(node *yaml.Node) error {
	var raw argsRaw
	if err := node.Decode(&raw); err != nil {
		return err
	}
	a.Size = raw.Size
	a.LazyCacheTTL = raw.LazyCacheTTL
	a.DumpFile = raw.DumpFile
	a.DumpInterval = raw.DumpInterval
	a.EnableECS = raw.EnableECS
	a.ActiveRefresh = raw.ActiveRefresh

	switch v := raw.ExcludeIP.(type) {
	case string:
		a.ExcludeIPs = strings.Fields(v)
	case []interface{}:
		for _, x := range v {
			if s, ok := x.(string); ok {
				a.ExcludeIPs = append(a.ExcludeIPs, s)
			} else {
				return fmt.Errorf("exclude_ip list contains non-string: %#v", x)
			}
		}
	case nil:
	default:
		return fmt.Errorf("exclude_ip must be string or list, got %T", v)
	}
	return nil
}

func (a *Args) init() {
	utils.SetDefaultUnsignNum(&a.Size, 1024)
	utils.SetDefaultUnsignNum(&a.DumpInterval, 600)
	a.ActiveRefresh.init()
}

func (a *ActiveRefreshArgs) init() {
	utils.SetDefaultUnsignNum(&a.Threshold, defaultActiveRefreshThreshold)
	utils.SetDefaultUnsignNum(&a.Interval, defaultActiveRefreshInterval)
	utils.SetDefaultUnsignNum(&a.RequeryTimeoutMS, defaultActiveRefreshRequeryTimeout)
	utils.SetDefaultUnsignNum(&a.Workers, defaultActiveRefreshWorkers)
	utils.SetDefaultUnsignNum(&a.MaxEntriesPerScan, defaultActiveRefreshMaxScan)
	utils.SetDefaultUnsignNum(&a.MaxIdleTime, defaultActiveRefreshMaxIdleTime)
	utils.SetDefaultUnsignNum(&a.MinRefreshInterval, defaultActiveRefreshMinInterval)
	a.FallbackProbe.init()
}

func (a *FallbackProbeArgs) init() {
	utils.SetDefaultUnsignNum(&a.TimeoutMS, defaultFallbackProbeTimeout)
	utils.SetDefaultUnsignNum(&a.StaleExtendTTL, defaultFallbackProbeStaleExtendTTL)
	utils.SetDefaultUnsignNum(&a.MaxStale, defaultFallbackProbeMaxStale)
	if len(a.Probes) == 0 {
		a.Probes = []string{"tcp:443", "tcp:80", "ping"}
	}
}

// 异步任务对象
type lazyTask struct {
	k        key
	qCtx     *query_context.Context
	next     sequence.ChainWalker
	expected *item
	epoch    uint64
	flight   refreshFlightKey
}

type activeRefreshTask struct {
	k        key
	qCtx     *query_context.Context
	next     sequence.ChainWalker
	expected *item
	epoch    uint64
	flight   refreshFlightKey
}

type activeRefreshMeta struct {
	k            key
	qCtx         *query_context.Context
	next         sequence.ChainWalker
	expected     *item
	lastAccess   atomic.Int64
	refreshCount atomic.Int64
	refreshAt    time.Time
	due          time.Time
	heapIndex    int
	stopped      atomic.Bool
}

type activeRefreshHeap []*activeRefreshMeta

func (h activeRefreshHeap) Len() int           { return len(h) }
func (h activeRefreshHeap) Less(i, j int) bool { return h[i].due.Before(h[j].due) }
func (h activeRefreshHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].heapIndex = i
	h[j].heapIndex = j
}
func (h *activeRefreshHeap) Push(x any) {
	m := x.(*activeRefreshMeta)
	m.heapIndex = len(*h)
	*h = append(*h, m)
}
func (h *activeRefreshHeap) Pop() any {
	old := *h
	n := len(old)
	m := old[n-1]
	old[n-1] = nil
	m.heapIndex = -1
	*h = old[:n-1]
	return m
}

type refreshFlightKey struct {
	k     key
	epoch uint64
}

type preparedCacheEntry struct {
	item            *item
	cacheExpiration time.Time
	msg             *dns.Msg
}

type decodedDumpEntry struct {
	k               key
	item            *item
	cacheExpiration time.Time
}

type Cache struct {
	args         *Args
	logger       *zap.Logger
	backend      *cache.Cache[key, *item]
	closeOnce    sync.Once
	closeNotify  chan struct{}
	lifecycleCtx context.Context
	cancel       context.CancelFunc
	updatedKey   atomic.Uint64
	refreshEpoch atomic.Uint64
	flushMu      sync.RWMutex
	commitLocks  [shardCount]sync.Mutex

	shards     [shardCount]*l1Shard
	dumpMu     sync.Mutex
	dumpLoopWG sync.WaitGroup

	queryTotal    prometheus.Counter
	hitTotal      prometheus.Counter
	lazyHitTotal  prometheus.Counter
	lazyDropTotal prometheus.Counter // 任务丢弃指标
	size          prometheus.GaugeFunc

	activeRefreshTotal          prometheus.Counter
	activeRefreshSuccessTotal   prometheus.Counter
	activeRefreshFailedTotal    prometheus.Counter
	activeRefreshProbeTotal     prometheus.Counter
	activeRefreshProbeKeepTotal prometheus.Counter
	activeRefreshDropTotal      prometheus.Counter
	activeRefreshDuration       prometheus.Histogram
	activeRefreshQueueSize      prometheus.GaugeFunc
	activeRefreshMetaSize       prometheus.GaugeFunc

	excludeNets                []*net.IPNet
	activeExcludeNets          []*net.IPNet
	activeExcludeDomainMatcher domain.Matcher[struct{}]
	activeExcludeDomainArgs    ActiveRefreshDomainArgs
	activeExcludeDomainBQ      sequence.BQ
	activeExcludeDomainValid   bool
	activeRefreshExec          sequence.Executable
	activeRefreshConfigValid   bool

	// 异步更新架构优化
	refreshInFlight sync.Map       // active/lazy 共用的按 key、epoch 去重字典
	lazyTaskChan    chan *lazyTask // 工作队列
	lazyWorkers     sync.WaitGroup // 优雅退出等待控制
	activeMu        sync.RWMutex
	activeMeta      map[key]*activeRefreshMeta
	activeHeap      activeRefreshHeap
	activeWake      chan struct{}
	activeTaskChan  chan *activeRefreshTask
	activeWorkers   sync.WaitGroup
}

type Opts struct {
	Logger                     *zap.Logger
	MetricsTag                 string
	BQ                         sequence.BQ
	ActiveExcludeDomainMatcher domain.Matcher[struct{}]
}

func Init(bp *coremain.BP, args any) (any, error) {
	cfg := args.(*Args)
	bq := sequence.NewBQ(bp.M(), bp.L())
	c := NewCache(cfg, Opts{
		Logger:     bp.L(),
		MetricsTag: bp.Tag(),
		BQ:         bq,
	})
	if cfg.ActiveRefresh.Enabled && !c.activeRefreshConfigValid {
		_ = c.Close()
		return nil, fmt.Errorf("invalid active_refresh configuration")
	}

	if err := c.RegMetricsTo(prometheus.WrapRegistererWithPrefix(PluginType+"_", bp.M().GetMetricsReg())); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("failed to register metrics, %w", err)
	}
	bp.RegAPI(c.Api())
	return c, nil
}

func quickSetupCache(bq sequence.BQ, s string) (any, error) {
	size := 0
	if len(s) > 0 {
		i, err := strconv.Atoi(s)
		if err != nil {
			return nil, fmt.Errorf("invalid size, %w", err)
		}
		size = i
	}
	return NewCache(&Args{Size: size}, Opts{Logger: bq.L(), BQ: bq}), nil
}

func NewCache(args *Args, opts Opts) *Cache {
	args.init()
	lifecycleCtx, cancel := context.WithCancel(context.Background())

	logger := opts.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	if args.ActiveRefresh.FallbackProbe.Enabled {
		validProbes := args.ActiveRefresh.FallbackProbe.Probes[:0]
		for _, probe := range args.ActiveRefresh.FallbackProbe.Probes {
			if probe == "ping" {
				validProbes = append(validProbes, probe)
				continue
			}
			if strings.HasPrefix(probe, "tcp:") {
				port, err := strconv.Atoi(strings.TrimPrefix(probe, "tcp:"))
				if err == nil && port >= 1 && port <= 65535 {
					validProbes = append(validProbes, probe)
					continue
				}
			}
			logger.Warn("invalid active_refresh fallback probe, skip", zap.String("probe", probe))
		}
		args.ActiveRefresh.FallbackProbe.Probes = validProbes
		if len(validProbes) == 0 {
			args.ActiveRefresh.FallbackProbe.Enabled = false
			logger.Warn("active_refresh fallback probe disabled because no valid probes remain")
		}
	}

	var excludeNets []*net.IPNet
	for _, cidr := range args.ExcludeIPs {
		ipnet, err := parseIPNet(cidr)
		if err != nil {
			logger.Warn("invalid exclude_ip, skip", zap.String("cidr", cidr), zap.Error(err))
			continue
		}
		excludeNets = append(excludeNets, ipnet)
	}

	var activeExcludeNets []*net.IPNet
	for _, cidr := range args.ActiveRefresh.ExcludeIPs {
		ipnet, err := parseIPNet(cidr)
		if err != nil {
			logger.Warn("invalid active_refresh.exclude_ip, skip", zap.String("cidr", cidr), zap.Error(err))
			continue
		}
		activeExcludeNets = append(activeExcludeNets, ipnet)
	}

	activeExcludeDomainMatcher := opts.ActiveExcludeDomainMatcher

	backend := cache.New[key, *item](cache.Opts{Size: args.Size})
	lb := map[string]string{"tag": opts.MetricsTag}
	p := &Cache{
		args:                       args,
		logger:                     logger,
		backend:                    backend,
		closeNotify:                make(chan struct{}),
		lifecycleCtx:               lifecycleCtx,
		cancel:                     cancel,
		excludeNets:                excludeNets,
		activeExcludeNets:          activeExcludeNets,
		activeExcludeDomainMatcher: activeExcludeDomainMatcher,
		activeExcludeDomainArgs:    args.ActiveRefresh.ExcludeDomain,
		activeExcludeDomainBQ:      opts.BQ,
		activeExcludeDomainValid:   true,
		activeRefreshConfigValid:   true,
		lazyTaskChan:               make(chan *lazyTask, lazyTaskQueueCapacity),
		activeMeta:                 make(map[key]*activeRefreshMeta),
		activeWake:                 make(chan struct{}, 1),

		queryTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:        "query_total",
			Help:        "The total number of processed queries",
			ConstLabels: lb,
		}),
		hitTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:        "hit_total",
			Help:        "The total number of queries that hit the cache",
			ConstLabels: lb,
		}),
		lazyHitTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:        "lazy_hit_total",
			Help:        "The total number of queries that hit the expired cache",
			ConstLabels: lb,
		}),
		lazyDropTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:        "lazy_drop_total",
			Help:        "The total number of dropped lazy update tasks",
			ConstLabels: lb,
		}),
		activeRefreshTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:        "active_refresh_total",
			Help:        "The total number of active refresh attempts",
			ConstLabels: lb,
		}),
		activeRefreshSuccessTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:        "active_refresh_success_total",
			Help:        "The total number of successful active DNS refreshes",
			ConstLabels: lb,
		}),
		activeRefreshFailedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:        "active_refresh_failed_total",
			Help:        "The total number of failed active refresh attempts",
			ConstLabels: lb,
		}),
		activeRefreshProbeTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:        "active_refresh_probe_total",
			Help:        "The total number of fallback probe attempts",
			ConstLabels: lb,
		}),
		activeRefreshProbeKeepTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:        "active_refresh_probe_keepalive_total",
			Help:        "The total number of fallback probe keepalive updates",
			ConstLabels: lb,
		}),
		activeRefreshDropTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:        "active_refresh_drop_total",
			Help:        "The total number of dropped active refresh tasks",
			ConstLabels: lb,
		}),
		activeRefreshDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:        "active_refresh_duration_seconds",
			Help:        "Duration of active refresh attempts",
			ConstLabels: lb,
			Buckets:     prometheus.DefBuckets,
		}),
		size: prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name:        "size_current",
			Help:        "Current cache size in records",
			ConstLabels: lb,
		}, func() float64 {
			return float64(backend.Len())
		}),
	}

	for i := 0; i < shardCount; i++ {
		p.shards[i] = &l1Shard{
			items: make(map[key]*l1Item, shardMaxSize),
			order: make([]key, shardMaxSize),
			ref:   make(map[key]bool, shardMaxSize),
		}
	}

	// 启动异步任务池
	if args.ActiveRefresh.Enabled {
		p.activeTaskChan = make(chan *activeRefreshTask, activeRefreshTaskQueueCapacity)
		if p.activeExcludeDomainMatcher == nil {
			matcher, err := buildActiveExcludeDomainMatcher(p.activeExcludeDomainBQ, p.activeExcludeDomainArgs)
			if err != nil {
				p.activeExcludeDomainValid = false
				p.activeRefreshConfigValid = false
				p.logger.Warn("invalid active_refresh.exclude_domain, active refresh disabled for safety", zap.Error(err))
			} else {
				p.activeExcludeDomainMatcher = matcher
			}
		}
		if tag := strings.TrimSpace(args.ActiveRefresh.RefreshSequence); tag != "" {
			if opts.BQ == nil || opts.BQ.M() == nil {
				p.activeRefreshConfigValid = false
				p.logger.Warn("active_refresh.refresh_sequence requires mosdns context", zap.String("tag", tag))
			} else if execPlugin, ok := opts.BQ.M().GetPlugin(tag).(sequence.Executable); !ok || execPlugin == nil {
				p.activeRefreshConfigValid = false
				p.logger.Warn("active_refresh.refresh_sequence is not executable", zap.String("tag", tag))
			} else {
				p.activeRefreshExec = execPlugin
			}
		}
	}
	p.activeRefreshQueueSize = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "active_refresh_queue_size", Help: "Current number of queued active refresh tasks", ConstLabels: lb,
	}, func() float64 {
		if p.activeTaskChan == nil {
			return 0
		}
		return float64(len(p.activeTaskChan))
	})
	p.activeRefreshMetaSize = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "active_refresh_meta_size", Help: "Current number of tracked active refresh entries", ConstLabels: lb,
	}, func() float64 {
		p.activeMu.RLock()
		defer p.activeMu.RUnlock()
		return float64(len(p.activeMeta))
	})

	if args.LazyCacheTTL > 0 {
		p.startWorkerPool()
	}

	if err := p.loadDump(); err != nil {
		p.logger.Error("failed to load cache dump", zap.Error(err))
	}
	p.startDumpLoop()
	p.startActiveRefresh()

	return p
}

// 架构优化：去除内部的 msg.Copy()，改为外部拷贝后传入，极大降低持锁时间
func (s *l1Shard) updateL1(k key, msg *dns.Msg, source *item) {
	if source == nil {
		return
	}
	s.Lock()
	defer s.Unlock()

	if _, ok := s.items[k]; ok {
		s.items[k] = &l1Item{
			msg: msg, storedTime: source.storedTime, expirationTime: source.expirationTime,
			domainSet: source.domainSet, upstreamOpt: copyOPT(source.upstreamOpt), source: source,
		}
		s.ref[k] = true
		return
	}

	for {
		oldKey := s.order[s.pos]
		if oldKey == "" {
			break
		}
		if s.ref[oldKey] {
			s.ref[oldKey] = false
			s.pos = (s.pos + 1) % shardMaxSize
			continue
		}
		delete(s.items, oldKey)
		delete(s.ref, oldKey)
		break
	}

	s.items[k] = &l1Item{
		msg: msg, storedTime: source.storedTime, expirationTime: source.expirationTime,
		domainSet: source.domainSet, upstreamOpt: copyOPT(source.upstreamOpt), source: source,
	}
	s.order[s.pos] = k
	s.ref[k] = true
	s.pos = (s.pos + 1) % shardMaxSize
}

func (c *Cache) containsExcluded(msg *dns.Msg) bool {
	if len(c.excludeNets) == 0 {
		return false
	}
	for _, rr := range msg.Answer {
		var ip net.IP
		switch rr := rr.(type) {
		case *dns.A:
			ip = rr.A
		case *dns.AAAA:
			ip = rr.AAAA
		default:
			continue
		}
		for _, net := range c.excludeNets {
			if net.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func (c *Cache) RegMetricsTo(r prometheus.Registerer) error {
	for _, collector := range [...]prometheus.Collector{
		c.queryTotal,
		c.hitTotal,
		c.lazyHitTotal,
		c.lazyDropTotal,
		c.activeRefreshTotal,
		c.activeRefreshSuccessTotal,
		c.activeRefreshFailedTotal,
		c.activeRefreshProbeTotal,
		c.activeRefreshProbeKeepTotal,
		c.activeRefreshDropTotal,
		c.activeRefreshDuration,
		c.activeRefreshQueueSize,
		c.activeRefreshMetaSize,
		c.size,
	} {
		if err := r.Register(collector); err != nil {
			return err
		}
	}
	return nil
}

func (c *Cache) Exec(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) error {
	c.queryTotal.Inc()
	q := qCtx.Q()

	msgKeyBuf, bufPtr := getMsgKeyBytes(q, qCtx, c.args.EnableECS)
	if msgKeyBuf == nil {
		return next.ExecNext(ctx, qCtx)
	}

	// 保留极客优化：利用 unsafe 转换进行零拷贝 Lookup，规避 string 内存分配
	kStr := *(*string)(unsafe.Pointer(&msgKeyBuf))
	k := key(kStr)

	h := k.Sum()
	shard := c.shards[h%shardCount]

	// --- L1 极速热路径 ---
	shard.RLock()
	v1, ok1 := shard.items[k]
	shard.RUnlock()

	now := time.Now()
	if ok1 && now.Before(v1.expirationTime) {
		c.hitTotal.Inc()
		c.observeActiveRefresh(k, v1.source, qCtx, next, now, v1.msg)
		r := v1.msg.Copy() // 从 L1 提取时执行 Copy，保护缓存稳定
		dnsutils.SubtractTTL(r, uint32(now.Sub(v1.storedTime).Seconds()))
		r.Id = q.Id
		qCtx.SetResponse(r)
		if v1.upstreamOpt != nil {
			qCtx.SetUpstreamOpt(v1.upstreamOpt)
		}
		if v1.domainSet != "" {
			qCtx.StoreValue(query_context.KeyDomainSet, v1.domainSet)
		}

		// 极速路径 0 逃逸：归还底层切片至对象池
		keyBufferPool.Put(bufPtr)
		return nil
	}

	// L1 未命中或过期，执行安全的深拷贝生成持久化 Key
	msgKey := string(msgKeyBuf)
	kReal := key(msgKey)
	keyBufferPool.Put(bufPtr) // 拷贝完成后安全归还

	// --- L2 深度路径 ---
	c.flushMu.RLock()
	observedEpoch := c.refreshEpoch.Load()
	cachedResp, lazyHit, cachedItem := getRespFromCache(msgKey, c.backend, c.args.LazyCacheTTL > 0, expiredMsgTtl)
	c.flushMu.RUnlock()
	if cachedResp != nil {
		c.hitTotal.Inc()
		c.observeActiveRefresh(kReal, cachedItem, qCtx, next, now, cachedResp)
		if lazyHit {
			c.lazyHitTotal.Inc()
			c.doLazyUpdate(kReal, cachedItem, qCtx, next)
		}
		cachedResp.Id = q.Id
		qCtx.SetResponse(cachedResp)
		if cachedItem.upstreamOpt != nil {
			qCtx.SetUpstreamOpt(cachedItem.upstreamOpt)
		}
		if cachedItem.domainSet != "" {
			qCtx.StoreValue(query_context.KeyDomainSet, cachedItem.domainSet)
		}

		if !lazyHit {
			c.promoteL1IfCurrent(kReal, cachedItem, observedEpoch, cachedResp)
		}
		return nil
	}

	var refreshCtx *query_context.Context
	var refreshNext sequence.ChainWalker
	if c.activeRefreshEnabled() {
		refreshCtx = qCtx.CopyWithoutResponse()
		refreshNext = next.Fork()
		if cachedItem != nil {
			retainedMsg := new(dns.Msg)
			if retainedMsg.Unpack(cachedItem.resp) == nil {
				c.trackActiveRefresh(kReal, cachedItem, refreshCtx, refreshNext, now, retainedMsg)
			}
		}
	}

	err := next.ExecNext(ctx, qCtx)
	r := qCtx.R()

	if r != nil && !c.containsExcluded(r) {
		// A privately retained fallback item is not directly serveable, but it
		// still protects useful response bytes. Do not let a transient failure
		// replace it, and only commit a healthy foreground result if the cache is
		// still absent or still contains the version this miss observed.
		allowTransientFailure := cachedItem == nil
		if prepared, ok := c.prepareCacheEntry(qCtx, allowTransientFailure); ok && c.commitPreparedForeground(kReal, cachedItem, observedEpoch, prepared) {
			if refreshCtx != nil {
				c.trackActiveRefresh(kReal, prepared.item, refreshCtx, refreshNext, time.Now(), prepared.msg)
			}
		}
	}

	return err
}

func (c *Cache) doLazyUpdate(k key, expected *item, qCtx *query_context.Context, next sequence.ChainWalker) {
	c.flushMu.RLock()
	defer c.flushMu.RUnlock()
	if c.lifecycleCtx.Err() != nil {
		return
	}
	epoch := c.refreshEpoch.Load()
	flight := refreshFlightKey{k: k, epoch: epoch}
	if _, loaded := c.refreshInFlight.LoadOrStore(flight, struct{}{}); loaded {
		return
	}
	task := &lazyTask{
		k: k, expected: expected,
		qCtx: qCtx.CopyWithoutResponse(), next: next.Fork(), epoch: epoch, flight: flight,
	}

	select {
	case c.lazyTaskChan <- task:
	default:
		c.lazyDropTotal.Inc() // 队列满则丢弃，保障主干 CPU 平滑
		c.refreshInFlight.Delete(flight)
	}
}

// 启动固定容量 Worker Pool
func (c *Cache) startWorkerPool() {
	workerCount := runtime.GOMAXPROCS(0) * 8
	if workerCount > maxConcurrentLazyUpdate {
		workerCount = maxConcurrentLazyUpdate
	}
	if workerCount < 8 {
		workerCount = 8
	}

	for i := 0; i < workerCount; i++ {
		c.lazyWorkers.Add(1)
		go func() {
			defer c.lazyWorkers.Done()
			for {
				select {
				case <-c.closeNotify:
					return
				default:
				}
				select {
				case <-c.closeNotify:
					return
				case task := <-c.lazyTaskChan:
					if task != nil {
						c.runLazyUpdateTask(task)
					}
				}
			}
		}()
	}
}

func (c *Cache) runLazyUpdateTask(task *lazyTask) {
	defer c.refreshInFlight.Delete(task.flight)
	if c.lifecycleCtx.Err() != nil || task.epoch != c.refreshEpoch.Load() {
		return
	}
	if current, _, ok := c.backend.Get(task.k); !ok || current != task.expected {
		return
	}
	task.qCtx.MarkCacheRefresh()
	ctx, cancel := context.WithTimeout(c.lifecycleCtx, defaultLazyUpdateTimeout)
	defer cancel()
	if ctx.Err() != nil {
		return
	}

	err := task.next.ExecNext(ctx, task.qCtx)
	if err != nil && !errors.Is(err, sequence.ErrExit) {
		c.logger.Debug("failed to update lazy cache", task.qCtx.InfoField(), zap.Error(err))
		return
	}
	if ctx.Err() != nil || task.qCtx.R() == nil || c.containsExcluded(task.qCtx.R()) {
		return
	}
	prepared, ok := c.prepareCacheEntry(task.qCtx, false)
	if !ok || !c.commitPrepared(task.k, task.expected, task.epoch, prepared) {
		return
	}
	c.updateActiveRefreshAfterCommit(task.k, task.expected, prepared.item, time.Now())
}

func (c *Cache) activeRefreshEnabled() bool {
	return c.args != nil && c.args.ActiveRefresh.Enabled && c.activeRefreshConfigValid && c.lifecycleCtx.Err() == nil
}

func (c *Cache) observeActiveRefresh(k key, expected *item, qCtx *query_context.Context, next sequence.ChainWalker, now time.Time, response *dns.Msg) {
	if !c.activeRefreshEnabled() || expected == nil || qCtx == nil {
		return
	}
	c.activeMu.RLock()
	meta := c.activeMeta[k]
	c.activeMu.RUnlock()
	if meta != nil {
		meta.lastAccess.Store(now.UnixNano())
		meta.refreshCount.Store(0)
		if meta.stopped.Swap(false) {
			c.rescheduleStoppedActiveMeta(meta, now)
		}
		return
	}
	if !c.activeExcludeDomainValid || c.activeDomainExcluded(qCtx.QQuestion().Name) || c.containsActiveExcluded(response) {
		return
	}
	// k can be an unsafe zero-copy view over the pooled request buffer on the
	// L1 path. Clone it before retaining it in metadata.
	durableKey := key(strings.Clone(string(k)))
	c.trackActiveRefresh(durableKey, expected, qCtx.CopyWithoutResponse(), next.Fork(), now, response)
}

func (c *Cache) trackActiveRefresh(k key, expected *item, qCtx *query_context.Context, next sequence.ChainWalker, now time.Time, response *dns.Msg) {
	if !c.activeRefreshEnabled() || expected == nil || qCtx == nil || !c.activeExcludeDomainValid {
		return
	}
	if question, ok := questionFromKey(k); !ok || c.activeDomainExcluded(question.Name) {
		return
	}
	if response != nil && c.containsActiveExcluded(response) {
		return
	}
	c.flushMu.RLock()
	current, _, ok := c.backend.Get(k)
	if !ok || current != expected {
		c.flushMu.RUnlock()
		return
	}

	c.activeMu.Lock()
	if meta := c.activeMeta[k]; meta != nil {
		meta.lastAccess.Store(now.UnixNano())
		meta.refreshCount.Store(0)
		meta.stopped.Store(false)
		meta.expected = expected
		meta.qCtx = qCtx
		meta.next = next.Fork()
		c.scheduleActiveMetaLocked(meta, c.activeRefreshAt(k, expected), now)
		c.activeMu.Unlock()
		c.flushMu.RUnlock()
		c.notifyActiveScheduler()
		return
	}

	maxMeta := c.args.Size
	if maxMeta < 1 {
		maxMeta = 1
	}
	if len(c.activeMeta) >= maxMeta {
		for oldKey, oldMeta := range c.activeMeta {
			c.removeActiveMetaLocked(oldKey, oldMeta)
			break
		}
	}
	meta := &activeRefreshMeta{k: k, qCtx: qCtx, next: next.Fork(), expected: expected, heapIndex: -1}
	meta.lastAccess.Store(now.UnixNano())
	c.activeMeta[k] = meta
	c.scheduleActiveMetaLocked(meta, c.activeRefreshAt(k, expected), now)
	c.activeMu.Unlock()
	c.flushMu.RUnlock()
	c.notifyActiveScheduler()
}

func (c *Cache) startActiveRefresh() {
	if !c.activeRefreshEnabled() || c.activeTaskChan == nil {
		return
	}

	workerCount := c.args.ActiveRefresh.Workers
	if workerCount > maxActiveRefreshWorkers {
		workerCount = maxActiveRefreshWorkers
	}
	if workerCount < 1 {
		workerCount = 1
	}

	for i := 0; i < workerCount; i++ {
		c.activeWorkers.Add(1)
		go func() {
			defer c.activeWorkers.Done()
			for {
				select {
				case <-c.closeNotify:
					return
				default:
				}
				select {
				case <-c.closeNotify:
					return
				case task := <-c.activeTaskChan:
					if task != nil {
						c.runActiveRefreshTask(task)
					}
				}
			}
		}()
	}

	c.activeWorkers.Add(1)
	go func() {
		defer c.activeWorkers.Done()
		c.activeSchedulerLoop()
	}()
}

func (c *Cache) activeSchedulerLoop() {
	for {
		c.activeMu.Lock()
		if len(c.activeHeap) == 0 {
			c.activeMu.Unlock()
			select {
			case <-c.closeNotify:
				return
			case <-c.activeWake:
				continue
			}
		}
		due := c.activeHeap[0].due
		c.activeMu.Unlock()

		delay := time.Until(due)
		if delay < 0 {
			delay = 0
		}
		timer := time.NewTimer(delay)
		select {
		case <-c.closeNotify:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return
		case <-c.activeWake:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			continue
		case now := <-timer.C:
			c.dispatchDueActiveRefresh(now)
			// Prevent a large cohort of equally due entries from turning a full
			// queue into a busy loop. Workers remain the primary rate limiter.
			pause := time.NewTimer(10 * time.Millisecond)
			select {
			case <-c.closeNotify:
				if !pause.Stop() {
					select {
					case <-pause.C:
					default:
					}
				}
				return
			case <-pause.C:
			}
		}
	}
}

func (c *Cache) dispatchDueActiveRefresh(now time.Time) {
	c.flushMu.RLock()
	defer c.flushMu.RUnlock()
	if c.lifecycleCtx.Err() != nil {
		return
	}
	limit := c.args.ActiveRefresh.MaxEntriesPerScan
	if limit < 1 {
		limit = 1
	}
	for dispatched := 0; dispatched < limit; {
		c.activeMu.Lock()
		if len(c.activeHeap) == 0 || c.activeHeap[0].due.After(now) {
			c.activeMu.Unlock()
			return
		}
		meta := heap.Pop(&c.activeHeap).(*activeRefreshMeta)
		if c.activeMeta[meta.k] != meta {
			c.activeMu.Unlock()
			continue
		}
		lastAccess := time.Unix(0, meta.lastAccess.Load())
		if maxIdle := c.args.ActiveRefresh.MaxIdleTime; maxIdle > 0 && now.Sub(lastAccess) >= time.Duration(maxIdle)*time.Second {
			c.removeActiveMetaLocked(meta.k, meta)
			c.activeMu.Unlock()
			continue
		}
		if now.Before(meta.refreshAt) {
			c.scheduleActiveMetaLocked(meta, meta.refreshAt, now)
			c.activeMu.Unlock()
			continue
		}
		if maxRefresh := c.args.ActiveRefresh.MaxRefreshTimes; maxRefresh > 0 && meta.refreshCount.Load() >= int64(maxRefresh) {
			meta.stopped.Store(true)
			c.activeMu.Unlock()
			continue
		}
		expected := meta.expected
		current, _, ok := c.backend.Get(meta.k)
		if !ok || current != expected {
			c.removeActiveMetaLocked(meta.k, meta)
			c.activeMu.Unlock()
			continue
		}
		epoch := c.refreshEpoch.Load()
		flight := refreshFlightKey{k: meta.k, epoch: epoch}
		if _, loaded := c.refreshInFlight.LoadOrStore(flight, struct{}{}); loaded {
			c.scheduleActiveMetaLocked(meta, now.Add(c.activeRetryInterval()), now)
			c.activeMu.Unlock()
			continue
		}
		task := &activeRefreshTask{
			k: meta.k, qCtx: meta.qCtx.Copy(), next: meta.next.Fork(),
			expected: expected, epoch: epoch, flight: flight,
		}
		c.activeMu.Unlock()

		select {
		case c.activeTaskChan <- task:
			meta.refreshCount.Add(1)
			dispatched++
		case <-c.closeNotify:
			c.refreshInFlight.Delete(flight)
			return
		default:
			c.activeRefreshDropTotal.Inc()
			c.refreshInFlight.Delete(flight)
			c.rescheduleActiveFailure(meta.k, expected, now)
			return
		}
	}
}

func (c *Cache) needsActiveRefresh(v *item, now time.Time) bool {
	if v == nil {
		return false
	}
	threshold := time.Duration(c.args.ActiveRefresh.Threshold) * time.Second
	if originalTTL := v.expirationTime.Sub(v.storedTime); originalTTL > 0 {
		threshold = min(threshold, originalTTL/3)
	}
	return v.expirationTime.Sub(now) <= threshold
}

func (c *Cache) runActiveRefreshTask(task *activeRefreshTask) {
	defer c.refreshInFlight.Delete(task.flight)
	if c.lifecycleCtx.Err() != nil || task.epoch != c.refreshEpoch.Load() {
		return
	}
	if current, _, ok := c.backend.Get(task.k); !ok || current != task.expected {
		return
	}
	c.activeRefreshTotal.Inc()
	timer := prometheus.NewTimer(c.activeRefreshDuration)
	defer timer.ObserveDuration()
	task.qCtx.MarkCacheRefresh()
	ctx, cancel := context.WithTimeout(c.lifecycleCtx, time.Duration(c.args.ActiveRefresh.RequeryTimeoutMS)*time.Millisecond)
	defer cancel()
	if ctx.Err() != nil {
		return
	}

	var err error
	if c.activeRefreshExec != nil {
		err = c.activeRefreshExec.Exec(ctx, task.qCtx)
	} else {
		err = task.next.ExecNext(ctx, task.qCtx)
	}
	if err != nil && !errors.Is(err, sequence.ErrExit) {
		c.logger.Debug("active refresh requery failed", task.qCtx.InfoField(), zap.Error(err))
	}
	if ctx.Err() == nil && (err == nil || errors.Is(err, sequence.ErrExit)) {
		r := task.qCtx.R()
		if r != nil && !c.containsExcluded(r) && !c.containsActiveExcluded(r) {
			if prepared, ok := c.prepareCacheEntry(task.qCtx, false); ok && c.commitPrepared(task.k, task.expected, task.epoch, prepared) {
				c.activeRefreshSuccessTotal.Inc()
				c.updateActiveRefreshAfterCommit(task.k, task.expected, prepared.item, time.Now())
				return
			}
		}
	}

	if c.lifecycleCtx.Err() == nil {
		probeBudget := time.Duration(c.args.ActiveRefresh.RequeryTimeoutMS) * time.Millisecond
		if probeBudget <= 0 {
			probeBudget = time.Duration(defaultActiveRefreshRequeryTimeout) * time.Millisecond
		}
		probeCtx, probeCancel := context.WithTimeout(c.lifecycleCtx, probeBudget)
		keptAlive := c.tryFallbackProbeKeepalive(probeCtx, task)
		probeCancel()
		if keptAlive {
			c.activeRefreshProbeKeepTotal.Inc()
			return
		}
	}
	c.activeRefreshFailedTotal.Inc()
	c.rescheduleActiveFailure(task.k, task.expected, time.Now())
}

func (c *Cache) activeRefreshAt(k key, v *item) time.Time {
	if v == nil {
		return time.Now()
	}
	threshold := time.Duration(c.args.ActiveRefresh.Threshold) * time.Second
	if originalTTL := v.expirationTime.Sub(v.storedTime); originalTTL > 0 {
		threshold = min(threshold, originalTTL/3)
	}
	if threshold <= 0 {
		return v.expirationTime
	}
	due := v.expirationTime.Add(-threshold)
	jitterWindow := min(threshold/5, time.Duration(c.args.ActiveRefresh.Interval)*time.Second/2)
	if jitterWindow > 0 && k != "" {
		due = due.Add(time.Duration(k.Sum() % uint64(jitterWindow)))
	}
	return due
}

func (c *Cache) activeRetryInterval() time.Duration {
	d := time.Duration(c.args.ActiveRefresh.MinRefreshInterval) * time.Second
	if d <= 0 {
		d = time.Second
	}
	return d
}

func (c *Cache) scheduleActiveMetaLocked(meta *activeRefreshMeta, refreshAt, now time.Time) {
	meta.refreshAt = refreshAt
	due := refreshAt
	if maxIdle := c.args.ActiveRefresh.MaxIdleTime; maxIdle > 0 {
		idleAt := time.Unix(0, meta.lastAccess.Load()).Add(time.Duration(maxIdle) * time.Second)
		if idleAt.Before(due) {
			due = idleAt
		}
	}
	if due.Before(now) {
		due = now
	}
	meta.due = due
	if meta.heapIndex >= 0 {
		heap.Fix(&c.activeHeap, meta.heapIndex)
	} else {
		heap.Push(&c.activeHeap, meta)
	}
}

func (c *Cache) removeActiveMetaLocked(k key, meta *activeRefreshMeta) {
	if c.activeMeta[k] != meta {
		return
	}
	if meta.heapIndex >= 0 {
		heap.Remove(&c.activeHeap, meta.heapIndex)
	}
	delete(c.activeMeta, k)
}

func (c *Cache) notifyActiveScheduler() {
	select {
	case c.activeWake <- struct{}{}:
	default:
	}
}

func (c *Cache) rescheduleStoppedActiveMeta(meta *activeRefreshMeta, now time.Time) {
	c.activeMu.Lock()
	if c.activeMeta[meta.k] == meta && meta.heapIndex < 0 {
		c.scheduleActiveMetaLocked(meta, c.activeRefreshAt(meta.k, meta.expected), now)
	}
	c.activeMu.Unlock()
	c.notifyActiveScheduler()
}

func (c *Cache) updateActiveRefreshAfterCommit(k key, expected, updated *item, now time.Time) {
	if !c.activeRefreshEnabled() || updated == nil {
		return
	}
	c.activeMu.Lock()
	meta := c.activeMeta[k]
	if meta == nil || meta.expected != expected {
		c.activeMu.Unlock()
		return
	}
	meta.expected = updated
	if maxRefresh := c.args.ActiveRefresh.MaxRefreshTimes; maxRefresh > 0 && meta.refreshCount.Load() >= int64(maxRefresh) {
		meta.stopped.Store(true)
	} else {
		c.scheduleActiveMetaLocked(meta, c.activeRefreshAt(k, updated), now)
	}
	c.activeMu.Unlock()
	c.notifyActiveScheduler()
}

func (c *Cache) rescheduleActiveFailure(k key, expected *item, now time.Time) {
	if !c.activeRefreshEnabled() {
		return
	}
	c.activeMu.Lock()
	meta := c.activeMeta[k]
	if meta == nil || meta.expected != expected {
		c.activeMu.Unlock()
		return
	}
	if maxRefresh := c.args.ActiveRefresh.MaxRefreshTimes; maxRefresh > 0 && meta.refreshCount.Load() >= int64(maxRefresh) {
		meta.stopped.Store(true)
	} else {
		retryAt := now.Add(c.activeRetryInterval())
		// A healthy answer should remain untouched until its real expiration.
		// Retry at that boundary so fallback probing can start without first
		// degrading the still-valid answer to a short stale TTL.
		if expected != nil && now.Before(expected.expirationTime) && expected.expirationTime.Before(retryAt) {
			retryAt = expected.expirationTime
		}
		c.scheduleActiveMetaLocked(meta, retryAt, now)
	}
	c.activeMu.Unlock()
	c.notifyActiveScheduler()
}

func (c *Cache) tryFallbackProbeKeepalive(ctx context.Context, task *activeRefreshTask) bool {
	cfg := c.args.ActiveRefresh.FallbackProbe
	if !cfg.Enabled || task.expected == nil {
		return false
	}
	if time.Now().Before(task.expected.expirationTime) {
		return false
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(task.expected.resp); err != nil {
		return false
	}
	if c.containsActiveExcluded(msg) {
		return false
	}
	ips := collectMsgIPs(msg)
	if len(ips) == 0 {
		return false
	}

	timeout := time.Duration(cfg.TimeoutMS) * time.Millisecond
	for _, probe := range cfg.Probes {
		for _, ip := range ips {
			if ctx.Err() != nil {
				return false
			}
			c.activeRefreshProbeTotal.Inc()
			if probeCachedIP(ctx, probe, ip, timeout) {
				prepared, ok := c.prepareStaleEntry(task.expected, msg, time.Now())
				if !ok || !c.commitPrepared(task.k, task.expected, task.epoch, prepared) {
					return false
				}
				c.updateActiveRefreshAfterCommit(task.k, task.expected, prepared.item, time.Now())
				return true
			}
		}
	}
	return false
}

func (c *Cache) prepareStaleEntry(old *item, msg *dns.Msg, now time.Time) (*preparedCacheEntry, bool) {
	cfg := c.args.ActiveRefresh.FallbackProbe
	if old == nil || msg == nil || cfg.StaleExtendTTL <= 0 || cfg.MaxStale <= 0 {
		return nil, false
	}
	deadline := old.staleDeadline
	if deadline.IsZero() {
		deadline = old.expirationTime.Add(time.Duration(cfg.MaxStale) * time.Second)
	}
	if !now.Before(deadline) {
		return nil, false
	}
	staleTTL := min(time.Duration(cfg.StaleExtendTTL)*time.Second, deadline.Sub(now))
	if staleTTL <= 0 {
		return nil, false
	}
	msgToCache := copyNoOpt(msg)
	msgToCache.AuthenticatedData = false
	advertisedTTL := min(staleTTL, 5*time.Second)
	if advertisedTTL < time.Second {
		advertisedTTL = time.Second
	}
	dnsutils.SetTTL(msgToCache, uint32(advertisedTTL/time.Second))
	if old.upstreamOpt != nil {
		msgToCache.Extra = append(msgToCache.Extra, copyOPT(old.upstreamOpt))
	}
	packedMsg, err := msgToCache.Pack()
	if err != nil {
		return nil, false
	}
	msgExpirationTime := now.Add(staleTTL)
	newItem := &item{
		resp:           packedMsg,
		storedTime:     now,
		expirationTime: msgExpirationTime,
		domainSet:      old.domainSet,
		upstreamOpt:    copyOPT(old.upstreamOpt),
		staleDeadline:  deadline,
		isStale:        true,
	}
	// Keep the bytes privately until the absolute stale deadline so a later
	// active attempt can probe and extend them again. getRespFromCache still
	// stops serving at expirationTime unless a new probe succeeds.
	return &preparedCacheEntry{item: newItem, cacheExpiration: deadline, msg: msgToCache}, true
}

func (c *Cache) Close() error {
	c.closeOnce.Do(func() {
		c.flushMu.Lock()
		c.refreshEpoch.Add(1)
		c.cancel()
		close(c.closeNotify)
		c.flushMu.Unlock()
	})
	c.lazyWorkers.Wait()
	c.activeWorkers.Wait()
	c.dumpLoopWG.Wait()
	c.drainPendingRefreshTasks()
	c.refreshInFlight.Clear()
	if err := c.dumpCache(); err != nil {
		c.logger.Error("failed to dump cache", zap.Error(err))
	}
	return c.backend.Close()
}

func (c *Cache) drainPendingRefreshTasks() {
	for {
		select {
		case <-c.lazyTaskChan:
			continue
		default:
			goto active
		}
	}

active:
	if c.activeTaskChan == nil {
		return
	}
	for {
		select {
		case <-c.activeTaskChan:
			continue
		default:
			return
		}
	}
}

func (c *Cache) loadDump() error {
	if len(c.args.DumpFile) == 0 {
		return nil
	}
	f, err := os.Open(c.args.DumpFile)
	if err != nil {
		if os.IsNotExist(err) {
			c.logger.Info("cache dump file not found, skipping load", zap.String("file", c.args.DumpFile))
			return nil
		}
		return err
	}
	defer f.Close()
	en, err := c.readDump(f)
	if err != nil {
		return err
	}
	c.logger.Info("cache dump loaded", zap.Int("entries", en))
	return nil
}

func (c *Cache) startDumpLoop() {
	if len(c.args.DumpFile) == 0 {
		return
	}
	c.dumpLoopWG.Add(1)
	go func() {
		defer c.dumpLoopWG.Done()
		ticker := time.NewTicker(time.Duration(c.args.DumpInterval) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				keyUpdated := c.updatedKey.Swap(0)
				if keyUpdated < minimumChangesToDump {
					c.updatedKey.Add(keyUpdated)
					continue
				}
				if err := c.dumpCache(); err != nil {
					c.updatedKey.Add(keyUpdated)
					c.logger.Error("dump cache", zap.Error(err))
				}
			case <-c.closeNotify:
				return
			}
		}
	}()
}

func (c *Cache) dumpCache() error {
	c.dumpMu.Lock()
	defer c.dumpMu.Unlock()

	if len(c.args.DumpFile) == 0 {
		return nil
	}
	f, err := os.Create(c.args.DumpFile)
	if err != nil {
		return err
	}
	defer f.Close()

	en, err := c.writeDump(f)
	if err != nil {
		return fmt.Errorf("failed to write dump, %w", err)
	}
	c.logger.Info("cache dumped", zap.Int("entries", en))
	return nil
}

func (c *Cache) Api() *chi.Mux {
	r := chi.NewRouter()

	r.Get("/flush", coremain.WithAsyncGC(func(w http.ResponseWriter, req *http.Request) {
		c.logger.Info("flushing cache via api")
		c.flushMu.Lock()
		c.refreshEpoch.Add(1)
		c.backend.Flush()
		c.clearRuntimeViews()
		c.updatedKey.Store(0)
		dumpErr := c.dumpCache()
		c.flushMu.Unlock()
		c.notifyActiveScheduler()

		if dumpErr != nil {
			c.logger.Error("failed to dump cache after flushing", zap.Error(dumpErr))
			http.Error(w, "cache was flushed but the empty dump could not be persisted", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Cache flushed and the empty dump was persisted.\n"))
	}))

	r.Get("/dump", coremain.WithAsyncGC(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("content-type", "application/octet-stream")
		_, err := c.writeDump(w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))

	r.Get("/save", func(w http.ResponseWriter, req *http.Request) {
		if len(c.args.DumpFile) == 0 {
			http.Error(w, "dump_file is not configured in config file", http.StatusBadRequest)
			return
		}

		c.logger.Info("saving cache to disk via api")
		err := c.dumpCache()
		if err != nil {
			c.logger.Error("failed to save cache via api", zap.Error(err))
			http.Error(w, fmt.Sprintf("failed to save cache: %v", err), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fmt.Sprintf("Cache successfully saved to %s\n", c.args.DumpFile)))
	})

	r.Post("/load_dump", coremain.WithAsyncGC(func(w http.ResponseWriter, req *http.Request) {
		if _, err := c.readDump(req.Body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	r.Get("/show", coremain.WithAsyncGC(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `inline; filename="cache.txt"`)

		query := strings.ToLower(req.URL.Query().Get("q"))
		limit, _ := strconv.Atoi(req.URL.Query().Get("limit"))
		offset, _ := strconv.Atoi(req.URL.Query().Get("offset"))

		if limit <= 0 {
			limit = 100
		}
		if offset < 0 {
			offset = 0
		}

		isIPLike := strings.Contains(query, ".") || strings.Contains(query, ":")

		now := time.Now()
		matchedCount := 0
		sentCount := 0
		stopIteration := errors.New("limit reached")

		reusableMsg := new(dns.Msg)

		err := c.backend.Range(func(k key, v *item, cacheExpirationTime time.Time) error {
			if cacheExpirationTime.Before(now) {
				return nil
			}

			keyStr := keyToString(k)
			found := false

			if query == "" || strings.Contains(strings.ToLower(keyStr), query) {
				found = true
			}

			isDeepMatched := false
			if !found && isIPLike {
				if err := reusableMsg.Unpack(v.resp); err == nil {
					for _, rr := range reusableMsg.Answer {
						if strings.Contains(rr.String(), query) {
							found = true
							isDeepMatched = true
							break
						}
					}
				}
			}

			if found {
				matchedCount++
				if matchedCount <= offset {
					return nil
				}

				fmt.Fprintf(w, "----- Cache Entry -----\n")
				fmt.Fprintf(w, "Key:           %s\n", keyStr)
				if v.domainSet != "" {
					fmt.Fprintf(w, "DomainSet:     %s\n", v.domainSet)
				}
				fmt.Fprintf(w, "StoredTime:    %s\n", v.storedTime.Format(time.RFC3339))
				fmt.Fprintf(w, "MsgExpire:     %s\n", v.expirationTime.Format(time.RFC3339))
				fmt.Fprintf(w, "CacheExpire:   %s\n", cacheExpirationTime.Format(time.RFC3339))

				if !isDeepMatched {
					if err := reusableMsg.Unpack(v.resp); err != nil {
						fmt.Fprintf(w, "DNS Message:\n<failed to unpack>\n")
						goto endLoop
					}
				}
				fmt.Fprintf(w, "DNS Message:\n%s\n", dnsMsgToString(reusableMsg))

			endLoop:
				sentCount++
				if sentCount >= limit {
					return stopIteration
				}
			}
			return nil
		})

		if err != nil && err != stopIteration {
			c.logger.Error("failed to enumerate cache", zap.Error(err))
		}
	}))

	return r
}

// clearRuntimeViews invalidates state derived from the L2 backend. The caller
// must hold flushMu for writing so no cache commit can repopulate the views
// halfway through the reset.
func (c *Cache) clearRuntimeViews() {
	for i := 0; i < shardCount; i++ {
		c.shards[i].Lock()
		c.shards[i].items = make(map[key]*l1Item, shardMaxSize)
		c.shards[i].order = make([]key, shardMaxSize)
		c.shards[i].pos = 0
		c.shards[i].ref = make(map[key]bool, shardMaxSize)
		c.shards[i].Unlock()
	}

	c.activeMu.Lock()
	for k, meta := range c.activeMeta {
		c.removeActiveMetaLocked(k, meta)
	}
	c.activeHeap = nil
	c.activeMu.Unlock()
}

func keyToString(k key) string {
	data := []byte(k)
	offset := 0
	var parts []string

	if len(data) < offset+1 {
		return fmt.Sprintf("invalid_key(len<1): %x", data)
	}
	flagsByte := data[offset]
	offset++
	var flags []string
	if flagsByte&adBit != 0 {
		flags = append(flags, "AD")
	}
	if flagsByte&cdBit != 0 {
		flags = append(flags, "CD")
	}
	if flagsByte&doBit != 0 {
		flags = append(flags, "DO")
	}
	if flagsByte&rdBit != 0 {
		flags = append(flags, "RD")
	}

	if len(data) < offset+4 {
		return fmt.Sprintf("invalid_key(missing_question_fields): %x", data)
	}
	qtype := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	qclass := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	if len(data) < offset+1 {
		return fmt.Sprintf("invalid_key(missing_name_len): %x", data)
	}
	nameLen := int(data[offset])
	offset++
	if len(data) < offset+nameLen {
		return fmt.Sprintf("invalid_key(incomplete_name): %x", data)
	}
	qname := string(data[offset : offset+nameLen])
	className := dns.ClassToString[qclass]
	if className == "" {
		className = strconv.Itoa(int(qclass))
	}
	parts = append(parts, qname, dns.TypeToString[qtype], className)
	offset += nameLen

	if len(flags) > 0 {
		parts = append(parts, fmt.Sprintf("[flags:%s]", strings.Join(flags, ",")))
	}
	if offset < len(data) {
		if len(data) < offset+2 {
			parts = append(parts, "[ecs:invalid_len]")
		} else {
			ecsLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
			offset += 2
			if len(data) < offset+ecsLen {
				parts = append(parts, "[ecs:incomplete]")
			} else if ecsLen > 0 {
				parts = append(parts, fmt.Sprintf("[ecs:%x]", data[offset:offset+ecsLen]))
			}
		}
	}
	return strings.Join(parts, " ")
}

func dnsMsgToString(msg *dns.Msg) string {
	if msg == nil {
		return "<nil>\n"
	}
	return strings.TrimSpace(msg.String()) + "\n"
}

func (c *Cache) writeDump(w io.Writer) (int, error) {
	en := 0
	gw, _ := gzip.NewWriterLevel(w, gzip.BestSpeed)
	gw.Name = dumpHeader

	block := new(CacheDumpBlock)
	writeBlock := func() error {
		b, err := proto.Marshal(block)
		if err != nil {
			return fmt.Errorf("failed to marshal protobuf, %w", err)
		}
		l := make([]byte, 8)
		binary.BigEndian.PutUint64(l, uint64(len(b)))
		if _, err := gw.Write(l); err != nil {
			return fmt.Errorf("failed to write header, %w", err)
		}
		if _, err := gw.Write(b); err != nil {
			return fmt.Errorf("failed to write data, %w", err)
		}
		en += len(block.GetEntries())
		block.Reset()
		return nil
	}

	now := time.Now()
	entries := make([]*CachedEntry, 0, c.backend.Len())
	rangeFunc := func(k key, v *item, cacheExpirationTime time.Time) error {
		// A probe-retained stale answer carries an absolute in-memory age
		// budget. Do not persist it and accidentally reset that budget after
		// restart.
		if cacheExpirationTime.Before(now) || v.isStale || v.isTransient {
			return nil
		}
		entries = append(entries, &CachedEntry{
			Key:                 []byte(k),
			CacheExpirationTime: cacheExpirationTime.Unix(),
			MsgExpirationTime:   v.expirationTime.Unix(),
			MsgStoredTime:       v.storedTime.Unix(),
			Msg:                 v.resp,
			DomainSet:           v.domainSet,
		})
		return nil
	}
	if err := c.backend.Range(rangeFunc); err != nil {
		return en, err
	}
	// Serialize after releasing backend shard locks. A slow disk or HTTP dump
	// consumer must not stall ordinary cache Get/Store operations.
	for _, entry := range entries {
		block.Entries = append(block.Entries, entry)
		if len(block.Entries) >= dumpBlockSize {
			if err := writeBlock(); err != nil {
				return en, err
			}
		}
	}
	if len(block.GetEntries()) > 0 {
		if err := writeBlock(); err != nil {
			return en, err
		}
	}
	return en, gw.Close()
}

func (c *Cache) readDump(r io.Reader) (int, error) {
	if c.lifecycleCtx.Err() != nil {
		return 0, context.Canceled
	}
	entries, err := c.decodeDump(r)
	if err != nil {
		return 0, err
	}
	if c.lifecycleCtx.Err() != nil {
		return 0, context.Canceled
	}
	if len(entries) == 0 {
		return 0, nil
	}

	// Parsing happens outside flushMu. Applying an already validated staging
	// set is intentionally the only write-locked part, so a slow upload cannot
	// block Close, flush, or ordinary cache commits.
	c.flushMu.Lock()
	if c.lifecycleCtx.Err() != nil {
		c.flushMu.Unlock()
		return 0, context.Canceled
	}
	c.refreshEpoch.Add(1)
	for _, entry := range entries {
		c.backend.Store(entry.k, entry.item, entry.cacheExpiration)
	}
	// Loading is merge-compatible at L2, but any overwritten entry makes its
	// L1 pointer and active-refresh expectation stale.
	c.clearRuntimeViews()
	c.flushMu.Unlock()
	c.notifyActiveScheduler()
	return len(entries), nil
}

func (c *Cache) decodeDump(r io.Reader) ([]decodedDumpEntry, error) {
	gr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read gzip header, %w", err)
	}
	defer gr.Close()
	if gr.Name != dumpHeader {
		return nil, fmt.Errorf("invalid or old cache dump, header is %s, want %s", gr.Name, dumpHeader)
	}

	maxEntries := max(c.args.Size, 1024)
	entries := make([]decodedDumpEntry, 0, min(maxEntries, dumpBlockSize))
	totalLength := uint64(0)
	blockCount := 0
	decodedEntryCount := 0
	now := time.Now()
	for {
		var header [8]byte
		_, err := io.ReadFull(gr, header[:])
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read block header, %w", err)
		}
		blockCount++
		if blockCount > maxEntries+1 {
			return nil, fmt.Errorf("cache dump contains too many blocks")
		}

		u := binary.BigEndian.Uint64(header[:])
		if u > dumpMaximumBlockLength {
			return nil, fmt.Errorf("invalid header, block length is big, %d", u)
		}
		totalLength += u
		if totalLength > dumpMaximumTotalLength {
			return nil, fmt.Errorf("cache dump decoded data exceeds %d bytes", dumpMaximumTotalLength)
		}
		b := make([]byte, int(u))
		_, err = io.ReadFull(gr, b)
		if err != nil {
			return nil, fmt.Errorf("failed to read block data, %w", err)
		}
		block := new(CacheDumpBlock)
		if err := proto.Unmarshal(b, block); err != nil {
			return nil, fmt.Errorf("failed to decode block data, %w", err)
		}

		decodedEntryCount += len(block.GetEntries())
		if decodedEntryCount > maxEntries {
			return nil, fmt.Errorf("cache dump contains more than %d entries", maxEntries)
		}
		for _, entry := range block.GetEntries() {
			cacheExpTime := time.Unix(entry.GetCacheExpirationTime(), 0)
			if !now.Before(cacheExpTime) {
				continue
			}
			msgExpTime := time.Unix(entry.GetMsgExpirationTime(), 0)
			storedTime := time.Unix(entry.GetMsgStoredTime(), 0)
			resp := append([]byte(nil), entry.GetMsg()...)
			restored := new(dns.Msg)
			if err := restored.Unpack(resp); err != nil {
				return nil, fmt.Errorf("cache dump contains an invalid DNS message, %w", err)
			}
			// Transient failures are never persisted by current versions. Ignore
			// them when importing an older or externally supplied v3 dump too, so
			// they cannot be restored as healthy fallback candidates.
			if restored.Rcode == dns.RcodeServerFailure {
				continue
			}
			i := &item{
				resp:           resp,
				storedTime:     storedTime,
				expirationTime: msgExpTime,
				domainSet:      entry.GetDomainSet(),
			}
			i.upstreamOpt = copyCacheableUpstreamOPT(restored.IsEdns0())
			if c.args.LazyCacheTTL > 0 && restored.Rcode == dns.RcodeSuccess {
				i.lazyDeadline = maxTime(i.expirationTime, storedTime.Add(time.Duration(c.args.LazyCacheTTL)*time.Second))
			}
			if c.args.ActiveRefresh.Enabled && c.activeRefreshConfigValid && c.args.ActiveRefresh.FallbackProbe.Enabled && c.args.ActiveRefresh.FallbackProbe.MaxStale > 0 && len(collectMsgIPs(restored)) > 0 {
				i.staleDeadline = i.expirationTime.Add(time.Duration(c.args.ActiveRefresh.FallbackProbe.MaxStale) * time.Second)
			}
			k := key(string(entry.GetKey()))
			if _, ok := questionFromKey(k); !ok {
				return nil, fmt.Errorf("cache dump contains an invalid cache key")
			}
			entries = append(entries, decodedDumpEntry{
				k: k, item: i, cacheExpiration: cacheExpTime,
			})
		}
	}
	return entries, nil
}

// getECSClient returns a canonical ECS key fragment. valid is false when the
// query contains an ECS option that cannot be represented safely; callers
// should bypass caching instead of collapsing it into the non-ECS key.
func getECSClient(qCtx *query_context.Context) (client []byte, valid bool) {
	ecs, valid := singleECSOption(qCtx.QOpt())
	if !valid || ecs == nil {
		return nil, valid
	}
	return canonicalECS(ecs, true)
}

// singleECSOption rejects duplicate ECS options and options that claim the
// ECS code with a different concrete representation. The latter can be
// constructed by plugins even though it cannot originate from normal wire
// decoding.
func singleECSOption(opt *dns.OPT) (*dns.EDNS0_SUBNET, bool) {
	if opt == nil {
		return nil, true
	}
	var found *dns.EDNS0_SUBNET
	for _, option := range opt.Option {
		if option == nil {
			return nil, false
		}
		if ecs, ok := option.(*dns.EDNS0_SUBNET); ok {
			if ecs == nil || found != nil {
				return nil, false
			}
			found = ecs
			continue
		}
		if option.Option() == dns.EDNS0SUBNET {
			return nil, false
		}
	}
	return found, true
}

func canonicalECS(ecs *dns.EDNS0_SUBNET, requireZeroScope bool) ([]byte, bool) {
	if ecs == nil || (requireZeroScope && ecs.SourceScope != 0) {
		return nil, false
	}

	var ip net.IP
	maxBits := 0
	switch ecs.Family {
	case 1:
		ip = ecs.Address.To4()
		maxBits = net.IPv4len * 8
	case 2:
		// To16 also accepts an IPv4 address. Reject that representation for
		// family 2, matching miekg/dns's wire encoder.
		if ecs.Address.To4() != nil {
			return nil, false
		}
		ip = ecs.Address.To16()
		maxBits = net.IPv6len * 8
	default:
		return nil, false
	}
	if ip == nil || int(ecs.SourceNetmask) > maxBits || int(ecs.SourceScope) > maxBits {
		return nil, false
	}

	bits := int(ecs.SourceNetmask)
	masked := ip.Mask(net.CIDRMask(bits, maxBits))
	byteLen := (bits + 7) / 8
	client := make([]byte, 0, 3+byteLen)
	client = append(client, byte(ecs.Family>>8), byte(ecs.Family), ecs.SourceNetmask)
	client = append(client, masked[:byteLen]...)
	return client, true
}

func getClientIdentitySubnet(qCtx *query_context.Context) []byte {
	addr := qCtx.ServerMeta.ClientAddr.Unmap()
	if !addr.IsValid() {
		return nil
	}
	if addr.Is4() {
		ip := addr.As4()
		return append([]byte{0, 1, 32}, ip[:]...)
	}
	if addr.Is6() {
		ip := addr.As16()
		return append([]byte{0, 2, 128}, ip[:]...)
	}
	return nil
}

func getMsgKeyBytes(q *dns.Msg, qCtx *query_context.Context, useECS bool) ([]byte, *[]byte) {
	if q.Response || q.Opcode != dns.OpcodeQuery || len(q.Question) != 1 {
		return nil, nil
	}

	question := q.Question[0]
	if len(question.Name) == 0 || len(question.Name) > 255 {
		return nil, nil
	}
	// Existing ECS always participates in the key. If enable_ecs is set but the
	// ECS handler is placed after cache, isolate by full client address rather
	// than allowing one client's regional answer to enter a shared key.
	ecs, validECS := getECSClient(qCtx)
	if !validECS {
		return nil, nil
	}
	if len(ecs) == 0 && useECS {
		ecs = getClientIdentitySubnet(qCtx)
		if len(ecs) == 0 {
			return nil, nil
		}
	}
	totalLen := 1 + 2 + 2 + 1 + len(question.Name) + 2 + len(ecs)

	bufPtr := keyBufferPool.Get().(*[]byte)
	buf := (*bufPtr)[:0]
	if cap(buf) < totalLen {
		buf = make([]byte, 0, totalLen+32)
	}

	b := byte(0)
	if q.AuthenticatedData {
		b = b | adBit
	}
	if q.CheckingDisabled {
		b = b | cdBit
	}
	if opt := q.IsEdns0(); opt != nil && opt.Do() {
		b = b | doBit
	}
	if q.RecursionDesired {
		b = b | rdBit
	}

	buf = append(buf, b)
	buf = append(buf, byte(question.Qtype>>8), byte(question.Qtype))
	buf = append(buf, byte(question.Qclass>>8), byte(question.Qclass))
	buf = append(buf, byte(len(question.Name)))
	buf = append(buf, question.Name...)
	buf = append(buf, byte(len(ecs)>>8), byte(len(ecs)))
	buf = append(buf, ecs...)

	*bufPtr = buf
	return buf, bufPtr
}

func copyNoOpt(m *dns.Msg) *dns.Msg {
	if m == nil {
		return nil
	}

	m2 := new(dns.Msg)
	m2.MsgHdr = m.MsgHdr
	m2.Compress = m.Compress

	if len(m.Question) > 0 {
		m2.Question = make([]dns.Question, len(m.Question))
		copy(m2.Question, m.Question)
	}

	lenExtra := len(m.Extra)
	for _, r := range m.Extra {
		if r.Header().Rrtype == dns.TypeOPT {
			lenExtra--
		}
	}

	s := make([]dns.RR, len(m.Answer)+len(m.Ns)+lenExtra)
	m2.Answer, s = s[:0:len(m.Answer)], s[len(m.Answer):]
	m2.Ns, s = s[:0:len(m.Ns)], s[len(m.Ns):]
	m2.Extra = s[:0:lenExtra]

	for _, r := range m.Answer {
		m2.Answer = append(m2.Answer, dns.Copy(r))
	}
	for _, r := range m.Ns {
		m2.Ns = append(m2.Ns, dns.Copy(r))
	}

	for _, r := range m.Extra {
		if r.Header().Rrtype == dns.TypeOPT {
			continue
		}
		m2.Extra = append(m2.Extra, dns.Copy(r))
	}
	return m2
}

func min[T constraints.Ordered](a, b T) T {
	if a < b {
		return a
	}
	return b
}

func max[T constraints.Ordered](a, b T) T {
	if a > b {
		return a
	}
	return b
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func stringListFromRaw(v any, field string) ([]string, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case string:
		return strings.Fields(x), nil
	case []string:
		return x, nil
	case []interface{}:
		out := make([]string, 0, len(x))
		for _, elem := range x {
			s, ok := elem.(string)
			if !ok {
				return nil, fmt.Errorf("%s list contains non-string: %#v", field, elem)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%s must be string or list, got %T", field, v)
	}
}

func parseIPNet(s string) (*net.IPNet, error) {
	if _, ipnet, err := net.ParseCIDR(s); err == nil {
		return ipnet, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("invalid ip or cidr %q", s)
	}
	if ip4 := ip.To4(); ip4 != nil {
		return &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}

func buildActiveExcludeDomainMatcher(bq sequence.BQ, args ActiveRefreshDomainArgs) (domain.Matcher[struct{}], error) {
	var matchers []domain.Matcher[struct{}]
	if len(args.Exps)+len(args.Files) > 0 {
		anonymousSet := domain.NewDomainMixMatcher()
		if err := domain_set.LoadExpsAndFiles(args.Exps, args.Files, anonymousSet); err != nil {
			return nil, err
		}
		if anonymousSet.Len() > 0 {
			matchers = append(matchers, anonymousSet)
		}
	}
	for _, tag := range args.DomainSets {
		if bq == nil || bq.M() == nil {
			return nil, fmt.Errorf("cannot use domain set %s without mosdns context", tag)
		}
		p := bq.M().GetPlugin(tag)
		dsProvider, _ := p.(data_provider.DomainMatcherProvider)
		if dsProvider == nil {
			return nil, fmt.Errorf("%s is not a DomainMatcherProvider", tag)
		}
		matcher := dsProvider.GetDomainMatcher()
		if matcher == nil {
			return nil, fmt.Errorf("%s returned a nil domain matcher", tag)
		}
		matchers = append(matchers, matcher)
	}
	if len(matchers) == 0 {
		return nil, nil
	}
	return domain_set.MatcherGroup(matchers), nil
}

func questionFromKey(k key) (dns.Question, bool) {
	data := []byte(k)
	if len(data) == 0 || data[0]&^(adBit|cdBit|doBit|rdBit) != 0 {
		return dns.Question{}, false
	}
	offset := 1
	if len(data) < offset+4 {
		return dns.Question{}, false
	}
	qtype := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	qclass := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	if len(data) < offset+1 {
		return dns.Question{}, false
	}
	nameLen := int(data[offset])
	offset++
	if nameLen == 0 || len(data) < offset+nameLen {
		return dns.Question{}, false
	}
	nameEnd := offset + nameLen
	if len(data) < nameEnd+2 {
		return dns.Question{}, false
	}
	ecsLen := int(binary.BigEndian.Uint16(data[nameEnd : nameEnd+2]))
	if ecsLen > 19 || len(data) != nameEnd+2+ecsLen {
		return dns.Question{}, false
	}
	return dns.Question{
		Name:   string(data[offset : offset+nameLen]),
		Qtype:  qtype,
		Qclass: qclass,
	}, true
}

func (c *Cache) activeDomainExcluded(qname string) bool {
	if !c.activeExcludeDomainValid {
		return true
	}
	matcher := c.activeExcludeDomainMatcher
	if matcher == nil {
		return false
	}
	_, ok := matcher.Match(qname)
	return ok
}

func (c *Cache) containsActiveExcluded(msg *dns.Msg) bool {
	return containsAnyNet(msg, c.activeExcludeNets)
}

func containsAnyNet(msg *dns.Msg, nets []*net.IPNet) bool {
	if len(nets) == 0 || msg == nil {
		return false
	}
	for _, ip := range collectMsgIPs(msg) {
		for _, net := range nets {
			if net.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func collectMsgIPs(msg *dns.Msg) []net.IP {
	var ips []net.IP
	for _, rr := range msg.Answer {
		switch rr := rr.(type) {
		case *dns.A:
			if rr.A != nil {
				ips = append(ips, rr.A)
			}
		case *dns.AAAA:
			if rr.AAAA != nil {
				ips = append(ips, rr.AAAA)
			}
		}
	}
	return ips
}

func probeCachedIP(parent context.Context, probe string, ip net.IP, timeout time.Duration) bool {
	if timeout <= 0 {
		timeout = time.Duration(defaultFallbackProbeTimeout) * time.Millisecond
	}
	if probe == "ping" {
		return probePing(parent, ip, timeout)
	}
	if strings.HasPrefix(probe, "tcp:") {
		port := strings.TrimPrefix(probe, "tcp:")
		if port == "" {
			return false
		}
		ctx, cancel := context.WithTimeout(parent, timeout)
		defer cancel()
		dialer := net.Dialer{Timeout: timeout}
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}
	return false
}

func probePing(parent context.Context, ip net.IP, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	timeoutMS := int(timeout / time.Millisecond)
	if timeoutMS <= 0 {
		timeoutMS = defaultFallbackProbeTimeout
	}

	var args []string
	if runtime.GOOS == "windows" {
		args = []string{"-n", "1", "-w", strconv.Itoa(timeoutMS), ip.String()}
	} else {
		timeoutSec := int((timeout + time.Second - 1) / time.Second)
		if timeoutSec < 1 {
			timeoutSec = 1
		}
		args = []string{"-c", "1", "-W", strconv.Itoa(timeoutSec), ip.String()}
	}
	cmd := exec.CommandContext(ctx, "ping", args...)
	return cmd.Run() == nil
}

func getRespFromCache(msgKey string, backend *cache.Cache[key, *item], lazyCacheEnabled bool, lazyTtl int) (*dns.Msg, bool, *item) {
	v, _, _ := backend.Get(key(msgKey))
	if v != nil {
		now := time.Now()

		m := dnsMsgPool.Get().(*dns.Msg)
		defer dnsMsgPool.Put(m)

		if err := m.Unpack(v.resp); err != nil {
			return nil, false, v
		}

		if now.Before(v.expirationTime) {
			r := m.Copy()
			dnsutils.SubtractTTL(r, uint32(now.Sub(v.storedTime).Seconds()))
			return r, false, v
		}

		if lazyCacheEnabled && !v.lazyDeadline.IsZero() && now.Before(v.lazyDeadline) {
			r := m.Copy()
			dnsutils.SetTTL(r, uint32(lazyTtl))
			return r, true, v
		}
		return nil, false, v
	}
	return nil, false, nil
}

func (c *Cache) prepareCacheEntry(qCtx *query_context.Context, allowTransientFailure bool) (*preparedCacheEntry, bool) {
	r := qCtx.R()
	if r == nil || r.Truncated {
		return nil, false
	}
	msgTTL, ok := cacheableResponseTTL(r, allowTransientFailure)
	if !ok || msgTTL <= 0 {
		return nil, false
	}

	cacheTTL := msgTTL
	if c.args.LazyCacheTTL > 0 && r.Rcode == dns.RcodeSuccess {
		cacheTTL = max(cacheTTL, time.Duration(c.args.LazyCacheTTL)*time.Second)
	}

	msgToCache := copyNoOpt(r)
	dnsutils.ApplyMaximumTTL(msgToCache, uint32(msgTTL/time.Second))
	upstreamOpt, validUpstreamOpt := validatedCacheableUpstreamOPT(qCtx.QOpt(), qCtx.UpstreamOpt())
	if !validUpstreamOpt {
		return nil, false
	}
	if upstreamOpt != nil {
		msgToCache.Extra = append(msgToCache.Extra, copyOPT(upstreamOpt))
	}
	packedMsg, err := msgToCache.Pack()
	if err != nil {
		return nil, false
	}

	now := time.Now()
	cacheExpiration := now.Add(cacheTTL)
	v := &item{
		resp:           packedMsg,
		storedTime:     now,
		expirationTime: now.Add(msgTTL),
		upstreamOpt:    upstreamOpt,
		isTransient:    r.Rcode == dns.RcodeServerFailure,
	}
	if c.args.LazyCacheTTL > 0 && r.Rcode == dns.RcodeSuccess {
		v.lazyDeadline = cacheExpiration
	}

	if val, ok := qCtx.GetValue(query_context.KeyDomainSet); ok {
		if name, isString := val.(string); isString {
			v.domainSet = name
		}
	}
	if !v.isTransient && c.activeRefreshEnabled() && c.args.ActiveRefresh.FallbackProbe.Enabled && c.args.ActiveRefresh.FallbackProbe.MaxStale > 0 && len(collectMsgIPs(msgToCache)) > 0 {
		v.staleDeadline = v.expirationTime.Add(time.Duration(c.args.ActiveRefresh.FallbackProbe.MaxStale) * time.Second)
		cacheExpiration = maxTime(cacheExpiration, v.staleDeadline)
	}
	return &preparedCacheEntry{item: v, cacheExpiration: cacheExpiration, msg: msgToCache}, true
}

func cacheableResponseTTL(r *dns.Msg, allowTransientFailure bool) (time.Duration, bool) {
	switch r.Rcode {
	case dns.RcodeSuccess:
		if len(r.Answer) == 0 {
			ttl, ok := negativeResponseTTL(r)
			if !ok {
				return 0, false
			}
			return min(ttl, 300*time.Second), true
		}
		ttl := dnsutils.GetMinimalTTL(r)
		if ttl == 0 {
			return 0, false
		}
		return time.Duration(ttl) * time.Second, true
	case dns.RcodeNameError:
		return negativeResponseTTL(r)
	case dns.RcodeServerFailure:
		if allowTransientFailure {
			return 5 * time.Second, true
		}
	}
	return 0, false
}

func negativeResponseTTL(r *dns.Msg) (time.Duration, bool) {
	var minTTL uint32
	found := false
	for _, rr := range r.Ns {
		soa, ok := rr.(*dns.SOA)
		if !ok {
			continue
		}
		ttl := min(soa.Hdr.Ttl, soa.Minttl)
		if ttl == 0 {
			continue
		}
		if !found || ttl < minTTL {
			minTTL = ttl
			found = true
		}
	}
	if !found {
		return 0, false
	}
	return time.Duration(minTTL) * time.Second, true
}

func (c *Cache) commitPrepared(k key, expected *item, epoch uint64, prepared *preparedCacheEntry) bool {
	if expected == nil {
		return c.commitPreparedMatching(k, epoch, false, nil, prepared)
	}
	return c.commitPreparedMatching(k, epoch, true, func(current *item, ok bool) bool {
		return ok && current == expected
	}, prepared)
}

func (c *Cache) promoteL1IfCurrent(k key, expected *item, epoch uint64, msg *dns.Msg) bool {
	if expected == nil || msg == nil || c.lifecycleCtx.Err() != nil {
		return false
	}
	// qCtx owns the response object. L1 keeps an independent copy so later
	// response processing cannot mutate the cached hot-path template.
	l1Msg := msg.Copy()
	c.flushMu.RLock()
	defer c.flushMu.RUnlock()
	if c.lifecycleCtx.Err() != nil || epoch != c.refreshEpoch.Load() {
		return false
	}
	commitMu := &c.commitLocks[k.Sum()%shardCount]
	commitMu.Lock()
	defer commitMu.Unlock()
	current, _, ok := c.backend.Get(k)
	if !ok || current != expected {
		return false
	}
	c.shards[k.Sum()%shardCount].updateL1(k, l1Msg, expected)
	return true
}

func (c *Cache) commitPreparedForeground(k key, observed *item, epoch uint64, prepared *preparedCacheEntry) bool {
	return c.commitPreparedMatching(k, epoch, true, func(current *item, ok bool) bool {
		if observed == nil {
			// The first healthy answer wins an absent-miss race, but a healthy
			// answer may heal a short-lived SERVFAIL inserted by an earlier peer.
			return !ok || (current != nil && current.isTransient && !prepared.item.isTransient)
		}
		// Eviction or expiry can legitimately remove the observed retained item
		// while the upstream query is running. Epoch protects flush/load, so an
		// absent current value is still safe to fill.
		return !ok || current == observed
	}, prepared)
}

func (c *Cache) commitPreparedMatching(k key, epoch uint64, checkEpoch bool, match func(current *item, ok bool) bool, prepared *preparedCacheEntry) bool {
	if prepared == nil || prepared.item == nil || prepared.msg == nil || c.lifecycleCtx.Err() != nil {
		return false
	}
	c.flushMu.RLock()
	defer c.flushMu.RUnlock()
	if c.lifecycleCtx.Err() != nil || (checkEpoch && epoch != c.refreshEpoch.Load()) {
		return false
	}
	commitMu := &c.commitLocks[k.Sum()%shardCount]
	commitMu.Lock()
	defer commitMu.Unlock()
	if match != nil {
		if !c.backend.StoreIf(k, prepared.item, prepared.cacheExpiration, match) {
			return false
		}
	} else {
		c.backend.Store(k, prepared.item, prepared.cacheExpiration)
	}
	c.shards[k.Sum()%shardCount].updateL1(k, prepared.msg.Copy(), prepared.item)
	c.updatedKey.Add(1)
	return true
}

func copyOPT(opt *dns.OPT) *dns.OPT {
	if opt == nil {
		return nil
	}
	return dns.Copy(opt).(*dns.OPT)
}

func copyCacheableUpstreamOPT(opt *dns.OPT) *dns.OPT {
	if opt == nil {
		return nil
	}
	filtered := copyOPT(opt)
	options := filtered.Option
	filtered.Option = make([]dns.EDNS0, 0, len(options))
	for _, option := range options {
		if option.Option() == dns.EDNS0SUBNET {
			filtered.Option = append(filtered.Option, option)
		}
	}
	if len(filtered.Option) == 0 {
		return nil
	}
	return filtered
}

// validatedCacheableUpstreamOPT keeps response ECS metadata only when it is a
// valid reply to the current query ECS. RFC 7871 requires the response family,
// source prefix length and address prefix to match the query, and forbids an
// unsolicited response ECS option.
func validatedCacheableUpstreamOPT(queryOpt, upstreamOpt *dns.OPT) (*dns.OPT, bool) {
	responseECS, valid := singleECSOption(upstreamOpt)
	if !valid {
		return nil, false
	}
	if responseECS == nil {
		return nil, true
	}

	queryECS, valid := singleECSOption(queryOpt)
	if !valid || queryECS == nil {
		return nil, false
	}
	queryPrefix, validQuery := canonicalECS(queryECS, true)
	responsePrefix, validResponse := canonicalECS(responseECS, false)
	if !validQuery || !validResponse || !bytes.Equal(queryPrefix, responsePrefix) {
		return nil, false
	}
	return copyCacheableUpstreamOPT(upstreamOpt), true
}
