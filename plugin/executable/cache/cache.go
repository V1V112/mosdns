package cache

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/maphash"
	"io"
	"math"
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
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"
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

	minimumChangesToDump          = 1024
	dumpHeader                    = "mosdns_cache_v3"
	dumpBlockSize                 = 128
	dumpMaximumBlockLength        = 1 << 20 // 1M block. 8kb pre entry. Should be enough.
	dumpMaximumTotalLength        = 256 << 20
	activeRefreshDumpStateVersion = 1

	shardCount = 256   // 256分段锁，平衡锁竞争与内存开销
	l1TotalCap = 51200 // L1 总容量限制

	// 后台异步任务池参数
	maxConcurrentLazyUpdate = 256
	lazyTaskQueueCapacity   = 8192

	defaultActiveRefreshThreshold      = 60
	defaultActiveRefreshRequeryTimeout = 1000
	defaultActiveRefreshWorkers        = 16
	defaultActiveRefreshMaxIdleTime    = 3600
	defaultActiveRefreshMaxQPS         = 30
	// RefreshBurst and MaxTasksPerBatch use these historical defaults as
	// baselines and scale linearly when MaxRefreshQPS is changed.
	defaultActiveRefreshBurst          = 60
	defaultActiveRefreshMaxBatch       = 256
	defaultActiveRefreshMaxPending     = 2048
	defaultActiveRefreshMaxRetry       = 2
	defaultFallbackProbeTimeout        = 500
	defaultFallbackProbeStaleExtendTTL = 60
	defaultFallbackProbeMaxStale       = 300
	maxActiveRefreshWorkers            = 256
)

const (
	adBit = 1 << iota
	cdBit
	doBit
	rdBit
)

var _ sequence.RecursiveExecutable = (*Cache)(nil)
var _ sequence.ContinuationBinder = (*Cache)(nil)

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
	generation            uint64
	staleSourceGeneration uint64
	activeMeta            atomic.Pointer[activeRefreshMeta]
	backendRemoved        atomic.Bool
	// activity is shared by every physical cache generation in one key lineage.
	// A real hit that already passed the old L1 pointer check therefore remains
	// visible after a concurrent active/lazy generation handoff. The pointer is
	// installed before backend publication and never replaced afterwards.
	activity atomic.Pointer[activeActivity]
	// admissionCapture is deliberately generation-local. Sharing this gate with
	// activity would let an old snapshot owner block, or accidentally release,
	// the owner for a newly published generation.
	admissionCapture atomic.Bool
	resp             []byte
	storedTime       time.Time
	expirationTime   time.Time
	lazyDeadline     time.Time
	domainSet        string
	upstreamOpt      *dns.OPT
	staleDeadline    time.Time
	isStale          bool
	isTransient      bool
}

// activeActivity is the lock-free popularity and idle state shared across a
// cache key's physical generations. admissionState packs the admission-window
// start Unix second in the high 32 bits and the saturating hit count in the low
// 32 bits. refreshState packs a real-access epoch in the high 32 bits and the
// consecutive successful refresh count in the low 32 bits. Keeping those two
// values in one CAS prevents a hit racing a refresh completion from being
// overwritten by a later Add(1).
type activeActivity struct {
	// admissionMu is used only while a lineage is not yet tracked. It publishes
	// lifetime count, idle state and admission-window state as one observation
	// to a concurrent metadata installer or foreground generation handoff. Once
	// activeMeta is bound, real hits stay on the atomic writer-pin fast path.
	admissionMu     sync.Mutex
	lastRealAccess  atomic.Int64
	realAccessCount atomic.Uint64
	admissionState  atomic.Uint64
	refreshState    atomic.Uint64
}

func (v *item) activityState() *activeActivity {
	if v == nil {
		return nil
	}
	if activity := v.activity.Load(); activity != nil {
		return activity
	}
	activity := new(activeActivity)
	if v.activity.CompareAndSwap(nil, activity) {
		return activity
	}
	return v.activity.Load()
}

func newActiveActivity(lastRealAccess time.Time) *activeActivity {
	activity := new(activeActivity)
	if !lastRealAccess.IsZero() {
		activity.lastRealAccess.Store(lastRealAccess.UnixNano())
	}
	return activity
}

// inheritActiveRefreshActivity must only be called before dst is published to
// the backend. Published generations keep an immutable activity pointer.
func inheritActiveRefreshActivity(dst, src *item) {
	if dst == nil || src == nil {
		return
	}
	dst.activity.Store(src.activityState())
}

func (a *activeActivity) refreshEpoch() uint32 {
	if a == nil {
		return 0
	}
	return uint32(a.refreshState.Load() >> 32)
}

func (a *activeActivity) refreshSuccesses() uint32 {
	if a == nil {
		return 0
	}
	return uint32(a.refreshState.Load())
}

func (a *activeActivity) storeRefreshSuccesses(successes uint32) {
	if a == nil {
		return
	}
	for state := a.refreshState.Load(); ; state = a.refreshState.Load() {
		updated := state&0xffffffff00000000 | uint64(successes)
		if a.refreshState.CompareAndSwap(state, updated) {
			return
		}
	}
}

func (a *activeActivity) recordRealAccess(now time.Time) {
	if a == nil {
		return
	}
	storeActiveRefreshAccessMax(&a.lastRealAccess, now.UnixNano())
	for state := a.refreshState.Load(); ; state = a.refreshState.Load() {
		nextEpoch := uint32(state>>32) + 1
		if a.refreshState.CompareAndSwap(state, uint64(nextEpoch)<<32) {
			return
		}
	}
}

// addRefreshSuccess records one successful active refresh only if no real hit
// changed the captured epoch while the upstream query was running.
func (a *activeActivity) addRefreshSuccess(epoch uint32) bool {
	if a == nil {
		return false
	}
	for state := a.refreshState.Load(); ; state = a.refreshState.Load() {
		if uint32(state>>32) != epoch {
			return false
		}
		successes := uint32(state)
		if successes == ^uint32(0) {
			return true
		}
		updated := state&0xffffffff00000000 | uint64(successes+1)
		if a.refreshState.CompareAndSwap(state, updated) {
			return true
		}
	}
}

func recordRealCacheAccess(v *item, now time.Time) {
	if v == nil {
		return
	}
	v.activityState().recordRealAccess(now)
}

type l1Item struct {
	msg            *dns.Msg
	storedTime     time.Time
	expirationTime time.Time
	domainSet      string
	upstreamOpt    *dns.OPT
	source         *item
	slot           int
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
	Enabled          bool    `yaml:"enabled"`
	Threshold        int     `yaml:"threshold"`
	RequeryTimeoutMS int     `yaml:"requery_timeout_ms"`
	Workers          int     `yaml:"workers"`
	MaxRefreshQPS    float64 `yaml:"max_refresh_qps"`
	RefreshBurst     int     `yaml:"refresh_burst"`
	MaxTasksPerBatch int     `yaml:"max_tasks_per_batch"`
	MaxPendingTasks  int     `yaml:"max_pending_tasks"`
	MaxRetryTimes    int     `yaml:"max_retry_times"`
	MaxRefreshTimes  int     `yaml:"max_refresh_times"`
	MaxIdleTime      int     `yaml:"max_idle_time"`
	// These six fields form one explicit opt-in tracking policy. When all are
	// omitted, active refresh keeps its historical immediate-admission and
	// least-urgent eviction behaviour. Partial groups are rejected.
	MaxTrackedEntries int `yaml:"max_tracked_entries,omitempty"`
	// AdmissionHits real client accesses must occur inside AdmissionWindow
	// before a previously untracked entry gets replay state and a refresh task.
	AdmissionHits     int                     `yaml:"admission_hits,omitempty"`
	AdmissionWindow   int                     `yaml:"admission_window,omitempty"`
	HeatHalfLife      int                     `yaml:"heat_half_life,omitempty"`
	ProtectedRatio    int                     `yaml:"protected_ratio,omitempty"`
	EvictionScanLimit int                     `yaml:"eviction_scan_limit,omitempty"`
	ExcludeIP         any                     `yaml:"exclude_ip"`
	ExcludeDomain     ActiveRefreshDomainArgs `yaml:"exclude_domain"`
	FallbackProbe     FallbackProbeArgs       `yaml:"fallback_probe"`

	maxRetryTimesConfigured  bool
	maxIdleTimeConfigured    bool
	trackingPolicyConfigured bool
}

type activeRefreshArgsRaw struct {
	Enabled           bool                    `yaml:"enabled"`
	Threshold         int                     `yaml:"threshold"`
	RequeryTimeoutMS  int                     `yaml:"requery_timeout_ms"`
	Workers           int                     `yaml:"workers"`
	MaxRefreshQPS     float64                 `yaml:"max_refresh_qps"`
	RefreshBurst      int                     `yaml:"refresh_burst"`
	MaxTasksPerBatch  int                     `yaml:"max_tasks_per_batch"`
	MaxPendingTasks   int                     `yaml:"max_pending_tasks"`
	MaxRetryTimes     int                     `yaml:"max_retry_times"`
	MaxRefreshTimes   int                     `yaml:"max_refresh_times"`
	MaxIdleTime       int                     `yaml:"max_idle_time"`
	MaxTrackedEntries int                     `yaml:"max_tracked_entries"`
	AdmissionHits     int                     `yaml:"admission_hits"`
	AdmissionWindow   int                     `yaml:"admission_window"`
	HeatHalfLife      int                     `yaml:"heat_half_life"`
	ProtectedRatio    int                     `yaml:"protected_ratio"`
	EvictionScanLimit int                     `yaml:"eviction_scan_limit"`
	ExcludeIP         any                     `yaml:"exclude_ip"`
	ExcludeDomain     ActiveRefreshDomainArgs `yaml:"exclude_domain"`
	FallbackProbe     FallbackProbeArgs       `yaml:"fallback_probe"`
}

func (a *ActiveRefreshArgs) UnmarshalYAML(node *yaml.Node) error {
	*a = ActiveRefreshArgs{}
	for node != nil && node.Kind == yaml.AliasNode && node.Alias != nil {
		node = node.Alias
	}
	if node == nil {
		return nil
	}
	if node.Kind == yaml.ScalarNode {
		var enabled bool
		if err := node.Decode(&enabled); err != nil {
			return err
		}
		a.Enabled = enabled
		return nil
	}
	maxRetryConfigured, maxIdleConfigured, trackingConfigured, err := validateActiveRefreshYAMLNode(node)
	if err != nil {
		return err
	}

	var raw activeRefreshArgsRaw
	if err := node.Decode(&raw); err != nil {
		return err
	}
	a.Enabled = raw.Enabled
	a.Threshold = raw.Threshold
	a.RequeryTimeoutMS = raw.RequeryTimeoutMS
	a.Workers = raw.Workers
	a.MaxRefreshQPS = raw.MaxRefreshQPS
	a.RefreshBurst = raw.RefreshBurst
	a.MaxTasksPerBatch = raw.MaxTasksPerBatch
	a.MaxPendingTasks = raw.MaxPendingTasks
	a.MaxRetryTimes = raw.MaxRetryTimes
	a.maxRetryTimesConfigured = maxRetryConfigured
	a.MaxRefreshTimes = raw.MaxRefreshTimes
	a.MaxIdleTime = raw.MaxIdleTime
	a.maxIdleTimeConfigured = maxIdleConfigured
	a.trackingPolicyConfigured = trackingConfigured
	a.MaxTrackedEntries = raw.MaxTrackedEntries
	a.AdmissionHits = raw.AdmissionHits
	a.AdmissionWindow = raw.AdmissionWindow
	a.HeatHalfLife = raw.HeatHalfLife
	a.ProtectedRatio = raw.ProtectedRatio
	a.EvictionScanLimit = raw.EvictionScanLimit
	a.ExcludeIP = raw.ExcludeIP
	a.ExcludeDomain = raw.ExcludeDomain
	a.FallbackProbe = raw.FallbackProbe
	return nil
}

type Args struct {
	Size          int                     `yaml:"size"`
	LazyCacheTTL  int                     `yaml:"lazy_cache_ttl"`
	EnableECS     bool                    `yaml:"enable_ecs"`
	ExcludeIPs    []string                `yaml:"exclude_ip"`
	ExcludeDomain ActiveRefreshDomainArgs `yaml:"exclude_domain"`
	DumpFile      string                  `yaml:"dump_file"`
	DumpInterval  int                     `yaml:"dump_interval"`
	ActiveRefresh ActiveRefreshArgs       `yaml:"active_refresh"`
}

type argsRaw struct {
	Size          int                     `yaml:"size"`
	LazyCacheTTL  int                     `yaml:"lazy_cache_ttl"`
	EnableECS     bool                    `yaml:"enable_ecs"`
	ExcludeIP     interface{}             `yaml:"exclude_ip"`
	ExcludeDomain ActiveRefreshDomainArgs `yaml:"exclude_domain"`
	DumpFile      string                  `yaml:"dump_file"`
	DumpInterval  int                     `yaml:"dump_interval"`
	ActiveRefresh ActiveRefreshArgs       `yaml:"active_refresh"`
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
	a.ExcludeDomain = raw.ExcludeDomain
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
	a.ActiveRefresh.init(a.Size)
}

func activeRefreshLimitForQPS(qps float64, baseline int) int {
	// The caller applies and validates MaxRefreshQPS before reaching here.
	// Still saturate the conversion so an otherwise valid, very large QPS
	// cannot overflow int while deriving an omitted limit.
	maxInt := int(^uint(0) >> 1)
	maxQPS := float64(maxInt) * defaultActiveRefreshMaxQPS / float64(baseline)
	if math.IsInf(qps, 1) || qps >= maxQPS {
		return maxInt
	}
	scaled := qps * float64(baseline) / defaultActiveRefreshMaxQPS
	if math.IsInf(scaled, 1) || scaled >= float64(maxInt) {
		return maxInt
	}
	return max(1, int(math.Ceil(scaled)))
}

func activeRefreshMaxBatchForQPS(qps float64, maxPending int) int {
	scaled := activeRefreshLimitForQPS(qps, defaultActiveRefreshMaxBatch)
	// A tiny batch makes an already-due future heap wake the scheduler in a
	// tight series of zero-delay loops. Keep automatic batches at least as
	// large as the scheduler's normal cleanup pass, but never move more than
	// the pending queue (or its default capacity) in one lock hold.
	floor := min(activeRefreshEvictionProbes, maxPending)
	ceiling := min(defaultActiveRefreshMaxPending, maxPending)
	return min(ceiling, max(floor, scaled))
}

func (a *ActiveRefreshArgs) init(_ int) {
	utils.SetDefaultUnsignNum(&a.Threshold, defaultActiveRefreshThreshold)
	utils.SetDefaultUnsignNum(&a.RequeryTimeoutMS, defaultActiveRefreshRequeryTimeout)
	utils.SetDefaultUnsignNum(&a.Workers, defaultActiveRefreshWorkers)
	if !a.maxIdleTimeConfigured && a.MaxIdleTime == 0 {
		a.MaxIdleTime = defaultActiveRefreshMaxIdleTime
	}
	utils.SetDefaultUnsignNum(&a.MaxRefreshQPS, defaultActiveRefreshMaxQPS)
	utils.SetDefaultUnsignNum(&a.MaxPendingTasks, defaultActiveRefreshMaxPending)
	if a.RefreshBurst == 0 {
		a.RefreshBurst = activeRefreshLimitForQPS(a.MaxRefreshQPS, defaultActiveRefreshBurst)
	}
	if a.MaxTasksPerBatch == 0 {
		a.MaxTasksPerBatch = activeRefreshMaxBatchForQPS(a.MaxRefreshQPS, a.MaxPendingTasks)
	}
	if !a.maxRetryTimesConfigured && a.MaxRetryTimes == 0 {
		a.MaxRetryTimes = defaultActiveRefreshMaxRetry
	}
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
	nextBase sequence.ChainWalker
	next     sequence.ChainWalker
	expected *item
	epoch    uint64
	flight   refreshFlightKey
}

type refreshFlightKey struct {
	k          key
	generation uint64
}

type preparedCacheEntry struct {
	item            *item
	cacheExpiration time.Time
	msg             *dns.Msg
}

// restoredPopularityState is shared by queued, in-flight and locally copied
// restore entries. Dump snapshots and metadata installation therefore advance
// one decay/count baseline even while ownership moves between those views.
type restoredPopularityState struct {
	mu       sync.Mutex
	heat     float64
	heatAt   time.Time
	observed uint64
}

type decodedDumpEntry struct {
	k                      key
	item                   *item
	cacheExpiration        time.Time
	lastRealAccess         time.Time
	refreshCount           uint32
	popularityStatePresent bool
	popularityTracked      bool
	popularity             *restoredPopularityState
}

type Cache struct {
	args         *Args
	logger       *zap.Logger
	backend      *cache.Cache[key, *item]
	closeOnce    sync.Once
	closeErr     error
	closeNotify  chan struct{}
	lifecycleCtx context.Context
	cancel       context.CancelFunc
	updatedKey   atomic.Uint64
	refreshEpoch atomic.Uint64
	generation   atomic.Uint64
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
	activeRefreshEvents         *prometheus.CounterVec
	activeRefreshQueueSize      prometheus.GaugeFunc
	activeRefreshMetaSize       prometheus.GaugeFunc

	excludeNets                []*net.IPNet
	excludeDomainMatcher       domain.Matcher[struct{}]
	activeExcludeIPMatcher     netlist.Matcher
	activeExcludeDomainMatcher domain.Matcher[struct{}]
	activeExcludeDomainValid   bool
	activeRefreshExec          sequence.Executable
	activeProbe                func(context.Context, string, net.IP, time.Duration) bool

	// 异步更新架构优化
	refreshInFlight   sync.Map       // active/lazy 共用的按 key、generation 去重字典
	activeRemoved     sync.Map       // backend removal hints, drained under activeMu
	lazyTaskChan      chan *lazyTask // 工作队列
	lazyQueueSlots    chan struct{}  // copying starts only after one slot is reserved
	lazyWorkers       sync.WaitGroup // 优雅退出等待控制
	activeMu          sync.RWMutex
	activeMeta        map[key]*activeRefreshMeta
	activeSchedule    activeScheduleHeap
	activePending     activePendingHeap
	activeEviction    activeEvictionHeap
	activeProtected   int
	activeClockTicket uint64
	activeWake        chan struct{}
	activeWorkerReady chan chan *activeRefreshWork
	activeWorkers     sync.WaitGroup

	activeRestoreMu       sync.Mutex
	activeRestore         map[key]decodedDumpEntry
	activeRestoreInFlight map[key]decodedDumpEntry
	activeRestoreRunning  bool
	activeReplayNext      sequence.ChainWalker
	activeReplayBound     bool
}

type Opts struct {
	Logger                     *zap.Logger
	MetricsTag                 string
	BQ                         sequence.BQ
	ConfigBaseDir              string
	ActiveExcludeDomainMatcher domain.Matcher[struct{}]
	ExcludeDomainMatcher       domain.Matcher[struct{}]
	ActiveExcludeIPMatcher     netlist.Matcher
	ActiveRefreshExec          sequence.Executable
}

func Init(bp *coremain.BP, args any) (any, error) {
	cfg := args.(*Args)
	bq := sequence.NewBQ(bp.M(), bp.L())
	c, err := NewCacheWithError(cfg, Opts{
		Logger:        bp.L(),
		MetricsTag:    bp.Tag(),
		BQ:            bq,
		ConfigBaseDir: bp.ConfigBaseDir(),
	})
	if err != nil {
		return nil, err
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
	return NewCacheWithError(&Args{Size: size}, Opts{Logger: bq.L(), BQ: bq})
}

// NewCache preserves the historical constructor used by embedders. Invalid
// programmatic arguments are programmer errors and panic; configuration paths
// use NewCacheWithError so users receive the original validation cause.
func NewCache(args *Args, opts Opts) *Cache {
	c, err := NewCacheWithError(args, opts)
	if err != nil {
		panic(err)
	}
	return c
}

func NewCacheWithError(args *Args, opts Opts) (*Cache, error) {
	if args == nil {
		return nil, fmt.Errorf("cache args must not be nil")
	}
	if err := validateActiveRefreshBeforeDefaults(&args.ActiveRefresh); err != nil {
		return nil, err
	}
	args.init()
	if err := validateActiveRefreshArgs(&args.ActiveRefresh); err != nil {
		return nil, err
	}
	if args.ActiveRefresh.trackingPolicyConfigured && args.ActiveRefresh.MaxTrackedEntries > args.Size {
		return nil, fmt.Errorf("active_refresh.max_tracked_entries must not exceed cache size %d", args.Size)
	}
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

	activeExcludeDomainMatcher := opts.ActiveExcludeDomainMatcher
	excludeDomainMatcher := opts.ExcludeDomainMatcher
	if excludeDomainMatcher == nil {
		matcher, err := buildExcludeDomainMatcher(opts.BQ, args.ExcludeDomain)
		if err != nil {
			return nil, fmt.Errorf("exclude_domain: %w", err)
		}
		excludeDomainMatcher = matcher
	}
	activeExcludeIPMatcher := opts.ActiveExcludeIPMatcher
	activeRefreshExec := opts.ActiveRefreshExec
	if args.ActiveRefresh.Enabled {
		if activeExcludeDomainMatcher == nil {
			matcher, err := buildActiveExcludeDomainMatcher(opts.BQ, args.ActiveRefresh.ExcludeDomain)
			if err != nil {
				return nil, fmt.Errorf("active_refresh.exclude_domain: %w", err)
			}
			activeExcludeDomainMatcher = matcher
		}
		if activeExcludeIPMatcher == nil {
			var lookup activeRefreshPluginLookup
			if opts.BQ != nil && opts.BQ.M() != nil {
				lookup = opts.BQ.M().GetPlugin
			}
			matcher, err := buildActiveRefreshExcludeIPMatcher(args.ActiveRefresh.ExcludeIP, opts.ConfigBaseDir, lookup)
			if err != nil {
				return nil, err
			}
			activeExcludeIPMatcher = matcher
		}
	}

	lifecycleCtx, cancel := context.WithCancel(context.Background())
	var p *Cache
	backend := cache.NewWithRemovalCallback[key, *item](cache.Opts{Size: args.Size}, func(k key, old *item, cause cache.RemovalCause) {
		if old == nil {
			return
		}
		old.backendRemoved.Store(true)
		if cause != cache.RemovalCauseFlushed && p != nil {
			p.removeL1IfSource(k, old)
		}
		if p != nil && (cause == cache.RemovalCauseExpired || cause == cache.RemovalCauseCapacity) {
			p.noteActiveBackendRemoval(k, old)
		}
	})
	lb := map[string]string{"tag": opts.MetricsTag}
	p = &Cache{
		args:                       args,
		logger:                     logger,
		backend:                    backend,
		closeNotify:                make(chan struct{}),
		lifecycleCtx:               lifecycleCtx,
		cancel:                     cancel,
		excludeNets:                excludeNets,
		excludeDomainMatcher:       excludeDomainMatcher,
		activeExcludeIPMatcher:     activeExcludeIPMatcher,
		activeExcludeDomainMatcher: activeExcludeDomainMatcher,
		activeExcludeDomainValid:   true,
		activeRefreshExec:          activeRefreshExec,
		activeProbe:                probeCachedIP,
		lazyTaskChan:               make(chan *lazyTask, lazyTaskQueueCapacity),
		lazyQueueSlots:             make(chan struct{}, lazyTaskQueueCapacity),
		activeMeta:                 make(map[key]*activeRefreshMeta),
		activeWake:                 make(chan struct{}, 1),
		activeRestore:              make(map[key]decodedDumpEntry),
		activeRestoreInFlight:      make(map[key]decodedDumpEntry),

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
		activeRefreshEvents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:        "active_refresh_events_total",
			Help:        "Active refresh scheduler events by outcome",
			ConstLabels: lb,
		}, []string{"event"}),
		size: prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name:        "size_current",
			Help:        "Current cache size in records",
			ConstLabels: lb,
		}, func() float64 {
			return float64(backend.Len())
		}),
	}
	for _, event := range activeRefreshEventNames {
		p.activeRefreshEvents.WithLabelValues(event)
	}

	l1Budget := min(args.Size, l1TotalCap)
	baseL1Capacity := l1Budget / shardCount
	extraL1Shards := l1Budget % shardCount
	for i := 0; i < shardCount; i++ {
		capacity := baseL1Capacity
		if i < extraL1Shards {
			capacity++
		}
		p.shards[i] = &l1Shard{
			items: make(map[key]*l1Item, capacity),
			order: make([]key, capacity),
			ref:   make(map[key]bool, capacity),
		}
	}

	if args.ActiveRefresh.Enabled {
		p.activeWorkerReady = make(chan chan *activeRefreshWork, args.ActiveRefresh.Workers)
	}
	p.activeRefreshQueueSize = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "active_refresh_queue_size", Help: "Current number of queued active refresh tasks", ConstLabels: lb,
	}, func() float64 {
		p.activeMu.RLock()
		defer p.activeMu.RUnlock()
		return float64(len(p.activePending))
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
	if p.activeRefreshExec != nil {
		p.bindActiveRefreshReplay(sequence.ChainWalker{})
	}
	p.startDumpLoop()
	p.startActiveRefresh()

	return p, nil
}

// 架构优化：去除内部的 msg.Copy()，改为外部拷贝后传入，极大降低持锁时间
func (s *l1Shard) updateL1(k key, msg *dns.Msg, source *item) bool {
	if source == nil || source.backendRemoved.Load() {
		return false
	}
	s.Lock()
	defer s.Unlock()
	if source.backendRemoved.Load() {
		return false
	}
	return s.updateL1Locked(k, msg, source)
}

func (s *l1Shard) updateL1Locked(k key, msg *dns.Msg, source *item) bool {
	capacity := len(s.order)
	if capacity == 0 {
		return false
	}

	if current, ok := s.items[k]; ok {
		s.items[k] = &l1Item{
			msg: msg, storedTime: source.storedTime, expirationTime: source.expirationTime,
			domainSet: source.domainSet, upstreamOpt: copyOPT(source.upstreamOpt), source: source,
			slot: current.slot,
		}
		s.ref[k] = true
		return true
	}

	for {
		slot := s.pos
		oldKey := s.order[slot]
		if oldKey == "" {
			break
		}
		oldItem, ok := s.items[oldKey]
		if !ok || oldItem.slot != slot {
			// A callback removed this generation, or the same key was inserted
			// into another slot. The stale clock slot must not affect the new one.
			s.order[slot] = ""
			break
		}
		if s.ref[oldKey] {
			s.ref[oldKey] = false
			s.pos = (s.pos + 1) % capacity
			continue
		}
		delete(s.items, oldKey)
		delete(s.ref, oldKey)
		break
	}

	slot := s.pos
	s.items[k] = &l1Item{
		msg: msg, storedTime: source.storedTime, expirationTime: source.expirationTime,
		domainSet: source.domainSet, upstreamOpt: copyOPT(source.upstreamOpt), source: source,
		slot: slot,
	}
	s.order[slot] = k
	s.ref[k] = true
	s.pos = (slot + 1) % capacity
	return true
}

func (s *l1Shard) removeIfSource(k key, source *item) bool {
	if source == nil {
		return false
	}
	s.Lock()
	defer s.Unlock()
	current, ok := s.items[k]
	if !ok || current.source != source {
		return false
	}
	delete(s.items, k)
	delete(s.ref, k)
	if current.slot >= 0 && current.slot < len(s.order) && s.order[current.slot] == k {
		s.order[current.slot] = ""
	}
	return true
}

func (c *Cache) removeL1IfSource(k key, source *item) bool {
	shard := c.shards[k.Sum()%shardCount]
	if shard == nil {
		return false
	}
	return shard.removeIfSource(k, source)
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
		c.activeRefreshEvents,
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

// previewActiveRefreshHitWeight decides whether an uncommitted cache miss is
// worth capturing without claiming the Context's one-shot fast-cache sample.
// Only the foreground branch that actually commits may consume that sample.
func previewActiveRefreshHitWeight(qCtx *query_context.Context) uint32 {
	if qCtx == nil || qCtx.IsCacheRefresh() {
		return 0
	}
	if hits, sampled := qCtx.PeekFastCacheHits(); sampled {
		return hits
	}
	return 1
}

// inheritedForegroundActiveRefreshReady recognizes the narrow handoff where
// two foreground branches both observed an absent key, the branch that
// returned SERVFAIL consumed the shared fast-cache sample, and a later healthy
// branch replaced that transient generation. commitPreparedForegroundWithDisplaced
// has already made both generations share one activity object, so the healthy
// branch must inherit readiness without recording a synthetic extra hit.
func (c *Cache) inheritedForegroundActiveRefreshReady(updated, displaced *item, now time.Time) bool {
	if !c.activeRefreshEnabled() || updated == nil || displaced == nil ||
		updated.isTransient || !displaced.isTransient {
		return false
	}
	updatedActivity := updated.activityState()
	displacedActivity := displaced.activityState()
	if updatedActivity == nil || updatedActivity != displacedActivity {
		return false
	}
	if boundActiveRefreshMeta(displaced) != nil {
		return true
	}
	accessCount, state := snapshotActiveAdmissionState(displaced)
	if !c.activeRefreshTrackingPolicyEnabled() {
		return accessCount > 0
	}
	if uint64(uint32(state)) < uint64(c.args.ActiveRefresh.AdmissionHits) {
		return false
	}
	window := time.Duration(c.args.ActiveRefresh.AdmissionWindow) * time.Second
	start := int64(uint32(state >> 32))
	if start == 0 || window <= 0 {
		return false
	}
	nowSecond := now.Unix()
	return nowSecond < start || nowSecond-start < int64(window/time.Second)
}

func (c *Cache) reconcileForegroundActiveRefresh(
	k key,
	updated *item,
	observed *item,
	displaced *item,
	ready bool,
	replay *query_context.ReplaySnapshot,
	next sequence.ChainWalker,
	now time.Time,
	response *dns.Msg,
) {
	if ready && replay != nil {
		c.installActiveRefreshEntry(k, updated, replay, next, now, response)
		return
	}
	if ready {
		// Snapshot packing can fail for a malformed request even though the
		// upstream response is cacheable. Reuse metadata only when it is proven
		// to share the observed/displaced generation lineage.
		c.adoptExistingActiveRefreshReplay(k, updated, observed, displaced, now, response)
		return
	}

	// A below-threshold foreground replacement intentionally remains
	// untracked. Remove metadata still owned by either replaced lineage so a
	// stopped old generation cannot pin a tracking slot forever. Exact pointer
	// checks keep a concurrent handoff to updated (or a newer item) intact.
	if observed != nil {
		c.removeActiveMetaIfExpected(k, observed)
	}
	if displaced != nil && displaced != observed {
		c.removeActiveMetaIfExpected(k, displaced)
	}
	c.removeSupersededActiveMetaAfterForegroundCommit(k, updated)
}

// removeSupersededActiveMetaAfterForegroundCommit covers the absent-lookup
// case: an expired/capacity-evicted backend entry may already be gone while its
// asynchronous removal hint and active metadata still exist. In that case both
// observed and displaced are nil. Stabilize the just-committed generation with
// the normal commit lock, then remove only metadata whose owner is explicitly
// marked as no longer resident. A concurrent handoff already bound to updated
// is preserved.
func (c *Cache) removeSupersededActiveMetaAfterForegroundCommit(k key, updated *item) {
	if !c.activeRefreshEnabled() || updated == nil {
		return
	}
	c.flushMu.RLock()
	commitMu := &c.commitLocks[k.Sum()%shardCount]
	commitMu.Lock()
	current, _, present := c.backend.Get(k)
	if !present || current != updated {
		commitMu.Unlock()
		c.flushMu.RUnlock()
		return
	}

	removed := false
	c.activeMu.Lock()
	if meta := c.activeMeta[k]; meta != nil && meta.expected != nil &&
		meta.expected != updated && meta.expected.backendRemoved.Load() {
		c.removeActiveMetaLocked(k, meta)
		removed = true
	}
	c.activeMu.Unlock()
	commitMu.Unlock()
	c.flushMu.RUnlock()
	if removed {
		c.notifyActiveScheduler()
	}
}

func (c *Cache) Exec(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) error {
	c.queryTotal.Inc()
	activeRefresh := c.activeRefreshEnabled()
	if activeRefresh {
		c.bindActiveRefreshReplay(next)
	}
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
	if ok1 && v1.source != nil && !v1.source.backendRemoved.Load() && now.Before(v1.expirationTime) {
		c.hitTotal.Inc()
		if activeRefresh {
			c.observeActiveRefresh(k, v1.source, qCtx, next, now, v1.msg)
		} else {
			recordRealCacheAccess(v1.source, now)
		}
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
		if activeRefresh {
			c.observeActiveRefresh(kReal, cachedItem, qCtx, next, now, cachedResp)
		} else {
			recordRealCacheAccess(cachedItem, now)
		}
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
	if cachedItem != nil && !activeRefresh {
		recordRealCacheAccess(cachedItem, now)
	}
	var refreshReplay *query_context.ReplaySnapshot
	var refreshNext sequence.ChainWalker
	var activityWeight uint32
	activityReady := false
	activityCaptureClaimed := false
	if activeRefresh {
		if cachedItem == nil {
			// Looking up a missing key is not yet a successful cache observation.
			// Peek so a failing parallel branch cannot steal the shared sample.
			activityWeight = previewActiveRefreshHitWeight(qCtx)
		} else {
			// A real query for a privately retained expired entry is still client
			// activity even though the old bytes are not directly served.
			activityReady, activityWeight = c.recordActiveRefreshContextActivity(cachedItem, qCtx, now)
		}
		shouldCapture := activityReady ||
			(cachedItem == nil && (!c.activeRefreshTrackingPolicyEnabled() ||
				uint64(activityWeight) >= uint64(c.args.ActiveRefresh.AdmissionHits)))
		if shouldCapture && cachedItem != nil {
			activityCaptureClaimed = beginActiveRefreshCapture(cachedItem)
			shouldCapture = activityCaptureClaimed
			if !shouldCapture {
				c.activeEvent("admission_capture_deduplicated")
			}
		}
		if shouldCapture {
			var snapshotErr error
			refreshReplay, snapshotErr = qCtx.SnapshotForReplay()
			if snapshotErr != nil {
				c.logger.Debug("failed to capture foreground active refresh replay", qCtx.InfoField(), zap.Error(snapshotErr))
			} else {
				refreshNext = next.Fork()
			}
		}
		if cachedItem != nil && activityReady && refreshReplay != nil {
			retainedMsg := new(dns.Msg)
			if retainedMsg.Unpack(cachedItem.resp) == nil {
				c.installActiveRefreshEntry(kReal, cachedItem, refreshReplay, refreshNext, now, retainedMsg)
			}
		}
		if activityCaptureClaimed {
			endActiveRefreshCapture(cachedItem)
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
		if prepared, ok := c.prepareCacheEntry(qCtx, allowTransientFailure); ok {
			if committed, displaced := c.commitPreparedForegroundWithDisplaced(kReal, cachedItem, observedEpoch, prepared); committed {
				committedAt := time.Now()
				ready := activityReady
				if cachedItem == nil {
					// The CAS/commit winner is the only missing-key branch allowed to
					// claim and attribute the one-shot fast-cache aggregate. The claim
					// is protected together with admission publication, so a peer cannot
					// observe a consumed sample and stale admission state.
					ready, activityWeight = c.recordActiveRefreshContextActivity(prepared.item, qCtx, committedAt)
					if _, sharedFastCacheSample := qCtx.PeekFastCacheHits(); activityWeight == 0 && sharedFastCacheSample && !qCtx.IsCacheRefresh() {
						// A peer may have consumed and recorded this one-shot sample
						// while publishing the transient generation just displaced by
						// this healthy answer. Inherit that exact shared activity; do
						// not turn a consumed aggregate into an ordinary +1 hit.
						ready = c.inheritedForegroundActiveRefreshReady(prepared.item, displaced, committedAt)
					}
				}
				c.reconcileForegroundActiveRefresh(
					kReal, prepared.item, cachedItem, displaced, ready,
					refreshReplay, refreshNext, committedAt, prepared.msg,
				)
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
	flight := refreshFlightKey{k: k, generation: expected.generation}
	if _, loaded := c.refreshInFlight.LoadOrStore(flight, struct{}{}); loaded {
		return
	}
	// Reserve queue capacity before copying Context or forking walkers. The
	// reservation counts builders plus queued tasks, so the subsequent send is
	// guaranteed to fit unless shutdown wins the select.
	select {
	case c.lazyQueueSlots <- struct{}{}:
	default:
		c.lazyDropTotal.Inc()
		c.releaseRefreshFlight(k, expected, flight)
		return
	}
	nextBase := next.Fork()
	task := &lazyTask{
		k: k, expected: expected,
		qCtx: qCtx.CopyWithoutResponse(), nextBase: nextBase, next: nextBase.Fork(), epoch: epoch, flight: flight,
	}

	select {
	case c.lazyTaskChan <- task:
	case <-c.closeNotify:
		<-c.lazyQueueSlots
		c.releaseRefreshFlight(k, expected, flight)
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
					<-c.lazyQueueSlots
					if task != nil {
						c.runLazyUpdateTask(task)
					}
				}
			}
		}()
	}
}

func (c *Cache) runLazyUpdateTask(task *lazyTask) {
	defer c.finishLazyUpdateTask(task)
	if c.lifecycleCtx.Err() != nil || task.epoch != c.refreshEpoch.Load() {
		return
	}
	current, _, ok := c.backend.Get(task.k)
	if !ok {
		c.removeActiveMetaIfExpected(task.k, task.expected)
		return
	}
	if current != task.expected {
		return
	}
	task.qCtx.RenewTrace()
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
	c.updateActiveRefreshAfterCommit(task.k, task.expected, prepared.item, time.Now(), prepared.msg, false, 0, task.qCtx, task.nextBase)
}

func (c *Cache) finishLazyUpdateTask(task *lazyTask) {
	if task == nil {
		return
	}
	c.releaseRefreshFlight(task.k, task.expected, task.flight)
}

func (c *Cache) releaseRefreshFlight(k key, expected *item, flight refreshFlightKey) {
	c.refreshInFlight.Delete(flight)
	// Capacity/expiry hint cleanup deliberately skips inflight owners. Whether
	// this owner executed, was queue-rejected or failed midway, it therefore
	// performs one final exact-generation cleanup after releasing the claim.
	c.removeActiveMetaIfBackendMissing(k, expected)
	c.notifyActiveScheduler()
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
		resp:                  packedMsg,
		storedTime:            now,
		expirationTime:        msgExpirationTime,
		domainSet:             old.domainSet,
		upstreamOpt:           copyOPT(old.upstreamOpt),
		staleDeadline:         deadline,
		isStale:               true,
		staleSourceGeneration: old.generation,
	}
	if old.staleSourceGeneration != 0 {
		newItem.staleSourceGeneration = old.staleSourceGeneration
	}
	inheritActiveRefreshActivity(newItem, old)
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

		c.lazyWorkers.Wait()
		c.activeWorkers.Wait()
		c.dumpLoopWG.Wait()
		c.drainPendingRefreshTasks()
		if err := c.dumpCacheOnClose(); err != nil {
			c.logger.Error("failed to dump cache", zap.Error(err))
		}
		c.clearActiveRefreshState()
		c.refreshInFlight.Clear()
		c.activeRemoved.Clear()
		c.closeErr = c.backend.Close()
	})
	return c.closeErr
}

func (c *Cache) clearActiveRefreshState() {
	c.activeMu.Lock()
	for k, meta := range c.activeMeta {
		c.removeActiveMetaLocked(k, meta)
	}
	c.activeSchedule = nil
	c.activePending = nil
	c.activeEviction = nil
	c.activeProtected = 0
	c.activeClockTicket = 0
	c.activeMu.Unlock()
	c.activeRemoved.Clear()

	c.activeRestoreMu.Lock()
	clear(c.activeRestore)
	clear(c.activeRestoreInFlight)
	c.activeRestoreRunning = false
	c.activeReplayNext = sequence.ChainWalker{}
	c.activeReplayBound = false
	c.activeRestoreMu.Unlock()
}

func (c *Cache) drainPendingRefreshTasks() {
	for {
		select {
		case <-c.lazyTaskChan:
			<-c.lazyQueueSlots
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
	return c.dumpCacheInternal(false)
}

func (c *Cache) dumpCacheOnClose() error {
	return c.dumpCacheInternal(true)
}

func (c *Cache) dumpCacheInternal(allowClosed bool) error {
	c.dumpMu.Lock()
	defer c.dumpMu.Unlock()
	return c.persistDumpLocked(allowClosed, false)
}

// persistDumpLocked serializes file writers under dumpMu. When flushLocked is
// true the caller also owns flushMu for writing, so the snapshot must not try
// to acquire its normal read side again.
func (c *Cache) persistDumpLocked(allowClosed, flushLocked bool) error {
	if !allowClosed && c.lifecycleCtx.Err() != nil {
		return context.Canceled
	}

	if len(c.args.DumpFile) == 0 {
		return nil
	}
	var en int
	err := writeFileAtomically(c.args.DumpFile, func(f *os.File) error {
		var err error
		en, err = c.writeDumpInternal(f, flushLocked)
		return err
	})
	if err != nil {
		return fmt.Errorf("failed to persist dump, %w", err)
	}
	c.logger.Info("cache dumped", zap.Int("entries", en))
	return nil
}

func (c *Cache) Api() *chi.Mux {
	r := chi.NewRouter()

	flushCache := coremain.WithAsyncGC(func(w http.ResponseWriter, req *http.Request) {
		c.logger.Info("flushing cache via api")
		if c.lifecycleCtx.Err() != nil {
			http.Error(w, "cache is shutting down", http.StatusServiceUnavailable)
			return
		}
		dumpConfigured := len(c.args.DumpFile) > 0
		// Keep the global order dumpMu -> flushMu. Ordinary dumps take the same
		// order with flushMu held for reading while they snapshot the backend.
		if dumpConfigured {
			c.dumpMu.Lock()
		}
		c.flushMu.Lock()
		if c.lifecycleCtx.Err() != nil {
			c.flushMu.Unlock()
			if dumpConfigured {
				c.dumpMu.Unlock()
			}
			http.Error(w, "cache is shutting down", http.StatusServiceUnavailable)
			return
		}
		c.refreshEpoch.Add(1)
		c.backend.Flush()
		c.clearRuntimeViews(nil)
		c.updatedKey.Store(0)
		var dumpErr error
		if dumpConfigured {
			dumpErr = c.persistDumpLocked(false, true)
		}
		c.flushMu.Unlock()
		if dumpConfigured {
			c.dumpMu.Unlock()
		}
		c.notifyActiveScheduler()

		if dumpErr != nil {
			c.logger.Error("failed to dump cache after flushing", zap.Error(dumpErr))
			http.Error(w, "cache was flushed but the empty dump could not be persisted", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		if dumpConfigured {
			_, _ = w.Write([]byte("Cache flushed and the empty dump was persisted.\n"))
		} else {
			_, _ = w.Write([]byte("Cache flushed.\n"))
		}
	})
	r.Post("/flush", flushCache)
	r.Delete("/flush", flushCache)
	r.Get("/flush", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Deprecated", "true")
		w.Header().Set("Warning", `299 mosdns "GET /flush is deprecated; use POST /flush or DELETE /flush"`)
		flushCache(w, req)
	})

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
func (c *Cache) clearRuntimeViews(restored []decodedDumpEntry) bool {
	for i := 0; i < shardCount; i++ {
		c.shards[i].Lock()
		capacity := len(c.shards[i].order)
		c.shards[i].items = make(map[key]*l1Item, capacity)
		c.shards[i].order = make([]key, capacity)
		c.shards[i].pos = 0
		c.shards[i].ref = make(map[key]bool, capacity)
		c.shards[i].Unlock()
	}

	c.activeMu.Lock()
	for k, meta := range c.activeMeta {
		c.removeActiveMetaLocked(k, meta)
	}
	c.activeSchedule = nil
	c.activePending = nil
	c.activeEviction = nil
	c.activeProtected = 0
	// Keep CLOCK tickets process-monotonic. A restore batch can reserve its
	// final ordering before a concurrent runtime load clears these derived
	// views; resetting here could make the surviving reservations collide with
	// tickets allocated after the load.
	c.activeRestoreMu.Lock()
	clear(c.activeRestore)
	clear(c.activeRestoreInFlight)
	restoreEnabled := c.activeRefreshEnabled()
	if restoreEnabled {
		for _, entry := range restored {
			c.activeRestore[entry.k] = entry
		}
	}
	replayBound := restoreEnabled && len(restored) > 0 && c.activeReplayBound
	c.activeRestoreMu.Unlock()
	c.activeMu.Unlock()
	c.activeRemoved.Clear()
	return replayBound
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

func validActiveRefreshDumpState(state *ActiveRefreshState) bool {
	if state == nil || state.GetVersion() != activeRefreshDumpStateVersion {
		return false
	}
	start := state.GetAdmissionWindowStartUnix()
	hits := state.GetAdmissionHits()
	if hits == 0 {
		return start == 0
	}
	return start > 0 && uint64(start) <= uint64(^uint32(0)) && uint64(hits) <= state.GetRealAccessCount()
}

func (c *Cache) writeDump(w io.Writer) (int, error) {
	return c.writeDumpInternal(w, false)
}

func (c *Cache) writeDumpInternal(w io.Writer, flushLocked bool) (int, error) {
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

	if !flushLocked {
		c.flushMu.RLock()
	}
	now := time.Now()
	popularity := c.snapshotActiveRefreshPopularityForDump()
	entries := make([]*CachedEntry, 0, c.backend.Len())
	activities := make([]*activeActivity, 0, c.backend.Len())
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
		activities = append(activities, v.activityState())
		return nil
	}
	rangeErr := c.backend.Range(rangeFunc)
	for i, entry := range entries {
		activity := activities[i]
		accessCount, admissionState := snapshotActiveAdmissionStateFromActivity(activity)
		lastRealAccess := activity.lastRealAccess.Load()
		entry.LastRealAccessTime = time.Unix(0, lastRealAccess).Unix()
		if lastRealAccess <= 0 {
			entry.LastRealAccessTime = entry.MsgStoredTime
		}
		entry.ConsecutiveRefreshSuccesses = activity.refreshSuccesses()

		state := &ActiveRefreshState{
			Version:                  activeRefreshDumpStateVersion,
			RealAccessCount:          accessCount,
			AdmissionWindowStartUnix: int64(uint32(admissionState >> 32)),
			AdmissionHits:            uint32(admissionState),
		}
		if tracked, ok := popularity[activity]; ok {
			state.Tracked = true
			state.RealAccessCount = tracked.realAccessCount
			state.AdmissionWindowStartUnix = int64(uint32(tracked.admissionState >> 32))
			state.AdmissionHits = uint32(tracked.admissionState)
			state.Heat = tracked.heat
			state.HeatAtUnixNano = tracked.heatAt.UnixNano()
		}
		entry.ActiveRefreshState = state
	}
	if !flushLocked {
		c.flushMu.RUnlock()
	}
	if rangeErr != nil {
		_ = gw.Close()
		return en, rangeErr
	}
	// Serialize after releasing backend shard locks and the flush snapshot lock.
	// A slow disk or HTTP dump consumer must not stall ordinary cache operations.
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
		entry.item.generation = c.generation.Add(1)
		entry.item.backendRemoved.Store(false)
		c.backend.Store(entry.k, entry.item, entry.cacheExpiration)
	}
	// Loading is merge-compatible at L2, but any overwritten entry makes its
	// L1 pointer and active-refresh expectation stale.
	replayBound := c.clearRuntimeViews(entries)
	c.flushMu.Unlock()
	if replayBound {
		c.bindActiveRefreshReplay(sequence.ChainWalker{})
	}
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
			lastRealAccess := time.Unix(entry.GetLastRealAccessTime(), 0)
			if entry.GetLastRealAccessTime() <= 0 {
				// v3 dumps written before active-refresh state was added use the
				// original store time as a conservative activity fallback.
				lastRealAccess = storedTime
			}
			activity := newActiveActivity(lastRealAccess)
			activity.storeRefreshSuccesses(entry.GetConsecutiveRefreshSuccesses())
			state := entry.GetActiveRefreshState()
			statePresent := validActiveRefreshDumpState(state)
			if statePresent {
				activity.realAccessCount.Store(state.GetRealAccessCount())
				windowStart := state.GetAdmissionWindowStartUnix()
				if windowStart > now.Unix() {
					// A dump written before a wall-clock correction must not pin an
					// admission window in the future.
					windowStart = now.Unix()
				}
				if windowStart > 0 && uint64(windowStart) <= uint64(^uint32(0)) {
					activity.admissionState.Store(uint64(uint32(windowStart))<<32 | uint64(state.GetAdmissionHits()))
				}
			} else if !c.activeRefreshTrackingPolicyEnabled() {
				// Older v3 dumps had no popularity state. Preserve their legacy
				// immediate-admission baseline only when the explicit hot policy is
				// not enabled. Policy mode must wait for fresh, real admission hits.
				activity.realAccessCount.Store(1)
				activity.admissionState.Store(uint64(uint32(lastRealAccess.Unix()))<<32 | 1)
			}
			i.activity.Store(activity)
			i.upstreamOpt = copyCacheableUpstreamOPT(restored.IsEdns0())
			if c.args.LazyCacheTTL > 0 && restored.Rcode == dns.RcodeSuccess {
				i.lazyDeadline = maxTime(i.expirationTime, storedTime.Add(time.Duration(c.args.LazyCacheTTL)*time.Second))
			}
			if c.args.ActiveRefresh.Enabled && c.args.ActiveRefresh.FallbackProbe.Enabled && c.args.ActiveRefresh.FallbackProbe.MaxStale > 0 && len(collectMsgIPs(restored)) > 0 {
				i.staleDeadline = i.expirationTime.Add(time.Duration(c.args.ActiveRefresh.FallbackProbe.MaxStale) * time.Second)
			}
			k := key(string(entry.GetKey()))
			if _, ok := questionFromKey(k); !ok {
				return nil, fmt.Errorf("cache dump contains an invalid cache key")
			}
			popularityTracked := false
			var popularity *restoredPopularityState
			if statePresent && state.GetTracked() && state.GetAdmissionHits() > 0 &&
				!math.IsNaN(state.GetHeat()) && !math.IsInf(state.GetHeat(), 0) &&
				state.GetHeat() >= 0 && state.GetHeat() <= float64(state.GetRealAccessCount()) &&
				state.GetHeatAtUnixNano() > 0 {
				popularityTracked = true
				heatAt := time.Unix(0, state.GetHeatAtUnixNano())
				if heatAt.After(now) {
					heatAt = now
				}
				popularity = &restoredPopularityState{
					heat: state.GetHeat(), heatAt: heatAt, observed: state.GetRealAccessCount(),
				}
			}
			entries = append(entries, decodedDumpEntry{
				k: k, item: i, cacheExpiration: cacheExpTime,
				lastRealAccess: lastRealAccess, refreshCount: entry.GetConsecutiveRefreshSuccesses(),
				popularityStatePresent: statePresent, popularityTracked: popularityTracked,
				popularity: popularity,
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
	return buildExcludeDomainMatcher(bq, args)
}

func buildExcludeDomainMatcher(bq sequence.BQ, args ActiveRefreshDomainArgs) (domain.Matcher[struct{}], error) {
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
	for i, tag := range args.DomainSets {
		field := fmt.Sprintf("domain_sets[%d]", i)
		if bq == nil || bq.M() == nil {
			return nil, fmt.Errorf("%s: cannot resolve plugin %q without mosdns context", field, tag)
		}
		p := bq.M().GetPlugin(tag)
		if p == nil {
			return nil, fmt.Errorf("%s: plugin %q not found", field, tag)
		}
		dsProvider, ok := p.(data_provider.DomainMatcherProvider)
		if !ok || dsProvider == nil {
			return nil, fmt.Errorf("%s: plugin %q does not implement data_provider.DomainMatcherProvider", field, tag)
		}
		matcher := dsProvider.GetDomainMatcher()
		if matcher == nil {
			return nil, fmt.Errorf("%s: plugin %q returned a nil domain matcher", field, tag)
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
	return responseMatchesActiveRefreshIP(msg, c.activeExcludeIPMatcher)
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
	if matcher := c.excludeDomainMatcher; matcher != nil {
		q := qCtx.Q()
		if q != nil && len(q.Question) == 1 {
			if _, excluded := matcher.Match(q.Question[0].Name); excluded {
				return nil, false
			}
		}
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
	v.activity.Store(newActiveActivity(now))
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
	if expected != nil && prepared != nil && prepared.item != nil {
		inheritActiveRefreshActivity(prepared.item, expected)
	}
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
	return c.shards[k.Sum()%shardCount].updateL1(k, l1Msg, expected)
}

func (c *Cache) commitPreparedForeground(k key, observed *item, epoch uint64, prepared *preparedCacheEntry) bool {
	committed, _ := c.commitPreparedForegroundWithDisplaced(k, observed, epoch, prepared)
	return committed
}

func (c *Cache) commitPreparedForegroundWithDisplaced(
	k key,
	observed *item,
	epoch uint64,
	prepared *preparedCacheEntry,
) (bool, *item) {
	if prepared != nil && prepared.item != nil && observed != nil {
		inheritActiveRefreshActivity(prepared.item, observed)
	}
	var displaced *item
	committed := c.commitPreparedMatching(k, epoch, true, func(current *item, ok bool) bool {
		allowed := false
		if observed == nil {
			// The first healthy answer wins an absent-miss race, but a healthy
			// answer may heal a short-lived SERVFAIL inserted by an earlier peer.
			allowed = !ok || (current != nil && current.isTransient && !prepared.item.isTransient)
		} else {
			// Eviction or expiry can legitimately remove the observed retained item
			// while the upstream query is running. Epoch protects flush/load, so an
			// absent current value is still safe to fill. A fallback probe may also
			// replace the observed item with a short stale derivative while this real
			// query is in flight; a healthy foreground answer must win that race.
			allowed = !ok || current == observed ||
				(!prepared.item.isTransient && current != nil && current.isStale &&
					current.staleSourceGeneration == observed.generation)
		}
		if allowed && ok {
			displaced = current
			inheritActiveRefreshActivity(prepared.item, current)
		}
		return allowed
	}, prepared)
	if !committed {
		return false, nil
	}
	return true, displaced
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
	prepared.item.generation = c.generation.Add(1)
	prepared.item.backendRemoved.Store(false)
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
