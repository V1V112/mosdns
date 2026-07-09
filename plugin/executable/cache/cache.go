package cache

import (
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
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
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
	"golang.org/x/sync/singleflight"
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
	dumpHeader             = "mosdns_cache_v2"
	dumpBlockSize          = 128
	dumpMaximumBlockLength = 1 << 20 // 1M block. 8kb pre entry. Should be enough.

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
	activeRefreshTaskQueueCapacity     = 4096
	maxActiveRefreshWorkers            = 256
)

const (
	adBit = 1 << iota
	cdBit
	doBit
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
	domainSet      string
}

type l1Item struct {
	msg            *dns.Msg
	storedTime     time.Time
	expirationTime time.Time
	domainSet      string
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
	Probes         []string `yaml:"probes"`
}

type fallbackProbeArgsRaw struct {
	Enabled        bool        `yaml:"enabled"`
	TimeoutMS      int         `yaml:"timeout_ms"`
	StaleExtendTTL int         `yaml:"stale_extend_ttl"`
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

	probes, err := stringListFromRaw(raw.Probes, "active_refresh.fallback_probe.probes")
	if err != nil {
		return err
	}
	a.Probes = probes
	return nil
}

type ActiveRefreshArgs struct {
	Enabled            bool                    `yaml:"enabled"`
	Threshold          int                     `yaml:"threshold"`
	Interval           int                     `yaml:"interval"`
	RequeryTimeoutMS   int                     `yaml:"requery_timeout_ms"`
	Workers            int                     `yaml:"workers"`
	MaxEntriesPerScan  int                     `yaml:"max_entries_per_scan"`
	MaxRefreshTimes    int                     `yaml:"max_refresh_times"`
	MaxIdleTime         int                     `yaml:"max_idle_time"`
	MinRefreshInterval int                     `yaml:"min_refresh_interval"`
	ExcludeIPs         []string                `yaml:"exclude_ip"`
	ExcludeDomain      ActiveRefreshDomainArgs `yaml:"exclude_domain"`
	FallbackProbe       FallbackProbeArgs       `yaml:"fallback_probe"`
}

type activeRefreshArgsRaw struct {
	Enabled            bool                    `yaml:"enabled"`
	Threshold          int                     `yaml:"threshold"`
	Interval           int                     `yaml:"interval"`
	RequeryTimeoutMS   int                     `yaml:"requery_timeout_ms"`
	Workers            int                     `yaml:"workers"`
	MaxEntriesPerScan  int                     `yaml:"max_entries_per_scan"`
	MaxRefreshTimes    int                     `yaml:"max_refresh_times"`
	MaxIdleTime         int                     `yaml:"max_idle_time"`
	MinRefreshInterval int                     `yaml:"min_refresh_interval"`
	ExcludeIP          interface{}             `yaml:"exclude_ip"`
	ExcludeDomain      ActiveRefreshDomainArgs `yaml:"exclude_domain"`
	FallbackProbe       FallbackProbeArgs       `yaml:"fallback_probe"`
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
	if len(a.Probes) == 0 {
		a.Probes = []string{"tcp:443", "tcp:80", "ping"}
	}
}

// 异步任务对象
type lazyTask struct {
	msgKey string
	qCtx   *query_context.Context
	next   sequence.ChainWalker
}

type activeRefreshTask struct {
	msgKey string
	k      key
	qCtx   *query_context.Context
	next   sequence.ChainWalker
}

type activeRefreshMeta struct {
	sync.Mutex
	qCtx         *query_context.Context
	next         sequence.ChainWalker
	lastAccess   time.Time
	lastRefresh  time.Time
	refreshCount int
}

type Cache struct {
	args         *Args
	logger       *zap.Logger
	backend      *cache.Cache[key, *item]
	lazyUpdateSF singleflight.Group
	closeOnce    sync.Once
	closeNotify  chan struct{}
	updatedKey   atomic.Uint64

	shards [shardCount]*l1Shard
	dumpMu sync.Mutex

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

	excludeNets []*net.IPNet
	activeExcludeNets          []*net.IPNet
	activeExcludeDomainMatcher domain.Matcher[struct{}]
	activeExcludeDomainArgs    ActiveRefreshDomainArgs
	activeExcludeDomainBQ      sequence.BQ
	activeExcludeDomainMu      sync.Mutex
	activeExcludeDomainErrLog  bool

	// 异步更新架构优化
	inFlight     sync.Map       // 入队去重字典
	lazyTaskChan chan *lazyTask // 工作队列
	lazyWorkers  sync.WaitGroup // 优雅退出等待控制
	activeMeta     sync.Map
	activeInFlight sync.Map
	activeTaskChan chan *activeRefreshTask
	activeWorkers  sync.WaitGroup
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

	if err := c.RegMetricsTo(prometheus.WrapRegistererWithPrefix(PluginType+"_", bp.M().GetMetricsReg())); err != nil {
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

	logger := opts.Logger
	if logger == nil {
		logger = zap.NewNop()
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
		args:                        args,
		logger:                      logger,
		backend:                     backend,
		closeNotify:                 make(chan struct{}),
		excludeNets:                 excludeNets,
		activeExcludeNets:          activeExcludeNets,
		activeExcludeDomainMatcher: activeExcludeDomainMatcher,
		activeExcludeDomainArgs:    args.ActiveRefresh.ExcludeDomain,
		activeExcludeDomainBQ:      opts.BQ,
		lazyTaskChan:               make(chan *lazyTask, lazyTaskQueueCapacity),

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
	}

	p.startWorkerPool()

	if err := p.loadDump(); err != nil {
		p.logger.Error("failed to load cache dump", zap.Error(err))
	}
	p.startDumpLoop()
	p.startActiveRefresh()

	return p
}

// 架构优化：去除内部的 msg.Copy()，改为外部拷贝后传入，极大降低持锁时间
func (s *l1Shard) updateL1(k key, msg *dns.Msg, storedTime, expirationTime time.Time, domainSet string) {
	s.Lock()
	defer s.Unlock()

	if _, ok := s.items[k]; ok {
		s.items[k] = &l1Item{msg: msg, storedTime: storedTime, expirationTime: expirationTime, domainSet: domainSet}
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

	s.items[k] = &l1Item{msg: msg, storedTime: storedTime, expirationTime: expirationTime, domainSet: domainSet}
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
	activeEnabled := c.activeRefreshEnabled()
	var activeMsgKey string
	var activeQCtx *query_context.Context
	var activeNext sequence.ChainWalker
	if activeEnabled {
		activeMsgKey = string(msgKeyBuf)
		activeQCtx = copyContextWithoutResp(qCtx)
		activeNext = next.Fork()
	}
	if ok1 && now.Before(v1.expirationTime) {
		c.hitTotal.Inc()
		if activeEnabled {
			c.resetActiveRefreshMeta(activeMsgKey, activeQCtx, activeNext, now)
		}
		r := v1.msg.Copy() // 从 L1 提取时执行 Copy，保护缓存稳定
		dnsutils.SubtractTTL(r, uint32(now.Sub(v1.storedTime).Seconds()))
		r.Id = q.Id
		qCtx.SetResponse(r)
		if v1.domainSet != "" {
			qCtx.StoreValue(query_context.KeyDomainSet, v1.domainSet)
		}

		// 极速路径 0 逃逸：归还底层切片至对象池
		keyBufferPool.Put(bufPtr)
		return nil
	}

	// L1 未命中或过期，执行安全的深拷贝生成持久化 Key
	msgKey := activeMsgKey
	if msgKey == "" {
		msgKey = string(msgKeyBuf)
	}
	kReal := key(msgKey)
	keyBufferPool.Put(bufPtr) // 拷贝完成后安全归还

	// --- L2 深度路径 ---
	cachedResp, lazyHit, domainSet := getRespFromCache(msgKey, c.backend, c.args.LazyCacheTTL > 0, expiredMsgTtl)
	if lazyHit {
		c.lazyHitTotal.Inc()
		c.doLazyUpdate(msgKey, qCtx, next)
	}
	if cachedResp != nil {
		c.hitTotal.Inc()
		if activeEnabled {
			c.resetActiveRefreshMeta(msgKey, activeQCtx, activeNext, now)
		}
		cachedResp.Id = q.Id
		qCtx.SetResponse(cachedResp)
		if domainSet != "" {
			qCtx.StoreValue(query_context.KeyDomainSet, domainSet)
		}

		if !lazyHit {
			v2, _, _ := c.backend.Get(kReal)
			if v2 != nil {
				// 极客优化 1：消除无效双重深拷贝
				// cachedResp 已经是 Unpack 后生成的新对象，直接存入 L1 复用该对象即可
				shard.updateL1(kReal, cachedResp, v2.storedTime, v2.expirationTime, v2.domainSet)
			}
		}
		return nil
	}

	err := next.ExecNext(ctx, qCtx)
	r := qCtx.R()

	if r != nil && !c.containsExcluded(r) {
		if saveRespToCache(msgKey, qCtx, c.backend, c.args.LazyCacheTTL) {
			c.updatedKey.Add(1)
			if activeEnabled {
				c.resetActiveRefreshMeta(msgKey, activeQCtx, activeNext, time.Now())
			}
			minTTL := dnsutils.GetMinimalTTL(r)
			var dset string
			if val, ok := qCtx.GetValue(query_context.KeyDomainSet); ok {
				if s, isString := val.(string); isString {
					dset = s
				}
			}
			// 在锁外部完成安全的单次 Copy
			shard.updateL1(kReal, r.Copy(), now, now.Add(time.Duration(minTTL)*time.Second), dset)
		}
	}

	return err
}

func (c *Cache) doLazyUpdate(msgKey string, qCtx *query_context.Context, next sequence.ChainWalker) {
	// 架构优化：入队去重拦截器，防过期风暴重入
	if _, loaded := c.inFlight.LoadOrStore(msgKey, struct{}{}); loaded {
		return
	}

	// 神优化：剥离庞大 Response 对象消除 qCtx.Copy() 耗时，直降 GC 开销
	oldResp := qCtx.R()
	qCtx.SetResponse(nil)
	fastCtx := qCtx.Copy()
	qCtx.SetResponse(oldResp)

	task := &lazyTask{msgKey: msgKey, qCtx: fastCtx, next: next.Fork()}

	select {
	case c.lazyTaskChan <- task:
	default:
		c.lazyDropTotal.Inc() // 队列满则丢弃，保障主干 CPU 平滑
		c.inFlight.Delete(msgKey)
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
			for task := range c.lazyTaskChan {
				c.lazyUpdateSF.Do(task.msgKey, func() (any, error) {
					defer c.lazyUpdateSF.Forget(task.msgKey)
					defer c.inFlight.Delete(task.msgKey) // 执行完从去重表摘除

					ctx, cancel := context.WithTimeout(context.Background(), defaultLazyUpdateTimeout)
					defer cancel()

					err := task.next.ExecNext(ctx, task.qCtx)
					if err != nil && err != sequence.ErrExit {
						// 极客优化 3：砍掉 Warn 级别的 I/O 锁竞争，降级为 Debug
						// 利用 Zap 特性在生产环境直接 Bypass 该方法，防止上游异常时拖死系统
						c.logger.Debug("failed to update lazy cache", task.qCtx.InfoField(), zap.Error(err))
					}

					r := task.qCtx.R()
					if r != nil && !c.containsExcluded(r) {
						if saveRespToCache(task.msgKey, task.qCtx, c.backend, c.args.LazyCacheTTL) {
							c.updatedKey.Add(1)
							k := key(task.msgKey)
							h := k.Sum()
							shard := c.shards[h%shardCount]
							minTTL := dnsutils.GetMinimalTTL(r)
							var dset string
							if val, ok := task.qCtx.GetValue(query_context.KeyDomainSet); ok {
								if s, isString := val.(string); isString {
									dset = s
								}
							}
							// 异步写回时也将 Copy 移至锁外
							shard.updateL1(k, r.Copy(), time.Now(), time.Now().Add(time.Duration(minTTL)*time.Second), dset)
						}
					}
					return nil, nil
				})
			}
		}()
	}
}

func (c *Cache) activeRefreshEnabled() bool {
	return c.args != nil && c.args.ActiveRefresh.Enabled
}

func copyContextWithoutResp(qCtx *query_context.Context) *query_context.Context {
	copied := qCtx.Copy()
	copied.SetResponse(nil)
	return copied
}

func (c *Cache) resetActiveRefreshMeta(msgKey string, qCtx *query_context.Context, next sequence.ChainWalker, now time.Time) {
	if !c.activeRefreshEnabled() || qCtx == nil {
		return
	}
	k := key(msgKey)
	v, _ := c.activeMeta.LoadOrStore(k, &activeRefreshMeta{})
	meta := v.(*activeRefreshMeta)
	meta.Lock()
	meta.qCtx = qCtx
	meta.next = next.Fork()
	meta.lastAccess = now
	meta.refreshCount = 0
	meta.Unlock()
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
		ticker := time.NewTicker(time.Duration(c.args.ActiveRefresh.Interval) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-c.closeNotify:
				return
			case now := <-ticker.C:
				c.scanActiveRefresh(now)
				c.cleanupActiveRefreshMeta(now)
			}
		}
	}()
}

func (c *Cache) scanActiveRefresh(now time.Time) {
	queued := 0
	stopIteration := errors.New("active refresh scan limit")
	err := c.backend.Range(func(k key, v *item, cacheExpirationTime time.Time) error {
		if queued >= c.args.ActiveRefresh.MaxEntriesPerScan {
			return stopIteration
		}
		if cacheExpirationTime.Before(now) {
			c.activeMeta.Delete(k)
			return nil
		}
		task := c.makeActiveRefreshTask(k, v, now)
		if task == nil {
			return nil
		}
		if _, loaded := c.activeInFlight.LoadOrStore(k, struct{}{}); loaded {
			return nil
		}
		select {
		case c.activeTaskChan <- task:
			queued++
		case <-c.closeNotify:
			c.activeInFlight.Delete(k)
			return stopIteration
		default:
			c.activeRefreshDropTotal.Inc()
			c.activeInFlight.Delete(k)
		}
		return nil
	})
	if err != nil && err != stopIteration {
		c.logger.Debug("failed to scan active refresh cache", zap.Error(err))
	}
}

func (c *Cache) makeActiveRefreshTask(k key, v *item, now time.Time) *activeRefreshTask {
	question, ok := questionFromKey(k)
	if !ok {
		return nil
	}
	if c.activeDomainExcluded(question.Name) {
		return nil
	}
	if !c.needsActiveRefresh(v, now) {
		return nil
	}
	if c.cachedRespHasActiveExcludedIP(v) {
		return nil
	}

	metaValue, ok := c.activeMeta.Load(k)
	if !ok {
		return nil
	}
	meta := metaValue.(*activeRefreshMeta)

	meta.Lock()
	defer meta.Unlock()
	if meta.qCtx == nil {
		return nil
	}
	if maxIdle := c.args.ActiveRefresh.MaxIdleTime; maxIdle > 0 && now.Sub(meta.lastAccess) > time.Duration(maxIdle)*time.Second {
		return nil
	}
	if maxRefresh := c.args.ActiveRefresh.MaxRefreshTimes; maxRefresh > 0 && meta.refreshCount >= maxRefresh {
		return nil
	}
	if minInterval := c.args.ActiveRefresh.MinRefreshInterval; minInterval > 0 && !meta.lastRefresh.IsZero() && now.Sub(meta.lastRefresh) < time.Duration(minInterval)*time.Second {
		return nil
	}

	meta.lastRefresh = now
	return &activeRefreshTask{
		msgKey: string(k),
		k:      k,
		qCtx:   meta.qCtx.Copy(),
		next:   meta.next.Fork(),
	}
}

func (c *Cache) needsActiveRefresh(v *item, now time.Time) bool {
	threshold := time.Duration(c.args.ActiveRefresh.Threshold) * time.Second
	if originalTTL := v.expirationTime.Sub(v.storedTime); originalTTL > 0 {
		threshold = min(threshold, originalTTL/3)
	}
	return v.expirationTime.Sub(now) <= threshold
}

func (c *Cache) runActiveRefreshTask(task *activeRefreshTask) {
	defer c.activeInFlight.Delete(task.k)
	c.activeRefreshTotal.Inc()
	c.markActiveRefreshAttempt(task.k)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.args.ActiveRefresh.RequeryTimeoutMS)*time.Millisecond)
	defer cancel()

	err := task.next.ExecNext(ctx, task.qCtx)
	if err != nil && !errors.Is(err, sequence.ErrExit) {
		c.logger.Debug("active refresh requery failed", task.qCtx.InfoField(), zap.Error(err))
	}
	if c.saveActiveRefreshResponse(task.msgKey, task.qCtx) {
		c.activeRefreshSuccessTotal.Inc()
		return
	}

	if c.tryFallbackProbeKeepalive(task.k) {
		c.activeRefreshProbeKeepTotal.Inc()
		return
	}
	c.activeRefreshFailedTotal.Inc()
}

func (c *Cache) saveActiveRefreshResponse(msgKey string, qCtx *query_context.Context) bool {
	r := qCtx.R()
	if r == nil || c.containsExcluded(r) || c.containsActiveExcluded(r) {
		return false
	}
	if !saveRespToCache(msgKey, qCtx, c.backend, c.args.LazyCacheTTL) {
		return false
	}

	c.updatedKey.Add(1)
	k := key(msgKey)
	shard := c.shards[k.Sum()%shardCount]
	minTTL := dnsutils.GetMinimalTTL(r)
	var dset string
	if val, ok := qCtx.GetValue(query_context.KeyDomainSet); ok {
		if s, isString := val.(string); isString {
			dset = s
		}
	}
	now := time.Now()
	shard.updateL1(k, r.Copy(), now, now.Add(time.Duration(minTTL)*time.Second), dset)
	return true
}

func (c *Cache) markActiveRefreshAttempt(k key) {
	metaValue, ok := c.activeMeta.Load(k)
	if !ok {
		return
	}
	meta := metaValue.(*activeRefreshMeta)
	meta.Lock()
	meta.refreshCount++
	meta.Unlock()
}

func (c *Cache) tryFallbackProbeKeepalive(k key) bool {
	cfg := c.args.ActiveRefresh.FallbackProbe
	if !cfg.Enabled {
		return false
	}

	v, cacheExpirationTime, ok := c.backend.Get(k)
	if !ok || v == nil {
		return false
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(v.resp); err != nil {
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
			c.activeRefreshProbeTotal.Inc()
			if probeCachedIP(probe, ip, timeout) {
				return c.extendStaleCache(k, v, cacheExpirationTime, msg, cfg.StaleExtendTTL)
			}
		}
	}
	return false
}

func (c *Cache) extendStaleCache(k key, old *item, cacheExpirationTime time.Time, msg *dns.Msg, ttl int) bool {
	if ttl <= 0 {
		return false
	}
	staleTTL := time.Duration(ttl) * time.Second
	msgToCache := copyNoOpt(msg)
	dnsutils.SetTTL(msgToCache, uint32(ttl))
	packedMsg, err := msgToCache.Pack()
	if err != nil {
		return false
	}

	now := time.Now()
	msgExpirationTime := now.Add(staleTTL)
	newItem := &item{
		resp:           packedMsg,
		storedTime:     now,
		expirationTime: msgExpirationTime,
		domainSet:      old.domainSet,
	}
	if cacheExpirationTime.Before(msgExpirationTime) {
		cacheExpirationTime = msgExpirationTime
	}
	c.backend.Store(k, newItem, cacheExpirationTime)
	c.updatedKey.Add(1)
	c.shards[k.Sum()%shardCount].updateL1(k, msgToCache.Copy(), now, msgExpirationTime, old.domainSet)
	return true
}

func (c *Cache) cleanupActiveRefreshMeta(now time.Time) {
	maxIdle := c.args.ActiveRefresh.MaxIdleTime
	if maxIdle <= 0 {
		return
	}
	expireBefore := now.Add(-time.Duration(maxIdle*2) * time.Second)
	c.activeMeta.Range(func(k, v any) bool {
		meta := v.(*activeRefreshMeta)
		meta.Lock()
		shouldDelete := !meta.lastAccess.IsZero() && meta.lastAccess.Before(expireBefore)
		meta.Unlock()
		if shouldDelete {
			c.activeMeta.Delete(k)
		}
		return true
	})
}

func (c *Cache) Close() error {
	if err := c.dumpCache(); err != nil {
		c.logger.Error("failed to dump cache", zap.Error(err))
	}
	c.closeOnce.Do(func() {
		close(c.closeNotify)
		close(c.lazyTaskChan) // 优雅关闭 Worker Pool
	})
	c.lazyWorkers.Wait() // 挂起等待落盘任务安全结束
	c.activeWorkers.Wait()
	return c.backend.Close()
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
	go func() {
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
		c.backend.Flush()

		for i := 0; i < shardCount; i++ {
			c.shards[i].Lock()
			c.shards[i].items = make(map[key]*l1Item, shardMaxSize)
			c.shards[i].order = make([]key, shardMaxSize)
			c.shards[i].pos = 0
			c.shards[i].ref = make(map[key]bool, shardMaxSize)
			c.shards[i].Unlock()
		}

		c.updatedKey.Store(0)
		c.activeMeta.Range(func(k, _ any) bool {
			c.activeMeta.Delete(k)
			return true
		})
		c.activeInFlight.Range(func(k, _ any) bool {
			c.activeInFlight.Delete(k)
			return true
		})

		go func() {
			if err := c.dumpCache(); err != nil {
				c.logger.Error("failed to dump cache after flushing", zap.Error(err))
			}
		}()

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Cache flushed and a background dump has been triggered.\n"))
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

	if len(data) < offset+2 {
		return fmt.Sprintf("invalid_key(len<3): %x", data)
	}
	qtype := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if len(data) < offset+1 {
		return fmt.Sprintf("invalid_key(len<4): %x", data)
	}
	nameLen := int(data[offset])
	offset++
	if len(data) < offset+nameLen {
		return fmt.Sprintf("invalid_key(incomplete_name): %x", data)
	}
	qname := string(data[offset : offset+nameLen])
	parts = append(parts, qname, dns.TypeToString[qtype], "IN")
	offset += nameLen

	if len(flags) > 0 {
		parts = append(parts, fmt.Sprintf("[flags:%s]", strings.Join(flags, ",")))
	}

	if offset < len(data) {
		if len(data) < offset+1 {
			parts = append(parts, "[ecs:invalid_len_byte]")
		} else {
			ecsLen := int(data[offset])
			offset++
			if len(data) < offset+ecsLen {
				parts = append(parts, "[ecs:incomplete_string]")
			} else {
				ecs := string(data[offset : offset+ecsLen])
				parts = append(parts, fmt.Sprintf("[ecs:%s]", ecs))
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
	rangeFunc := func(k key, v *item, cacheExpirationTime time.Time) error {
		if cacheExpirationTime.Before(now) {
			return nil
		}
		e := &CachedEntry{
			Key:                 []byte(k),
			CacheExpirationTime: cacheExpirationTime.Unix(),
			MsgExpirationTime:   v.expirationTime.Unix(),
			MsgStoredTime:       v.storedTime.Unix(),
			Msg:                 v.resp,
			DomainSet:           v.domainSet,
		}
		block.Entries = append(block.Entries, e)
		if len(block.Entries) >= dumpBlockSize {
			return writeBlock()
		}
		return nil
	}
	if err := c.backend.Range(rangeFunc); err != nil {
		return en, err
	}
	if len(block.GetEntries()) > 0 {
		if err := writeBlock(); err != nil {
			return en, err
		}
	}
	return en, gw.Close()
}

func (c *Cache) readDump(r io.Reader) (int, error) {
	en := 0
	gr, err := gzip.NewReader(r)
	if err != nil {
		return en, fmt.Errorf("failed to read gzip header, %w", err)
	}
	if gr.Name != dumpHeader {
		return en, fmt.Errorf("invalid or old cache dump, header is %s, want %s", gr.Name, dumpHeader)
	}

	var errReadHeaderEOF = errors.New("")
	readBlock := func() error {
		h := pool.GetBuf(8)
		defer pool.ReleaseBuf(h)
		_, err := io.ReadFull(gr, *h)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return errReadHeaderEOF
			}
			return fmt.Errorf("failed to read block header, %w", err)
		}
		u := binary.BigEndian.Uint64(*h)
		if u > dumpMaximumBlockLength {
			return fmt.Errorf("invalid header, block length is big, %d", u)
		}
		b := pool.GetBuf(int(u))
		defer pool.ReleaseBuf(b)
		_, err = io.ReadFull(gr, *b)
		if err != nil {
			return fmt.Errorf("failed to read block data, %w", err)
		}
		block := new(CacheDumpBlock)
		if err := proto.Unmarshal(*b, block); err != nil {
			return fmt.Errorf("failed to decode block data, %w", err)
		}

		en += len(block.GetEntries())
		for _, entry := range block.GetEntries() {
			cacheExpTime := time.Unix(entry.GetCacheExpirationTime(), 0)
			msgExpTime := time.Unix(entry.GetMsgExpirationTime(), 0)
			storedTime := time.Unix(entry.GetMsgStoredTime(), 0)

			i := &item{
				resp:           entry.GetMsg(),
				storedTime:     storedTime,
				expirationTime: msgExpTime,
				domainSet:      entry.GetDomainSet(),
			}
			c.backend.Store(key(entry.GetKey()), i, cacheExpTime)
		}
		return nil
	}

	for {
		err = readBlock()
		if err != nil {
			if err == errReadHeaderEOF {
				err = nil
			}
			break
		}
	}

	if err != nil {
		return en, err
	}
	return en, gr.Close()
}

func getECSClient(qCtx *query_context.Context) string {
	queryOpt := qCtx.QOpt()
	for _, o := range queryOpt.Option {
		if o.Option() == dns.EDNS0SUBNET {
			return o.String()
		}
	}
	return ""
}

func getMsgKeyBytes(q *dns.Msg, qCtx *query_context.Context, useECS bool) ([]byte, *[]byte) {
	if q.Response || q.Opcode != dns.OpcodeQuery || len(q.Question) != 1 {
		return nil, nil
	}

	question := q.Question[0]
	totalLen := 1 + 2 + 1 + len(question.Name)
	ecs := ""
	if useECS {
		ecs = getECSClient(qCtx)
		totalLen += 1 + len(ecs)
	}

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

	buf = append(buf, b)
	buf = append(buf, byte(question.Qtype>>8), byte(question.Qtype))
	buf = append(buf, byte(len(question.Name)))
	buf = append(buf, question.Name...)
	if len(ecs) > 0 {
		buf = append(buf, byte(len(ecs)))
		buf = append(buf, ecs...)
	}

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
	offset := 1
	if len(data) < offset+2 {
		return dns.Question{}, false
	}
	qtype := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	if len(data) < offset+1 {
		return dns.Question{}, false
	}
	nameLen := int(data[offset])
	offset++
	if len(data) < offset+nameLen {
		return dns.Question{}, false
	}
	return dns.Question{
		Name:   string(data[offset : offset+nameLen]),
		Qtype:  qtype,
		Qclass: dns.ClassINET,
	}, true
}

func (c *Cache) activeDomainExcluded(qname string) bool {
	matcher, buildOK := c.getActiveExcludeDomainMatcher()
	if !buildOK {
		return true
	}
	if matcher == nil {
		return false
	}
	_, ok := matcher.Match(qname)
	return ok
}

func (c *Cache) getActiveExcludeDomainMatcher() (domain.Matcher[struct{}], bool) {
	if c.activeExcludeDomainMatcher != nil {
		return c.activeExcludeDomainMatcher, true
	}
	args := c.activeExcludeDomainArgs
	if len(args.Exps)+len(args.Files)+len(args.DomainSets) == 0 {
		return nil, true
	}

	c.activeExcludeDomainMu.Lock()
	defer c.activeExcludeDomainMu.Unlock()
	if c.activeExcludeDomainMatcher != nil {
		return c.activeExcludeDomainMatcher, true
	}
	matcher, err := buildActiveExcludeDomainMatcher(c.activeExcludeDomainBQ, args)
	if err != nil {
		if !c.activeExcludeDomainErrLog {
			c.logger.Warn("invalid active_refresh.exclude_domain, active refresh will skip entries until it is valid", zap.Error(err))
			c.activeExcludeDomainErrLog = true
		}
		return nil, false
	}
	c.activeExcludeDomainMatcher = matcher
	return c.activeExcludeDomainMatcher, true
}

func (c *Cache) cachedRespHasActiveExcludedIP(v *item) bool {
	if len(c.activeExcludeNets) == 0 || v == nil {
		return false
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(v.resp); err != nil {
		return false
	}
	return c.containsActiveExcluded(msg)
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

func probeCachedIP(probe string, ip net.IP, timeout time.Duration) bool {
	if timeout <= 0 {
		timeout = time.Duration(defaultFallbackProbeTimeout) * time.Millisecond
	}
	if probe == "ping" {
		return probePing(ip, timeout)
	}
	if strings.HasPrefix(probe, "tcp:") {
		port := strings.TrimPrefix(probe, "tcp:")
		if port == "" {
			return false
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
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

func probePing(ip net.IP, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
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

func getRespFromCache(msgKey string, backend *cache.Cache[key, *item], lazyCacheEnabled bool, lazyTtl int) (*dns.Msg, bool, string) {
	v, _, _ := backend.Get(key(msgKey))
	if v != nil {
		now := time.Now()

		m := dnsMsgPool.Get().(*dns.Msg)
		defer dnsMsgPool.Put(m)

		if err := m.Unpack(v.resp); err != nil {
			return nil, false, ""
		}

		if now.Before(v.expirationTime) {
			r := m.Copy()
			dnsutils.SubtractTTL(r, uint32(now.Sub(v.storedTime).Seconds()))
			return r, false, v.domainSet
		}

		if lazyCacheEnabled {
			r := m.Copy()
			dnsutils.SetTTL(r, uint32(lazyTtl))
			return r, true, v.domainSet
		}
	}
	return nil, false, ""
}

// 极客优化 2：展平 TTL 计算逻辑，降低分支预测阻力
func saveRespToCache(msgKey string, qCtx *query_context.Context, backend *cache.Cache[key, *item], lazyCacheTtl int) bool {
	r := qCtx.R()
	if r == nil || r.Truncated != false {
		return false
	}

	var msgTtl time.Duration
	var cacheTtl time.Duration

	switch r.Rcode {
	case dns.RcodeNameError:
		msgTtl = time.Second * 30
	case dns.RcodeServerFailure:
		msgTtl = time.Second * 5
	case dns.RcodeSuccess:
		minTTL := dnsutils.GetMinimalTTL(r)
		// 展平空响应上限判断逻辑
		if len(r.Answer) == 0 && minTTL > 300 {
			minTTL = 300
		}
		msgTtl = time.Duration(minTTL) * time.Second
	}

	// 统一处理 CacheTtl (避免由于层级嵌套引起流水线打断)
	if lazyCacheTtl > 0 && r.Rcode == dns.RcodeSuccess {
		cacheTtl = time.Duration(lazyCacheTtl) * time.Second
	} else {
		cacheTtl = msgTtl
	}

	const minCacheableTTL = 5 * time.Second
	if msgTtl <= 0 {
		msgTtl = minCacheableTTL
	}
	if cacheTtl <= 0 {
		cacheTtl = minCacheableTTL
	}

	msgToCache := copyNoOpt(r)
	packedMsg, err := msgToCache.Pack()
	if err != nil {
		return false
	}

	now := time.Now()
	v := &item{
		resp:           packedMsg,
		storedTime:     now,
		expirationTime: now.Add(msgTtl),
	}

	if val, ok := qCtx.GetValue(query_context.KeyDomainSet); ok {
		if name, isString := val.(string); isString {
			v.domainSet = name
		}
	}

	backend.Store(key(msgKey), v, now.Add(cacheTtl))
	return true
}
