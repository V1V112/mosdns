package udp_server

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
)

const (
	legacyFastCacheSize       = 4_194_304
	defaultFastCacheSize      = 262_144
	maxFastCacheSize          = legacyFastCacheSize
	fastCacheAssoc            = 4
	fastCacheInternalTTL      = 5
	fastCacheClientTTL        = 10
	fastCacheStaleRetention   = 15 * time.Second
	fastCacheKernelQueueSize  = 1024
	fastCacheKernelRetryDelay = 3 * time.Second
	fastCachePinnedMapPath    = "/sys/fs/bpf/mosdns_fast_cache"
	fastCacheKernelKeySize    = 4
	fastCacheKernelValueSize  = 528
)

type FastCacheArgs struct {
	Mode string `yaml:"mode"`
	// Size is the total number of userspace entries. Kernel map capacity is
	// owned by nft_add and cannot be changed safely from the UDP plugin.
	Size int `yaml:"size"`
}

type resolvedFastCacheMode struct {
	kernel        bool
	userspace     bool
	legacy        bool
	userspaceSize int
}

func normalizeFastCacheArgs(a *FastCacheArgs) (resolvedFastCacheMode, error) {
	if a == nil {
		return resolvedFastCacheMode{
			kernel:        true,
			legacy:        true,
			userspaceSize: legacyFastCacheSize,
		}, nil
	}

	mode := strings.ToLower(strings.TrimSpace(a.Mode))
	if mode == "" {
		return resolvedFastCacheMode{}, fmt.Errorf("fast_cache.mode must be one of off, kernel, userspace, both")
	}

	resolved := resolvedFastCacheMode{}
	switch mode {
	case "off":
		if a.Size != 0 {
			return resolved, fmt.Errorf("fast_cache.size is only valid in userspace or both mode")
		}
	case "kernel":
		if a.Size != 0 {
			return resolved, fmt.Errorf("fast_cache.size only controls the userspace cache; omit it in kernel mode")
		}
		resolved.kernel = true
	case "userspace":
		resolved.userspace = true
	case "both":
		resolved.kernel = true
		resolved.userspace = true
	default:
		return resolved, fmt.Errorf("invalid fast_cache.mode %q; must be one of off, kernel, userspace, both", a.Mode)
	}

	if resolved.userspace {
		size := a.Size
		if size == 0 {
			size = defaultFastCacheSize
		}
		if err := validateFastCacheSize(size); err != nil {
			return resolved, err
		}
		resolved.userspaceSize = size
	}

	a.Mode = mode
	if resolved.userspace {
		a.Size = resolved.userspaceSize
	}
	return resolved, nil
}

func validateFastCacheSize(size int) error {
	if size < fastCacheAssoc || size > maxFastCacheSize || size&(size-1) != 0 {
		return fmt.Errorf("fast_cache.size must be a power of two between %d and %d", fastCacheAssoc, maxFastCacheSize)
	}
	return nil
}

type eBpfCacheVal struct {
	ExpireNs uint64
	Updating uint32
	Len      uint16
	Pad      uint16
	Data     [512]byte
}

type fastCacheItem struct {
	expire   int64
	hash     uint32
	resp     []byte
	question []byte
	updating uint32
}

type fastCacheGroup [fastCacheAssoc]atomic.Pointer[fastCacheItem]

type fastCacheTable struct {
	groups []fastCacheGroup
	mask   uint64
}

func newFastCacheTable(size int) (*fastCacheTable, error) {
	if err := validateFastCacheSize(size); err != nil {
		return nil, err
	}
	groupCount := size / fastCacheAssoc
	return &fastCacheTable{
		groups: make([]fastCacheGroup, groupCount),
		mask:   uint64(groupCount - 1),
	}, nil
}

type fastKernelMap interface {
	Put(key, value any) error
	Close() error
}

type fastCacheDeps struct {
	loadKernelMap func() (fastKernelMap, error)
	now           func() time.Time
	bootNow       func() uint64
}

func defaultFastCacheDeps() fastCacheDeps {
	return fastCacheDeps{
		loadKernelMap: func() (fastKernelMap, error) {
			m, err := ebpf.LoadPinnedMap(fastCachePinnedMapPath, nil)
			if err != nil {
				return nil, err
			}
			keySize, valueSize := m.KeySize(), m.ValueSize()
			if keySize != fastCacheKernelKeySize || valueSize != fastCacheKernelValueSize {
				_ = m.Close()
				return nil, fmt.Errorf(
					"unexpected fast cache map ABI: key=%d value=%d",
					keySize,
					valueSize,
				)
			}
			return m, nil
		},
		now:     time.Now,
		bootNow: getBootTimeNano,
	}
}

type fastKernelUpdate struct {
	hash     uint32
	value    eBpfCacheVal
	priority bool
}

type fastCache struct {
	local atomic.Pointer[fastCacheTable]

	legacyLocalSize int
	kernelEnabled   bool
	updates         chan fastKernelUpdate
	reloadKernel    chan struct{}

	ctx                  context.Context
	cancel               context.CancelFunc
	closeOnce            sync.Once
	wg                   sync.WaitGroup
	closed               atomic.Bool
	enableLocalRequested atomic.Bool
	localHasEntries      atomic.Bool

	deps   fastCacheDeps
	logger *zap.Logger

	sweepCursor atomic.Uint64
}

func newFastCache(mode resolvedFastCacheMode, logger *zap.Logger) (*fastCache, error) {
	return newFastCacheWithDeps(mode, logger, defaultFastCacheDeps())
}

func newFastCacheWithDeps(mode resolvedFastCacheMode, logger *zap.Logger, deps fastCacheDeps) (*fastCache, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	if deps.loadKernelMap == nil || deps.now == nil || deps.bootNow == nil {
		return nil, fmt.Errorf("fast cache dependencies must not be nil")
	}
	ctx, cancel := context.WithCancel(context.Background())
	fc := &fastCache{
		legacyLocalSize: mode.userspaceSize,
		kernelEnabled:   mode.kernel,
		ctx:             ctx,
		cancel:          cancel,
		deps:            deps,
		logger:          logger,
	}

	if mode.userspace {
		if err := fc.enableUserspace(mode.userspaceSize); err != nil {
			cancel()
			return nil, err
		}
	}
	if mode.kernel {
		fc.updates = make(chan fastKernelUpdate, fastCacheKernelQueueSize)
		fc.reloadKernel = make(chan struct{}, 1)
		fc.wg.Add(1)
		go fc.kernelWriter()
	}
	if mode.userspace || mode.legacy {
		fc.wg.Add(1)
		go fc.localCleaner()
	}
	return fc, nil
}

func (fc *fastCache) Close() {
	if fc == nil {
		return
	}
	fc.closeOnce.Do(func() {
		fc.stop()
		fc.wg.Wait()
	})
}

func (fc *fastCache) stop() {
	if fc == nil {
		return
	}
	fc.closed.Store(true)
	fc.cancel()
}

func (fc *fastCache) enableUserspace(size int) error {
	if fc == nil || fc.local.Load() != nil {
		return nil
	}
	t, err := newFastCacheTable(size)
	if err != nil {
		return err
	}
	fc.local.CompareAndSwap(nil, t)
	return nil
}

func (fc *fastCache) userspaceEnabled() bool {
	return fc != nil && fc.local.Load() != nil
}

func (fc *fastCache) requestUserspaceEnable() {
	if fc == nil || fc.closed.Load() || fc.local.Load() != nil || fc.legacyLocalSize == 0 {
		return
	}
	fc.enableLocalRequested.Store(true)
}

func (fc *fastCache) localCapacity() int {
	if fc == nil {
		return 0
	}
	t := fc.local.Load()
	if t == nil {
		return 0
	}
	return len(t.groups) * fastCacheAssoc
}

func (fc *fastCache) requestKernelReload() {
	if fc == nil || !fc.kernelEnabled || fc.closed.Load() {
		return
	}
	select {
	case fc.reloadKernel <- struct{}{}:
	default:
	}
}

func (fc *fastCache) enqueueKernel(update fastKernelUpdate) {
	if fc == nil || !fc.kernelEnabled || fc.closed.Load() {
		return
	}
	if update.priority {
		select {
		case fc.updates <- update:
		case <-fc.ctx.Done():
		}
		return
	}
	select {
	case fc.updates <- update:
	default:
	}
}

func (fc *fastCache) kernelWriter() {
	defer fc.wg.Done()
	var m fastKernelMap
	var nextAttempt time.Time
	defer func() {
		if m != nil {
			_ = m.Close()
		}
	}()

	reset := func() {
		if m != nil {
			_ = m.Close()
			m = nil
		}
		nextAttempt = time.Time{}
	}

	for {
		select {
		case <-fc.ctx.Done():
			return
		case <-fc.reloadKernel:
			reset()
		case update := <-fc.updates:
			now := fc.deps.now()
			if m == nil && (nextAttempt.IsZero() || !now.Before(nextAttempt)) {
				loaded, err := fc.deps.loadKernelMap()
				if err != nil {
					nextAttempt = now.Add(fastCacheKernelRetryDelay)
				} else {
					m = loaded
					fc.logger.Info("fast cache kernel map connected", zap.String("path", fastCachePinnedMapPath))
				}
			}
			if m == nil {
				continue
			}
			// The task may have waited in the bounded queue. Start the kernel
			// lifetime when it is actually published, not when it was enqueued.
			update.value.ExpireNs = fc.deps.bootNow() + uint64(fastCacheInternalTTL)*uint64(time.Second)
			if err := m.Put(&update.hash, &update.value); err != nil {
				fc.logger.Warn("failed to update fast cache kernel map", zap.Error(err))
				reset()
				nextAttempt = now.Add(fastCacheKernelRetryDelay)
			}
		}
	}
}

func (fc *fastCache) localCleaner() {
	defer fc.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-fc.ctx.Done():
			return
		case now := <-ticker.C:
			if fc.enableLocalRequested.Swap(false) && fc.local.Load() == nil {
				if err := fc.enableUserspace(fc.legacyLocalSize); err != nil {
					fc.logger.Warn("failed to enable legacy userspace fast cache", zap.Error(err))
				}
			}
			if fc.localHasEntries.Load() {
				fc.sweepExpired(now)
			}
		}
	}
}

func (fc *fastCache) sweepExpired(now time.Time) {
	t := fc.local.Load()
	if t == nil || len(t.groups) == 0 {
		return
	}
	// Sweep the whole table in roughly 30 seconds. Entries remain available
	// briefly after expiry for stale-while-refresh, then their response buffers
	// can be reclaimed even if their bucket never receives another write.
	batch := (len(t.groups) + 29) / 30
	cutoff := now.Add(-fastCacheStaleRetention).Unix()
	start := fc.sweepCursor.Add(uint64(batch)) - uint64(batch)
	for i := 0; i < batch; i++ {
		g := &t.groups[(start+uint64(i))&t.mask]
		for slot := 0; slot < fastCacheAssoc; slot++ {
			item := g[slot].Load()
			if item != nil && atomic.LoadInt64(&item.expire) < cutoff {
				g[slot].CompareAndSwap(item, nil)
			}
		}
	}
}

func calcFNV1a(data []byte) uint32 {
	h := uint32(0x811c9dc5)
	n := len(data)
	for i, b := range data {
		if i < n-4 && b >= 'A' && b <= 'Z' {
			b += 32
		}
		h ^= uint32(b)
		h *= 0x01000193
	}
	return h
}

func fastQuestionWire(msg []byte) ([]byte, bool) {
	if len(msg) < 17 || binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return nil, false
	}
	offset := 12
	for {
		if offset >= len(msg) {
			return nil, false
		}
		labelLen := int(msg[offset])
		offset++
		if labelLen == 0 {
			break
		}
		if labelLen > 63 || offset+labelLen > len(msg) {
			return nil, false
		}
		offset += labelLen
	}
	if offset+4 > len(msg) || offset+4 > 256 {
		return nil, false
	}
	return msg[12 : offset+4], true
}

func equalFastQuestion(a, b []byte) bool {
	if len(a) != len(b) || len(a) < 4 {
		return false
	}
	nameEnd := len(a) - 4
	for i := 0; i < nameEnd; i++ {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 32
		}
		if y >= 'A' && y <= 'Z' {
			y += 32
		}
		if x != y {
			return false
		}
	}
	for i := nameEnd; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (fc *fastCache) lookupLocal(hash uint32, question []byte) *fastCacheItem {
	if fc == nil {
		return nil
	}
	t := fc.local.Load()
	if t == nil {
		return nil
	}
	group := &t.groups[uint64(hash)&t.mask]
	for i := 0; i < fastCacheAssoc; i++ {
		item := group[i].Load()
		if item != nil && item.hash == hash && equalFastQuestion(item.question, question) {
			return item
		}
	}
	return nil
}

func (fc *fastCache) storeLocal(item *fastCacheItem, now int64) {
	t := fc.local.Load()
	if t == nil || item == nil {
		return
	}
	group := &t.groups[uint64(item.hash)&t.mask]
	for i := 0; i < fastCacheAssoc; i++ {
		old := group[i].Load()
		if old != nil && old.hash == item.hash && equalFastQuestion(old.question, item.question) {
			group[i].Store(item)
			return
		}
	}
	for i := 0; i < fastCacheAssoc; i++ {
		if group[i].CompareAndSwap(nil, item) {
			return
		}
	}
	oldest := 0
	oldestExpire := int64(^uint64(0) >> 1)
	for i := 0; i < fastCacheAssoc; i++ {
		old := group[i].Load()
		if old == nil {
			oldest = i
			break
		}
		expire := atomic.LoadInt64(&old.expire)
		if expire < oldestExpire {
			oldestExpire = expire
			oldest = i
		}
		if expire < now {
			oldest = i
			break
		}
	}
	group[oldest].Store(item)
}

func (fc *fastCache) Store(resp []byte, priority bool) {
	if fc == nil || fc.closed.Load() || len(resp) <= 16 || len(resp) > 512 {
		return
	}
	local := fc.local.Load()
	if !fc.kernelEnabled && local == nil {
		return
	}
	if fc.kernelEnabled && local == nil {
		// Kernel-only mode can bake directly into the fixed ABI value. This
		// avoids allocating a short-lived Go response slice for every fill.
		value := eBpfCacheVal{Len: uint16(len(resp))}
		copy(value.Data[:], resp)
		bakedResp := value.Data[:len(resp)]
		question, ok := fastQuestionWire(bakedResp)
		if !ok {
			return
		}
		patchAnswerTTLs(bakedResp, fastCacheClientTTL)
		fc.enqueueKernel(fastKernelUpdate{
			hash:     calcFNV1a(question),
			value:    value,
			priority: priority,
		})
		return
	}

	bakedResp := append([]byte(nil), resp...)
	question, ok := fastQuestionWire(bakedResp)
	if !ok {
		return
	}
	patchAnswerTTLs(bakedResp, fastCacheClientTTL)

	hash := calcFNV1a(question)
	if fc.kernelEnabled {
		value := eBpfCacheVal{
			Len: uint16(len(bakedResp)),
		}
		copy(value.Data[:], bakedResp)
		fc.enqueueKernel(fastKernelUpdate{hash: hash, value: value, priority: priority})
	}

	if fc.local.Load() != nil {
		now := fc.deps.now()
		fc.storeLocal(&fastCacheItem{
			hash:     hash,
			resp:     bakedResp,
			question: question,
			expire:   now.Add(fastCacheInternalTTL * time.Second).Unix(),
		}, now.Unix())
		fc.localHasEntries.Store(true)
	}
}

func patchAnswerTTLs(msg []byte, ttl uint32) {
	if len(msg) < 12 {
		return
	}
	qdcount := binary.BigEndian.Uint16(msg[4:6])
	ancount := binary.BigEndian.Uint16(msg[6:8])
	if ancount == 0 {
		return
	}
	offset := 12
	for i := 0; i < int(qdcount); i++ {
		for offset < len(msg) {
			l := int(msg[offset])
			if l == 0 {
				offset++
				break
			}
			if l&0xC0 == 0xC0 {
				offset += 2
				break
			}
			offset += l + 1
		}
		offset += 4
	}
	for i := 0; i < int(ancount); i++ {
		for offset < len(msg) {
			l := int(msg[offset])
			if l == 0 {
				offset++
				break
			}
			if l&0xC0 == 0xC0 {
				offset += 2
				break
			}
			offset += l + 1
		}
		if offset+10 > len(msg) {
			break
		}
		offset += 4
		binary.BigEndian.PutUint32(msg[offset:offset+4], ttl)
		offset += 4
		rdlen := binary.BigEndian.Uint16(msg[offset : offset+2])
		offset += 2 + int(rdlen)
	}
}
