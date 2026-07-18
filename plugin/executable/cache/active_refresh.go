package cache

import (
	"container/heap"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

const (
	activeRefreshCoalesceWindow = 500 * time.Millisecond
	activeRefreshMaxTimeout     = time.Second
	activeRefreshMinBudget      = 50 * time.Millisecond
	activeRefreshRetryFloor     = 500 * time.Millisecond
	activeRefreshMaxTimerDelay  = time.Duration(1<<63 - 1)
	activeRefreshEvictionProbes = 64
)

var activeRefreshEventNames = [...]string{
	"scheduled",
	"executed",
	"success",
	"failed",
	"retried",
	"probe_success",
	"probe_failed",
	"stale_generation",
	"duplicate_inflight",
	"inactive_skipped",
	"excluded_domain_skipped",
	"excluded_ip_skipped",
	"expired_before_run",
	"insufficient_time",
	"rate_limited",
	"queue_dropped",
	"dump_restored_tasks",
	"admission_wait",
	"admission_ready",
	"admitted",
	"admission_capacity_rejected",
	"admission_capture_deduplicated",
	"clock_promoted",
	"clock_demoted",
	"clock_evicted",
	"fast_cache_hits_merged",
}

// refreshTask is a versioned scheduling record. Future tasks live in
// activeSchedule and are ordered by refreshAt. Once due they move to
// activePending, which is ordered by expireAt so the closest deadline wins.
type refreshTask struct {
	key           key
	refreshAt     time.Time
	expireAt      time.Time
	refreshWindow time.Duration
	generation    uint64
	retryCount    int

	meta          *activeRefreshMeta
	dueAt         time.Time
	probeOnly     bool
	scheduleIndex int
	pendingIndex  int
}

type activeRefreshMeta struct {
	k              key
	replay         *query_context.ReplaySnapshot
	next           sequence.ChainWalker
	expected       *item
	task           *refreshTask
	evictionIndex  int
	referenced     atomic.Bool
	protected      bool
	heat           float64
	heatAt         time.Time
	heatObserved   uint64
	evictionTicket uint64
	// accessWriters pins this metadata while a lock-free real hit publishes its
	// counter, idle timestamp and CLOCK reference bit. Eviction first invalidates
	// the bound handle and then requires this count to be zero, so a hit that
	// acquired the handle cannot be mistaken for activity already included in an
	// eviction sample while it is only partially published.
	accessWriters atomic.Uint64

	// boundGeneration is the generation for which expected.activeMeta points to
	// this metadata. Hits use it as a lock-free validation token; all task and
	// heap mutations remain protected by activeMu.
	boundGeneration atomic.Uint64
	stopped         atomic.Bool
}

type activeRefreshWork struct {
	task     *refreshTask
	replay   *query_context.ReplaySnapshot
	qCtx     *query_context.Context
	nextBase sequence.ChainWalker
	next     sequence.ChainWalker
	expected *item
	epoch    uint64
	// activityEpoch is captured before the upstream refresh starts. A real hit
	// atomically changes it and clears the consecutive-success count, so commit
	// can conditionally increment without a Store(0)/Add(1) race.
	activityEpoch uint32
	flight        refreshFlightKey
}

type activeScheduleHeap []*refreshTask

func (h activeScheduleHeap) Len() int { return len(h) }
func (h activeScheduleHeap) Less(i, j int) bool {
	if h[i].dueAt.Equal(h[j].dueAt) {
		return h[i].expireAt.Before(h[j].expireAt)
	}
	return h[i].dueAt.Before(h[j].dueAt)
}
func (h activeScheduleHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].scheduleIndex = i
	h[j].scheduleIndex = j
}
func (h *activeScheduleHeap) Push(v any) {
	t := v.(*refreshTask)
	t.scheduleIndex = len(*h)
	*h = append(*h, t)
}
func (h *activeScheduleHeap) Pop() any {
	old := *h
	n := len(old)
	t := old[n-1]
	old[n-1] = nil
	t.scheduleIndex = -1
	*h = old[:n-1]
	return t
}

type activePendingHeap []*refreshTask

func (h activePendingHeap) Len() int { return len(h) }
func (h activePendingHeap) Less(i, j int) bool {
	if h[i].expireAt.Equal(h[j].expireAt) {
		return h[i].refreshAt.Before(h[j].refreshAt)
	}
	return h[i].expireAt.Before(h[j].expireAt)
}
func (h activePendingHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].pendingIndex = i
	h[j].pendingIndex = j
}
func (h *activePendingHeap) Push(v any) {
	t := v.(*refreshTask)
	t.pendingIndex = len(*h)
	*h = append(*h, t)
}
func (h *activePendingHeap) Pop() any {
	old := *h
	n := len(old)
	t := old[n-1]
	old[n-1] = nil
	t.pendingIndex = -1
	*h = old[:n-1]
	return t
}

// activeEvictionHeap is shared by both modes. Explicit popularity policy uses
// non-zero CLOCK rotation tickets; legacy mode leaves every ticket at zero and
// therefore falls back to latest-expiration (least urgent) ordering. It is
// separate from activeSchedule because scheduled, pending, dispatched and
// stopped metadata all need to remain eligible for capacity cleanup.
type activeEvictionHeap []*activeRefreshMeta

func (h activeEvictionHeap) Len() int { return len(h) }
func (h activeEvictionHeap) Less(i, j int) bool {
	if h[i].evictionTicket != h[j].evictionTicket {
		return h[i].evictionTicket < h[j].evictionTicket
	}
	if h[i].expected == nil || h[j].expected == nil {
		return h[i].expected == nil && h[j].expected != nil
	}
	iExpiration := activeMetaExpiration(h[i])
	jExpiration := activeMetaExpiration(h[j])
	if iExpiration.Equal(jExpiration) {
		return h[i].k > h[j].k
	}
	return iExpiration.After(jExpiration)
}
func (h activeEvictionHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].evictionIndex = i
	h[j].evictionIndex = j
}
func (h *activeEvictionHeap) Push(v any) {
	meta := v.(*activeRefreshMeta)
	meta.evictionIndex = len(*h)
	*h = append(*h, meta)
}
func (h *activeEvictionHeap) Pop() any {
	old := *h
	n := len(old)
	meta := old[n-1]
	old[n-1] = nil
	meta.evictionIndex = -1
	*h = old[:n-1]
	return meta
}

func activeMetaExpiration(meta *activeRefreshMeta) time.Time {
	if meta == nil || meta.expected == nil {
		return time.Time{}
	}
	return meta.expected.expirationTime
}

// refreshTokenBucket is scheduler-owned. Keeping it in the scheduler goroutine
// means validation and token consumption form one serialized decision without
// a goroutine per waiter.
type refreshTokenBucket struct {
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func newRefreshTokenBucket(qps float64, burst int, now time.Time) refreshTokenBucket {
	b := refreshTokenBucket{rate: qps, burst: float64(burst), last: now}
	b.tokens = b.burst
	return b
}

func (b *refreshTokenBucket) refill(now time.Time) {
	if now.Before(b.last) {
		b.last = now
		return
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = math.Min(b.burst, b.tokens+elapsed*b.rate)
		b.last = now
	}
}

func (b *refreshTokenBucket) available(now time.Time) bool {
	b.refill(now)
	return b.tokens >= 1
}

func (b *refreshTokenBucket) take(now time.Time) bool {
	if !b.available(now) {
		return false
	}
	b.tokens--
	return true
}

func (b *refreshTokenBucket) delay(now time.Time) time.Duration {
	b.refill(now)
	if b.tokens >= 1 {
		return 0
	}
	seconds := (1 - b.tokens) / b.rate
	if seconds <= 0 {
		return 0
	}
	nanos := seconds * float64(time.Second)
	if math.IsInf(nanos, 1) || nanos >= float64(activeRefreshMaxTimerDelay) {
		return activeRefreshMaxTimerDelay
	}
	return time.Duration(math.Ceil(nanos))
}

func calculateRefreshWindow(originalTTL, threshold time.Duration) (time.Duration, bool) {
	if originalTTL <= 0 || threshold <= 0 {
		return 0, false
	}
	baseWindow := min(threshold, originalTTL/3)
	safetyWindow := min(originalTTL/2, 2*time.Second)
	window := min(threshold, max(baseWindow, safetyWindow))
	if window <= 0 || window >= originalTTL {
		return 0, false
	}
	return window, true
}

func calculateRefreshAt(v *item, threshold time.Duration) (time.Time, time.Duration, bool) {
	if v == nil || v.storedTime.IsZero() || v.expirationTime.IsZero() {
		return time.Time{}, 0, false
	}
	originalTTL := v.expirationTime.Sub(v.storedTime)
	window, ok := calculateRefreshWindow(originalTTL, threshold)
	if !ok {
		return time.Time{}, 0, false
	}
	refreshAt := v.expirationTime.Add(-window)
	if !refreshAt.Before(v.expirationTime) {
		return time.Time{}, 0, false
	}
	return refreshAt, window, true
}

func calculateRetryDelay(remaining, refreshWindow time.Duration) time.Duration {
	if remaining <= 0 || refreshWindow <= 0 {
		return 0
	}
	delay := min(remaining/3, refreshWindow/2)
	return max(activeRefreshRetryFloor, delay)
}

func calculateRequeryTimeout(configured, remaining time.Duration) (time.Duration, bool) {
	if configured <= 0 || remaining <= 0 {
		return 0, false
	}
	configured = min(configured, activeRefreshMaxTimeout)
	actual := min(configured, remaining/2)
	if actual < activeRefreshMinBudget || actual >= remaining {
		return 0, false
	}
	return actual, true
}

func calculateProbeTimeout(configured, remainingBudget time.Duration) (time.Duration, bool) {
	if configured <= 0 || remainingBudget <= 0 {
		return 0, false
	}
	actual := min(configured, remainingBudget)
	return actual, actual > 0
}

func (c *Cache) activeRefreshEnabled() bool {
	return c.args != nil && c.args.ActiveRefresh.Enabled && c.lifecycleCtx.Err() == nil
}

func (c *Cache) activeEvent(name string) {
	if c.activeRefreshEvents != nil {
		c.activeRefreshEvents.WithLabelValues(name).Inc()
	}
}

func (c *Cache) activeEventAdd(name string, value uint64) {
	if value > 0 && c.activeRefreshEvents != nil {
		c.activeRefreshEvents.WithLabelValues(name).Add(float64(value))
	}
}

// bindActiveMetaHandleLocked publishes the lock-free hit-path handle only
// after meta has a live task for expected. The caller must hold activeMu.
func bindActiveMetaHandleLocked(meta *activeRefreshMeta, expected *item) {
	if meta == nil || expected == nil || meta.expected != expected || meta.task == nil {
		return
	}
	meta.boundGeneration.Store(expected.generation)
	expected.activeMeta.Store(meta)
}

// clearActiveMetaHandleLocked invalidates the generation token before
// detaching the pointer. A concurrent hit that already loaded the pointer will
// therefore take the version-validating slow path instead of treating a
// replaced or stopped generation as tracked. The caller must hold activeMu.
func clearActiveMetaHandleLocked(meta *activeRefreshMeta) {
	if meta == nil {
		return
	}
	meta.boundGeneration.Store(0)
	if expected := meta.expected; expected != nil {
		expected.activeMeta.CompareAndSwap(meta, nil)
	}
}

func clearActiveMetaTaskLocked(meta *activeRefreshMeta) {
	if meta == nil {
		return
	}
	clearActiveMetaHandleLocked(meta)
	meta.task = nil
}

func saturatingAddUint64(dst *atomic.Uint64, delta uint64) uint64 {
	if dst == nil || delta == 0 {
		if dst == nil {
			return 0
		}
		return dst.Load()
	}
	for current := dst.Load(); ; current = dst.Load() {
		updated := current + delta
		if updated < current {
			updated = ^uint64(0)
		}
		if dst.CompareAndSwap(current, updated) {
			return updated
		}
	}
}

func updateActiveAdmission(v *item, now time.Time, window time.Duration, weight uint32) uint32 {
	if v == nil || weight == 0 || window <= 0 {
		return 0
	}
	activity := v.activityState()
	nowSecond := now.Unix()
	if nowSecond < 1 {
		nowSecond = 1
	}
	for state := activity.admissionState.Load(); ; state = activity.admissionState.Load() {
		start := int64(uint32(state >> 32))
		hits := uint32(state)
		if start == 0 {
			start = nowSecond
			hits = 0
		} else if nowSecond < start {
			// Request goroutines can reach this CAS out of timestamp order. Keep
			// the newer window and count this hit in it instead of moving time
			// backwards and discarding concurrent activity.
			nowSecond = start
		} else if nowSecond-start >= int64(window/time.Second) {
			start = nowSecond
			hits = 0
		}
		updatedHits := hits + weight
		if updatedHits < hits {
			updatedHits = ^uint32(0)
		}
		updated := uint64(uint32(start))<<32 | uint64(updatedHits)
		if activity.admissionState.CompareAndSwap(state, updated) {
			return updatedHits
		}
	}
}

// snapshotActiveAdmissionState observes the lifetime counter and admission
// window from the same completed untracked-hit publication. The per-lineage
// lock is not used after metadata is bound on the normal hit path.
func snapshotActiveAdmissionState(v *item) (accessCount, admissionState uint64) {
	if v == nil {
		return 0, 0
	}
	activity := v.activityState()
	activity.admissionMu.Lock()
	accessCount = activity.realAccessCount.Load()
	admissionState = activity.admissionState.Load()
	activity.admissionMu.Unlock()
	return accessCount, admissionState
}

type activeRefreshActivityWriter struct {
	activity        *activeActivity
	meta            *activeRefreshMeta
	admissionLocked bool
}

// acquireActiveRefreshActivityWriter protects the one-shot sample claim and
// every activity-field write as one publication. Tracked entries use only the
// metadata writer pin. An untracked lineage uses its own short-lived mutex and
// rechecks the handle after locking, so metadata installation and a foreground
// handoff cannot observe a consumed sample before its admission state exists.
func acquireActiveRefreshActivityWriter(expected *item) activeRefreshActivityWriter {
	writer := activeRefreshActivityWriter{activity: expected.activityState()}
	writer.meta = acquireActiveRefreshMetaWriter(expected)
	if writer.meta != nil {
		return writer
	}
	writer.activity.admissionMu.Lock()
	writer.admissionLocked = true
	writer.meta = acquireActiveRefreshMetaWriter(expected)
	return writer
}

func (writer *activeRefreshActivityWriter) release() {
	if writer == nil {
		return
	}
	if writer.meta != nil {
		releaseActiveRefreshMetaWriter(writer.meta)
	}
	if writer.admissionLocked {
		writer.activity.admissionMu.Unlock()
	}
}

func (c *Cache) publishActiveRefreshActivity(
	expected *item,
	now time.Time,
	weight uint32,
	writer *activeRefreshActivityWriter,
) bool {
	if writer == nil || writer.activity == nil || weight == 0 {
		if writer != nil {
			writer.release()
		}
		return false
	}
	saturatingAddUint64(&writer.activity.realAccessCount, uint64(weight))
	writer.activity.recordRealAccess(now)
	tracked := writer.meta != nil
	ready := tracked || !c.activeRefreshTrackingPolicyEnabled()
	if tracked {
		if c.activeRefreshTrackingPolicyEnabled() {
			writer.meta.referenced.Store(true)
		}
	} else if c.activeRefreshTrackingPolicyEnabled() {
		hits := updateActiveAdmission(
			expected,
			now,
			time.Duration(c.args.ActiveRefresh.AdmissionWindow)*time.Second,
			weight,
		)
		ready = uint64(hits) >= uint64(c.args.ActiveRefresh.AdmissionHits)
	}
	writer.release()

	if weight > 1 {
		c.activeEventAdd("fast_cache_hits_merged", uint64(weight))
	}
	if !tracked && c.activeRefreshTrackingPolicyEnabled() {
		if ready {
			c.activeEvent("admission_ready")
		} else {
			c.activeEvent("admission_wait")
		}
	}
	return ready
}

// recordActiveRefreshActivity publishes an explicit activity weight. It is
// primarily used by internal handoff/restore paths and deterministic tests.
func (c *Cache) recordActiveRefreshActivity(expected *item, now time.Time, weight uint32) bool {
	if !c.activeRefreshEnabled() || expected == nil || weight == 0 {
		return false
	}
	writer := acquireActiveRefreshActivityWriter(expected)
	return c.publishActiveRefreshActivity(expected, now, weight, &writer)
}

// recordActiveRefreshContextActivity claims a Context's shared one-shot fast
// cache sample only after the target lineage is protected. A parallel branch
// can therefore never see "sample consumed" together with pre-publication
// admission state.
func (c *Cache) recordActiveRefreshContextActivity(expected *item, qCtx *query_context.Context, now time.Time) (ready bool, weight uint32) {
	if !c.activeRefreshEnabled() || expected == nil || qCtx == nil || qCtx.IsCacheRefresh() {
		return false, 0
	}
	writer := acquireActiveRefreshActivityWriter(expected)
	weight = activeRefreshHitWeight(qCtx)
	return c.publishActiveRefreshActivity(expected, now, weight, &writer), weight
}

func activeRefreshHitWeight(qCtx *query_context.Context) uint32 {
	if qCtx == nil || qCtx.IsCacheRefresh() {
		return 0
	}
	if hits, sampled := qCtx.TakeFastCacheHits(); sampled {
		return hits
	}
	return 1
}

func boundActiveRefreshMeta(expected *item) *activeRefreshMeta {
	if expected == nil {
		return nil
	}
	meta := expected.activeMeta.Load()
	if meta == nil || meta.boundGeneration.Load() != expected.generation || meta.stopped.Load() {
		return nil
	}
	return meta
}

// acquireActiveRefreshMetaWriter establishes the real-hit side of the
// hit/eviction linearization protocol. Incrementing before revalidation closes
// the load-vs-clear race: either eviction observes the writer, or this caller
// observes the cleared/replaced handle and publishes through the untracked slow
// path instead. The returned pin must cover every activity field write.
func acquireActiveRefreshMetaWriter(expected *item) *activeRefreshMeta {
	if expected == nil {
		return nil
	}
	for {
		meta := expected.activeMeta.Load()
		if meta == nil || meta.boundGeneration.Load() != expected.generation || meta.stopped.Load() {
			return nil
		}
		meta.accessWriters.Add(1)
		if expected.activeMeta.Load() == meta &&
			meta.boundGeneration.Load() == expected.generation && !meta.stopped.Load() {
			return meta
		}
		meta.accessWriters.Add(^uint64(0))
		// A generation handoff may have replaced the handle between the two
		// reads. Retry only when another live handle is already visible.
		if expected.activeMeta.Load() == nil {
			return nil
		}
	}
}

func releaseActiveRefreshMetaWriter(meta *activeRefreshMeta) {
	if meta != nil {
		meta.accessWriters.Add(^uint64(0))
	}
}

// beginActiveRefreshCapture elects one request to build the replay snapshot
// for an untracked cache generation. Activity accounting remains lock-free for
// every request, but concurrent threshold crossings no longer duplicate a
// potentially large Context copy only to race at metadata installation.
func beginActiveRefreshCapture(expected *item) bool {
	if expected == nil || boundActiveRefreshMeta(expected) != nil {
		return false
	}
	if !expected.admissionCapture.CompareAndSwap(false, true) {
		return false
	}
	// Metadata may have become visible between the optimistic check and claim.
	if boundActiveRefreshMeta(expected) != nil {
		expected.admissionCapture.Store(false)
		return false
	}
	return true
}

func endActiveRefreshCapture(expected *item) {
	if expected != nil {
		expected.admissionCapture.Store(false)
	}
}

func (c *Cache) observeActiveRefresh(k key, expected *item, qCtx *query_context.Context, next sequence.ChainWalker, now time.Time, response *dns.Msg) {
	if !c.activeRefreshEnabled() || expected == nil || qCtx == nil {
		return
	}
	// Ordinary hits touch only entry-owned atomics and this generation-checked
	// handle. In particular, they do not contend on the global activeMu. The
	// idle sentinel may wake once at its previous deadline; prepareActiveWork
	// rechecks lastRealAccess and returns it to the future heap when the hit
	// extended the idle boundary.
	if ready, _ := c.recordActiveRefreshContextActivity(expected, qCtx, now); !ready {
		return
	}
	if meta := boundActiveRefreshMeta(expected); meta != nil {
		if c.activeRefreshTrackingPolicyEnabled() {
			meta.referenced.Store(true)
		}
		return
	}
	if !beginActiveRefreshCapture(expected) {
		c.activeEvent("admission_capture_deduplicated")
		return
	}
	defer endActiveRefreshCapture(expected)

	// k may be a zero-copy view over a pooled request buffer on the L1 path.
	durableKey := key(strings.Clone(string(k)))
	c.captureActiveRefreshReplay(durableKey, expected, qCtx, next, now, response)
}

func (c *Cache) trackActiveRefresh(k key, expected *item, qCtx *query_context.Context, next sequence.ChainWalker, now time.Time, response *dns.Msg) {
	if !c.activeRefreshEnabled() || expected == nil || qCtx == nil || !c.activeExcludeDomainValid {
		return
	}
	if ready, _ := c.recordActiveRefreshContextActivity(expected, qCtx, now); !ready {
		return
	}
	if meta := boundActiveRefreshMeta(expected); meta != nil {
		c.activeMu.Lock()
		if c.activeMeta[k] == meta && meta.expected == expected && meta.task != nil {
			c.recalculateScheduledDueLocked(meta, now)
			if c.activeRefreshTrackingPolicyEnabled() {
				meta.referenced.Store(true)
			}
		}
		c.activeMu.Unlock()
		c.notifyActiveScheduler()
		return
	}
	if !beginActiveRefreshCapture(expected) {
		c.activeEvent("admission_capture_deduplicated")
		return
	}
	defer endActiveRefreshCapture(expected)
	c.captureActiveRefreshReplay(k, expected, qCtx, next, now, response)
}

func (c *Cache) captureActiveRefreshReplay(k key, expected *item, qCtx *query_context.Context, next sequence.ChainWalker, now time.Time, response *dns.Msg) {
	replay, err := qCtx.SnapshotForReplay()
	if err != nil {
		c.logger.Debug("failed to capture active refresh replay", qCtx.InfoField(), zap.Error(err))
		return
	}
	// Snapshot creation and walker forking can allocate. Keep both outside the
	// cache commit and active scheduler locks; the locked path only validates
	// the generation, swaps immutable pointers and updates heaps.
	c.installActiveRefreshEntry(k, expected, replay, next.Fork(), now, response)
}

func (c *Cache) installActiveRefreshEntry(k key, expected *item, replay *query_context.ReplaySnapshot, next sequence.ChainWalker, now time.Time, response *dns.Msg) {
	if !c.activeRefreshEnabled() || expected == nil || replay == nil || !c.activeExcludeDomainValid {
		return
	}
	// Serialize observation with replacement of this key. Otherwise an old L1
	// hit can validate the old pointer, lose a race with StoreIf, and overwrite
	// (or delete) metadata for the new generation.
	c.flushMu.RLock()
	commitMu := &c.commitLocks[k.Sum()%shardCount]
	commitMu.Lock()
	current, _, present := c.backend.Get(k)
	if !present || current != expected || current.generation != expected.generation {
		commitMu.Unlock()
		c.flushMu.RUnlock()
		return
	}
	question, validQuestion := questionFromKey(k)
	excludedDomain := !validQuestion || c.activeDomainExcluded(question.Name)
	excludedIP := response != nil && c.containsActiveExcluded(response)
	c.activeMu.Lock()
	meta := c.activeMeta[k]
	if excludedDomain || excludedIP {
		if meta != nil {
			c.removeActiveMetaLocked(k, meta)
		}
		c.activeMu.Unlock()
		commitMu.Unlock()
		c.flushMu.RUnlock()
		if excludedDomain {
			c.activeEvent("excluded_domain_skipped")
		} else {
			c.activeEvent("excluded_ip_skipped")
		}
		c.notifyActiveScheduler()
		return
	}
	// Another path may have published the same generation while the elected
	// owner was building its snapshot outside the locks. Keep the already-live
	// replay/task instead of letting the slower builder overwrite it.
	if meta != nil && expected.admissionCapture.Load() && meta.expected == expected &&
		meta.task != nil && boundActiveRefreshMeta(expected) == meta {
		if c.activeRefreshTrackingPolicyEnabled() {
			meta.referenced.Store(true)
		}
		c.activeMu.Unlock()
		commitMu.Unlock()
		c.flushMu.RUnlock()
		return
	}
	if meta == nil {
		if !c.ensureActiveMetaSlotLocked(expected) {
			c.activeMu.Unlock()
			commitMu.Unlock()
			c.flushMu.RUnlock()
			return
		}
		meta = &activeRefreshMeta{k: k, expected: expected, evictionIndex: -1}
		c.addActiveMetaLocked(k, meta)
		if c.activeRefreshTrackingPolicyEnabled() {
			c.activeEvent("admitted")
		}
	}
	sameGeneration := meta.expected == expected
	meta.replay = replay
	meta.next = next
	meta.stopped.Store(false)
	// A real hit must not postpone an already scheduled TTL deadline. This is
	// especially important for an expired answer whose existing task is a
	// fallback probe. Rebuild only when the cache generation changed or the
	// previous task was stopped/dropped.
	if !sameGeneration || meta.task == nil {
		scheduled := false
		if now.Before(expected.expirationTime) {
			scheduled = c.scheduleEntryLocked(meta, expected, 0, false, now, false)
		} else if cfg := c.args.ActiveRefresh.FallbackProbe; cfg.Enabled &&
			!expected.staleDeadline.IsZero() && now.Before(expected.staleDeadline) {
			scheduled = c.scheduleEntryLocked(meta, expected, 0, true, now, false)
		}
		if !scheduled {
			c.removeActiveMetaLocked(k, meta)
		}
	} else {
		c.recalculateScheduledDueLocked(meta, now)
		bindActiveMetaHandleLocked(meta, expected)
	}
	c.activeMu.Unlock()
	commitMu.Unlock()
	c.flushMu.RUnlock()
	c.notifyActiveScheduler()
}

func activeRefreshLineageGeneration(v *item) uint64 {
	if v == nil {
		return 0
	}
	if v.staleSourceGeneration != 0 {
		return v.staleSourceGeneration
	}
	return v.generation
}

func canAdoptActiveRefreshReplay(metaExpected, updated, observed, displaced *item) bool {
	if metaExpected == nil || updated == nil {
		return false
	}
	if metaExpected == updated || metaExpected == observed || metaExpected == displaced {
		return true
	}
	if observed == nil {
		return false
	}
	root := activeRefreshLineageGeneration(observed)
	if root == 0 || activeRefreshLineageGeneration(metaExpected) != root {
		return false
	}
	return displaced == nil || activeRefreshLineageGeneration(displaced) == root
}

func storeActiveRefreshAccessMax(dst *atomic.Int64, candidate int64) {
	if dst == nil || candidate <= 0 {
		return
	}
	for current := dst.Load(); candidate > current; current = dst.Load() {
		if dst.CompareAndSwap(current, candidate) {
			return
		}
	}
}

// adoptExistingActiveRefreshReplay handles the rare foreground path where the
// request cannot be packed into a fresh replay snapshot. Only metadata proven
// to belong to the entry actually observed or displaced by the foreground
// commit may cross to updated; unrelated same-key metadata is removed.
func (c *Cache) adoptExistingActiveRefreshReplay(
	k key,
	updated, observed, displaced *item,
	now time.Time,
	response *dns.Msg,
) {
	if !c.activeRefreshEnabled() || updated == nil || !c.activeExcludeDomainValid {
		return
	}
	c.flushMu.RLock()
	commitMu := &c.commitLocks[k.Sum()%shardCount]
	commitMu.Lock()
	current, _, present := c.backend.Get(k)
	if !present || current != updated || current.generation != updated.generation {
		commitMu.Unlock()
		c.flushMu.RUnlock()
		return
	}
	question, validQuestion := questionFromKey(k)
	excludedDomain := !validQuestion || c.activeDomainExcluded(question.Name)
	excludedIP := response != nil && c.containsActiveExcluded(response)

	c.activeMu.Lock()
	meta := c.activeMeta[k]
	if meta == nil {
		c.activeMu.Unlock()
		commitMu.Unlock()
		c.flushMu.RUnlock()
		return
	}
	previous := meta.expected
	if excludedDomain || excludedIP || meta.replay == nil ||
		!canAdoptActiveRefreshReplay(previous, updated, observed, displaced) {
		c.removeActiveMetaLocked(k, meta)
		c.activeMu.Unlock()
		commitMu.Unlock()
		c.flushMu.RUnlock()
		if excludedDomain {
			c.activeEvent("excluded_domain_skipped")
		} else if excludedIP {
			c.activeEvent("excluded_ip_skipped")
		}
		c.notifyActiveScheduler()
		return
	}

	sameGeneration := previous == updated
	if !sameGeneration {
		// Invalidating the old handle before the reads below makes an overlapping
		// real hit either visible to these loads or generation-local afterwards.
		c.removeMetaTaskLocked(meta)
	}
	// commitPreparedForegroundWithDisplaced published updated with the activity
	// pointer of the exact observed/displaced lineage. Never replace that pointer
	// after publication; concurrent old/new hits already update the same atomics.
	if !sameGeneration {
		c.setActiveMetaExpectedLocked(meta, updated)
	}
	meta.stopped.Store(false)
	if !sameGeneration || meta.task == nil {
		scheduled := false
		if now.Before(updated.expirationTime) {
			scheduled = c.scheduleEntryLocked(meta, updated, 0, false, now, false)
		} else if cfg := c.args.ActiveRefresh.FallbackProbe; cfg.Enabled &&
			!updated.staleDeadline.IsZero() && now.Before(updated.staleDeadline) {
			scheduled = c.scheduleEntryLocked(meta, updated, 0, true, now, false)
		}
		if !scheduled {
			c.removeActiveMetaLocked(k, meta)
		}
	} else {
		c.recalculateScheduledDueLocked(meta, now)
		bindActiveMetaHandleLocked(meta, updated)
	}
	c.activeMu.Unlock()
	commitMu.Unlock()
	c.flushMu.RUnlock()
	c.notifyActiveScheduler()
}

func (c *Cache) removeActiveMetaIfExpected(k key, expected *item) {
	c.activeMu.Lock()
	if meta := c.activeMeta[k]; meta != nil && meta.expected == expected {
		c.removeActiveMetaLocked(k, meta)
	}
	c.activeMu.Unlock()
	c.notifyActiveScheduler()
}

func (c *Cache) removeActiveMetaIfBackendMissing(k key, expected *item) {
	if expected == nil {
		return
	}
	if _, _, present := c.backend.Get(k); present {
		return
	}
	c.activeMu.Lock()
	if _, _, present := c.backend.Get(k); !present {
		if meta := c.activeMeta[k]; meta != nil && meta.expected == expected {
			c.removeActiveMetaLocked(k, meta)
		}
	}
	c.activeMu.Unlock()
}

func (c *Cache) recalculateScheduledDueLocked(meta *activeRefreshMeta, now time.Time) bool {
	if meta == nil || meta.task == nil || meta.task.scheduleIndex < 0 {
		return false
	}
	t := meta.task
	due := t.refreshAt
	if maxIdle := c.args.ActiveRefresh.MaxIdleTime; maxIdle > 0 {
		idleAt := time.Unix(0, meta.expected.activityState().lastRealAccess.Load()).Add(time.Duration(maxIdle) * time.Second)
		if idleAt.Before(due) {
			due = idleAt
		}
	}
	if due.Before(now) {
		due = now
	}
	if !due.Equal(t.dueAt) {
		t.dueAt = due
		heap.Fix(&c.activeSchedule, t.scheduleIndex)
		return true
	}
	return false
}

func (c *Cache) activeRefreshCapacity() int {
	if c == nil || c.args == nil {
		return 1
	}
	if !c.activeRefreshTrackingPolicyEnabled() {
		return max(c.args.Size, 1)
	}
	return max(c.args.ActiveRefresh.MaxTrackedEntries, 1)
}

func (c *Cache) activeRefreshTrackingPolicyEnabled() bool {
	return c != nil && c.args != nil && c.args.ActiveRefresh.trackingPolicyConfigured
}

func (c *Cache) activeRefreshProtectedLimit() int {
	if !c.activeRefreshTrackingPolicyEnabled() {
		return 0
	}
	capacity := c.activeRefreshCapacity()
	configured := capacity * c.args.ActiveRefresh.ProtectedRatio / 100
	// Always leave at least one probationary slot. Otherwise ratio=100 can
	// protect the entire tracking set and reject every newcomer until a later
	// pass happens to decay and demote an entry.
	return min(configured, max(capacity-1, 0))
}

// refreshActiveHeatLocked folds lock-free real-hit counters into a decaying
// score only on admission/eviction slow paths. Ordinary hits never take
// activeMu or repair the indexed heap.
func (c *Cache) refreshActiveHeatLocked(meta *activeRefreshMeta, now time.Time) float64 {
	if !c.activeRefreshTrackingPolicyEnabled() || meta == nil || meta.expected == nil {
		return 0
	}
	if meta.heatAt.IsZero() {
		meta.heatAt = now
	}
	if elapsed := now.Sub(meta.heatAt); elapsed > 0 {
		halfLife := time.Duration(c.args.ActiveRefresh.HeatHalfLife) * time.Second
		meta.heat *= math.Exp2(-elapsed.Seconds() / halfLife.Seconds())
	}
	current := meta.expected.activityState().realAccessCount.Load()
	if current >= meta.heatObserved {
		meta.heat += float64(current - meta.heatObserved)
	} else {
		// A generation without inherited counters is treated as new activity.
		meta.heat += float64(current)
	}
	meta.heatObserved = current
	meta.heatAt = now
	return meta.heat
}

func (c *Cache) evictLeastUrgentMetaLocked() bool {
	if !c.activeRefreshTrackingPolicyEnabled() {
		return c.evictLegacyActiveMetaLocked()
	}
	return c.evictActiveMetaLocked(0, false)
}

// evictLegacyActiveMetaLocked preserves the pre-policy capacity behaviour:
// metadata is ordered by latest expiration (least urgent first), at most 64
// candidates are checked, and the first unpinned entry is removed. The final
// atomic recheck keeps the newer hit/eviction race fix without introducing
// popularity, CLOCK or protected-segment decisions.
func (c *Cache) evictLegacyActiveMetaLocked() bool {
	if len(c.activeMeta) < c.activeRefreshCapacity() {
		return true
	}
	scanLimit := min(activeRefreshEvictionProbes, len(c.activeEviction))
	skipped := make([]*activeRefreshMeta, 0, scanLimit)
	restoreSkipped := func() {
		for _, meta := range skipped {
			if meta != nil && c.activeMeta[meta.k] == meta && meta.evictionIndex < 0 {
				heap.Push(&c.activeEviction, meta)
			}
		}
	}
	for probes := 0; probes < scanLimit && len(c.activeEviction) > 0; probes++ {
		victim := heap.Pop(&c.activeEviction).(*activeRefreshMeta)
		if victim == nil || c.activeMeta[victim.k] != victim {
			continue
		}
		current, _, present := c.backend.Get(victim.k)
		if c.activeMetaPinnedForEviction(victim, current, present) {
			skipped = append(skipped, victim)
			continue
		}
		if expected := victim.expected; expected != nil {
			activity := expected.activityState()
			sampledCount := activity.realAccessCount.Load()
			lastAccess := activity.lastRealAccess.Load()
			clearActiveMetaHandleLocked(victim)
			if victim.accessWriters.Load() != 0 ||
				activity.realAccessCount.Load() != sampledCount || activity.lastRealAccess.Load() != lastAccess {
				bindActiveMetaHandleLocked(victim, expected)
				skipped = append(skipped, victim)
				continue
			}
		}
		c.removeActiveMetaLocked(victim.k, victim)
		restoreSkipped()
		return true
	}
	restoreSkipped()
	return false
}

func (c *Cache) evictActiveMetaLocked(incomingHeat float64, compareIncoming bool) bool {
	if len(c.activeMeta) < c.activeRefreshCapacity() {
		return true
	}
	// Keep the existing indexed heap for O(log N) removal, but apply a bounded
	// CLOCK-style second chance and a protected segment before choosing the
	// coldest probationary entry from this scan. No map-wide scan is performed.
	scanLimit := min(c.args.ActiveRefresh.EvictionScanLimit, len(c.activeEviction))
	skipped := make([]*activeRefreshMeta, 0, scanLimit)
	restoreSkipped := func() {
		for _, meta := range skipped {
			if meta != nil && c.activeMeta[meta.k] == meta && meta.evictionIndex < 0 {
				meta.evictionTicket = c.nextActiveClockTicketLocked()
				heap.Push(&c.activeEviction, meta)
			}
		}
	}
	now := time.Now()
	var victim *activeRefreshMeta
	victimHeat := math.MaxFloat64
	var victimAccessCount uint64
	for probes := 0; probes < scanLimit && len(c.activeEviction) > 0; probes++ {
		candidate := heap.Pop(&c.activeEviction).(*activeRefreshMeta)
		if candidate == nil || c.activeMeta[candidate.k] != candidate {
			continue
		}
		current, _, present := c.backend.Get(candidate.k)
		if c.activeMetaPinnedForEviction(candidate, current, present) {
			skipped = append(skipped, candidate)
			continue
		}
		heat := c.refreshActiveHeatLocked(candidate, now)
		if candidate.referenced.Swap(false) {
			if !candidate.protected && c.activeProtected < c.activeRefreshProtectedLimit() {
				candidate.protected = true
				c.activeProtected++
				c.activeEvent("clock_promoted")
			}
			skipped = append(skipped, candidate)
			continue
		}
		if candidate.protected {
			if heat < float64(c.args.ActiveRefresh.AdmissionHits) {
				candidate.protected = false
				c.activeProtected--
				c.activeEvent("clock_demoted")
			}
			skipped = append(skipped, candidate)
			continue
		}
		if heat < victimHeat {
			if victim != nil {
				skipped = append(skipped, victim)
			}
			victim = candidate
			victimHeat = heat
			// refreshActiveHeatLocked fixed heatObserved to the exact access
			// counter folded into heat. Keep that sample with this candidate;
			// meta.heatObserved may be refreshed only after a detected race.
			victimAccessCount = candidate.heatObserved
		} else {
			skipped = append(skipped, candidate)
		}
	}
	restoreSkipped()
	if victim == nil {
		c.activeEvent("admission_capacity_rejected")
		return false
	}
	if compareIncoming && incomingHeat < victimHeat {
		victim.evictionTicket = c.nextActiveClockTicketLocked()
		heap.Push(&c.activeEviction, victim)
		c.activeEvent("admission_capacity_rejected")
		return false
	}
	if !c.finalizeActiveEvictionLocked(victim, victimAccessCount) {
		return false
	}
	c.removeActiveMetaLocked(victim.k, victim)
	c.activeEvent("clock_evicted")
	return true
}

// finalizeActiveEvictionLocked establishes the eviction linearization point.
// sampledAccessCount is the exact realAccessCount already folded into the
// victim's heat while it was selected. The caller has removed victim from the
// eviction heap and must hold activeMu.
func (c *Cache) finalizeActiveEvictionLocked(victim *activeRefreshMeta, sampledAccessCount uint64) bool {
	if victim == nil || victim.expected == nil {
		return true
	}
	activity := victim.expected.activityState()
	lastAccess := activity.lastRealAccess.Load()
	clearActiveMetaHandleLocked(victim)
	if victim.accessWriters.Load() != 0 || victim.referenced.Swap(false) ||
		activity.realAccessCount.Load() != sampledAccessCount ||
		activity.lastRealAccess.Load() != lastAccess {
		// A hit overlapped victim selection. Fold the newly observed counter into
		// heat before rotating the entry, otherwise the next CLOCK pass could
		// compare it using the same stale score that selected it this time.
		c.refreshActiveHeatLocked(victim, time.Now())
		bindActiveMetaHandleLocked(victim, victim.expected)
		victim.evictionTicket = c.nextActiveClockTicketLocked()
		heap.Push(&c.activeEviction, victim)
		c.activeEvent("admission_capacity_rejected")
		return false
	}
	return true
}

func activeAdmissionHeatFromState(state uint64, now time.Time, window time.Duration) float64 {
	if window <= 0 {
		return 0
	}
	start := int64(uint32(state >> 32))
	if start == 0 {
		return 0
	}
	nowSecond := now.Unix()
	// Out-of-order request timestamps deliberately remain in the newer window,
	// matching updateActiveAdmission. Otherwise only the still-live admission
	// window contributes initial heat.
	if nowSecond >= start && nowSecond-start >= int64(window/time.Second) {
		return 0
	}
	return float64(uint32(state))
}

func activeAdmissionHeat(v *item, now time.Time, window time.Duration) float64 {
	if v == nil {
		return 0
	}
	_, state := snapshotActiveAdmissionState(v)
	return activeAdmissionHeatFromState(state, now, window)
}

func (c *Cache) ensureActiveMetaSlotLocked(incoming *item) bool {
	drainLimit := activeRefreshEvictionProbes
	if c.activeRefreshTrackingPolicyEnabled() {
		drainLimit = c.args.ActiveRefresh.EvictionScanLimit
	}
	c.drainActiveBackendRemovalsLocked(drainLimit)
	maxMeta := c.activeRefreshCapacity()
	incomingHeat := 0.0
	if c.activeRefreshTrackingPolicyEnabled() {
		incomingHeat = activeAdmissionHeat(
			incoming,
			time.Now(),
			time.Duration(c.args.ActiveRefresh.AdmissionWindow)*time.Second,
		)
	}
	for len(c.activeMeta) >= maxMeta {
		evicted := false
		if c.activeRefreshTrackingPolicyEnabled() {
			evicted = c.evictActiveMetaLocked(incomingHeat, true)
		} else {
			evicted = c.evictLegacyActiveMetaLocked()
		}
		if !evicted {
			return false
		}
	}
	return true
}

func (c *Cache) activeMetaPinnedForEviction(candidate *activeRefreshMeta, current *item, present bool) bool {
	if candidate == nil {
		return true
	}
	if present && current != nil && current != candidate.expected {
		// The backend committed a replacement whose updater may be waiting for
		// activeMu to install the new generation's task.
		return true
	}
	if task := candidate.task; task != nil && task.scheduleIndex < 0 && task.pendingIndex < 0 {
		// The scheduler removed this task from both heaps for validation or worker
		// dispatch. Its inflight claim may not be visible yet.
		return true
	}
	if expected := candidate.expected; expected != nil {
		_, inFlight := c.refreshInFlight.Load(refreshFlightKey{k: candidate.k, generation: expected.generation})
		return inFlight
	}
	return false
}

func (c *Cache) scheduleEntryLocked(meta *activeRefreshMeta, expected *item, retryCount int, probeOnly bool, now time.Time, restored bool) bool {
	if c.lifecycleCtx.Err() != nil || meta == nil || expected == nil || expected.generation == 0 {
		return false
	}
	c.removeMetaTaskLocked(meta)
	threshold := time.Duration(c.args.ActiveRefresh.Threshold) * time.Second
	refreshAt, window, ok := calculateRefreshAt(expected, threshold)
	if probeOnly {
		window = max(window, activeRefreshRetryFloor)
		refreshAt = maxTime(now, expected.expirationTime)
		ok = !refreshAt.IsZero()
	}
	if !ok || !now.Before(expected.expirationTime) && !probeOnly {
		return false
	}
	if restored && !refreshAt.After(now) {
		jitter := time.Duration(meta.k.Sum() % uint64(5*time.Second+1))
		refreshAt = now.Add(jitter)
		latest := expected.expirationTime.Add(-activeRefreshMinBudget)
		if refreshAt.After(latest) {
			refreshAt = latest
		}
		if refreshAt.Before(now) {
			return false
		}
	}
	t := &refreshTask{
		key: kClone(meta.k), refreshAt: refreshAt, expireAt: expected.expirationTime,
		refreshWindow: window, generation: expected.generation, retryCount: retryCount,
		meta: meta, dueAt: refreshAt, probeOnly: probeOnly, scheduleIndex: -1, pendingIndex: -1,
	}
	if maxIdle := c.args.ActiveRefresh.MaxIdleTime; maxIdle > 0 {
		idleAt := time.Unix(0, expected.activityState().lastRealAccess.Load()).Add(time.Duration(maxIdle) * time.Second)
		if idleAt.Before(t.dueAt) {
			t.dueAt = idleAt
		}
	}
	if t.dueAt.Before(now) {
		t.dueAt = now
	}
	meta.task = t
	c.setActiveMetaExpectedLocked(meta, expected)
	heap.Push(&c.activeSchedule, t)
	bindActiveMetaHandleLocked(meta, expected)
	c.activeEvent("scheduled")
	return true
}

func kClone(k key) key { return key(strings.Clone(string(k))) }

func (c *Cache) removeMetaTaskLocked(meta *activeRefreshMeta) {
	if meta == nil {
		return
	}
	clearActiveMetaHandleLocked(meta)
	if meta.task == nil {
		return
	}
	t := meta.task
	if t.scheduleIndex >= 0 {
		heap.Remove(&c.activeSchedule, t.scheduleIndex)
	}
	if t.pendingIndex >= 0 {
		heap.Remove(&c.activePending, t.pendingIndex)
	}
	meta.task = nil
}

func (c *Cache) removeActiveMetaLocked(k key, meta *activeRefreshMeta) {
	if meta == nil || c.activeMeta[k] != meta {
		return
	}
	c.removeMetaTaskLocked(meta)
	if meta.evictionIndex >= 0 {
		heap.Remove(&c.activeEviction, meta.evictionIndex)
	}
	if meta.protected {
		meta.protected = false
		if c.activeProtected > 0 {
			c.activeProtected--
		}
	}
	delete(c.activeMeta, k)
}

func (c *Cache) addActiveMetaLocked(k key, meta *activeRefreshMeta) {
	if meta == nil {
		return
	}
	meta.k = k
	meta.evictionIndex = -1
	if c.activeRefreshTrackingPolicyEnabled() {
		meta.evictionTicket = c.nextActiveClockTicketLocked()
	} else {
		meta.evictionTicket = 0
	}
	meta.protected = false
	meta.referenced.Store(c.activeRefreshTrackingPolicyEnabled())
	if c.activeRefreshTrackingPolicyEnabled() {
		if meta.expected != nil {
			accessCount, admissionState := snapshotActiveAdmissionState(meta.expected)
			meta.heatAt = time.Now()
			meta.heatObserved = accessCount
			// realAccessCount is lifetime/lineage accounting and is only a
			// baseline for future deltas. Initial heat is the live admission
			// window, so old windows and a previously evicted incarnation cannot
			// regain their full historical score on (re)admission.
			meta.heat = activeAdmissionHeatFromState(
				admissionState,
				meta.heatAt,
				time.Duration(c.args.ActiveRefresh.AdmissionWindow)*time.Second,
			)
		} else {
			meta.heatAt = time.Now()
		}
	} else {
		meta.heatAt = time.Time{}
		meta.heatObserved = 0
		meta.heat = 0
	}
	c.activeMeta[k] = meta
	heap.Push(&c.activeEviction, meta)
}

func (c *Cache) nextActiveClockTicketLocked() uint64 {
	c.activeClockTicket++
	// Wraparound requires centuries even at extreme admission rates. Reserve
	// zero for uninitialised metadata if it ever occurs.
	if c.activeClockTicket == 0 {
		c.activeClockTicket = 1
	}
	return c.activeClockTicket
}

func (c *Cache) setActiveMetaExpectedLocked(meta *activeRefreshMeta, expected *item) {
	if meta == nil || meta.expected == expected {
		return
	}
	meta.expected = expected
	if meta.evictionIndex >= 0 {
		heap.Fix(&c.activeEviction, meta.evictionIndex)
	}
}

func (c *Cache) removeActiveMeta(k key) {
	c.activeMu.Lock()
	if meta := c.activeMeta[k]; meta != nil {
		c.removeActiveMetaLocked(k, meta)
	}
	c.activeMu.Unlock()
	c.notifyActiveScheduler()
}

func (c *Cache) notifyActiveScheduler() {
	select {
	case c.activeWake <- struct{}{}:
	default:
	}
}

func (c *Cache) noteActiveBackendRemoval(k key, old *item) {
	if old == nil || !c.activeRefreshEnabled() {
		return
	}
	for {
		actual, loaded := c.activeRemoved.LoadOrStore(k, old)
		if !loaded {
			break
		}
		current, ok := actual.(*item)
		if !ok || current == nil || current.generation >= old.generation {
			return
		}
		if c.activeRemoved.CompareAndSwap(k, actual, old) {
			break
		}
	}
	c.notifyActiveScheduler()
}

// drainActiveBackendRemovalsLocked consumes exact backend-eviction hints
// without scanning activeMeta. Removal callbacks can arrive out of order, so
// the newest hint generation and current backend state are revalidated. The
// caller must hold activeMu.
func (c *Cache) drainActiveBackendRemovalsLocked(limit int) {
	if limit <= 0 {
		return
	}
	visited := 0
	c.activeRemoved.Range(func(rawK, rawOld any) bool {
		if visited >= limit {
			return false
		}
		visited++
		k, keyOK := rawK.(key)
		old, itemOK := rawOld.(*item)
		if !keyOK || !itemOK || old == nil || !c.activeRemoved.CompareAndDelete(rawK, rawOld) {
			return true
		}
		meta := c.activeMeta[k]
		if meta == nil {
			return true
		}
		current, _, present := c.backend.Get(k)
		if present && current != nil {
			// Either the callback arrived out of order or a replacement is in
			// its commit-to-metadata handoff window. Keep the container.
			return true
		}
		// With no backend value, any generation of metadata for this key is
		// stale. A newer removal hint may have replaced an older one before the
		// older generation was drained, so do not require meta.expected == old.
		if c.activeMetaPinnedForEviction(meta, current, present) {
			// The owner of a dispatched active task removes missing metadata.
			// A lazy owner does the same on its backend preflight. Do not put the
			// hint back here: doing so could overwrite a newer same-key hint or
			// spin the scheduler while the owner is still running.
			return true
		}
		c.removeActiveMetaLocked(k, meta)
		return true
	})
	if visited >= limit {
		// activeWake intentionally coalesces notifications. Re-arm it after a
		// full batch so a burst larger than limit is eventually drained even
		// when there are no scheduled tasks or all metadata is stopped.
		c.notifyActiveScheduler()
	}
}

func (c *Cache) startActiveRefresh() {
	if !c.activeRefreshEnabled() || c.activeWorkerReady == nil {
		return
	}
	for i := 0; i < c.args.ActiveRefresh.Workers; i++ {
		c.activeWorkers.Add(1)
		go c.activeWorkerLoop()
	}
	c.activeWorkers.Add(1)
	go func() {
		defer c.activeWorkers.Done()
		c.activeSchedulerLoop()
	}()
}

func (c *Cache) activeWorkerLoop() {
	defer c.activeWorkers.Done()
	slot := make(chan *activeRefreshWork, 1)
	for {
		select {
		case <-c.closeNotify:
			return
		case c.activeWorkerReady <- slot:
		}
		select {
		case <-c.closeNotify:
			return
		case work := <-slot:
			if work != nil {
				// The scheduler already granted this worker, rate and inflight
				// permits. Expand the immutable replay here so DNS Unpack and map
				// allocation scale with Workers instead of serializing dispatch.
				if !c.materializeActiveWork(work) {
					c.discardActiveTask(work.task, true)
					c.releaseRefreshFlight(work.task.key, work.expected, work.flight)
					continue
				}
				c.runActiveRefreshTask(work)
			}
		}
	}
}

func stopAndDrainTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func resetActiveTimer(timer *time.Timer, delay time.Duration) {
	stopAndDrainTimer(timer)
	if delay < 0 {
		delay = 0
	}
	timer.Reset(delay)
}

func (c *Cache) activeSchedulerLoop() {
	timer := time.NewTimer(time.Hour)
	stopAndDrainTimer(timer)
	defer timer.Stop()
	bucket := newRefreshTokenBucket(c.args.ActiveRefresh.MaxRefreshQPS, c.args.ActiveRefresh.RefreshBurst, time.Now())
	ready := make([]chan *activeRefreshWork, 0, c.args.ActiveRefresh.Workers)

	for {
		now := time.Now()
		c.moveDueActiveTasks(now)
		for {
			select {
			case slot := <-c.activeWorkerReady:
				ready = append(ready, slot)
			default:
				goto dispatch
			}
		}

	dispatch:
		for len(ready) > 0 {
			task := c.popPendingTask()
			if task == nil {
				break
			}
			work, requiresToken := c.prepareActiveWork(task, time.Now())
			if work == nil {
				continue
			}
			if requiresToken && !bucket.available(time.Now()) {
				c.requeuePendingTask(task)
				c.activeEvent("rate_limited")
				break
			}
			if !c.claimActiveFlight(work) {
				c.activeEvent("duplicate_inflight")
				c.rescheduleActiveConflict(task, time.Now())
				continue
			}
			if requiresToken && !bucket.take(time.Now()) {
				c.releaseRefreshFlight(task.key, work.expected, work.flight)
				c.requeuePendingTask(task)
				break
			}
			slot := ready[0]
			ready = ready[1:]
			select {
			case <-c.closeNotify:
				c.refreshInFlight.Delete(work.flight)
				return
			case slot <- work:
			}
		}

		delay, arm := c.nextActiveSchedulerDelay(time.Now(), &bucket, len(ready) > 0)
		if arm {
			resetActiveTimer(timer, delay)
		} else {
			stopAndDrainTimer(timer)
		}

		select {
		case <-c.closeNotify:
			return
		case <-c.activeWake:
		case slot := <-c.activeWorkerReady:
			ready = append(ready, slot)
		case <-timer.C:
		}
	}
}

func (c *Cache) moveDueActiveTasks(now time.Time) {
	limit := c.args.ActiveRefresh.MaxTasksPerBatch
	c.activeMu.Lock()
	defer c.activeMu.Unlock()
	c.drainActiveBackendRemovalsLocked(activeRefreshEvictionProbes)
	if len(c.activeSchedule) == 0 || c.activeSchedule[0].dueAt.After(now) {
		return
	}
	horizon := now.Add(activeRefreshCoalesceWindow)
	for moved := 0; moved < limit && len(c.activeSchedule) > 0; {
		t := c.activeSchedule[0]
		if t.dueAt.After(horizon) {
			break
		}
		// dueAt can be earlier than refreshAt solely to retire an entry at its
		// max-idle boundary. Never coalesce that sentinel early: doing so could
		// turn an idle-state check into an upstream refresh just before the entry
		// becomes inactive.
		if t.dueAt.After(now) && !t.dueAt.Equal(t.refreshAt) {
			break
		}
		heap.Pop(&c.activeSchedule)
		if t.meta == nil || t.meta.task != t || c.activeMeta[t.key] != t.meta {
			continue
		}
		if !c.enqueuePendingLocked(t, now) {
			// The full-queue slow path may replace t with a retry after finding
			// an inflight conflict. Do not detach that newly scheduled task.
			if t.meta.task == t {
				clearActiveMetaTaskLocked(t.meta)
			}
		}
		moved++
	}
}

func (c *Cache) enqueuePendingLocked(task *refreshTask, now time.Time) bool {
	limit := c.args.ActiveRefresh.MaxPendingTasks
	heap.Push(&c.activePending, task)
	if len(c.activePending) <= limit {
		return true
	}
	// Full-queue cleanup is deliberately the slow path. It performs backend,
	// exclusion and inflight validation before sacrificing any live task, while
	// the ordinary enqueue path stays O(log n).
	c.prunePendingLocked(now)
	for len(c.activePending) > limit {
		worst := 0
		for i := 1; i < len(c.activePending); i++ {
			if c.activePending[i].expireAt.After(c.activePending[worst].expireAt) {
				worst = i
			}
		}
		dropped := heap.Remove(&c.activePending, worst).(*refreshTask)
		if dropped.meta != nil && dropped.meta.task == dropped {
			clearActiveMetaTaskLocked(dropped.meta)
		}
		c.activeRefreshDropTotal.Inc()
		c.activeEvent("queue_dropped")
	}
	return task.pendingIndex >= 0
}

func (c *Cache) prunePendingLocked(now time.Time) {
	// Drain first, then rebuild. Removing arbitrary indexes while iterating a
	// heap can move an unchecked parent into an already-visited index and leave
	// invalid work behind precisely when the queue is under pressure.
	tasks := make([]*refreshTask, 0, len(c.activePending))
	for len(c.activePending) > 0 {
		tasks = append(tasks, heap.Pop(&c.activePending).(*refreshTask))
	}
	for _, t := range tasks {
		staleMeta := t.meta == nil || t.meta.task != t || c.activeMeta[t.key] != t.meta ||
			t.meta.expected == nil || t.meta.expected.generation != t.generation
		var current *item
		backendMissing := false
		backendChanged := false
		if !staleMeta {
			var present bool
			current, _, present = c.backend.Get(t.key)
			backendMissing = !present || current == nil
			backendChanged = !backendMissing && (current != t.meta.expected || current.generation != t.generation)
		}

		expired := !staleMeta && !backendMissing && !backendChanged && !t.probeOnly && !now.Before(t.expireAt)
		if expired && c.args.ActiveRefresh.FallbackProbe.Enabled &&
			!current.staleDeadline.IsZero() && now.Before(current.staleDeadline) {
			// An expired DNS requery is no longer useful, but the private retained
			// answer may still be eligible for a no-QPS fallback probe.
			t.probeOnly = true
			expired = false
			c.activeEvent("expired_before_run")
		}
		inactive := false
		if !staleMeta && !backendMissing && !backendChanged && !expired && c.args.ActiveRefresh.MaxIdleTime > 0 {
			activity := t.meta.expected.activityState()
			last := time.Unix(0, activity.lastRealAccess.Load())
			inactive = now.Sub(last) >= time.Duration(c.args.ActiveRefresh.MaxIdleTime)*time.Second
			if inactive {
				// Publish the slow-path state before the final decision. A hit that
				// raced the first read either changed lastRealAccess and is observed
				// below, or sees the invalid handle and rebuilds after activeMu is
				// released.
				clearActiveMetaHandleLocked(t.meta)
				last = time.Unix(0, activity.lastRealAccess.Load())
				inactive = now.Sub(last) >= time.Duration(c.args.ActiveRefresh.MaxIdleTime)*time.Second
				if !inactive {
					bindActiveMetaHandleLocked(t.meta, t.meta.expected)
				}
			}
		}

		excludedDomain := false
		excludedIP := false
		if !staleMeta && !backendMissing && !backendChanged && !expired && !inactive {
			question, validQuestion := questionFromKey(t.key)
			excludedDomain = !validQuestion || c.activeDomainExcluded(question.Name)
			if !excludedDomain {
				msg := new(dns.Msg)
				if err := msg.Unpack(current.resp); err == nil {
					excludedIP = c.containsActiveExcluded(msg)
				}
			}
		}
		_, duplicateInflight := c.refreshInFlight.Load(refreshFlightKey{k: t.key, generation: t.generation})
		if staleMeta || backendMissing || backendChanged || expired || inactive || excludedDomain || excludedIP || duplicateInflight {
			if duplicateInflight && !staleMeta && !backendMissing && !backendChanged && !expired && !inactive && !excludedDomain && !excludedIP {
				deadline := t.expireAt
				delay := calculateRetryDelay(deadline.Sub(now), t.refreshWindow)
				if t.probeOnly {
					deadline = current.staleDeadline
					delay = activeRefreshRetryFloor
				}
				if delay > 0 && now.Add(delay+activeRefreshMinBudget).Before(deadline) {
					if !c.scheduleRetryLocked(t.meta, t, delay, now, false) && t.meta.task == t {
						clearActiveMetaTaskLocked(t.meta)
					}
				} else if t.meta.task == t {
					clearActiveMetaTaskLocked(t.meta)
				}
				c.activeEvent("duplicate_inflight")
				continue
			}
			if t.meta != nil && t.meta.task == t {
				clearActiveMetaTaskLocked(t.meta)
				if (backendMissing || inactive || excludedDomain || excludedIP) && c.activeMeta[t.key] == t.meta {
					c.removeActiveMetaLocked(t.key, t.meta)
				}
			}
			switch {
			case staleMeta || backendMissing || backendChanged:
				c.activeEvent("stale_generation")
			case expired:
				c.activeEvent("expired_before_run")
			case inactive:
				c.activeEvent("inactive_skipped")
			case excludedDomain:
				c.activeEvent("excluded_domain_skipped")
			case excludedIP:
				c.activeEvent("excluded_ip_skipped")
			}
			continue
		}
		heap.Push(&c.activePending, t)
	}
}

func (c *Cache) popPendingTask() *refreshTask {
	c.activeMu.Lock()
	defer c.activeMu.Unlock()
	if len(c.activePending) == 0 {
		return nil
	}
	return heap.Pop(&c.activePending).(*refreshTask)
}

func (c *Cache) requeuePendingTask(task *refreshTask) {
	c.activeMu.Lock()
	if task != nil && task.meta != nil && task.meta.task == task && task.pendingIndex < 0 && task.scheduleIndex < 0 {
		heap.Push(&c.activePending, task)
	}
	c.activeMu.Unlock()
}

func (c *Cache) nextActiveSchedulerDelay(now time.Time, bucket *refreshTokenBucket, hasReadyWorker bool) (time.Duration, bool) {
	c.activeMu.RLock()
	defer c.activeMu.RUnlock()
	var delay time.Duration
	armed := false
	if len(c.activeSchedule) > 0 {
		delay = max(time.Duration(0), c.activeSchedule[0].dueAt.Sub(now))
		armed = true
	}
	if len(c.activePending) > 0 && hasReadyWorker {
		tokenDelay := bucket.delay(now)
		if !armed || tokenDelay < delay {
			delay = tokenDelay
			armed = true
		}
	}
	return delay, armed
}

func (c *Cache) prepareActiveWork(task *refreshTask, now time.Time) (*activeRefreshWork, bool) {
	if task == nil || c.lifecycleCtx.Err() != nil {
		return nil, false
	}
	if task.probeOnly && now.Before(task.expireAt) {
		c.activeMu.Lock()
		if task.meta != nil && task.meta.task == task && c.activeMeta[task.key] == task.meta {
			task.refreshAt = task.expireAt
			task.dueAt = task.expireAt
			heap.Push(&c.activeSchedule, task)
		}
		c.activeMu.Unlock()
		c.notifyActiveScheduler()
		return nil, false
	}
	c.activeMu.Lock()
	meta := task.meta
	if meta == nil || meta.task != task || c.activeMeta[task.key] != meta {
		c.activeMu.Unlock()
		c.activeEvent("stale_generation")
		return nil, false
	}
	expected := meta.expected
	if meta.replay == nil {
		c.removeActiveMetaLocked(task.key, meta)
		c.activeMu.Unlock()
		return nil, false
	}
	replay := meta.replay
	nextBase := meta.next
	c.activeMu.Unlock()

	current, _, ok := c.backend.Get(task.key)
	if !ok || expected == nil {
		c.activeEvent("stale_generation")
		c.discardActiveTask(task, true)
		return nil, false
	}
	if current != expected || current.generation != task.generation {
		c.activeEvent("stale_generation")
		// A newer current pointer can be in the short handoff window between a
		// successful commit and updateActiveRefreshAfterCommit. Keep the metadata
		// container so that handoff can install the new generation's task.
		c.discardActiveTask(task, false)
		return nil, false
	}
	// Heap/task state is serialized here, while real-hit activity remains
	// lock-free. Before an inactive/stop decision becomes final we invalidate the
	// entry handle and re-read its atomics: an overlapping hit is either observed
	// by that second read or forced onto the slow path.
	c.activeMu.Lock()
	if meta.task != task || c.activeMeta[task.key] != meta || meta.expected != expected {
		c.activeMu.Unlock()
		c.activeEvent("stale_generation")
		return nil, false
	}
	if maxIdle := c.args.ActiveRefresh.MaxIdleTime; maxIdle > 0 {
		activity := expected.activityState()
		lastAccess := time.Unix(0, activity.lastRealAccess.Load())
		if now.Sub(lastAccess) >= time.Duration(maxIdle)*time.Second {
			clearActiveMetaHandleLocked(meta)
			lastAccess = time.Unix(0, activity.lastRealAccess.Load())
			if now.Sub(lastAccess) >= time.Duration(maxIdle)*time.Second {
				c.removeActiveMetaLocked(task.key, meta)
				c.activeMu.Unlock()
				c.activeEvent("inactive_skipped")
				return nil, false
			}
			bindActiveMetaHandleLocked(meta, expected)
		}
	}
	if now.Before(task.refreshAt) && task.dueAt.Before(task.refreshAt) {
		// This is a max-idle sentinel, not the TTL refresh deadline. A real hit may
		// have extended the idle boundary after the scheduler moved it to pending;
		// in that case return it to the future heap instead of querying early.
		task.dueAt = task.refreshAt
		if maxIdle := c.args.ActiveRefresh.MaxIdleTime; maxIdle > 0 {
			idleAt := time.Unix(0, expected.activityState().lastRealAccess.Load()).Add(time.Duration(maxIdle) * time.Second)
			if idleAt.Before(task.dueAt) {
				task.dueAt = idleAt
			}
		}
		if task.dueAt.Before(now) {
			task.dueAt = now
		}
		heap.Push(&c.activeSchedule, task)
		c.activeMu.Unlock()
		c.notifyActiveScheduler()
		return nil, false
	}
	activity := expected.activityState()
	if maxRefresh := c.args.ActiveRefresh.MaxRefreshTimes; maxRefresh > 0 && uint64(activity.refreshSuccesses()) >= uint64(maxRefresh) {
		clearActiveMetaHandleLocked(meta)
		if uint64(activity.refreshSuccesses()) >= uint64(maxRefresh) {
			clearActiveMetaTaskLocked(meta)
			meta.stopped.Store(true)
			c.activeMu.Unlock()
			c.removeActiveMetaIfBackendMissing(task.key, expected)
			return nil, false
		}
		bindActiveMetaHandleLocked(meta, expected)
	}
	c.activeMu.Unlock()
	question, ok := questionFromKey(task.key)
	if !ok || c.activeDomainExcluded(question.Name) {
		c.activeEvent("excluded_domain_skipped")
		c.discardActiveTask(task, true)
		return nil, false
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(current.resp); err != nil {
		c.discardActiveTask(task, true)
		return nil, false
	}
	if c.containsActiveExcluded(msg) {
		c.activeEvent("excluded_ip_skipped")
		c.discardActiveTask(task, true)
		return nil, false
	}

	if !task.probeOnly {
		remaining := task.expireAt.Sub(now)
		if remaining <= 0 {
			c.activeEvent("expired_before_run")
			if c.scheduleProbeTask(task, current, now) {
				return nil, false
			}
			c.discardActiveTask(task, true)
			return nil, false
		}
		configured := time.Duration(c.args.ActiveRefresh.RequeryTimeoutMS) * time.Millisecond
		if _, enough := calculateRequeryTimeout(configured, remaining); !enough {
			c.activeEvent("insufficient_time")
			if c.scheduleProbeTask(task, current, now) {
				return nil, false
			}
			c.discardActiveTask(task, true)
			return nil, false
		}
	}

	epoch := c.refreshEpoch.Load()
	return &activeRefreshWork{
		task: task, replay: replay, nextBase: nextBase,
		expected: current, epoch: epoch, activityEpoch: current.activityState().refreshEpoch(),
		flight: refreshFlightKey{k: task.key, generation: task.generation},
	}, !task.probeOnly
}

func (c *Cache) materializeActiveWork(work *activeRefreshWork) bool {
	if work == nil || work.replay == nil || c.lifecycleCtx.Err() != nil {
		return false
	}
	if work.task != nil && work.task.probeOnly {
		return true
	}
	qCtx, err := work.replay.ContextForReplay()
	if err != nil {
		c.logger.Debug("failed to materialize active refresh replay", zap.Error(err))
		return false
	}
	work.qCtx = qCtx
	if c.activeRefreshExec == nil {
		work.next = work.nextBase.Fork()
	}
	return true
}

func (c *Cache) claimActiveFlight(work *activeRefreshWork) bool {
	if work == nil {
		return false
	}
	_, loaded := c.refreshInFlight.LoadOrStore(work.flight, struct{}{})
	return !loaded
}

func (c *Cache) discardActiveTask(task *refreshTask, removeMeta bool) {
	var expected *item
	c.activeMu.Lock()
	if task != nil && task.meta != nil && task.meta.task == task {
		expected = task.meta.expected
		clearActiveMetaTaskLocked(task.meta)
		if removeMeta && c.activeMeta[task.key] == task.meta {
			c.removeActiveMetaLocked(task.key, task.meta)
		}
	}
	c.activeMu.Unlock()
	if !removeMeta && task != nil && expected != nil {
		c.removeActiveMetaIfBackendMissing(task.key, expected)
	}
}

func (c *Cache) rescheduleActiveConflict(task *refreshTask, now time.Time) {
	if task == nil || task.meta == nil {
		return
	}
	c.activeMu.Lock()
	if task.meta.task == task && c.activeMeta[task.key] == task.meta {
		deadline := task.expireAt
		delay := calculateRetryDelay(deadline.Sub(now), task.refreshWindow)
		if task.probeOnly && task.meta.expected != nil {
			deadline = task.meta.expected.staleDeadline
			delay = activeRefreshRetryFloor
		}
		if delay > 0 && now.Add(delay+activeRefreshMinBudget).Before(deadline) {
			c.scheduleRetryLocked(task.meta, task, delay, now, false)
		} else {
			clearActiveMetaTaskLocked(task.meta)
		}
	}
	c.activeMu.Unlock()
	c.notifyActiveScheduler()
}

func (c *Cache) scheduleRetryLocked(meta *activeRefreshMeta, previous *refreshTask, delay time.Duration, now time.Time, increment bool) bool {
	if c.lifecycleCtx.Err() != nil || meta == nil || previous == nil || meta.expected == nil || delay <= 0 {
		return false
	}
	retryCount := previous.retryCount
	if increment {
		retryCount++
	}
	c.removeMetaTaskLocked(meta)
	t := &refreshTask{
		key: kClone(meta.k), refreshAt: now.Add(delay), expireAt: previous.expireAt,
		refreshWindow: previous.refreshWindow, generation: previous.generation,
		retryCount: retryCount, meta: meta, dueAt: now.Add(delay),
		probeOnly: previous.probeOnly, scheduleIndex: -1, pendingIndex: -1,
	}
	meta.task = t
	heap.Push(&c.activeSchedule, t)
	bindActiveMetaHandleLocked(meta, meta.expected)
	c.activeEvent("scheduled")
	return true
}

func (c *Cache) scheduleProbeTask(task *refreshTask, current *item, now time.Time) bool {
	cfg := c.args.ActiveRefresh.FallbackProbe
	if c.lifecycleCtx.Err() != nil || !cfg.Enabled || task == nil || task.meta == nil || current == nil || current.staleDeadline.IsZero() || !now.Before(current.staleDeadline) {
		return false
	}
	c.activeMu.Lock()
	defer c.activeMu.Unlock()
	meta := task.meta
	if meta.task != task || c.activeMeta[task.key] != meta || meta.expected != current {
		return false
	}
	return c.scheduleEntryLocked(meta, current, task.retryCount, true, now, false)
}

func (c *Cache) runActiveRefreshTask(work *activeRefreshWork) {
	defer c.finishActiveRefreshWork(work)
	if c.lifecycleCtx.Err() != nil || work.epoch != c.refreshEpoch.Load() {
		return
	}
	current, _, ok := c.backend.Get(work.task.key)
	if !ok {
		c.activeEvent("stale_generation")
		c.discardActiveTask(work.task, true)
		return
	}
	if current != work.expected || current.generation != work.task.generation {
		c.activeEvent("stale_generation")
		c.discardActiveTask(work.task, false)
		return
	}
	if work.task.probeOnly {
		c.runFallbackProbe(work, current)
		c.discardActiveTask(work.task, true)
		return
	}

	remaining := current.expirationTime.Sub(time.Now())
	timeout, ok := calculateRequeryTimeout(time.Duration(c.args.ActiveRefresh.RequeryTimeoutMS)*time.Millisecond, remaining)
	if !ok {
		c.activeEvent("insufficient_time")
		if !c.scheduleProbeTask(work.task, current, time.Now()) {
			c.discardActiveTask(work.task, true)
		}
		return
	}
	work.qCtx.RenewTrace()
	work.qCtx.MarkCacheRefresh()
	ctx, cancel := context.WithTimeout(c.lifecycleCtx, timeout)
	defer cancel()
	if ctx.Err() != nil {
		return
	}

	c.activeRefreshTotal.Inc()
	c.activeEvent("executed")
	timer := prometheus.NewTimer(c.activeRefreshDuration)
	defer timer.ObserveDuration()
	var err error
	if c.activeRefreshExec != nil {
		err = c.activeRefreshExec.Exec(ctx, work.qCtx)
	} else {
		err = work.next.ExecNext(ctx, work.qCtx)
	}
	if err != nil && !errors.Is(err, sequence.ErrExit) {
		c.logger.Debug("active refresh requery failed", work.qCtx.InfoField(), zap.Error(err))
	}
	if c.lifecycleCtx.Err() != nil || work.epoch != c.refreshEpoch.Load() {
		return
	}
	if ctx.Err() == nil && (err == nil || errors.Is(err, sequence.ErrExit)) {
		r := work.qCtx.R()
		// Top-level exclude_ip keeps its existing meaning: such a response must
		// not enter this cache. active_refresh.exclude_ip is different: commit
		// the fresh response, then stop scheduling it.
		if r != nil && !c.containsExcluded(r) {
			if prepared, cacheable := c.prepareCacheEntry(work.qCtx, false); cacheable && c.commitPrepared(work.task.key, work.expected, work.epoch, prepared) {
				c.activeRefreshSuccessTotal.Inc()
				c.activeEvent("success")
				c.updateActiveRefreshAfterCommitReplay(work.task.key, work.expected, prepared.item, time.Now(), prepared.msg, true, work.activityEpoch, work.replay, nil, work.nextBase)
				return
			}
		}
	}

	c.activeRefreshFailedTotal.Inc()
	c.activeEvent("failed")
	if c.scheduleActiveRetry(work.task, current, time.Now()) {
		return
	}
	if c.scheduleProbeTask(work.task, current, time.Now()) {
		return
	}
	if !time.Now().Before(current.expirationTime) {
		c.runFallbackProbe(work, current)
	}
	c.discardActiveTask(work.task, true)
}

func (c *Cache) finishActiveRefreshWork(work *activeRefreshWork) {
	if work == nil || work.task == nil {
		return
	}
	c.releaseRefreshFlight(work.task.key, work.expected, work.flight)
}

func (c *Cache) scheduleActiveRetry(task *refreshTask, expected *item, now time.Time) bool {
	if task == nil || task.meta == nil || expected == nil || task.retryCount >= c.args.ActiveRefresh.MaxRetryTimes {
		return false
	}
	remaining := expected.expirationTime.Sub(now)
	delay := calculateRetryDelay(remaining, task.refreshWindow)
	configured := time.Duration(c.args.ActiveRefresh.RequeryTimeoutMS) * time.Millisecond
	safety, ok := calculateRequeryTimeout(configured, max(remaining-delay, time.Duration(0)))
	if delay <= 0 || !ok || !now.Add(delay+safety).Before(expected.expirationTime) {
		c.activeEvent("insufficient_time")
		return false
	}
	c.activeMu.Lock()
	meta := task.meta
	rescheduled := meta.task == task && meta.expected == expected && c.activeMeta[task.key] == meta &&
		c.scheduleRetryLocked(meta, task, delay, now, true)
	c.activeMu.Unlock()
	if rescheduled {
		c.activeEvent("retried")
		c.notifyActiveScheduler()
	}
	return rescheduled
}

func (c *Cache) runFallbackProbe(work *activeRefreshWork, expected *item) {
	if work == nil || expected == nil || c.lifecycleCtx.Err() != nil {
		return
	}
	cfg := c.args.ActiveRefresh.FallbackProbe
	if !cfg.Enabled || expected.staleDeadline.IsZero() || !time.Now().Before(expected.staleDeadline) {
		return
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(expected.resp); err != nil || c.containsActiveExcluded(msg) {
		return
	}
	ips := collectMsgIPs(msg)
	if len(ips) == 0 {
		return
	}
	budget := min(time.Duration(c.args.ActiveRefresh.RequeryTimeoutMS)*time.Millisecond, expected.staleDeadline.Sub(time.Now()))
	budget = min(budget, activeRefreshMaxTimeout)
	if budget <= 0 {
		return
	}
	deadline := time.Now().Add(budget)
	configuredTimeout := time.Duration(cfg.TimeoutMS) * time.Millisecond
	for _, probe := range cfg.Probes {
		for _, ip := range ips {
			remaining := time.Until(deadline)
			timeout, ok := calculateProbeTimeout(configuredTimeout, remaining)
			if !ok || c.lifecycleCtx.Err() != nil {
				c.activeEvent("probe_failed")
				return
			}
			c.activeRefreshProbeTotal.Inc()
			if c.activeProbe != nil && c.activeProbe(c.lifecycleCtx, probe, ip, timeout) {
				prepared, ok := c.prepareStaleEntry(expected, msg, time.Now())
				if ok && c.commitPrepared(work.task.key, expected, work.epoch, prepared) {
					c.activeRefreshProbeKeepTotal.Inc()
					c.activeEvent("probe_success")
					c.updateActiveRefreshAfterCommitReplay(work.task.key, expected, prepared.item, time.Now(), prepared.msg, false, work.activityEpoch, work.replay, nil, work.nextBase)
					return
				}
			}
		}
	}
	c.activeEvent("probe_failed")
}

func (c *Cache) updateActiveRefreshAfterCommit(
	k key,
	expected, updated *item,
	now time.Time,
	response *dns.Msg,
	activeSuccess bool,
	activityEpoch uint32,
	qCtx *query_context.Context,
	next sequence.ChainWalker,
) {
	c.updateActiveRefreshAfterCommitReplay(k, expected, updated, now, response, activeSuccess, activityEpoch, nil, qCtx, next)
}

func (c *Cache) updateActiveRefreshAfterCommitReplay(
	k key,
	expected, updated *item,
	now time.Time,
	response *dns.Msg,
	activeSuccess bool,
	activityEpoch uint32,
	replay *query_context.ReplaySnapshot,
	qCtx *query_context.Context,
	nextBase sequence.ChainWalker,
) {
	if !c.activeRefreshEnabled() || updated == nil {
		return
	}
	for {
		c.activeMu.Lock()
		meta := c.activeMeta[k]
		current, _, present := c.backend.Get(k)
		if !present || current != updated {
			c.activeMu.Unlock()
			return
		}
		if meta == nil {
			// Capacity cleanup can race with the short commit-to-metadata handoff
			// window. Rebuild the container from the committed item's persisted state
			// so a successful refresh never loses the new generation's schedule.
			if replay == nil && qCtx == nil {
				c.activeMu.Unlock()
				return
			}
			if replay == nil {
				// A lazy refresh normally finds the metadata container installed by
				// the real hit. In the rare handoff-recovery path, capture its replay
				// outside activeMu and then revalidate the committed generation.
				c.activeMu.Unlock()
				var err error
				replay, err = qCtx.SnapshotForReplay()
				if err != nil {
					c.logger.Debug("failed to capture committed refresh replay", qCtx.InfoField(), zap.Error(err))
					return
				}
				nextBase = nextBase.Fork()
				qCtx = nil
				continue
			}
			if !c.ensureActiveMetaSlotLocked(updated) {
				c.activeMu.Unlock()
				return
			}
			meta = &activeRefreshMeta{k: k, replay: replay, next: nextBase, expected: expected, evictionIndex: -1}
			c.addActiveMetaLocked(k, meta)
		} else if meta.expected != expected {
			c.activeMu.Unlock()
			return
		}
		c.removeMetaTaskLocked(meta)
		// commitPrepared published updated with expected's shared activity pointer.
		// The packed epoch/success CAS makes a real hit on either physical
		// generation win deterministically over this completion.
		activity := updated.activityState()
		c.setActiveMetaExpectedLocked(meta, updated)
		if activeSuccess {
			activity.addRefreshSuccess(activityEpoch)
		}
		question, validQuestion := questionFromKey(k)
		excludedDomain := !validQuestion || c.activeDomainExcluded(question.Name)
		excludedIP := response != nil && c.containsActiveExcluded(response)
		if excludedDomain || excludedIP {
			c.removeActiveMetaLocked(k, meta)
			c.activeMu.Unlock()
			if excludedDomain {
				c.activeEvent("excluded_domain_skipped")
			} else {
				c.activeEvent("excluded_ip_skipped")
			}
			c.notifyActiveScheduler()
			return
		}
		if maxRefresh := c.args.ActiveRefresh.MaxRefreshTimes; maxRefresh > 0 && uint64(activity.refreshSuccesses()) >= uint64(maxRefresh) {
			meta.stopped.Store(true)
		} else {
			c.scheduleEntryLocked(meta, updated, 0, false, now, false)
		}
		c.activeMu.Unlock()
		c.notifyActiveScheduler()
		return
	}
}

// BindContinuation receives the immutable rules following this cache from the
// sequence compiler. Dump-restored refresh work can therefore be rebuilt at
// startup without a dedicated refresh_sequence or a bootstrap client query.
func (c *Cache) BindContinuation(next sequence.ChainWalker) error {
	if !c.activeRefreshEnabled() || !c.args.ActiveRefresh.RestoreOnStartup || c.activeRefreshExec != nil {
		return nil
	}
	return c.installActiveRefreshReplay(next, true)
}

func (c *Cache) bindActiveRefreshReplay(next sequence.ChainWalker) {
	_ = c.installActiveRefreshReplay(next, false)
}

func (c *Cache) installActiveRefreshReplay(next sequence.ChainWalker, rejectDuplicate bool) error {
	if !c.activeRefreshEnabled() || !c.args.ActiveRefresh.RestoreOnStartup {
		return nil
	}
	c.activeRestoreMu.Lock()
	if !c.activeReplayBound {
		c.activeReplayNext = next.Fork()
		c.activeReplayBound = true
	} else if rejectDuplicate {
		c.activeRestoreMu.Unlock()
		return fmt.Errorf("cache is referenced by more than one sequence while active_refresh.restore_on_startup is enabled")
	}
	if len(c.activeRestore) == 0 {
		c.activeRestoreMu.Unlock()
		return nil
	}
	entries := make([]decodedDumpEntry, 0, len(c.activeRestore))
	for _, entry := range c.activeRestore {
		entries = append(entries, entry)
	}
	clear(c.activeRestore)
	replayNext := c.activeReplayNext.Fork()
	c.activeRestoreMu.Unlock()
	c.restoreActiveRefreshEntries(entries, replayNext)
	return nil
}

func (c *Cache) queueRestoredActiveRefresh(entries []decodedDumpEntry) {
	if !c.activeRefreshEnabled() || !c.args.ActiveRefresh.RestoreOnStartup || len(entries) == 0 {
		return
	}
	c.activeRestoreMu.Lock()
	for _, entry := range entries {
		c.activeRestore[entry.k] = entry
	}
	bound := c.activeReplayBound
	c.activeRestoreMu.Unlock()
	if bound {
		c.bindActiveRefreshReplay(sequence.ChainWalker{})
	}
}

func (c *Cache) restoreActiveRefreshEntries(entries []decodedDumpEntry, next sequence.ChainWalker) {
	now := time.Now()
	restored := 0
	// Dump decoding is map-backed and therefore unordered. Restore most-recently
	// used entries first so an independent tracking cap deterministically keeps
	// the hottest available candidates after restart.
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].lastRealAccess.After(entries[j].lastRealAccess)
	})
	for _, entry := range entries {
		v := entry.item
		if v == nil || !now.Before(v.expirationTime) {
			continue
		}
		if v.generation == 0 {
			continue
		}
		lastAccess := entry.lastRealAccess
		if lastAccess.IsZero() {
			lastAccess = v.storedTime
		}
		if maxIdle := c.args.ActiveRefresh.MaxIdleTime; maxIdle > 0 && now.Sub(lastAccess) >= time.Duration(maxIdle)*time.Second {
			continue
		}
		if maxRefresh := c.args.ActiveRefresh.MaxRefreshTimes; maxRefresh > 0 && entry.refreshCount >= uint32(maxRefresh) {
			continue
		}
		qCtx, ok := queryContextFromKey(entry.k)
		if !ok || c.activeDomainExcluded(qCtx.QQuestion().Name) {
			continue
		}
		replay, err := qCtx.SnapshotForReplay()
		if err != nil {
			continue
		}
		nextBase := next.Fork()
		msg := new(dns.Msg)
		if err := msg.Unpack(v.resp); err != nil || c.containsActiveExcluded(msg) {
			continue
		}

		installed := func() bool {
			// Runtime /load_dump may overlap ordinary hits after the backend merge.
			// Use the normal flush -> per-shard commit -> active lock order so the
			// backend generation check and metadata admission are one transaction.
			c.flushMu.RLock()
			defer c.flushMu.RUnlock()
			commitMu := &c.commitLocks[entry.k.Sum()%shardCount]
			commitMu.Lock()
			defer commitMu.Unlock()
			c.activeMu.Lock()
			defer c.activeMu.Unlock()

			current, _, present := c.backend.Get(entry.k)
			if !present || current != v || current.generation != v.generation {
				return false
			}
			if existing := c.activeMeta[entry.k]; existing != nil {
				if existing.expected == v {
					// A real hit already rebuilt this generation after the dump merge.
					// Preserve its newer activity state and TTL task.
					return false
				}
				c.removeActiveMetaLocked(entry.k, existing)
			}
			if !c.ensureActiveMetaSlotLocked(v) {
				return false
			}

			meta := &activeRefreshMeta{
				k: entry.k, replay: replay, next: nextBase, expected: v, evictionIndex: -1,
			}
			c.addActiveMetaLocked(entry.k, meta)
			if !c.scheduleEntryLocked(meta, v, 0, false, now, true) {
				c.removeActiveMetaLocked(entry.k, meta)
				return false
			}
			return true
		}()
		if installed {
			restored++
		}
	}
	if restored > 0 && c.activeRefreshEvents != nil {
		c.activeRefreshEvents.WithLabelValues("dump_restored_tasks").Add(float64(restored))
	}
	if restored > 0 {
		c.notifyActiveScheduler()
	}
}

func queryContextFromKey(k key) (*query_context.Context, bool) {
	data := []byte(k)
	question, ok := questionFromKey(k)
	if !ok {
		return nil, false
	}
	flags := data[0]
	offset := 1 + 2 + 2
	nameLength := int(data[offset])
	offset++
	offset += nameLength
	ecsLength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	ecsData := data[offset : offset+ecsLength]

	var ecs *dns.EDNS0_SUBNET
	if len(ecsData) > 0 {
		if len(ecsData) < 3 {
			return nil, false
		}
		family := binary.BigEndian.Uint16(ecsData[:2])
		sourceMask := ecsData[2]
		addressBytes := ecsData[3:]
		var address net.IP
		switch family {
		case 1:
			if sourceMask > 32 || len(addressBytes) != (int(sourceMask)+7)/8 {
				return nil, false
			}
			address = make(net.IP, net.IPv4len)
		case 2:
			if sourceMask > 128 || len(addressBytes) != (int(sourceMask)+7)/8 {
				return nil, false
			}
			address = make(net.IP, net.IPv6len)
		default:
			return nil, false
		}
		copy(address, addressBytes)
		ecs = &dns.EDNS0_SUBNET{
			Code: dns.EDNS0SUBNET, Family: family, SourceNetmask: sourceMask, Address: address,
		}
	}

	q := new(dns.Msg)
	q.MsgHdr.AuthenticatedData = flags&adBit != 0
	q.MsgHdr.CheckingDisabled = flags&cdBit != 0
	q.MsgHdr.RecursionDesired = flags&rdBit != 0
	q.Question = []dns.Question{question}
	// Build the client OPT before NewContext takes ownership, then mirror the
	// key-relevant state into the mutable query OPT. This preserves both QOpt
	// and ClientOpt semantics for dump-restored refresh sequences.
	if flags&doBit != 0 || ecs != nil {
		clientOpt := new(dns.OPT)
		clientOpt.Hdr.Name = "."
		clientOpt.Hdr.Rrtype = dns.TypeOPT
		clientOpt.SetUDPSize(1232)
		if flags&doBit != 0 {
			clientOpt.SetDo()
		}
		if ecs != nil {
			clientOpt.Option = append(clientOpt.Option, ecs)
		}
		q.Extra = append(q.Extra, clientOpt)
	}
	qCtx := query_context.NewContext(q)
	opt := qCtx.QOpt()
	if flags&doBit != 0 {
		opt.SetDo()
	}
	if ecs != nil {
		opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
			Code: ecs.Code, Family: ecs.Family, SourceNetmask: ecs.SourceNetmask,
			SourceScope: ecs.SourceScope, Address: append(net.IP(nil), ecs.Address...),
		})
	}
	return qCtx, true
}

func (c *Cache) activeRefreshAt(_ key, v *item) time.Time {
	refreshAt, _, ok := calculateRefreshAt(v, time.Duration(c.args.ActiveRefresh.Threshold)*time.Second)
	if !ok {
		return time.Time{}
	}
	return refreshAt
}

func (c *Cache) needsActiveRefresh(v *item, now time.Time) bool {
	refreshAt := c.activeRefreshAt("", v)
	return !refreshAt.IsZero() && !now.Before(refreshAt)
}
