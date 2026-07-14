package cache

import (
	"container/heap"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
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
	k        key
	qCtx     *query_context.Context
	next     sequence.ChainWalker
	expected *item
	task     *refreshTask

	lastAccess   atomic.Int64
	refreshCount atomic.Int64
	stopped      atomic.Bool
}

type activeRefreshWork struct {
	task     *refreshTask
	qCtx     *query_context.Context
	next     sequence.ChainWalker
	expected *item
	epoch    uint64
	flight   refreshFlightKey
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

func (c *Cache) observeActiveRefresh(k key, expected *item, qCtx *query_context.Context, next sequence.ChainWalker, now time.Time, response *dns.Msg) {
	if !c.activeRefreshEnabled() || expected == nil || qCtx == nil {
		return
	}
	// k may be a zero-copy view over a pooled request buffer on the L1 path.
	durableKey := key(strings.Clone(string(k)))
	// Ordinary hits on an already tracked generation only update activity and
	// (when still in the future heap) its idle sentinel. Avoid a backend lookup,
	// query-context copy and per-key commit lock on this hot path. Generation and
	// exclusions are checked again before any worker or token is consumed.
	c.activeMu.Lock()
	if meta := c.activeMeta[durableKey]; meta != nil && meta.expected == expected && meta.task != nil && !meta.stopped.Load() {
		recordRealCacheAccess(expected, now)
		meta.lastAccess.Store(now.UnixNano())
		meta.refreshCount.Store(0)
		dueChanged := c.recalculateScheduledDueLocked(meta, now)
		c.activeMu.Unlock()
		if dueChanged {
			c.notifyActiveScheduler()
		}
		return
	}
	c.activeMu.Unlock()
	c.trackActiveRefresh(durableKey, expected, qCtx, next, now, response)
}

func (c *Cache) trackActiveRefresh(k key, expected *item, qCtx *query_context.Context, next sequence.ChainWalker, now time.Time, response *dns.Msg) {
	if !c.activeRefreshEnabled() || expected == nil || qCtx == nil || !c.activeExcludeDomainValid {
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
	// This is real client activity even when the current answer is excluded
	// from active refresh. Persist it on the item before applying scheduling
	// exclusions so a later rule change or dump restore sees the correct idle
	// and consecutive-success state.
	recordRealCacheAccess(expected, now)

	question, ok := questionFromKey(k)
	if !ok {
		c.removeActiveMetaIfExpected(k, expected)
		commitMu.Unlock()
		c.flushMu.RUnlock()
		return
	}
	if c.activeDomainExcluded(question.Name) {
		c.activeEvent("excluded_domain_skipped")
		c.removeActiveMetaIfExpected(k, expected)
		commitMu.Unlock()
		c.flushMu.RUnlock()
		return
	}
	if response != nil && c.containsActiveExcluded(response) {
		c.activeEvent("excluded_ip_skipped")
		c.removeActiveMetaIfExpected(k, expected)
		commitMu.Unlock()
		c.flushMu.RUnlock()
		return
	}

	c.activeMu.Lock()
	meta := c.activeMeta[k]
	if meta == nil {
		if !c.ensureActiveMetaSlotLocked() {
			c.activeMu.Unlock()
			commitMu.Unlock()
			c.flushMu.RUnlock()
			return
		}
		meta = &activeRefreshMeta{k: k}
		c.activeMeta[k] = meta
	}
	sameGeneration := meta.expected == expected
	meta.qCtx = qCtx.CopyWithoutResponse()
	meta.next = next.Fork()
	meta.expected = expected
	meta.lastAccess.Store(now.UnixNano())
	meta.refreshCount.Store(0)
	meta.stopped.Store(false)
	// A real hit must not postpone an already scheduled TTL deadline. This is
	// especially important for an expired answer whose existing task is a
	// fallback probe. Rebuild only when the cache generation changed or the
	// previous task was stopped/dropped.
	if !sameGeneration || meta.task == nil {
		if now.Before(expected.expirationTime) {
			c.scheduleEntryLocked(meta, expected, 0, false, now, false)
		} else if cfg := c.args.ActiveRefresh.FallbackProbe; cfg.Enabled &&
			!expected.staleDeadline.IsZero() && now.Before(expected.staleDeadline) {
			c.scheduleEntryLocked(meta, expected, 0, true, now, false)
		}
	} else {
		c.recalculateScheduledDueLocked(meta, now)
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

func (c *Cache) recalculateScheduledDueLocked(meta *activeRefreshMeta, now time.Time) bool {
	if meta == nil || meta.task == nil || meta.task.scheduleIndex < 0 {
		return false
	}
	t := meta.task
	due := t.refreshAt
	if maxIdle := c.args.ActiveRefresh.MaxIdleTime; maxIdle > 0 {
		idleAt := time.Unix(0, meta.lastAccess.Load()).Add(time.Duration(maxIdle) * time.Second)
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

func (c *Cache) evictLeastUrgentMetaLocked() bool {
	// Backend eviction is the cheapest and highest-value cleanup. Only absent
	// entries are removed here: a different current pointer can be the brief
	// interval between a successful commit and its metadata handoff.
	for k, candidate := range c.activeMeta {
		if current, _, present := c.backend.Get(k); !present || current == nil {
			c.removeActiveMetaLocked(k, candidate)
		}
	}
	if len(c.activeMeta) < max(c.args.Size, 1) {
		return true
	}
	// A candidate can become pinned while we inspect another key because cache
	// commits and inflight claims do not require activeMu. Revalidate the final
	// victim, and skip a failed candidate for the remainder of this attempt.
	skipped := make(map[*activeRefreshMeta]struct{})
	for len(skipped) < len(c.activeMeta) {
		var victim *activeRefreshMeta
		for _, candidate := range c.activeMeta {
			if _, wasSkipped := skipped[candidate]; wasSkipped {
				continue
			}
			current, _, present := c.backend.Get(candidate.k)
			if c.activeMetaPinnedForEviction(candidate, current, present) {
				continue
			}
			if victim == nil || (candidate.expected != nil && victim.expected != nil && candidate.expected.expirationTime.After(victim.expected.expirationTime)) {
				victim = candidate
			}
		}
		if victim == nil {
			return false
		}

		current, _, present := c.backend.Get(victim.k)
		if c.activeMeta[victim.k] != victim || c.activeMetaPinnedForEviction(victim, current, present) {
			skipped[victim] = struct{}{}
			continue
		}
		c.removeActiveMetaLocked(victim.k, victim)
		return true
	}
	return false
}

func (c *Cache) ensureActiveMetaSlotLocked() bool {
	maxMeta := max(c.args.Size, 1)
	for len(c.activeMeta) >= maxMeta {
		if !c.evictLeastUrgentMetaLocked() {
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
		idleAt := time.Unix(0, meta.lastAccess.Load()).Add(time.Duration(maxIdle) * time.Second)
		if idleAt.Before(t.dueAt) {
			t.dueAt = idleAt
		}
	}
	if t.dueAt.Before(now) {
		t.dueAt = now
	}
	meta.task = t
	meta.expected = expected
	heap.Push(&c.activeSchedule, t)
	c.activeEvent("scheduled")
	return true
}

func kClone(k key) key { return key(strings.Clone(string(k))) }

func (c *Cache) removeMetaTaskLocked(meta *activeRefreshMeta) {
	if meta == nil || meta.task == nil {
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
	delete(c.activeMeta, k)
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
				c.refreshInFlight.Delete(work.flight)
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
				t.meta.task = nil
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
			dropped.meta.task = nil
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
			last := time.Unix(0, t.meta.lastAccess.Load())
			inactive = now.Sub(last) >= time.Duration(c.args.ActiveRefresh.MaxIdleTime)*time.Second
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
						t.meta.task = nil
					}
				} else if t.meta.task == t {
					t.meta.task = nil
				}
				c.activeEvent("duplicate_inflight")
				continue
			}
			if t.meta != nil && t.meta.task == t {
				t.meta.task = nil
				if (backendMissing || inactive || excludedDomain || excludedIP) && c.activeMeta[t.key] == t.meta {
					delete(c.activeMeta, t.key)
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
	if meta.qCtx == nil {
		c.removeActiveMetaLocked(task.key, meta)
		c.activeMu.Unlock()
		return nil, false
	}
	qCtx := meta.qCtx.CopyWithoutResponse()
	next := meta.next.Fork()
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
	// Make activity and max-success decisions atomically with real-hit updates.
	// If a hit waits behind this lock after a remove/stop decision, its slow path
	// will recreate or reactivate the task; if it won the lock first, these reads
	// observe its new lastAccess/count.
	c.activeMu.Lock()
	if meta.task != task || c.activeMeta[task.key] != meta || meta.expected != expected {
		c.activeMu.Unlock()
		c.activeEvent("stale_generation")
		return nil, false
	}
	if maxIdle := c.args.ActiveRefresh.MaxIdleTime; maxIdle > 0 {
		lastAccess := time.Unix(0, meta.lastAccess.Load())
		if now.Sub(lastAccess) >= time.Duration(maxIdle)*time.Second {
			c.removeActiveMetaLocked(task.key, meta)
			c.activeMu.Unlock()
			c.activeEvent("inactive_skipped")
			return nil, false
		}
	}
	if now.Before(task.refreshAt) && task.dueAt.Before(task.refreshAt) {
		// This is a max-idle sentinel, not the TTL refresh deadline. A real hit may
		// have extended the idle boundary after the scheduler moved it to pending;
		// in that case return it to the future heap instead of querying early.
		task.dueAt = task.refreshAt
		if maxIdle := c.args.ActiveRefresh.MaxIdleTime; maxIdle > 0 {
			idleAt := time.Unix(0, meta.lastAccess.Load()).Add(time.Duration(maxIdle) * time.Second)
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
	if maxRefresh := c.args.ActiveRefresh.MaxRefreshTimes; maxRefresh > 0 && meta.refreshCount.Load() >= int64(maxRefresh) {
		meta.task = nil
		meta.stopped.Store(true)
		c.activeMu.Unlock()
		return nil, false
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
		task: task, qCtx: qCtx, next: next,
		expected: current, epoch: epoch,
		flight: refreshFlightKey{k: task.key, generation: task.generation},
	}, !task.probeOnly
}

func (c *Cache) claimActiveFlight(work *activeRefreshWork) bool {
	if work == nil {
		return false
	}
	_, loaded := c.refreshInFlight.LoadOrStore(work.flight, struct{}{})
	return !loaded
}

func (c *Cache) discardActiveTask(task *refreshTask, removeMeta bool) {
	c.activeMu.Lock()
	if task != nil && task.meta != nil && task.meta.task == task {
		task.meta.task = nil
		if removeMeta && c.activeMeta[task.key] == task.meta {
			delete(c.activeMeta, task.key)
		}
	}
	c.activeMu.Unlock()
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
			task.meta.task = nil
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
	defer c.refreshInFlight.Delete(work.flight)
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
				c.updateActiveRefreshAfterCommit(work.task.key, work.expected, prepared.item, time.Now(), prepared.msg, true, work.qCtx, work.next)
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
					c.updateActiveRefreshAfterCommit(work.task.key, expected, prepared.item, time.Now(), prepared.msg, false, work.qCtx, work.next)
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
	qCtx *query_context.Context,
	next sequence.ChainWalker,
) {
	if !c.activeRefreshEnabled() || updated == nil {
		return
	}
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
		if qCtx == nil {
			c.activeMu.Unlock()
			return
		}
		if !c.ensureActiveMetaSlotLocked() {
			c.activeMu.Unlock()
			return
		}
		meta = &activeRefreshMeta{k: k, qCtx: qCtx.CopyWithoutResponse(), next: next.Fork(), expected: expected}
		meta.lastAccess.Store(updated.lastRealAccess.Load())
		meta.refreshCount.Store(updated.refreshSuccess.Load())
		c.activeMeta[k] = meta
	} else if meta.expected != expected {
		c.activeMu.Unlock()
		return
	}
	c.removeMetaTaskLocked(meta)
	meta.expected = updated
	if activeSuccess {
		meta.refreshCount.Add(1)
	}
	updated.lastRealAccess.Store(meta.lastAccess.Load())
	updated.refreshSuccess.Store(meta.refreshCount.Load())
	question, validQuestion := questionFromKey(k)
	excludedDomain := !validQuestion || c.activeDomainExcluded(question.Name)
	excludedIP := response != nil && c.containsActiveExcluded(response)
	if excludedDomain || excludedIP {
		delete(c.activeMeta, k)
		c.activeMu.Unlock()
		if excludedDomain {
			c.activeEvent("excluded_domain_skipped")
		} else {
			c.activeEvent("excluded_ip_skipped")
		}
		c.notifyActiveScheduler()
		return
	}
	if maxRefresh := c.args.ActiveRefresh.MaxRefreshTimes; maxRefresh > 0 && meta.refreshCount.Load() >= int64(maxRefresh) {
		meta.stopped.Store(true)
	} else {
		c.scheduleEntryLocked(meta, updated, 0, false, now, false)
	}
	c.activeMu.Unlock()
	c.notifyActiveScheduler()
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
			if !c.ensureActiveMetaSlotLocked() {
				return false
			}

			meta := &activeRefreshMeta{
				k: entry.k, qCtx: qCtx, next: next.Fork(), expected: v,
			}
			meta.lastAccess.Store(lastAccess.UnixNano())
			meta.refreshCount.Store(int64(entry.refreshCount))
			c.activeMeta[entry.k] = meta
			if !c.scheduleEntryLocked(meta, v, 0, false, now, true) {
				delete(c.activeMeta, entry.k)
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
