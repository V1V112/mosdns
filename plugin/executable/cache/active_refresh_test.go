package cache

import (
	"bytes"
	"container/heap"
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func newDormantActiveCache(t *testing.T, args *Args, opts Opts) *Cache {
	t.Helper()
	args.ActiveRefresh.Enabled = false
	c := newCacheForTest(t, args, opts)
	args.ActiveRefresh.Enabled = true
	return c
}

func counterValue(t *testing.T, counter prometheus.Counter) float64 {
	t.Helper()
	metric := new(dto.Metric)
	if err := counter.Write(metric); err != nil {
		t.Fatal(err)
	}
	return metric.GetCounter().GetValue()
}

func preparedAWithAge(t *testing.T, q *dns.Msg, ttl, age time.Duration) *preparedCacheEntry {
	t.Helper()
	p := testPreparedA(t, q, "192.0.2.1", ttl)
	p.item.storedTime = time.Now().Add(-age)
	p.item.expirationTime = p.item.storedTime.Add(ttl)
	p.cacheExpiration = p.item.expirationTime
	return p
}

func seedTrackedEntry(t *testing.T, c *Cache, name string, ttl, age time.Duration) (key, *query_context.Context, *preparedCacheEntry) {
	t.Helper()
	qCtx := newTestQuery(name, dns.TypeA, dns.ClassINET, true)
	k := testCacheKey(t, qCtx)
	p := preparedAWithAge(t, qCtx.Q(), ttl, age)
	if !c.commitPrepared(k, nil, 0, p) {
		t.Fatal("failed to seed cache entry")
	}
	c.trackActiveRefresh(k, p.item, qCtx.CopyWithoutResponse(), sequence.ChainWalker{}, time.Now(), p.msg)
	return k, qCtx, p
}

func TestActiveRefreshDynamicTimingHelpers(t *testing.T) {
	if got := calculateRetryDelay(12*time.Second, 10*time.Second); got != 4*time.Second {
		t.Fatalf("retry delay = %s, want 4s", got)
	}
	if got := calculateRetryDelay(time.Second, 10*time.Second); got != activeRefreshRetryFloor {
		t.Fatalf("short retry delay = %s, want %s", got, activeRefreshRetryFloor)
	}
	if got, ok := calculateRequeryTimeout(time.Second, 1500*time.Millisecond); !ok || got != 750*time.Millisecond {
		t.Fatalf("timeout = %s, %v; want 750ms", got, ok)
	}
	if got, ok := calculateRequeryTimeout(5*time.Second, 10*time.Second); !ok || got != time.Second {
		t.Fatalf("configured timeout cap = %s, %v; want 1s", got, ok)
	}
	if _, ok := calculateRequeryTimeout(time.Second, 80*time.Millisecond); ok {
		t.Fatal("insufficient remaining TTL unexpectedly allowed a requery")
	}
	if got, ok := calculateProbeTimeout(500*time.Millisecond, 120*time.Millisecond); !ok || got != 120*time.Millisecond {
		t.Fatalf("probe timeout = %s, %v; want 120ms", got, ok)
	}
}

func TestRefreshTokenBucketBurstAndRate(t *testing.T) {
	now := time.Unix(1700000000, 0)
	bucket := newRefreshTokenBucket(2, 3, now)
	for i := 0; i < 3; i++ {
		if !bucket.take(now) {
			t.Fatalf("burst token %d was not available", i)
		}
	}
	if bucket.take(now) {
		t.Fatal("bucket exceeded configured burst")
	}
	if got := bucket.delay(now); got != 500*time.Millisecond {
		t.Fatalf("next token delay = %s, want 500ms", got)
	}
	if !bucket.take(now.Add(500 * time.Millisecond)) {
		t.Fatal("rate token did not refill")
	}
	tiny := newRefreshTokenBucket(1e-300, 1, now)
	if !tiny.take(now) {
		t.Fatal("tiny-rate bucket did not provide its burst token")
	}
	if got := tiny.delay(now); got != activeRefreshMaxTimerDelay {
		t.Fatalf("tiny-rate delay = %s, want saturated timer delay", got)
	}
}

func TestActiveRefreshMetricsExposeAllRequiredEvents(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16}, Opts{})
	defer c.Close()
	registry := prometheus.NewRegistry()
	if err := c.RegMetricsTo(registry); err != nil {
		t.Fatal(err)
	}
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, family := range families {
		if family.GetName() != "active_refresh_events_total" {
			continue
		}
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetName() == "event" {
					seen[label.GetValue()] = true
				}
			}
		}
	}
	for _, event := range activeRefreshEventNames {
		if !seen[event] {
			t.Errorf("metric event %q is missing", event)
		}
	}
}

func TestPendingQueuePrioritizesEarliestExpirationAndDropsLatest(t *testing.T) {
	args := &Args{Size: 16, ActiveRefresh: ActiveRefreshArgs{
		Threshold: 60, MaxPendingTasks: 2, MaxTasksPerBatch: 16,
	}}
	c := newDormantActiveCache(t, args, Opts{})
	defer c.Close()

	now := time.Now()
	for i, remaining := range []time.Duration{15 * time.Second, 5 * time.Second, 10 * time.Second} {
		ttl := 30 * time.Second
		age := ttl - remaining
		seedTrackedEntry(t, c, "priority-"+string(rune('a'+i))+".example.", ttl, age)
	}
	c.moveDueActiveTasks(now.Add(time.Second))
	first := c.popPendingTask()
	second := c.popPendingTask()
	if first == nil || second == nil {
		t.Fatalf("pending tasks = %#v, %#v; want two", first, second)
	}
	firstRemaining := first.expireAt.Sub(now)
	secondRemaining := second.expireAt.Sub(now)
	if !(firstRemaining < secondRemaining && secondRemaining < 13*time.Second) {
		t.Fatalf("pending deadlines = %s, %s; latest task was not evicted", firstRemaining, secondRemaining)
	}
}

func TestStaleGenerationRejectedBeforeInflight(t *testing.T) {
	args := &Args{Size: 16, ActiveRefresh: ActiveRefreshArgs{Threshold: 60}}
	c := newDormantActiveCache(t, args, Opts{})
	defer c.Close()

	k, qCtx, old := seedTrackedEntry(t, c, "generation.example.", 30*time.Second, 22*time.Second)
	c.moveDueActiveTasks(time.Now())
	task := c.popPendingTask()
	if task == nil {
		t.Fatal("due task was not moved to pending")
	}
	newer := testPreparedA(t, qCtx.Q(), "192.0.2.2", time.Minute)
	if !c.commitPrepared(k, old.item, c.refreshEpoch.Load(), newer) {
		t.Fatal("failed to replace cache generation")
	}
	work, _ := c.prepareActiveWork(task, time.Now())
	if work != nil {
		t.Fatal("stale generation reached worker preparation")
	}
	if _, present := c.refreshInFlight.Load(refreshFlightKey{k: k, generation: old.item.generation}); present {
		t.Fatal("stale generation consumed inflight state")
	}
	// Simulate the commit-to-metadata handoff used by a concurrent lazy refresh.
	// Rejecting the old task must not delete the metadata container needed here.
	c.updateActiveRefreshAfterCommit(k, old.item, newer.item, time.Now(), newer.msg, false, qCtx, sequence.ChainWalker{})
	c.activeMu.RLock()
	meta := c.activeMeta[k]
	c.activeMu.RUnlock()
	if meta == nil || meta.expected != newer.item || meta.task == nil || meta.task.generation != newer.item.generation {
		t.Fatalf("new generation handoff was lost: %#v", meta)
	}
}

func TestActiveRefreshInflightDeduplication(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16}, Opts{})
	defer c.Close()
	_, _, p := seedTrackedEntry(t, c, "inflight.example.", 30*time.Second, 22*time.Second)
	work := &activeRefreshWork{flight: refreshFlightKey{k: "same", generation: p.item.generation}}
	if !c.claimActiveFlight(work) {
		t.Fatal("first inflight claim failed")
	}
	if c.claimActiveFlight(work) {
		t.Fatal("duplicate inflight claim succeeded")
	}
	c.refreshInFlight.Delete(work.flight)
	if !c.claimActiveFlight(work) {
		t.Fatal("inflight state was not reusable after cleanup")
	}
	c.refreshInFlight.Delete(work.flight)
}

func TestActiveRefreshSuccessReschedulesFromNewTTL(t *testing.T) {
	var queries atomic.Int32
	exec := sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
		queries.Add(1)
		qCtx.SetResponse(testAResponse(t, qCtx.Q(), "192.0.2.2", 60))
		return nil
	})
	c := newDormantActiveCache(t, &Args{Size: 16}, Opts{ActiveRefreshExec: exec})
	defer c.Close()

	k, _, old := seedTrackedEntry(t, c, "success.example.", 30*time.Second, 22*time.Second)
	c.activeMu.RLock()
	task := c.activeMeta[k].task
	c.activeMu.RUnlock()
	work := &activeRefreshWork{
		task: task, qCtx: task.meta.qCtx.CopyWithoutResponse(), next: task.meta.next.Fork(),
		expected: old.item, epoch: c.refreshEpoch.Load(),
		flight: refreshFlightKey{k: k, generation: old.item.generation},
	}
	started := time.Now()
	c.runActiveRefreshTask(work)
	if queries.Load() != 1 {
		t.Fatalf("queries = %d, want 1", queries.Load())
	}
	current, _, ok := c.backend.Get(k)
	if !ok || current.generation == old.item.generation {
		t.Fatal("successful refresh did not install a new generation")
	}
	c.activeMu.RLock()
	rescheduled := c.activeMeta[k].task
	c.activeMu.RUnlock()
	if rescheduled == nil || rescheduled.generation != current.generation {
		t.Fatal("new generation was not rescheduled")
	}
	if got := rescheduled.refreshAt.Sub(started); got < 39*time.Second || got > 41*time.Second {
		t.Fatalf("new 60s TTL refresh delay = %s, want about 40s", got)
	}
}

func TestMaxRefreshSuccessLimitStopsUntilRealAccess(t *testing.T) {
	exec := sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
		qCtx.SetResponse(testAResponse(t, qCtx.Q(), "192.0.2.2", 60))
		return nil
	})
	c := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: ActiveRefreshArgs{
		MaxRefreshTimes: 1,
	}}, Opts{ActiveRefreshExec: exec})
	defer c.Close()

	k, qCtx, old := seedTrackedEntry(t, c, "max-success.example.", 30*time.Second, 22*time.Second)
	c.activeMu.RLock()
	task := c.activeMeta[k].task
	c.activeMu.RUnlock()
	c.runActiveRefreshTask(&activeRefreshWork{
		task: task, qCtx: task.meta.qCtx.CopyWithoutResponse(), expected: old.item,
		epoch: c.refreshEpoch.Load(), flight: refreshFlightKey{k: k, generation: old.item.generation},
	})

	current, _, present := c.backend.Get(k)
	c.activeMu.RLock()
	meta := c.activeMeta[k]
	c.activeMu.RUnlock()
	if !present || meta == nil || meta.expected != current || meta.task != nil || !meta.stopped.Load() || meta.refreshCount.Load() != 1 {
		t.Fatalf("max-refresh stop state: present=%v current=%#v meta=%#v", present, current, meta)
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(current.resp); err != nil {
		t.Fatal(err)
	}
	c.observeActiveRefresh(k, current, qCtx, sequence.ChainWalker{}, time.Now(), msg)
	c.activeMu.RLock()
	resumed := meta.task != nil && !meta.stopped.Load() && meta.refreshCount.Load() == 0
	c.activeMu.RUnlock()
	if !resumed {
		t.Fatalf("real access did not resume stopped metadata: %#v", meta)
	}
}

func TestSuccessfulRefreshCommitsNewlyExcludedAnswerThenStops(t *testing.T) {
	matcher := netlist.NewList()
	matcher.Append(netip.MustParsePrefix("192.0.2.2/32"))
	matcher.Sort()
	exec := sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
		qCtx.SetResponse(testAResponse(t, qCtx.Q(), "192.0.2.2", 60))
		return nil
	})
	c := newDormantActiveCache(t, &Args{Size: 16}, Opts{
		ActiveRefreshExec: exec, ActiveExcludeIPMatcher: matcher,
	})
	defer c.Close()
	k, _, old := seedTrackedEntry(t, c, "newly-excluded.example.", 30*time.Second, 22*time.Second)
	c.activeMu.RLock()
	task := c.activeMeta[k].task
	c.activeMu.RUnlock()
	c.runActiveRefreshTask(&activeRefreshWork{
		task: task, qCtx: task.meta.qCtx.CopyWithoutResponse(), expected: old.item,
		epoch: c.refreshEpoch.Load(), flight: refreshFlightKey{k: k, generation: old.item.generation},
	})
	current, _, ok := c.backend.Get(k)
	if !ok || current == old.item {
		t.Fatal("newly excluded fresh answer was not committed")
	}
	c.activeMu.RLock()
	_, tracked := c.activeMeta[k]
	c.activeMu.RUnlock()
	if tracked {
		t.Fatal("newly excluded answer scheduled another refresh")
	}
}

func TestActiveRefreshFailureUsesDynamicRetry(t *testing.T) {
	exec := sequence.ExecutableFunc(func(context.Context, *query_context.Context) error {
		return errors.New("upstream failed")
	})
	args := &Args{Size: 16, ActiveRefresh: ActiveRefreshArgs{MaxRetryTimes: 2}}
	c := newDormantActiveCache(t, args, Opts{ActiveRefreshExec: exec})
	defer c.Close()

	k, _, old := seedTrackedEntry(t, c, "retry.example.", 30*time.Second, 21*time.Second)
	c.activeMu.RLock()
	task := c.activeMeta[k].task
	c.activeMu.RUnlock()
	work := &activeRefreshWork{
		task: task, qCtx: task.meta.qCtx.CopyWithoutResponse(), expected: old.item,
		epoch: c.refreshEpoch.Load(), flight: refreshFlightKey{k: k, generation: old.item.generation},
	}
	before := time.Now()
	c.runActiveRefreshTask(work)
	c.activeMu.RLock()
	retry := c.activeMeta[k].task
	c.activeMu.RUnlock()
	if retry == nil || retry.retryCount != 1 {
		t.Fatalf("retry task = %#v, want retryCount=1", retry)
	}
	if delay := retry.refreshAt.Sub(before); delay < 2500*time.Millisecond || delay > 3500*time.Millisecond {
		t.Fatalf("dynamic retry delay = %s, want about 3s", delay)
	}
}

func TestInsufficientTimeSkipsRequery(t *testing.T) {
	var queries atomic.Int32
	exec := sequence.ExecutableFunc(func(context.Context, *query_context.Context) error {
		queries.Add(1)
		return nil
	})
	c := newDormantActiveCache(t, &Args{Size: 16}, Opts{ActiveRefreshExec: exec})
	defer c.Close()

	k, _, p := seedTrackedEntry(t, c, "too-late.example.", time.Second, 920*time.Millisecond)
	c.activeMu.RLock()
	task := c.activeMeta[k].task
	c.activeMu.RUnlock()
	work := &activeRefreshWork{
		task: task, qCtx: task.meta.qCtx.CopyWithoutResponse(), expected: p.item,
		epoch: c.refreshEpoch.Load(), flight: refreshFlightKey{k: k, generation: p.item.generation},
	}
	c.runActiveRefreshTask(work)
	if queries.Load() != 0 {
		t.Fatal("requery ran without enough remaining TTL")
	}
}

func TestExcludeIPRecheckRejectsTaskBeforeWorkerAndToken(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16}, Opts{})
	defer c.Close()
	k, _, _ := seedTrackedEntry(t, c, "excluded-late.example.", 30*time.Second, 22*time.Second)

	list := netlist.NewList()
	list.Append(netip.MustParsePrefix("192.0.2.0/24"))
	list.Sort()
	c.activeExcludeIPMatcher = list
	beforeRefresh := counterValue(t, c.activeRefreshTotal)
	beforeFailed := counterValue(t, c.activeRefreshFailedTotal)
	beforeProbe := counterValue(t, c.activeRefreshProbeTotal)
	c.moveDueActiveTasks(time.Now())
	task := c.popPendingTask()
	if task == nil {
		t.Fatal("due task was not pending")
	}
	work, _ := c.prepareActiveWork(task, time.Now())
	if work != nil {
		t.Fatal("newly excluded response reached worker preparation")
	}
	if _, present := c.refreshInFlight.Load(refreshFlightKey{k: k, generation: task.generation}); present {
		t.Fatal("excluded task consumed inflight state")
	}
	if got := counterValue(t, c.activeRefreshTotal); got != beforeRefresh {
		t.Fatalf("excluded task consumed a refresh attempt: before=%v after=%v", beforeRefresh, got)
	}
	if got := counterValue(t, c.activeRefreshFailedTotal); got != beforeFailed {
		t.Fatalf("excluded task incremented failures: before=%v after=%v", beforeFailed, got)
	}
	if got := counterValue(t, c.activeRefreshProbeTotal); got != beforeProbe {
		t.Fatalf("excluded task executed fallback probe: before=%v after=%v", beforeProbe, got)
	}
}

func TestInactiveEntryStopsAndRealHitReactivates(t *testing.T) {
	args := &Args{Size: 16, ActiveRefresh: ActiveRefreshArgs{MaxIdleTime: 1}}
	c := newDormantActiveCache(t, args, Opts{})
	defer c.Close()
	k, qCtx, p := seedTrackedEntry(t, c, "idle.example.", time.Hour, 0)

	c.activeMu.Lock()
	meta := c.activeMeta[k]
	meta.lastAccess.Store(time.Now().Add(-time.Hour).UnixNano())
	meta.expected.lastRealAccess.Store(meta.lastAccess.Load())
	meta.task.dueAt = time.Now().Add(-time.Millisecond)
	heap.Fix(&c.activeSchedule, meta.task.scheduleIndex)
	c.activeMu.Unlock()
	c.moveDueActiveTasks(time.Now())
	task := c.popPendingTask()
	if task == nil {
		t.Fatal("idle check task was not pending")
	}
	if work, _ := c.prepareActiveWork(task, time.Now()); work != nil {
		t.Fatal("inactive entry reached worker preparation")
	}
	c.activeMu.RLock()
	_, stillTracked := c.activeMeta[k]
	c.activeMu.RUnlock()
	if stillTracked {
		t.Fatal("inactive entry remained scheduled")
	}

	c.observeActiveRefresh(k, p.item, qCtx, sequence.ChainWalker{}, time.Now(), p.msg)
	c.activeMu.RLock()
	reactivated := c.activeMeta[k]
	c.activeMu.RUnlock()
	if reactivated == nil || reactivated.task == nil || reactivated.refreshCount.Load() != 0 {
		t.Fatalf("real cache hit did not reactivate refresh: %#v", reactivated)
	}
}

func TestRealHitRecalculatesIdleWakeWithoutMovingTTLDeadline(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: ActiveRefreshArgs{
		MaxIdleTime: 10,
	}}, Opts{})
	defer c.Close()

	k, qCtx, p := seedTrackedEntry(t, c, "idle-extension.example.", time.Hour, 0)
	c.activeMu.RLock()
	initial := c.activeMeta[k].task
	initialRefreshAt := initial.refreshAt
	initialDueAt := initial.dueAt
	c.activeMu.RUnlock()

	hitAt := time.Now().Add(5 * time.Second)
	c.trackActiveRefresh(k, p.item, qCtx.CopyWithoutResponse(), sequence.ChainWalker{}, hitAt, p.msg)
	c.activeMu.RLock()
	updated := c.activeMeta[k].task
	c.activeMu.RUnlock()
	if updated != initial {
		t.Fatal("same generation real hit replaced the TTL task")
	}
	if !updated.refreshAt.Equal(initialRefreshAt) {
		t.Fatalf("refreshAt moved from %s to %s", initialRefreshAt, updated.refreshAt)
	}
	if updated.dueAt.Sub(hitAt) < 9*time.Second || updated.dueAt.Sub(hitAt) > 11*time.Second {
		t.Fatalf("updated idle wake = %s after hit, want about 10s", updated.dueAt.Sub(hitAt))
	}
	if !updated.dueAt.After(initialDueAt.Add(4 * time.Second)) {
		t.Fatalf("idle wake was not extended: initial=%s updated=%s", initialDueAt, updated.dueAt)
	}
	c.moveDueActiveTasks(initialDueAt.Add(100 * time.Millisecond))
	if task := c.popPendingTask(); task != nil {
		t.Fatal("old idle deadline incorrectly produced pending work")
	}
}

func TestPendingIdleSentinelExtendedByRealHitIsRequeued(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: ActiveRefreshArgs{
		MaxIdleTime: 10,
	}}, Opts{})
	defer c.Close()

	k, qCtx, p := seedTrackedEntry(t, c, "pending-idle.example.", time.Hour, 0)
	now := time.Now()
	c.activeMu.Lock()
	meta := c.activeMeta[k]
	meta.lastAccess.Store(now.Add(-10 * time.Second).UnixNano())
	meta.task.dueAt = now.Add(-time.Millisecond)
	heap.Fix(&c.activeSchedule, meta.task.scheduleIndex)
	c.activeMu.Unlock()
	c.moveDueActiveTasks(now)
	// The real hit races after transfer to pending, so scheduleIndex is already
	// gone and trackActiveRefresh cannot simply heap.Fix the old idle sentinel.
	c.trackActiveRefresh(k, p.item, qCtx.CopyWithoutResponse(), sequence.ChainWalker{}, now, p.msg)
	task := c.popPendingTask()
	if task == nil {
		t.Fatal("idle sentinel was not pending")
	}
	if !now.Before(task.refreshAt) || !task.dueAt.Before(task.refreshAt) {
		t.Fatalf("task is not an idle sentinel: due=%s refresh=%s", task.dueAt, task.refreshAt)
	}
	if work, _ := c.prepareActiveWork(task, now); work != nil {
		t.Fatal("recently reactivated idle sentinel produced upstream work")
	}
	c.activeMu.RLock()
	rescheduled := task.meta.task == task && task.scheduleIndex >= 0
	delay := task.dueAt.Sub(now)
	c.activeMu.RUnlock()
	if !rescheduled || delay < 9*time.Second || delay > 11*time.Second {
		t.Fatalf("idle sentinel was not requeued at the extended boundary: scheduled=%v delay=%s", rescheduled, delay)
	}
}

func TestOldGenerationObservationCannotDeleteNewMetadata(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16}, Opts{})
	defer c.Close()

	k, qCtx, old := seedTrackedEntry(t, c, "observation-race.example.", time.Minute, 0)
	newer := testPreparedA(t, qCtx.Q(), "192.0.2.2", 2*time.Minute)
	if !c.commitPrepared(k, old.item, c.refreshEpoch.Load(), newer) {
		t.Fatal("failed to commit newer generation")
	}
	c.trackActiveRefresh(k, newer.item, qCtx.CopyWithoutResponse(), sequence.ChainWalker{}, time.Now(), newer.msg)
	c.trackActiveRefresh(k, old.item, qCtx.CopyWithoutResponse(), sequence.ChainWalker{}, time.Now(), old.msg)

	c.activeMu.RLock()
	meta := c.activeMeta[k]
	c.activeMu.RUnlock()
	if meta == nil || meta.expected != newer.item || meta.task == nil || meta.task.generation != newer.item.generation {
		t.Fatalf("old observation damaged new metadata: %#v", meta)
	}
}

func TestMetadataCapPinsGenerationHandoff(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 1}, Opts{})
	defer c.Close()

	k1, qCtx1, old := seedTrackedEntry(t, c, "handoff-pinned.example.", time.Minute, 0)
	newer := testPreparedA(t, qCtx1.Q(), "192.0.2.2", 2*time.Minute)
	if !c.commitPrepared(k1, old.item, c.refreshEpoch.Load(), newer) {
		t.Fatal("failed to commit handoff generation")
	}

	var qCtx2 *query_context.Context
	var k2 key
	for i := 0; ; i++ {
		candidate := newTestQuery("handoff-contender-"+string(rune('a'+i))+".example.", dns.TypeA, dns.ClassINET, true)
		candidateKey := testCacheKey(t, candidate)
		if candidateKey.Sum()%64 != k1.Sum()%64 {
			qCtx2, k2 = candidate, candidateKey
			break
		}
	}
	contender := testPreparedA(t, qCtx2.Q(), "192.0.2.3", time.Minute)
	if !c.commitPrepared(k2, nil, 0, contender) {
		t.Fatal("failed to commit contender")
	}
	c.trackActiveRefresh(k2, contender.item, qCtx2.CopyWithoutResponse(), sequence.ChainWalker{}, time.Now(), contender.msg)

	c.activeMu.RLock()
	pinned := c.activeMeta[k1]
	_, contenderTracked := c.activeMeta[k2]
	c.activeMu.RUnlock()
	if pinned == nil || pinned.expected != old.item || contenderTracked {
		t.Fatalf("cap evicted handoff metadata: pinned=%#v contenderTracked=%v", pinned, contenderTracked)
	}
	c.updateActiveRefreshAfterCommit(k1, old.item, newer.item, time.Now(), newer.msg, false, qCtx1, sequence.ChainWalker{})
	c.activeMu.RLock()
	handedOff := c.activeMeta[k1]
	metaLen := len(c.activeMeta)
	c.activeMu.RUnlock()
	if handedOff == nil || handedOff.expected != newer.item || handedOff.task == nil || metaLen != 1 {
		t.Fatalf("generation handoff after cap pressure = %#v, metaLen=%d", handedOff, metaLen)
	}
}

func TestMetadataCapPinsInflightAndDispatchedTask(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 1}, Opts{})
	defer c.Close()

	k, _, p := seedTrackedEntry(t, c, "inflight-meta-pinned.example.", time.Minute, 0)
	flight := refreshFlightKey{k: k, generation: p.item.generation}
	c.refreshInFlight.Store(flight, struct{}{})
	c.activeMu.Lock()
	evictedInflight := c.evictLeastUrgentMetaLocked()
	inflightMeta := c.activeMeta[k]
	c.activeMu.Unlock()
	c.refreshInFlight.Delete(flight)
	if evictedInflight || inflightMeta == nil {
		t.Fatalf("inflight metadata was evicted: evicted=%v meta=%#v", evictedInflight, inflightMeta)
	}

	c.activeMu.Lock()
	task := c.activeMeta[k].task
	if task == nil || task.scheduleIndex < 0 {
		c.activeMu.Unlock()
		t.Fatalf("tracked task is not in future heap: %#v", task)
	}
	heap.Remove(&c.activeSchedule, task.scheduleIndex)
	evictedDispatched := c.evictLeastUrgentMetaLocked()
	dispatchedMeta := c.activeMeta[k]
	c.activeMu.Unlock()
	if evictedDispatched || dispatchedMeta == nil {
		t.Fatalf("dispatched metadata was evicted: evicted=%v meta=%#v", evictedDispatched, dispatchedMeta)
	}
}

func TestMetadataHandoffRecoversEvictedContainer(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 1}, Opts{})
	defer c.Close()

	k, qCtx, old := seedTrackedEntry(t, c, "handoff-recovery.example.", time.Minute, 0)
	newer := testPreparedA(t, qCtx.Q(), "192.0.2.2", 2*time.Minute)
	if !c.commitPrepared(k, old.item, c.refreshEpoch.Load(), newer) {
		t.Fatal("failed to commit replacement generation")
	}
	c.activeMu.Lock()
	c.removeActiveMetaLocked(k, c.activeMeta[k])
	c.activeMu.Unlock()

	c.updateActiveRefreshAfterCommit(k, old.item, newer.item, time.Now(), newer.msg, false, qCtx, sequence.ChainWalker{})
	c.activeMu.RLock()
	recovered := c.activeMeta[k]
	c.activeMu.RUnlock()
	if recovered == nil || recovered.expected != newer.item || recovered.task == nil || recovered.task.generation != newer.item.generation {
		t.Fatalf("evicted handoff metadata was not recovered: %#v", recovered)
	}
}

func TestConcurrentRealHitCannotBeLostByStopDecision(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 4096, ActiveRefresh: ActiveRefreshArgs{
		MaxIdleTime: 1, MaxRefreshTimes: 1,
	}}, Opts{})
	defer c.Close()

	for i := 0; i < 100; i++ {
		k, qCtx, p := seedTrackedEntry(t, c, "stop-race-"+strconv.Itoa(i)+".example.", time.Hour, 0)
		c.activeMu.Lock()
		meta := c.activeMeta[k]
		task := meta.task
		if task.scheduleIndex >= 0 {
			heap.Remove(&c.activeSchedule, task.scheduleIndex)
		}
		if i%2 == 0 {
			meta.lastAccess.Store(time.Now().Add(-time.Hour).UnixNano())
			meta.refreshCount.Store(0)
		} else {
			meta.lastAccess.Store(time.Now().UnixNano())
			meta.refreshCount.Store(1)
		}
		c.activeMu.Unlock()

		now := time.Now()
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, _ = c.prepareActiveWork(task, now)
		}()
		go func() {
			defer wg.Done()
			<-start
			c.observeActiveRefresh(k, p.item, qCtx, sequence.ChainWalker{}, now, p.msg)
		}()
		close(start)
		wg.Wait()

		c.activeMu.RLock()
		currentMeta := c.activeMeta[k]
		valid := currentMeta != nil && currentMeta.expected == p.item && currentMeta.task != nil &&
			!currentMeta.stopped.Load() && currentMeta.refreshCount.Load() == 0
		c.activeMu.RUnlock()
		if !valid {
			t.Fatalf("real hit was lost at iteration %d: %#v", i, currentMeta)
		}
	}
}

func TestExcludedRealHitStillUpdatesPersistedActivity(t *testing.T) {
	matcher := netlist.NewList()
	matcher.Append(netip.MustParsePrefix("192.0.2.1/32"))
	matcher.Sort()
	c := newDormantActiveCache(t, &Args{Size: 16}, Opts{ActiveExcludeIPMatcher: matcher})
	defer c.Close()

	qCtx := newTestQuery("excluded-activity.example.", dns.TypeA, dns.ClassINET, true)
	k := testCacheKey(t, qCtx)
	p := testPreparedA(t, qCtx.Q(), "192.0.2.1", time.Minute)
	if !c.commitPrepared(k, nil, 0, p) {
		t.Fatal("failed to seed excluded entry")
	}
	p.item.lastRealAccess.Store(time.Now().Add(-time.Hour).UnixNano())
	p.item.refreshSuccess.Store(7)
	hitAt := time.Now()
	c.trackActiveRefresh(k, p.item, qCtx.CopyWithoutResponse(), sequence.ChainWalker{}, hitAt, p.msg)
	if got := time.Unix(0, p.item.lastRealAccess.Load()); got.Before(hitAt) {
		t.Fatalf("last real access = %s, want >= %s", got, hitAt)
	}
	if got := p.item.refreshSuccess.Load(); got != 0 {
		t.Fatalf("consecutive refresh successes = %d, want 0", got)
	}
	c.activeMu.RLock()
	_, tracked := c.activeMeta[k]
	c.activeMu.RUnlock()
	if tracked {
		t.Fatal("excluded entry remained scheduled")
	}
}

func TestMaxTasksPerBatchLimitsEachDueTransfer(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: ActiveRefreshArgs{
		MaxTasksPerBatch: 2, MaxPendingTasks: 16,
	}}, Opts{})
	defer c.Close()
	for i := 0; i < 5; i++ {
		seedTrackedEntry(t, c, "batch-"+string(rune('a'+i))+".example.", 30*time.Second, 22*time.Second)
	}
	c.moveDueActiveTasks(time.Now())
	c.activeMu.RLock()
	pending, future := len(c.activePending), len(c.activeSchedule)
	c.activeMu.RUnlock()
	if pending != 2 || future != 3 {
		t.Fatalf("after first batch pending/future = %d/%d, want 2/3", pending, future)
	}
	c.moveDueActiveTasks(time.Now())
	c.activeMu.RLock()
	pending, future = len(c.activePending), len(c.activeSchedule)
	c.activeMu.RUnlock()
	if pending != 4 || future != 1 {
		t.Fatalf("after second batch pending/future = %d/%d, want 4/1", pending, future)
	}
}

func TestFullPendingQueuePrunesDynamicallyExcludedTask(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 256, ActiveRefresh: ActiveRefreshArgs{
		MaxTasksPerBatch: 16, MaxPendingTasks: 2,
	}}, Opts{})
	defer c.Close()

	seed := func(name, address string) key {
		qCtx := newTestQuery(name, dns.TypeA, dns.ClassINET, true)
		k := testCacheKey(t, qCtx)
		p := testPreparedA(t, qCtx.Q(), address, 30*time.Second)
		p.item.storedTime = time.Now().Add(-22 * time.Second)
		p.item.expirationTime = p.item.storedTime.Add(30 * time.Second)
		p.cacheExpiration = p.item.expirationTime
		if !c.commitPrepared(k, nil, 0, p) {
			t.Fatalf("failed to seed %s", name)
		}
		c.trackActiveRefresh(k, p.item, qCtx.CopyWithoutResponse(), sequence.ChainWalker{}, time.Now(), p.msg)
		return k
	}
	excludedKey := seed("excluded-pending.example.", "192.0.2.1")
	keepKey := seed("keep-pending.example.", "192.0.2.2")
	c.moveDueActiveTasks(time.Now())

	matcher := netlist.NewList()
	matcher.Append(netip.MustParsePrefix("192.0.2.1/32"))
	matcher.Sort()
	c.activeExcludeIPMatcher = matcher
	newKey := seed("new-pending.example.", "192.0.2.3")
	c.moveDueActiveTasks(time.Now())

	c.activeMu.RLock()
	keys := make(map[key]bool, len(c.activePending))
	for _, task := range c.activePending {
		keys[task.key] = true
	}
	c.activeMu.RUnlock()
	if keys[excludedKey] || !keys[keepKey] || !keys[newKey] || len(keys) != 2 {
		t.Fatalf("pending keys after exclusion prune = %#v", keys)
	}
}

func TestPendingPruneRebuildChecksEveryHeapElement(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 4096, ActiveRefresh: ActiveRefreshArgs{
		MaxTasksPerBatch: 64, MaxPendingTasks: 64,
	}}, Opts{})
	defer c.Close()

	keep := make(map[key]bool)
	for i := 0; i < 24; i++ {
		qCtx := newTestQuery("prune-all-"+strconv.Itoa(i)+".example.", dns.TypeA, dns.ClassINET, true)
		k := testCacheKey(t, qCtx)
		address := "192.0.2.1"
		if i%2 != 0 {
			address = "192.0.2.2"
			keep[k] = true
		}
		p := testPreparedA(t, qCtx.Q(), address, 30*time.Second)
		p.item.storedTime = time.Now().Add(-22 * time.Second)
		p.item.expirationTime = p.item.storedTime.Add(30 * time.Second)
		p.cacheExpiration = p.item.expirationTime
		if !c.commitPrepared(k, nil, 0, p) {
			t.Fatalf("failed to seed %d", i)
		}
		c.trackActiveRefresh(k, p.item, qCtx.CopyWithoutResponse(), sequence.ChainWalker{}, time.Now(), p.msg)
	}
	c.moveDueActiveTasks(time.Now())
	matcher := netlist.NewList()
	matcher.Append(netip.MustParsePrefix("192.0.2.1/32"))
	matcher.Sort()
	c.activeExcludeIPMatcher = matcher
	c.activeMu.Lock()
	c.prunePendingLocked(time.Now())
	remaining := make(map[key]bool, len(c.activePending))
	for _, task := range c.activePending {
		remaining[task.key] = true
	}
	c.activeMu.Unlock()
	if len(remaining) != len(keep) {
		t.Fatalf("remaining pending tasks = %d, want %d", len(remaining), len(keep))
	}
	for k := range remaining {
		if !keep[k] {
			t.Fatalf("excluded task survived heap rebuild: %q", keyToString(k))
		}
	}
}

func TestFullPendingQueuePreservesInflightRetry(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 256, ActiveRefresh: ActiveRefreshArgs{
		MaxTasksPerBatch: 16, MaxPendingTasks: 1,
	}}, Opts{})
	defer c.Close()

	seedDue := func(name, address string) (key, *item) {
		qCtx := newTestQuery(name, dns.TypeA, dns.ClassINET, true)
		k := testCacheKey(t, qCtx)
		p := testPreparedA(t, qCtx.Q(), address, 30*time.Second)
		p.item.storedTime = time.Now().Add(-22 * time.Second)
		p.item.expirationTime = p.item.storedTime.Add(30 * time.Second)
		p.cacheExpiration = p.item.expirationTime
		if !c.commitPrepared(k, nil, 0, p) {
			t.Fatalf("failed to seed %s", name)
		}
		c.trackActiveRefresh(k, p.item, qCtx.CopyWithoutResponse(), sequence.ChainWalker{}, time.Now(), p.msg)
		return k, p.item
	}

	seedDue("pending-blocker.example.", "192.0.2.1")
	c.moveDueActiveTasks(time.Now())

	k, v := seedDue("inflight-on-full.example.", "192.0.2.2")
	c.activeMu.RLock()
	original := c.activeMeta[k].task
	c.activeMu.RUnlock()
	if original == nil {
		t.Fatal("incoming task was not scheduled")
	}
	flight := refreshFlightKey{k: k, generation: v.generation}
	c.refreshInFlight.Store(flight, struct{}{})
	c.moveDueActiveTasks(time.Now())
	c.refreshInFlight.Delete(flight)

	c.activeMu.RLock()
	retry := c.activeMeta[k].task
	inSchedule := retry != nil && retry.scheduleIndex >= 0
	c.activeMu.RUnlock()
	if retry == nil || retry == original || !inSchedule {
		t.Fatalf("full-queue inflight retry was detached: original=%p retry=%p inSchedule=%v", original, retry, inSchedule)
	}
}

func TestProbeInflightConflictRetriesUntilStaleDeadline(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: ActiveRefreshArgs{
		FallbackProbe: FallbackProbeArgs{Enabled: true, StaleExtendTTL: 60, MaxStale: 300},
	}}, Opts{})
	defer c.Close()

	qCtx := newTestQuery("probe-conflict.example.", dns.TypeA, dns.ClassINET, true)
	k := testCacheKey(t, qCtx)
	p := preparedAWithAge(t, qCtx.Q(), 30*time.Second, 31*time.Second)
	p.item.staleDeadline = time.Now().Add(5 * time.Second)
	p.cacheExpiration = p.item.staleDeadline
	if !c.commitPrepared(k, nil, 0, p) {
		t.Fatal("failed to seed expired retained entry")
	}
	c.trackActiveRefresh(k, p.item, qCtx.CopyWithoutResponse(), sequence.ChainWalker{}, time.Now(), p.msg)
	c.activeMu.RLock()
	task := c.activeMeta[k].task
	c.activeMu.RUnlock()
	if task == nil || !task.probeOnly {
		t.Fatalf("initial probe task = %#v", task)
	}
	flight := refreshFlightKey{k: k, generation: p.item.generation}
	c.refreshInFlight.Store(flight, struct{}{})
	now := time.Now()
	c.rescheduleActiveConflict(task, now)
	c.refreshInFlight.Delete(flight)
	c.activeMu.RLock()
	retry := c.activeMeta[k].task
	c.activeMu.RUnlock()
	if retry == nil || retry == task || !retry.probeOnly {
		t.Fatalf("probe conflict retry = %#v", retry)
	}
	if delay := retry.refreshAt.Sub(now); delay < 400*time.Millisecond || delay > 700*time.Millisecond {
		t.Fatalf("probe conflict delay = %s, want about 500ms", delay)
	}
}

func TestFullQueueConvertsExpiredRequeryToProbe(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: ActiveRefreshArgs{
		MaxPendingTasks: 1,
		FallbackProbe:   FallbackProbeArgs{Enabled: true, StaleExtendTTL: 60, MaxStale: 300},
	}}, Opts{})
	defer c.Close()

	qCtx := newTestQuery("expired-to-probe.example.", dns.TypeA, dns.ClassINET, true)
	k := testCacheKey(t, qCtx)
	p := preparedAWithAge(t, qCtx.Q(), 30*time.Second, 31*time.Second)
	p.item.staleDeadline = time.Now().Add(5 * time.Second)
	p.cacheExpiration = p.item.staleDeadline
	if !c.commitPrepared(k, nil, 0, p) {
		t.Fatal("failed to seed retained item")
	}
	c.trackActiveRefresh(k, p.item, qCtx.CopyWithoutResponse(), sequence.ChainWalker{}, time.Now(), p.msg)
	c.moveDueActiveTasks(time.Now())
	c.activeMu.Lock()
	if len(c.activePending) != 1 {
		c.activeMu.Unlock()
		t.Fatal("expected one pending task")
	}
	// Model a normal DNS requery that expired while waiting in a full queue.
	c.activePending[0].probeOnly = false
	c.prunePendingLocked(time.Now())
	converted := len(c.activePending) == 1 && c.activePending[0].probeOnly
	c.activeMu.Unlock()
	if !converted {
		t.Fatal("expired requery was dropped instead of converted to a fallback probe")
	}
}

func TestFallbackProbeUsesConfiguredOrderAndRemainingBudget(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: ActiveRefreshArgs{
		RequeryTimeoutMS: 120,
		FallbackProbe: FallbackProbeArgs{
			Enabled: true, TimeoutMS: 500, StaleExtendTTL: 60, MaxStale: 300,
			Probes: []string{"tcp:443", "tcp:80", "ping"},
		},
	}}, Opts{})
	defer c.Close()

	qCtx := newTestQuery("probe-order.example.", dns.TypeA, dns.ClassINET, true)
	k := testCacheKey(t, qCtx)
	p := preparedAWithAge(t, qCtx.Q(), 30*time.Second, 31*time.Second)
	p.item.staleDeadline = time.Now().Add(5 * time.Second)
	p.cacheExpiration = p.item.staleDeadline
	if !c.commitPrepared(k, nil, 0, p) {
		t.Fatal("failed to seed retained item")
	}
	c.trackActiveRefresh(k, p.item, qCtx.CopyWithoutResponse(), sequence.ChainWalker{}, time.Now(), p.msg)
	c.activeMu.RLock()
	meta := c.activeMeta[k]
	var task *refreshTask
	if meta != nil {
		task = meta.task
	}
	c.activeMu.RUnlock()
	if task == nil || !task.probeOnly {
		t.Fatalf("probe task = %#v", task)
	}

	var calls []string
	var timeouts []time.Duration
	c.activeProbe = func(_ context.Context, probe string, _ net.IP, timeout time.Duration) bool {
		calls = append(calls, probe)
		timeouts = append(timeouts, timeout)
		return len(calls) == 3
	}
	c.runFallbackProbe(&activeRefreshWork{
		task: task, expected: p.item, epoch: c.refreshEpoch.Load(),
		flight: refreshFlightKey{k: k, generation: p.item.generation},
	}, p.item)

	wantCalls := []string{"tcp:443", "tcp:80", "ping"}
	if len(calls) != len(wantCalls) {
		t.Fatalf("probe calls = %#v, want %#v", calls, wantCalls)
	}
	for i := range wantCalls {
		if calls[i] != wantCalls[i] {
			t.Fatalf("probe calls = %#v, want %#v", calls, wantCalls)
		}
		if timeouts[i] <= 0 || timeouts[i] > 120*time.Millisecond {
			t.Fatalf("probe timeout[%d] = %s, want within remaining 120ms budget", i, timeouts[i])
		}
	}
	current, _, present := c.backend.Get(k)
	if !present || current == p.item || !current.isStale {
		t.Fatalf("successful probe did not install bounded stale entry: %#v", current)
	}
}

func TestSchedulerEnforcesQPSBeyondBurst(t *testing.T) {
	starts := make(chan time.Time, 8)
	exec := sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
		starts <- time.Now()
		qCtx.SetResponse(testAResponse(t, qCtx.Q(), "192.0.2.99", 60))
		return nil
	})
	c := newCacheForTest(t, &Args{Size: 256, ActiveRefresh: ActiveRefreshArgs{
		Enabled: true, Workers: 3, MaxRefreshQPS: 5, RefreshBurst: 1,
	}}, Opts{ActiveRefreshExec: exec})
	defer c.Close()
	for i := 0; i < 3; i++ {
		seedTrackedEntry(t, c, "qps-"+string(rune('a'+i))+".example.", 30*time.Second, 22*time.Second)
	}

	times := make([]time.Time, 0, 3)
	deadline := time.After(3 * time.Second)
	for len(times) < 3 {
		select {
		case started := <-starts:
			times = append(times, started)
		case <-deadline:
			t.Fatalf("only %d refreshes started", len(times))
		}
	}
	for i := 1; i < len(times); i++ {
		if spacing := times[i].Sub(times[i-1]); spacing < 150*time.Millisecond {
			t.Fatalf("refreshes %d/%d spaced by %s, want rate-limited near 200ms", i-1, i, spacing)
		}
	}
}

func TestQueryContextFromKeyPreservesFlagsTypeAndECS(t *testing.T) {
	qCtx := newTestQuery("replay.example.", dns.TypeAAAA, dns.ClassCHAOS, true)
	qCtx.Q().AuthenticatedData = true
	qCtx.Q().CheckingDisabled = true
	qCtx.QOpt().Hdr.Ttl |= 1 << 15
	qCtx.QOpt().Option = append(qCtx.QOpt().Option, &dns.EDNS0_SUBNET{
		Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24,
		Address: netip.MustParseAddr("198.51.100.123").AsSlice(),
	})
	k := testCacheKey(t, qCtx)
	replayed, ok := queryContextFromKey(k)
	if !ok {
		t.Fatal("failed to reconstruct query context")
	}
	if replayed.QQuestion() != qCtx.QQuestion() || !replayed.Q().AuthenticatedData || !replayed.Q().CheckingDisabled || !replayed.Q().RecursionDesired {
		t.Fatalf("replayed query flags/question mismatch: %#v", replayed.Q())
	}
	if replayed.QOpt().Hdr.Ttl&(1<<15) == 0 || len(replayed.QOpt().Option) != 1 {
		t.Fatalf("replayed EDNS state mismatch: %#v", replayed.QOpt())
	}
	if replayed.ClientOpt() == nil || !replayed.ClientOpt().Do() || len(replayed.ClientOpt().Option) != 1 {
		t.Fatalf("replayed client EDNS state mismatch: %#v", replayed.ClientOpt())
	}
	if got, valid := getECSClient(replayed); !valid || len(got) == 0 {
		t.Fatalf("replayed ECS = %x, valid=%v", got, valid)
	}
}

func TestDumpRestoreRebuildsVersionedSchedule(t *testing.T) {
	sourceArgs := &Args{Size: 16}
	source := newDormantActiveCache(t, sourceArgs, Opts{})
	defer source.Close()
	k, _, _ := seedTrackedEntry(t, source, "restore.example.", time.Hour, 10*time.Minute)
	source.activeMu.RLock()
	sourceMeta := source.activeMeta[k]
	source.activeMu.RUnlock()
	sourceMeta.lastAccess.Store(time.Now().Add(-time.Minute).UnixNano())
	sourceMeta.refreshCount.Store(2)
	sourceMeta.expected.lastRealAccess.Store(sourceMeta.lastAccess.Load())
	sourceMeta.expected.refreshSuccess.Store(2)

	buf := new(bytes.Buffer)
	if n, err := source.writeDump(buf); err != nil || n != 1 {
		t.Fatalf("write dump: entries=%d err=%v", n, err)
	}
	target := newDormantActiveCache(t, &Args{Size: 16}, Opts{})
	defer target.Close()
	target.bindActiveRefreshReplay(sequence.ChainWalker{})
	if n, err := target.readDump(buf); err != nil || n != 1 {
		t.Fatalf("read dump: entries=%d err=%v", n, err)
	}
	target.activeMu.RLock()
	meta := target.activeMeta[k]
	target.activeMu.RUnlock()
	if meta == nil || meta.task == nil || meta.expected == nil || meta.expected.generation == 0 {
		t.Fatalf("restored metadata is incomplete: %#v", meta)
	}
	if got := meta.refreshCount.Load(); got != 2 {
		t.Fatalf("restored consecutive refreshes = %d, want 2", got)
	}
	if got := time.Unix(0, meta.lastAccess.Load()); time.Since(got) < 50*time.Second || time.Since(got) > 70*time.Second {
		t.Fatalf("restored last access = %s", got)
	}
}

func TestDumpRestoreStormRemainsBatchAndPendingBounded(t *testing.T) {
	const entries = 12
	source := newDormantActiveCache(t, &Args{Size: 256}, Opts{})
	defer source.Close()
	for i := 0; i < entries; i++ {
		seedTrackedEntry(t, source, "restore-storm-"+string(rune('a'+i))+".example.", 60*time.Second, 45*time.Second)
	}
	buf := new(bytes.Buffer)
	if n, err := source.writeDump(buf); err != nil || n != entries {
		t.Fatalf("write dump: entries=%d err=%v", n, err)
	}

	target := newDormantActiveCache(t, &Args{Size: 256, ActiveRefresh: ActiveRefreshArgs{
		MaxTasksPerBatch: 3, MaxPendingTasks: 4,
	}}, Opts{})
	defer target.Close()
	target.bindActiveRefreshReplay(sequence.ChainWalker{})
	restoreStart := time.Now()
	if n, err := target.readDump(buf); err != nil || n != entries {
		t.Fatalf("read dump: entries=%d err=%v", n, err)
	}
	target.activeMu.RLock()
	if len(target.activeMeta) != entries || len(target.activeSchedule) != entries {
		target.activeMu.RUnlock()
		t.Fatalf("restored meta/future = %d/%d, want %d/%d", len(target.activeMeta), len(target.activeSchedule), entries, entries)
	}
	for _, task := range target.activeSchedule {
		if task.refreshAt.Before(restoreStart.Add(-100*time.Millisecond)) || task.refreshAt.After(restoreStart.Add(5100*time.Millisecond)) {
			target.activeMu.RUnlock()
			t.Fatalf("restored jittered refreshAt = %s, start=%s", task.refreshAt, restoreStart)
		}
	}
	target.activeMu.RUnlock()

	target.moveDueActiveTasks(restoreStart.Add(6 * time.Second))
	target.activeMu.RLock()
	firstPending, firstFuture := len(target.activePending), len(target.activeSchedule)
	target.activeMu.RUnlock()
	if firstPending != 3 || firstFuture != entries-3 {
		t.Fatalf("first restored batch pending/future = %d/%d, want 3/%d", firstPending, firstFuture, entries-3)
	}
	for i := 0; i < entries; i++ {
		target.moveDueActiveTasks(restoreStart.Add(6 * time.Second))
	}
	target.activeMu.RLock()
	pending := len(target.activePending)
	target.activeMu.RUnlock()
	if pending > 4 {
		t.Fatalf("restored pending queue grew to %d, want <=4", pending)
	}
}

func TestRestoreActiveRefreshEntriesHonorsMetadataCap(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 1}, Opts{})
	defer c.Close()

	entries := make([]decodedDumpEntry, 0, 8)
	seenShards := make(map[uint64]struct{})
	for i := 0; len(entries) < cap(entries) && i < 512; i++ {
		qCtx := newTestQuery("restore-cap-"+strconv.Itoa(i)+".example.", dns.TypeA, dns.ClassINET, true)
		k := testCacheKey(t, qCtx)
		shard := k.Sum() % shardCount
		if _, duplicate := seenShards[shard]; duplicate {
			continue
		}
		seenShards[shard] = struct{}{}
		p := testPreparedA(t, qCtx.Q(), "192.0.2.1", time.Hour)
		p.item.generation = c.generation.Add(1)
		lastAccess := time.Now().Add(-time.Minute)
		p.item.lastRealAccess.Store(lastAccess.UnixNano())
		c.backend.Store(k, p.item, p.cacheExpiration)
		entries = append(entries, decodedDumpEntry{
			k: k, item: p.item, cacheExpiration: p.cacheExpiration, lastRealAccess: lastAccess,
		})
	}
	if len(entries) < 2 {
		t.Fatalf("only built %d independently sharded restore entries", len(entries))
	}
	present := 0
	for _, entry := range entries {
		if current, _, ok := c.backend.Get(entry.k); ok && current == entry.item {
			present++
		}
	}
	if present < 2 {
		t.Fatalf("backend retained only %d restore entries; test requires at least two", present)
	}

	c.restoreActiveRefreshEntries(entries, sequence.ChainWalker{})
	c.activeMu.RLock()
	metaLen, futureLen := len(c.activeMeta), len(c.activeSchedule)
	c.activeMu.RUnlock()
	if metaLen > 1 || futureLen > 1 {
		t.Fatalf("restore exceeded metadata cap: meta=%d future=%d", metaLen, futureLen)
	}
}

func TestRestoreDoesNotOverwriteConcurrentMetadata(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16}, Opts{})
	defer c.Close()

	k, qCtx, old := seedTrackedEntry(t, c, "restore-concurrent.example.", time.Hour, 0)
	c.activeMu.RLock()
	originalMeta := c.activeMeta[k]
	originalAccess := originalMeta.lastAccess.Load()
	c.activeMu.RUnlock()
	oldEntry := decodedDumpEntry{
		k: k, item: old.item, cacheExpiration: old.cacheExpiration,
		lastRealAccess: time.Now().Add(-30 * time.Minute), refreshCount: 9,
	}
	c.restoreActiveRefreshEntries([]decodedDumpEntry{oldEntry}, sequence.ChainWalker{})
	c.activeMu.RLock()
	preserved := c.activeMeta[k]
	c.activeMu.RUnlock()
	if preserved != originalMeta || preserved.lastAccess.Load() != originalAccess || preserved.refreshCount.Load() != 0 {
		t.Fatalf("restore overwrote newer same-generation activity: %#v", preserved)
	}

	newer := testPreparedA(t, qCtx.Q(), "192.0.2.2", 2*time.Hour)
	if !c.commitPrepared(k, old.item, c.refreshEpoch.Load(), newer) {
		t.Fatal("failed to commit concurrent generation")
	}
	c.trackActiveRefresh(k, newer.item, qCtx.CopyWithoutResponse(), sequence.ChainWalker{}, time.Now(), newer.msg)
	c.restoreActiveRefreshEntries([]decodedDumpEntry{oldEntry}, sequence.ChainWalker{})
	c.activeMu.RLock()
	currentMeta := c.activeMeta[k]
	c.activeMu.RUnlock()
	if currentMeta == nil || currentMeta.expected != newer.item || currentMeta.task == nil || currentMeta.task.generation != newer.item.generation {
		t.Fatalf("restore replaced concurrent generation metadata: %#v", currentMeta)
	}
}

func TestActiveRefreshWorkerConcurrencyLimit(t *testing.T) {
	started := make(chan struct{}, 8)
	release := make(chan struct{})
	var running atomic.Int32
	var maxRunning atomic.Int32
	exec := sequence.ExecutableFunc(func(ctx context.Context, _ *query_context.Context) error {
		n := running.Add(1)
		defer running.Add(-1)
		for {
			old := maxRunning.Load()
			if n <= old || maxRunning.CompareAndSwap(old, n) {
				break
			}
		}
		started <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return errors.New("test stop")
	})
	args := &Args{Size: 32, ActiveRefresh: ActiveRefreshArgs{
		Enabled: true, Workers: 2, MaxRefreshQPS: 1000, RefreshBurst: 100,
	}}
	c := newCacheForTest(t, args, Opts{ActiveRefreshExec: exec})
	defer c.Close()
	for i := 0; i < 5; i++ {
		seedTrackedEntry(t, c, "worker-"+string(rune('a'+i))+".example.", 30*time.Second, 22*time.Second)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			close(release)
			t.Fatal("workers did not start")
		}
	}
	select {
	case <-started:
		close(release)
		t.Fatal("more refreshes started than the worker limit")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if got := maxRunning.Load(); got > 2 {
		t.Fatalf("max concurrent refreshes = %d, want <=2", got)
	}
}

func TestActiveRefreshCloseCancelsWorkerAndScheduler(t *testing.T) {
	started := make(chan struct{}, 1)
	exec := sequence.ExecutableFunc(func(ctx context.Context, _ *query_context.Context) error {
		started <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	})
	c := newCacheForTest(t, &Args{Size: 16, ActiveRefresh: ActiveRefreshArgs{
		Enabled: true, Workers: 1, MaxRefreshQPS: 100, RefreshBurst: 1,
	}}, Opts{ActiveRefreshExec: exec})
	seedTrackedEntry(t, c, "close.example.", 30*time.Second, 22*time.Second)
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		_ = c.Close()
		t.Fatal("refresh worker did not start")
	}
	c.activeRestoreMu.Lock()
	c.activeRestore[key("pending-restore")] = decodedDumpEntry{}
	c.activeRestoreMu.Unlock()
	done := make(chan struct{})
	go func() {
		_ = c.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not cancel active refresh goroutines")
	}
	c.activeMu.RLock()
	metaLen, futureLen, pendingLen := len(c.activeMeta), len(c.activeSchedule), len(c.activePending)
	c.activeMu.RUnlock()
	c.activeRestoreMu.Lock()
	restoreLen := len(c.activeRestore)
	c.activeRestoreMu.Unlock()
	if metaLen != 0 || futureLen != 0 || pendingLen != 0 || restoreLen != 0 {
		t.Fatalf("active state after Close: meta=%d future=%d pending=%d restore=%d", metaLen, futureLen, pendingLen, restoreLen)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
}
