package cache

import (
	"bytes"
	"compress/gzip"
	"container/heap"
	"context"
	"encoding/binary"
	"errors"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"google.golang.org/protobuf/proto"
)

func newDormantActiveCache(t *testing.T, args *Args, opts Opts) *Cache {
	t.Helper()
	args.ActiveRefresh.Enabled = false
	c := newCacheForTest(t, args, opts)
	args.ActiveRefresh.Enabled = true
	return c
}

func activeRefreshTrackingPolicyForTest(maxTrackedEntries int) ActiveRefreshArgs {
	return ActiveRefreshArgs{
		MaxTrackedEntries: maxTrackedEntries,
		AdmissionHits:     1,
		AdmissionWindow:   600,
		HeatHalfLife:      600,
		ProtectedRatio:    80,
		EvictionScanLimit: 64,
	}
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

func encodeLegacyDumpEntry(t *testing.T, entry *CachedEntry) []byte {
	t.Helper()
	block, err := proto.Marshal(&CacheDumpBlock{Entries: []*CachedEntry{entry}})
	if err != nil {
		t.Fatal(err)
	}
	buf := new(bytes.Buffer)
	gw := gzip.NewWriter(buf)
	gw.Name = dumpHeader
	var header [8]byte
	binary.BigEndian.PutUint64(header[:], uint64(len(block)))
	if _, err := gw.Write(header[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := gw.Write(block); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func replayContextForTest(t *testing.T, meta *activeRefreshMeta) *query_context.Context {
	t.Helper()
	if meta == nil || meta.replay == nil {
		t.Fatal("active refresh metadata has no replay snapshot")
	}
	qCtx, err := meta.replay.ContextForReplay()
	if err != nil {
		t.Fatal(err)
	}
	return qCtx
}

func assertActiveEvictionInvariant(t *testing.T, c *Cache) {
	t.Helper()
	c.activeMu.RLock()
	defer c.activeMu.RUnlock()
	if len(c.activeMeta) != len(c.activeEviction) {
		t.Fatalf("active metadata/eviction heap lengths differ: %d/%d", len(c.activeMeta), len(c.activeEviction))
	}
	seen := make(map[*activeRefreshMeta]struct{}, len(c.activeEviction))
	for i, meta := range c.activeEviction {
		if meta == nil || meta.evictionIndex != i || c.activeMeta[meta.k] != meta {
			t.Fatalf("invalid eviction heap entry %d: %#v", i, meta)
		}
		if _, duplicate := seen[meta]; duplicate {
			t.Fatalf("duplicate eviction heap entry %d: %#v", i, meta)
		}
		seen[meta] = struct{}{}
	}
	for k, meta := range c.activeMeta {
		if _, ok := seen[meta]; !ok || meta.k != k {
			t.Fatalf("metadata entry is missing from eviction heap: key=%q meta=%#v", k, meta)
		}
	}
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

func TestActiveRefreshLegacyFirstAccessTracksImmediately(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 4}, Opts{})
	defer c.Close()
	if c.activeRefreshTrackingPolicyEnabled() {
		t.Fatal("tracking policy unexpectedly enabled without its six fields")
	}

	qCtx := newTestQuery("legacy-first-access.example.", dns.TypeA, dns.ClassINET, true)
	k := testCacheKey(t, qCtx)
	p := testPreparedA(t, qCtx.Q(), "192.0.2.1", time.Minute)
	if !c.commitPrepared(k, nil, 0, p) {
		t.Fatal("failed to seed legacy cache entry")
	}
	c.trackActiveRefresh(k, p.item, qCtx.CopyWithoutResponse(), sequence.ChainWalker{}, time.Now(), p.msg)
	if meta := p.item.activeMeta.Load(); meta == nil || meta.expected != p.item || meta.task == nil {
		t.Fatalf("first legacy observation was not tracked immediately: %#v", meta)
	}
}

func TestActiveRefreshSecondHitAdmissionAndWindowReset(t *testing.T) {
	policy := activeRefreshTrackingPolicyForTest(16)
	policy.AdmissionHits = 2
	policy.AdmissionWindow = 60
	c := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: policy}, Opts{})
	defer c.Close()

	qCtx := newTestQuery("second-hit.example.", dns.TypeA, dns.ClassINET, true)
	k := testCacheKey(t, qCtx)
	p := testPreparedA(t, qCtx.Q(), "192.0.2.1", 5*time.Minute)
	if !c.commitPrepared(k, nil, 0, p) {
		t.Fatal("failed to seed cache")
	}
	base := time.Now()
	c.trackActiveRefresh(k, p.item, qCtx.CopyWithoutResponse(), sequence.ChainWalker{}, base, p.msg)
	if meta := p.item.activeMeta.Load(); meta != nil {
		t.Fatal("first access created active refresh metadata")
	}
	c.observeActiveRefresh(k, p.item, qCtx, sequence.ChainWalker{}, base.Add(time.Second), p.msg)
	if meta := p.item.activeMeta.Load(); meta == nil {
		t.Fatal("second access inside admission window was not admitted")
	}
	if got := p.item.activityState().realAccessCount.Load(); got != 2 {
		t.Fatalf("real access count = %d, want 2", got)
	}

	qCtx2 := newTestQuery("window-reset.example.", dns.TypeA, dns.ClassINET, true)
	k2 := testCacheKey(t, qCtx2)
	p2 := testPreparedA(t, qCtx2.Q(), "192.0.2.2", 5*time.Minute)
	if !c.commitPrepared(k2, nil, 0, p2) {
		t.Fatal("failed to seed reset candidate")
	}
	c.trackActiveRefresh(k2, p2.item, qCtx2.CopyWithoutResponse(), sequence.ChainWalker{}, base, p2.msg)
	c.observeActiveRefresh(k2, p2.item, qCtx2, sequence.ChainWalker{}, base.Add(61*time.Second), p2.msg)
	if meta := p2.item.activeMeta.Load(); meta != nil {
		t.Fatal("access outside admission window reused the old hit")
	}
	c.observeActiveRefresh(k2, p2.item, qCtx2, sequence.ChainWalker{}, base.Add(62*time.Second), p2.msg)
	if meta := p2.item.activeMeta.Load(); meta == nil {
		t.Fatal("second access in the reset window was not admitted")
	}
}

func TestActiveRefreshAdmissionHeatDoesNotRevivePreviousWindow(t *testing.T) {
	policy := activeRefreshTrackingPolicyForTest(16)
	policy.AdmissionHits = 2
	policy.AdmissionWindow = 60
	c := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: policy}, Opts{})
	defer c.Close()

	qCtx := newTestQuery("old-window-heat.example.", dns.TypeA, dns.ClassINET, true)
	k := testCacheKey(t, qCtx)
	p := testPreparedA(t, qCtx.Q(), "192.0.2.1", 5*time.Minute)
	if !c.commitPrepared(k, nil, 0, p) {
		t.Fatal("failed to seed cache entry")
	}
	activity := p.item.activityState()
	const oldHits = uint32(100)
	activity.realAccessCount.Store(uint64(oldHits))
	oldWindow := time.Now().Add(-2 * time.Duration(policy.AdmissionWindow) * time.Second)
	activity.admissionState.Store(uint64(uint32(oldWindow.Unix()))<<32 | uint64(oldHits))

	now := time.Now()
	c.trackActiveRefresh(k, p.item, qCtx.CopyWithoutResponse(), sequence.ChainWalker{}, now, p.msg)
	if meta := p.item.activeMeta.Load(); meta != nil {
		t.Fatal("first hit in the new window unexpectedly admitted the old history")
	}
	c.observeActiveRefresh(k, p.item, qCtx, sequence.ChainWalker{}, now.Add(time.Second), p.msg)

	c.activeMu.RLock()
	meta := c.activeMeta[k]
	var heat float64
	var observed uint64
	if meta != nil {
		heat = meta.heat
		observed = meta.heatObserved
	}
	c.activeMu.RUnlock()
	if meta == nil {
		t.Fatal("second hit in the new window was not admitted")
	}
	if heat != 2 {
		t.Fatalf("new-window initial heat = %f, want 2", heat)
	}
	if want := uint64(oldHits) + 2; observed != want {
		t.Fatalf("lifetime heat baseline = %d, want %d", observed, want)
	}
}

func TestActiveRefreshHeatTimestampNeverMovesBackward(t *testing.T) {
	policy := activeRefreshTrackingPolicyForTest(16)
	c := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: policy}, Opts{})
	defer c.Close()
	k, _, prepared := seedTrackedEntry(t, c, "heat-time-order.example.", time.Hour, 0)
	baseline := time.Now()
	c.activeMu.Lock()
	meta := c.activeMeta[k]
	meta.heat = 4
	meta.heatAt = baseline
	meta.heatObserved = prepared.item.activityState().realAccessCount.Load()
	got := c.refreshActiveHeatLocked(meta, baseline.Add(-time.Second))
	gotAt := meta.heatAt
	c.activeMu.Unlock()
	if got != 4 || !gotAt.Equal(baseline) {
		t.Fatalf("out-of-order heat refresh = %f at %s, want 4 at %s", got, gotAt, baseline)
	}
}

func TestActiveRefreshReadmissionHeatDoesNotReviveEvictedHistory(t *testing.T) {
	policy := activeRefreshTrackingPolicyForTest(1)
	policy.AdmissionWindow = 60
	c := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: policy}, Opts{})
	defer c.Close()

	k, qCtx, p := seedTrackedEntry(t, c, "readmitted-heat.example.", 5*time.Minute, 0)
	activity := p.item.activityState()
	const historicalHits = uint64(501)
	activity.realAccessCount.Store(historicalHits)
	oldWindow := time.Now().Add(-2 * time.Duration(policy.AdmissionWindow) * time.Second)
	activity.admissionState.Store(uint64(uint32(oldWindow.Unix()))<<32 | uint64(uint32(historicalHits)))

	c.activeMu.Lock()
	oldMeta := c.activeMeta[k]
	if oldMeta == nil {
		c.activeMu.Unlock()
		t.Fatal("missing initially tracked metadata")
	}
	oldMeta.referenced.Store(false)
	oldMeta.protected = false
	c.activeProtected = 0
	evicted := c.evictLeastUrgentMetaLocked()
	_, stillTracked := c.activeMeta[k]
	c.activeMu.Unlock()
	if !evicted || stillTracked {
		t.Fatalf("failed to evict old metadata: evicted=%v tracked=%v", evicted, stillTracked)
	}

	c.trackActiveRefresh(k, p.item, qCtx.CopyWithoutResponse(), sequence.ChainWalker{}, time.Now(), p.msg)
	c.activeMu.RLock()
	meta := c.activeMeta[k]
	var heat float64
	var observed uint64
	if meta != nil {
		heat = meta.heat
		observed = meta.heatObserved
	}
	c.activeMu.RUnlock()
	if meta == nil || meta == oldMeta {
		t.Fatalf("evicted entry was not readmitted with new metadata: %#v", meta)
	}
	if heat != 1 {
		t.Fatalf("readmitted initial heat = %f, want 1", heat)
	}
	if want := historicalHits + 1; observed != want {
		t.Fatalf("readmitted lifetime heat baseline = %d, want %d", observed, want)
	}
}

func TestActiveRefreshMetaHeatWaitsForCompleteAdmissionPublication(t *testing.T) {
	policy := activeRefreshTrackingPolicyForTest(16)
	policy.AdmissionHits = 5
	c := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: policy}, Opts{})
	defer c.Close()

	qCtx := newTestQuery("coherent-heat-snapshot.example.", dns.TypeA, dns.ClassINET, true)
	k := testCacheKey(t, qCtx)
	p := testPreparedA(t, qCtx.Q(), "192.0.2.63", time.Minute)
	p.item.generation = c.generation.Add(1)
	activity := p.item.activityState()
	writer := acquireActiveRefreshActivityWriter(p.item)
	if writer.meta != nil || !writer.admissionLocked {
		writer.release()
		t.Fatal("failed to establish untracked admission publication")
	}

	// Publish only the lifetime side first. Metadata creation must wait instead
	// of pairing this new baseline with the previous admission window.
	saturatingAddUint64(&activity.realAccessCount, 5)
	activity.recordRealAccess(time.Now())
	meta := &activeRefreshMeta{k: k, expected: p.item, evictionIndex: -1}
	installed := make(chan struct{})
	go func() {
		c.activeMu.Lock()
		c.addActiveMetaLocked(k, meta)
		c.activeMu.Unlock()
		close(installed)
	}()
	select {
	case <-installed:
		writer.release()
		t.Fatal("metadata captured a half-published admission state")
	case <-time.After(20 * time.Millisecond):
	}

	if hits := updateActiveAdmission(p.item, time.Now(), time.Duration(policy.AdmissionWindow)*time.Second, 5); hits != 5 {
		writer.release()
		t.Fatalf("published admission hits = %d, want 5", hits)
	}
	publicationCompletedAt := time.Now()
	writer.release()
	<-installed

	if meta.heatObserved != 5 || meta.heat != 5 {
		t.Fatalf("coherent heat snapshot = observed:%d heat:%f, want 5/5", meta.heatObserved, meta.heat)
	}
	if meta.heatAt.Before(publicationCompletedAt) {
		t.Fatalf("heat timestamp predates completed admission publication: %s < %s", meta.heatAt, publicationCompletedAt)
	}
	assertActiveEvictionInvariant(t, c)
}

func TestActiveRefreshConsumesFastCacheAggregateWithoutDoubleCount(t *testing.T) {
	policy := activeRefreshTrackingPolicyForTest(16)
	policy.AdmissionHits = 5
	c := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: policy}, Opts{})
	defer c.Close()

	qCtx := newTestQuery("fast-weight.example.", dns.TypeA, dns.ClassINET, true)
	qCtx.SetFastCacheHits(9)
	k := testCacheKey(t, qCtx)
	p := testPreparedA(t, qCtx.Q(), "192.0.2.9", time.Minute)
	if !c.commitPrepared(k, nil, 0, p) {
		t.Fatal("failed to seed cache")
	}
	c.trackActiveRefresh(k, p.item, qCtx, sequence.ChainWalker{}, time.Now(), p.msg)
	if got := p.item.activityState().realAccessCount.Load(); got != 9 {
		t.Fatalf("aggregated real access count = %d, want 9", got)
	}
	if meta := p.item.activeMeta.Load(); meta == nil {
		t.Fatal("aggregated fast-cache hits did not satisfy admission")
	}
	if got := counterValue(t, c.activeRefreshEvents.WithLabelValues("fast_cache_hits_merged")); got != 9 {
		t.Fatalf("merged-hit metric = %f, want 9", got)
	}
	// A parallel Context copy sees that the aggregate token existed but was
	// already consumed; it must not add a synthetic +1.
	parallelSource := newTestQuery("parallel-fast-weight.example.", dns.TypeA, dns.ClassINET, true)
	parallelSource.SetFastCacheHits(7)
	firstBranch := parallelSource.Copy()
	secondBranch := parallelSource.Copy()
	kp := testCacheKey(t, parallelSource)
	pp := testPreparedA(t, parallelSource.Q(), "192.0.2.11", time.Minute)
	if !c.commitPrepared(kp, nil, 0, pp) {
		t.Fatal("failed to seed parallel sample entry")
	}
	c.trackActiveRefresh(kp, pp.item, firstBranch, sequence.ChainWalker{}, time.Now(), pp.msg)
	pp.item.activityState().storeRefreshSuccesses(4)
	firstAccess := pp.item.activityState().lastRealAccess.Load()
	c.observeActiveRefresh(kp, pp.item, secondBranch, sequence.ChainWalker{}, time.Now(), pp.msg)
	if got := pp.item.activityState().realAccessCount.Load(); got != 7 {
		t.Fatalf("parallel aggregate count = %d, want 7", got)
	}
	if got := pp.item.activityState().lastRealAccess.Load(); got != firstAccess {
		t.Fatalf("consumed parallel token changed last access: got=%d want=%d", got, firstAccess)
	}
	if got := pp.item.activityState().refreshSuccesses(); got != 4 {
		t.Fatalf("consumed parallel token reset refresh successes: got=%d want=4", got)
	}
	if got := counterValue(t, c.activeRefreshEvents.WithLabelValues("fast_cache_hits_merged")); got != 16 {
		t.Fatalf("merged-hit metric after parallel sample = %f, want 16", got)
	}

	internal := newTestQuery("internal-no-heat.example.", dns.TypeA, dns.ClassINET, true)
	internal.MarkCacheRefresh()
	ki := testCacheKey(t, internal)
	pi := testPreparedA(t, internal.Q(), "192.0.2.10", time.Minute)
	if !c.commitPrepared(ki, nil, 0, pi) {
		t.Fatal("failed to seed internal entry")
	}
	c.trackActiveRefresh(ki, pi.item, internal, sequence.ChainWalker{}, time.Now(), pi.msg)
	if got := pi.item.activityState().realAccessCount.Load(); got != 0 || pi.item.activeMeta.Load() != nil {
		t.Fatalf("internal refresh changed heat: count=%d meta=%#v", got, pi.item.activeMeta.Load())
	}
	if got := counterValue(t, c.activeRefreshEvents.WithLabelValues("fast_cache_hits_merged")); got != 16 {
		t.Fatalf("internal refresh changed merged-hit metric: got %f, want 16", got)
	}
}

func TestActiveRefreshAdmissionCaptureHasSingleOwnerAndRetries(t *testing.T) {
	v := &item{generation: 1}
	const contenders = 32
	start := make(chan struct{})
	release := make(chan struct{})
	var attempted sync.WaitGroup
	var finished sync.WaitGroup
	attempted.Add(contenders)
	finished.Add(contenders)
	var owners atomic.Int32
	for range contenders {
		go func() {
			defer finished.Done()
			<-start
			owned := beginActiveRefreshCapture(v)
			if owned {
				owners.Add(1)
			}
			attempted.Done()
			if owned {
				<-release
				endActiveRefreshCapture(v)
			}
		}()
	}
	close(start)
	attempted.Wait()
	if got := owners.Load(); got != 1 {
		t.Fatalf("capture owners = %d, want 1", got)
	}
	close(release)
	finished.Wait()
	if !beginActiveRefreshCapture(v) {
		t.Fatal("capture ownership was not released for retry")
	}
	endActiveRefreshCapture(v)
}

func TestActiveActivityConcurrentInitialization(t *testing.T) {
	v := new(item)
	const contenders = 64
	start := make(chan struct{})
	activities := make(chan *activeActivity, contenders)
	var wg sync.WaitGroup
	wg.Add(contenders)
	for range contenders {
		go func() {
			defer wg.Done()
			<-start
			activities <- v.activityState()
		}()
	}
	close(start)
	wg.Wait()
	close(activities)

	var first *activeActivity
	for activity := range activities {
		if activity == nil {
			t.Fatal("activityState returned nil")
		}
		if first == nil {
			first = activity
			continue
		}
		if activity != first {
			t.Fatal("concurrent initialization published more than one activity pointer")
		}
	}
}

func TestActiveActivityGenerationHandoffSharesOnlyActivity(t *testing.T) {
	old := &item{generation: 1}
	oldActivity := old.activityState()
	oldActivity.realAccessCount.Store(7)
	oldActivity.storeRefreshSuccesses(3)
	oldActivity.admissionState.Store(11)
	old.admissionCapture.Store(true)

	updated := &item{generation: 2}
	inheritActiveRefreshActivity(updated, old)
	if updated.activityState() != oldActivity {
		t.Fatal("generation handoff copied activity instead of sharing its pointer")
	}
	if updated.admissionCapture.Load() {
		t.Fatal("generation-local admission capture gate was inherited")
	}
	if !updated.admissionCapture.CompareAndSwap(false, true) {
		t.Fatal("new generation could not independently claim replay capture")
	}

	saturatingAddUint64(&updated.activityState().realAccessCount, 5)
	if got := old.activityState().realAccessCount.Load(); got != 12 {
		t.Fatalf("old generation did not observe shared heat: got=%d want=12", got)
	}
	old.activityState().admissionState.Store(19)
	if got := updated.activityState().admissionState.Load(); got != 19 {
		t.Fatalf("new generation did not observe shared admission state: got=%d want=19", got)
	}
}

func TestActiveActivityRealHitWinsRefreshCompletion(t *testing.T) {
	activity := newActiveActivity(time.Now())
	activity.storeRefreshSuccesses(3)
	epochCaptured := make(chan uint32, 1)
	hitFinished := make(chan struct{})
	refreshRecorded := make(chan bool, 1)
	go func() {
		epoch := activity.refreshEpoch()
		epochCaptured <- epoch
		<-hitFinished
		refreshRecorded <- activity.addRefreshSuccess(epoch)
	}()

	oldEpoch := <-epochCaptured
	activity.recordRealAccess(time.Now().Add(time.Second))
	close(hitFinished)
	if recorded := <-refreshRecorded; recorded {
		t.Fatal("refresh completion incremented after a newer real hit")
	}
	if got := activity.refreshSuccesses(); got != 0 {
		t.Fatalf("real hit did not reset consecutive successes: got=%d want=0", got)
	}
	if got := activity.refreshEpoch(); got == oldEpoch {
		t.Fatalf("real hit did not advance refresh epoch: got=%d", got)
	}

	currentEpoch := activity.refreshEpoch()
	if !activity.addRefreshSuccess(currentEpoch) {
		t.Fatal("refresh completion with the current epoch was rejected")
	}
	if got := activity.refreshSuccesses(); got != 1 {
		t.Fatalf("current refresh success count = %d, want 1", got)
	}
	activity.storeRefreshSuccesses(^uint32(0))
	if !activity.addRefreshSuccess(activity.refreshEpoch()) || activity.refreshSuccesses() != ^uint32(0) {
		t.Fatal("refresh success count did not saturate at uint32 max")
	}
}

func TestActiveRefreshIndependentCapEvictsColdEntry(t *testing.T) {
	policy := activeRefreshTrackingPolicyForTest(2)
	policy.EvictionScanLimit = 8
	c := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: policy}, Opts{})
	defer c.Close()

	seed := func(name string) (key, *query_context.Context, *preparedCacheEntry) {
		qCtx := newTestQuery(name, dns.TypeA, dns.ClassINET, true)
		k := testCacheKey(t, qCtx)
		p := testPreparedA(t, qCtx.Q(), "192.0.2.1", time.Minute)
		if !c.commitPrepared(k, nil, 0, p) {
			t.Fatalf("failed to seed %s", name)
		}
		c.trackActiveRefresh(k, p.item, qCtx.CopyWithoutResponse(), sequence.ChainWalker{}, time.Now(), p.msg)
		return k, qCtx, p
	}
	coldKey, _, _ := seed("cold-cap.example.")
	hotKey, _, hot := seed("hot-cap.example.")
	// Make the second resident measurably hot, then expose both residents to the
	// bounded cold-candidate scan.
	saturatingAddUint64(&hot.item.activityState().realAccessCount, 20)
	c.activeMu.Lock()
	for _, meta := range c.activeMeta {
		meta.referenced.Store(false)
		meta.protected = false
	}
	c.activeProtected = 0
	c.activeMu.Unlock()
	thirdKey, _, _ := seed("incoming-cap.example.")

	c.activeMu.RLock()
	_, coldPresent := c.activeMeta[coldKey]
	_, hotPresent := c.activeMeta[hotKey]
	_, incomingPresent := c.activeMeta[thirdKey]
	tracked := len(c.activeMeta)
	c.activeMu.RUnlock()
	if coldPresent || !hotPresent || !incomingPresent || tracked != 2 {
		t.Fatalf("cap result cold=%v hot=%v incoming=%v tracked=%d", coldPresent, hotPresent, incomingPresent, tracked)
	}
}

func TestActiveRefreshIndependentCapRejectsColderIncomingEntry(t *testing.T) {
	policy := activeRefreshTrackingPolicyForTest(1)
	policy.EvictionScanLimit = 4
	c := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: policy}, Opts{})
	defer c.Close()
	hotKey, _, hot := seedTrackedEntry(t, c, "resident-hot.example.", time.Minute, 0)
	saturatingAddUint64(&hot.item.activityState().realAccessCount, 100)
	if meta := hot.item.activeMeta.Load(); meta != nil {
		meta.referenced.Store(false)
	}

	incomingCtx := newTestQuery("incoming-cold.example.", dns.TypeA, dns.ClassINET, true)
	incomingKey := testCacheKey(t, incomingCtx)
	incoming := testPreparedA(t, incomingCtx.Q(), "192.0.2.2", time.Minute)
	if !c.commitPrepared(incomingKey, nil, 0, incoming) {
		t.Fatal("failed to seed incoming entry")
	}
	c.trackActiveRefresh(incomingKey, incoming.item, incomingCtx, sequence.ChainWalker{}, time.Now(), incoming.msg)

	c.activeMu.RLock()
	_, hotPresent := c.activeMeta[hotKey]
	_, incomingPresent := c.activeMeta[incomingKey]
	c.activeMu.RUnlock()
	if !hotPresent || incomingPresent {
		t.Fatalf("colder admission replaced hot resident: hot=%v incoming=%v", hotPresent, incomingPresent)
	}
}

func TestActiveRefreshEvictionRechecksCounterBeforeReferenceBit(t *testing.T) {
	policy := activeRefreshTrackingPolicyForTest(1)
	policy.EvictionScanLimit = 4
	c := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: policy}, Opts{})
	defer c.Close()

	k, _, p := seedTrackedEntry(t, c, "eviction-counter-race.example.", time.Minute, 0)
	activity := p.item.activityState()

	c.activeMu.Lock()
	meta := c.activeMeta[k]
	if meta == nil || meta.evictionIndex < 0 {
		c.activeMu.Unlock()
		t.Fatal("tracked entry is missing from the eviction heap")
	}
	heap.Remove(&c.activeEviction, meta.evictionIndex)
	meta.referenced.Store(false)
	sampledAt := time.Now()
	sampledHeat := c.refreshActiveHeatLocked(meta, sampledAt)
	sampledCount := meta.heatObserved

	// Model the precise lock-free hit interleaving that used to be missed:
	// realAccessCount has been published, but the goroutine is paused before it
	// records lastRealAccess or reaches referenced.Store(true). A last-access
	// baseline taken now cannot detect this hit; the fixed heat sample must.
	const newHits = uint64(37)
	saturatingAddUint64(&activity.realAccessCount, newHits)
	if c.finalizeActiveEvictionLocked(meta, sampledCount) {
		c.activeMu.Unlock()
		t.Fatal("eviction committed after realAccessCount changed since heat sampling")
	}
	kept := c.activeMeta[k] == meta
	requeued := meta.evictionIndex >= 0
	rebound := p.item.activeMeta.Load() == meta && meta.boundGeneration.Load() == p.item.generation
	observed := meta.heatObserved
	refreshedHeat := meta.heat
	c.activeMu.Unlock()

	if !kept || !requeued || !rebound {
		t.Fatalf("raced victim was not restored: kept=%v requeued=%v rebound=%v", kept, requeued, rebound)
	}
	if want := sampledCount + newHits; observed != want {
		t.Fatalf("refreshed heat observed count = %d, want %d", observed, want)
	}
	if refreshedHeat < sampledHeat+float64(newHits)-0.01 {
		t.Fatalf("raced hit was not folded into heat: before=%f after=%f", sampledHeat, refreshedHeat)
	}
}

func TestActiveRefreshEvictionRejectsHitAlreadyAddedBeforeSampling(t *testing.T) {
	tests := []struct {
		name   string
		policy bool
	}{
		{name: "legacy"},
		{name: "clock", policy: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args := &Args{Size: 1}
			if tc.policy {
				args.Size = 16
				args.ActiveRefresh = activeRefreshTrackingPolicyForTest(1)
			}
			c := newDormantActiveCache(t, args, Opts{})
			defer c.Close()

			k, _, p := seedTrackedEntry(t, c, "partial-hit-"+tc.name+".example.", time.Minute, 0)
			activity := p.item.activityState()
			meta := p.item.activeMeta.Load()
			if meta == nil {
				t.Fatal("missing tracked metadata")
			}
			writer := acquireActiveRefreshMetaWriter(p.item)
			if writer != meta {
				if writer != nil {
					releaseActiveRefreshMetaWriter(writer)
				}
				t.Fatalf("failed to pin tracked metadata: got=%p want=%p", writer, meta)
			}
			before := activity.realAccessCount.Load()
			const newHits = uint64(37)
			// This is the formerly unsafe interleaving: Add is visible before
			// eviction takes any counter/timestamp sample, while lastRealAccess
			// and referenced are deliberately still unpublished.
			saturatingAddUint64(&activity.realAccessCount, newHits)

			c.activeMu.Lock()
			meta.referenced.Store(false)
			evicted := c.evictLeastUrgentMetaLocked()
			kept := c.activeMeta[k] == meta
			requeued := meta.evictionIndex >= 0
			rebound := p.item.activeMeta.Load() == meta && meta.boundGeneration.Load() == p.item.generation
			observed := meta.heatObserved
			c.activeMu.Unlock()

			// Complete the paused hit in the same order as the production path.
			activity.recordRealAccess(time.Now())
			if tc.policy {
				meta.referenced.Store(true)
			}
			releaseActiveRefreshMetaWriter(writer)

			if evicted || !kept || !requeued || !rebound {
				t.Fatalf("partially published hit was evicted: evicted=%v kept=%v requeued=%v rebound=%v", evicted, kept, requeued, rebound)
			}
			if tc.policy && observed != before+newHits {
				t.Fatalf("CLOCK sampled counter = %d, want %d", observed, before+newHits)
			}
			if got := meta.accessWriters.Load(); got != 0 {
				t.Fatalf("writer pin leaked after hit completion: %d", got)
			}
			assertActiveEvictionInvariant(t, c)
		})
	}
}

func TestActiveRefreshHitAfterHandleClearUsesAdmissionSlowPath(t *testing.T) {
	tests := []struct {
		name   string
		policy bool
	}{
		{name: "legacy"},
		{name: "clock", policy: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args := &Args{Size: 1}
			if tc.policy {
				args.Size = 16
				args.ActiveRefresh = activeRefreshTrackingPolicyForTest(1)
			}
			c := newDormantActiveCache(t, args, Opts{})
			defer c.Close()

			k, qCtx, p := seedTrackedEntry(t, c, "post-clear-hit-"+tc.name+".example.", time.Minute, 0)
			c.activeMu.Lock()
			meta := c.activeMeta[k]
			clearActiveMetaHandleLocked(meta)
			c.activeMu.Unlock()
			if meta == nil || p.item.activeMeta.Load() != nil {
				t.Fatal("failed to establish cleared-handle interleaving")
			}

			before := p.item.activityState().realAccessCount.Load()
			if ready := c.recordActiveRefreshActivity(p.item, time.Now(), 1); !ready {
				t.Fatal("hit beginning after handle clear did not enter the admission slow path")
			}
			if got := p.item.activityState().realAccessCount.Load(); got != before+1 {
				t.Fatalf("slow-path hit count = %d, want %d", got, before+1)
			}
			if got := meta.accessWriters.Load(); got != 0 {
				t.Fatalf("post-clear hit incorrectly pinned detached metadata: %d", got)
			}
			if !beginActiveRefreshCapture(p.item) {
				t.Fatal("post-clear slow path could not claim replay capture")
			}
			c.captureActiveRefreshReplay(
				k,
				p.item,
				qCtx.CopyWithoutResponse(),
				sequence.ChainWalker{},
				time.Now(),
				p.msg,
			)
			endActiveRefreshCapture(p.item)
			if rebound := boundActiveRefreshMeta(p.item); rebound != meta {
				t.Fatalf("slow path did not restore metadata binding: got=%p want=%p", rebound, meta)
			}
		})
	}
}

func TestActiveRefreshHeatHalfLife(t *testing.T) {
	policy := activeRefreshTrackingPolicyForTest(16)
	policy.HeatHalfLife = 10
	c := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: policy}, Opts{})
	defer c.Close()
	_, _, p := seedTrackedEntry(t, c, "heat-decay.example.", time.Minute, 0)
	meta := p.item.activeMeta.Load()
	if meta == nil {
		t.Fatal("missing metadata")
	}
	now := time.Now()
	c.activeMu.Lock()
	meta.heat = 8
	meta.heatObserved = p.item.activityState().realAccessCount.Load()
	meta.heatAt = now.Add(-10 * time.Second)
	got := c.refreshActiveHeatLocked(meta, now)
	c.activeMu.Unlock()
	if got < 3.99 || got > 4.01 {
		t.Fatalf("one-half-life heat = %f, want about 4", got)
	}
}

func TestActiveRefreshProtectedLimitLeavesProbationSlot(t *testing.T) {
	policy := activeRefreshTrackingPolicyForTest(2)
	policy.ProtectedRatio = 100
	c := newDormantActiveCache(t, &Args{Size: 2, ActiveRefresh: policy}, Opts{})
	defer c.Close()
	if got := c.activeRefreshProtectedLimit(); got != 1 {
		t.Fatalf("protected limit = %d, want 1 of 2", got)
	}
	c.args.ActiveRefresh.MaxTrackedEntries = 1
	if got := c.activeRefreshProtectedLimit(); got != 0 {
		t.Fatalf("single-entry protected limit = %d, want 0", got)
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
	c.updateActiveRefreshAfterCommit(k, old.item, newer.item, time.Now(), newer.msg, false, 0, qCtx, sequence.ChainWalker{})
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
		task: task, replay: task.meta.replay, qCtx: replayContextForTest(t, task.meta), nextBase: task.meta.next, next: task.meta.next.Fork(),
		expected: old.item, epoch: c.refreshEpoch.Load(), activityEpoch: old.item.activityState().refreshEpoch(),
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
		task: task, replay: task.meta.replay, qCtx: replayContextForTest(t, task.meta), nextBase: task.meta.next, expected: old.item,
		epoch: c.refreshEpoch.Load(), activityEpoch: old.item.activityState().refreshEpoch(),
		flight: refreshFlightKey{k: k, generation: old.item.generation},
	})

	current, _, present := c.backend.Get(k)
	c.activeMu.RLock()
	meta := c.activeMeta[k]
	c.activeMu.RUnlock()
	if !present || meta == nil || meta.expected != current || meta.task != nil || !meta.stopped.Load() ||
		current.activityState().refreshSuccesses() != 1 || current.activeMeta.Load() != nil {
		t.Fatalf("max-refresh stop state: present=%v current=%#v meta=%#v", present, current, meta)
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(current.resp); err != nil {
		t.Fatal(err)
	}
	c.observeActiveRefresh(k, current, qCtx, sequence.ChainWalker{}, time.Now(), msg)
	c.activeMu.RLock()
	resumed := meta.task != nil && !meta.stopped.Load() && current.activityState().refreshSuccesses() == 0 &&
		current.activeMeta.Load() == meta && meta.boundGeneration.Load() == current.generation
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
		task: task, replay: task.meta.replay, qCtx: replayContextForTest(t, task.meta), nextBase: task.meta.next, expected: old.item,
		epoch: c.refreshEpoch.Load(), activityEpoch: old.item.activityState().refreshEpoch(),
		flight: refreshFlightKey{k: k, generation: old.item.generation},
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
		task: task, replay: task.meta.replay, qCtx: replayContextForTest(t, task.meta), nextBase: task.meta.next, expected: old.item,
		epoch: c.refreshEpoch.Load(), activityEpoch: old.item.activityState().refreshEpoch(),
		flight: refreshFlightKey{k: k, generation: old.item.generation},
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
		task: task, replay: task.meta.replay, qCtx: replayContextForTest(t, task.meta), nextBase: task.meta.next, expected: p.item,
		epoch: c.refreshEpoch.Load(), activityEpoch: p.item.activityState().refreshEpoch(),
		flight: refreshFlightKey{k: k, generation: p.item.generation},
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
	meta.expected.activityState().lastRealAccess.Store(time.Now().Add(-time.Hour).UnixNano())
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
	if reactivated == nil || reactivated.task == nil || p.item.activityState().refreshSuccesses() != 0 {
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

func TestTrackedHitDoesNotWaitForActiveMu(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16}, Opts{})
	defer c.Close()

	k, qCtx, p := seedTrackedEntry(t, c, "lock-free-hit.example.", time.Hour, 0)
	c.activeMu.RLock()
	meta := c.activeMeta[k]
	c.activeMu.RUnlock()
	if meta == nil || p.item.activeMeta.Load() != meta || meta.boundGeneration.Load() != p.item.generation {
		t.Fatalf("active handle was not published: meta=%#v handle=%#v", meta, p.item.activeMeta.Load())
	}
	p.item.activityState().storeRefreshSuccesses(3)
	hitAt := time.Now()

	c.activeMu.Lock()
	done := make(chan struct{})
	go func() {
		c.observeActiveRefresh(k, p.item, qCtx, sequence.ChainWalker{}, hitAt, p.msg)
		close(done)
	}()
	select {
	case <-done:
		c.activeMu.Unlock()
	case <-time.After(time.Second):
		c.activeMu.Unlock()
		<-done
		t.Fatal("tracked cache hit waited for activeMu")
	}

	if got := p.item.activityState().refreshSuccesses(); got != 0 {
		t.Fatalf("refresh success count after real hit = %d, want 0", got)
	}
	if got := time.Unix(0, p.item.activityState().lastRealAccess.Load()); got.Before(hitAt) {
		t.Fatalf("last access = %s, want >= %s", got, hitAt)
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
	meta.expected.activityState().lastRealAccess.Store(now.Add(-10 * time.Second).UnixNano())
	meta.task.dueAt = now.Add(-time.Millisecond)
	heap.Fix(&c.activeSchedule, meta.task.scheduleIndex)
	c.activeMu.Unlock()
	c.moveDueActiveTasks(now)
	// The real hit races after transfer to pending. The lock-free hit path only
	// updates entry activity; worker preparation must observe it and return the
	// old idle sentinel to the future heap.
	c.observeActiveRefresh(k, p.item, qCtx, sequence.ChainWalker{}, now, p.msg)
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

func TestOldGenerationHandleSharesNewGenerationActivity(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16}, Opts{})
	defer c.Close()

	k, qCtx, old := seedTrackedEntry(t, c, "old-handle.example.", time.Minute, 0)
	old.item.activityState().storeRefreshSuccesses(2)
	newer := testPreparedA(t, qCtx.Q(), "192.0.2.2", 2*time.Minute)
	if !c.commitPrepared(k, old.item, c.refreshEpoch.Load(), newer) {
		t.Fatal("failed to commit newer generation")
	}
	c.updateActiveRefreshAfterCommit(k, old.item, newer.item, time.Now(), newer.msg, false, 0, qCtx, sequence.ChainWalker{})

	c.activeMu.RLock()
	meta := c.activeMeta[k]
	c.activeMu.RUnlock()
	if meta == nil || meta.expected != newer.item || newer.item.activeMeta.Load() != meta {
		t.Fatalf("new generation handle was not installed: meta=%#v handle=%#v", meta, newer.item.activeMeta.Load())
	}
	if old.item.activeMeta.Load() != nil {
		t.Fatalf("old generation retained active handle: %#v", old.item.activeMeta.Load())
	}

	// Model an L1 lookup that captured the old pointer before the replacement.
	// Both physical generations share one activity lineage, so this real hit
	// must reset the current generation's consecutive refresh count.
	newer.item.activityState().storeRefreshSuccesses(2)
	c.observeActiveRefresh(k, old.item, qCtx, sequence.ChainWalker{}, time.Now(), old.msg)
	if got := newer.item.activityState().refreshSuccesses(); got != 0 {
		t.Fatalf("stale-pointer real hit did not reset shared refresh count: got=%d", got)
	}
	if newer.item.activeMeta.Load() != meta || meta.boundGeneration.Load() != newer.item.generation {
		t.Fatal("stale generation disturbed the current active handle")
	}
}

func TestGenerationHandoffPreservesRealHitBeforeHandleDetach(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: ActiveRefreshArgs{
		MaxRefreshTimes: 1,
	}}, Opts{})
	defer c.Close()

	k, qCtx, old := seedTrackedEntry(t, c, "handoff-hit.example.", time.Minute, 0)
	newer := testPreparedA(t, qCtx.Q(), "192.0.2.2", 2*time.Minute)
	if !c.commitPrepared(k, old.item, c.refreshEpoch.Load(), newer) {
		t.Fatal("failed to commit newer generation")
	}
	committedAccess := newer.item.activityState().lastRealAccess.Load()
	activityEpoch := newer.item.activityState().refreshEpoch()
	hitAt := time.Now().Add(time.Millisecond)
	// The backend and L1 already contain newer, but an in-progress L1 hit may
	// still hold old until the metadata handoff detaches its handle.
	c.observeActiveRefresh(k, old.item, qCtx, sequence.ChainWalker{}, hitAt, old.msg)
	if old.item.activityState().lastRealAccess.Load() <= committedAccess {
		t.Fatal("test hit did not advance old generation activity")
	}

	c.updateActiveRefreshAfterCommit(k, old.item, newer.item, time.Now(), newer.msg, true, activityEpoch, qCtx, sequence.ChainWalker{})
	c.activeMu.RLock()
	meta := c.activeMeta[k]
	c.activeMu.RUnlock()
	if meta == nil || meta.expected != newer.item || meta.task == nil || meta.stopped.Load() {
		t.Fatalf("handoff hit was lost and stopped the new generation: %#v", meta)
	}
	if got := newer.item.activityState().refreshSuccesses(); got != 0 {
		t.Fatalf("new generation refresh count = %d, want reset by real hit", got)
	}
	if got := newer.item.activityState().lastRealAccess.Load(); got < hitAt.UnixNano() {
		t.Fatalf("new generation last access = %d, want >= %d", got, hitAt.UnixNano())
	}
}

func TestLegacyMetadataCapPinsGenerationHandoff(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 1}, Opts{})
	defer c.Close()
	if c.activeRefreshTrackingPolicyEnabled() {
		t.Fatal("legacy metadata cap test enabled the tracking policy")
	}

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
	c.updateActiveRefreshAfterCommit(k1, old.item, newer.item, time.Now(), newer.msg, false, 0, qCtx1, sequence.ChainWalker{})
	c.activeMu.RLock()
	handedOff := c.activeMeta[k1]
	metaLen := len(c.activeMeta)
	c.activeMu.RUnlock()
	if handedOff == nil || handedOff.expected != newer.item || handedOff.task == nil || metaLen != 1 {
		t.Fatalf("generation handoff after cap pressure = %#v, metaLen=%d", handedOff, metaLen)
	}
}

func TestLegacyMetadataCapPinsInflightAndDispatchedTask(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 1}, Opts{})
	defer c.Close()
	if c.activeRefreshTrackingPolicyEnabled() {
		t.Fatal("legacy metadata cap test enabled the tracking policy")
	}

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

func TestActiveRefreshLegacyEvictsLatestExpiration(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 3}, Opts{})
	defer c.Close()
	if c.activeRefreshTrackingPolicyEnabled() {
		t.Fatal("tracking policy unexpectedly enabled without its six fields")
	}

	k1, _, _ := seedTrackedEntry(t, c, "legacy-urgent.example.", time.Hour, 0)
	k2, _, _ := seedTrackedEntry(t, c, "legacy-least-urgent.example.", 3*time.Hour, 0)
	k3, _, _ := seedTrackedEntry(t, c, "legacy-middle.example.", 2*time.Hour, 0)
	c.activeMu.Lock()
	evicted := c.evictLeastUrgentMetaLocked()
	_, has1 := c.activeMeta[k1]
	_, has2 := c.activeMeta[k2]
	_, has3 := c.activeMeta[k3]
	c.activeMu.Unlock()
	if !evicted || !has1 || has2 || !has3 {
		t.Fatalf("legacy latest-expiration eviction: evicted=%v present=%v/%v/%v", evicted, has1, has2, has3)
	}
	assertActiveEvictionInvariant(t, c)
}

func TestMetadataEvictionClockStartsWithOldestSegment(t *testing.T) {
	policy := activeRefreshTrackingPolicyForTest(3)
	c := newDormantActiveCache(t, &Args{Size: 4096, ActiveRefresh: policy}, Opts{})
	defer c.Close()

	k1, _, _ := seedTrackedEntry(t, c, "eviction-one.example.", time.Hour, 0)
	k2, _, _ := seedTrackedEntry(t, c, "eviction-two.example.", 2*time.Hour, 0)
	k3, _, _ := seedTrackedEntry(t, c, "eviction-three.example.", 3*time.Hour, 0)
	assertActiveEvictionInvariant(t, c)

	// Keep the backend roomy while exercising the independent metadata cap.
	c.activeMu.Lock()
	commonHeatAt := time.Now()
	for _, meta := range c.activeMeta {
		meta.referenced.Store(false)
		meta.heat = 1
		meta.heatAt = commonHeatAt
		meta.heatObserved = meta.expected.activityState().realAccessCount.Load()
	}
	evicted := c.evictLeastUrgentMetaLocked()
	_, has1 := c.activeMeta[k1]
	_, has2 := c.activeMeta[k2]
	_, has3 := c.activeMeta[k3]
	c.activeMu.Unlock()
	if !evicted || has1 || !has2 || !has3 {
		t.Fatalf("oldest CLOCK segment eviction: evicted=%v present=%v/%v/%v", evicted, has1, has2, has3)
	}
	assertActiveEvictionInvariant(t, c)
}

func TestLegacyMetadataEvictionHeapFixesGenerationHandoff(t *testing.T) {
	// Keep the backend roomy while seeding. With a cache size below the shard
	// count, two deterministic keys may hash to the same one-entry shard and
	// make this metadata test depend on the process-random maphash seed.
	c := newDormantActiveCache(t, &Args{Size: 2 * shardCount}, Opts{})
	defer c.Close()
	if c.activeRefreshTrackingPolicyEnabled() {
		t.Fatal("legacy eviction heap test enabled the tracking policy")
	}

	k1, qCtx1, old := seedTrackedEntry(t, c, "eviction-handoff.example.", time.Hour, 0)
	k2, _, _ := seedTrackedEntry(t, c, "eviction-other.example.", 2*time.Hour, 0)
	newer := testPreparedA(t, qCtx1.Q(), "192.0.2.2", 3*time.Hour)
	if !c.commitPrepared(k1, old.item, c.refreshEpoch.Load(), newer) {
		t.Fatal("failed to commit handoff generation")
	}
	c.updateActiveRefreshAfterCommit(k1, old.item, newer.item, time.Now(), newer.msg, false, 0, qCtx1, sequence.ChainWalker{})
	assertActiveEvictionInvariant(t, c)

	// Legacy metadata capacity follows args.Size. Tighten it only after both
	// backend entries and the generation handoff are established.
	c.args.Size = 2
	c.activeMu.Lock()
	evicted := c.evictLeastUrgentMetaLocked()
	_, has1 := c.activeMeta[k1]
	_, has2 := c.activeMeta[k2]
	c.activeMu.Unlock()
	if !evicted || has1 || !has2 {
		t.Fatalf("handoff heap fix: evicted=%v present=%v/%v", evicted, has1, has2)
	}
	assertActiveEvictionInvariant(t, c)
}

func TestLegacyMetadataEvictionProbeBudgetIsBounded(t *testing.T) {
	const entries = activeRefreshEvictionProbes + 6
	c := newDormantActiveCache(t, &Args{Size: entries}, Opts{})
	defer c.Close()
	if c.activeRefreshTrackingPolicyEnabled() {
		t.Fatal("legacy eviction budget test enabled the tracking policy")
	}

	flights := make([]refreshFlightKey, 0, entries)
	for i := 0; i < entries; i++ {
		k, _, p := seedTrackedEntry(t, c, "eviction-pinned-"+strconv.Itoa(i)+".example.", time.Hour, 0)
		flight := refreshFlightKey{k: k, generation: p.item.generation}
		c.refreshInFlight.Store(flight, struct{}{})
		flights = append(flights, flight)
	}
	c.activeMu.Lock()
	evicted := c.evictLeastUrgentMetaLocked()
	remaining := len(c.activeMeta)
	c.activeMu.Unlock()
	if evicted || remaining != entries {
		t.Fatalf("all-pinned eviction: evicted=%v remaining=%d, want %d", evicted, remaining, entries)
	}
	assertActiveEvictionInvariant(t, c)

	// Unpin the current root. The next attempt should need only one indexed
	// candidate instead of revisiting the full metadata map.
	c.activeMu.RLock()
	root := c.activeEviction[0]
	rootFlight := refreshFlightKey{k: root.k, generation: root.expected.generation}
	c.activeMu.RUnlock()
	c.refreshInFlight.Delete(rootFlight)
	c.activeMu.Lock()
	evicted = c.evictLeastUrgentMetaLocked()
	remaining = len(c.activeMeta)
	c.activeMu.Unlock()
	if !evicted || remaining != entries-1 {
		t.Fatalf("unblocked indexed eviction: evicted=%v remaining=%d", evicted, remaining)
	}
	for _, flight := range flights {
		c.refreshInFlight.Delete(flight)
	}
	assertActiveEvictionInvariant(t, c)
}

func TestMetadataEvictionClockAdvancesPastPinnedSegment(t *testing.T) {
	policy := activeRefreshTrackingPolicyForTest(3)
	policy.EvictionScanLimit = 2
	c := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: policy}, Opts{})
	defer c.Close()

	var pinned []refreshFlightKey
	for i := 0; i < 3; i++ {
		k, _, p := seedTrackedEntry(t, c, "clock-rotation-"+strconv.Itoa(i)+".example.", time.Hour, 0)
		p.item.activityState().realAccessCount.Store(1)
		if i < 2 {
			flight := refreshFlightKey{k: k, generation: p.item.generation}
			c.refreshInFlight.Store(flight, struct{}{})
			pinned = append(pinned, flight)
		}
	}
	c.activeMu.Lock()
	for _, meta := range c.activeMeta {
		meta.referenced.Store(false)
		meta.heat = 1
		meta.heatAt = time.Now()
		meta.heatObserved = meta.expected.activityState().realAccessCount.Load()
	}
	first := c.evictLeastUrgentMetaLocked()
	firstRemaining := len(c.activeMeta)
	second := c.evictLeastUrgentMetaLocked()
	secondRemaining := len(c.activeMeta)
	c.activeMu.Unlock()
	for _, flight := range pinned {
		c.refreshInFlight.Delete(flight)
	}

	if first || firstRemaining != 3 {
		t.Fatalf("first bounded scan unexpectedly evicted: evicted=%v remaining=%d", first, firstRemaining)
	}
	if !second || secondRemaining != 2 {
		t.Fatalf("CLOCK did not advance beyond pinned segment: evicted=%v remaining=%d", second, secondRemaining)
	}
	assertActiveEvictionInvariant(t, c)
}

func TestBackendRemovalHintCleansIndexedMetadata(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16}, Opts{})
	defer c.Close()

	k, _, p := seedTrackedEntry(t, c, "backend-removal.example.", time.Hour, 0)
	// Replace the physical backend envelope with an already-expired one using
	// the same item, then let Get emit the exact Expired callback.
	c.backend.Store(k, p.item, time.Now().Add(10*time.Millisecond))
	time.Sleep(25 * time.Millisecond)
	if _, _, present := c.backend.Get(k); present {
		t.Fatal("expired backend item remained present")
	}
	c.moveDueActiveTasks(time.Now())
	c.activeMu.RLock()
	_, tracked := c.activeMeta[k]
	c.activeMu.RUnlock()
	if tracked {
		t.Fatal("backend removal hint left stale active metadata")
	}
	assertActiveEvictionInvariant(t, c)
}

func TestOutOfOrderBackendRemovalHintPreservesHandoff(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16}, Opts{})
	defer c.Close()

	k, qCtx, old := seedTrackedEntry(t, c, "backend-removal-handoff.example.", time.Hour, 0)
	newer := testPreparedA(t, qCtx.Q(), "192.0.2.2", 2*time.Hour)
	if !c.commitPrepared(k, old.item, c.refreshEpoch.Load(), newer) {
		t.Fatal("failed to commit handoff generation")
	}
	// Simulate a delayed capacity/expiry notification for the old physical
	// entry. The newer backend pointer must protect the metadata handoff.
	c.noteActiveBackendRemoval(k, old.item)
	c.moveDueActiveTasks(time.Now())
	c.activeMu.RLock()
	preserved := c.activeMeta[k]
	c.activeMu.RUnlock()
	if preserved == nil || preserved.expected != old.item {
		t.Fatalf("out-of-order removal destroyed handoff metadata: %#v", preserved)
	}
	c.updateActiveRefreshAfterCommit(k, old.item, newer.item, time.Now(), newer.msg, false, 0, qCtx, sequence.ChainWalker{})
	c.activeMu.RLock()
	handedOff := c.activeMeta[k]
	c.activeMu.RUnlock()
	if handedOff == nil || handedOff.expected != newer.item || handedOff.task == nil {
		t.Fatalf("generation handoff did not recover: %#v", handedOff)
	}
	assertActiveEvictionInvariant(t, c)
}

func TestBackendRemovalHintsRearmAfterFullBatch(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 128}, Opts{})
	defer c.Close()

	const hints = activeRefreshEvictionProbes + 6
	for i := 0; i < hints; i++ {
		c.noteActiveBackendRemoval(key("removal-hint-"+strconv.Itoa(i)), &item{generation: uint64(i + 1)})
	}
	select {
	case <-c.activeWake:
	default:
		t.Fatal("removal hints did not wake the scheduler")
	}
	c.activeMu.Lock()
	c.drainActiveBackendRemovalsLocked(activeRefreshEvictionProbes)
	c.activeMu.Unlock()
	remaining := 0
	c.activeRemoved.Range(func(_, _ any) bool {
		remaining++
		return true
	})
	if remaining != hints-activeRefreshEvictionProbes {
		t.Fatalf("remaining removal hints = %d, want %d", remaining, hints-activeRefreshEvictionProbes)
	}
	select {
	case <-c.activeWake:
	default:
		t.Fatal("full removal batch did not re-arm the scheduler")
	}
	c.activeMu.Lock()
	c.drainActiveBackendRemovalsLocked(activeRefreshEvictionProbes)
	c.activeMu.Unlock()
	remaining = 0
	c.activeRemoved.Range(func(_, _ any) bool {
		remaining++
		return true
	})
	if remaining != 0 {
		t.Fatalf("removal hints were not fully drained: %d", remaining)
	}
}

func TestBackendRemovalHintKeepsNewestGeneration(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16}, Opts{})
	defer c.Close()
	k := key("versioned-removal-hint")
	old := &item{generation: 1}
	newer := &item{generation: 2}

	c.noteActiveBackendRemoval(k, newer)
	c.noteActiveBackendRemoval(k, old)
	if stored, ok := c.activeRemoved.Load(k); !ok || stored != newer {
		t.Fatalf("older delayed hint replaced newer hint: %#v, %v", stored, ok)
	}
	c.activeRemoved.Clear()
	c.noteActiveBackendRemoval(k, old)
	c.noteActiveBackendRemoval(k, newer)
	if stored, ok := c.activeRemoved.Load(k); !ok || stored != newer {
		t.Fatalf("newer hint did not replace older hint: %#v, %v", stored, ok)
	}
}

func TestNewerRemovalHintCleansOlderMetadataWhenBackendAbsent(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16}, Opts{})
	defer c.Close()

	k, _, old := seedTrackedEntry(t, c, "newer-hint-old-meta.example.", time.Hour, 0)
	c.activeMu.Lock()
	meta := c.activeMeta[k]
	c.removeMetaTaskLocked(meta)
	meta.stopped.Store(true)
	c.activeMu.Unlock()
	c.backend.Flush()
	c.noteActiveBackendRemoval(k, &item{generation: old.item.generation + 1})
	c.activeMu.Lock()
	c.drainActiveBackendRemovalsLocked(activeRefreshEvictionProbes)
	_, tracked := c.activeMeta[k]
	c.activeMu.Unlock()
	if tracked {
		t.Fatal("newer removal hint left older stopped metadata without a backend owner")
	}
	assertActiveEvictionInvariant(t, c)
}

func TestDiscardedHandoffOwnerCleansMissingMetadata(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16}, Opts{})
	defer c.Close()

	k, _, old := seedTrackedEntry(t, c, "discarded-handoff-owner.example.", time.Hour, 0)
	c.activeMu.Lock()
	task := c.activeMeta[k].task
	heap.Remove(&c.activeSchedule, task.scheduleIndex)
	c.activeMu.Unlock()
	c.backend.Flush()
	c.discardActiveTask(task, false)
	c.activeMu.RLock()
	_, tracked := c.activeMeta[k]
	c.activeMu.RUnlock()
	if tracked {
		t.Fatal("discarded handoff owner left metadata after backend disappeared")
	}
	if old.item.activeMeta.Load() != nil {
		t.Fatal("discarded handoff owner left the entry handle attached")
	}
	assertActiveEvictionInvariant(t, c)
}

func TestActiveOwnerFinalizerCleansBackendRemovedDuringExecution(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16}, Opts{})
	defer c.Close()

	k, _, old := seedTrackedEntry(t, c, "active-finalizer-missing.example.", time.Hour, 0)
	c.activeMu.RLock()
	task := c.activeMeta[k].task
	c.activeMu.RUnlock()
	flight := refreshFlightKey{k: k, generation: old.item.generation}
	c.refreshInFlight.Store(flight, struct{}{})
	c.backend.Flush()
	c.finishActiveRefreshWork(&activeRefreshWork{task: task, expected: old.item, flight: flight})
	c.activeMu.RLock()
	_, tracked := c.activeMeta[k]
	c.activeMu.RUnlock()
	if tracked {
		t.Fatal("active owner finalizer left metadata after backend removal")
	}
	if _, retained := c.refreshInFlight.Load(flight); retained {
		t.Fatal("active owner finalizer retained its inflight claim")
	}
	assertActiveEvictionInvariant(t, c)
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

	c.updateActiveRefreshAfterCommit(k, old.item, newer.item, time.Now(), newer.msg, false, 0, qCtx, sequence.ChainWalker{})
	c.activeMu.RLock()
	recovered := c.activeMeta[k]
	c.activeMu.RUnlock()
	if recovered == nil || recovered.expected != newer.item || recovered.task == nil || recovered.task.generation != newer.item.generation {
		t.Fatalf("evicted handoff metadata was not recovered: %#v", recovered)
	}
}

func TestActiveRefreshHandoffUsesExistingReplayWhenNewSnapshotFails(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16}, Opts{})
	defer c.Close()

	k, qCtx, old := seedTrackedEntry(t, c, "snapshot-failure-handoff.example.", time.Minute, 0)
	c.activeMu.RLock()
	originalReplay := c.activeMeta[k].replay
	c.activeMu.RUnlock()
	qCtx.Q().Extra = append(qCtx.Q().Extra, &dns.TXT{
		Hdr: dns.RR_Header{Name: "snapshot-failure-handoff.example.", Rrtype: dns.TypeTXT, Class: dns.ClassINET},
		Txt: []string{strings.Repeat("x", 256)},
	})
	if _, err := qCtx.SnapshotForReplay(); err == nil {
		t.Fatal("malformed request unexpectedly produced a replay snapshot")
	}
	newer := testPreparedA(t, qCtx.Q(), "192.0.2.2", 2*time.Minute)
	committed, displaced := c.commitPreparedForegroundWithDisplaced(k, old.item, c.refreshEpoch.Load(), newer)
	if !committed || displaced != old.item {
		t.Fatal("failed to commit replacement generation")
	}
	newerAccess := time.Now().Add(time.Second).UnixNano()
	newer.item.activityState().lastRealAccess.Store(newerAccess)

	// A foreground request whose DNS message cannot be packed has no new replay
	// snapshot. The existing immutable template must still hand off to the new
	// cache generation instead of leaving metadata attached to old.
	c.adoptExistingActiveRefreshReplay(k, newer.item, old.item, displaced, time.Now(), newer.msg)
	c.activeMu.RLock()
	handedOff := c.activeMeta[k]
	c.activeMu.RUnlock()
	if handedOff == nil || handedOff.expected != newer.item || handedOff.task == nil || handedOff.task.generation != newer.item.generation {
		t.Fatalf("existing replay was not handed off: %#v", handedOff)
	}
	if handedOff.replay != originalReplay {
		t.Fatal("handoff replaced the pristine replay template")
	}
	if old.item.activeMeta.Load() != nil || newer.item.activeMeta.Load() != handedOff {
		t.Fatal("generation handles were not transferred to the committed item")
	}
	if got := newer.item.activityState().lastRealAccess.Load(); got != newerAccess {
		t.Fatalf("adoption overwrote newer concurrent activity: got %d, want %d", got, newerAccess)
	}
	assertActiveEvictionInvariant(t, c)
}

func TestActiveRefreshReplayAdoptionCrossesFallbackDerivative(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16}, Opts{})
	defer c.Close()

	k, qCtx, old := seedTrackedEntry(t, c, "snapshot-fallback-race.example.", time.Minute, 0)
	old.item.activityState().storeRefreshSuccesses(7)
	if !c.recordActiveRefreshActivity(old.item, time.Now(), 1) {
		t.Fatal("foreground real hit was not recorded")
	}
	c.activeMu.RLock()
	originalReplay := c.activeMeta[k].replay
	c.activeMu.RUnlock()
	epoch := c.refreshEpoch.Load()
	stale := testPreparedA(t, qCtx.Q(), "192.0.2.1", 30*time.Second)
	stale.item.isStale = true
	stale.item.staleSourceGeneration = old.item.generation
	if !c.commitPrepared(k, old.item, epoch, stale) {
		t.Fatal("failed to install fallback derivative")
	}
	c.updateActiveRefreshAfterCommit(k, old.item, stale.item, time.Now(), stale.msg, false, 0, qCtx, sequence.ChainWalker{})
	c.activeMu.RLock()
	staleMeta := c.activeMeta[k]
	c.activeMu.RUnlock()
	if staleMeta == nil || staleMeta.expected != stale.item {
		t.Fatalf("fallback metadata handoff failed: %#v", staleMeta)
	}

	fresh := testPreparedA(t, qCtx.Q(), "192.0.2.2", 2*time.Minute)
	committed, displaced := c.commitPreparedForegroundWithDisplaced(k, old.item, epoch, fresh)
	if !committed || displaced != stale.item {
		t.Fatal("healthy foreground answer did not replace fallback derivative")
	}
	c.adoptExistingActiveRefreshReplay(k, fresh.item, old.item, displaced, time.Now(), fresh.msg)
	c.activeMu.RLock()
	handedOff := c.activeMeta[k]
	c.activeMu.RUnlock()
	if handedOff == nil || handedOff.expected != fresh.item || handedOff.task == nil || handedOff.task.generation != fresh.item.generation {
		t.Fatalf("fallback replay was not adopted by foreground generation: %#v", handedOff)
	}
	if handedOff.replay != originalReplay {
		t.Fatal("fallback race replaced the existing immutable replay")
	}
	if stale.item.activeMeta.Load() != nil || fresh.item.activeMeta.Load() != handedOff {
		t.Fatal("fallback generation handle was not transferred")
	}
	if got := fresh.item.activityState().refreshSuccesses(); got != 0 {
		t.Fatalf("foreground adoption inherited refresh-success count %d", got)
	}
	assertActiveEvictionInvariant(t, c)
}

func TestActiveRefreshReplayAdoptionHandlesPendingFallbackHandoff(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16}, Opts{})
	defer c.Close()

	k, qCtx, old := seedTrackedEntry(t, c, "snapshot-pending-fallback.example.", time.Minute, 0)
	c.activeMu.RLock()
	originalReplay := c.activeMeta[k].replay
	c.activeMu.RUnlock()
	epoch := c.refreshEpoch.Load()
	stale := testPreparedA(t, qCtx.Q(), "192.0.2.1", 30*time.Second)
	stale.item.isStale = true
	stale.item.staleSourceGeneration = old.item.generation
	if !c.commitPrepared(k, old.item, epoch, stale) {
		t.Fatal("failed to publish fallback derivative")
	}
	// Model the short window where backend already contains stale while its
	// metadata handoff is still waiting: meta intentionally remains on old.
	c.activeMu.RLock()
	pending := c.activeMeta[k]
	c.activeMu.RUnlock()
	if pending == nil || pending.expected != old.item {
		t.Fatalf("test did not preserve pending fallback handoff: %#v", pending)
	}

	fresh := testPreparedA(t, qCtx.Q(), "192.0.2.2", 2*time.Minute)
	committed, displaced := c.commitPreparedForegroundWithDisplaced(k, old.item, epoch, fresh)
	if !committed || displaced != stale.item {
		t.Fatal("foreground answer did not displace pending fallback")
	}
	c.adoptExistingActiveRefreshReplay(k, fresh.item, old.item, displaced, time.Now(), fresh.msg)
	c.activeMu.RLock()
	handedOff := c.activeMeta[k]
	c.activeMu.RUnlock()
	if handedOff == nil || handedOff.expected != fresh.item || handedOff.replay != originalReplay || handedOff.task == nil {
		t.Fatalf("pending fallback replay was not adopted: %#v", handedOff)
	}
	if old.item.activeMeta.Load() != nil || fresh.item.activeMeta.Load() != handedOff {
		t.Fatal("pending fallback left the wrong generation handle")
	}
	assertActiveEvictionInvariant(t, c)
}

func TestActiveRefreshReplayAdoptionCleansUnrelatedOrphan(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16}, Opts{})
	defer c.Close()

	k, qCtx, old := seedTrackedEntry(t, c, "snapshot-removal-race.example.", time.Minute, 0)
	c.activeMu.RLock()
	originalReplay := c.activeMeta[k].replay
	c.activeMu.RUnlock()
	c.backend.Flush()
	c.activeMu.RLock()
	orphaned := c.activeMeta[k]
	c.activeMu.RUnlock()
	if orphaned == nil || orphaned.expected != old.item {
		t.Fatalf("test did not retain metadata across backend removal: %#v", orphaned)
	}

	fresh := testPreparedA(t, qCtx.Q(), "192.0.2.2", 2*time.Minute)
	committed, displaced := c.commitPreparedForegroundWithDisplaced(k, nil, c.refreshEpoch.Load(), fresh)
	if !committed || displaced != nil {
		t.Fatal("failed to fill entry removed during foreground lookup")
	}
	c.adoptExistingActiveRefreshReplay(k, fresh.item, nil, displaced, time.Now(), fresh.msg)
	c.activeMu.RLock()
	_, retained := c.activeMeta[k]
	c.activeMu.RUnlock()
	if retained {
		t.Fatal("unrelated orphan replay was adopted by an absent foreground fill")
	}
	if old.item.activeMeta.Load() != nil || fresh.item.activeMeta.Load() != nil {
		t.Fatal("orphan cleanup left a generation handle attached")
	}
	if originalReplay == nil {
		t.Fatal("test did not start with an orphan replay")
	}
	assertActiveEvictionInvariant(t, c)
}

func TestActiveRefreshReplayAdoptionAfterObservedEntryRemoval(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16}, Opts{})
	defer c.Close()

	k, qCtx, old := seedTrackedEntry(t, c, "snapshot-observed-removal.example.", time.Minute, 0)
	c.activeMu.RLock()
	originalReplay := c.activeMeta[k].replay
	c.activeMu.RUnlock()
	c.backend.Flush()
	fresh := testPreparedA(t, qCtx.Q(), "192.0.2.2", 2*time.Minute)
	committed, displaced := c.commitPreparedForegroundWithDisplaced(k, old.item, c.refreshEpoch.Load(), fresh)
	if !committed || displaced != nil {
		t.Fatal("failed to fill an observed entry removed during lookup")
	}
	c.adoptExistingActiveRefreshReplay(k, fresh.item, old.item, displaced, time.Now(), fresh.msg)
	c.activeMu.RLock()
	handedOff := c.activeMeta[k]
	c.activeMu.RUnlock()
	if handedOff == nil || handedOff.expected != fresh.item || handedOff.replay != originalReplay || handedOff.task == nil {
		t.Fatalf("observed removed replay was not adopted: %#v", handedOff)
	}
	if old.item.activeMeta.Load() != nil || fresh.item.activeMeta.Load() != handedOff {
		t.Fatal("observed removed generation handle was not transferred")
	}
	assertActiveEvictionInvariant(t, c)
}

func TestActiveRefreshReplayAdoptionFromTrackedTransient(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16}, Opts{})
	defer c.Close()

	qCtx := newTestQuery("snapshot-transient.example.", dns.TypeA, dns.ClassINET, true)
	k := testCacheKey(t, qCtx)
	transientCtx := qCtx.CopyWithoutResponse()
	servfail := new(dns.Msg)
	servfail.SetRcode(qCtx.Q(), dns.RcodeServerFailure)
	transientCtx.SetResponse(servfail)
	transient, ok := c.prepareCacheEntry(transientCtx, true)
	if !ok || !transient.item.isTransient {
		t.Fatal("failed to prepare tracked transient entry")
	}
	epoch := c.refreshEpoch.Load()
	committed, displaced := c.commitPreparedForegroundWithDisplaced(k, nil, epoch, transient)
	if !committed || displaced != nil {
		t.Fatal("failed to commit initial transient entry")
	}
	c.trackActiveRefresh(k, transient.item, qCtx, sequence.ChainWalker{}, time.Now(), transient.msg)
	c.activeMu.RLock()
	transientMeta := c.activeMeta[k]
	c.activeMu.RUnlock()
	if transientMeta == nil || transientMeta.expected != transient.item || transientMeta.replay == nil {
		t.Fatalf("transient entry was not tracked: %#v", transientMeta)
	}
	transientReplay := transientMeta.replay

	healthy := testPreparedA(t, qCtx.Q(), "192.0.2.2", 2*time.Minute)
	committed, displaced = c.commitPreparedForegroundWithDisplaced(k, nil, epoch, healthy)
	if !committed || displaced != transient.item {
		t.Fatal("healthy foreground answer did not displace transient")
	}
	c.adoptExistingActiveRefreshReplay(k, healthy.item, nil, displaced, time.Now(), healthy.msg)
	c.activeMu.RLock()
	handedOff := c.activeMeta[k]
	c.activeMu.RUnlock()
	if handedOff == nil || handedOff.expected != healthy.item || handedOff.replay != transientReplay || handedOff.task == nil {
		t.Fatalf("tracked transient replay was not adopted exactly: %#v", handedOff)
	}
	if transient.item.activeMeta.Load() != nil || healthy.item.activeMeta.Load() != handedOff {
		t.Fatal("transient generation handle was not transferred")
	}
	if got := healthy.item.activityState().refreshSuccesses(); got != 0 {
		t.Fatalf("healthy foreground entry inherited refresh-success count %d", got)
	}
	assertActiveEvictionInvariant(t, c)
}

func TestActiveRefreshReplayAdoptionIgnoresSupersededCommit(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16}, Opts{})
	defer c.Close()

	k, qCtx, old := seedTrackedEntry(t, c, "snapshot-superseded.example.", time.Minute, 0)
	epoch := c.refreshEpoch.Load()
	foreground := testPreparedA(t, qCtx.Q(), "192.0.2.2", 2*time.Minute)
	committed, displaced := c.commitPreparedForegroundWithDisplaced(k, old.item, epoch, foreground)
	if !committed || displaced != old.item {
		t.Fatal("failed to commit foreground generation")
	}
	newer := testPreparedA(t, qCtx.Q(), "192.0.2.3", 3*time.Minute)
	if !c.commitPrepared(k, foreground.item, epoch, newer) {
		t.Fatal("failed to supersede foreground generation")
	}
	c.trackActiveRefresh(k, newer.item, qCtx, sequence.ChainWalker{}, time.Now(), newer.msg)
	c.activeMu.RLock()
	newMeta := c.activeMeta[k]
	newReplay := newMeta.replay
	newTask := newMeta.task
	c.activeMu.RUnlock()

	c.adoptExistingActiveRefreshReplay(k, foreground.item, old.item, displaced, time.Now(), foreground.msg)
	c.activeMu.RLock()
	after := c.activeMeta[k]
	c.activeMu.RUnlock()
	if after != newMeta || after.expected != newer.item || after.replay != newReplay || after.task != newTask {
		t.Fatalf("superseded adoption touched the current generation: %#v", after)
	}
	if newer.item.activeMeta.Load() != newMeta {
		t.Fatal("superseded adoption detached the current handle")
	}
	assertActiveEvictionInvariant(t, c)
}

func TestActiveRefreshHandoffReusesPristineReplaySnapshot(t *testing.T) {
	mutationKey := query_context.RegKey()
	var c *Cache
	exec := sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
		qCtx.StoreValue(mutationKey, "worker mutation")
		qCtx.SetMark(999)
		// Simulate the rare commit-handoff recovery path by removing the
		// metadata container while this worker owns the dispatched task.
		c.activeMu.Lock()
		if meta := c.activeMeta[testCacheKey(t, qCtx)]; meta != nil {
			c.removeActiveMetaLocked(meta.k, meta)
		}
		c.activeMu.Unlock()
		qCtx.SetResponse(testAResponse(t, qCtx.Q(), "192.0.2.2", 60))
		return nil
	})
	c = newDormantActiveCache(t, &Args{Size: 16}, Opts{ActiveRefreshExec: exec})
	defer c.Close()

	k, _, old := seedTrackedEntry(t, c, "pristine-handoff.example.", 30*time.Second, 22*time.Second)
	c.activeMu.RLock()
	task := c.activeMeta[k].task
	replay := c.activeMeta[k].replay
	nextBase := c.activeMeta[k].next
	c.activeMu.RUnlock()
	qCtx, err := replay.ContextForReplay()
	if err != nil {
		t.Fatal(err)
	}
	c.runActiveRefreshTask(&activeRefreshWork{
		task: task, replay: replay, qCtx: qCtx, nextBase: nextBase,
		expected: old.item, epoch: c.refreshEpoch.Load(), activityEpoch: old.item.activityState().refreshEpoch(),
		flight: refreshFlightKey{k: k, generation: old.item.generation},
	})

	c.activeMu.RLock()
	recovered := c.activeMeta[k]
	c.activeMu.RUnlock()
	if recovered == nil || recovered.replay != replay || recovered.expected == old.item {
		t.Fatalf("active refresh did not take over the pristine snapshot: %#v", recovered)
	}
	replayed := replayContextForTest(t, recovered)
	if replayed.IsCacheRefresh() || replayed.HasMark(999) {
		t.Fatal("worker-only marks leaked into the reusable replay template")
	}
	if value, ok := replayed.GetValue(mutationKey); ok || value != nil {
		t.Fatalf("worker-only value leaked into replay template: %#v, %v", value, ok)
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
			meta.expected.activityState().lastRealAccess.Store(time.Now().Add(-time.Hour).UnixNano())
			meta.expected.activityState().storeRefreshSuccesses(0)
		} else {
			meta.expected.activityState().lastRealAccess.Store(time.Now().UnixNano())
			meta.expected.activityState().storeRefreshSuccesses(1)
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
			!currentMeta.stopped.Load() && p.item.activityState().refreshSuccesses() == 0 &&
			p.item.activeMeta.Load() == currentMeta && currentMeta.boundGeneration.Load() == p.item.generation
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
	p.item.activityState().lastRealAccess.Store(time.Now().Add(-time.Hour).UnixNano())
	p.item.activityState().storeRefreshSuccesses(7)
	hitAt := time.Now()
	c.trackActiveRefresh(k, p.item, qCtx.CopyWithoutResponse(), sequence.ChainWalker{}, hitAt, p.msg)
	if got := time.Unix(0, p.item.activityState().lastRealAccess.Load()); got.Before(hitAt) {
		t.Fatalf("last real access = %s, want >= %s", got, hitAt)
	}
	if got := p.item.activityState().refreshSuccesses(); got != 0 {
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
	c := newDormantActiveCache(t, &Args{Size: 4096, ActiveRefresh: ActiveRefreshArgs{
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
	sourceMeta.expected.activityState().lastRealAccess.Store(time.Now().Add(-time.Minute).UnixNano())
	sourceMeta.expected.activityState().storeRefreshSuccesses(2)

	buf := new(bytes.Buffer)
	if n, err := source.writeDump(buf); err != nil || n != 1 {
		t.Fatalf("write dump: entries=%d err=%v", n, err)
	}
	target := newDormantActiveCache(t, &Args{Size: 16}, Opts{})
	defer target.Close()
	if n, err := target.readDump(buf); err != nil || n != 1 {
		t.Fatalf("read dump: entries=%d err=%v", n, err)
	}
	plugins := map[string]any{
		"cache": target,
		"resolver": sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
			qCtx.SetResponse(testAResponse(t, qCtx.Q(), "192.0.2.99", 60))
			return nil
		}),
	}
	m := coremain.NewTestMosdnsWithPlugins(plugins)
	if _, err := sequence.NewSequence(coremain.NewBP("restore-sequence", m), []sequence.RuleArgs{
		{Exec: "$cache"},
		{Exec: "$resolver"},
	}); err != nil {
		t.Fatal(err)
	}
	target.activeMu.RLock()
	meta := target.activeMeta[k]
	target.activeMu.RUnlock()
	if meta == nil || meta.task == nil || meta.expected == nil || meta.expected.generation == 0 {
		t.Fatalf("restored metadata is incomplete: %#v", meta)
	}
	if got := meta.expected.activityState().refreshSuccesses(); got != 2 {
		t.Fatalf("restored consecutive refreshes = %d, want 2", got)
	}
	if got := time.Unix(0, meta.expected.activityState().lastRealAccess.Load()); time.Since(got) < 50*time.Second || time.Since(got) > 70*time.Second {
		t.Fatalf("restored last access = %s", got)
	}
	replayCtx := replayContextForTest(t, meta)
	replayNext := meta.next.Fork()
	if err := replayNext.ExecNext(context.Background(), replayCtx); err != nil {
		t.Fatal(err)
	}
	if replayCtx.R() == nil {
		t.Fatal("restored task continuation did not reach resolver")
	}
}

func TestDumpRestorePopularityPolicyOnlyRestoresAdmittedEntries(t *testing.T) {
	policy := activeRefreshTrackingPolicyForTest(16)
	policy.AdmissionHits = 2
	source := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: policy}, Opts{})
	defer source.Close()
	now := time.Now()

	seed := func(name string) (key, *query_context.Context, *preparedCacheEntry) {
		qCtx := newTestQuery(name, dns.TypeA, dns.ClassINET, true)
		k := testCacheKey(t, qCtx)
		prepared := testPreparedA(t, qCtx.Q(), "192.0.2.1", time.Hour)
		if !source.commitPrepared(k, nil, 0, prepared) {
			t.Fatalf("failed to seed %s", name)
		}
		source.trackActiveRefresh(k, prepared.item, qCtx.CopyWithoutResponse(), sequence.ChainWalker{}, now, prepared.msg)
		return k, qCtx, prepared
	}
	hotKey, hotQuery, hot := seed("restore-hot.example.")
	coldKey, coldQuery, cold := seed("restore-cold.example.")
	source.observeActiveRefresh(hotKey, hot.item, hotQuery, sequence.ChainWalker{}, now.Add(time.Second), hot.msg)
	if source.activeMeta[hotKey] == nil || source.activeMeta[coldKey] != nil {
		t.Fatal("test setup did not produce one admitted and one untracked entry")
	}

	buf := new(bytes.Buffer)
	if n, err := source.writeDump(buf); err != nil || n != 2 {
		t.Fatalf("write dump: entries=%d err=%v", n, err)
	}
	targetPolicy := activeRefreshTrackingPolicyForTest(16)
	targetPolicy.AdmissionHits = 2
	target := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: targetPolicy}, Opts{})
	defer target.Close()
	target.bindActiveRefreshReplay(sequence.ChainWalker{})
	if n, err := target.readDump(buf); err != nil || n != 2 {
		t.Fatalf("read dump: entries=%d err=%v", n, err)
	}

	hotLoaded, _, hotPresent := target.backend.Get(hotKey)
	coldLoaded, _, coldPresent := target.backend.Get(coldKey)
	if !hotPresent || !coldPresent {
		t.Fatalf("cache restore lost entries: hot=%v cold=%v", hotPresent, coldPresent)
	}
	target.activeMu.RLock()
	hotMeta, hotTracked := target.activeMeta[hotKey]
	_, coldTracked := target.activeMeta[coldKey]
	target.activeMu.RUnlock()
	if !hotTracked || hotMeta == nil || hotMeta.task == nil || coldTracked {
		t.Fatalf("popularity restore mismatch: hot=%#v coldTracked=%v", hotMeta, coldTracked)
	}
	if hotMeta.referenced.Load() || hotMeta.protected {
		t.Fatal("restored popularity metadata inherited process-local CLOCK state")
	}
	if got := hotLoaded.activityState().realAccessCount.Load(); got != 2 {
		t.Fatalf("restored hot access count = %d, want 2", got)
	}
	if got := coldLoaded.activityState().realAccessCount.Load(); got != 1 {
		t.Fatalf("restored cold admission progress = %d, want 1", got)
	}
	target.observeActiveRefresh(coldKey, coldLoaded, coldQuery, sequence.ChainWalker{}, now.Add(2*time.Second), cold.msg)
	if meta := target.activeMeta[coldKey]; meta == nil || meta.task == nil {
		t.Fatalf("restored partial admission did not accept the next real hit: %#v", meta)
	}
	target.activeMu.Lock()
	coldMeta := target.activeMeta[coldKey]
	heatAfterAdmission := target.refreshActiveHeatLocked(coldMeta, now.Add(3*time.Second))
	heatObserved := coldMeta.heatObserved
	target.activeMu.Unlock()
	if heatAfterAdmission > 2 || heatAfterAdmission < 1.99 || heatObserved != 2 {
		t.Fatalf("restored admission heat double-counted: heat=%f observed=%d", heatAfterAdmission, heatObserved)
	}
}

func TestDumpRestoreExpiredPartialAdmissionStartsNewWindow(t *testing.T) {
	policy := activeRefreshTrackingPolicyForTest(16)
	policy.AdmissionHits = 2
	policy.AdmissionWindow = 1
	source := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: policy}, Opts{})
	defer source.Close()
	qCtx := newTestQuery("restore-expired-admission.example.", dns.TypeA, dns.ClassINET, true)
	k := testCacheKey(t, qCtx)
	prepared := testPreparedA(t, qCtx.Q(), "192.0.2.1", time.Hour)
	if !source.commitPrepared(k, nil, 0, prepared) {
		t.Fatal("failed to seed partial admission entry")
	}
	oldHit := time.Now().Add(-2 * time.Second)
	source.trackActiveRefresh(k, prepared.item, qCtx.CopyWithoutResponse(), sequence.ChainWalker{}, oldHit, prepared.msg)

	buf := new(bytes.Buffer)
	if n, err := source.writeDump(buf); err != nil || n != 1 {
		t.Fatalf("write dump: entries=%d err=%v", n, err)
	}
	target := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: policy}, Opts{})
	defer target.Close()
	target.bindActiveRefreshReplay(sequence.ChainWalker{})
	if n, err := target.readDump(buf); err != nil || n != 1 {
		t.Fatalf("read dump: entries=%d err=%v", n, err)
	}
	loaded, _, present := target.backend.Get(k)
	if !present {
		t.Fatal("partial admission cache entry was not restored")
	}
	now := time.Now()
	target.observeActiveRefresh(k, loaded, qCtx, sequence.ChainWalker{}, now, prepared.msg)
	if meta := target.activeMeta[k]; meta != nil {
		t.Fatalf("expired partial admission incorrectly reached threshold: %#v", meta)
	}
	state := loaded.activityState().admissionState.Load()
	if hits := uint32(state); hits != 1 {
		t.Fatalf("new admission window hits = %d, want 1", hits)
	}
}

func TestDumpRestorePopularityCapPrefersPersistedHeat(t *testing.T) {
	sourcePolicy := activeRefreshTrackingPolicyForTest(2)
	sourcePolicy.HeatHalfLife = 3600
	source := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: sourcePolicy}, Opts{})
	defer source.Close()
	hotKey, _, hot := seedTrackedEntry(t, source, "restore-hotter.example.", time.Hour, 0)
	coldKey, _, cold := seedTrackedEntry(t, source, "restore-newer-but-colder.example.", time.Hour, 0)
	now := time.Now()
	hot.item.activityState().lastRealAccess.Store(now.Add(-10 * time.Minute).UnixNano())
	cold.item.activityState().lastRealAccess.Store(now.UnixNano())
	hot.item.activityState().realAccessCount.Store(100)
	cold.item.activityState().realAccessCount.Store(2)
	source.activeMu.Lock()
	hotMeta := source.activeMeta[hotKey]
	coldMeta := source.activeMeta[coldKey]
	hotMeta.heat, hotMeta.heatAt = 100, now
	coldMeta.heat, coldMeta.heatAt = 2, now
	hotMeta.heatObserved = hot.item.activityState().realAccessCount.Load()
	coldMeta.heatObserved = cold.item.activityState().realAccessCount.Load()
	source.activeMu.Unlock()

	buf := new(bytes.Buffer)
	if n, err := source.writeDump(buf); err != nil || n != 2 {
		t.Fatalf("write dump: entries=%d err=%v", n, err)
	}
	dumpBytes := append([]byte(nil), buf.Bytes()...)
	targetPolicy := activeRefreshTrackingPolicyForTest(1)
	targetPolicy.HeatHalfLife = 3600
	target := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: targetPolicy}, Opts{})
	defer target.Close()
	target.bindActiveRefreshReplay(sequence.ChainWalker{})
	if n, err := target.readDump(bytes.NewReader(dumpBytes)); err != nil || n != 2 {
		t.Fatalf("read dump: entries=%d err=%v", n, err)
	}
	target.activeMu.RLock()
	restoredHot := target.activeMeta[hotKey]
	restoredCold := target.activeMeta[coldKey]
	target.activeMu.RUnlock()
	if restoredHot == nil || restoredHot.task == nil || restoredCold != nil {
		t.Fatalf("heat cap selection mismatch: hot=%#v cold=%#v", restoredHot, restoredCold)
	}
	if restoredHot.heat < 90 {
		t.Fatalf("restored hot heat = %f, want persisted score near 100", restoredHot.heat)
	}

	clockPolicy := activeRefreshTrackingPolicyForTest(2)
	clockPolicy.HeatHalfLife = 3600
	clockTarget := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: clockPolicy}, Opts{})
	defer clockTarget.Close()
	clockTarget.bindActiveRefreshReplay(sequence.ChainWalker{})
	if n, err := clockTarget.readDump(bytes.NewReader(dumpBytes)); err != nil || n != 2 {
		t.Fatalf("read clock dump: entries=%d err=%v", n, err)
	}
	clockTarget.activeMu.RLock()
	clockHot := clockTarget.activeMeta[hotKey]
	clockCold := clockTarget.activeMeta[coldKey]
	clockTarget.activeMu.RUnlock()
	if clockHot == nil || clockCold == nil || clockCold.evictionTicket >= clockHot.evictionTicket {
		t.Fatalf("restored CLOCK ticket order: hot=%#v cold=%#v", clockHot, clockCold)
	}
	if clockHot.referenced.Load() || clockCold.referenced.Load() || clockHot.protected || clockCold.protected {
		t.Fatal("restored CLOCK state was not reset")
	}
}

func TestDumpRestorePopularityHeatDecaysDuringDowntime(t *testing.T) {
	policy := activeRefreshTrackingPolicyForTest(16)
	policy.HeatHalfLife = 60
	qCtx := newTestQuery("restore-decay.example.", dns.TypeA, dns.ClassINET, true)
	k := testCacheKey(t, qCtx)
	prepared := testPreparedA(t, qCtx.Q(), "192.0.2.1", time.Hour)
	now := time.Now()
	dump := encodeLegacyDumpEntry(t, &CachedEntry{
		Key: []byte(k), Msg: prepared.item.resp,
		CacheExpirationTime: prepared.cacheExpiration.Unix(), MsgExpirationTime: prepared.item.expirationTime.Unix(),
		MsgStoredTime: prepared.item.storedTime.Unix(), LastRealAccessTime: now.Unix(),
		ActiveRefreshState: &ActiveRefreshState{
			Version: 1, Tracked: true, RealAccessCount: 8,
			AdmissionWindowStartUnix: now.Unix(), AdmissionHits: 1,
			Heat: 8, HeatAtUnixNano: now.Add(-60 * time.Second).UnixNano(),
		},
	})
	target := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: policy}, Opts{})
	defer target.Close()
	target.bindActiveRefreshReplay(sequence.ChainWalker{})
	if n, err := target.readDump(bytes.NewReader(dump)); err != nil || n != 1 {
		t.Fatalf("read dump: entries=%d err=%v", n, err)
	}
	target.activeMu.RLock()
	meta := target.activeMeta[k]
	target.activeMu.RUnlock()
	if meta == nil || meta.heat < 3.9 || meta.heat > 4.1 {
		t.Fatalf("restored decayed heat = %#v, want approximately 4", meta)
	}
}

func TestOldDumpPopularityPolicyWaitsForFreshAdmission(t *testing.T) {
	qCtx := newTestQuery("old-dump.example.", dns.TypeA, dns.ClassINET, true)
	k := testCacheKey(t, qCtx)
	prepared := testPreparedA(t, qCtx.Q(), "192.0.2.1", time.Hour)
	legacyDump := encodeLegacyDumpEntry(t, &CachedEntry{
		Key: []byte(k), Msg: prepared.item.resp,
		CacheExpirationTime: prepared.cacheExpiration.Unix(), MsgExpirationTime: prepared.item.expirationTime.Unix(),
		MsgStoredTime: prepared.item.storedTime.Unix(), LastRealAccessTime: time.Now().Unix(),
	})

	policy := activeRefreshTrackingPolicyForTest(16)
	policy.AdmissionHits = 2
	policyTarget := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: policy}, Opts{})
	defer policyTarget.Close()
	policyTarget.bindActiveRefreshReplay(sequence.ChainWalker{})
	if n, err := policyTarget.readDump(bytes.NewReader(legacyDump)); err != nil || n != 1 {
		t.Fatalf("policy read old dump: entries=%d err=%v", n, err)
	}
	loaded, _, present := policyTarget.backend.Get(k)
	if !present || loaded == nil {
		t.Fatal("policy mode did not restore old dump cache content")
	}
	if meta := policyTarget.activeMeta[k]; meta != nil {
		t.Fatalf("old dump bypassed popularity admission: %#v", meta)
	}
	if got := loaded.activityState().realAccessCount.Load(); got != 0 {
		t.Fatalf("old dump synthesized %d popularity hits, want 0", got)
	}

	legacyTarget := newDormantActiveCache(t, &Args{Size: 16}, Opts{})
	defer legacyTarget.Close()
	legacyTarget.bindActiveRefreshReplay(sequence.ChainWalker{})
	if n, err := legacyTarget.readDump(bytes.NewReader(legacyDump)); err != nil || n != 1 {
		t.Fatalf("legacy read old dump: entries=%d err=%v", n, err)
	}
	if meta := legacyTarget.activeMeta[k]; meta == nil || meta.task == nil {
		t.Fatalf("legacy restore behaviour changed: %#v", meta)
	}
}

func TestDecodeDumpSanitizesPopularityState(t *testing.T) {
	qCtx := newTestQuery("sanitize-dump.example.", dns.TypeA, dns.ClassINET, true)
	k := testCacheKey(t, qCtx)
	prepared := testPreparedA(t, qCtx.Q(), "192.0.2.1", time.Hour)
	policy := activeRefreshTrackingPolicyForTest(16)
	target := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: policy}, Opts{})
	defer target.Close()
	baseEntry := func(state *ActiveRefreshState) *CachedEntry {
		return &CachedEntry{
			Key: []byte(k), Msg: prepared.item.resp,
			CacheExpirationTime: prepared.cacheExpiration.Unix(), MsgExpirationTime: prepared.item.expirationTime.Unix(),
			MsgStoredTime: prepared.item.storedTime.Unix(), LastRealAccessTime: time.Now().Unix(),
			ActiveRefreshState: state,
		}
	}
	for _, tc := range []struct {
		name  string
		state *ActiveRefreshState
	}{
		{name: "unknown_version", state: &ActiveRefreshState{Version: 99, Tracked: true, RealAccessCount: 1, AdmissionWindowStartUnix: time.Now().Unix(), AdmissionHits: 1, Heat: 1, HeatAtUnixNano: time.Now().UnixNano()}},
		{name: "nan_heat", state: &ActiveRefreshState{Version: 1, Tracked: true, RealAccessCount: 1, AdmissionWindowStartUnix: time.Now().Unix(), AdmissionHits: 1, Heat: math.NaN(), HeatAtUnixNano: time.Now().UnixNano()}},
		{name: "infinite_heat", state: &ActiveRefreshState{Version: 1, Tracked: true, RealAccessCount: 1, AdmissionWindowStartUnix: time.Now().Unix(), AdmissionHits: 1, Heat: math.Inf(1), HeatAtUnixNano: time.Now().UnixNano()}},
		{name: "negative_heat", state: &ActiveRefreshState{Version: 1, Tracked: true, RealAccessCount: 1, AdmissionWindowStartUnix: time.Now().Unix(), AdmissionHits: 1, Heat: -1, HeatAtUnixNano: time.Now().UnixNano()}},
		{name: "heat_exceeds_count", state: &ActiveRefreshState{Version: 1, Tracked: true, RealAccessCount: 1, AdmissionWindowStartUnix: time.Now().Unix(), AdmissionHits: 1, Heat: 2, HeatAtUnixNano: time.Now().UnixNano()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entries, err := target.decodeDump(bytes.NewReader(encodeLegacyDumpEntry(t, baseEntry(tc.state))))
			if err != nil || len(entries) != 1 {
				t.Fatalf("decode entries=%d err=%v", len(entries), err)
			}
			if entries[0].popularityTracked {
				t.Fatal("invalid popularity state remained tracked")
			}
		})
	}

	future := time.Now().Add(time.Hour)
	entries, err := target.decodeDump(bytes.NewReader(encodeLegacyDumpEntry(t, baseEntry(&ActiveRefreshState{
		Version: 1, Tracked: true, RealAccessCount: 2,
		AdmissionWindowStartUnix: future.Unix(), AdmissionHits: 1,
		Heat: 1, HeatAtUnixNano: future.UnixNano(),
	}))))
	if err != nil || len(entries) != 1 || !entries[0].popularityTracked {
		t.Fatalf("future timestamp state was not safely retained: entries=%d err=%v", len(entries), err)
	}
	if entries[0].popularity == nil || entries[0].popularity.heatAt.After(time.Now()) {
		t.Fatalf("future heat timestamp was not clamped: %#v", entries[0].popularity)
	}
	state := entries[0].item.activityState().admissionState.Load()
	if start := int64(uint32(state >> 32)); start > time.Now().Unix() {
		t.Fatalf("future admission window was not clamped: %d", start)
	}
}

func TestCloseDumpPreservesPopularityAdmission(t *testing.T) {
	policy := activeRefreshTrackingPolicyForTest(16)
	dumpPath := filepath.Join(t.TempDir(), "cache.dump")
	source := newDormantActiveCache(t, &Args{
		Size: 16, DumpFile: dumpPath, DumpInterval: 3600, ActiveRefresh: policy,
	}, Opts{})
	hotKey, _, _ := seedTrackedEntry(t, source, "close-dump-hot.example.", time.Hour, 0)
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := source.dumpCache(); !errors.Is(err, context.Canceled) {
		t.Fatalf("post-close dump error = %v, want context.Canceled", err)
	}

	f, err := os.Open(dumpPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	target := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: activeRefreshTrackingPolicyForTest(16)}, Opts{})
	defer target.Close()
	target.bindActiveRefreshReplay(sequence.ChainWalker{})
	if n, err := target.readDump(f); err != nil || n != 1 {
		t.Fatalf("read close dump: entries=%d err=%v", n, err)
	}
	meta := target.activeMeta[hotKey]
	if meta == nil || meta.task == nil {
		t.Fatalf("final close dump lost popularity admission: %#v", meta)
	}
	activity := meta.expected.activityState()
	if got := activity.realAccessCount.Load(); got != 1 {
		t.Fatalf("final close dump access count = %d, want 1", got)
	}
	if hits := uint32(activity.admissionState.Load()); hits != 1 || meta.heat < 0.9 || meta.heatObserved != 1 {
		t.Fatalf("final close dump popularity state: hits=%d heat=%f observed=%d", hits, meta.heat, meta.heatObserved)
	}
}

func TestPendingRestoreRedumpPreservesPopularityAdmission(t *testing.T) {
	policy := activeRefreshTrackingPolicyForTest(16)
	source := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: policy}, Opts{})
	defer source.Close()
	hotKey, _, _ := seedTrackedEntry(t, source, "pending-redump-hot.example.", time.Hour, 0)
	firstDump := new(bytes.Buffer)
	if n, err := source.writeDump(firstDump); err != nil || n != 1 {
		t.Fatalf("write first dump: entries=%d err=%v", n, err)
	}

	middle := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: policy}, Opts{})
	defer middle.Close()
	if n, err := middle.readDump(firstDump); err != nil || n != 1 {
		t.Fatalf("load pending dump: entries=%d err=%v", n, err)
	}
	middle.activeRestoreMu.Lock()
	pending := len(middle.activeRestore)
	middle.activeRestoreMu.Unlock()
	if pending != 1 {
		t.Fatalf("pending restore entries = %d, want 1", pending)
	}
	pendingDump := new(bytes.Buffer)
	if n, err := middle.writeDump(pendingDump); err != nil || n != 1 {
		t.Fatalf("write pending dump: entries=%d err=%v", n, err)
	}
	middle.activeRestoreMu.Lock()
	for pendingKey, entry := range middle.activeRestore {
		middle.activeRestoreInFlight[pendingKey] = entry
		delete(middle.activeRestore, pendingKey)
	}
	middle.activeRestoreRunning = true
	middle.activeRestoreMu.Unlock()
	inFlightDump := new(bytes.Buffer)
	if n, err := middle.writeDump(inFlightDump); err != nil || n != 1 {
		t.Fatalf("write in-flight dump: entries=%d err=%v", n, err)
	}

	target := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: policy}, Opts{})
	defer target.Close()
	target.bindActiveRefreshReplay(sequence.ChainWalker{})
	if n, err := target.readDump(inFlightDump); err != nil || n != 1 {
		t.Fatalf("load in-flight dump: entries=%d err=%v", n, err)
	}
	if meta := target.activeMeta[hotKey]; meta == nil || meta.task == nil {
		t.Fatalf("pending restore redump lost admission: %#v", meta)
	}
}

func TestActiveRefreshDisabledLoadsCacheWithoutRefreshTasks(t *testing.T) {
	source := newDormantActiveCache(t, &Args{Size: 16}, Opts{})
	defer source.Close()
	k, _, _ := seedTrackedEntry(t, source, "restore-disabled.example.", time.Hour, 10*time.Minute)
	buf := new(bytes.Buffer)
	if n, err := source.writeDump(buf); err != nil || n != 1 {
		t.Fatalf("write dump: entries=%d err=%v", n, err)
	}

	target := newCacheForTest(t, &Args{Size: 16}, Opts{})
	defer target.Close()
	if err := target.BindContinuation(sequence.ChainWalker{}); err != nil {
		t.Fatal(err)
	}
	if n, err := target.readDump(buf); err != nil || n != 1 {
		t.Fatalf("read dump: entries=%d err=%v", n, err)
	}
	if current, _, present := target.backend.Get(k); !present || current == nil {
		t.Fatal("dump entry was not loaded into cache")
	}
	target.activeMu.RLock()
	metaLen, futureLen := len(target.activeMeta), len(target.activeSchedule)
	target.activeMu.RUnlock()
	target.activeRestoreMu.Lock()
	restoreLen := len(target.activeRestore)
	target.activeRestoreMu.Unlock()
	if metaLen != 0 || futureLen != 0 || restoreLen != 0 {
		t.Fatalf("disabled startup restore created state: meta=%d future=%d restore=%d", metaLen, futureLen, restoreLen)
	}
}

func TestAutomaticDumpRestoreRejectsMultipleSequenceBindings(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16}, Opts{})
	defer c.Close()
	if err := c.BindContinuation(sequence.ChainWalker{}); err != nil {
		t.Fatal(err)
	}
	if err := c.BindContinuation(sequence.ChainWalker{}); err == nil || !strings.Contains(err.Error(), "more than one sequence") {
		t.Fatalf("second binding error = %v, want multiple-sequence error", err)
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
		p.item.activityState().lastRealAccess.Store(lastAccess.UnixNano())
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
	originalAccess := originalMeta.expected.activityState().lastRealAccess.Load()
	c.activeMu.RUnlock()
	oldEntry := decodedDumpEntry{
		k: k, item: old.item, cacheExpiration: old.cacheExpiration,
		lastRealAccess: time.Now().Add(-30 * time.Minute), refreshCount: 9,
	}
	c.restoreActiveRefreshEntries([]decodedDumpEntry{oldEntry}, sequence.ChainWalker{})
	c.activeMu.RLock()
	preserved := c.activeMeta[k]
	c.activeMu.RUnlock()
	if preserved != originalMeta || preserved.expected.activityState().lastRealAccess.Load() != originalAccess || preserved.expected.activityState().refreshSuccesses() != 0 {
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
