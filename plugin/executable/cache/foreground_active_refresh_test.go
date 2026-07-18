package cache

import (
	"context"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

func TestPreviewActiveRefreshHitWeightDoesNotConsumeSample(t *testing.T) {
	qCtx := newTestQuery("deferred-fast-sample.example.", dns.TypeA, dns.ClassINET, true)
	qCtx.SetFastCacheHits(7)

	if got := previewActiveRefreshHitWeight(qCtx); got != 7 {
		t.Fatalf("first preview = %d, want 7", got)
	}
	if got := previewActiveRefreshHitWeight(qCtx); got != 7 {
		t.Fatalf("second preview consumed sample: got %d, want 7", got)
	}
	if got := activeRefreshHitWeight(qCtx); got != 7 {
		t.Fatalf("commit claim = %d, want 7", got)
	}
	if got := activeRefreshHitWeight(qCtx); got != 0 {
		t.Fatalf("sample was claimable twice: got %d", got)
	}
}

func TestHealthyForegroundHandoffInheritsReadyAdmissionBeforeMetaInstall(t *testing.T) {
	policy := activeRefreshTrackingPolicyForTest(16)
	policy.AdmissionHits = 5
	c := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: policy}, Opts{})
	defer c.Close()

	base := newTestQuery("pre-meta-transient-heal.example.", dns.TypeA, dns.ClassINET, true)
	base.SetFastCacheHits(5)
	transientBranch := base.Copy()
	healthyBranch := base.Copy()
	transientResponse := new(dns.Msg)
	transientResponse.SetReply(base.Q())
	transientResponse.Rcode = dns.RcodeServerFailure
	transientBranch.SetResponse(transientResponse)
	healthyResponse := testAResponse(t, base.Q(), "192.0.2.54", 60)
	healthyBranch.SetResponse(healthyResponse)
	transientReplay, err := transientBranch.SnapshotForReplay()
	if err != nil {
		t.Fatal(err)
	}
	healthyReplay, err := healthyBranch.SnapshotForReplay()
	if err != nil {
		t.Fatal(err)
	}

	k := testCacheKey(t, base)
	epoch := c.refreshEpoch.Load()
	transientPrepared, ok := c.prepareCacheEntry(transientBranch, true)
	if !ok {
		t.Fatal("failed to prepare transient foreground entry")
	}
	committed, displaced := c.commitPreparedForegroundWithDisplaced(k, nil, epoch, transientPrepared)
	if !committed || displaced != nil {
		t.Fatal("failed to commit transient foreground entry")
	}
	now := time.Now()
	if ready, hits := c.recordActiveRefreshContextActivity(transientPrepared.item, transientBranch, now); hits != 5 || !ready {
		t.Fatal("transient activity did not reach admission threshold")
	}
	if boundActiveRefreshMeta(transientPrepared.item) != nil {
		t.Fatal("test unexpectedly installed metadata before the handoff")
	}

	healthyPrepared, ok := c.prepareCacheEntry(healthyBranch, true)
	if !ok {
		t.Fatal("failed to prepare healthy foreground entry")
	}
	committed, displaced = c.commitPreparedForegroundWithDisplaced(k, nil, epoch, healthyPrepared)
	if !committed || displaced != transientPrepared.item {
		t.Fatal("healthy foreground entry did not displace transient generation")
	}
	if _, hits := c.recordActiveRefreshContextActivity(healthyPrepared.item, healthyBranch, now); hits != 0 {
		t.Fatalf("healthy branch reclaimed shared sample: got %d, want 0", hits)
	}
	if !c.inheritedForegroundActiveRefreshReady(healthyPrepared.item, displaced, now) {
		t.Fatal("healthy handoff did not inherit the recorded admission state")
	}
	c.reconcileForegroundActiveRefresh(
		k, healthyPrepared.item, nil, displaced, true,
		healthyReplay, sequence.ChainWalker{}, now, healthyPrepared.msg,
	)
	// Model the transient branch's delayed commit-to-metadata handoff. Its
	// generation check must not disturb metadata already bound to healthy.
	c.reconcileForegroundActiveRefresh(
		k, transientPrepared.item, nil, nil, true,
		transientReplay, sequence.ChainWalker{}, now, transientPrepared.msg,
	)

	if got := healthyPrepared.item.activityState().realAccessCount.Load(); got != 5 {
		t.Fatalf("readiness inheritance changed hit count: got %d, want 5", got)
	}
	c.activeMu.RLock()
	meta := c.activeMeta[k]
	tracked := meta != nil && meta.expected == healthyPrepared.item && meta.task != nil
	c.activeMu.RUnlock()
	if !tracked || boundActiveRefreshMeta(healthyPrepared.item) != meta {
		t.Fatal("healthy generation was not tracked after pre-metadata handoff")
	}
	if boundActiveRefreshMeta(transientPrepared.item) != nil {
		t.Fatal("late transient handoff published a stale metadata handle")
	}
	assertActiveEvictionInvariant(t, c)
}

func TestConsumedFastSampleCannotPrecedeAdmissionPublication(t *testing.T) {
	policy := activeRefreshTrackingPolicyForTest(16)
	policy.AdmissionHits = 5
	c := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: policy}, Opts{})
	defer c.Close()

	base := newTestQuery("half-published-fast-sample.example.", dns.TypeA, dns.ClassINET, true)
	base.SetFastCacheHits(5)
	transientBranch := base.Copy()
	healthyBranch := base.Copy()
	transient := testPreparedA(t, base.Q(), "192.0.2.61", time.Minute)
	transient.item.isTransient = true
	healthy := testPreparedA(t, base.Q(), "192.0.2.62", time.Minute)
	inheritActiveRefreshActivity(healthy.item, transient.item)

	// Pause the claimant after it has consumed the shared token but before it
	// publishes count/admission. The lineage lock must keep the healthy peer
	// from observing that impossible intermediate state.
	writer := acquireActiveRefreshActivityWriter(transient.item)
	hits := activeRefreshHitWeight(transientBranch)
	if hits != 5 {
		writer.release()
		t.Fatalf("transient claim = %d, want 5", hits)
	}
	type result struct {
		ready  bool
		weight uint32
	}
	healthyResult := make(chan result, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		ready, weight := c.recordActiveRefreshContextActivity(healthy.item, healthyBranch, time.Now())
		healthyResult <- result{ready: ready, weight: weight}
	}()
	<-started
	select {
	case got := <-healthyResult:
		writer.release()
		t.Fatalf("healthy peer observed half-published sample: %+v", got)
	case <-time.After(20 * time.Millisecond):
	}

	if !c.publishActiveRefreshActivity(transient.item, time.Now(), hits, &writer) {
		t.Fatal("transient publication did not reach admission threshold")
	}
	got := <-healthyResult
	if got.ready || got.weight != 0 {
		t.Fatalf("healthy peer re-recorded consumed sample: %+v", got)
	}
	if !c.inheritedForegroundActiveRefreshReady(healthy.item, transient.item, time.Now()) {
		t.Fatal("healthy peer did not inherit the completed admission publication")
	}
	if count := healthy.item.activityState().realAccessCount.Load(); count != 5 {
		t.Fatalf("shared hit count = %d, want 5", count)
	}
}

func TestParallelHealthyForegroundReplacementKeepsTransientTracking(t *testing.T) {
	policy := activeRefreshTrackingPolicyForTest(16)
	policy.AdmissionHits = 5
	c := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: policy}, Opts{})
	defer c.Close()

	base := newTestQuery("parallel-transient-heal.example.", dns.TypeA, dns.ClassINET, true)
	base.SetFastCacheHits(5)
	healthyBranch := base.Copy()
	transientBranch := base.Copy()
	healthyResponse := testAResponse(t, base.Q(), "192.0.2.55", 60)
	transientResponse := new(dns.Msg)
	transientResponse.SetReply(base.Q())
	transientResponse.Rcode = dns.RcodeServerFailure

	healthyEnteredUpstream := make(chan struct{})
	releaseHealthy := make(chan struct{})
	released := false
	upstream := sequence.ExecutableFunc(func(ctx context.Context, qCtx *query_context.Context) error {
		switch qCtx {
		case healthyBranch:
			close(healthyEnteredUpstream)
			select {
			case <-releaseHealthy:
			case <-ctx.Done():
				return ctx.Err()
			}
			qCtx.SetResponse(healthyResponse.Copy())
		case transientBranch:
			qCtx.SetResponse(transientResponse.Copy())
		}
		return nil
	})
	plugins := map[string]any{"cache": c, "upstream": upstream}
	m := coremain.NewTestMosdnsWithPlugins(plugins)
	flow, err := sequence.NewSequence(coremain.NewBP("foreground-handoff", m), []sequence.RuleArgs{
		{Exec: "$cache"},
		{Exec: "$upstream"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()

	healthyDone := make(chan error, 1)
	healthyExited := make(chan struct{})
	go func() {
		defer close(healthyExited)
		healthyDone <- flow.Exec(context.Background(), healthyBranch)
	}()
	defer func() {
		if !released {
			close(releaseHealthy)
		}
		select {
		case <-healthyExited:
		case <-time.After(time.Second):
		}
	}()
	select {
	case <-healthyEnteredUpstream:
	case <-time.After(time.Second):
		t.Fatal("healthy branch did not reach the controlled upstream")
	}

	// Both branches observed an absent cache. Let the transient branch finish
	// first so it alone consumes the shared fast-cache sample and installs the
	// initial active-refresh metadata.
	if err := flow.Exec(context.Background(), transientBranch); err != nil {
		t.Fatal(err)
	}
	k := testCacheKey(t, base)
	transient, _, present := c.backend.Get(k)
	if !present || transient == nil || !transient.isTransient {
		t.Fatalf("transient branch did not publish SERVFAIL: present=%v item=%#v", present, transient)
	}
	if got := transient.activityState().realAccessCount.Load(); got != 5 {
		t.Fatalf("transient hit count = %d, want 5", got)
	}
	c.activeMu.RLock()
	transientMeta := c.activeMeta[k]
	transientTracked := transientMeta != nil && transientMeta.expected == transient && transientMeta.task != nil
	c.activeMu.RUnlock()
	if !transientTracked || boundActiveRefreshMeta(transient) != transientMeta {
		t.Fatal("transient branch did not establish active-refresh tracking")
	}

	close(releaseHealthy)
	released = true
	select {
	case err := <-healthyDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("healthy branch did not finish after release")
	}

	current, _, present := c.backend.Get(k)
	if !present || current == nil || current.isTransient {
		t.Fatalf("healthy branch did not replace SERVFAIL: present=%v item=%#v", present, current)
	}
	if current == transient {
		t.Fatal("healthy branch retained the transient generation")
	}
	if current.activityState() != transient.activityState() {
		t.Fatal("healthy replacement did not inherit the transient activity lineage")
	}
	if got := current.activityState().realAccessCount.Load(); got != 5 {
		t.Fatalf("healthy handoff double-counted shared hits: got %d, want 5", got)
	}
	c.activeMu.RLock()
	currentMeta := c.activeMeta[k]
	currentTracked := currentMeta != nil && currentMeta.expected == current && currentMeta.task != nil
	c.activeMu.RUnlock()
	if !currentTracked || boundActiveRefreshMeta(current) != currentMeta {
		t.Fatal("healthy replacement lost inherited active-refresh tracking")
	}
	if boundActiveRefreshMeta(transient) != nil {
		t.Fatal("transient generation retained a live metadata handle after handoff")
	}
	assertActiveEvictionInvariant(t, c)
}

func TestBelowThresholdForegroundReplacementReleasesOldTrackingSlot(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: ActiveRefreshArgs{
		MaxTrackedEntries: 1,
		AdmissionHits:     1,
		AdmissionWindow:   60,
		HeatHalfLife:      600,
		ProtectedRatio:    80,
		EvictionScanLimit: 64,
	}}, Opts{})
	defer c.Close()

	k, qCtx, old := seedTrackedEntry(t, c, "stopped-old-lineage.example.", time.Minute, 0)
	c.activeMu.Lock()
	oldMeta := c.activeMeta[k]
	c.removeMetaTaskLocked(oldMeta)
	oldMeta.stopped.Store(true)
	c.activeMu.Unlock()

	// Model the first real access in a fresh admission window: it is useful
	// activity, but not enough to track the replacement yet.
	c.args.ActiveRefresh.AdmissionHits = 2
	old.item.activityState().admissionState.Store(0)
	if c.recordActiveRefreshActivity(old.item, time.Now(), 1) {
		t.Fatal("single access unexpectedly met the two-hit admission threshold")
	}

	fresh := testPreparedA(t, qCtx.Q(), "192.0.2.2", 2*time.Minute)
	committed, displaced := c.commitPreparedForegroundWithDisplaced(k, old.item, c.refreshEpoch.Load(), fresh)
	if !committed || displaced != old.item {
		t.Fatal("failed to commit foreground replacement")
	}
	c.reconcileForegroundActiveRefresh(
		k, fresh.item, old.item, displaced, false,
		nil, sequence.ChainWalker{}, time.Now(), fresh.msg,
	)

	c.activeMu.RLock()
	_, retained := c.activeMeta[k]
	c.activeMu.RUnlock()
	if retained || old.item.activeMeta.Load() != nil {
		t.Fatal("below-threshold replacement retained stopped old metadata")
	}

	// The only slot must now be available to a different key after two hits.
	otherCtx := newTestQuery("new-hot-entry.example.", dns.TypeA, dns.ClassINET, true)
	otherKey := testCacheKey(t, otherCtx)
	other := testPreparedA(t, otherCtx.Q(), "192.0.2.3", time.Minute)
	if !c.commitPrepared(otherKey, nil, c.refreshEpoch.Load(), other) {
		t.Fatal("failed to seed replacement admission candidate")
	}
	c.trackActiveRefresh(otherKey, other.item, otherCtx, sequence.ChainWalker{}, time.Now(), other.msg)
	c.observeActiveRefresh(otherKey, other.item, otherCtx, sequence.ChainWalker{}, time.Now(), other.msg)
	c.activeMu.RLock()
	admitted := c.activeMeta[otherKey]
	c.activeMu.RUnlock()
	if admitted == nil || admitted.expected != other.item {
		t.Fatalf("released tracking slot was not reusable: %#v", admitted)
	}
	assertActiveEvictionInvariant(t, c)
}

func TestBelowThresholdAbsentRefillCleansEvictedMetadata(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: ActiveRefreshArgs{
		MaxTrackedEntries: 1,
		AdmissionHits:     1,
		AdmissionWindow:   60,
		HeatHalfLife:      600,
		ProtectedRatio:    80,
		EvictionScanLimit: 64,
	}}, Opts{})
	defer c.Close()

	k, qCtx, old := seedTrackedEntry(t, c, "evicted-before-refill.example.", time.Minute, 0)
	c.activeMu.Lock()
	oldMeta := c.activeMeta[k]
	c.removeMetaTaskLocked(oldMeta)
	oldMeta.stopped.Store(true)
	c.activeMu.Unlock()

	// Model an expiry/capacity removal whose hint has not yet been drained. The
	// next foreground lookup therefore observes an absent key, and StoreIf also
	// displaces nothing even though the old metadata container still exists.
	c.backend.Flush()
	c.noteActiveBackendRemoval(k, old.item)
	if !old.item.backendRemoved.Load() {
		t.Fatal("removed backend generation was not marked")
	}
	if _, _, present := c.backend.Get(k); present {
		t.Fatal("test backend entry is still present")
	}

	c.args.ActiveRefresh.AdmissionHits = 2
	old.item.activityState().admissionState.Store(0)
	fresh := testPreparedA(t, qCtx.Q(), "192.0.2.4", 2*time.Minute)
	committed, displaced := c.commitPreparedForegroundWithDisplaced(k, nil, c.refreshEpoch.Load(), fresh)
	if !committed || displaced != nil {
		t.Fatal("absent foreground refill did not commit cleanly")
	}
	c.reconcileForegroundActiveRefresh(
		k, fresh.item, nil, displaced, false,
		nil, sequence.ChainWalker{}, time.Now(), fresh.msg,
	)

	c.activeMu.RLock()
	_, retained := c.activeMeta[k]
	c.activeMu.RUnlock()
	if retained || old.item.activeMeta.Load() != nil {
		t.Fatal("absent refill retained evicted old metadata")
	}
	current, _, present := c.backend.Get(k)
	if !present || current != fresh.item {
		t.Fatal("metadata cleanup disturbed the committed refill")
	}
	assertActiveEvictionInvariant(t, c)
}
