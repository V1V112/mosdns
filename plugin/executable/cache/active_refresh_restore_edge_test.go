package cache

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

func TestRestoreTransferPopularitySnapshotsShareOneBaseline(t *testing.T) {
	policy := activeRefreshTrackingPolicyForTest(16)
	c := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: policy}, Opts{})
	defer c.Close()

	qCtx := newTestQuery("shared-restore-baseline.example.", dns.TypeA, dns.ClassINET, true)
	k := testCacheKey(t, qCtx)
	prepared := testPreparedA(t, qCtx.Q(), "192.0.2.70", time.Hour)
	activity := prepared.item.activityState()
	activity.realAccessCount.Store(8)
	activity.admissionState.Store(uint64(uint32(time.Now().Unix()))<<32 | 4)

	// A future baseline models a dump caller whose timestamp is stale relative
	// to the shared transfer state. Both map entries are value copies, but they
	// deliberately retain the same popularity pointer.
	baseline := time.Now().Add(time.Hour)
	popularity := &restoredPopularityState{heat: 3, heatAt: baseline, observed: 3}
	entry := decodedDumpEntry{
		k: k, item: prepared.item, cacheExpiration: prepared.cacheExpiration,
		lastRealAccess: time.Now(), popularityStatePresent: true,
		popularityTracked: true, popularity: popularity,
	}
	c.activeRestoreMu.Lock()
	c.activeRestore[k] = entry
	c.activeRestoreInFlight[k] = entry
	c.activeRestoreMu.Unlock()

	firstStates := c.snapshotActiveRefreshPopularityForDump()
	first, ok := firstStates[activity]
	if !ok {
		t.Fatal("shared pending/in-flight popularity state was not snapshotted")
	}
	if first.realAccessCount != 8 || uint32(first.admissionState) != 4 {
		t.Fatalf("first transfer snapshot = count:%d hits:%d, want 8/4",
			first.realAccessCount, uint32(first.admissionState))
	}
	if first.heat != 8 {
		t.Fatalf("first transfer heat = %f, want baseline 3 plus one count delta 5", first.heat)
	}
	if !first.heatAt.Equal(baseline) {
		t.Fatalf("first transfer heatAt moved backward: got %s want %s", first.heatAt, baseline)
	}

	secondStates := c.snapshotActiveRefreshPopularityForDump()
	second, ok := secondStates[activity]
	if !ok {
		t.Fatal("shared transfer popularity state disappeared on consecutive snapshot")
	}
	if second.heat != first.heat {
		t.Fatalf("consecutive transfer snapshot counted the same delta twice: first=%f second=%f",
			first.heat, second.heat)
	}
	if second.heatAt.Before(first.heatAt) {
		t.Fatalf("consecutive transfer heatAt moved backward: first=%s second=%s",
			first.heatAt, second.heatAt)
	}
	if uint64(uint32(second.admissionState)) > second.realAccessCount {
		t.Fatalf("invalid transfer snapshot pair: hits=%d count=%d",
			uint32(second.admissionState), second.realAccessCount)
	}
}

func TestSnapshotActiveAdmissionStateDoesNotExposeHalfPublishedPair(t *testing.T) {
	v := new(item)
	activity := v.activityState()
	windowStart := uint64(uint32(time.Now().Unix())) << 32
	activity.realAccessCount.Store(1)
	activity.admissionState.Store(windowStart | 1)

	writer := acquireActiveRefreshActivityWriter(v)
	if writer.meta != nil || !writer.admissionLocked {
		writer.release()
		t.Fatal("failed to hold the untracked admission publication lock")
	}
	released := false
	defer func() {
		if !released {
			writer.release()
		}
	}()

	// Emulate the moment at which a reader has retained the old lifetime count
	// while the next admission value is becoming visible. The pair is not a
	// completed publication until the writer lock is released.
	activity.admissionState.Store(windowStart | 2)
	type snapshotResult struct {
		count uint64
		state uint64
	}
	started := make(chan struct{})
	result := make(chan snapshotResult, 1)
	go func() {
		close(started)
		count, state := snapshotActiveAdmissionState(v)
		result <- snapshotResult{count: count, state: state}
	}()
	<-started
	select {
	case got := <-result:
		writer.release()
		released = true
		t.Fatalf("snapshot escaped an incomplete publication: hits=%d count=%d",
			uint32(got.state), got.count)
	case <-time.After(20 * time.Millisecond):
	}

	activity.realAccessCount.Store(2)
	writer.release()
	released = true
	select {
	case got := <-result:
		hits := uint64(uint32(got.state))
		if got.count != 2 || hits != 2 || hits > got.count {
			t.Fatalf("coherent admission snapshot = hits:%d count:%d, want 2/2", hits, got.count)
		}
	case <-time.After(time.Second):
		t.Fatal("admission snapshot remained blocked after publication completed")
	}
}

type restoreClockCandidate struct {
	entry decodedDumpEntry
	shard uint64
}

func newRestoreClockCandidate(
	t *testing.T,
	c *Cache,
	label string,
	count uint64,
	now time.Time,
	usedShards map[uint64]struct{},
) restoreClockCandidate {
	t.Helper()
	for suffix := 0; suffix < shardCount*2; suffix++ {
		qCtx := newTestQuery(fmt.Sprintf("restore-clock-%s-%d.example.", label, suffix), dns.TypeA, dns.ClassINET, true)
		k := testCacheKey(t, qCtx)
		shard := k.Sum() % shardCount
		if _, exists := usedShards[shard]; exists {
			continue
		}
		prepared := testPreparedA(t, qCtx.Q(), "192.0.2.71", time.Hour)
		if !c.commitPrepared(k, nil, 0, prepared) {
			t.Fatalf("failed to seed %s restore candidate", label)
		}
		activity := prepared.item.activityState()
		activity.lastRealAccess.Store(now.UnixNano())
		activity.realAccessCount.Store(count)
		activity.admissionState.Store(uint64(uint32(now.Unix()))<<32 | count)
		usedShards[shard] = struct{}{}
		return restoreClockCandidate{
			shard: shard,
			entry: decodedDumpEntry{
				k: k, item: prepared.item, cacheExpiration: prepared.cacheExpiration,
				lastRealAccess: now, popularityStatePresent: true,
				popularityTracked: true,
				popularity: &restoredPopularityState{
					heat: float64(count), heatAt: now, observed: count,
				},
			},
		}
	}
	t.Fatalf("could not find an unused commit shard for %s", label)
	return restoreClockCandidate{}
}

func TestRestoreReservesFinalClockOrderBeforeInstallAndRuntimeClearKeepsTicket(t *testing.T) {
	policy := activeRefreshTrackingPolicyForTest(3)
	policy.HeatHalfLife = 3600
	c := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: policy}, Opts{})
	defer c.Close()

	now := time.Now()
	usedShards := make(map[uint64]struct{}, 3)
	hot := newRestoreClockCandidate(t, c, "hot", 30, now, usedShards)
	mid := newRestoreClockCandidate(t, c, "mid", 20, now, usedShards)
	cold := newRestoreClockCandidate(t, c, "cold", 10, now, usedShards)

	coldCommit := &c.commitLocks[cold.shard]
	coldCommit.Lock()
	coldLocked := true
	defer func() {
		if coldLocked {
			coldCommit.Unlock()
		}
	}()

	done := make(chan struct{})
	go func() {
		c.restoreActiveRefreshEntries([]decodedDumpEntry{mid.entry, cold.entry, hot.entry}, sequence.ChainWalker{})
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	var hotTicket, midTicket, clockTicket uint64
	for {
		c.activeMu.RLock()
		hotMeta := c.activeMeta[hot.entry.k]
		midMeta := c.activeMeta[mid.entry.k]
		coldMeta := c.activeMeta[cold.entry.k]
		clockTicket = c.activeClockTicket
		if hotMeta != nil {
			hotTicket = hotMeta.evictionTicket
		}
		if midMeta != nil {
			midTicket = midMeta.evictionTicket
		}
		c.activeMu.RUnlock()
		if hotMeta != nil && midMeta != nil && coldMeta == nil {
			break
		}
		select {
		case <-done:
			t.Fatal("restore completed while the cold candidate commit lock was held")
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("restore did not reach the blocked cold candidate")
		}
		time.Sleep(time.Millisecond)
	}

	// All three tickets must already be reserved while only hot and mid are
	// installed. Cold owns ticket 1 even though its commit is still blocked.
	if clockTicket != 3 || midTicket != 2 || hotTicket != 3 || midTicket >= hotTicket {
		t.Fatalf("in-progress CLOCK order = clock:%d mid:%d hot:%d, want 3/2/3",
			clockTicket, midTicket, hotTicket)
	}

	coldCommit.Unlock()
	coldLocked = false
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("restore did not finish after releasing the cold candidate")
	}

	c.activeMu.RLock()
	hotMeta := c.activeMeta[hot.entry.k]
	midMeta := c.activeMeta[mid.entry.k]
	coldMeta := c.activeMeta[cold.entry.k]
	clockTicket = c.activeClockTicket
	c.activeMu.RUnlock()
	if hotMeta == nil || midMeta == nil || coldMeta == nil {
		t.Fatalf("completed restore metadata = hot:%#v mid:%#v cold:%#v", hotMeta, midMeta, coldMeta)
	}
	if coldMeta.evictionTicket != 1 || midMeta.evictionTicket != 2 || hotMeta.evictionTicket != 3 || clockTicket != 3 {
		t.Fatalf("completed cold-to-hot CLOCK order = cold:%d mid:%d hot:%d clock:%d, want 1/2/3/3",
			coldMeta.evictionTicket, midMeta.evictionTicket, hotMeta.evictionTicket, clockTicket)
	}

	c.flushMu.Lock()
	c.clearRuntimeViews(nil)
	c.flushMu.Unlock()
	c.activeMu.RLock()
	keptTicket := c.activeClockTicket
	remainingMeta := len(c.activeMeta)
	c.activeMu.RUnlock()
	if remainingMeta != 0 {
		t.Fatalf("runtime clear left %d active metadata entries", remainingMeta)
	}
	if keptTicket != clockTicket {
		t.Fatalf("runtime clear reset CLOCK ticket: before=%d after=%d", clockTicket, keptTicket)
	}
	c.activeMu.Lock()
	nextTicket := c.nextActiveClockTicketLocked()
	c.activeMu.Unlock()
	if nextTicket != clockTicket+1 {
		t.Fatalf("CLOCK ticket was not process-monotonic after runtime clear: got %d want %d",
			nextTicket, clockTicket+1)
	}
}

func TestRestoreMergesPersistedHeatIntoExistingGenerationWithoutReplacingRuntimeState(t *testing.T) {
	policy := activeRefreshTrackingPolicyForTest(3)
	policy.HeatHalfLife = 60
	c := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: policy}, Opts{})
	defer c.Close()

	k, _, prepared := seedTrackedEntry(t, c, "restore-existing-generation.example.", time.Hour, 0)
	activity := prepared.item.activityState()
	now := time.Now()
	activity.realAccessCount.Store(8)
	activity.admissionState.Store(uint64(uint32(now.Unix()))<<32 | 1)
	activity.lastRealAccess.Store(now.UnixNano())

	c.activeMu.Lock()
	existing := c.activeMeta[k]
	if existing == nil || existing.task == nil || existing.expected != prepared.item {
		c.activeMu.Unlock()
		t.Fatalf("test setup produced incomplete existing metadata: %#v", existing)
	}
	existing.heat = 0.25
	existing.heatAt = now
	existing.heatObserved = 8
	existing.referenced.Store(true)
	taskBefore := existing.task
	ticketBefore := existing.evictionTicket
	referencedBefore := existing.referenced.Load()
	c.activeMu.Unlock()

	persistedHeatAt := now.Add(-time.Duration(policy.HeatHalfLife) * time.Second)
	popularity := &restoredPopularityState{heat: 8, heatAt: persistedHeatAt, observed: 8}
	entry := decodedDumpEntry{
		k: k, item: prepared.item, cacheExpiration: prepared.cacheExpiration,
		lastRealAccess: now, popularityStatePresent: true,
		popularityTracked: true, popularity: popularity,
	}
	mergeStarted := time.Now()
	c.restoreActiveRefreshEntries([]decodedDumpEntry{entry}, sequence.ChainWalker{})

	c.activeMu.RLock()
	merged := c.activeMeta[k]
	if merged == nil {
		c.activeMu.RUnlock()
		t.Fatal("existing generation metadata disappeared during restore merge")
	}
	taskAfter := merged.task
	ticketAfter := merged.evictionTicket
	referencedAfter := merged.referenced.Load()
	mergedHeat := merged.heat
	mergedHeatAt := merged.heatAt
	mergedObserved := merged.heatObserved
	c.activeMu.RUnlock()

	if merged != existing {
		t.Fatal("same-generation restore replaced the existing metadata object")
	}
	if taskAfter != taskBefore || ticketAfter != ticketBefore || referencedAfter != referencedBefore {
		t.Fatalf("same-generation merge changed runtime state: task %p->%p ticket %d->%d referenced %v->%v",
			taskBefore, taskAfter, ticketBefore, ticketAfter, referencedBefore, referencedAfter)
	}
	if mergedHeat < 3.8 || mergedHeat > 4.1 {
		t.Fatalf("persisted heat was not merged with one half-life of decay: got %f want approximately 4", mergedHeat)
	}
	if mergedObserved != 8 {
		t.Fatalf("merged heat baseline observed count = %d, want 8", mergedObserved)
	}
	if mergedHeatAt.Before(mergeStarted) || mergedHeatAt.Before(persistedHeatAt) {
		t.Fatalf("merged decay baseline did not advance: persisted=%s merge-start=%s merged=%s",
			persistedHeatAt, mergeStarted, mergedHeatAt)
	}
	popularity.mu.Lock()
	sharedHeat := popularity.heat
	sharedHeatAt := popularity.heatAt
	sharedObserved := popularity.observed
	popularity.mu.Unlock()
	if sharedHeat != mergedHeat || !sharedHeatAt.Equal(mergedHeatAt) || sharedObserved != mergedObserved {
		t.Fatalf("existing metadata and persisted baseline diverged: meta=%f/%s/%d shared=%f/%s/%d",
			mergedHeat, mergedHeatAt, mergedObserved, sharedHeat, sharedHeatAt, sharedObserved)
	}
}

func assertCoherentTrackedRuntimeLoadDump(
	t *testing.T,
	c *Cache,
	dump []byte,
	k key,
	wantResp []byte,
	wantCount uint64,
) {
	t.Helper()
	entries, err := c.decodeDump(bytes.NewReader(dump))
	if err != nil || len(entries) != 1 {
		t.Fatalf("decode snapshot: entries=%d err=%v", len(entries), err)
	}
	entry := entries[0]
	if entry.k != k || entry.item == nil || !bytes.Equal(entry.item.resp, wantResp) {
		t.Fatalf("snapshot did not contain the runtime-loaded backend generation: key=%q item=%#v", entry.k, entry.item)
	}
	activity := entry.item.activityState()
	count, state := snapshotActiveAdmissionStateFromActivity(activity)
	hits := uint64(uint32(state))
	if count != wantCount || hits != 1 || hits > count {
		t.Fatalf("runtime-loaded snapshot count/admission = %d/%d, want %d/1", count, hits, wantCount)
	}
	if !entry.popularityTracked || entry.popularity == nil {
		t.Fatalf("runtime-loaded backend was paired with torn/untracked popularity state: %#v", entry)
	}
	entry.popularity.mu.Lock()
	heat := entry.popularity.heat
	heatAt := entry.popularity.heatAt
	observed := entry.popularity.observed
	entry.popularity.mu.Unlock()
	if observed != wantCount || heat < float64(wantCount)-0.5 || heat > float64(wantCount) || heatAt.IsZero() {
		t.Fatalf("runtime-loaded popularity baseline = heat:%f at:%s observed:%d, want coherent count %d",
			heat, heatAt, observed, wantCount)
	}
}

func TestDumpSnapshotLinearizesWithRuntimeLoadAndFlushLockedPath(t *testing.T) {
	policy := activeRefreshTrackingPolicyForTest(8)
	policy.HeatHalfLife = 3600
	c := newDormantActiveCache(t, &Args{Size: 16, ActiveRefresh: policy}, Opts{})
	defer c.Close()

	k, qCtx, old := seedTrackedEntry(t, c, "dump-runtime-load-linearized.example.", time.Hour, 0)
	c.bindActiveRefreshReplay(sequence.ChainWalker{})
	now := time.Now()
	replacement := testPreparedA(t, qCtx.Q(), "192.0.2.92", time.Hour)
	const restoredCount = uint64(12)
	runtimeDump := encodeLegacyDumpEntry(t, &CachedEntry{
		Key: []byte(k), Msg: replacement.item.resp,
		CacheExpirationTime: replacement.cacheExpiration.Unix(),
		MsgExpirationTime:   replacement.item.expirationTime.Unix(),
		MsgStoredTime:       replacement.item.storedTime.Unix(),
		LastRealAccessTime:  now.Unix(),
		ActiveRefreshState: &ActiveRefreshState{
			Version: activeRefreshDumpStateVersion, Tracked: true,
			RealAccessCount: restoredCount, AdmissionWindowStartUnix: now.Unix(), AdmissionHits: 1,
			Heat: float64(restoredCount), HeatAtUnixNano: now.UnixNano(),
		},
	})

	// Stop clearRuntimeViews after readDump has replaced the backend but before
	// it can publish the matching pending/active popularity view. readDump keeps
	// flushMu write-locked throughout this deliberately torn internal window.
	c.activeMu.Lock()
	activeLocked := true
	defer func() {
		if activeLocked {
			c.activeMu.Unlock()
		}
	}()
	type ioResult struct {
		n   int
		err error
	}
	loadResult := make(chan ioResult, 1)
	go func() {
		n, err := c.readDump(bytes.NewReader(runtimeDump))
		loadResult <- ioResult{n: n, err: err}
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		current, _, present := c.backend.Get(k)
		if present && current != old.item {
			break
		}
		select {
		case got := <-loadResult:
			t.Fatalf("runtime load completed before reaching the controlled transition: entries=%d err=%v", got.n, got.err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("runtime load did not publish its backend generation")
		}
		time.Sleep(time.Millisecond)
	}

	var concurrentDump bytes.Buffer
	dumpStarted := make(chan struct{})
	dumpResult := make(chan ioResult, 1)
	go func() {
		close(dumpStarted)
		n, err := c.writeDump(&concurrentDump)
		dumpResult <- ioResult{n: n, err: err}
	}()
	<-dumpStarted
	select {
	case got := <-dumpResult:
		t.Fatalf("dump crossed the runtime-load transition instead of waiting for flushMu: entries=%d err=%v", got.n, got.err)
	case <-time.After(20 * time.Millisecond):
	}

	c.activeMu.Unlock()
	activeLocked = false
	select {
	case got := <-loadResult:
		if got.err != nil || got.n != 1 {
			t.Fatalf("runtime load: entries=%d err=%v", got.n, got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runtime load did not finish after releasing activeMu")
	}
	select {
	case got := <-dumpResult:
		if got.err != nil || got.n != 1 {
			t.Fatalf("concurrent dump: entries=%d err=%v", got.n, got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dump did not finish after the runtime load committed")
	}
	assertCoherentTrackedRuntimeLoadDump(t, c, concurrentDump.Bytes(), k, replacement.item.resp, restoredCount)

	// Flush/close callers already own flushMu for writing. The explicit true
	// contract must bypass a second read-lock acquisition while preserving the
	// same coherent backend/popularity snapshot.
	var flushHeldDump bytes.Buffer
	c.flushMu.Lock()
	heldResult := make(chan ioResult, 1)
	go func() {
		n, err := c.writeDumpInternal(&flushHeldDump, true)
		heldResult <- ioResult{n: n, err: err}
	}()
	select {
	case got := <-heldResult:
		c.flushMu.Unlock()
		if got.err != nil || got.n != 1 {
			t.Fatalf("flush-held dump: entries=%d err=%v", got.n, got.err)
		}
	case <-time.After(time.Second):
		c.flushMu.Unlock()
		select {
		case <-heldResult:
		case <-time.After(time.Second):
		}
		t.Fatal("writeDumpInternal(flushLocked=true) deadlocked while flushMu was held")
	}
	assertCoherentTrackedRuntimeLoadDump(t, c, flushHeldDump.Bytes(), k, replacement.item.resp, restoredCount)
}
