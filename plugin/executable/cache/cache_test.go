/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package cache

import (
	"bytes"
	"context"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

func newTestQuery(name string, qtype, qclass uint16, recursionDesired bool) *query_context.Context {
	q := new(dns.Msg)
	q.SetQuestion(name, qtype)
	q.Question[0].Qclass = qclass
	q.RecursionDesired = recursionDesired
	return query_context.NewContext(q)
}

func testCacheKey(t *testing.T, qCtx *query_context.Context) key {
	t.Helper()
	b, bp := getMsgKeyBytes(qCtx.Q(), qCtx, false)
	if b == nil || bp == nil {
		t.Fatal("msg key is nil")
	}
	k := key(string(b))
	keyBufferPool.Put(bp)
	return k
}

func testAResponse(t *testing.T, q *dns.Msg, address string, ttl uint32) *dns.Msg {
	t.Helper()
	ip := net.ParseIP(address).To4()
	if ip == nil {
		t.Fatalf("invalid test IPv4 address %q", address)
	}
	r := new(dns.Msg)
	r.SetReply(q)
	r.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{
			Name:   q.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  q.Question[0].Qclass,
			Ttl:    ttl,
		},
		A: ip,
	}}
	return r
}

func testPreparedA(t *testing.T, q *dns.Msg, address string, ttl time.Duration) *preparedCacheEntry {
	t.Helper()
	seconds := uint32(ttl / time.Second)
	r := testAResponse(t, q, address, seconds)
	packed, err := r.Pack()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	expires := now.Add(ttl)
	v := &item{resp: packed, storedTime: now, expirationTime: expires}
	return &preparedCacheEntry{item: v, cacheExpiration: expires, msg: r}
}

func testNegativeResponse(q *dns.Msg, rcode int, soaTTL, minimumTTL uint32) *dns.Msg {
	r := new(dns.Msg)
	r.SetReply(q)
	r.Rcode = rcode
	r.Ns = []dns.RR{&dns.SOA{
		Hdr: dns.RR_Header{
			Name:   q.Question[0].Name,
			Rrtype: dns.TypeSOA,
			Class:  q.Question[0].Qclass,
			Ttl:    soaTTL,
		},
		Ns:      "ns1.example.",
		Mbox:    "hostmaster.example.",
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  minimumTTL,
	}}
	return r
}

func newCacheForTest(t *testing.T, args *Args, opts Opts) *Cache {
	t.Helper()
	c, err := NewCacheWithError(args, opts)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func cloneItemForTest(src *item) *item {
	dst := &item{
		generation: src.generation, staleSourceGeneration: src.staleSourceGeneration,
		resp:       append([]byte(nil), src.resp...),
		storedTime: src.storedTime, expirationTime: src.expirationTime,
		lazyDeadline: src.lazyDeadline, domainSet: src.domainSet,
		upstreamOpt: copyOPT(src.upstreamOpt), staleDeadline: src.staleDeadline,
		isStale: src.isStale, isTransient: src.isTransient,
	}
	dst.lastRealAccess.Store(src.lastRealAccess.Load())
	dst.refreshSuccess.Store(src.refreshSuccess.Load())
	return dst
}

func Test_cachePlugin_Dump(t *testing.T) {
	c := newCacheForTest(t, &Args{Size: 16 * dumpBlockSize}, Opts{}) // Big enough to create dump fragments.
	defer c.Close()

	resp := new(dns.Msg)
	resp.SetQuestion("test.", dns.TypeA)

	// Fix: Pack the dns.Msg to []byte because item.resp is now []byte
	packedResp, err := resp.Pack()
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	hourLater := now.Add(time.Hour)
	v := &item{
		resp:           packedResp,
		storedTime:     now,
		expirationTime: hourLater,
	}

	// Fill the cache
	for i := 0; i < 32*dumpBlockSize; i++ {
		qCtx := newTestQuery(strconv.Itoa(i)+".dump.test.", dns.TypeA, dns.ClassINET, true)
		c.backend.Store(testCacheKey(t, qCtx), v, hourLater)
	}

	buf := new(bytes.Buffer)
	enw, err := c.writeDump(buf)
	if err != nil {
		t.Fatal(err)
	}
	enr, err := c.readDump(buf)
	if err != nil {
		t.Fatal(err)
	}

	if enw == 0 {
		t.Fatal("dump unexpectedly contained no entries")
	}
	if enw != enr {
		t.Fatalf("read err, wrote %d entries, read %d", enw, enr)
	}
}

func TestActiveRefreshArgs_WeakDecode(t *testing.T) {
	raw := map[string]any{
		"size":       1024,
		"exclude_ip": []any{"203.0.113.0/24"},
		"active_refresh": map[string]any{
			"enabled":             true,
			"restore_on_startup":  true,
			"threshold":           60,
			"requery_timeout_ms":  1000,
			"workers":             16,
			"max_refresh_qps":     30,
			"refresh_burst":       60,
			"max_tasks_per_batch": 256,
			"max_pending_tasks":   2048,
			"max_retry_times":     0,
			"max_refresh_times":   0,
			"max_idle_time":       3600,
			"exclude_ip": map[string]any{
				"cidrs":   []any{"198.18.0.0/15"},
				"ip_sets": []any{"geoip:cloudflare"},
				"files":   []any{"no-active-refresh-ip.txt"},
			},
			"exclude_domain": map[string]any{
				"exps":  []any{"domain:fakeip.local"},
				"files": []any{"/tmp/no_active_refresh.txt"},
			},
			"fallback_probe": map[string]any{
				"enabled":          true,
				"timeout_ms":       60,
				"stale_extend_ttl": 60,
				"max_stale":        300,
				"probes":           []any{"tcp:443", "tcp:8443", "ping"},
			},
		},
	}
	var args Args
	if err := utils.WeakDecode(raw, &args); err != nil {
		t.Fatal(err)
	}
	args.init()

	if len(args.ExcludeIPs) != 1 || args.ExcludeIPs[0] != "203.0.113.0/24" {
		t.Fatalf("top-level exclude ip mismatch: %#v", args.ExcludeIPs)
	}
	ar := args.ActiveRefresh
	if !ar.Enabled {
		t.Fatal("active refresh should be enabled")
	}
	if !ar.RestoreOnStartup {
		t.Fatal("restore on startup should be enabled")
	}
	if ar.RequeryTimeoutMS != 1000 || ar.MaxRefreshQPS != 30 || ar.RefreshBurst != 60 {
		t.Fatalf("active limits mismatch: %#v", ar)
	}
	if ar.MaxRetryTimes != 0 || ar.MaxRefreshTimes != 0 {
		t.Fatalf("retry/refresh limits = %d/%d, want 0/0", ar.MaxRetryTimes, ar.MaxRefreshTimes)
	}
	exclude, err := normalizeActiveRefreshExcludeIP(ar.ExcludeIP)
	if err != nil {
		t.Fatal(err)
	}
	if len(exclude.CIDRs) != 1 || len(exclude.IPSets) != 1 || len(exclude.Files) != 1 {
		t.Fatalf("exclude ip mismatch: %#v", exclude)
	}
	if len(ar.ExcludeDomain.Exps) != 1 || ar.ExcludeDomain.Exps[0] != "domain:fakeip.local" {
		t.Fatalf("exclude domain exps mismatch: %#v", ar.ExcludeDomain.Exps)
	}
	if !ar.FallbackProbe.Enabled || ar.FallbackProbe.TimeoutMS != 60 {
		t.Fatalf("fallback probe mismatch: %#v", ar.FallbackProbe)
	}
	if ar.FallbackProbe.MaxStale != 300 {
		t.Fatalf("fallback max stale = %d, want 300", ar.FallbackProbe.MaxStale)
	}
	if len(ar.FallbackProbe.Probes) != 3 {
		t.Fatalf("probe count mismatch: %#v", ar.FallbackProbe.Probes)
	}
	if got := ar.FallbackProbe.Probes[1]; got != "tcp:8443" {
		t.Fatalf("probe order mismatch, got %s", got)
	}

	for field, want := range removedActiveRefreshFields {
		t.Run("removed_"+field, func(t *testing.T) {
			invalid := map[string]any{"active_refresh": map[string]any{field: 1}}
			var decoded Args
			err := utils.WeakDecode(invalid, &decoded)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("error = %v, want %q", err, want)
			}
		})
	}
}

func TestTopLevelExcludeDomainSkipsCacheWrite(t *testing.T) {
	c, err := NewCacheWithError(&Args{
		ExcludeDomain: ActiveRefreshDomainArgs{
			Exps: []string{"domain:fakeip.example"},
		},
	}, Opts{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	excluded := newTestQuery("www.fakeip.example.", dns.TypeA, dns.ClassINET, true)
	excludedResponse := new(dns.Msg)
	excludedResponse.SetReply(excluded.Q())
	excludedResponse.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "www.fakeip.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("203.0.113.10").To4(),
	}}
	excluded.SetResponse(excludedResponse)
	if prepared, ok := c.prepareCacheEntry(excluded, false); ok || prepared != nil {
		t.Fatal("domain excluded response was prepared for cache")
	}

	allowed := newTestQuery("allowed.example.", dns.TypeA, dns.ClassINET, true)
	allowedResponse := new(dns.Msg)
	allowedResponse.SetReply(allowed.Q())
	allowedResponse.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "allowed.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("203.0.113.11").To4(),
	}}
	allowed.SetResponse(allowedResponse)
	if prepared, ok := c.prepareCacheEntry(allowed, false); !ok || prepared == nil {
		t.Fatal("non-excluded response was not prepared for cache")
	}
}

func TestActiveRefreshArgsRejectNonPositiveLimits(t *testing.T) {
	for _, field := range []string{
		"workers", "max_refresh_qps", "refresh_burst", "max_tasks_per_batch", "max_pending_tasks",
	} {
		t.Run(field, func(t *testing.T) {
			var args Args
			err := utils.WeakDecode(map[string]any{
				"active_refresh": map[string]any{field: 0},
			}, &args)
			if err == nil || !strings.Contains(err.Error(), "active_refresh."+field+" must be greater than 0") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestActiveRefreshMaxIdleTimeExplicitZeroMeansUnlimited(t *testing.T) {
	t.Run("weak_decode", func(t *testing.T) {
		var args Args
		if err := utils.WeakDecode(map[string]any{
			"active_refresh": map[string]any{"max_idle_time": 0},
		}, &args); err != nil {
			t.Fatal(err)
		}
		args.init()
		if args.ActiveRefresh.MaxIdleTime != 0 {
			t.Fatalf("max idle time = %d, want unlimited (0)", args.ActiveRefresh.MaxIdleTime)
		}
	})

	t.Run("direct_yaml", func(t *testing.T) {
		var args Args
		if err := yaml.Unmarshal([]byte("active_refresh:\n  max_idle_time: 0\n"), &args); err != nil {
			t.Fatal(err)
		}
		args.init()
		if args.ActiveRefresh.MaxIdleTime != 0 {
			t.Fatalf("max idle time = %d, want unlimited (0)", args.ActiveRefresh.MaxIdleTime)
		}
	})

	t.Run("omitted_uses_default", func(t *testing.T) {
		var args Args
		if err := yaml.Unmarshal([]byte("active_refresh:\n  enabled: true\n"), &args); err != nil {
			t.Fatal(err)
		}
		args.init()
		if args.ActiveRefresh.MaxIdleTime != defaultActiveRefreshMaxIdleTime {
			t.Fatalf("max idle time = %d, want default %d", args.ActiveRefresh.MaxIdleTime, defaultActiveRefreshMaxIdleTime)
		}
	})
}

func TestActiveRefreshArgsRejectInvalidValuesAcrossDecodePaths(t *testing.T) {
	t.Run("weak_decode_non_finite_qps", func(t *testing.T) {
		var args Args
		err := utils.WeakDecode(map[string]any{
			"active_refresh": map[string]any{"max_refresh_qps": math.NaN()},
		}, &args)
		if err == nil || !strings.Contains(err.Error(), "must be a finite number") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("direct_yaml_explicit_zero", func(t *testing.T) {
		var args Args
		err := yaml.Unmarshal([]byte("active_refresh:\n  workers: 0\n"), &args)
		if err == nil || !strings.Contains(err.Error(), "active_refresh.workers must be greater than 0") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("programmatic_negative_before_defaults", func(t *testing.T) {
		_, err := NewCacheWithError(&Args{ActiveRefresh: ActiveRefreshArgs{Workers: -1}}, Opts{})
		if err == nil || !strings.Contains(err.Error(), "active_refresh.workers") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("programmatic_infinite_qps", func(t *testing.T) {
		_, err := NewCacheWithError(&Args{ActiveRefresh: ActiveRefreshArgs{MaxRefreshQPS: math.Inf(1)}}, Opts{})
		if err == nil || !strings.Contains(err.Error(), "active_refresh.max_refresh_qps must be finite") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestActiveRefreshArgsWeakDecodeLegacyExcludeIPList(t *testing.T) {
	var args Args
	if err := utils.WeakDecode(map[string]any{
		"active_refresh": map[string]any{
			"enabled":    true,
			"exclude_ip": []any{"198.18.0.0/15", "2001:db8::/32"},
		},
	}, &args); err != nil {
		t.Fatal(err)
	}
	normalized, err := normalizeActiveRefreshExcludeIP(args.ActiveRefresh.ExcludeIP)
	if err != nil {
		t.Fatal(err)
	}
	if len(normalized.CIDRs) != 2 || normalized.CIDRs[0] != "198.18.0.0/15" || normalized.CIDRs[1] != "2001:db8::/32" {
		t.Fatalf("legacy exclude_ip = %#v", normalized.CIDRs)
	}
}

func TestActiveRefresh_LowTTLScheduledBeforeExpiration(t *testing.T) {
	c := newCacheForTest(t, &Args{
		ActiveRefresh: ActiveRefreshArgs{Threshold: 60},
	}, Opts{})
	defer c.Close()

	stored := time.Unix(1700000000, 0)
	for _, tc := range []struct {
		ttl       time.Duration
		window    time.Duration
		refreshIn time.Duration
	}{
		{30 * time.Second, 10 * time.Second, 20 * time.Second},
		{60 * time.Second, 20 * time.Second, 40 * time.Second},
		{90 * time.Second, 30 * time.Second, 60 * time.Second},
		{300 * time.Second, 60 * time.Second, 240 * time.Second},
	} {
		t.Run(tc.ttl.String(), func(t *testing.T) {
			window, ok := calculateRefreshWindow(tc.ttl, 60*time.Second)
			if !ok || window != tc.window {
				t.Fatalf("window = %s, %v; want %s", window, ok, tc.window)
			}
			v := &item{storedTime: stored, expirationTime: stored.Add(tc.ttl)}
			due := c.activeRefreshAt(key("ttl-"+tc.ttl.String()), v)
			if got := due.Sub(stored); got != tc.refreshIn {
				t.Fatalf("refresh in %s, want %s", got, tc.refreshIn)
			}
		})
	}
	for _, ttl := range []time.Duration{time.Second, 3 * time.Second, 5 * time.Second} {
		t.Run("short_"+ttl.String(), func(t *testing.T) {
			v := &item{storedTime: stored, expirationTime: stored.Add(ttl)}
			due := c.activeRefreshAt(key("low-ttl-"+ttl.String()), v)
			if !due.After(v.storedTime) {
				t.Fatalf("refresh due %s is not after stored time %s", due, v.storedTime)
			}
			if !due.Before(v.expirationTime) {
				t.Fatalf("refresh due %s is not before expiration %s", due, v.expirationTime)
			}
		})
	}

	v := &item{storedTime: stored, expirationTime: stored.Add(30 * time.Second)}
	if c.needsActiveRefresh(v, stored.Add(19*time.Second)) {
		t.Fatal("30s original ttl should not refresh with 11s remaining")
	}
	if !c.needsActiveRefresh(v, stored.Add(20*time.Second)) {
		t.Fatal("30s original ttl should refresh with 10s remaining")
	}
}

func TestActiveRefresh_MaxRefreshTimesCountsSuccesses(t *testing.T) {
	args := &Args{
		ActiveRefresh: ActiveRefreshArgs{
			Enabled:         true,
			Threshold:       60,
			MaxRefreshTimes: 1,
		},
	}
	c := newCacheForTest(t, args, Opts{})
	defer c.Close()

	qCtx := newTestQuery("example.com.", dns.TypeA, dns.ClassINET, true)
	k := testCacheKey(t, qCtx)
	prepared := testPreparedA(t, qCtx.Q(), "192.0.2.1", time.Hour)
	if !c.commitPrepared(k, nil, 0, prepared) {
		t.Fatal("failed to seed cache")
	}
	now := time.Now()
	c.trackActiveRefresh(k, prepared.item, qCtx.CopyWithoutResponse(), sequence.ChainWalker{}, now, prepared.msg)

	c.activeMu.RLock()
	meta := c.activeMeta[k]
	c.activeMu.RUnlock()
	if meta == nil {
		t.Fatal("active refresh metadata was not tracked")
	}
	prepared.item.refreshSuccess.Store(1)
	meta.stopped.Store(true)

	c.observeActiveRefresh(k, prepared.item, qCtx, sequence.ChainWalker{}, now.Add(time.Second), prepared.msg)
	c.activeMu.RLock()
	refreshCount := prepared.item.refreshSuccess.Load()
	stopped := meta.stopped.Load()
	task := meta.task
	c.activeMu.RUnlock()
	if refreshCount != 0 || stopped || task == nil || task.scheduleIndex < 0 {
		t.Fatalf("access reset count=%d stopped=%v task=%#v", refreshCount, stopped, task)
	}
}

func TestActiveRefresh_TransientResponseDoesNotReplaceHealthyEntry(t *testing.T) {
	c := newCacheForTest(t, &Args{
		Size: shardCount,
		ActiveRefresh: ActiveRefreshArgs{
			Enabled: true,
			Workers: 1,
		},
	}, Opts{})
	defer c.Close()

	for _, tc := range []struct {
		name  string
		rcode int
	}{
		{name: "SERVFAIL", rcode: dns.RcodeServerFailure},
		{name: "REFUSED", rcode: dns.RcodeRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			qCtx := newTestQuery(tc.name+".example.", dns.TypeA, dns.ClassINET, true)
			k := testCacheKey(t, qCtx)
			healthy := testPreparedA(t, qCtx.Q(), "192.0.2.10", time.Minute)
			if !c.commitPrepared(k, nil, 0, healthy) {
				t.Fatal("failed to seed healthy cache entry")
			}

			transient := new(dns.Msg)
			transient.SetReply(qCtx.Q())
			transient.Rcode = tc.rcode
			qCtx.SetResponse(transient)
			epoch := c.refreshEpoch.Load()
			flight := refreshFlightKey{k: k, generation: healthy.item.generation}
			task := &refreshTask{
				key: k, expireAt: healthy.item.expirationTime,
				refreshWindow: 20 * time.Second, generation: healthy.item.generation,
			}
			c.runActiveRefreshTask(&activeRefreshWork{
				task: task, qCtx: qCtx, next: sequence.ChainWalker{},
				expected: healthy.item, epoch: epoch, flight: flight,
			})

			got, _, ok := c.backend.Get(k)
			if !ok {
				t.Fatal("healthy cache entry disappeared")
			}
			if got != healthy.item {
				t.Fatalf("%s response replaced the healthy cache entry", tc.name)
			}
			shard := c.shards[k.Sum()%shardCount]
			shard.RLock()
			l1 := shard.items[k]
			shard.RUnlock()
			if l1 == nil || l1.source != healthy.item {
				t.Fatalf("%s response replaced the healthy L1 entry", tc.name)
			}
		})
	}
}

func TestCommitPreparedRejectsStaleExpectedAndFlushEpoch(t *testing.T) {
	c := newCacheForTest(t, &Args{Size: 16}, Opts{})
	defer c.Close()

	qCtx := newTestQuery("commit.example.", dns.TypeA, dns.ClassINET, true)
	k := testCacheKey(t, qCtx)
	old := testPreparedA(t, qCtx.Q(), "192.0.2.1", time.Hour)
	current := testPreparedA(t, qCtx.Q(), "192.0.2.2", time.Hour)
	stale := testPreparedA(t, qCtx.Q(), "192.0.2.3", time.Hour)
	epoch := c.refreshEpoch.Load()

	if !c.commitPrepared(k, nil, 0, old) {
		t.Fatal("failed to seed old entry")
	}
	if !c.commitPrepared(k, old.item, epoch, current) {
		t.Fatal("failed to install newer entry")
	}
	if c.commitPrepared(k, old.item, epoch, stale) {
		t.Fatal("stale expected pointer overwrote a newer entry")
	}
	if got, _, ok := c.backend.Get(k); !ok || got != current.item {
		t.Fatal("newer entry was not preserved after stale conditional commit")
	}

	staleEpoch := c.refreshEpoch.Load()
	rr := httptest.NewRecorder()
	c.Api().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/flush", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("flush status = %d, want %d", rr.Code, http.StatusOK)
	}
	if c.refreshEpoch.Load() == staleEpoch {
		t.Fatal("flush did not advance the refresh epoch")
	}

	// Reinsert the exact expected pointer. Without the epoch guard, the stale
	// task would now pass the pointer comparison and repopulate flushed data.
	c.backend.Store(k, current.item, current.cacheExpiration)
	if c.commitPrepared(k, current.item, staleEpoch, stale) {
		t.Fatal("task from before flush repopulated the cache")
	}
	if got, _, ok := c.backend.Get(k); !ok || got != current.item {
		t.Fatal("stale epoch changed the restored current entry")
	}
}

func TestForegroundMissCannotOverwriteRetainedOrNewerEntry(t *testing.T) {
	c := newCacheForTest(t, &Args{Size: 16}, Opts{})
	defer c.Close()

	qCtx := newTestQuery("foreground-race.example.", dns.TypeA, dns.ClassINET, true)
	k := testCacheKey(t, qCtx)
	retained := testPreparedA(t, qCtx.Q(), "192.0.2.1", time.Hour)
	retained.item.expirationTime = time.Now().Add(-time.Second)
	c.backend.Store(k, retained.item, time.Now().Add(time.Hour))

	resp, lazy, observed := getRespFromCache(string(k), c.backend, false, expiredMsgTtl)
	if resp != nil || lazy || observed != retained.item {
		t.Fatalf("retained lookup = (%v, %v, %p), want (nil, false, %p)", resp, lazy, observed, retained.item)
	}
	transientCtx := qCtx.CopyWithoutResponse()
	transient := new(dns.Msg)
	transient.SetRcode(qCtx.Q(), dns.RcodeServerFailure)
	transientCtx.SetResponse(transient)
	if prepared, ok := c.prepareCacheEntry(transientCtx, observed == nil); ok || prepared != nil {
		t.Fatal("SERVFAIL was allowed to replace a privately retained healthy entry")
	}

	epoch := c.refreshEpoch.Load()
	newer := testPreparedA(t, qCtx.Q(), "192.0.2.2", time.Hour)
	if !c.commitPrepared(k, retained.item, epoch, newer) {
		t.Fatal("failed to simulate a newer active refresh")
	}
	slowForeground := testPreparedA(t, qCtx.Q(), "192.0.2.3", time.Hour)
	if c.commitPreparedForeground(k, observed, epoch, slowForeground) {
		t.Fatal("slow foreground miss overwrote a newer active refresh")
	}
	if got, _, ok := c.backend.Get(k); !ok || got != newer.item {
		t.Fatal("newer active refresh was not preserved")
	}

	// The absent case is conditional too: another foreground winner must not
	// be overwritten by a slower request that observed the cache as empty.
	c.backend.Flush()
	absentEpoch := c.refreshEpoch.Load()
	winner := testPreparedA(t, qCtx.Q(), "198.51.100.1", time.Hour)
	if !c.commitPrepared(k, nil, 0, winner) {
		t.Fatal("failed to install concurrent foreground winner")
	}
	if c.commitPreparedForeground(k, nil, absentEpoch, slowForeground) {
		t.Fatal("slow absent miss overwrote a concurrent foreground winner")
	}
	if got, _, ok := c.backend.Get(k); !ok || got != winner.item {
		t.Fatal("concurrent foreground winner was not preserved")
	}

	// A healthy result may heal a SERVFAIL that won an absent race, while the
	// inverse direction remains forbidden.
	c.backend.Flush()
	transientPrepared, ok := c.prepareCacheEntry(transientCtx, true)
	if !ok || !transientPrepared.item.isTransient || !transientPrepared.item.staleDeadline.IsZero() {
		t.Fatal("SERVFAIL was not prepared as a short-lived non-fallback entry")
	}
	healEpoch := c.refreshEpoch.Load()
	if !c.commitPreparedForeground(k, nil, healEpoch, transientPrepared) {
		t.Fatal("failed to install initial transient miss result")
	}
	transientDump := new(bytes.Buffer)
	if entries, err := c.writeDump(transientDump); err != nil || entries != 0 {
		t.Fatalf("transient dump entries=%d err=%v, want 0", entries, err)
	}
	healthy := testPreparedA(t, qCtx.Q(), "203.0.113.1", time.Hour)
	if !c.commitPreparedForeground(k, nil, healEpoch, healthy) {
		t.Fatal("healthy foreground result did not replace transient winner")
	}
	if got, _, ok := c.backend.Get(k); !ok || got != healthy.item {
		t.Fatal("healthy foreground result did not heal transient cache")
	}

	staleEpoch := c.refreshEpoch.Load()
	rr := httptest.NewRecorder()
	c.Api().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/flush", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("flush status = %d", rr.Code)
	}
	if c.commitPreparedForeground(k, nil, staleEpoch, slowForeground) {
		t.Fatal("foreground request from before flush repopulated the cache")
	}
	if _, _, ok := c.backend.Get(k); ok {
		t.Fatal("cache is not empty after rejecting pre-flush foreground commit")
	}
}

func TestHealthyForegroundAnswerReplacesProbeStaleDerivative(t *testing.T) {
	c := newCacheForTest(t, &Args{Size: 16, ActiveRefresh: ActiveRefreshArgs{
		FallbackProbe: FallbackProbeArgs{Enabled: true, StaleExtendTTL: 60, MaxStale: 300},
	}}, Opts{})
	defer c.Close()

	qCtx := newTestQuery("foreground-wins-probe.example.", dns.TypeA, dns.ClassINET, true)
	k := testCacheKey(t, qCtx)
	old := testPreparedA(t, qCtx.Q(), "192.0.2.1", time.Minute)
	old.item.staleDeadline = old.item.expirationTime.Add(5 * time.Minute)
	old.cacheExpiration = old.item.staleDeadline
	if !c.commitPrepared(k, nil, 0, old) {
		t.Fatal("failed to seed retained answer")
	}

	stale, ok := c.prepareStaleEntry(old.item, old.msg, time.Now())
	if !ok || !c.commitPrepared(k, old.item, c.refreshEpoch.Load(), stale) {
		t.Fatal("failed to install probe-stale derivative")
	}
	if !stale.item.isStale || stale.item.staleSourceGeneration != old.item.generation {
		t.Fatalf("stale lineage = %#v", stale.item)
	}

	fresh := testPreparedA(t, qCtx.Q(), "192.0.2.99", 2*time.Minute)
	if !c.commitPreparedForeground(k, old.item, c.refreshEpoch.Load(), fresh) {
		t.Fatal("healthy foreground response lost to probe-stale derivative")
	}
	current, _, present := c.backend.Get(k)
	if !present || current != fresh.item || current.isStale {
		t.Fatalf("current = %#v, want fresh foreground item", current)
	}
}

func TestL2PromotionCannotRestoreStaleL1(t *testing.T) {
	c := newCacheForTest(t, &Args{Size: shardCount}, Opts{})
	defer c.Close()

	qCtx := newTestQuery("promotion-race.example.", dns.TypeA, dns.ClassINET, true)
	k := testCacheKey(t, qCtx)
	old := testPreparedA(t, qCtx.Q(), "192.0.2.1", time.Hour)
	if !c.commitPrepared(k, nil, 0, old) {
		t.Fatal("failed to seed old entry")
	}
	epoch := c.refreshEpoch.Load()
	oldMsg, lazy, observed := getRespFromCache(string(k), c.backend, false, expiredMsgTtl)
	if oldMsg == nil || lazy || observed != old.item {
		t.Fatal("failed to observe old L2 entry")
	}
	shard := c.shards[k.Sum()%shardCount]
	shard.Lock()
	delete(shard.items, k)
	shard.Unlock()
	if !c.promoteL1IfCurrent(k, old.item, epoch, oldMsg) {
		t.Fatal("current L2 entry was not promoted")
	}
	oldMsg.Answer[0].Header().Ttl = 1
	shard.RLock()
	promoted := shard.items[k]
	shard.RUnlock()
	if promoted == nil || promoted.msg.Answer[0].Header().Ttl == 1 {
		t.Fatal("L1 shares its message object with the client response")
	}

	newer := testPreparedA(t, qCtx.Q(), "192.0.2.2", time.Hour)
	if !c.commitPrepared(k, old.item, epoch, newer) {
		t.Fatal("failed to install newer entry")
	}
	if c.promoteL1IfCurrent(k, old.item, epoch, oldMsg) {
		t.Fatal("stale L2 observation was promoted after a newer commit")
	}
	shard.RLock()
	l1 := shard.items[k]
	shard.RUnlock()
	if l1 == nil || l1.source != newer.item {
		t.Fatal("stale L2 promotion replaced the newer L1 entry")
	}

	rr := httptest.NewRecorder()
	c.Api().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/flush", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("flush status = %d", rr.Code)
	}
	if c.promoteL1IfCurrent(k, old.item, epoch, oldMsg) {
		t.Fatal("pre-flush L2 observation was promoted after flush")
	}
	shard.RLock()
	_, present := shard.items[k]
	shard.RUnlock()
	if present {
		t.Fatal("pre-flush L2 observation repopulated L1")
	}
}

func TestLazyRefreshMarkerAndEpochFastReject(t *testing.T) {
	c := newCacheForTest(t, &Args{Size: 16}, Opts{})
	defer c.Close()

	qCtx := newTestQuery("lazy-marker.example.", dns.TypeA, dns.ClassINET, true)
	k := testCacheKey(t, qCtx)
	seeded := testPreparedA(t, qCtx.Q(), "192.0.2.1", time.Hour)
	if !c.commitPrepared(k, nil, 0, seeded) {
		t.Fatal("failed to seed cache")
	}

	epoch := c.refreshEpoch.Load()
	currentCtx := qCtx.CopyWithoutResponse()
	currentTrace, currentID, currentStart := currentCtx.TraceID, currentCtx.Id(), currentCtx.StartTime()
	c.runLazyUpdateTask(&lazyTask{
		k: k, qCtx: currentCtx, expected: seeded.item, epoch: epoch,
		flight: refreshFlightKey{k: k, generation: seeded.item.generation},
	})
	if !currentCtx.IsCacheRefresh() {
		t.Fatal("lazy refresh replay was not marked as internal")
	}
	if currentCtx.TraceID == currentTrace || currentCtx.Id() == currentID || !currentCtx.StartTime().After(currentStart) {
		t.Fatal("lazy refresh replay retained the client query identity")
	}
	activeCtx := qCtx.CopyWithoutResponse()
	activeTrace, activeID, activeStart := activeCtx.TraceID, activeCtx.Id(), activeCtx.StartTime()
	c.runActiveRefreshTask(&activeRefreshWork{
		task: &refreshTask{
			key: k, expireAt: seeded.item.expirationTime,
			refreshWindow: 20 * time.Second, generation: seeded.item.generation,
		},
		qCtx: activeCtx, expected: seeded.item, epoch: epoch,
		flight: refreshFlightKey{k: k, generation: seeded.item.generation},
	})
	if !activeCtx.IsCacheRefresh() {
		t.Fatal("active refresh replay was not marked as internal")
	}
	if activeCtx.TraceID == activeTrace || activeCtx.Id() == activeID || !activeCtx.StartTime().After(activeStart) {
		t.Fatal("active refresh replay retained the client query identity")
	}

	staleCtx := qCtx.CopyWithoutResponse()
	c.refreshEpoch.Add(1)
	c.runLazyUpdateTask(&lazyTask{
		k: k, qCtx: staleCtx, expected: seeded.item, epoch: epoch,
		flight: refreshFlightKey{k: k, generation: seeded.item.generation},
	})
	if staleCtx.IsCacheRefresh() {
		t.Fatal("stale-epoch lazy task reached sequence execution")
	}
}

func TestLazyRefreshReservesQueueBeforeContextCopy(t *testing.T) {
	c := newCacheForTest(t, &Args{Size: 16, LazyCacheTTL: 3600}, Opts{})
	defer c.Close()
	qCtx := newTestQuery("lazy-permit.example.", dns.TypeA, dns.ClassINET, true)
	k := testCacheKey(t, qCtx)
	prepared := testPreparedA(t, qCtx.Q(), "192.0.2.1", time.Minute)
	if !c.commitPrepared(k, nil, 0, prepared) {
		t.Fatal("failed to seed lazy cache entry")
	}

	for i := 0; i < cap(c.lazyQueueSlots); i++ {
		c.lazyQueueSlots <- struct{}{}
	}
	before := counterValue(t, c.lazyDropTotal)
	c.doLazyUpdate(k, prepared.item, qCtx, sequence.ChainWalker{})
	if got := counterValue(t, c.lazyDropTotal); got != before+1 {
		t.Fatalf("lazy drops = %v, want %v", got, before+1)
	}
	if len(c.lazyTaskChan) != 0 {
		t.Fatalf("lazy task was built and queued without a permit: %d", len(c.lazyTaskChan))
	}
	flight := refreshFlightKey{k: k, generation: prepared.item.generation}
	if _, retained := c.refreshInFlight.Load(flight); retained {
		t.Fatal("queue rejection retained the lazy inflight claim")
	}
	for i := 0; i < cap(c.lazyQueueSlots); i++ {
		<-c.lazyQueueSlots
	}
}

func TestLazyRefreshMissingBackendRemovesPinnedActiveMetadata(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16, LazyCacheTTL: 3600}, Opts{})
	defer c.Close()
	qCtx := newTestQuery("lazy-missing-active.example.", dns.TypeA, dns.ClassINET, true)
	k := testCacheKey(t, qCtx)
	prepared := testPreparedA(t, qCtx.Q(), "192.0.2.1", time.Minute)
	if !c.commitPrepared(k, nil, 0, prepared) {
		t.Fatal("failed to seed lazy cache entry")
	}
	c.trackActiveRefresh(k, prepared.item, qCtx, sequence.ChainWalker{}, time.Now(), prepared.msg)
	flight := refreshFlightKey{k: k, generation: prepared.item.generation}
	c.refreshInFlight.Store(flight, struct{}{})
	c.backend.Flush()
	c.runLazyUpdateTask(&lazyTask{
		k: k, qCtx: qCtx.CopyWithoutResponse(), expected: prepared.item,
		epoch: c.refreshEpoch.Load(), flight: flight,
	})
	c.activeMu.RLock()
	_, tracked := c.activeMeta[k]
	c.activeMu.RUnlock()
	if tracked {
		t.Fatal("lazy owner left active metadata pinned after backend removal")
	}
	assertActiveEvictionInvariant(t, c)
}

func TestLazyRefreshFinalizerCleansBackendRemovedDuringExecution(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16, LazyCacheTTL: 3600}, Opts{})
	defer c.Close()
	qCtx := newTestQuery("lazy-finalizer-active.example.", dns.TypeA, dns.ClassINET, true)
	k := testCacheKey(t, qCtx)
	prepared := testPreparedA(t, qCtx.Q(), "192.0.2.1", time.Minute)
	if !c.commitPrepared(k, nil, 0, prepared) {
		t.Fatal("failed to seed lazy cache entry")
	}
	c.trackActiveRefresh(k, prepared.item, qCtx, sequence.ChainWalker{}, time.Now(), prepared.msg)
	if current, _, present := c.backend.Get(k); !present || current != prepared.item {
		t.Fatal("lazy preflight did not observe the expected backend item")
	}
	flight := refreshFlightKey{k: k, generation: prepared.item.generation}
	c.refreshInFlight.Store(flight, struct{}{})
	task := &lazyTask{k: k, expected: prepared.item, flight: flight}

	// Model capacity/expiry removal after preflight but before a failed lazy
	// continuation returns. The deferred owner finalizer must clean metadata.
	c.backend.Flush()
	c.finishLazyUpdateTask(task)
	c.activeMu.RLock()
	_, tracked := c.activeMeta[k]
	c.activeMu.RUnlock()
	if tracked {
		t.Fatal("lazy finalizer left metadata after mid-execution backend removal")
	}
	if _, retained := c.refreshInFlight.Load(flight); retained {
		t.Fatal("lazy finalizer retained its inflight claim")
	}
	assertActiveEvictionInvariant(t, c)
}

func TestLazyQueueRejectionReleasesPinnedMissingMetadata(t *testing.T) {
	c := newDormantActiveCache(t, &Args{Size: 16, LazyCacheTTL: 3600}, Opts{})
	defer c.Close()
	qCtx := newTestQuery("lazy-rejected-missing.example.", dns.TypeA, dns.ClassINET, true)
	k := testCacheKey(t, qCtx)
	prepared := testPreparedA(t, qCtx.Q(), "192.0.2.1", time.Minute)
	if !c.commitPrepared(k, nil, 0, prepared) {
		t.Fatal("failed to seed lazy cache entry")
	}
	c.trackActiveRefresh(k, prepared.item, qCtx, sequence.ChainWalker{}, time.Now(), prepared.msg)
	for i := 0; i < cap(c.lazyQueueSlots); i++ {
		c.lazyQueueSlots <- struct{}{}
	}
	c.backend.Flush()
	c.doLazyUpdate(k, prepared.item, qCtx, sequence.ChainWalker{})
	for i := 0; i < cap(c.lazyQueueSlots); i++ {
		<-c.lazyQueueSlots
	}
	c.activeMu.RLock()
	_, tracked := c.activeMeta[k]
	c.activeMu.RUnlock()
	if tracked {
		t.Fatal("queue rejection left backend-missing active metadata pinned")
	}
	flight := refreshFlightKey{k: k, generation: prepared.item.generation}
	if _, retained := c.refreshInFlight.Load(flight); retained {
		t.Fatal("queue rejection retained its inflight claim")
	}
	assertActiveEvictionInvariant(t, c)
}

func TestReadDumpInvalidatesDerivedViewsAndRefreshEpoch(t *testing.T) {
	targetArgs := &Args{Size: 16}
	target := newCacheForTest(t, targetArgs, Opts{})
	defer target.Close()
	source := newCacheForTest(t, &Args{Size: 16}, Opts{})
	defer source.Close()

	qCtx := newTestQuery("load-dump.example.", dns.TypeA, dns.ClassINET, true)
	k := testCacheKey(t, qCtx)
	old := testPreparedA(t, qCtx.Q(), "192.0.2.1", time.Hour)
	fresh := testPreparedA(t, qCtx.Q(), "192.0.2.2", time.Hour)
	if !target.commitPrepared(k, nil, 0, old) || !source.commitPrepared(k, nil, 0, fresh) {
		t.Fatal("failed to seed source or target cache")
	}

	// Enable tracking only after construction so no active scheduler can race
	// this protocol-level test.
	targetArgs.ActiveRefresh.Enabled = true
	target.trackActiveRefresh(k, old.item, qCtx.CopyWithoutResponse(), sequence.ChainWalker{}, time.Now(), old.msg)
	if len(target.activeMeta) != 1 {
		t.Fatal("failed to seed active-refresh metadata")
	}

	buf := new(bytes.Buffer)
	if written, err := source.writeDump(buf); err != nil || written != 1 {
		t.Fatalf("write dump: entries=%d err=%v", written, err)
	}
	oldEpoch := target.refreshEpoch.Load()
	if read, err := target.readDump(buf); err != nil || read != 1 {
		t.Fatalf("read dump: entries=%d err=%v", read, err)
	}
	if got := target.refreshEpoch.Load(); got != oldEpoch+1 {
		t.Fatalf("refresh epoch = %d, want %d", got, oldEpoch+1)
	}

	shard := target.shards[k.Sum()%shardCount]
	shard.RLock()
	_, l1Present := shard.items[k]
	shard.RUnlock()
	if l1Present {
		t.Fatal("dump load left stale L1 data in place")
	}
	target.activeMu.RLock()
	metaCount, scheduledCount, pendingCount := len(target.activeMeta), len(target.activeSchedule), len(target.activePending)
	target.activeMu.RUnlock()
	if metaCount != 0 || scheduledCount != 0 || pendingCount != 0 {
		t.Fatalf("dump load left active state: meta=%d scheduled=%d pending=%d", metaCount, scheduledCount, pendingCount)
	}

	loaded, _, ok := target.backend.Get(k)
	if !ok || loaded == old.item {
		t.Fatal("dump did not replace the L2 entry")
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(loaded.resp); err != nil {
		t.Fatal(err)
	}
	a, ok := msg.Answer[0].(*dns.A)
	if !ok || !a.A.Equal(net.ParseIP("192.0.2.2")) {
		t.Fatalf("loaded answer = %#v, want 192.0.2.2", msg.Answer)
	}

	closedBuf := new(bytes.Buffer)
	if _, err := source.writeDump(closedBuf); err != nil {
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := target.readDump(closedBuf); err != context.Canceled {
		t.Fatalf("load after Close error = %v, want context.Canceled", err)
	}
}

func TestNegativeSOATTLKeepsCachedMessageAndL1ExpirationAligned(t *testing.T) {
	c := newCacheForTest(t, &Args{Size: shardCount, LazyCacheTTL: 3600}, Opts{})
	defer c.Close()

	for _, tc := range []struct {
		name       string
		rcode      int
		soaTTL     uint32
		minimumTTL uint32
		wantTTL    time.Duration
	}{
		{name: "NXDOMAIN", rcode: dns.RcodeNameError, soaTTL: 120, minimumTTL: 30, wantTTL: 30 * time.Second},
		{name: "NODATA", rcode: dns.RcodeSuccess, soaTTL: 40, minimumTTL: 90, wantTTL: 40 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			qCtx := newTestQuery(tc.name+".negative.example.", dns.TypeA, dns.ClassINET, true)
			qCtx.SetResponse(testNegativeResponse(qCtx.Q(), tc.rcode, tc.soaTTL, tc.minimumTTL))
			prepared, ok := c.prepareCacheEntry(qCtx, false)
			if !ok {
				t.Fatal("negative response was not cacheable")
			}
			if got := prepared.item.expirationTime.Sub(prepared.item.storedTime); got != tc.wantTTL {
				t.Fatalf("message ttl = %s, want %s", got, tc.wantTTL)
			}
			if len(prepared.msg.Ns) != 1 {
				t.Fatalf("cached authority records = %d, want 1", len(prepared.msg.Ns))
			}
			soa, ok := prepared.msg.Ns[0].(*dns.SOA)
			if !ok {
				t.Fatalf("cached authority record = %T, want *dns.SOA", prepared.msg.Ns[0])
			}
			if got, want := soa.Hdr.Ttl, uint32(tc.wantTTL/time.Second); got != want {
				t.Fatalf("cached SOA ttl = %d, want %d", got, want)
			}

			k := testCacheKey(t, qCtx)
			if !c.commitPrepared(k, nil, 0, prepared) {
				t.Fatal("failed to commit negative response")
			}
			stored, _, ok := c.backend.Get(k)
			if !ok || stored != prepared.item {
				t.Fatal("negative response missing from L2")
			}

			shard := c.shards[k.Sum()%shardCount]
			shard.RLock()
			l1 := shard.items[k]
			shard.RUnlock()
			if l1 == nil {
				t.Fatal("negative response missing from L1")
			}
			if l1.source != stored || !l1.storedTime.Equal(stored.storedTime) || !l1.expirationTime.Equal(stored.expirationTime) {
				t.Fatalf("L1 expiration/source not aligned with L2 item: %#v", l1)
			}
		})
	}
}

func TestZeroTTLResponsesAreNotCached(t *testing.T) {
	c := newCacheForTest(t, &Args{Size: 16, LazyCacheTTL: 3600}, Opts{})
	defer c.Close()

	for _, tc := range []struct {
		name string
		resp func(*testing.T, *dns.Msg) *dns.Msg
	}{
		{
			name: "positive answer",
			resp: func(t *testing.T, q *dns.Msg) *dns.Msg {
				return testAResponse(t, q, "192.0.2.1", 0)
			},
		},
		{
			name: "NXDOMAIN zero SOA ttl",
			resp: func(_ *testing.T, q *dns.Msg) *dns.Msg {
				return testNegativeResponse(q, dns.RcodeNameError, 0, 30)
			},
		},
		{
			name: "NXDOMAIN zero SOA minimum",
			resp: func(_ *testing.T, q *dns.Msg) *dns.Msg {
				return testNegativeResponse(q, dns.RcodeNameError, 30, 0)
			},
		},
		{
			name: "NODATA zero SOA ttl",
			resp: func(_ *testing.T, q *dns.Msg) *dns.Msg {
				return testNegativeResponse(q, dns.RcodeSuccess, 0, 30)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			qCtx := newTestQuery("zero-ttl.example.", dns.TypeA, dns.ClassINET, true)
			qCtx.SetResponse(tc.resp(t, qCtx.Q()))
			if prepared, ok := c.prepareCacheEntry(qCtx, false); ok || prepared != nil {
				t.Fatalf("TTL 0 response produced cache entry %#v", prepared)
			}
		})
	}
}

func TestFallbackRetentionAndStaleEntryAreBounded(t *testing.T) {
	c := newCacheForTest(t, &Args{
		Size:         16,
		LazyCacheTTL: 15,
		ActiveRefresh: ActiveRefreshArgs{
			Enabled: true,
			Workers: 1,
			FallbackProbe: FallbackProbeArgs{
				Enabled:        true,
				StaleExtendTTL: 60,
				MaxStale:       20,
			},
		},
	}, Opts{})
	defer c.Close()

	qCtx := newTestQuery("stale.example.", dns.TypeA, dns.ClassINET, true)
	response := testAResponse(t, qCtx.Q(), "192.0.2.1", 10)
	response.AuthenticatedData = true
	qCtx.SetResponse(response)
	prepared, ok := c.prepareCacheEntry(qCtx, false)
	if !ok {
		t.Fatal("failed to prepare healthy response")
	}
	wantStaleDeadline := prepared.item.expirationTime.Add(20 * time.Second)
	if !prepared.item.staleDeadline.Equal(wantStaleDeadline) || !prepared.cacheExpiration.Equal(wantStaleDeadline) {
		t.Fatalf("fallback retention deadline item=%s cache=%s want=%s", prepared.item.staleDeadline, prepared.cacheExpiration, wantStaleDeadline)
	}
	if prepared.item.lazyDeadline.IsZero() || !prepared.item.lazyDeadline.Before(prepared.cacheExpiration) {
		t.Fatalf("lazy deadline=%s should be set before private fallback retention=%s", prepared.item.lazyDeadline, prepared.cacheExpiration)
	}

	// Private fallback retention must not make an answer lazy-servable after
	// its separately configured lazy window has elapsed.
	retained := cloneItemForTest(prepared.item)
	retained.expirationTime = time.Now().Add(-2 * time.Second)
	retained.lazyDeadline = time.Now().Add(-time.Second)
	k := testCacheKey(t, qCtx)
	c.backend.Store(k, retained, time.Now().Add(time.Minute))
	if msg, lazy, _ := getRespFromCache(string(k), c.backend, true, expiredMsgTtl); msg != nil || lazy {
		t.Fatal("private fallback retention leaked into lazy serving")
	}

	now := time.Now()
	old := cloneItemForTest(prepared.item)
	old.expirationTime = now.Add(-time.Second)
	old.staleDeadline = now.Add(20 * time.Second)
	stale, ok := c.prepareStaleEntry(old, prepared.msg, now)
	if !ok {
		t.Fatal("expired healthy entry did not produce a bounded stale entry")
	}
	if !stale.item.isStale || !stale.item.expirationTime.Equal(old.staleDeadline) || !stale.cacheExpiration.Equal(old.staleDeadline) {
		t.Fatalf("stale bounds item=%s cache=%s deadline=%s", stale.item.expirationTime, stale.cacheExpiration, old.staleDeadline)
	}
	if stale.msg.AuthenticatedData {
		t.Fatal("stale response retained the AD bit")
	}
	if got := dnsutils.GetMinimalTTL(stale.msg); got == 0 || got > 5 {
		t.Fatalf("stale advertised TTL = %d, want 1..5", got)
	}
	if _, ok := c.prepareStaleEntry(stale.item, stale.msg, old.staleDeadline); ok {
		t.Fatal("stale entry was extended beyond its absolute deadline")
	}

	c.backend.Store(k, stale.item, stale.cacheExpiration)
	buf := new(bytes.Buffer)
	if entries, err := c.writeDump(buf); err != nil || entries != 0 {
		t.Fatalf("stale dump entries=%d err=%v, want 0", entries, err)
	}
}

func TestPrepareCacheEntryPreservesUpstreamECSSourceScope(t *testing.T) {
	c := newCacheForTest(t, &Args{Size: shardCount}, Opts{})
	defer c.Close()

	qCtx := newTestQuery("upstream-ecs.example.", dns.TypeA, dns.ClassINET, true)
	qCtx.QOpt().Option = append(qCtx.QOpt().Option, &dns.EDNS0_SUBNET{
		Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24,
		Address: net.ParseIP("198.51.100.0").To4(),
	})
	r := testAResponse(t, qCtx.Q(), "192.0.2.1", 60)
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.SetUDPSize(1232)
	opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: 24,
		SourceScope:   17,
		Address:       net.ParseIP("198.51.100.0").To4(),
	})
	r.Extra = append(r.Extra, opt)
	qCtx.SetResponse(r)

	prepared, ok := c.prepareCacheEntry(qCtx, false)
	if !ok {
		t.Fatal("response with upstream ECS was not cacheable")
	}
	assertScope := func(where string, opt *dns.OPT) {
		t.Helper()
		if opt == nil {
			t.Fatalf("%s OPT is nil", where)
		}
		for _, option := range opt.Option {
			if ecs, ok := option.(*dns.EDNS0_SUBNET); ok {
				if ecs.SourceScope != 17 {
					t.Fatalf("%s ECS source scope = %d, want 17", where, ecs.SourceScope)
				}
				return
			}
		}
		t.Fatalf("%s OPT does not contain ECS", where)
	}

	assertScope("prepared item", prepared.item.upstreamOpt)
	assertScope("prepared message", prepared.msg.IsEdns0())
	packed := new(dns.Msg)
	if err := packed.Unpack(prepared.item.resp); err != nil {
		t.Fatal(err)
	}
	assertScope("packed cache message", packed.IsEdns0())

	k := testCacheKey(t, qCtx)
	if !c.commitPrepared(k, nil, 0, prepared) {
		t.Fatal("failed to commit response with upstream ECS")
	}
	stored, _, ok := c.backend.Get(k)
	if !ok || stored != prepared.item {
		t.Fatal("committed response with upstream ECS is missing from L2")
	}
	assertScope("stored L2 item", stored.upstreamOpt)
	shard := c.shards[k.Sum()%shardCount]
	shard.RLock()
	l1 := shard.items[k]
	shard.RUnlock()
	if l1 == nil {
		t.Fatal("committed response with upstream ECS is missing from L1")
	}
	assertScope("stored L1 item", l1.upstreamOpt)
}

func TestCacheKeyIncludesRDQClassAndNormalizedECS(t *testing.T) {
	rd := testCacheKey(t, newTestQuery("key.example.", dns.TypeA, dns.ClassINET, true))
	noRD := testCacheKey(t, newTestQuery("key.example.", dns.TypeA, dns.ClassINET, false))
	if rd == noRD {
		t.Fatal("RD and non-RD queries share a cache key")
	}

	in := testCacheKey(t, newTestQuery("key.example.", dns.TypeA, dns.ClassINET, true))
	chaos := testCacheKey(t, newTestQuery("key.example.", dns.TypeA, dns.ClassCHAOS, true))
	if in == chaos {
		t.Fatal("different QCLASS values share a cache key")
	}

	keyWithECS := func(t *testing.T, address string, mask uint8) key {
		t.Helper()
		qCtx := newTestQuery("ecs.example.", dns.TypeA, dns.ClassINET, true)
		qCtx.QOpt().Option = append(qCtx.QOpt().Option, &dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        1,
			SourceNetmask: mask,
			Address:       net.ParseIP(address).To4(),
		})
		return testCacheKey(t, qCtx)
	}

	maskedA := keyWithECS(t, "192.0.2.129", 25)
	maskedB := keyWithECS(t, "192.0.2.254", 25)
	if maskedA != maskedB {
		t.Fatal("addresses in the same ECS /25 produced different cache keys")
	}
	differentPrefix := keyWithECS(t, "192.0.2.1", 25)
	if maskedA == differentPrefix {
		t.Fatal("different ECS /25 prefixes produced the same cache key")
	}
}

func TestCacheKeyRejectsMalformedECS(t *testing.T) {
	for _, ecs := range []*dns.EDNS0_SUBNET{
		{Code: dns.EDNS0SUBNET, Family: 3, SourceNetmask: 24, Address: net.ParseIP("192.0.2.1")},
		{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 33, Address: net.ParseIP("192.0.2.1")},
		{Code: dns.EDNS0SUBNET, Family: 2, SourceNetmask: 129, Address: net.ParseIP("2001:db8::1")},
		{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, SourceScope: 24, Address: net.ParseIP("192.0.2.1")},
	} {
		qCtx := newTestQuery("malformed-ecs.example.", dns.TypeA, dns.ClassINET, true)
		qCtx.QOpt().Option = append(qCtx.QOpt().Option, ecs)
		if buf, pooled := getMsgKeyBytes(qCtx.Q(), qCtx, false); buf != nil || pooled != nil {
			if pooled != nil {
				keyBufferPool.Put(pooled)
			}
			t.Fatalf("malformed ECS produced cache key %x", buf)
		}
	}

	duplicate := newTestQuery("duplicate-ecs.example.", dns.TypeA, dns.ClassINET, true)
	for _, address := range []string{"192.0.2.1", "198.51.100.1"} {
		duplicate.QOpt().Option = append(duplicate.QOpt().Option, &dns.EDNS0_SUBNET{
			Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.ParseIP(address).To4(),
		})
	}
	if buf, pooled := getMsgKeyBytes(duplicate.Q(), duplicate, false); buf != nil || pooled != nil {
		if pooled != nil {
			keyBufferPool.Put(pooled)
		}
		t.Fatalf("duplicate ECS options produced cache key %x", buf)
	}
}

func TestEnableECSFallsBackToFullClientIdentity(t *testing.T) {
	keyForClient := func(t *testing.T, address string) key {
		t.Helper()
		qCtx := newTestQuery("client-ecs.example.", dns.TypeA, dns.ClassINET, true)
		if address != "" {
			qCtx.ServerMeta.ClientAddr = netip.MustParseAddr(address)
		}
		buf, pooled := getMsgKeyBytes(qCtx.Q(), qCtx, true)
		if buf == nil || pooled == nil {
			t.Fatal("valid client identity did not produce a cache key")
		}
		k := key(string(buf))
		keyBufferPool.Put(pooled)
		return k
	}

	first := keyForClient(t, "192.0.2.1")
	second := keyForClient(t, "192.0.2.2")
	if first == second {
		t.Fatal("different clients share an enable_ecs fallback key")
	}

	missing := newTestQuery("client-ecs.example.", dns.TypeA, dns.ClassINET, true)
	if buf, pooled := getMsgKeyBytes(missing.Q(), missing, true); buf != nil || pooled != nil {
		if pooled != nil {
			keyBufferPool.Put(pooled)
		}
		t.Fatalf("missing client identity produced cache key %x", buf)
	}
}

func TestActiveRefreshMetadataIsBoundedByCacheSize(t *testing.T) {
	const cacheSize = 3
	c := newCacheForTest(t, &Args{
		Size: cacheSize,
		ActiveRefresh: ActiveRefreshArgs{
			Enabled: true,
			Workers: 1,
		},
	}, Opts{})
	defer c.Close()

	for i := 0; i < 10; i++ {
		qCtx := newTestQuery("meta-"+strconv.Itoa(i)+".example.", dns.TypeA, dns.ClassINET, true)
		k := testCacheKey(t, qCtx)
		prepared := testPreparedA(t, qCtx.Q(), "192.0.2.1", time.Hour)
		if !c.commitPrepared(k, nil, 0, prepared) {
			t.Fatalf("failed to seed entry %d", i)
		}
		c.trackActiveRefresh(k, prepared.item, qCtx.CopyWithoutResponse(), sequence.ChainWalker{}, time.Now(), prepared.msg)

		c.activeMu.RLock()
		metaLen := len(c.activeMeta)
		heapLen := len(c.activeSchedule)
		c.activeMu.RUnlock()
		if metaLen > cacheSize || heapLen > cacheSize {
			t.Fatalf("after entry %d metadata=%d heap=%d, cache size=%d", i, metaLen, heapLen, cacheSize)
		}
	}

	c.activeMu.RLock()
	metaLen := len(c.activeMeta)
	heapLen := len(c.activeSchedule)
	if metaLen != cacheSize || heapLen != cacheSize {
		c.activeMu.RUnlock()
		t.Fatalf("metadata=%d heap=%d, want both capped at %d", metaLen, heapLen, cacheSize)
	}
	for k, meta := range c.activeMeta {
		current, _, present := c.backend.Get(k)
		if !present || current != meta.expected {
			c.activeMu.RUnlock()
			t.Fatalf("metadata retained an evicted/stale entry for %q", keyToString(k))
		}
	}
	c.activeMu.RUnlock()
}

func TestActiveRefresh_ParseIPNetSupportsIPAndCIDR(t *testing.T) {
	ipNet, err := parseIPNet("198.18.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if !ipNet.Contains(net.ParseIP("198.18.0.1")) || ipNet.Contains(net.ParseIP("198.18.0.2")) {
		t.Fatalf("single ip net mismatch: %v", ipNet)
	}

	cidr, err := parseIPNet("198.18.0.0/15")
	if err != nil {
		t.Fatal(err)
	}
	if !cidr.Contains(net.ParseIP("198.19.255.255")) || cidr.Contains(net.ParseIP("198.20.0.1")) {
		t.Fatalf("cidr net mismatch: %v", cidr)
	}
}

func TestActiveRefresh_QuestionFromKey(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeAAAA)
	qCtx := query_context.NewContext(q)
	msgKeyBuf, bufPtr := getMsgKeyBytes(qCtx.Q(), qCtx, false)
	if msgKeyBuf == nil {
		t.Fatal("msg key is nil")
	}
	defer keyBufferPool.Put(bufPtr)

	question, ok := questionFromKey(key(string(msgKeyBuf)))
	if !ok {
		t.Fatal("failed to parse question from key")
	}
	if question.Name != "example.com." || question.Qtype != dns.TypeAAAA || question.Qclass != dns.ClassINET {
		t.Fatalf("question mismatch: %#v", question)
	}
}

func TestActiveRefresh_ExcludeDomainMatcher(t *testing.T) {
	m, err := buildActiveExcludeDomainMatcher(nil, ActiveRefreshDomainArgs{
		Exps: []string{"domain:fakeip.local", "full:test.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Match("a.fakeip.local."); !ok {
		t.Fatal("domain rule should match subdomain")
	}
	if _, ok := m.Match("test.example.com."); !ok {
		t.Fatal("full rule should match exact domain")
	}
	if _, ok := m.Match("a.test.example.com."); ok {
		t.Fatal("full rule should not match subdomain")
	}
}

func TestBackendCapacityEvictionInvalidatesMatchingL1(t *testing.T) {
	c := newCacheForTest(t, &Args{Size: 64}, Opts{})
	defer c.Close()

	var oldKey, replacementKey key
	var backendShard uint64
	for i := 0; i < 10000; i++ {
		candidate := key("capacity-eviction-" + strconv.Itoa(i))
		l1Shard := c.shards[candidate.Sum()%shardCount]
		if oldKey == "" {
			if len(l1Shard.order) == 0 {
				continue
			}
			oldKey = candidate
			backendShard = candidate.Sum() % 64
			continue
		}
		if candidate != oldKey && candidate.Sum()%64 == backendShard {
			replacementKey = candidate
			break
		}
	}
	if oldKey == "" || replacementKey == "" {
		t.Fatal("failed to find keys in the same backend shard")
	}

	qCtx := newTestQuery("capacity-eviction.example.", dns.TypeA, dns.ClassINET, true)
	old := testPreparedA(t, qCtx.Q(), "192.0.2.1", time.Hour)
	if !c.commitPrepared(oldKey, nil, 0, old) {
		t.Fatal("failed to seed capacity victim")
	}
	oldShard := c.shards[oldKey.Sum()%shardCount]
	oldShard.RLock()
	seeded := oldShard.items[oldKey]
	oldShard.RUnlock()
	if seeded == nil || seeded.source != old.item {
		t.Fatal("capacity victim was not seeded in L1")
	}

	replacement := testPreparedA(t, qCtx.Q(), "192.0.2.2", time.Hour)
	c.backend.Store(replacementKey, replacement.item, replacement.cacheExpiration)
	if _, _, ok := c.backend.Get(oldKey); ok {
		t.Fatal("old entry survived a capacity-one backend insertion")
	}
	if !old.item.backendRemoved.Load() {
		t.Fatal("capacity-evicted item was not marked as removed from L2")
	}
	oldShard.RLock()
	_, present := oldShard.items[oldKey]
	oldShard.RUnlock()
	if present {
		t.Fatal("capacity-evicted backend entry remained hittable in L1")
	}
}

func TestL1RemovalMatchesOldPointerAndClearsItsClockSlot(t *testing.T) {
	c := newCacheForTest(t, &Args{Size: 2 * shardCount}, Opts{})
	defer c.Close()

	qCtx := newTestQuery("l1-pointer-match.example.", dns.TypeA, dns.ClassINET, true)
	k := testCacheKey(t, qCtx)
	old := testPreparedA(t, qCtx.Q(), "192.0.2.1", time.Hour)
	newer := testPreparedA(t, qCtx.Q(), "192.0.2.2", time.Hour)
	if !c.commitPrepared(k, nil, 0, old) {
		t.Fatal("failed to seed old L1 entry")
	}
	shard := c.shards[k.Sum()%shardCount]
	shard.RLock()
	oldSlot := shard.items[k].slot
	shard.RUnlock()

	if !c.commitPrepared(k, old.item, c.refreshEpoch.Load(), newer) {
		t.Fatal("failed to replace old entry")
	}
	shard.RLock()
	current := shard.items[k]
	oldSlotValue := shard.order[oldSlot]
	shard.RUnlock()
	if current == nil || current.source != newer.item {
		t.Fatal("newer pointer was not installed in L1")
	}
	if current.slot == oldSlot || oldSlotValue != "" {
		t.Fatalf("old clock slot was reused or left stale: old=%d new=%d value=%q", oldSlot, current.slot, oldSlotValue)
	}

	if c.removeL1IfSource(k, old.item) {
		t.Fatal("delayed old-pointer notification removed a newer L1 entry")
	}
	shard.RLock()
	preserved := shard.items[k]
	newSlotValue := shard.order[current.slot]
	shard.RUnlock()
	if preserved == nil || preserved.source != newer.item || newSlotValue != k {
		t.Fatal("newer L1 entry or its clock slot was not preserved")
	}

	if !c.removeL1IfSource(k, newer.item) {
		t.Fatal("matching pointer did not remove L1 entry")
	}
	shard.RLock()
	_, present := shard.items[k]
	clearedSlot := shard.order[current.slot]
	shard.RUnlock()
	if present || clearedSlot != "" {
		t.Fatal("matching removal left the item or its clock slot behind")
	}
}

func TestL1CapacityTracksBackendBudgetAndFlushPreservesLayout(t *testing.T) {
	for _, size := range []int{1, shardCount - 1, shardCount, shardCount + 1, l1TotalCap + 1024} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			c := newCacheForTest(t, &Args{Size: size}, Opts{})
			defer c.Close()
			wantTotal := min(size, l1TotalCap)
			base := wantTotal / shardCount
			extra := wantTotal % shardCount
			gotTotal := 0
			zeroCapacityShards := 0
			for i, shard := range c.shards {
				want := base
				if i < extra {
					want++
				}
				if got := len(shard.order); got != want {
					t.Fatalf("shard %d capacity = %d, want %d", i, got, want)
				}
				gotTotal += len(shard.order)
				if len(shard.order) == 0 {
					zeroCapacityShards++
				}
			}
			if gotTotal != wantTotal {
				t.Fatalf("total L1 capacity = %d, want %d", gotTotal, wantTotal)
			}
			if size < shardCount && zeroCapacityShards == 0 {
				t.Fatal("small cache did not create any zero-capacity L1 shards")
			}
		})
	}

	c := newCacheForTest(t, &Args{Size: shardCount + 1}, Opts{})
	defer c.Close()
	capacities := make([]int, shardCount)
	for i, shard := range c.shards {
		capacities[i] = len(shard.order)
	}
	qCtx := newTestQuery("dynamic-flush.example.", dns.TypeA, dns.ClassINET, true)
	k := testCacheKey(t, qCtx)
	prepared := testPreparedA(t, qCtx.Q(), "192.0.2.1", time.Hour)
	if !c.commitPrepared(k, nil, 0, prepared) {
		t.Fatal("failed to seed cache before flush")
	}

	rr := httptest.NewRecorder()
	c.Api().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/flush", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("flush status = %d, want %d", rr.Code, http.StatusOK)
	}
	if !prepared.item.backendRemoved.Load() {
		t.Fatal("flush did not mark the backend item as removed")
	}
	for i, shard := range c.shards {
		shard.RLock()
		capacity := len(shard.order)
		items, refs, pos := len(shard.items), len(shard.ref), shard.pos
		shard.RUnlock()
		if capacity != capacities[i] || items != 0 || refs != 0 || pos != 0 {
			t.Fatalf("shard %d after flush: capacity=%d items=%d refs=%d pos=%d", i, capacity, items, refs, pos)
		}
	}
}
