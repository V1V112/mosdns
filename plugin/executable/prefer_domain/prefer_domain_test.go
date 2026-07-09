package prefer_domain

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

type matcherFunc func(netip.Addr) bool

func (f matcherFunc) Match(addr netip.Addr) bool {
	return f(addr)
}

func TestMatchRuleUsesConfiguredRuleOrder(t *testing.T) {
	firstIP := netip.MustParseAddr("192.0.2.1")
	secondIP := netip.MustParseAddr("192.0.2.2")
	p := &PreferDomain{
		rules: []compiledRule{
			{
				preferDomain: "first.example.",
				matcher: matcherFunc(func(addr netip.Addr) bool {
					return addr == secondIP
				}),
			},
			{
				preferDomain: "second.example.",
				matcher: matcherFunc(func(addr netip.Addr) bool {
					return addr == firstIP
				}),
			},
		},
	}
	r := &dns.Msg{
		Answer: []dns.RR{
			newA("original.example.", firstIP.String(), 300),
			newA("original.example.", secondIP.String(), 300),
		},
	}

	rule, addr, ok := p.matchRule(r)
	if !ok {
		t.Fatal("matchRule() did not match")
	}
	if rule != &p.rules[0] {
		t.Fatalf("matchRule() selected %q, want first configured rule", rule.preferDomain)
	}
	if addr != secondIP {
		t.Fatalf("matchRule() matched %v, want %v", addr, secondIP)
	}
}

func TestBuildMaskedResponseClearsSynthesizedSecurityFlags(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("original.example.", dns.TypeA)
	q.CheckingDisabled = true

	preferred := new(dns.Msg)
	preferred.Authoritative = true
	preferred.AuthenticatedData = true
	preferred.RecursionAvailable = true
	preferred.Answer = []dns.RR{newA("preferred.example.", "192.0.2.10", 300)}

	got, ok := buildMaskedResponse(q, preferred, 0)
	if !ok {
		t.Fatal("buildMaskedResponse() rejected a usable response")
	}
	if got.Authoritative {
		t.Fatal("synthesized response must not be authoritative")
	}
	if got.AuthenticatedData {
		t.Fatal("synthesized response must not claim DNSSEC authentication")
	}
	if !got.CheckingDisabled {
		t.Fatal("synthesized response did not preserve the client CD flag")
	}
	if !got.RecursionAvailable {
		t.Fatal("synthesized response did not preserve resolver availability")
	}
}

func TestCachedResponseTTLIsAged(t *testing.T) {
	rule := &compiledRule{preferDomain: "preferred.example."}
	msg := &dns.Msg{Answer: []dns.RR{newA(rule.preferDomain, "192.0.2.20", 300)}}
	now := time.Now()
	p := &PreferDomain{
		cache: map[string]cacheEntry{
			cacheKey(rule.preferDomain, dns.TypeA): {
				msg:     msg,
				stored:  now.Add(-2500 * time.Millisecond),
				expires: now.Add(time.Minute),
			},
		},
	}

	got, stale, err := p.getPreferredResponse(context.Background(), rule, dns.TypeA)
	if err != nil {
		t.Fatalf("getPreferredResponse() error = %v", err)
	}
	if stale {
		t.Fatal("fresh cache entry was marked stale")
	}
	ttl := got.Answer[0].Header().Ttl
	if ttl >= 300 || ttl < 296 {
		t.Fatalf("cached TTL was not aged correctly: got %d, want 296..299", ttl)
	}
}

func TestStaleResponseGetsZeroTTL(t *testing.T) {
	rule := &compiledRule{preferDomain: "preferred.example."}
	msg := &dns.Msg{Answer: []dns.RR{newA(rule.preferDomain, "192.0.2.30", 300)}}
	p := &PreferDomain{
		resolver: sequence.ExecutableFunc(func(context.Context, *query_context.Context) error {
			return errors.New("upstream unavailable")
		}),
		timeout:    time.Second,
		serveStale: true,
		cache: map[string]cacheEntry{
			cacheKey(rule.preferDomain, dns.TypeA): {
				msg:     msg,
				stored:  time.Now().Add(-time.Minute),
				expires: time.Now().Add(-time.Second),
			},
		},
	}

	got, stale, err := p.getPreferredResponse(context.Background(), rule, dns.TypeA)
	if err != nil {
		t.Fatalf("getPreferredResponse() error = %v", err)
	}
	if !stale {
		t.Fatal("expired cache entry was not marked stale")
	}
	if ttl := got.Answer[0].Header().Ttl; ttl != 0 {
		t.Fatalf("stale TTL = %d, want 0", ttl)
	}
}

func TestZeroTTLResponseIsNotCached(t *testing.T) {
	rule := &compiledRule{preferDomain: "preferred.example."}
	p := &PreferDomain{cache: make(map[string]cacheEntry)}
	msg := &dns.Msg{Answer: []dns.RR{newA(rule.preferDomain, "192.0.2.40", 0)}}

	p.storePreferred(rule, dns.TypeA, msg)

	if _, ok := p.cache[cacheKey(rule.preferDomain, dns.TypeA)]; ok {
		t.Fatal("zero-TTL response was cached")
	}
}

func TestWarmOnStartWorksWithoutWarmInterval(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resolved := make(chan uint16, 2)
	p := &PreferDomain{
		logger: zap.NewNop(),
		resolver: sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
			q := qCtx.Q()
			r := new(dns.Msg)
			r.SetReply(q)
			switch q.Question[0].Qtype {
			case dns.TypeA:
				r.Answer = append(r.Answer, newA(q.Question[0].Name, "192.0.2.50", 300))
			case dns.TypeAAAA:
				r.Answer = append(r.Answer, newAAAA(q.Question[0].Name, "2001:db8::50", 300))
			}
			qCtx.SetResponse(r)
			resolved <- q.Question[0].Qtype
			return nil
		}),
		rules:       []compiledRule{{preferDomain: "preferred.example.", preferDisplay: "preferred.example"}},
		timeout:     time.Second,
		warmOnStart: true,
		cache:       make(map[string]cacheEntry),
		ctx:         ctx,
		cancel:      cancel,
	}

	p.startWarmers()

	seen := make(map[uint16]bool)
	for len(seen) < 2 {
		select {
		case qType := <-resolved:
			seen[qType] = true
		case <-time.After(time.Second):
			t.Fatal("warm_on_start did not resolve both A and AAAA with warm_interval disabled")
		}
	}
}

func TestConcurrentCacheMissUsesSingleflight(t *testing.T) {
	pluginCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var calls atomic.Int32
	resolverStarted := make(chan struct{})
	allowResolver := make(chan struct{})
	var startedOnce sync.Once
	p := &PreferDomain{
		resolver: sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
			calls.Add(1)
			startedOnce.Do(func() { close(resolverStarted) })
			<-allowResolver
			q := qCtx.Q()
			r := new(dns.Msg)
			r.SetReply(q)
			r.Answer = append(r.Answer, newA(q.Question[0].Name, "192.0.2.60", 300))
			qCtx.SetResponse(r)
			return nil
		}),
		timeout: time.Second,
		cache:   make(map[string]cacheEntry),
		ctx:     pluginCtx,
		cancel:  cancel,
	}
	rule := &compiledRule{preferDomain: "preferred.example."}

	const concurrency = 16
	start := make(chan struct{})
	var ready sync.WaitGroup
	var done sync.WaitGroup
	ready.Add(concurrency)
	done.Add(concurrency)
	errs := make(chan error, concurrency)
	for range concurrency {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			_, _, err := p.getPreferredResponse(context.Background(), rule, dns.TypeA)
			errs <- err
		}()
	}

	ready.Wait()
	close(start)
	<-resolverStarted
	close(allowResolver)
	done.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("getPreferredResponse() error = %v", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("resolver calls = %d, want 1", got)
	}
}

func TestWarmAllDeduplicatesDomainAndQType(t *testing.T) {
	pluginCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var calls atomic.Int32
	p := &PreferDomain{
		logger: zap.NewNop(),
		resolver: sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
			calls.Add(1)
			q := qCtx.Q()
			r := new(dns.Msg)
			r.SetReply(q)
			switch q.Question[0].Qtype {
			case dns.TypeA:
				r.Answer = append(r.Answer, newA(q.Question[0].Name, "192.0.2.70", 300))
			case dns.TypeAAAA:
				r.Answer = append(r.Answer, newAAAA(q.Question[0].Name, "2001:db8::70", 300))
			}
			qCtx.SetResponse(r)
			return nil
		}),
		rules: []compiledRule{
			{preferDomain: "Preferred.Example.", preferDisplay: "Preferred.Example"},
			{preferDomain: "preferred.example.", preferDisplay: "preferred.example"},
		},
		timeout: time.Second,
		cache:   make(map[string]cacheEntry),
		ctx:     pluginCtx,
		cancel:  cancel,
	}

	p.warmAll()

	if got := calls.Load(); got != 2 {
		t.Fatalf("resolver calls = %d, want 2 (one A and one AAAA)", got)
	}
}

func newA(name, ip string, ttl uint32) *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.ParseIP(ip).To4(),
	}
}

func newAAAA(name, ip string, ttl uint32) *dns.AAAA {
	return &dns.AAAA{
		Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
		AAAA: net.ParseIP(ip),
	}
}
