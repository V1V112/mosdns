package prefer_domain

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	sequencefallback "github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence/fallback"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

type matcherFunc func(netip.Addr) bool

func (f matcherFunc) Match(addr netip.Addr) bool {
	return f(addr)
}

type matcherProvider struct {
	matcher netlist.Matcher
}

func (p matcherProvider) GetIPMatcher() netlist.Matcher {
	return p.matcher
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
	r := &dns.Msg{Answer: []dns.RR{
		newA("original.example.", firstIP.String(), 300),
		newA("original.example.", secondIP.String(), 300),
	}}

	rule, addr, owner, ok := p.matchRule(r, dns.TypeA)
	if !ok {
		t.Fatal("matchRule() did not match")
	}
	if rule != &p.rules[0] {
		t.Fatalf("matchRule() selected %q, want first configured rule", rule.preferDomain)
	}
	if addr != secondIP {
		t.Fatalf("matchRule() matched %v, want %v", addr, secondIP)
	}
	if owner != "original.example." {
		t.Fatalf("matchRule() owner = %q, want original.example.", owner)
	}
}

func TestMatchRuleOnlyChecksRequestedAddressFamily(t *testing.T) {
	ipv6 := netip.MustParseAddr("2001:db8::1")
	p := &PreferDomain{rules: []compiledRule{{
		matcher: matcherFunc(func(addr netip.Addr) bool { return addr == ipv6 }),
	}}}
	r := &dns.Msg{Answer: []dns.RR{newAAAA("original.example.", ipv6.String(), 300)}}

	if _, _, _, ok := p.matchRule(r, dns.TypeA); ok {
		t.Fatal("A matching was triggered by an AAAA record")
	}
	if _, addr, _, ok := p.matchRule(r, dns.TypeAAAA); !ok || addr != ipv6 {
		t.Fatalf("AAAA matching = (%v, %v), want (%v, true)", addr, ok, ipv6)
	}
}

func TestMatchRuleOnlyChecksTerminalCNAMEAddressRRSet(t *testing.T) {
	unrelatedIP := netip.MustParseAddr("192.0.2.9")
	p := &PreferDomain{rules: []compiledRule{{
		matcher: matcherFunc(func(addr netip.Addr) bool { return addr == unrelatedIP }),
	}}}
	q := new(dns.Msg)
	q.SetQuestion("original.example.", dns.TypeA)
	r := new(dns.Msg)
	r.SetReply(q)
	r.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: "original.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: "edge.example."},
		newA("unrelated.example.", unrelatedIP.String(), 300),
		newA("edge.example.", "198.51.100.9", 300),
	}

	if _, _, _, ok := p.matchRule(r, dns.TypeA); ok {
		t.Fatal("an unrelated Answer RRset triggered preferred-domain matching")
	}
}

func TestBuildReplacedResponsePreservesOriginalMessage(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("original.example.", dns.TypeA)
	original := new(dns.Msg)
	original.SetReply(q)
	original.Authoritative = true
	original.AuthenticatedData = true
	original.RecursionAvailable = true
	original.CheckingDisabled = true
	original.Answer = []dns.RR{
		&dns.CNAME{
			Hdr:    dns.RR_Header{Name: "original.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 120},
			Target: "edge.example.",
		},
		newA("edge.example.", "192.0.2.1", 120),
		newA("edge.example.", "192.0.2.2", 120),
		&dns.RRSIG{
			Hdr:         dns.RR_Header{Name: "edge.example.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 120},
			TypeCovered: dns.TypeA,
		},
		&dns.TXT{
			Hdr: dns.RR_Header{Name: "edge.example.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 120},
			Txt: []string{"keep"},
		},
		newAAAA("edge.example.", "2001:db8::1", 120),
		newA("unrelated.example.", "198.51.100.99", 120),
	}
	original.Ns = []dns.RR{&dns.NS{
		Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 600},
		Ns:  "ns.example.",
	}}
	original.Extra = []dns.RR{newA("ns.example.", "198.51.100.53", 600)}

	preferredQ := new(dns.Msg)
	preferredQ.SetQuestion("preferred.example.", dns.TypeA)
	preferred := new(dns.Msg)
	preferred.SetReply(preferredQ)
	preferred.Answer = []dns.RR{
		&dns.CNAME{
			Hdr:    dns.RR_Header{Name: "preferred.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
			Target: "preferred-edge.example.",
		},
		newA("preferred-edge.example.", "203.0.113.10", 300),
		newA("preferred-edge.example.", "203.0.113.11", 200),
		newA("unrelated-preferred.example.", "203.0.113.99", 300),
	}

	got, ok := buildReplacedResponse(original, preferred, dns.TypeA, "edge.example.")
	if !ok {
		t.Fatal("buildReplacedResponse() rejected a usable response")
	}
	if got.Authoritative || got.AuthenticatedData {
		t.Fatalf("modified response retained unsafe flags: AA=%v AD=%v", got.Authoritative, got.AuthenticatedData)
	}
	if !got.CheckingDisabled || !got.RecursionAvailable {
		t.Fatalf("original response flags were lost: CD=%v RA=%v", got.CheckingDisabled, got.RecursionAvailable)
	}
	if len(got.Ns) != 1 || len(got.Extra) != 1 {
		t.Fatalf("unrelated sections were not preserved: ns=%v extra=%v", got.Ns, got.Extra)
	}
	if len(got.Answer) != 6 {
		t.Fatalf("answers = %v, want CNAME + 2 preferred A + TXT + AAAA + unrelated A", got.Answer)
	}
	if _, ok := got.Answer[0].(*dns.CNAME); !ok {
		t.Fatalf("CNAME chain was not preserved: %v", got.Answer)
	}
	for i, wantIP := range []string{"203.0.113.10", "203.0.113.11"} {
		a, ok := got.Answer[i+1].(*dns.A)
		if !ok || a.Hdr.Name != "edge.example." || a.A.String() != wantIP {
			t.Fatalf("replacement answer %d = %v, want edge.example. A %s", i, got.Answer[i+1], wantIP)
		}
	}
	for _, rr := range got.Answer {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeA {
			t.Fatalf("invalidated A RRSIG was retained: %v", sig)
		}
		if rr.Header().Name == "preferred.example." || rr.Header().Name == "preferred-edge.example." {
			t.Fatalf("preferred-domain owner leaked into response: %v", rr)
		}
	}
	if rrAddress(got.Answer[len(got.Answer)-1]) != "198.51.100.99" {
		t.Fatalf("unrelated A RRset was not preserved: %v", got.Answer)
	}
	if len(original.Answer) != 7 {
		t.Fatal("buildReplacedResponse() mutated its input")
	}
}

func TestExecReplacesExistingAddressResponses(t *testing.T) {
	tests := []struct {
		name        string
		qType       uint16
		originalIP  string
		preferredIP string
	}{
		{name: "A", qType: dns.TypeA, originalIP: "192.0.2.80", preferredIP: "203.0.113.80"},
		{name: "AAAA", qType: dns.TypeAAAA, originalIP: "2001:db8::80", preferredIP: "2001:db8:1::80"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pluginCtx, cancel := context.WithCancel(context.Background())
			defer cancel()

			originalAddr := netip.MustParseAddr(tt.originalIP)
			var calls atomic.Int32
			p := newTestPreferDomain(pluginCtx, originalAddr, sequence.ExecutableFunc(func(_ context.Context, _ *query_context.Context) error {
				calls.Add(1)
				return errors.New("client request must not resolve preferred domain")
			}))
			cachePreferred(t, p, &p.rules[0], tt.qType, tt.preferredIP, 300)

			q := new(dns.Msg)
			q.SetQuestion("original.example.", tt.qType)
			q.Id = 4242
			r := new(dns.Msg)
			r.SetReply(q)
			r.RecursionAvailable = true
			if tt.qType == dns.TypeA {
				r.Answer = []dns.RR{newA(q.Question[0].Name, tt.originalIP, 120)}
			} else {
				r.Answer = []dns.RR{newAAAA(q.Question[0].Name, tt.originalIP, 120)}
			}
			qCtx := query_context.NewContext(q)
			qCtx.SetResponse(r)
			opt := new(dns.OPT)
			opt.Hdr.Name = "."
			opt.Hdr.Rrtype = dns.TypeOPT
			opt.SetUDPSize(1232)
			opt.Option = []dns.EDNS0{&dns.EDNS0_NSID{Code: dns.EDNS0NSID, Nsid: "01020304"}}
			qCtx.SetUpstreamOpt(opt)

			if err := p.Exec(context.Background(), qCtx); err != nil {
				t.Fatalf("Exec() error = %v", err)
			}
			got := qCtx.R()
			if got == nil || got.Id != 4242 || got.Rcode != dns.RcodeSuccess || !got.RecursionAvailable {
				t.Fatalf("response header was not preserved: %v", got)
			}
			if len(got.Answer) != 1 || rrAddress(got.Answer[0]) != tt.preferredIP {
				t.Fatalf("replacement response = %v, want %s", got, tt.preferredIP)
			}
			if got.Answer[0].Header().Name != "original.example." {
				t.Fatalf("replacement owner = %q, want original.example.", got.Answer[0].Header().Name)
			}
			if qCtx.UpstreamOpt() == nil || qCtx.UpstreamOpt().UDPSize() != 1232 {
				t.Fatalf("upstream OPT was not preserved: %v", qCtx.UpstreamOpt())
			}
			if len(qCtx.UpstreamOpt().Option) != 1 {
				t.Fatalf("upstream EDNS options were not preserved: %v", qCtx.UpstreamOpt())
			}
			nsid, ok := qCtx.UpstreamOpt().Option[0].(*dns.EDNS0_NSID)
			if !ok || nsid.Nsid != "01020304" {
				t.Fatalf("upstream NSID was not preserved: %v", qCtx.UpstreamOpt().Option)
			}
			if gotCalls := calls.Load(); gotCalls != 0 {
				t.Fatalf("preferred resolver calls = %d, want 0", gotCalls)
			}
		})
	}
}

func TestExecReplacesAddressAfterCNAMEChain(t *testing.T) {
	pluginCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	originalAddr := netip.MustParseAddr("192.0.2.81")
	p := newTestPreferDomain(pluginCtx, originalAddr, addressResolver("203.0.113.81"))
	cachePreferred(t, p, &p.rules[0], dns.TypeA, "203.0.113.81", 300)
	q := new(dns.Msg)
	q.SetQuestion("original.example.", dns.TypeA)
	r := new(dns.Msg)
	r.SetReply(q)
	r.Answer = []dns.RR{
		&dns.CNAME{
			Hdr:    dns.RR_Header{Name: "original.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 120},
			Target: "edge.example.",
		},
		newA("edge.example.", originalAddr.String(), 120),
	}
	qCtx := query_context.NewContext(q)
	qCtx.SetResponse(r)

	if err := p.Exec(context.Background(), qCtx); err != nil {
		t.Fatalf("Exec() error = %v", err)
	}
	if len(qCtx.R().Answer) != 2 {
		t.Fatalf("CNAME response = %v, want two answers", qCtx.R())
	}
	if cname, ok := qCtx.R().Answer[0].(*dns.CNAME); !ok || cname.Target != "edge.example." {
		t.Fatalf("CNAME chain was not preserved: %v", qCtx.R().Answer)
	}
	if a, ok := qCtx.R().Answer[1].(*dns.A); !ok || a.Hdr.Name != "edge.example." || a.A.String() != "203.0.113.81" {
		t.Fatalf("terminal address was not replaced: %v", qCtx.R().Answer[1])
	}
}

func TestFallbackFinalResponseIsPostProcessed(t *testing.T) {
	tests := []struct {
		name               string
		primaryIP          string
		secondaryIP        string
		primaryFailureOnly bool
		wantIP             string
	}{
		{
			name:      "primary winner matches",
			primaryIP: "192.0.2.82",
			wantIP:    "203.0.113.82",
		},
		{
			name:               "secondary winner matches",
			secondaryIP:        "192.0.2.82",
			primaryFailureOnly: true,
			wantIP:             "203.0.113.82",
		},
		{
			name:               "secondary winner does not match",
			secondaryIP:        "198.51.100.82",
			primaryFailureOnly: true,
			wantIP:             "198.51.100.82",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			responseExec := func(ip string) sequence.Executable {
				return sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
					if ip == "" {
						return nil
					}
					r := new(dns.Msg)
					r.SetReply(qCtx.Q())
					r.Answer = []dns.RR{newA(qCtx.Q().Question[0].Name, ip, 120)}
					qCtx.SetResponse(r)
					return sequence.ErrExit
				})
			}

			plugins := map[string]any{
				"primary":   responseExec(tt.primaryIP),
				"secondary": responseExec(tt.secondaryIP),
			}
			m := coremain.NewTestMosdnsWithPlugins(plugins)
			fallbackPlugin, err := sequencefallback.Init(coremain.NewBP("fallback", m), &sequencefallback.Args{
				Primary:            "primary",
				Secondary:          "secondary",
				PrimaryFailureOnly: tt.primaryFailureOnly,
			})
			if err != nil {
				t.Fatalf("fallback.Init() error = %v", err)
			}
			plugins["fallback"] = fallbackPlugin

			pluginCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			prefer := newTestPreferDomain(pluginCtx, netip.MustParseAddr("192.0.2.82"), addressResolver("203.0.113.82"))
			cachePreferred(t, prefer, &prefer.rules[0], dns.TypeA, "203.0.113.82", 300)
			plugins["prefer"] = prefer
			outer, err := sequence.NewSequence(coremain.NewBP("outer", m), []sequence.RuleArgs{{
				Exec: []string{"$fallback", "$prefer"},
			}})
			if err != nil {
				t.Fatalf("sequence.NewSequence() error = %v", err)
			}

			q := new(dns.Msg)
			q.SetQuestion("unknown.example.", dns.TypeA)
			qCtx := query_context.NewContext(q)
			if err := outer.Exec(context.Background(), qCtx); err != nil {
				t.Fatalf("outer.Exec() error = %v", err)
			}
			if qCtx.R() == nil || len(qCtx.R().Answer) != 1 || rrAddress(qCtx.R().Answer[0]) != tt.wantIP {
				t.Fatalf("final fallback response = %v, want %s", qCtx.R(), tt.wantIP)
			}
		})
	}
}

func TestExecNonMatchingResponseIsUnchanged(t *testing.T) {
	var resolverCalls atomic.Int32
	p := &PreferDomain{
		logger: zap.NewNop(),
		resolver: sequence.ExecutableFunc(func(context.Context, *query_context.Context) error {
			resolverCalls.Add(1)
			return nil
		}),
		rules: []compiledRule{{matcher: matcherFunc(func(netip.Addr) bool { return false })}},
	}
	q := new(dns.Msg)
	q.SetQuestion("original.example.", dns.TypeA)
	r := new(dns.Msg)
	r.SetReply(q)
	r.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: "original.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "edge.example."},
		newA("edge.example.", "198.51.100.1", 60),
	}
	r.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60}, Ns: "ns.example."}}
	r.Extra = []dns.RR{newA("ns.example.", "198.51.100.53", 60)}
	wantWire := mustPack(t, r)
	qCtx := query_context.NewContext(q)
	qCtx.SetResponse(r)
	originalPointer := qCtx.R()

	if err := p.Exec(context.Background(), qCtx); err != nil {
		t.Fatalf("Exec() error = %v", err)
	}
	assertResponseUntouched(t, qCtx, originalPointer, wantWire)
	if calls := resolverCalls.Load(); calls != 0 {
		t.Fatalf("preferred resolver calls = %d, want 0", calls)
	}
}

func TestExecWithoutResponseIsNoop(t *testing.T) {
	var resolverCalls atomic.Int32
	p := &PreferDomain{
		logger: zap.NewNop(),
		resolver: sequence.ExecutableFunc(func(context.Context, *query_context.Context) error {
			resolverCalls.Add(1)
			return nil
		}),
		rules: []compiledRule{{matcher: matcherFunc(func(netip.Addr) bool { return true })}},
	}
	q := new(dns.Msg)
	q.SetQuestion("original.example.", dns.TypeA)
	qCtx := query_context.NewContext(q)

	if err := p.Exec(context.Background(), qCtx); err != nil {
		t.Fatalf("Exec() error = %v", err)
	}
	if qCtx.R() != nil {
		t.Fatalf("Exec() created a response: %v", qCtx.R())
	}
	if calls := resolverCalls.Load(); calls != 0 {
		t.Fatalf("preferred resolver calls = %d, want 0", calls)
	}
}

func TestExecSafelyIgnoresUnsupportedResponses(t *testing.T) {
	tests := []struct {
		name   string
		qType  uint16
		qClass uint16
		rcode  int
		answer dns.RR
	}{
		{name: "TXT", qType: dns.TypeTXT, qClass: dns.ClassINET, rcode: dns.RcodeSuccess, answer: &dns.TXT{Hdr: dns.RR_Header{Name: "original.example.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"value"}}},
		{name: "HTTPS", qType: dns.TypeHTTPS, qClass: dns.ClassINET, rcode: dns.RcodeSuccess},
		{name: "MX", qType: dns.TypeMX, qClass: dns.ClassINET, rcode: dns.RcodeSuccess},
		{name: "PTR", qType: dns.TypePTR, qClass: dns.ClassINET, rcode: dns.RcodeSuccess},
		{name: "NXDOMAIN", qType: dns.TypeA, qClass: dns.ClassINET, rcode: dns.RcodeNameError},
		{name: "SERVFAIL", qType: dns.TypeA, qClass: dns.ClassINET, rcode: dns.RcodeServerFailure},
		{name: "REFUSED", qType: dns.TypeA, qClass: dns.ClassINET, rcode: dns.RcodeRefused},
		{name: "NOERROR without address", qType: dns.TypeA, qClass: dns.ClassINET, rcode: dns.RcodeSuccess, answer: &dns.CNAME{Hdr: dns.RR_Header{Name: "original.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "edge.example."}},
		{name: "non-IN class", qType: dns.TypeA, qClass: dns.ClassCHAOS, rcode: dns.RcodeSuccess, answer: newA("original.example.", "192.0.2.90", 60)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resolverCalls atomic.Int32
			p := &PreferDomain{
				logger: zap.NewNop(),
				resolver: sequence.ExecutableFunc(func(context.Context, *query_context.Context) error {
					resolverCalls.Add(1)
					return nil
				}),
				rules: []compiledRule{{matcher: matcherFunc(func(netip.Addr) bool { return true })}},
			}
			q := new(dns.Msg)
			q.SetQuestion("original.example.", tt.qType)
			q.Question[0].Qclass = tt.qClass
			r := new(dns.Msg)
			r.SetReply(q)
			r.Rcode = tt.rcode
			if tt.answer != nil {
				r.Answer = []dns.RR{tt.answer}
			}
			wantWire := mustPack(t, r)
			qCtx := query_context.NewContext(q)
			qCtx.SetResponse(r)
			originalPointer := qCtx.R()

			if err := p.Exec(context.Background(), qCtx); err != nil {
				t.Fatalf("Exec() error = %v", err)
			}
			assertResponseUntouched(t, qCtx, originalPointer, wantWire)
			if calls := resolverCalls.Load(); calls != 0 {
				t.Fatalf("preferred resolver calls = %d, want 0", calls)
			}
		})
	}
}

func TestExecColdCacheIsNonBlockingAndKeepsOriginalResponse(t *testing.T) {
	pluginCtx, cancelPlugin := context.WithCancel(context.Background())
	defer cancelPlugin()

	var resolverCalls atomic.Int32
	p := newTestPreferDomain(pluginCtx, netip.MustParseAddr("192.0.2.91"), sequence.ExecutableFunc(func(ctx context.Context, _ *query_context.Context) error {
		resolverCalls.Add(1)
		<-ctx.Done()
		return context.Cause(ctx)
	}))
	p.timeout = time.Second
	qCtx, originalPointer, wantWire := matchingQueryContext(t, "192.0.2.91")

	execCtx, cancelExec := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Exec(execCtx, qCtx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Exec() error = %v", err)
		}
	case <-time.After(50 * time.Millisecond):
		cancelExec()
		<-done
		t.Fatal("Exec() blocked on preferred-domain resolution with an empty cache")
	}
	cancelExec()

	assertResponseUntouched(t, qCtx, originalPointer, wantWire)
	if calls := resolverCalls.Load(); calls != 0 {
		t.Fatalf("preferred resolver calls = %d, want 0", calls)
	}
}

func TestInternalMarkerOnlySkipsOwningInstance(t *testing.T) {
	ownerCtx, cancelOwner := context.WithCancel(context.Background())
	defer cancelOwner()
	otherCtx, cancelOther := context.WithCancel(context.Background())
	defer cancelOther()

	var resolverCalls atomic.Int32
	owner := newTestPreferDomain(ownerCtx, netip.MustParseAddr("192.0.2.1"), addressResolver("203.0.113.1"))
	other := newTestPreferDomain(otherCtx, netip.MustParseAddr("192.0.2.93"), sequence.ExecutableFunc(func(context.Context, *query_context.Context) error {
		resolverCalls.Add(1)
		return errors.New("client request must not invoke resolver")
	}))
	cachePreferred(t, other, &other.rules[0], dns.TypeA, "203.0.113.93", 300)
	q := new(dns.Msg)
	q.SetQuestion("original.example.", dns.TypeA)
	r := new(dns.Msg)
	r.SetReply(q)
	r.Answer = []dns.RR{newA(q.Question[0].Name, "192.0.2.93", 300)}
	qCtx := query_context.NewContext(q)
	qCtx.SetResponse(r)
	qCtx.StoreValue(internalQueryKey, owner)

	if err := other.Exec(context.Background(), qCtx); err != nil {
		t.Fatalf("Exec() error = %v", err)
	}
	if resolverCalls.Load() != 0 || rrAddress(qCtx.R().Answer[0]) != "203.0.113.93" {
		t.Fatalf("marker for another instance suppressed processing: response=%v calls=%d", qCtx.R(), resolverCalls.Load())
	}
}

func TestCachedResponseTTLIsAged(t *testing.T) {
	rule := &compiledRule{preferDomain: "preferred.example."}
	msg := &dns.Msg{Answer: []dns.RR{newA(rule.preferDomain, "192.0.2.20", 300)}}
	now := time.Now()
	p := &PreferDomain{cache: map[string]cacheEntry{
		cacheKey(rule.preferDomain, dns.TypeA): {
			msg:     msg,
			stored:  now.Add(-2500 * time.Millisecond),
			expires: now.Add(time.Minute),
		},
	}}

	got, stale, err := p.getPreferredResponse(context.Background(), rule, dns.TypeA)
	if err != nil {
		t.Fatalf("getPreferredResponse() error = %v", err)
	}
	if stale {
		t.Fatal("fresh cache entry was marked stale")
	}
	if ttl := got.Answer[0].Header().Ttl; ttl >= 300 || ttl < 296 {
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
	if !stale || got.Answer[0].Header().Ttl != 0 {
		t.Fatalf("stale response = (%v, %v), want zero-TTL stale response", got, stale)
	}
}

func TestMaxStaleLimit(t *testing.T) {
	now := time.Now()
	msg := &dns.Msg{Answer: []dns.RR{newA("preferred.example.", "192.0.2.31", 300)}}
	p := &PreferDomain{serveStale: true, maxStale: time.Minute}

	if got, ok := p.getStaleResponse(cacheEntry{msg: msg, expires: now.Add(-2 * time.Minute)}, now); ok || got != nil {
		t.Fatalf("response older than max_stale was served: %v", got)
	}
	if got, ok := p.getStaleResponse(cacheEntry{msg: msg, expires: now.Add(-30 * time.Second)}, now); !ok || got == nil || got.Answer[0].Header().Ttl != 0 {
		t.Fatalf("response within max_stale was not served with zero TTL: %v", got)
	}
}

func TestZeroDNSAnswerTTLIsCachedByPositiveCacheTTL(t *testing.T) {
	pluginCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := newTestPreferDomain(pluginCtx, netip.MustParseAddr("192.0.2.40"), addressResolver("203.0.113.40"))
	p.cacheTTL = 5 * time.Minute
	rule := &p.rules[0]
	msg := preferredResponse(rule.preferDomain, dns.TypeA, "203.0.113.40", 0)

	if err := p.storePreferred(rule, dns.TypeA, msg); err != nil {
		t.Fatalf("storePreferred() rejected a DNS TTL 0 response with positive cache_ttl: %v", err)
	}
	p.mu.RLock()
	entry := p.cache[cacheKey(rule.preferDomain, dns.TypeA)]
	p.mu.RUnlock()
	if got := entry.expires.Sub(entry.stored); got != p.cacheTTL {
		t.Fatalf("stored cache lifetime = %v, want cache_ttl %v", got, p.cacheTTL)
	}

	qCtx, _, _ := matchingQueryContext(t, "192.0.2.40")
	if err := p.Exec(context.Background(), qCtx); err != nil {
		t.Fatalf("Exec() error = %v", err)
	}
	if addr, ttl := rrAddress(qCtx.R().Answer[0]), qCtx.R().Answer[0].Header().Ttl; addr != "203.0.113.40" || ttl != 0 {
		t.Fatalf("replacement = %s ttl %d, want 203.0.113.40 ttl 0", addr, ttl)
	}
}

func TestCacheTTLOverridesAnswerTTL(t *testing.T) {
	pluginCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := newTestPreferDomain(pluginCtx, netip.MustParseAddr("192.0.2.42"), addressResolver("203.0.113.42"))
	p.cacheTTL = 25 * time.Second
	msg := &dns.Msg{Answer: []dns.RR{newA("preferred.example.", "192.0.2.42", 10)}}

	if got, want := p.cacheDuration(), 25*time.Second; got != want {
		t.Fatalf("cache duration = %v, want %v", got, want)
	}
	before := time.Now()
	if err := p.storePreferred(&p.rules[0], dns.TypeA, msg); err != nil {
		t.Fatalf("storePreferred() error = %v", err)
	}
	p.mu.RLock()
	entry := p.cache[cacheKey(p.rules[0].preferDomain, dns.TypeA)]
	p.mu.RUnlock()
	if got := entry.expires.Sub(entry.stored); got != 25*time.Second {
		t.Fatalf("stored cache lifetime = %v, want 25s", got)
	}
	if entry.stored.Before(before) {
		t.Fatalf("stored timestamp %v predates store call %v", entry.stored, before)
	}
}

func TestExecKeepsPreferredDNSResponseTTL(t *testing.T) {
	pluginCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := newTestPreferDomain(pluginCtx, netip.MustParseAddr("192.0.2.43"), addressResolver("203.0.113.43"))
	p.cacheTTL = 2 * time.Minute
	cachePreferred(t, p, &p.rules[0], dns.TypeA, "203.0.113.43", 73)

	q := new(dns.Msg)
	q.SetQuestion("original.example.", dns.TypeA)
	r := new(dns.Msg)
	r.SetReply(q)
	r.Answer = []dns.RR{newA(q.Question[0].Name, "192.0.2.43", 60)}
	qCtx := query_context.NewContext(q)
	qCtx.SetResponse(r)

	if err := p.Exec(context.Background(), qCtx); err != nil {
		t.Fatalf("Exec() error = %v", err)
	}
	if ttl := qCtx.R().Answer[0].Header().Ttl; ttl < 72 || ttl > 73 {
		t.Fatalf("visible replacement TTL = %d, want freshly aged preferred DNS TTL 72..73", ttl)
	}
}

func TestPreferredCacheSeparatesAAndAAAA(t *testing.T) {
	pluginCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	p := newTestPreferDomain(pluginCtx, netip.MustParseAddr("192.0.2.41"), sequence.ExecutableFunc(func(context.Context, *query_context.Context) error {
		calls.Add(1)
		return errors.New("cache reads must not invoke resolver")
	}))
	rule := &p.rules[0]
	cachePreferred(t, p, rule, dns.TypeA, "192.0.2.41", 300)
	cachePreferred(t, p, rule, dns.TypeAAAA, "2001:db8::41", 300)

	a, _, err := p.getPreferredResponse(context.Background(), rule, dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	aaaa, _, err := p.getPreferredResponse(context.Background(), rule, dns.TypeAAAA)
	if err != nil {
		t.Fatal(err)
	}
	if got := rrAddress(a.Answer[0]); got != "192.0.2.41" {
		t.Fatalf("A cache returned %s", got)
	}
	if got := rrAddress(aaaa.Answer[0]); got != "2001:db8::41" {
		t.Fatalf("AAAA cache returned %s", got)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("resolver calls = %d, want 0", got)
	}
}

func TestWarmerWaitsForPluginsReadyThenStarts(t *testing.T) {
	pluginCtx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	var calls atomic.Int32
	p := newTestPreferDomain(pluginCtx, netip.MustParseAddr("192.0.2.50"), sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
		calls.Add(1)
		setAddressResponse(qCtx, "192.0.2.50", "2001:db8::50", 300)
		return nil
	}))
	p.cancel = cancel
	p.ready = ready
	p.warmOnStart = true
	p.initialRetryInterval = time.Millisecond
	p.initialAttempts = 10
	p.startWarmers()
	defer p.Close()

	time.Sleep(25 * time.Millisecond)
	if got := calls.Load(); got != 0 {
		t.Fatalf("resolver calls before plugins-ready = %d, want 0", got)
	}
	close(ready)
	waitForCondition(t, time.Second, func() bool { return calls.Load() == 2 }, "initial A and AAAA warm-up after plugins-ready")
	if _, _, err := p.getPreferredResponse(context.Background(), &p.rules[0], dns.TypeA); err != nil {
		t.Fatalf("A cache was not populated after ready: %v", err)
	}
	if _, _, err := p.getPreferredResponse(context.Background(), &p.rules[0], dns.TypeAAAA); err != nil {
		t.Fatalf("AAAA cache was not populated after ready: %v", err)
	}
}

func TestWarmOnStartFalseUsesCacheTTLDerivedDelay(t *testing.T) {
	pluginCtx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	firstCall := make(chan time.Time, 1)
	p := newTestPreferDomain(pluginCtx, netip.MustParseAddr("192.0.2.150"), sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
		if calls.Add(1) == 1 {
			firstCall <- time.Now()
		}
		setAddressResponse(qCtx, "203.0.113.150", "2001:db8::150", 300)
		return nil
	}))
	p.cancel = cancel
	p.ready = alreadyClosedChannel()
	p.timeout = 5 * time.Millisecond
	p.cacheTTL = 80 * time.Millisecond
	p.refreshAdvance = 40 * time.Millisecond
	p.warmOnStart = false
	started := time.Now()
	p.startWarmers()
	defer p.Close()

	var calledAt time.Time
	select {
	case calledAt = <-firstCall:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for delayed first warm-up")
	}
	if elapsed := calledAt.Sub(started); elapsed < 35*time.Millisecond {
		t.Fatalf("first resolver call started after %v, want cache_ttl-derived delay near 40ms", elapsed)
	}
	waitForCondition(t, time.Second, func() bool { return calls.Load() == 2 }, "delayed A and AAAA warm-up")
}

func TestInitialWarmRetriesTransientFailuresUntilSuccess(t *testing.T) {
	tests := []struct {
		name    string
		failure func(context.Context, *query_context.Context) error
	}{
		{
			name: "execution error",
			failure: func(context.Context, *query_context.Context) error {
				return errors.New("temporary network error")
			},
		},
		{
			name: "SERVFAIL",
			failure: func(_ context.Context, qCtx *query_context.Context) error {
				r := new(dns.Msg)
				r.SetReply(qCtx.Q())
				r.Rcode = dns.RcodeServerFailure
				qCtx.SetResponse(r)
				return nil
			},
		},
		{
			name: "timeout",
			failure: func(ctx context.Context, _ *query_context.Context) error {
				<-ctx.Done()
				return context.Cause(ctx)
			},
		},
		{
			name: "no response",
			failure: func(context.Context, *query_context.Context) error {
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pluginCtx, cancel := context.WithCancel(context.Background())
			var calls atomic.Int32
			p := newTestPreferDomain(pluginCtx, netip.MustParseAddr("192.0.2.51"), sequence.ExecutableFunc(func(ctx context.Context, qCtx *query_context.Context) error {
				if qCtx.Q().Question[0].Qtype == dns.TypeAAAA {
					setAddressResponse(qCtx, "203.0.113.51", "2001:db8::51", 300)
					return nil
				}
				if calls.Add(1) <= 2 {
					return tt.failure(ctx, qCtx)
				}
				setAddressResponse(qCtx, "203.0.113.51", "2001:db8::51", 300)
				return nil
			}))
			p.cancel = cancel
			p.ready = alreadyClosedChannel()
			p.timeout = 4 * time.Millisecond
			p.warmOnStart = true
			p.initialRetryInterval = time.Millisecond
			p.initialAttempts = 10
			p.startWarmers()
			defer p.Close()

			waitForCondition(t, time.Second, func() bool { return calls.Load() == 3 }, "third initial warm attempt")
			if got := calls.Load(); got != 3 {
				t.Fatalf("resolver calls = %d, want 3", got)
			}
			waitForCondition(t, time.Second, func() bool {
				got, _, err := p.getPreferredResponse(context.Background(), &p.rules[0], dns.TypeA)
				return err == nil && rrAddress(got.Answer[0]) == "203.0.113.51"
			}, "cache population after transient failures")
			if got, _, err := p.getPreferredResponse(context.Background(), &p.rules[0], dns.TypeA); err != nil || rrAddress(got.Answer[0]) != "203.0.113.51" {
				t.Fatalf("cached response = %v, err = %v", got, err)
			}
		})
	}
}

func TestWarmRetryPolicyConstants(t *testing.T) {
	if initialWarmAttempts != 10 {
		t.Fatalf("initial warm attempts = %d, want 10", initialWarmAttempts)
	}
	if initialWarmRetryInterval != 15*time.Second {
		t.Fatalf("initial warm retry interval = %v, want 15s", initialWarmRetryInterval)
	}
	if periodicRefreshAttempts != 2 {
		t.Fatalf("periodic refresh attempts = %d, want 2", periodicRefreshAttempts)
	}
}

func TestInitialWarmRetriesAtMostTenTimes(t *testing.T) {
	pluginCtx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	tenthAttempt := make(chan struct{})
	p := newTestPreferDomain(pluginCtx, netip.MustParseAddr("192.0.2.52"), sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
		if qCtx.Q().Question[0].Qtype == dns.TypeAAAA {
			setAddressResponse(qCtx, "203.0.113.52", "2001:db8::52", 300)
			return nil
		}
		if calls.Add(1) == 10 {
			close(tenthAttempt)
		}
		return errors.New("temporary network error")
	}))
	p.cancel = cancel
	p.ready = alreadyClosedChannel()
	p.warmOnStart = true
	p.initialRetryInterval = time.Millisecond
	p.initialAttempts = 10
	p.startWarmers()
	defer p.Close()

	waitForSignal(t, tenthAttempt, time.Second, "tenth initial warm attempt")
	time.Sleep(5 * time.Millisecond)
	if got := calls.Load(); got != 10 {
		t.Fatalf("resolver calls = %d, want exactly 10", got)
	}
	if _, _, err := p.getPreferredResponse(context.Background(), &p.rules[0], dns.TypeA); !errors.Is(err, errPreferredCacheUnavailable) {
		t.Fatalf("cold cache error = %v, want %v", err, errPreferredCacheUnavailable)
	}
}

func TestInitialWarmDoesNotBurstRetryTerminalResponses(t *testing.T) {
	tests := []struct {
		name  string
		rcode int
	}{
		{name: "NXDOMAIN", rcode: dns.RcodeNameError},
		{name: "NODATA", rcode: dns.RcodeSuccess},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pluginCtx, cancel := context.WithCancel(context.Background())
			var calls atomic.Int32
			p := newTestPreferDomain(pluginCtx, netip.MustParseAddr("192.0.2.53"), sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
				if qCtx.Q().Question[0].Qtype == dns.TypeAAAA {
					setAddressResponse(qCtx, "203.0.113.53", "2001:db8::53", 300)
					return nil
				}
				calls.Add(1)
				r := new(dns.Msg)
				r.SetReply(qCtx.Q())
				r.Rcode = tt.rcode
				qCtx.SetResponse(r)
				return nil
			}))
			p.cancel = cancel
			p.ready = alreadyClosedChannel()
			p.warmOnStart = true
			p.initialRetryInterval = time.Millisecond
			p.initialAttempts = 10
			p.startWarmers()
			defer p.Close()

			waitForCondition(t, time.Second, func() bool { return calls.Load() == 1 }, "terminal initial response")
			time.Sleep(10 * time.Millisecond)
			if got := calls.Load(); got != 1 {
				t.Fatalf("resolver calls = %d, want 1", got)
			}
		})
	}
}

func TestSuccessfulTargetRefreshesWhileSiblingStillRetriesInitially(t *testing.T) {
	pluginCtx, cancel := context.WithCancel(context.Background())
	secondARefresh := make(chan struct{})
	var aCalls atomic.Int32
	var aaaaCalls atomic.Int32
	p := newTestPreferDomain(pluginCtx, netip.MustParseAddr("192.0.2.153"), sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
		if qCtx.Q().Question[0].Qtype == dns.TypeA {
			if aCalls.Add(1) == 2 {
				close(secondARefresh)
			}
			setAddressResponse(qCtx, "203.0.113.153", "2001:db8::153", 300)
			return nil
		}
		aaaaCalls.Add(1)
		r := new(dns.Msg)
		r.SetReply(qCtx.Q())
		r.Rcode = dns.RcodeServerFailure
		qCtx.SetResponse(r)
		return nil
	}))
	p.cancel = cancel
	p.ready = alreadyClosedChannel()
	p.timeout = 5 * time.Millisecond
	p.cacheTTL = 80 * time.Millisecond
	p.refreshAdvance = 40 * time.Millisecond
	p.warmOnStart = true
	p.initialRetryInterval = 30 * time.Millisecond
	p.initialAttempts = 10
	p.startWarmers()
	defer p.Close()

	waitForSignal(t, secondARefresh, 200*time.Millisecond, "successful A target's independent early refresh")
	if got := aaaaCalls.Load(); got >= 10 {
		t.Fatalf("A refresh waited for sibling retries to finish: AAAA attempts=%d", got)
	}
}

func TestInitialWarmExhaustionPassesThroughUntilCacheTTLRetry(t *testing.T) {
	pluginCtx, cancel := context.WithCancel(context.Background())
	exhausted := make(chan struct{})
	nextRefreshAttempted := make(chan struct{})
	allowNextRefresh := make(chan struct{})
	var aCalls atomic.Int32
	p := newTestPreferDomain(pluginCtx, netip.MustParseAddr("192.0.2.54"), sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
		if qCtx.Q().Question[0].Qtype == dns.TypeAAAA {
			setAddressResponse(qCtx, "203.0.113.54", "2001:db8::54", 300)
			return nil
		}
		n := aCalls.Add(1)
		if n <= 10 {
			if n == 10 {
				close(exhausted)
			}
			r := new(dns.Msg)
			r.SetReply(qCtx.Q())
			r.Rcode = dns.RcodeServerFailure
			qCtx.SetResponse(r)
			return nil
		}
		if n == 11 {
			close(nextRefreshAttempted)
			select {
			case <-allowNextRefresh:
			case <-pluginCtx.Done():
				return context.Cause(pluginCtx)
			}
		}
		setAddressResponse(qCtx, "203.0.113.54", "2001:db8::54", 300)
		return nil
	}))
	p.cancel = cancel
	p.ready = alreadyClosedChannel()
	p.timeout = 10 * time.Millisecond
	p.cacheTTL = 80 * time.Millisecond
	p.refreshAdvance = 40 * time.Millisecond
	p.warmOnStart = true
	p.initialRetryInterval = time.Millisecond
	p.initialAttempts = 10
	p.startWarmers()
	defer func() {
		select {
		case <-allowNextRefresh:
		default:
			close(allowNextRefresh)
		}
		p.Close()
	}()

	waitForSignal(t, exhausted, time.Second, "ten initial attempts")
	callsBeforeExec := aCalls.Load()
	qCtx, originalPointer, wantWire := matchingQueryContext(t, "192.0.2.54")
	if err := p.Exec(context.Background(), qCtx); err != nil {
		t.Fatalf("Exec() error = %v", err)
	}
	assertResponseUntouched(t, qCtx, originalPointer, wantWire)
	if got := aCalls.Load(); got != callsBeforeExec {
		t.Fatalf("client request triggered preferred resolution: calls changed from %d to %d", callsBeforeExec, got)
	}

	waitForSignal(t, nextRefreshAttempted, time.Second, "cache_ttl-derived refresh retry")
	close(allowNextRefresh)
	waitForCondition(t, time.Second, func() bool {
		_, _, err := p.getPreferredResponse(context.Background(), &p.rules[0], dns.TypeA)
		return err == nil
	}, "successful cache_ttl-derived refresh")
	freshCtx, _, _ := matchingQueryContext(t, "192.0.2.54")
	if err := p.Exec(context.Background(), freshCtx); err != nil {
		t.Fatalf("Exec() error after refresh = %v", err)
	}
	if got := rrAddress(freshCtx.R().Answer[0]); got != "203.0.113.54" {
		t.Fatalf("replacement after cache_ttl retry = %s, want 203.0.113.54", got)
	}
}

func TestRefreshDelayUsesFixedAdvanceBeforeCacheExpiry(t *testing.T) {
	tests := []struct {
		name           string
		cacheTTL       time.Duration
		refreshAdvance time.Duration
		want           time.Duration
	}{
		{
			name:     "production five second advance",
			cacheTTL: 301 * time.Second,
			want:     296 * time.Second,
		},
		{
			name:           "short test window override",
			cacheTTL:       80 * time.Millisecond,
			refreshAdvance: 40 * time.Millisecond,
			want:           40 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &PreferDomain{cacheTTL: tt.cacheTTL, refreshAdvance: tt.refreshAdvance}
			if got := p.refreshDelay(); got != tt.want {
				t.Fatalf("refreshDelay() = %v, want %v", got, tt.want)
			}

			stored := time.Now()
			target := warmTarget{key: cacheKey("preferred.example.", dns.TypeA)}
			p.cache = map[string]cacheEntry{
				target.key: {
					msg:     preferredResponse("preferred.example.", dns.TypeA, "203.0.113.55", 300),
					stored:  stored,
					expires: stored.Add(tt.cacheTTL),
				},
			}
			wantAt := stored.Add(tt.want)
			if got := p.nextRefreshAfterSuccess(target, stored); !got.Equal(wantAt) {
				t.Fatalf("nextRefreshAfterSuccess() = %v, want %v", got, wantAt)
			}
		})
	}
}

func TestNextRefreshAfterFailureStaysAnchoredAndSkipsElapsedWindows(t *testing.T) {
	stored := time.Unix(1_700_000_000, 0)
	target := warmTarget{key: cacheKey("preferred.example.", dns.TypeA)}
	p := &PreferDomain{
		cacheTTL:       20 * time.Second,
		refreshAdvance: 5 * time.Second,
		cache: map[string]cacheEntry{
			target.key: {
				msg:     preferredResponse("preferred.example.", dns.TypeA, "203.0.113.55", 300),
				stored:  stored,
				expires: stored.Add(20 * time.Second),
			},
		},
	}

	tests := []struct {
		name       string
		nowOffset  time.Duration
		wantOffset time.Duration
	}{
		{name: "upcoming first window", nowOffset: 14 * time.Second, wantOffset: 15 * time.Second},
		{name: "completed first window advances one ttl", nowOffset: 15 * time.Second, wantOffset: 35 * time.Second},
		{name: "late worker skips all missed windows", nowOffset: 76 * time.Second, wantOffset: 95 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := stored.Add(tt.nowOffset)
			want := stored.Add(tt.wantOffset)
			got := p.nextRefreshAfterFailure(target, stored.Add(15*time.Second), now)
			if !got.Equal(want) {
				t.Fatalf("nextRefreshAfterFailure() = %v, want anchored window %v", got, want)
			}
			if !got.After(now) {
				t.Fatalf("nextRefreshAfterFailure() = %v is not after now %v; worker could burst", got, now)
			}
		})
	}

	delete(p.cache, target.key)
	if got, want := p.nextRefreshAfterFailure(
		target,
		stored.Add(15*time.Second),
		stored.Add(76*time.Second),
	), stored.Add(95*time.Second); !got.Equal(want) {
		t.Fatalf("cold-cache nextRefreshAfterFailure() = %v, want anchored window %v", got, want)
	}
}

func TestPeriodicRefreshRetriesImmediatelyAndSecondAttemptReplacesExpiredCache(t *testing.T) {
	pluginCtx, cancel := context.WithCancel(context.Background())
	firstRefreshFailed := make(chan struct{})
	secondAttemptStarted := make(chan struct{})
	allowSecondAttempt := make(chan struct{})
	var aCalls atomic.Int32
	p := newTestPreferDomain(pluginCtx, netip.MustParseAddr("192.0.2.56"), sequence.ExecutableFunc(func(ctx context.Context, qCtx *query_context.Context) error {
		if qCtx.Q().Question[0].Qtype == dns.TypeAAAA {
			r := new(dns.Msg)
			r.SetReply(qCtx.Q())
			r.Rcode = dns.RcodeNameError
			qCtx.SetResponse(r)
			return nil
		}
		switch aCalls.Add(1) {
		case 1:
			setAddressResponse(qCtx, "203.0.113.56", "2001:db8::56", 300)
			return nil
		case 2:
			close(firstRefreshFailed)
			return errors.New("temporary refresh failure")
		case 3:
			close(secondAttemptStarted)
			select {
			case <-allowSecondAttempt:
			case <-ctx.Done():
				return context.Cause(ctx)
			}
			setAddressResponse(qCtx, "203.0.113.156", "2001:db8::156", 300)
			return nil
		default:
			setAddressResponse(qCtx, "203.0.113.156", "2001:db8::156", 300)
			return nil
		}
	}))
	p.cancel = cancel
	p.ready = alreadyClosedChannel()
	p.timeout = 5 * time.Millisecond
	p.cacheTTL = 80 * time.Millisecond
	p.refreshAdvance = 40 * time.Millisecond
	p.warmOnStart = true
	p.serveStale = true
	p.initialRetryInterval = time.Millisecond
	p.initialAttempts = 10
	p.startWarmers()
	defer func() {
		select {
		case <-allowSecondAttempt:
		default:
			close(allowSecondAttempt)
		}
		p.Close()
	}()

	waitForSignal(t, firstRefreshFailed, time.Second, "first early periodic refresh failure")
	waitForSignal(t, secondAttemptStarted, 100*time.Millisecond, "immediate second periodic refresh attempt")
	if got := aCalls.Load(); got != 3 {
		t.Fatalf("A resolver calls after second periodic attempt started = %d, want 3 (initial plus two periodic attempts)", got)
	}
	key := cacheKey(p.rules[0].preferDomain, dns.TypeA)
	p.mu.RLock()
	entryAfterFailure := p.cache[key]
	p.mu.RUnlock()
	if got := rrAddress(entryAfterFailure.msg.Answer[0]); got != "203.0.113.56" {
		t.Fatalf("periodic failure overwrote old cache with %s", got)
	}
	waitForCondition(t, time.Second, func() bool { return time.Now().After(entryAfterFailure.expires) }, "old cache expiry")

	callsBeforeExec := aCalls.Load()
	staleCtx, _, _ := matchingQueryContext(t, "192.0.2.56")
	if err := p.Exec(context.Background(), staleCtx); err != nil {
		t.Fatalf("Exec() with stale cache error = %v", err)
	}
	if addr, ttl := rrAddress(staleCtx.R().Answer[0]), staleCtx.R().Answer[0].Header().Ttl; addr != "203.0.113.56" || ttl != 0 {
		t.Fatalf("stale replacement = %s ttl %d, want 203.0.113.56 ttl 0", addr, ttl)
	}
	if got := aCalls.Load(); got != callsBeforeExec {
		t.Fatalf("stale client request invoked resolver: calls changed from %d to %d", callsBeforeExec, got)
	}

	close(allowSecondAttempt)
	waitForCondition(t, time.Second, func() bool {
		p.mu.RLock()
		defer p.mu.RUnlock()
		ce := p.cache[key]
		return ce.msg != nil && rrAddress(ce.msg.Answer[0]) == "203.0.113.156"
	}, "new cache value")
	freshCtx, _, _ := matchingQueryContext(t, "192.0.2.56")
	if err := p.Exec(context.Background(), freshCtx); err != nil {
		t.Fatalf("Exec() with refreshed cache error = %v", err)
	}
	if got := rrAddress(freshCtx.R().Answer[0]); got != "203.0.113.156" {
		t.Fatalf("replacement after recovery = %s, want 203.0.113.156", got)
	}
}

func TestPeriodicRefreshRetriesAnyFailureOnceAndNeverAThirdTime(t *testing.T) {
	tests := []struct {
		name    string
		failure func(context.Context, *query_context.Context) error
	}{
		{
			name: "execution error",
			failure: func(context.Context, *query_context.Context) error {
				return errors.New("temporary network error")
			},
		},
		{
			name: "timeout",
			failure: func(ctx context.Context, _ *query_context.Context) error {
				<-ctx.Done()
				return context.Cause(ctx)
			},
		},
		{
			name: "SERVFAIL",
			failure: func(_ context.Context, qCtx *query_context.Context) error {
				r := new(dns.Msg)
				r.SetReply(qCtx.Q())
				r.Rcode = dns.RcodeServerFailure
				qCtx.SetResponse(r)
				return nil
			},
		},
		{
			name: "NXDOMAIN",
			failure: func(_ context.Context, qCtx *query_context.Context) error {
				r := new(dns.Msg)
				r.SetReply(qCtx.Q())
				r.Rcode = dns.RcodeNameError
				qCtx.SetResponse(r)
				return nil
			},
		},
		{
			name: "NODATA",
			failure: func(_ context.Context, qCtx *query_context.Context) error {
				r := new(dns.Msg)
				r.SetReply(qCtx.Q())
				qCtx.SetResponse(r)
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pluginCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var calls atomic.Int32
			p := newTestPreferDomain(pluginCtx, netip.MustParseAddr("192.0.2.157"), sequence.ExecutableFunc(func(ctx context.Context, qCtx *query_context.Context) error {
				calls.Add(1)
				return tt.failure(ctx, qCtx)
			}))
			p.timeout = 5 * time.Millisecond

			started := time.Now()
			err := p.runPeriodicRefreshTarget(warmTargetFor(&p.rules[0], dns.TypeA))
			if err == nil {
				t.Fatal("runPeriodicRefreshTarget() succeeded, want failure")
			}
			if got := calls.Load(); got != 2 {
				t.Fatalf("resolver calls = %d, want exactly 2", got)
			}
			if elapsed := time.Since(started); elapsed >= time.Second {
				t.Fatalf("two periodic attempts took %v; second attempt was not immediate", elapsed)
			}
		})
	}
}

func TestPeriodicDoubleFailurePreservesExpiredCacheAccordingToServeStale(t *testing.T) {
	tests := []struct {
		name       string
		serveStale bool
	}{
		{name: "serve stale", serveStale: true},
		{name: "do not serve stale", serveStale: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pluginCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var calls atomic.Int32
			p := newTestPreferDomain(pluginCtx, netip.MustParseAddr("192.0.2.158"), sequence.ExecutableFunc(func(context.Context, *query_context.Context) error {
				calls.Add(1)
				return errors.New("periodic refresh unavailable")
			}))
			p.serveStale = tt.serveStale
			key := cacheKey(p.rules[0].preferDomain, dns.TypeA)
			stored := time.Now()
			expires := stored.Add(p.cacheTTL)
			p.cache[key] = cacheEntry{
				msg:     preferredResponse(p.rules[0].preferDomain, dns.TypeA, "203.0.113.158", 300),
				stored:  stored,
				expires: expires,
			}

			if err := p.runPeriodicRefreshTarget(warmTargetFor(&p.rules[0], dns.TypeA)); err == nil {
				t.Fatal("runPeriodicRefreshTarget() succeeded, want failure after two attempts")
			}
			if got := calls.Load(); got != 2 {
				t.Fatalf("resolver calls = %d, want exactly 2", got)
			}
			p.mu.RLock()
			preserved := p.cache[key]
			p.mu.RUnlock()
			if got := rrAddress(preserved.msg.Answer[0]); got != "203.0.113.158" || !preserved.stored.Equal(stored) || !preserved.expires.Equal(expires) {
				t.Fatalf("double failure changed old cache: addr=%s stored=%v expires=%v", got, preserved.stored, preserved.expires)
			}

			p.mu.Lock()
			preserved.expires = time.Now().Add(-time.Millisecond)
			p.cache[key] = preserved
			p.mu.Unlock()

			qCtx, originalPointer, wantWire := matchingQueryContext(t, "192.0.2.158")
			callsBeforeExec := calls.Load()
			if err := p.Exec(context.Background(), qCtx); err != nil {
				t.Fatalf("Exec() error = %v", err)
			}
			if got := calls.Load(); got != callsBeforeExec {
				t.Fatalf("client request invoked resolver: calls changed from %d to %d", callsBeforeExec, got)
			}
			if !tt.serveStale {
				assertResponseUntouched(t, qCtx, originalPointer, wantWire)
				return
			}
			if addr, ttl := rrAddress(qCtx.R().Answer[0]), qCtx.R().Answer[0].Header().Ttl; addr != "203.0.113.158" || ttl != 0 {
				t.Fatalf("stale replacement = %s ttl %d, want 203.0.113.158 ttl 0", addr, ttl)
			}
		})
	}
}

func TestCloseCancelsReadyWaitAndInitialRetryWait(t *testing.T) {
	t.Run("plugins-ready wait", func(t *testing.T) {
		pluginCtx, cancel := context.WithCancel(context.Background())
		ready := make(chan struct{})
		var calls atomic.Int32
		p := newTestPreferDomain(pluginCtx, netip.MustParseAddr("192.0.2.57"), sequence.ExecutableFunc(func(context.Context, *query_context.Context) error {
			calls.Add(1)
			return nil
		}))
		p.cancel = cancel
		p.ready = ready
		p.warmOnStart = true
		p.startWarmers()
		closeWithin(t, p)
		if got := calls.Load(); got != 0 {
			t.Fatalf("resolver calls while waiting for ready = %d, want 0", got)
		}
	})

	t.Run("initial retry wait", func(t *testing.T) {
		pluginCtx, cancel := context.WithCancel(context.Background())
		firstAttempt := make(chan struct{}, 1)
		var calls atomic.Int32
		p := newTestPreferDomain(pluginCtx, netip.MustParseAddr("192.0.2.58"), sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
			calls.Add(1)
			select {
			case firstAttempt <- struct{}{}:
			default:
			}
			r := new(dns.Msg)
			r.SetReply(qCtx.Q())
			r.Rcode = dns.RcodeServerFailure
			qCtx.SetResponse(r)
			return nil
		}))
		p.cancel = cancel
		p.ready = alreadyClosedChannel()
		p.warmOnStart = true
		p.initialRetryInterval = time.Hour
		p.initialAttempts = 10
		p.startWarmers()
		waitForSignal(t, firstAttempt, time.Second, "first initial warm attempt")
		closeWithin(t, p)
		if got := calls.Load(); got > 2 {
			t.Fatalf("Close() allowed retry burst: calls=%d", got)
		}
	})
}

func TestPluginInstancesKeepIndependentPreferredCaches(t *testing.T) {
	ctxOne, cancelOne := context.WithCancel(context.Background())
	defer cancelOne()
	ctxTwo, cancelTwo := context.WithCancel(context.Background())
	defer cancelTwo()
	var callsOne atomic.Int32
	var callsTwo atomic.Int32
	pOne := newTestPreferDomain(ctxOne, netip.MustParseAddr("192.0.2.59"), sequence.ExecutableFunc(func(context.Context, *query_context.Context) error {
		callsOne.Add(1)
		return errors.New("client request must not resolve")
	}))
	pOne.cancel = cancelOne
	pTwo := newTestPreferDomain(ctxTwo, netip.MustParseAddr("192.0.2.59"), sequence.ExecutableFunc(func(context.Context, *query_context.Context) error {
		callsTwo.Add(1)
		return errors.New("client request must not resolve")
	}))
	pTwo.cancel = cancelTwo
	cachePreferred(t, pOne, &pOne.rules[0], dns.TypeA, "203.0.113.59", 300)

	firstCtx, _, _ := matchingQueryContext(t, "192.0.2.59")
	if err := pOne.Exec(context.Background(), firstCtx); err != nil {
		t.Fatal(err)
	}
	if got := rrAddress(firstCtx.R().Answer[0]); got != "203.0.113.59" {
		t.Fatalf("first instance replacement = %s", got)
	}
	secondColdCtx, secondPointer, secondWire := matchingQueryContext(t, "192.0.2.59")
	if err := pTwo.Exec(context.Background(), secondColdCtx); err != nil {
		t.Fatal(err)
	}
	assertResponseUntouched(t, secondColdCtx, secondPointer, secondWire)

	cachePreferred(t, pTwo, &pTwo.rules[0], dns.TypeA, "203.0.113.159", 300)
	firstAgain, _, _ := matchingQueryContext(t, "192.0.2.59")
	secondFresh, _, _ := matchingQueryContext(t, "192.0.2.59")
	if err := pOne.Exec(context.Background(), firstAgain); err != nil {
		t.Fatal(err)
	}
	if err := pTwo.Exec(context.Background(), secondFresh); err != nil {
		t.Fatal(err)
	}
	if one, two := rrAddress(firstAgain.R().Answer[0]), rrAddress(secondFresh.R().Answer[0]); one != "203.0.113.59" || two != "203.0.113.159" {
		t.Fatalf("instance cache values = (%s, %s), want independent values", one, two)
	}
	if callsOne.Load() != 0 || callsTwo.Load() != 0 {
		t.Fatalf("client requests invoked resolvers: first=%d second=%d", callsOne.Load(), callsTwo.Load())
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
			if q.Question[0].Qtype == dns.TypeA {
				r.Answer = []dns.RR{newA(q.Question[0].Name, "192.0.2.70", 300)}
			} else {
				r.Answer = []dns.RR{newAAAA(q.Question[0].Name, "2001:db8::70", 300)}
			}
			qCtx.SetResponse(r)
			return nil
		}),
		rules: []compiledRule{
			{preferDomain: "Preferred.Example.", preferDisplay: "Preferred.Example"},
			{preferDomain: "preferred.example.", preferDisplay: "preferred.example"},
		},
		timeout:  time.Second,
		cacheTTL: 5 * time.Minute,
		cache:    make(map[string]cacheEntry),
		ctx:      pluginCtx,
		cancel:   cancel,
	}

	p.warmAll()
	if got := calls.Load(); got != 2 {
		t.Fatalf("resolver calls = %d, want 2 (one A and one AAAA)", got)
	}
}

func TestParseFixedDurationDefaultsAndUnits(t *testing.T) {
	tests := []struct {
		name         string
		value        string
		defaultValue int64
		unit         time.Duration
		want         time.Duration
		wantErr      bool
	}{
		{name: "preferred timeout default", defaultValue: defaultTimeoutMilliseconds, unit: time.Millisecond, want: 500 * time.Millisecond},
		{name: "cache ttl default", defaultValue: 0, unit: time.Second, want: 0},
		{name: "cache ttl seconds", value: "301", unit: time.Second, want: 301 * time.Second},
		{name: "seconds", value: "60", unit: time.Second, want: time.Minute},
		{name: "explicit zero", value: "0", unit: time.Second, want: 0},
		{name: "unit suffix rejected", value: "500ms", unit: time.Millisecond, wantErr: true},
		{name: "negative rejected", value: "-1", unit: time.Millisecond, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseFixedDuration(tt.value, tt.defaultValue, tt.unit)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseFixedDuration() = %v, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseFixedDuration() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("parseFixedDuration() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestArgsWeakDecodeRejectsRemovedRefreshFields(t *testing.T) {
	var accepted Args
	if err := utils.WeakDecode(map[string]any{"cache_ttl": "301"}, &accepted); err != nil {
		t.Fatalf("WeakDecode() rejected cache_ttl: %v", err)
	}
	if accepted.CacheTTL != "301" {
		t.Fatalf("decoded cache_ttl = %q, want 301", accepted.CacheTTL)
	}

	tests := []struct {
		name  string
		key   string
		value any
	}{
		{name: "warm interval", key: "warm_interval", value: "300"},
		{name: "internal ttl binding", key: "bind_ttl_to_warm_interval", value: true},
		{name: "response ttl binding", key: "bind_response_ttl_to_warm_interval", value: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var args Args
			err := utils.WeakDecode(map[string]any{
				"cache_ttl": "301",
				tt.key:      tt.value,
			}, &args)
			if err == nil {
				t.Fatalf("WeakDecode() accepted removed field %q", tt.key)
			}
			if !strings.Contains(err.Error(), tt.key) {
				t.Fatalf("WeakDecode() error = %v, want it to identify %q", err, tt.key)
			}
		})
	}
}

func TestInitValidatesCacheTTLRefreshBounds(t *testing.T) {
	resolver := sequence.ExecutableFunc(func(context.Context, *query_context.Context) error { return nil })
	provider := matcherProvider{matcher: matcherFunc(func(netip.Addr) bool { return true })}
	m := coremain.NewTestMosdnsWithPlugins(map[string]any{
		"resolver": resolver,
		"matcher":  provider,
	})
	bp := coremain.NewBP("prefer-domain-test", m)

	tests := []struct {
		name     string
		cacheTTL string
		timeout  string
		wantTTL  time.Duration
		wantErr  string
	}{
		{name: "cache ttl omitted", wantErr: "cache_ttl must be greater than 5 seconds"},
		{name: "cache ttl zero", cacheTTL: "0", wantErr: "cache_ttl must be greater than 5 seconds"},
		{name: "cache ttl five seconds", cacheTTL: "5", wantErr: "cache_ttl must be greater than 5 seconds"},
		{name: "cache ttl six seconds", cacheTTL: "6", wantTTL: 6 * time.Second},
		{name: "timeout zero", cacheTTL: "6", timeout: "0", wantErr: "timeout must be greater than 0"},
		{name: "timeout equals two point five seconds", cacheTTL: "6", timeout: "2500", wantErr: "timeout must be less than 2.5s"},
		{name: "timeout above two point five seconds", cacheTTL: "6", timeout: "2501", wantErr: "timeout must be less than 2.5s"},
		{name: "timeout just below boundary", cacheTTL: "6", timeout: "2499", wantTTL: 6 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Init(bp, &Args{
				Resolver:     "resolver",
				IPMatcher:    "matcher",
				PreferDomain: "preferred.example",
				Timeout:      tt.timeout,
				CacheTTL:     tt.cacheTTL,
			})
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Init() error = %v, want an error containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Init() error = %v", err)
			}
			p, ok := got.(*PreferDomain)
			if !ok {
				t.Fatalf("Init() returned %T, want *PreferDomain", got)
			}
			if p.cacheTTL != tt.wantTTL {
				t.Fatalf("cache TTL = %v, want %v", p.cacheTTL, tt.wantTTL)
			}
			if err := p.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
		})
	}
}

func newTestPreferDomain(pluginCtx context.Context, matchAddr netip.Addr, resolver sequence.Executable) *PreferDomain {
	ctx, cancel := context.WithCancel(pluginCtx)
	return &PreferDomain{
		logger:   zap.NewNop(),
		resolver: resolver,
		rules: []compiledRule{{
			ipMatcherTag:  "test-ip-set",
			preferDomain:  "preferred.example.",
			preferDisplay: "preferred.example",
			matcher: matcherFunc(func(addr netip.Addr) bool {
				return addr == matchAddr
			}),
		}},
		timeout:  time.Second,
		cacheTTL: 5 * time.Minute,
		cache:    make(map[string]cacheEntry),
		ctx:      ctx,
		cancel:   cancel,
	}
}

func warmTargetFor(rule *compiledRule, qType uint16) warmTarget {
	return warmTarget{
		rule:  rule,
		qType: qType,
		key:   cacheKey(rule.preferDomain, qType),
	}
}

func preferredResponse(name string, qType uint16, ip string, ttl uint32) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qType)
	r := new(dns.Msg)
	r.SetReply(q)
	if qType == dns.TypeA {
		r.Answer = []dns.RR{newA(q.Question[0].Name, ip, ttl)}
	} else {
		r.Answer = []dns.RR{newAAAA(q.Question[0].Name, ip, ttl)}
	}
	return r
}

func cachePreferred(t *testing.T, p *PreferDomain, rule *compiledRule, qType uint16, ip string, ttl uint32) {
	t.Helper()
	if err := p.storePreferred(rule, qType, preferredResponse(rule.preferDomain, qType, ip, ttl)); err != nil {
		t.Fatalf("storePreferred() error = %v", err)
	}
}

func setAddressResponse(qCtx *query_context.Context, ipv4, ipv6 string, ttl uint32) {
	q := qCtx.Q()
	r := new(dns.Msg)
	r.SetReply(q)
	if q.Question[0].Qtype == dns.TypeA {
		r.Answer = []dns.RR{newA(q.Question[0].Name, ipv4, ttl)}
	} else {
		r.Answer = []dns.RR{newAAAA(q.Question[0].Name, ipv6, ttl)}
	}
	qCtx.SetResponse(r)
}

func matchingQueryContext(t *testing.T, ip string) (*query_context.Context, *dns.Msg, []byte) {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion("original.example.", dns.TypeA)
	r := new(dns.Msg)
	r.SetReply(q)
	r.Answer = []dns.RR{newA(q.Question[0].Name, ip, 300)}
	qCtx := query_context.NewContext(q)
	qCtx.SetResponse(r)
	return qCtx, r, mustPack(t, r)
}

func alreadyClosedChannel() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

func waitForSignal(t *testing.T, ch <-chan struct{}, timeout time.Duration, description string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func waitForCondition(t *testing.T, timeout time.Duration, condition func() bool, description string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	if !condition() {
		t.Fatalf("timed out waiting for %s", description)
	}
}

func closeWithin(t *testing.T, p *PreferDomain) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- p.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("Close() did not cancel the background wait promptly")
	}
}

func addressResolver(ip string) sequence.Executable {
	return sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
		q := qCtx.Q()
		r := new(dns.Msg)
		r.SetReply(q)
		if q.Question[0].Qtype == dns.TypeA {
			r.Answer = []dns.RR{newA(q.Question[0].Name, ip, 300)}
		} else {
			r.Answer = []dns.RR{newAAAA(q.Question[0].Name, ip, 300)}
		}
		qCtx.SetResponse(r)
		return nil
	})
}

func assertResponseUntouched(t *testing.T, qCtx *query_context.Context, originalPointer *dns.Msg, wantWire []byte) {
	t.Helper()
	if qCtx.R() != originalPointer {
		t.Fatal("plugin replaced a response that should have remained untouched")
	}
	if gotWire := mustPack(t, qCtx.R()); !bytes.Equal(gotWire, wantWire) {
		t.Fatalf("response changed:\n got: %v\nwant: %v", qCtx.R(), wantWire)
	}
}

func mustPack(t *testing.T, msg *dns.Msg) []byte {
	t.Helper()
	b, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack DNS message: %v", err)
	}
	return b
}

func rrAddress(rr dns.RR) string {
	switch rr := rr.(type) {
	case *dns.A:
		return rr.A.String()
	case *dns.AAAA:
		return rr.AAAA.String()
	default:
		return ""
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
