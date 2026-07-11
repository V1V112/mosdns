package prefer_domain

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	sequencefallback "github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence/fallback"
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

	got, ok := buildReplacedResponse(original, preferred, dns.TypeA, "edge.example.", 0)
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

func TestBuildReplacedResponseForcesAddressTTL(t *testing.T) {
	original := &dns.Msg{Answer: []dns.RR{newA("original.example.", "192.0.2.1", 100)}}
	preferred := &dns.Msg{Answer: []dns.RR{newA("preferred.example.", "203.0.113.1", 300)}}

	got, ok := buildReplacedResponse(original, preferred, dns.TypeA, "original.example.", 301)
	if !ok {
		t.Fatal("buildReplacedResponse() rejected a usable response")
	}
	if ttl := got.Answer[0].Header().Ttl; ttl != 301 {
		t.Fatalf("replacement TTL = %d, want 301", ttl)
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
			questionCh := make(chan dns.Question, 1)
			p := newTestPreferDomain(pluginCtx, originalAddr, sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
				calls.Add(1)
				q := qCtx.Q()
				questionCh <- q.Question[0]
				r := new(dns.Msg)
				r.SetReply(q)
				if tt.qType == dns.TypeA {
					r.Answer = []dns.RR{newA(q.Question[0].Name, tt.preferredIP, 300)}
				} else {
					r.Answer = []dns.RR{newAAAA(q.Question[0].Name, tt.preferredIP, 300)}
				}
				qCtx.SetResponse(r)
				return nil
			}))

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
			if gotCalls := calls.Load(); gotCalls != 1 {
				t.Fatalf("preferred resolver calls = %d, want 1", gotCalls)
			}
			preferredQuestion := <-questionCh
			if preferredQuestion.Name != "preferred.example." || preferredQuestion.Qtype != tt.qType {
				t.Fatalf("preferred query = %v, want preferred.example. type %d", preferredQuestion, tt.qType)
			}
		})
	}
}

func TestExecReplacesAddressAfterCNAMEChain(t *testing.T) {
	pluginCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	originalAddr := netip.MustParseAddr("192.0.2.81")
	p := newTestPreferDomain(pluginCtx, originalAddr, addressResolver("203.0.113.81"))
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

func TestExecPreferredResolutionFailuresKeepOriginalResponse(t *testing.T) {
	tests := []struct {
		name     string
		resolver sequence.Executable
		timeout  time.Duration
	}{
		{
			name: "execution error",
			resolver: sequence.ExecutableFunc(func(context.Context, *query_context.Context) error {
				return errors.New("resolver failed")
			}),
		},
		{
			name: "timeout",
			resolver: sequence.ExecutableFunc(func(ctx context.Context, _ *query_context.Context) error {
				<-ctx.Done()
				return context.Cause(ctx)
			}),
			timeout: 20 * time.Millisecond,
		},
		{
			name: "no response",
			resolver: sequence.ExecutableFunc(func(context.Context, *query_context.Context) error {
				return nil
			}),
		},
		{
			name: "SERVFAIL",
			resolver: sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
				r := new(dns.Msg)
				r.SetReply(qCtx.Q())
				r.Rcode = dns.RcodeServerFailure
				qCtx.SetResponse(r)
				return nil
			}),
		},
		{
			name: "no matching address type",
			resolver: sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
				r := new(dns.Msg)
				r.SetReply(qCtx.Q())
				r.Answer = []dns.RR{newAAAA(qCtx.Q().Question[0].Name, "2001:db8::1", 300)}
				qCtx.SetResponse(r)
				return nil
			}),
		},
		{
			name: "malformed address",
			resolver: sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
				r := new(dns.Msg)
				r.SetReply(qCtx.Q())
				r.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{Name: qCtx.Q().Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.IP{1},
				}}
				qCtx.SetResponse(r)
				return nil
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pluginCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := newTestPreferDomain(pluginCtx, netip.MustParseAddr("192.0.2.91"), tt.resolver)
			if tt.timeout > 0 {
				p.timeout = tt.timeout
			}
			q := new(dns.Msg)
			q.SetQuestion("original.example.", dns.TypeA)
			r := new(dns.Msg)
			r.SetReply(q)
			r.Answer = []dns.RR{newA(q.Question[0].Name, "192.0.2.91", 300)}
			wantWire := mustPack(t, r)
			qCtx := query_context.NewContext(q)
			qCtx.SetResponse(r)
			originalPointer := qCtx.R()

			if err := p.Exec(context.Background(), qCtx); err != nil {
				t.Fatalf("Exec() error = %v, want nil", err)
			}
			assertResponseUntouched(t, qCtx, originalPointer, wantWire)
		})
	}
}

func TestExecInternalPreferredQueryDoesNotReenter(t *testing.T) {
	pluginCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var resolverCalls atomic.Int32
	var p *PreferDomain
	resolver := sequence.ExecutableFunc(func(ctx context.Context, qCtx *query_context.Context) error {
		resolverCalls.Add(1)
		q := qCtx.Q()
		r := new(dns.Msg)
		r.SetReply(q)
		r.Answer = []dns.RR{newA(q.Question[0].Name, "203.0.113.92", 300)}
		qCtx.SetResponse(r)
		return p.Exec(ctx, qCtx)
	})
	p = newTestPreferDomain(pluginCtx, netip.MustParseAddr("192.0.2.92"), resolver)
	// Match both the outer and internally resolved address. Without the
	// per-instance marker, the inner Exec would recursively request the same
	// preferred-domain singleflight key.
	p.rules[0].matcher = matcherFunc(func(netip.Addr) bool { return true })

	q := new(dns.Msg)
	q.SetQuestion("original.example.", dns.TypeA)
	r := new(dns.Msg)
	r.SetReply(q)
	r.Answer = []dns.RR{newA(q.Question[0].Name, "192.0.2.92", 300)}
	qCtx := query_context.NewContext(q)
	qCtx.SetResponse(r)

	if err := p.Exec(context.Background(), qCtx); err != nil {
		t.Fatalf("Exec() error = %v", err)
	}
	if resolverCalls.Load() != 1 {
		t.Fatalf("preferred resolver re-entered the same plugin: calls=%d", resolverCalls.Load())
	}
	if len(qCtx.R().Answer) != 1 || rrAddress(qCtx.R().Answer[0]) != "203.0.113.92" {
		t.Fatalf("outer response was not replaced: %v", qCtx.R())
	}
}

func TestInternalMarkerOnlySkipsOwningInstance(t *testing.T) {
	var resolverCalls atomic.Int32
	owner := &PreferDomain{}
	other := &PreferDomain{
		logger: zap.NewNop(),
		resolver: sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
			resolverCalls.Add(1)
			q := qCtx.Q()
			r := new(dns.Msg)
			r.SetReply(q)
			r.Answer = []dns.RR{newA(q.Question[0].Name, "203.0.113.93", 300)}
			qCtx.SetResponse(r)
			return nil
		}),
		rules: []compiledRule{{
			preferDomain:  "preferred.example.",
			preferDisplay: "preferred.example",
			matcher:       matcherFunc(func(netip.Addr) bool { return true }),
		}},
		timeout: time.Second,
		cache:   make(map[string]cacheEntry),
	}
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
	if resolverCalls.Load() != 1 || rrAddress(qCtx.R().Answer[0]) != "203.0.113.93" {
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

func TestZeroTTLResponseIsNotCached(t *testing.T) {
	rule := &compiledRule{preferDomain: "preferred.example."}
	p := &PreferDomain{cache: make(map[string]cacheEntry)}
	msg := &dns.Msg{Answer: []dns.RR{newA(rule.preferDomain, "192.0.2.40", 0)}}

	p.storePreferred(rule, dns.TypeA, msg)

	if _, ok := p.cache[cacheKey(rule.preferDomain, dns.TypeA)]; ok {
		t.Fatal("zero-TTL response was cached")
	}
}

func TestBindTTLToWarmIntervalControlsCacheDuration(t *testing.T) {
	p := &PreferDomain{
		warmInterval:          5 * time.Minute,
		bindTTLToWarmInterval: true,
		cacheTTL:              time.Millisecond,
	}
	msg := &dns.Msg{Answer: []dns.RR{newA("preferred.example.", "192.0.2.42", 10)}}

	if got, want := p.cacheDuration(msg, dns.TypeA), 5*time.Minute+time.Second; got != want {
		t.Fatalf("cache duration = %v, want %v", got, want)
	}
}

func TestExecBindsVisibleResponseTTLToWarmInterval(t *testing.T) {
	pluginCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := newTestPreferDomain(pluginCtx, netip.MustParseAddr("192.0.2.43"), addressResolver("203.0.113.43"))
	p.warmInterval = 5 * time.Minute
	p.bindTTLToWarmInterval = true
	p.bindResponseTTLToWarmInterval = true

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
	if ttl := qCtx.R().Answer[0].Header().Ttl; ttl != 301 {
		t.Fatalf("visible replacement TTL = %d, want 301", ttl)
	}
}

func TestExecStaleResponseKeepsZeroTTLWhenResponseBindingEnabled(t *testing.T) {
	preferredQ := new(dns.Msg)
	preferredQ.SetQuestion("preferred.example.", dns.TypeA)
	preferred := new(dns.Msg)
	preferred.SetReply(preferredQ)
	preferred.Answer = []dns.RR{newA("preferred.example.", "203.0.113.44", 300)}
	p := &PreferDomain{
		logger: zap.NewNop(),
		resolver: sequence.ExecutableFunc(func(context.Context, *query_context.Context) error {
			return errors.New("upstream unavailable")
		}),
		rules: []compiledRule{{
			preferDomain:  "preferred.example.",
			preferDisplay: "preferred.example",
			matcher: matcherFunc(func(addr netip.Addr) bool {
				return addr == netip.MustParseAddr("192.0.2.44")
			}),
		}},
		timeout:                       time.Second,
		warmInterval:                  5 * time.Minute,
		bindTTLToWarmInterval:         true,
		bindResponseTTLToWarmInterval: true,
		serveStale:                    true,
		cache: map[string]cacheEntry{
			cacheKey("preferred.example.", dns.TypeA): {
				msg:     preferred,
				stored:  time.Now().Add(-time.Hour),
				expires: time.Now().Add(-time.Second),
			},
		},
	}

	q := new(dns.Msg)
	q.SetQuestion("original.example.", dns.TypeA)
	r := new(dns.Msg)
	r.SetReply(q)
	r.Answer = []dns.RR{newA(q.Question[0].Name, "192.0.2.44", 60)}
	qCtx := query_context.NewContext(q)
	qCtx.SetResponse(r)

	if err := p.Exec(context.Background(), qCtx); err != nil {
		t.Fatalf("Exec() error = %v", err)
	}
	if addr, ttl := rrAddress(qCtx.R().Answer[0]), qCtx.R().Answer[0].Header().Ttl; addr != "203.0.113.44" || ttl != 0 {
		t.Fatalf("stale replacement = %s ttl %d, want 203.0.113.44 ttl 0", addr, ttl)
	}
}

func TestPreferredCacheSeparatesAAndAAAA(t *testing.T) {
	pluginCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var aCalls atomic.Int32
	var aaaaCalls atomic.Int32
	p := &PreferDomain{
		resolver: sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
			q := qCtx.Q()
			r := new(dns.Msg)
			r.SetReply(q)
			if q.Question[0].Qtype == dns.TypeA {
				aCalls.Add(1)
				r.Answer = []dns.RR{newA(q.Question[0].Name, "192.0.2.41", 300)}
			} else {
				aaaaCalls.Add(1)
				r.Answer = []dns.RR{newAAAA(q.Question[0].Name, "2001:db8::41", 300)}
			}
			qCtx.SetResponse(r)
			return nil
		}),
		timeout: time.Second,
		cache:   make(map[string]cacheEntry),
		ctx:     pluginCtx,
		cancel:  cancel,
	}
	rule := &compiledRule{preferDomain: "preferred.example."}

	for range 2 {
		if _, _, err := p.getPreferredResponse(context.Background(), rule, dns.TypeA); err != nil {
			t.Fatal(err)
		}
		if _, _, err := p.getPreferredResponse(context.Background(), rule, dns.TypeAAAA); err != nil {
			t.Fatal(err)
		}
	}
	if aCalls.Load() != 1 || aaaaCalls.Load() != 1 {
		t.Fatalf("resolver calls: A=%d AAAA=%d, want one each", aCalls.Load(), aaaaCalls.Load())
	}
}

func TestWarmOnStartWorksWithoutWarmInterval(t *testing.T) {
	pluginCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resolved := make(chan uint16, 2)
	p := &PreferDomain{
		logger: zap.NewNop(),
		resolver: sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
			q := qCtx.Q()
			r := new(dns.Msg)
			r.SetReply(q)
			if q.Question[0].Qtype == dns.TypeA {
				r.Answer = []dns.RR{newA(q.Question[0].Name, "192.0.2.50", 300)}
			} else {
				r.Answer = []dns.RR{newAAAA(q.Question[0].Name, "2001:db8::50", 300)}
			}
			qCtx.SetResponse(r)
			resolved <- q.Question[0].Qtype
			return nil
		}),
		rules:       []compiledRule{{preferDomain: "preferred.example.", preferDisplay: "preferred.example"}},
		timeout:     time.Second,
		warmOnStart: true,
		cache:       make(map[string]cacheEntry),
		ctx:         pluginCtx,
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
			r.Answer = []dns.RR{newA(q.Question[0].Name, "192.0.2.60", 300)}
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
		{name: "warm interval default", defaultValue: defaultWarmIntervalSeconds, unit: time.Second, want: 300 * time.Second},
		{name: "cache ttl default", defaultValue: 0, unit: time.Millisecond, want: 0},
		{name: "cache ttl milliseconds", value: "1500", unit: time.Millisecond, want: 1500 * time.Millisecond},
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

func newTestPreferDomain(pluginCtx context.Context, matchAddr netip.Addr, resolver sequence.Executable) *PreferDomain {
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
		timeout: time.Second,
		cache:   make(map[string]cacheEntry),
		ctx:     pluginCtx,
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
