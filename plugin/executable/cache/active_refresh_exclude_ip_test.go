package cache

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"
	"github.com/miekg/dns"
)

type activeRefreshExcludeIPTestProvider struct {
	matcher netlist.Matcher
}

func (p *activeRefreshExcludeIPTestProvider) GetIPMatcher() netlist.Matcher {
	return p.matcher
}

type activeRefreshExcludeIPTestMatcher func(addr netip.Addr) bool

func (f activeRefreshExcludeIPTestMatcher) Match(addr netip.Addr) bool {
	return f(addr)
}

func TestNormalizeActiveRefreshExcludeIP(t *testing.T) {
	tests := []struct {
		name       string
		raw        any
		wantCIDRs  []string
		wantIPSets []string
		wantFiles  []string
	}{
		{
			name:      "legacy scalar",
			raw:       "198.18.0.0/15 2001:db8::/32",
			wantCIDRs: []string{"198.18.0.0/15", "2001:db8::/32"},
		},
		{
			name:      "legacy list",
			raw:       []any{"198.18.0.0/15", "1.1.1.1"},
			wantCIDRs: []string{"198.18.0.0/15", "1.1.1.1"},
		},
		{
			name: "structured mapping",
			raw: map[string]any{
				"cidrs":   []any{"198.18.0.0/15"},
				"ip_sets": []any{"geoip:cloudflare"},
				"files":   []any{"rules.txt"},
			},
			wantCIDRs:  []string{"198.18.0.0/15"},
			wantIPSets: []string{"geoip:cloudflare"},
			wantFiles:  []string{"rules.txt"},
		},
		{
			name: "yaml style mapping",
			raw: map[any]any{
				"cidrs":   []any{"2001:db8::/32"},
				"ip_sets": "geoip:cn",
				"files":   "rules.txt",
			},
			wantCIDRs:  []string{"2001:db8::/32"},
			wantIPSets: []string{"geoip:cn"},
			wantFiles:  []string{"rules.txt"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeActiveRefreshExcludeIP(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			assertActiveRefreshExcludeIPStrings(t, "cidrs", got.CIDRs, tc.wantCIDRs)
			assertActiveRefreshExcludeIPStrings(t, "ip_sets", got.IPSets, tc.wantIPSets)
			assertActiveRefreshExcludeIPStrings(t, "files", got.Files, tc.wantFiles)
		})
	}
}

func TestNormalizeActiveRefreshExcludeIPRejectsInvalidShapes(t *testing.T) {
	tests := []struct {
		name    string
		raw     any
		wantErr string
	}{
		{
			name:    "unsupported top level type",
			raw:     123,
			wantErr: "active_refresh.exclude_ip must be a string, list, or mapping",
		},
		{
			name:    "non string legacy entry",
			raw:     []any{"1.1.1.1", 123},
			wantErr: "active_refresh.exclude_ip[1] must be a string",
		},
		{
			name:    "unknown structured field",
			raw:     map[string]any{"ranges": []string{"1.1.1.1"}},
			wantErr: "active_refresh.exclude_ip contains unsupported field(s): ranges",
		},
		{
			name:    "non string structured entry",
			raw:     map[string]any{"cidrs": []any{"1.1.1.1", false}},
			wantErr: "active_refresh.exclude_ip.cidrs[1] must be a string",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := normalizeActiveRefreshExcludeIP(tc.raw)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestParseActiveRefreshExcludeIPPrefix(t *testing.T) {
	tests := []struct {
		rule     string
		want     string
		wantBits int
	}{
		{rule: "1.1.1.1", want: "1.1.1.1/32", wantBits: 32},
		{rule: "2606:4700:4700::1111", want: "2606:4700:4700::1111/128", wantBits: 128},
		{rule: "198.18.1.2/15", want: "198.18.0.0/15", wantBits: 15},
		{rule: "2001:db8:1::1/32", want: "2001:db8::/32", wantBits: 32},
	}
	for _, tc := range tests {
		t.Run(tc.rule, func(t *testing.T) {
			prefix, err := parseActiveRefreshExcludeIPPrefix(tc.rule)
			if err != nil {
				t.Fatal(err)
			}
			if prefix.String() != tc.want || prefix.Bits() != tc.wantBits {
				t.Fatalf("prefix = %s/%d, want %s/%d", prefix.Addr(), prefix.Bits(), tc.want, tc.wantBits)
			}
		})
	}

	for _, rule := range []string{"", "300.1.1.1", "198.18.0.0/99", "fe80::1%eth0"} {
		t.Run("invalid "+rule, func(t *testing.T) {
			if _, err := parseActiveRefreshExcludeIPPrefix(rule); err == nil {
				t.Fatalf("expected %q to be rejected", rule)
			}
		})
	}
}

func TestBuildActiveRefreshExcludeIPMatcher(t *testing.T) {
	baseDir := t.TempDir()
	rulesPath := filepath.Join(baseDir, "rules.txt")
	rules := "\ufeff# UTF-8 BOM and comment\r\n" +
		"198.18.0.0/15 # inline comment\n" +
		"\r\n" +
		"2001:db8::/32\r\n"
	if err := os.WriteFile(rulesPath, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}

	providerMatcher := activeRefreshExcludeIPTestMatcher(func(addr netip.Addr) bool {
		return addr == netip.MustParseAddr("203.0.113.8")
	})
	provider := &activeRefreshExcludeIPTestProvider{matcher: providerMatcher}
	lookupCalls := 0
	lookup := func(tag string) any {
		lookupCalls++
		if tag == "geoip:test" {
			return provider
		}
		return nil
	}

	raw := map[string]any{
		"cidrs":   []any{"192.0.2.1", "2606:4700:4700::1111"},
		"files":   []any{"rules.txt"},
		"ip_sets": []any{"geoip:test"},
	}
	matcher, err := buildActiveRefreshExcludeIPMatcher(raw, baseDir, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if lookupCalls != 1 {
		t.Fatalf("provider lookup calls = %d, want 1", lookupCalls)
	}

	for _, addr := range []string{
		"192.0.2.1",
		"2606:4700:4700::1111",
		"198.19.255.255",
		"2001:db8:ffff::1",
		"203.0.113.8",
	} {
		if !matcher.Match(netip.MustParseAddr(addr)) {
			t.Errorf("expected %s to match", addr)
		}
	}
	if matcher.Match(netip.MustParseAddr("8.8.8.8")) {
		t.Error("8.8.8.8 unexpectedly matched")
	}
}

func TestActiveRefreshExcludeIPFileErrorIncludesPathAndLine(t *testing.T) {
	baseDir := t.TempDir()
	path := filepath.Join(baseDir, "invalid.txt")
	contents := "# comment\r\n\r\n300.1.1.1 # invalid\r\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := buildActiveRefreshExcludeIPMatcher(
		map[string]any{"files": []any{"invalid.txt"}},
		baseDir,
		nil,
	)
	if err == nil {
		t.Fatal("expected invalid file rule to fail")
	}
	for _, want := range []string{
		"active_refresh.exclude_ip.files[0]",
		"invalid.txt",
		"line 3",
		"300.1.1.1",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestActiveRefreshExcludeIPProviderErrors(t *testing.T) {
	tests := []struct {
		name    string
		plugin  any
		wantErr string
	}{
		{name: "not found", plugin: nil, wantErr: `plugin "geoip:test" not found`},
		{name: "wrong type", plugin: struct{}{}, wantErr: "does not implement data_provider.IPMatcherProvider"},
		{
			name:    "nil matcher",
			plugin:  &activeRefreshExcludeIPTestProvider{},
			wantErr: "returned a nil IP matcher",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildActiveRefreshExcludeIPMatcher(
				map[string]any{"ip_sets": []any{"geoip:test"}},
				"",
				func(string) any { return tc.plugin },
			)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tc.wantErr)
			}
			if !strings.Contains(err.Error(), "active_refresh.exclude_ip.ip_sets[0]") {
				t.Fatalf("error lacks field path: %v", err)
			}
		})
	}
}

func TestResponseMatchesActiveRefreshIP(t *testing.T) {
	matcher := activeRefreshExcludeIPTestMatcher(func(addr netip.Addr) bool {
		return addr == netip.MustParseAddr("1.1.1.1") || addr == netip.MustParseAddr("2001:db8::1")
	})

	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeCNAME}, Target: "alias.example.org."},
		&dns.A{Hdr: dns.RR_Header{Name: "alias.example.org.", Rrtype: dns.TypeA}, A: net.ParseIP("8.8.8.8")},
		&dns.AAAA{Hdr: dns.RR_Header{Name: "alias.example.org.", Rrtype: dns.TypeAAAA}, AAAA: net.ParseIP("2001:db8::1")},
	}
	if !responseMatchesActiveRefreshIP(msg, matcher) {
		t.Fatal("expected any matching Answer A/AAAA to exclude the response")
	}

	additionalOnly := new(dns.Msg)
	additionalOnly.Extra = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeA}, A: net.ParseIP("1.1.1.1")},
	}
	if responseMatchesActiveRefreshIP(additionalOnly, matcher) {
		t.Fatal("Additional-section addresses must not be matched")
	}
	if responseMatchesActiveRefreshIP(nil, matcher) {
		t.Fatal("nil response unexpectedly matched")
	}
	for _, rcode := range []int{dns.RcodeSuccess, dns.RcodeNameError, dns.RcodeServerFailure} {
		empty := new(dns.Msg)
		empty.Rcode = rcode
		empty.Answer = []dns.RR{&dns.CNAME{
			Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeCNAME}, Target: "alias.example.org.",
		}}
		if responseMatchesActiveRefreshIP(empty, matcher) {
			t.Fatalf("CNAME-only response with rcode %d unexpectedly matched", rcode)
		}
	}
}

func assertActiveRefreshExcludeIPStrings(t *testing.T, field string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s length = %d, want %d (%#v vs %#v)", field, len(got), len(want), got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s[%d] = %q, want %q", field, i, got[i], want[i])
		}
	}
}
