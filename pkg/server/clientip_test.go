package server

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func clientIPTestMessage(data []byte) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion("client-ip.example.", dns.TypeA)
	q.SetEdns0(1232, false)
	q.IsEdns0().Option = append(q.IsEdns0().Option,
		&dns.EDNS0_LOCAL{Code: EDNS0ClientIPCode, Data: data},
		&dns.EDNS0_NSID{Nsid: "keep"},
	)
	return q
}

func TestExtractClientIPTrustedSourceAndStrip(t *testing.T) {
	want := netip.MustParseAddr("192.0.2.45")
	q := clientIPTestMessage(want.AsSlice())
	got, ok := ExtractClientIP(q, netip.MustParseAddr("127.0.0.1"))
	if !ok || got != want {
		t.Fatalf("ExtractClientIP() = %v, %v; want %v, true", got, ok, want)
	}
	if options := q.IsEdns0().Option; len(options) != 1 {
		t.Fatalf("remaining EDNS options = %#v, want only NSID", options)
	} else if _, ok := options[0].(*dns.EDNS0_NSID); !ok {
		t.Fatalf("remaining EDNS option = %T, want NSID", options[0])
	}
}

func TestExtractClientIPUntrustedSourceStillStrips(t *testing.T) {
	q := clientIPTestMessage(netip.MustParseAddr("192.0.2.45").AsSlice())
	if got, ok := ExtractClientIP(q, netip.MustParseAddr("198.51.100.10")); ok || got.IsValid() {
		t.Fatalf("untrusted ExtractClientIP() = %v, %v; want invalid, false", got, ok)
	}
	for _, option := range q.IsEdns0().Option {
		if local, ok := option.(*dns.EDNS0_LOCAL); ok && local.Code == EDNS0ClientIPCode {
			t.Fatal("private client-IP option was not stripped")
		}
	}
}
