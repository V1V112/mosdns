package server

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type udpTestHandler func(context.Context, *dns.Msg, QueryMeta, func(*dns.Msg) (*[]byte, error)) *[]byte

func (f udpTestHandler) Handle(
	ctx context.Context,
	q *dns.Msg,
	meta QueryMeta,
	pack func(*dns.Msg) (*[]byte, error),
) *[]byte {
	return f(ctx, q, meta, pack)
}

func runUDPMetadataTest(t *testing.T, opts UDPServerOpts) QueryMeta {
	t.Helper()
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	metas := make(chan QueryMeta, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = ServeUDP(listener, udpTestHandler(func(
			_ context.Context,
			_ *dns.Msg,
			meta QueryMeta,
			_ func(*dns.Msg) (*[]byte, error),
		) *[]byte {
			metas <- meta
			return nil
		}), opts)
	}()

	client, err := net.DialUDP("udp", nil, listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	q := new(dns.Msg)
	q.SetQuestion("udp-telemetry.example.", dns.TypeA)
	wire, err := q.Pack()
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	if _, err := client.Write(wire); err != nil {
		client.Close()
		t.Fatal(err)
	}
	_ = client.Close()

	select {
	case meta := <-metas:
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("ServeUDP did not stop after listener close")
		}
		return meta
	case <-time.After(2 * time.Second):
		t.Fatal("UDP handler did not receive query metadata")
		return QueryMeta{}
	}
}

func TestServeUDPFastBypassTelemetryTakesPrecedence(t *testing.T) {
	var legacyCalls atomic.Int32
	meta := runUDPMetadataTest(t, UDPServerOpts{
		FastBypass: func(int, []byte, netip.AddrPort) (int, int, uint64, string) {
			legacyCalls.Add(1)
			return FastActionContinue, 0, 1, "legacy"
		},
		FastBypassWithTelemetry: func(int, []byte, netip.AddrPort) (int, int, uint64, string, uint32) {
			return FastActionContinue, 0, 9, "telemetry", 37
		},
	})
	if legacyCalls.Load() != 0 {
		t.Fatalf("legacy bypass called %d times despite telemetry callback", legacyCalls.Load())
	}
	if !meta.FromUDP || meta.PreFastFlags != 9 || meta.PreFastDomainSet != "telemetry" || meta.FastCacheHits != 37 {
		t.Fatalf("telemetry metadata = %#v", meta)
	}
}

func TestServeUDPLegacyFastBypassFallback(t *testing.T) {
	meta := runUDPMetadataTest(t, UDPServerOpts{
		FastBypass: func(int, []byte, netip.AddrPort) (int, int, uint64, string) {
			return FastActionContinue, 0, 5, "legacy"
		},
	})
	if !meta.FromUDP || meta.PreFastFlags != 5 || meta.PreFastDomainSet != "legacy" || meta.FastCacheHits != 0 {
		t.Fatalf("legacy metadata = %#v", meta)
	}
}
