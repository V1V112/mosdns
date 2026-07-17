package udp_server

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/server"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

type testHandlerFunc func(context.Context, *dns.Msg, server.QueryMeta, func(*dns.Msg) (*[]byte, error)) *[]byte

func (f testHandlerFunc) Handle(
	ctx context.Context,
	q *dns.Msg,
	meta server.QueryMeta,
	pack func(*dns.Msg) (*[]byte, error),
) *[]byte {
	return f(ctx, q, meta, pack)
}

func testFastCacheResponse(t *testing.T, id uint16, name string, ttl uint32) ([]byte, *dns.Msg) {
	t.Helper()
	q := new(dns.Msg)
	q.Id = id
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	r := new(dns.Msg)
	r.SetReply(q)
	rr, err := dns.NewRR(fmt.Sprintf("%s %d IN A 192.0.2.1", dns.Fqdn(name), ttl))
	if err != nil {
		t.Fatal(err)
	}
	r.Answer = []dns.RR{rr}
	w, err := r.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return w, q
}

func testFastCacheDeps(now time.Time) fastCacheDeps {
	return fastCacheDeps{
		loadKernelMap: func() (fastKernelMap, error) {
			return nil, fmt.Errorf("kernel map unavailable")
		},
		now:     func() time.Time { return now },
		bootNow: func() uint64 { return 1 },
	}
}

func TestNormalizeFastCacheArgs(t *testing.T) {
	legacy, err := normalizeFastCacheArgs(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !legacy.legacy || !legacy.kernel || legacy.userspace || legacy.userspaceSize != legacyFastCacheSize {
		t.Fatalf("unexpected legacy mode: %#v", legacy)
	}

	tests := []struct {
		name      string
		args      FastCacheArgs
		kernel    bool
		userspace bool
		size      int
	}{
		{name: "off", args: FastCacheArgs{Mode: "off"}},
		{name: "kernel", args: FastCacheArgs{Mode: " Kernel "}, kernel: true},
		{name: "userspace default", args: FastCacheArgs{Mode: "userspace"}, userspace: true, size: defaultFastCacheSize},
		{name: "userspace sized", args: FastCacheArgs{Mode: "userspace", Size: 1024}, userspace: true, size: 1024},
		{name: "both", args: FastCacheArgs{Mode: "both", Size: 8}, kernel: true, userspace: true, size: 8},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeFastCacheArgs(&tc.args)
			if err != nil {
				t.Fatal(err)
			}
			if got.kernel != tc.kernel || got.userspace != tc.userspace || got.userspaceSize != tc.size {
				t.Fatalf("resolved mode = %#v", got)
			}
		})
	}
}

func TestFastCacheArgsValidation(t *testing.T) {
	invalid := []FastCacheArgs{
		{},
		{Mode: "invalid"},
		{Mode: "kernel", Size: 1024},
		{Mode: "off", Size: 4},
		{Mode: "userspace", Size: 3},
		{Mode: "userspace", Size: 12},
		{Mode: "userspace", Size: maxFastCacheSize + 1},
	}
	for _, args := range invalid {
		if _, err := normalizeFastCacheArgs(&args); err == nil {
			t.Fatalf("expected error for %#v", args)
		}
	}
}

func TestFastCacheArgsWeakDecode(t *testing.T) {
	var args Args
	raw := map[string]any{
		"entry":  "main",
		"listen": ":53",
		"fast_cache": map[string]any{
			"mode": "userspace",
			"size": 1024,
		},
	}
	if err := utils.WeakDecode(raw, &args); err != nil {
		t.Fatal(err)
	}
	mode, err := args.init()
	if err != nil {
		t.Fatal(err)
	}
	if !mode.userspace || mode.userspaceSize != 1024 {
		t.Fatalf("unexpected decoded mode: %#v", mode)
	}

	var bad Args
	raw["fast_cache"].(map[string]any)["unknown"] = true
	if err := utils.WeakDecode(raw, &bad); err == nil {
		t.Fatal("unknown nested fast_cache field was accepted")
	}
}

func TestFastCacheModeResources(t *testing.T) {
	now := time.Unix(1000, 0)
	for _, tc := range []struct {
		name     string
		mode     resolvedFastCacheMode
		capacity int
	}{
		{name: "off", mode: resolvedFastCacheMode{}},
		{name: "kernel", mode: resolvedFastCacheMode{kernel: true}},
		{name: "userspace", mode: resolvedFastCacheMode{userspace: true, userspaceSize: 8}, capacity: 8},
		{name: "both", mode: resolvedFastCacheMode{kernel: true, userspace: true, userspaceSize: 16}, capacity: 16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fc, err := newFastCacheWithDeps(tc.mode, zap.NewNop(), testFastCacheDeps(now))
			if err != nil {
				t.Fatal(err)
			}
			defer fc.Close()
			if got := fc.localCapacity(); got != tc.capacity {
				t.Fatalf("local capacity = %d, want %d", got, tc.capacity)
			}
		})
	}
}

func TestFastCacheStoreCopiesAndChecksQuestion(t *testing.T) {
	now := time.Unix(1000, 0)
	fc, err := newFastCacheWithDeps(
		resolvedFastCacheMode{userspace: true, userspaceSize: 8},
		zap.NewNop(),
		testFastCacheDeps(now),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer fc.Close()

	wire, _ := testFastCacheResponse(t, 1, "Example.COM.", 60)
	original := append([]byte(nil), wire...)
	fc.Store(wire, false)
	for i := range wire {
		wire[i] = 0
	}

	query := new(dns.Msg)
	query.SetQuestion("eXAMPLE.com.", dns.TypeA)
	queryWire, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	question, ok := fastQuestionWire(queryWire)
	if !ok {
		t.Fatal("failed to parse test question")
	}
	item := fc.lookupLocal(calcFNV1a(question), question)
	if item == nil {
		t.Fatal("case-insensitive question did not hit")
	}
	if len(item.resp) != len(original) || item.resp[0] != original[0] || item.resp[1] != original[1] {
		t.Fatal("stored response aliases the caller payload")
	}
	var cached dns.Msg
	if err := cached.Unpack(item.resp); err != nil {
		t.Fatal(err)
	}
	if len(cached.Answer) != 1 || cached.Answer[0].Header().Ttl != fastCacheClientTTL {
		t.Fatalf("cached answer TTL was not baked to %d", fastCacheClientTTL)
	}

	other := new(dns.Msg)
	other.SetQuestion("other.example.", dns.TypeA)
	otherWire, _ := other.Pack()
	otherQuestion, _ := fastQuestionWire(otherWire)
	if got := fc.lookupLocal(item.hash, otherQuestion); got != nil {
		t.Fatal("hash-only collision returned a response for a different question")
	}
}

func TestFastHandlerPayloadOwnership(t *testing.T) {
	now := time.Unix(1000, 0)
	fc, err := newFastCacheWithDeps(
		resolvedFastCacheMode{userspace: true, userspaceSize: 8},
		zap.NewNop(),
		testFastCacheDeps(now),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer fc.Close()

	wire, q := testFastCacheResponse(t, 1, "ownership.example.", 60)
	payload := append([]byte(nil), wire...)
	next := testHandlerFunc(func(context.Context, *dns.Msg, server.QueryMeta, func(*dns.Msg) (*[]byte, error)) *[]byte {
		return &payload
	})
	var releases atomic.Int32
	h := &fastHandler{
		next: next,
		fc:   fc,
		releasePayload: func(*[]byte) {
			releases.Add(1)
		},
	}

	if got := h.Handle(context.Background(), q, server.QueryMeta{}, nil); got != &payload {
		t.Fatal("normal response ownership was not returned to ServeUDP")
	}
	if releases.Load() != 0 {
		t.Fatal("normal response was released by the wrapper")
	}
	if got := h.Handle(context.Background(), q, server.QueryMeta{PreFastFlags: asyncRefreshMark}, nil); got != nil {
		t.Fatal("async refresh returned a client response")
	}
	if releases.Load() != 1 {
		t.Fatalf("async response release count = %d, want 1", releases.Load())
	}
}

func TestExplicitUserspaceDoesNotEnableSwitchPolicy(t *testing.T) {
	now := time.Unix(1000, 0)
	fc, err := newFastCacheWithDeps(
		resolvedFastCacheMode{userspace: true, userspaceSize: 8},
		zap.NewNop(),
		testFastCacheDeps(now),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer fc.Close()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	oldMarks := query_context.GlobalSwitchMask.Load()
	query_context.GlobalSwitchMask.Store(1 << 36)
	defer query_context.GlobalSwitchMask.Store(oldMarks)

	q := new(dns.Msg)
	q.SetQuestion("policy.example.", dns.TypeSOA)
	wire, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), wire...)
	bypass := buildFastBypass(
		coremain.NewBP("test", coremain.NewTestMosdnsWithPlugins(map[string]any{})),
		fc,
		conn,
		true,
		false,
	)
	action, _, marks, dset := bypass(len(wire), wire, netip.MustParseAddrPort("127.0.0.1:53000"))
	if action != server.FastActionContinue || marks != 0 || dset != "" {
		t.Fatalf("unexpected policy result without switch15: action=%d marks=%x dset=%q", action, marks, dset)
	}
	if !bytes.Equal(wire, original) {
		t.Fatal("explicit userspace mode applied switch policy and rewrote the query")
	}
}

type fakeFastKernelMap struct {
	updates chan fastKernelUpdate
	closed  atomic.Bool
}

func (m *fakeFastKernelMap) Put(key, value any) error {
	u := fastKernelUpdate{
		hash:  *key.(*uint32),
		value: *value.(*eBpfCacheVal),
	}
	m.updates <- u
	return nil
}

func (m *fakeFastKernelMap) Close() error {
	m.closed.Store(true)
	return nil
}

func TestKernelModeDoesNotRetainUserspaceResponse(t *testing.T) {
	now := time.Unix(1000, 0)
	m := &fakeFastKernelMap{updates: make(chan fastKernelUpdate, 1)}
	deps := testFastCacheDeps(now)
	deps.loadKernelMap = func() (fastKernelMap, error) { return m, nil }
	fc, err := newFastCacheWithDeps(resolvedFastCacheMode{kernel: true}, zap.NewNop(), deps)
	if err != nil {
		t.Fatal(err)
	}
	defer fc.Close()

	wire, _ := testFastCacheResponse(t, 7, "kernel.example.", 60)
	fc.Store(wire, false)
	select {
	case update := <-m.updates:
		if update.value.Len != uint16(len(wire)) {
			t.Fatalf("kernel value length = %d, want %d", update.value.Len, len(wire))
		}
		var cached dns.Msg
		if err := cached.Unpack(update.value.Data[:update.value.Len]); err != nil {
			t.Fatal(err)
		}
		if len(cached.Answer) != 1 || cached.Answer[0].Header().Ttl != fastCacheClientTTL {
			t.Fatalf("kernel answer TTL was not baked to %d", fastCacheClientTTL)
		}
	case <-time.After(time.Second):
		t.Fatal("kernel update was not written")
	}
	if fc.localCapacity() != 0 || fc.lookupLocal(0, nil) != nil {
		t.Fatal("kernel-only mode retained a userspace table")
	}
}
