package query_context

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func TestReplaySnapshotRoundTripAndIsolation(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("snapshot.example.", dns.TypeAAAA)
	q.AuthenticatedData = true
	q.Compress = true
	clientOpt := newOpt()
	clientOpt.SetUDPSize(4096)
	clientOpt.SetDo()
	clientOpt.Option = append(clientOpt.Option, &dns.EDNS0_LOCAL{Code: 65001, Data: []byte{1, 2, 3}})
	q.Extra = append(q.Extra, clientOpt)

	ctx := NewContext(q)
	ctx.SetFastCacheHits(23)
	ctx.ServerMeta = ServerMeta{
		FromUDP:          true,
		ClientAddr:       netip.MustParseAddr("192.0.2.10"),
		ServerName:       "snapshot-server",
		UrlPath:          "/dns-query",
		PreFastFlags:     1 << 17,
		PreFastDomainSet: "snapshot-set",
		FastCacheHits:    23,
	}
	ctx.QOpt().SetUDPSize(1232)
	ctx.QOpt().Option = append(ctx.QOpt().Option, &dns.EDNS0_LOCAL{Code: 65002, Data: []byte{4, 5, 6}})
	ctx.RespOpt().SetUDPSize(1400)
	ctx.RespOpt().Option = append(ctx.RespOpt().Option, &dns.EDNS0_LOCAL{Code: 65003, Data: []byte{7, 8, 9}})
	valueKey := RegKey()
	ctx.StoreValue(valueKey, "captured")
	ctx.SetMark(42)
	ctx.SetFastFlag(7)
	ctx.SetFastFlag(37)

	snapshot, err := ctx.SnapshotForReplay()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.queryWire) == 0 || len(snapshot.clientOpt) == 0 || len(snapshot.respOpt) == 0 {
		t.Fatal("snapshot did not retain compact DNS/EDNS wire state")
	}

	// Mutating the source after capture must not change the replay template.
	ctx.Q().Question[0].Name = "mutated-source.example."
	ctx.QOpt().SetUDPSize(2048)
	ctx.ClientOpt().SetUDPSize(512)
	ctx.RespOpt().SetUDPSize(512)
	ctx.StoreValue(valueKey, "source-mutated")
	ctx.DeleteMark(42)
	ctx.DeleteFastFlag(37)

	first, err := snapshot.ContextForReplay()
	if err != nil {
		t.Fatal(err)
	}
	if got := first.ConsumeFastCacheHits(); got != 0 {
		t.Fatalf("replay retained one-shot fast-cache sample %d", got)
	}
	if first.ServerMeta.FastCacheHits != 0 {
		t.Fatalf("replay server metadata retained fast-cache hits %d", first.ServerMeta.FastCacheHits)
	}
	if first.TraceID != "" || first.Id() != 0 || !first.StartTime().IsZero() {
		t.Fatal("client trace identity was retained in compact replay state")
	}
	first.RenewTrace()
	if first.TraceID == "" || first.Id() == 0 || first.StartTime().IsZero() {
		t.Fatal("replay trace identity was not renewed")
	}
	if first.QQuestion().Name != "snapshot.example." || !first.Q().AuthenticatedData || !first.Q().Compress {
		t.Fatalf("query state was not restored: %#v", first.Q())
	}
	if first.QOpt().UDPSize() != 1232 || len(first.QOpt().Option) != 1 {
		t.Fatalf("query OPT was not restored: %#v", first.QOpt())
	}
	if first.ClientOpt() == nil || first.ClientOpt().UDPSize() != 4096 || !first.ClientOpt().Do() || len(first.ClientOpt().Option) != 1 {
		t.Fatalf("client OPT was not restored: %#v", first.ClientOpt())
	}
	if first.RespOpt() == nil || first.RespOpt().UDPSize() != 1400 || len(first.RespOpt().Option) != 1 {
		t.Fatalf("response OPT was not restored: %#v", first.RespOpt())
	}
	if first.ServerMeta != snapshot.serverMeta || !first.HasMark(42) || !first.HasFastFlag(7) || !first.HasFastFlag(37) {
		t.Fatal("server metadata, marks or fast flags were not restored")
	}
	if value, ok := first.GetValue(valueKey); !ok || value != "captured" {
		t.Fatalf("stored value = %#v, %v; want captured", value, ok)
	}
	if first.R() != nil || first.UpstreamOpt() != nil {
		t.Fatal("response-side state leaked into replay Context")
	}

	// Every execution gets independent mutable DNS state and maps.
	first.Q().Question[0].Name = "mutated-first.example."
	first.QOpt().SetUDPSize(9000)
	first.ClientOpt().SetUDPSize(9000)
	first.RespOpt().SetUDPSize(9000)
	first.StoreValue(valueKey, "first-mutated")
	first.DeleteMark(42)
	first.DeleteFastFlag(37)

	second, err := snapshot.ContextForReplay()
	if err != nil {
		t.Fatal(err)
	}
	if second.QQuestion().Name != "snapshot.example." || !second.Q().Compress || second.QOpt().UDPSize() != 1232 ||
		second.ClientOpt().UDPSize() != 4096 || second.RespOpt().UDPSize() != 1400 {
		t.Fatal("one replay execution mutated the immutable template")
	}
	if value, _ := second.GetValue(valueKey); value != "captured" || !second.HasMark(42) || !second.HasFastFlag(37) {
		t.Fatal("one replay execution mutated template values, marks or flags")
	}
}

func TestReplaySnapshotRejectsEmptyInput(t *testing.T) {
	if _, err := (*Context)(nil).SnapshotForReplay(); err == nil {
		t.Fatal("nil Context snapshot unexpectedly succeeded")
	}
	if _, err := (*ReplaySnapshot)(nil).ContextForReplay(); err == nil {
		t.Fatal("nil replay snapshot unexpectedly materialized")
	}
}
