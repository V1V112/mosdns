package query_context

import (
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestRenewTrace(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("example.org.", dns.TypeA)
	ctx := NewContext(q)
	oldID, oldTrace, oldStart := ctx.Id(), ctx.TraceID, ctx.StartTime()

	time.Sleep(time.Millisecond)
	before := time.Now()
	ctx.RenewTrace()
	after := time.Now()

	if ctx.Id() == oldID || ctx.TraceID == oldTrace {
		t.Fatal("RenewTrace did not assign a new identity")
	}
	if !ctx.StartTime().After(oldStart) {
		t.Fatal("RenewTrace did not restart elapsed-time accounting")
	}
	if ctx.StartTime().Before(before) || ctx.StartTime().After(after) {
		t.Fatalf("renewed start time %s is outside call interval [%s, %s]", ctx.StartTime(), before, after)
	}
}

func TestCopyWithoutResponse(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("example.org.", dns.TypeA)
	clientOpt := newOpt()
	clientOpt.Option = append(clientOpt.Option, &dns.EDNS0_LOCAL{
		Code: 65001,
		Data: []byte{1, 2, 3},
	})
	q.Extra = append(q.Extra, clientOpt)

	ctx := NewContext(q)
	ctx.ServerMeta = ServerMeta{
		FromUDP:          true,
		ClientAddr:       netip.MustParseAddr("192.0.2.1"),
		ServerName:       "test-server",
		UrlPath:          "/dns-query",
		PreFastFlags:     1 << 9,
		PreFastDomainSet: "test-domain-set",
	}

	upstreamOpt := newOpt()
	upstreamOpt.Option = append(upstreamOpt.Option, &dns.EDNS0_LOCAL{
		Code: 65002,
		Data: []byte{4, 5, 6},
	})
	resp := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:       q.Id,
			Response: true,
			Rcode:    dns.RcodeSuccess,
		},
		Question: append([]dns.Question(nil), q.Question...),
		Extra:    []dns.RR{upstreamOpt},
	}
	ctx.SetResponse(resp)

	valueKey := RegKey()
	ctx.StoreValue(valueKey, "original")
	ctx.SetMark(42)
	ctx.SetFastFlag(7)
	ctx.SetFastFlag(37)

	copied := ctx.CopyWithoutResponse()

	if copied == ctx {
		t.Fatal("CopyWithoutResponse returned the original Context")
	}
	if copied.R() != nil {
		t.Fatal("response was copied")
	}
	if copied.UpstreamOpt() != nil {
		t.Fatal("upstream OPT was copied")
	}
	if ctx.R() == nil || ctx.UpstreamOpt() == nil {
		t.Fatal("copying modified the source response state")
	}

	if copied.TraceID != ctx.TraceID || copied.Id() != ctx.Id() || copied.StartTime() != ctx.StartTime() {
		t.Fatal("context identity metadata was not preserved")
	}
	if copied.ServerMeta != ctx.ServerMeta {
		t.Fatalf("server metadata mismatch: got %+v, want %+v", copied.ServerMeta, ctx.ServerMeta)
	}
	if copied.FastQName != ctx.FastQName || copied.FastQType != ctx.FastQType {
		t.Fatal("fast query fields were not preserved")
	}

	if copied.Q() == ctx.Q() {
		t.Fatal("query was not deep-copied")
	}
	copied.Q().Question[0].Name = "copied.example.org."
	if ctx.Q().Question[0].Name != "example.org." {
		t.Fatal("mutating the copied query changed the source query")
	}
	copied.QOpt().SetUDPSize(4096)
	if ctx.QOpt().UDPSize() == 4096 {
		t.Fatal("mutating the copied query OPT changed the source query OPT")
	}

	if copied.ClientOpt() == nil || copied.ClientOpt() == ctx.ClientOpt() {
		t.Fatal("client OPT was not deep-copied")
	}
	copied.ClientOpt().SetUDPSize(2048)
	if ctx.ClientOpt().UDPSize() == 2048 {
		t.Fatal("mutating the copied client OPT changed the source client OPT")
	}
	if copied.RespOpt() == nil || copied.RespOpt() == ctx.RespOpt() {
		t.Fatal("response OPT was not deep-copied")
	}
	copied.RespOpt().SetUDPSize(3072)
	if ctx.RespOpt().UDPSize() == 3072 {
		t.Fatal("mutating the copied response OPT changed the source response OPT")
	}

	copied.StoreValue(valueKey, "copied")
	if got, _ := ctx.GetValue(valueKey); got != "original" {
		t.Fatal("updating a copied value changed the source value")
	}

	if !copied.HasMark(42) {
		t.Fatal("mark was not preserved")
	}
	copied.DeleteMark(42)
	if !ctx.HasMark(42) {
		t.Fatal("marks map is shared with the source Context")
	}
	if !copied.HasFastFlag(7) || !copied.HasFastFlag(37) {
		t.Fatal("fast flags were not preserved")
	}
	copied.DeleteFastFlag(37)
	if !ctx.HasFastFlag(37) {
		t.Fatal("updating copied fast flags changed the source Context")
	}
}

func TestCopyWithoutResponseWithNilOptionalState(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("example.org.", dns.TypeAAAA)
	ctx := NewContext(q)

	copied := ctx.CopyWithoutResponse()

	if copied.R() != nil || copied.UpstreamOpt() != nil {
		t.Fatal("response state should be empty")
	}
	if copied.ClientOpt() != nil || copied.RespOpt() != nil {
		t.Fatal("absent EDNS client state should remain absent")
	}
	if copied.kv != nil || copied.marks != nil {
		t.Fatal("nil maps should remain nil")
	}
}

func TestSetUpstreamOptCopiesAndClears(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("example.org.", dns.TypeA)
	ctx := NewContext(q)

	local := &dns.EDNS0_LOCAL{
		Code: 65001,
		Data: []byte{1, 2, 3},
	}
	opt := newOpt()
	opt.SetUDPSize(4096)
	opt.Option = append(opt.Option, local)

	ctx.SetUpstreamOpt(opt)
	got := ctx.UpstreamOpt()
	if got == nil {
		t.Fatal("upstream OPT was not set")
	}
	if got == opt {
		t.Fatal("Context took ownership of the caller's OPT instead of copying it")
	}
	if got.UDPSize() != opt.UDPSize() {
		t.Fatalf("UDP size mismatch: got %d, want %d", got.UDPSize(), opt.UDPSize())
	}
	if len(got.Option) != 1 {
		t.Fatalf("option count mismatch: got %d, want 1", len(got.Option))
	}
	gotLocal, ok := got.Option[0].(*dns.EDNS0_LOCAL)
	if !ok {
		t.Fatalf("unexpected copied option type %T", got.Option[0])
	}
	if gotLocal == local {
		t.Fatal("nested EDNS option was not deep-copied")
	}

	opt.SetUDPSize(1232)
	local.Data[0] = 9
	if got.UDPSize() != 4096 || gotLocal.Data[0] != 1 {
		t.Fatal("mutating the caller-owned OPT changed the Context copy")
	}
	gotLocal.Data[1] = 8
	if local.Data[1] != 2 {
		t.Fatal("mutating the Context copy changed the caller-owned OPT")
	}

	ctx.SetUpstreamOpt(nil)
	if ctx.UpstreamOpt() != nil {
		t.Fatal("passing nil did not clear the upstream OPT")
	}
}

func TestCacheRefreshMarker(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("example.org.", dns.TypeA)
	ctx := NewContext(q)

	if ctx.IsCacheRefresh() {
		t.Fatal("new Context is marked as a cache refresh")
	}
	ctx.StoreValue(KeyCacheRefresh, "true")
	if ctx.IsCacheRefresh() {
		t.Fatal("non-boolean marker value was accepted")
	}
	ctx.MarkCacheRefresh()
	if !ctx.IsCacheRefresh() {
		t.Fatal("MarkCacheRefresh did not set the marker")
	}
}
