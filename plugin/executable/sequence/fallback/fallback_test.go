package fallback

import (
	"context"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

type stubExecutable struct {
	err  error
	resp *dns.Msg
}

func (s stubExecutable) Exec(_ context.Context, qCtx *query_context.Context) error {
	if s.err != nil {
		return s.err
	}
	if s.resp != nil {
		qCtx.SetResponse(s.resp)
	}
	return nil
}

func TestExecTreatsExitWithResponseAsPrimarySuccess(t *testing.T) {
	primaryResp := new(dns.Msg)
	primaryResp.Rcode = dns.RcodeSuccess

	f := &fallback{
		primary:              stubExecutable{err: sequence.ErrExit, resp: primaryResp},
		secondary:            stubExecutable{resp: new(dns.Msg)},
		fastFallbackDuration: defaultFallbackThreshold,
	}

	qCtx := query_context.NewContext(new(dns.Msg))
	if err := f.Exec(context.Background(), qCtx); err != nil {
		t.Fatalf("Exec() error = %v", err)
	}
	if qCtx.R() != primaryResp {
		t.Fatalf("expected primary response to be preserved, got %v", qCtx.R())
	}
}
