package fallback

import (
	"context"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

type stubExecutable struct {
	err  error
	resp *dns.Msg
}

func (s stubExecutable) Exec(_ context.Context, qCtx *query_context.Context) error {
	if s.resp != nil {
		qCtx.SetResponse(s.resp)
	}
	if s.err != nil {
		return s.err
	}
	return nil
}

type executableFunc func(context.Context, *query_context.Context) error

func (f executableFunc) Exec(ctx context.Context, qCtx *query_context.Context) error {
	return f(ctx, qCtx)
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

func TestPrimaryFailureOnlyDoesNotStartSecondaryOnThreshold(t *testing.T) {
	primaryStarted := make(chan struct{})
	allowPrimaryFail := make(chan struct{})
	secondaryStarted := make(chan struct{}, 1)
	secondaryResp := new(dns.Msg)
	secondaryResp.Rcode = dns.RcodeSuccess

	f := &fallback{
		primary: executableFunc(func(_ context.Context, _ *query_context.Context) error {
			close(primaryStarted)
			<-allowPrimaryFail
			// No response means primary failed.
			return nil
		}),
		secondary: executableFunc(func(_ context.Context, qCtx *query_context.Context) error {
			secondaryStarted <- struct{}{}
			qCtx.SetResponse(secondaryResp)
			return nil
		}),
		fastFallbackDuration: time.Millisecond * 10,
		primaryFailureOnly:   true,
	}

	qCtx := query_context.NewContext(new(dns.Msg))
	done := make(chan error, 1)
	go func() {
		done <- f.Exec(context.Background(), qCtx)
	}()

	<-primaryStarted
	select {
	case <-secondaryStarted:
		t.Fatal("secondary started before primary explicitly failed")
	case <-time.After(time.Millisecond * 50):
	}

	close(allowPrimaryFail)
	select {
	case <-secondaryStarted:
	case <-time.After(time.Second):
		t.Fatal("secondary did not start after primary failed")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Exec() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Exec() did not return")
	}

	if qCtx.R() != secondaryResp {
		t.Fatalf("expected secondary response, got %v", qCtx.R())
	}
}
