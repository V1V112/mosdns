package fallback

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
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

func assertDNSMsgEqual(t *testing.T, got, want *dns.Msg) {
	t.Helper()
	if got == nil || want == nil {
		if got != want {
			t.Fatalf("DNS response mismatch: got %v, want %v", got, want)
		}
		return
	}
	gotWire, gotErr := got.Pack()
	wantWire, wantErr := want.Pack()
	if gotErr != nil || wantErr != nil {
		t.Fatalf("pack DNS response: got error %v, want error %v", gotErr, wantErr)
	}
	if !bytes.Equal(gotWire, wantWire) {
		t.Fatalf("DNS response mismatch:\n got: %v\nwant: %v", got, want)
	}
}

func TestExpectedLosingBranchCancellationIsNotWarned(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	secondaryDone := make(chan struct{})
	primaryResp := new(dns.Msg)
	primaryResp.Rcode = dns.RcodeSuccess

	f := &fallback{
		logger: zap.New(core),
		primary: executableFunc(func(_ context.Context, qCtx *query_context.Context) error {
			qCtx.SetResponse(primaryResp)
			return nil
		}),
		secondary: executableFunc(func(ctx context.Context, _ *query_context.Context) error {
			defer close(secondaryDone)
			<-ctx.Done()
			return context.Cause(ctx)
		}),
		fastFallbackDuration: defaultFallbackThreshold,
		alwaysStandby:        true,
	}

	q := new(dns.Msg)
	q.SetQuestion("example.org.", dns.TypeA)
	if err := f.Exec(context.Background(), query_context.NewContext(q)); err != nil {
		t.Fatalf("Exec() error = %v", err)
	}
	select {
	case <-secondaryDone:
	case <-time.After(time.Second):
		t.Fatal("secondary branch did not observe coordinator cancellation")
	}
	if got := logs.FilterMessage("secondary error").Len(); got != 0 {
		t.Fatalf("expected cancellation produced %d secondary warnings", got)
	}
}

func TestShouldLogBranchError(t *testing.T) {
	runCtx, cancel := context.WithCancel(context.Background())
	cancel()

	if shouldLogBranchError(runCtx, context.Canceled) {
		t.Fatal("coordinator cancellation should not be logged")
	}
	if !shouldLogBranchError(runCtx, context.DeadlineExceeded) {
		t.Fatal("deadline exceeded should remain visible")
	}
	if !shouldLogBranchError(context.Background(), context.Canceled) {
		t.Fatal("independent branch cancellation should remain visible")
	}
	if shouldLogBranchError(context.Background(), sequence.ErrExit) {
		t.Fatal("sequence exit should not be logged")
	}
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
	assertDNSMsgEqual(t, qCtx.R(), primaryResp)
}

func TestExecTreatsWrappedExitWithResponseAsPrimarySuccess(t *testing.T) {
	primaryResp := new(dns.Msg)
	primaryResp.Id = 1001

	f := &fallback{
		primary: stubExecutable{
			err:  fmt.Errorf("wrapped control signal: %w", sequence.ErrExit),
			resp: primaryResp,
		},
		secondary:            stubExecutable{resp: new(dns.Msg)},
		fastFallbackDuration: defaultFallbackThreshold,
	}

	qCtx := query_context.NewContext(new(dns.Msg))
	if err := f.Exec(context.Background(), qCtx); err != nil {
		t.Fatalf("Exec() error = %v", err)
	}
	assertDNSMsgEqual(t, qCtx.R(), primaryResp)
}

func TestPrimaryExitWithoutResponseFallsBackToSecondary(t *testing.T) {
	secondaryResp := new(dns.Msg)
	secondaryResp.Id = 2002

	f := &fallback{
		primary:              stubExecutable{err: sequence.ErrExit},
		secondary:            stubExecutable{resp: secondaryResp},
		fastFallbackDuration: defaultFallbackThreshold,
		primaryFailureOnly:   true,
	}

	qCtx := query_context.NewContext(new(dns.Msg))
	if err := f.Exec(context.Background(), qCtx); err != nil {
		t.Fatalf("Exec() error = %v", err)
	}
	assertDNSMsgEqual(t, qCtx.R(), secondaryResp)
}

func TestSecondaryExitWithResponseIsSuccessful(t *testing.T) {
	for _, alwaysStandby := range []bool{false, true} {
		t.Run(fmt.Sprintf("always_standby=%t", alwaysStandby), func(t *testing.T) {
			secondaryResp := new(dns.Msg)
			secondaryResp.Id = 3003

			f := &fallback{
				primary:              stubExecutable{},
				secondary:            stubExecutable{err: sequence.ErrExit, resp: secondaryResp},
				fastFallbackDuration: defaultFallbackThreshold,
				alwaysStandby:        alwaysStandby,
				primaryFailureOnly:   true,
			}

			qCtx := query_context.NewContext(new(dns.Msg))
			if err := f.Exec(context.Background(), qCtx); err != nil {
				t.Fatalf("Exec() error = %v", err)
			}
			assertDNSMsgEqual(t, qCtx.R(), secondaryResp)
		})
	}
}

func TestOuterMultiExecContinuesAfterFallbackBranchExit(t *testing.T) {
	primaryResp := new(dns.Msg)
	primaryResp.Id = 4101
	secondaryResp := new(dns.Msg)
	secondaryResp.Id = 4102

	tests := []struct {
		name               string
		primary            sequence.Executable
		secondary          sequence.Executable
		primaryFailureOnly bool
		wantResp           *dns.Msg
	}{
		{
			name:      "primary",
			primary:   stubExecutable{err: sequence.ErrExit, resp: primaryResp},
			secondary: stubExecutable{},
			wantResp:  primaryResp,
		},
		{
			name:               "secondary",
			primary:            stubExecutable{},
			secondary:          stubExecutable{err: sequence.ErrExit, resp: secondaryResp},
			primaryFailureOnly: true,
			wantResp:           secondaryResp,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fallback{
				primary:              tt.primary,
				secondary:            tt.secondary,
				fastFallbackDuration: defaultFallbackThreshold,
				primaryFailureOnly:   tt.primaryFailureOnly,
			}

			postCalls := 0
			postSawResponse := false
			post := executableFunc(func(_ context.Context, qCtx *query_context.Context) error {
				postCalls++
				postSawResponse = qCtx.R() != nil && qCtx.R().Id == tt.wantResp.Id
				return nil
			})

			plugins := map[string]any{
				"fallback": f,
				"post":     post,
			}
			m := coremain.NewTestMosdnsWithPlugins(plugins)
			outer, err := sequence.NewSequence(coremain.NewBP("outer", m), []sequence.RuleArgs{
				{Exec: []string{"$fallback", "$post"}},
			})
			if err != nil {
				t.Fatalf("NewSequence() error = %v", err)
			}

			q := new(dns.Msg)
			q.SetQuestion("example.org.", dns.TypeA)
			qCtx := query_context.NewContext(q)
			if err := outer.Exec(context.Background(), qCtx); err != nil {
				t.Fatalf("Exec() error = %v", err)
			}

			if postCalls != 1 {
				t.Fatalf("post calls = %d, want 1", postCalls)
			}
			if !postSawResponse {
				t.Fatalf("post did not observe fallback response %v", tt.wantResp)
			}
			assertDNSMsgEqual(t, qCtx.R(), tt.wantResp)
		})
	}
}

func TestOrdinaryPrimaryErrorStillFallsBackToSecondary(t *testing.T) {
	secondaryResp := new(dns.Msg)
	secondaryResp.Id = 4004

	f := &fallback{
		logger:               zap.NewNop(),
		primary:              stubExecutable{err: errors.New("primary failed")},
		secondary:            stubExecutable{resp: secondaryResp},
		fastFallbackDuration: defaultFallbackThreshold,
		primaryFailureOnly:   true,
	}

	qCtx := query_context.NewContext(new(dns.Msg))
	if err := f.Exec(context.Background(), qCtx); err != nil {
		t.Fatalf("Exec() error = %v", err)
	}
	assertDNSMsgEqual(t, qCtx.R(), secondaryResp)
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

	assertDNSMsgEqual(t, qCtx.R(), secondaryResp)
}

func TestAlwaysStandbyPrimaryFailureOnlyStartsSecondaryImmediately(t *testing.T) {
	primaryStarted := make(chan struct{})
	allowPrimaryFail := make(chan struct{})
	secondaryStarted := make(chan struct{}, 1)
	secondaryResp := new(dns.Msg)
	secondaryResp.Rcode = dns.RcodeSuccess

	f := &fallback{
		primary: executableFunc(func(_ context.Context, _ *query_context.Context) error {
			close(primaryStarted)
			<-allowPrimaryFail
			// No response means primary explicitly failed.
			return nil
		}),
		secondary: executableFunc(func(_ context.Context, qCtx *query_context.Context) error {
			secondaryStarted <- struct{}{}
			qCtx.SetResponse(secondaryResp)
			return nil
		}),
		fastFallbackDuration: time.Second,
		alwaysStandby:        true,
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
	case <-time.After(time.Second):
		t.Fatal("secondary did not start immediately in always_standby + primary_failure_only mode")
	}

	select {
	case err := <-done:
		t.Fatalf("Exec() returned before primary failed, err = %v", err)
	case <-time.After(time.Millisecond * 50):
	}

	close(allowPrimaryFail)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Exec() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Exec() did not return after primary failed")
	}

	assertDNSMsgEqual(t, qCtx.R(), secondaryResp)
}

func TestFastFallbackLazyStartsSecondaryAfterThreshold(t *testing.T) {
	primaryStarted := make(chan struct{})
	allowPrimaryReturn := make(chan struct{})
	secondaryStarted := make(chan struct{}, 1)
	secondaryResp := new(dns.Msg)
	secondaryResp.Rcode = dns.RcodeSuccess

	f := &fallback{
		primary: executableFunc(func(_ context.Context, _ *query_context.Context) error {
			close(primaryStarted)
			<-allowPrimaryReturn
			return nil
		}),
		secondary: executableFunc(func(_ context.Context, qCtx *query_context.Context) error {
			secondaryStarted <- struct{}{}
			qCtx.SetResponse(secondaryResp)
			return nil
		}),
		fastFallbackDuration: time.Millisecond * 50,
	}

	qCtx := query_context.NewContext(new(dns.Msg))
	done := make(chan error, 1)
	go func() {
		done <- f.Exec(context.Background(), qCtx)
	}()

	<-primaryStarted
	select {
	case <-secondaryStarted:
		t.Fatal("secondary started before threshold")
	case <-time.After(time.Millisecond * 20):
	}

	select {
	case <-secondaryStarted:
	case <-time.After(time.Second):
		t.Fatal("secondary did not start after threshold")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Exec() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Exec() did not return")
	}

	close(allowPrimaryReturn)
	assertDNSMsgEqual(t, qCtx.R(), secondaryResp)
}

func TestAlwaysStandbyFastFallbackReturnsSecondaryAfterThreshold(t *testing.T) {
	primaryStarted := make(chan struct{})
	allowPrimaryReturn := make(chan struct{})
	secondaryStarted := make(chan struct{}, 1)
	secondaryResp := new(dns.Msg)
	secondaryResp.Rcode = dns.RcodeSuccess
	threshold := time.Millisecond * 60

	f := &fallback{
		primary: executableFunc(func(_ context.Context, _ *query_context.Context) error {
			close(primaryStarted)
			<-allowPrimaryReturn
			return nil
		}),
		secondary: executableFunc(func(_ context.Context, qCtx *query_context.Context) error {
			secondaryStarted <- struct{}{}
			qCtx.SetResponse(secondaryResp)
			return nil
		}),
		fastFallbackDuration: threshold,
		alwaysStandby:        true,
	}

	qCtx := query_context.NewContext(new(dns.Msg))
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- f.Exec(context.Background(), qCtx)
	}()

	<-primaryStarted
	select {
	case <-secondaryStarted:
	case <-time.After(time.Second):
		t.Fatal("secondary did not start immediately in always_standby mode")
	}

	select {
	case err := <-done:
		t.Fatalf("Exec() returned before threshold, err = %v", err)
	case <-time.After(threshold / 2):
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Exec() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Exec() did not return after threshold")
	}

	close(allowPrimaryReturn)
	if elapsed := time.Since(start); elapsed < threshold {
		t.Fatalf("Exec() returned before threshold: elapsed = %v, threshold = %v", elapsed, threshold)
	}
	assertDNSMsgEqual(t, qCtx.R(), secondaryResp)
}

func TestAlwaysStandbyPrimaryFailureOnlyKeepsSecondaryResultUntilPrimaryFails(t *testing.T) {
	primaryStarted := make(chan struct{})
	allowPrimarySuccess := make(chan struct{})
	secondaryStarted := make(chan struct{}, 1)
	primaryResp := new(dns.Msg)
	primaryResp.Rcode = dns.RcodeSuccess
	primaryResp.Id = 1001
	secondaryResp := new(dns.Msg)
	secondaryResp.Rcode = dns.RcodeSuccess
	secondaryResp.Id = 2002

	f := &fallback{
		primary: executableFunc(func(_ context.Context, qCtx *query_context.Context) error {
			close(primaryStarted)
			<-allowPrimarySuccess
			qCtx.SetResponse(primaryResp)
			return nil
		}),
		secondary: executableFunc(func(_ context.Context, qCtx *query_context.Context) error {
			secondaryStarted <- struct{}{}
			qCtx.SetResponse(secondaryResp)
			return nil
		}),
		fastFallbackDuration: time.Second,
		alwaysStandby:        true,
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
	case <-time.After(time.Second):
		t.Fatal("secondary did not start immediately in always_standby + primary_failure_only mode")
	}

	select {
	case err := <-done:
		t.Fatalf("Exec() returned before primary succeeded or failed, err = %v", err)
	case <-time.After(time.Millisecond * 50):
	}

	close(allowPrimarySuccess)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Exec() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Exec() did not return after primary succeeded")
	}

	if qCtx.R() == nil || qCtx.R().Id != primaryResp.Id {
		t.Fatalf("expected primary response to win, got %v", qCtx.R())
	}
}

func TestAlwaysStandbyPrimaryFailureOnlyUsesSecondaryAfterAcceptThreshold(t *testing.T) {
	primaryStarted := make(chan struct{})
	allowPrimaryFail := make(chan struct{})
	secondaryStarted := make(chan struct{}, 1)
	secondaryResp := new(dns.Msg)
	secondaryResp.Rcode = dns.RcodeSuccess
	secondaryResp.Id = 3003
	acceptDelay := time.Millisecond * 80

	f := &fallback{
		primary: executableFunc(func(_ context.Context, _ *query_context.Context) error {
			close(primaryStarted)
			<-allowPrimaryFail
			// No response means primary explicitly failed.
			return nil
		}),
		secondary: executableFunc(func(_ context.Context, qCtx *query_context.Context) error {
			secondaryStarted <- struct{}{}
			qCtx.SetResponse(secondaryResp)
			return nil
		}),
		fastFallbackDuration: defaultFallbackThreshold,
		alwaysStandby:        true,
		primaryFailureOnly:   true,
		secondaryAcceptDelay: acceptDelay,
	}

	qCtx := query_context.NewContext(new(dns.Msg))
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- f.Exec(context.Background(), qCtx)
	}()

	<-primaryStarted
	select {
	case <-secondaryStarted:
	case <-time.After(time.Second):
		t.Fatal("secondary did not start immediately in always_standby + primary_failure_only mode")
	}

	close(allowPrimaryFail)
	select {
	case err := <-done:
		t.Fatalf("Exec() returned before secondary_accept_threshold elapsed, err = %v", err)
	case <-time.After(acceptDelay / 2):
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Exec() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Exec() did not return after secondary_accept_threshold elapsed")
	}

	if elapsed := time.Since(start); elapsed < acceptDelay {
		t.Fatalf("Exec() returned before secondary_accept_threshold: elapsed = %v, threshold = %v", elapsed, acceptDelay)
	}
	if qCtx.R() == nil || qCtx.R().Id != secondaryResp.Id {
		t.Fatalf("expected secondary response after accept threshold, got %v", qCtx.R())
	}
}
