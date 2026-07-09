package fallback

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
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
	if !reflect.DeepEqual(qCtx.R(), primaryResp) {
		t.Fatalf("expected primary response to be preserved, got %v", qCtx.R())
	}
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
	if !reflect.DeepEqual(qCtx.R(), primaryResp) {
		t.Fatalf("expected wrapped ErrExit response to be preserved, got %v", qCtx.R())
	}
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
	if !reflect.DeepEqual(qCtx.R(), secondaryResp) {
		t.Fatalf("expected secondary response after response-less ErrExit, got %v", qCtx.R())
	}
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
			if !reflect.DeepEqual(qCtx.R(), secondaryResp) {
				t.Fatalf("expected secondary ErrExit response, got %v", qCtx.R())
			}
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
	if !reflect.DeepEqual(qCtx.R(), secondaryResp) {
		t.Fatalf("expected secondary response after ordinary primary error, got %v", qCtx.R())
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

	if !reflect.DeepEqual(qCtx.R(), secondaryResp) {
		t.Fatalf("expected secondary response, got %v", qCtx.R())
	}
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

	if !reflect.DeepEqual(qCtx.R(), secondaryResp) {
		t.Fatalf("expected secondary response, got %v", qCtx.R())
	}
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
	if !reflect.DeepEqual(qCtx.R(), secondaryResp) {
		t.Fatalf("expected secondary response, got %v", qCtx.R())
	}
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
	if !reflect.DeepEqual(qCtx.R(), secondaryResp) {
		t.Fatalf("expected secondary response, got %v", qCtx.R())
	}
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
