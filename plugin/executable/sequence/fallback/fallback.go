/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package fallback

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"go.uber.org/zap"
)

const PluginType = "fallback"

const (
	defaultParallelTimeout   = time.Second * 5
	defaultFallbackThreshold = time.Millisecond * 500
)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

type fallback struct {
	logger               *zap.Logger
	primary              sequence.Executable
	secondary            sequence.Executable
	fastFallbackDuration time.Duration
	alwaysStandby        bool
	primaryFailureOnly   bool
}

type Args struct {
	// Primary exec sequence.
	Primary string `yaml:"primary"`
	// Secondary exec sequence.
	Secondary string `yaml:"secondary"`

	// Threshold in milliseconds. Default is 500.
	Threshold int `yaml:"threshold"`

	// AlwaysStandby: secondary should always stand by in fallback.
	AlwaysStandby bool `yaml:"always_standby"`

	// PrimaryFailureOnly: secondary only starts after primary explicitly failed.
	// If enabled, threshold timeout will not trigger secondary.
	PrimaryFailureOnly bool `yaml:"primary_failure_only"`
}

func Init(bp *coremain.BP, args any) (any, error) {
	return newFallbackPlugin(bp, args.(*Args))
}

func newFallbackPlugin(bp *coremain.BP, args *Args) (*fallback, error) {
	if len(args.Primary) == 0 || len(args.Secondary) == 0 {
		return nil, errors.New("args missing primary or secondary")
	}

	pe := sequence.ToExecutable(bp.M().GetPlugin(args.Primary))
	if pe == nil {
		return nil, fmt.Errorf("can not find primary executable %s", args.Primary)
	}
	se := sequence.ToExecutable(bp.M().GetPlugin(args.Secondary))
	if se == nil {
		return nil, fmt.Errorf("can not find secondary executable %s", args.Secondary)
	}
	threshold := time.Duration(args.Threshold) * time.Millisecond
	if threshold <= 0 {
		threshold = defaultFallbackThreshold
	}

	s := &fallback{
		logger:               bp.L(),
		primary:              pe,
		secondary:            se,
		fastFallbackDuration: threshold,
		alwaysStandby:        args.AlwaysStandby,
		primaryFailureOnly:   args.PrimaryFailureOnly,
	}
	return s, nil
}

var (
	ErrFailed = errors.New("no valid response from both primary and secondary")
)

var _ sequence.Executable = (*fallback)(nil)

func (f *fallback) Exec(ctx context.Context, qCtx *query_context.Context) error {
	return f.doFallback(ctx, qCtx)
}

func (f *fallback) doFallback(ctx context.Context, qCtx *query_context.Context) error {
	respChan := make(chan *query_context.Context, 2) // resp could be nil.
	primFailed := make(chan struct{})
	primDone := make(chan struct{})

	// primary goroutine.
	qCtxP := qCtx.Copy()
	go func() {
		qCtx := qCtxP
		ctx, cancel := makeDdlCtx(ctx, defaultParallelTimeout)
		defer cancel()
		err := f.primary.Exec(ctx, qCtx)
		primarySucceeded := false
		if err != nil {
			if errors.Is(err, sequence.ErrExit) {
				primarySucceeded = true
			} else {
				f.logger.Warn("primary error", qCtx.InfoField(), zap.Error(err))
			}
		} else if qCtx.R() != nil {
			primarySucceeded = true
		}

		if primarySucceeded {
			close(primDone)
			respChan <- qCtx
		} else {
			close(primFailed)
			respChan <- nil
		}
	}()

	// Secondary goroutine.
	qCtxS := qCtx.Copy()
	go func() {
		timer := pool.GetTimer(f.fastFallbackDuration)
		defer pool.ReleaseTimer(timer)

		if !f.alwaysStandby { // secondary is lazy-started.
			if f.primaryFailureOnly {
				// Strict fallback mode: threshold must not start secondary.
				// It only starts after primary explicitly failed.
				select {
				case <-primDone: // primary is done, no need to exec this.
					respChan <- nil // Send a nil to unblock the main loop.
					return
				case <-primFailed: // primary failed
				}
			} else {
				// Threshold fallback mode: threshold starts secondary.
				select {
				case <-primDone: // primary is done, no need to exec this.
					respChan <- nil // Send a nil to unblock the main loop.
					return
				case <-timer.C: // timed out
				}
			}
		}

		qCtx := qCtxS
		ctx, cancel := makeDdlCtx(ctx, defaultParallelTimeout)
		defer cancel()
		err := f.secondary.Exec(ctx, qCtx)
		if err != nil {
			f.logger.Warn("secondary error", qCtx.InfoField(), zap.Error(err))
			respChan <- nil
			return
		}

		r := qCtx.R()
		if r == nil {
			respChan <- nil
			return
		}

		// always_standby means secondary has already queried in parallel,
		// but its response is held until the selected fallback condition is met.
		if f.alwaysStandby {
			if f.primaryFailureOnly {
				// Parallel strict fallback: use secondary only after primary explicitly failed.
				select {
				case <-ctx.Done():
					respChan <- nil
				case <-primDone:
					respChan <- nil
				case <-primFailed:
					respChan <- qCtx
				}
			} else {
				// Parallel threshold fallback: secondary is usable after threshold.
				select {
				case <-ctx.Done():
					respChan <- nil
				case <-primDone:
					respChan <- nil
				case <-timer.C: // threshold reached.
					respChan <- qCtx
				}
			}
		} else {
			respChan <- qCtx
		}
	}()

	for i := 0; i < 2; i++ {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case successCtx := <-respChan:
			if successCtx == nil { // One of goroutines finished but failed or was skipped.
				continue
			}
			// Copy all data from the successful context to the original context.
			successCtx.CopyTo(qCtx)
			return nil
		}
	}

	// All goroutines finished but failed.
	return ErrFailed
}

func makeDdlCtx(ctx context.Context, timeout time.Duration) (context.Context, func()) {
	ddl, ok := ctx.Deadline()
	if !ok {
		ddl = time.Now().Add(timeout)
	}
	return context.WithDeadline(context.Background(), ddl)
}
