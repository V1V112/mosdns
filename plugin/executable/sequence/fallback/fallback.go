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

type fallbackResultSource uint8

const (
	fallbackResultPrimary fallbackResultSource = iota
	fallbackResultSecondary
)

type fallbackResult struct {
	source  fallbackResultSource
	qCtx    *query_context.Context
	success bool
}

func (f *fallback) doFallback(ctx context.Context, qCtx *query_context.Context) error {
	runCtx, cancelAll := context.WithCancel(ctx)
	defer cancelAll()

	resultChan := make(chan fallbackResult, 2)

	go func() {
		qCtxP := qCtx.Copy()
		execCtx, cancel := makeDdlCtx(runCtx, defaultParallelTimeout)
		defer cancel()

		err := f.primary.Exec(execCtx, qCtxP)
		primarySucceeded := false
		if err != nil {
			if errors.Is(err, sequence.ErrExit) {
				primarySucceeded = true
			} else {
				f.logger.Warn("primary error", qCtxP.InfoField(), zap.Error(err))
			}
		} else if qCtxP.R() != nil {
			primarySucceeded = true
		}

		sendFallbackResult(runCtx, resultChan, fallbackResult{
			source:  fallbackResultPrimary,
			qCtx:    qCtxP,
			success: primarySucceeded,
		})
	}()

	secondaryStarted := false
	startSecondary := func() {
		if secondaryStarted {
			return
		}
		secondaryStarted = true

		go func() {
			qCtxS := qCtx.Copy()
			execCtx, cancel := makeDdlCtx(runCtx, defaultParallelTimeout)
			defer cancel()

			err := f.secondary.Exec(execCtx, qCtxS)
			secondarySucceeded := false
			if err != nil {
				f.logger.Warn("secondary error", qCtxS.InfoField(), zap.Error(err))
			} else if qCtxS.R() != nil {
				secondarySucceeded = true
			}

			sendFallbackResult(runCtx, resultChan, fallbackResult{
				source:  fallbackResultSecondary,
				qCtx:    qCtxS,
				success: secondarySucceeded,
			})
		}()
	}

	var timer *time.Timer
	var timerC <-chan time.Time
	if !f.primaryFailureOnly {
		timer = pool.GetTimer(f.fastFallbackDuration)
		defer pool.ReleaseTimer(timer)
		timerC = timer.C
	}

	if f.alwaysStandby {
		startSecondary()
	}

	primaryDone := false
	primaryFailed := false
	secondaryDone := false
	thresholdReached := false
	var secondarySuccessCtx *query_context.Context

	useSecondaryIfAllowed := func() bool {
		if secondarySuccessCtx == nil {
			return false
		}
		if f.primaryFailureOnly {
			if !primaryFailed {
				return false
			}
		} else if f.alwaysStandby && !thresholdReached {
			return false
		}

		secondarySuccessCtx.CopyTo(qCtx)
		return true
	}

	for {
		if useSecondaryIfAllowed() {
			return nil
		}

		if primaryDone && primaryFailed {
			if f.primaryFailureOnly && !secondaryStarted {
				startSecondary()
			}
			if secondaryStarted && secondaryDone && secondarySuccessCtx == nil {
				return ErrFailed
			}
		}

		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-timerC:
			thresholdReached = true
			timerC = nil
			if !f.alwaysStandby && !secondaryStarted {
				startSecondary()
			}
		case result := <-resultChan:
			switch result.source {
			case fallbackResultPrimary:
				primaryDone = true
				if result.success {
					result.qCtx.CopyTo(qCtx)
					return nil
				}
				primaryFailed = true
			case fallbackResultSecondary:
				secondaryDone = true
				if result.success {
					// In primary_failure_only mode, secondary is allowed to run in
					// parallel, but its result must only be cached here. It can be
					// copied to the original qCtx only after primary explicitly fails.
					secondarySuccessCtx = result.qCtx
				}
			}
		}
	}
}

func sendFallbackResult(ctx context.Context, ch chan<- fallbackResult, result fallbackResult) {
	select {
	case ch <- result:
	case <-ctx.Done():
	}
}

func makeDdlCtx(ctx context.Context, timeout time.Duration) (context.Context, func()) {
	ddl, ok := ctx.Deadline()
	if !ok {
		ddl = time.Now().Add(timeout)
	}
	return context.WithDeadline(ctx, ddl)
}
