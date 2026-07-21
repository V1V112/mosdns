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

// Package prefer_domain implements an executable plugin that replaces an
// existing A/AAAA response with the warmed result of a configured preferred
// domain when the original response IP hits a configured IP matcher provider tag.
package prefer_domain

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const (
	PluginType = "prefer_domain"

	defaultTimeoutMilliseconds = 500
	initialWarmAttempts        = 10
	periodicRefreshAttempts    = 2
	maxConcurrentRefreshes     = 8

	initialWarmRetryInterval = 15 * time.Second
	defaultRefreshAdvance    = 5 * time.Second
	refreshSafetyMargin      = time.Second
	minimumRefreshDelay      = 10 * time.Millisecond
	maxWorkerCloseWait       = 5 * time.Second
)

var internalQueryKey = query_context.RegKey()

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

var _ sequence.Executable = (*PreferDomain)(nil)
var _ interface{ Close() error } = (*PreferDomain)(nil)

// Args is the plugin configuration.
//
// Example:
//
//   - tag: cf_prefer
//     type: prefer_domain
//     args:
//     resolver: fallback_direct
//     timeout: 500         # milliseconds
//     cache_ttl: 301       # seconds; required internal cache TTL
//     warm_on_start: true
//     serve_stale: true
//     max_stale: 3600      # seconds; 0 means unlimited
//     rules:
//   - ip_matcher: cf_manual_ip
//     prefer_domain: cf.example.com
//
// Run the plugin after the resolver whose response should be inspected:
//
//   - exec: [$smartdns_direct, $cf_prefer]
//
// For a single rule, top-level ip_matcher/prefer_domain are also accepted.
// Legacy ip_set/ip_set_tag/ipset fields are still accepted as aliases.
type Args struct {
	// Resolver is used only by background warming and refresh work.
	Resolver string `yaml:"resolver"`

	// Single-rule shorthand.
	IPMatcher       string `yaml:"ip_matcher"`
	Matcher         string `yaml:"matcher"`
	IPSet           string `yaml:"ip_set"`
	IPSetTag        string `yaml:"ip_set_tag"`
	IPSetDeprecated string `yaml:"ipset"`
	PreferDomain    string `yaml:"prefer_domain"`
	Target          string `yaml:"target"`
	Prefer          string `yaml:"prefer"`

	// Multi-rule form. Rules are checked in order; first hit wins.
	Rules []RuleArgs `yaml:"rules"`

	// timeout is always milliseconds. Default is 500.
	Timeout string `yaml:"timeout"`

	// cache_ttl is always seconds. It is the preferred-domain cache's
	// internal TTL and the sole basis for scheduling refresh windows.
	CacheTTL string `yaml:"cache_ttl"`

	WarmOnStart bool `yaml:"warm_on_start"`
	ServeStale  bool `yaml:"serve_stale"`

	// max_stale is always seconds. Default 0 keeps the existing behavior and
	// allows an expired preferred-domain response to be used without an age
	// limit when serve_stale is enabled.
	MaxStale string `yaml:"max_stale"`
}

type RuleArgs struct {
	IPMatcher       string `yaml:"ip_matcher"`
	Matcher         string `yaml:"matcher"`
	IPSet           string `yaml:"ip_set"`
	IPSetTag        string `yaml:"ip_set_tag"`
	IPSetDeprecated string `yaml:"ipset"`
	PreferDomain    string `yaml:"prefer_domain"`
	Target          string `yaml:"target"`
	Prefer          string `yaml:"prefer"`
}

type compiledRule struct {
	ipMatcherTag  string
	preferDomain  string
	preferDisplay string
	matcher       netlist.Matcher
}

type cacheEntry struct {
	msg     *dns.Msg
	stored  time.Time
	expires time.Time
}

type warmTarget struct {
	rule  *compiledRule
	qType uint16
	key   string
}

type warmResult struct {
	target     warmTarget
	err        error
	retryAfter time.Duration
}

type preferredQueryError struct {
	err       error
	retryable bool
}

func (e *preferredQueryError) Error() string {
	return e.err.Error()
}

func (e *preferredQueryError) Unwrap() error {
	return e.err
}

var errPreferredCacheUnavailable = errors.New("preferred-domain cache is unavailable")

type PreferDomain struct {
	logger *zap.Logger

	resolver sequence.Executable
	rules    []compiledRule

	timeout              time.Duration
	cacheTTL             time.Duration
	warmOnStart          bool
	serveStale           bool
	maxStale             time.Duration
	ready                <-chan struct{}
	initialRetryInterval time.Duration
	initialAttempts      int
	refreshAdvance       time.Duration
	refreshSem           chan struct{}

	mu    sync.RWMutex
	cache map[string]cacheEntry

	ctx    context.Context
	cancel context.CancelFunc

	closeOnce   sync.Once
	startOnce   sync.Once
	schedulerWG sync.WaitGroup
	workerWG    sync.WaitGroup
}

func Init(bp *coremain.BP, args any) (any, error) {
	cfg := args.(*Args)
	if cfg.Resolver == "" {
		return nil, fmt.Errorf("%s: resolver must be specified", PluginType)
	}

	resolverPlugin := bp.M().GetPlugin(cfg.Resolver)
	if resolverPlugin == nil {
		return nil, fmt.Errorf("%s: resolver plugin %q not found", PluginType, cfg.Resolver)
	}
	resolver := sequence.ToExecutable(resolverPlugin)
	if resolver == nil {
		return nil, fmt.Errorf("%s: resolver plugin %q is not executable", PluginType, cfg.Resolver)
	}

	timeout, err := parseFixedDuration(
		cfg.Timeout,
		defaultTimeoutMilliseconds,
		time.Millisecond,
	)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid timeout: %w", PluginType, err)
	}
	cacheTTL, err := parseFixedDuration(cfg.CacheTTL, 0, time.Second)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid cache_ttl: %w", PluginType, err)
	}
	maxStale, err := parseFixedDuration(cfg.MaxStale, 0, time.Second)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid max_stale: %w", PluginType, err)
	}
	if maxStale > 0 && !cfg.ServeStale {
		return nil, fmt.Errorf("%s: max_stale requires serve_stale", PluginType)
	}
	if cacheTTL <= defaultRefreshAdvance {
		return nil, fmt.Errorf("%s: cache_ttl must be greater than %d seconds", PluginType, int(defaultRefreshAdvance/time.Second))
	}
	if timeout <= 0 {
		return nil, fmt.Errorf("%s: timeout must be greater than 0", PluginType)
	}
	if timeout >= defaultRefreshAdvance/periodicRefreshAttempts {
		return nil, fmt.Errorf("%s: timeout must be less than %s so both refresh attempts fit before cache expiry", PluginType, defaultRefreshAdvance/periodicRefreshAttempts)
	}
	ruleArgs := normalizeRuleArgs(cfg)
	if len(ruleArgs) == 0 {
		return nil, fmt.Errorf("%s: at least one rule is required", PluginType)
	}

	rules := make([]compiledRule, 0, len(ruleArgs))
	for i, r := range ruleArgs {
		ipMatcherTag := firstNonEmpty(r.IPMatcher, r.Matcher, r.IPSet, r.IPSetTag, r.IPSetDeprecated)
		preferDomain := firstNonEmpty(r.PreferDomain, r.Target, r.Prefer)
		if ipMatcherTag == "" {
			return nil, fmt.Errorf("%s: rules[%d].ip_matcher must be specified", PluginType, i)
		}
		if preferDomain == "" {
			return nil, fmt.Errorf("%s: rules[%d].prefer_domain must be specified", PluginType, i)
		}

		provider, _ := bp.M().GetPlugin(ipMatcherTag).(data_provider.IPMatcherProvider)
		if provider == nil {
			return nil, fmt.Errorf("%s: ip_matcher plugin %q is not an IPMatcherProvider", PluginType, ipMatcherTag)
		}

		rules = append(rules, compiledRule{
			ipMatcherTag:  ipMatcherTag,
			preferDomain:  dns.Fqdn(preferDomain),
			preferDisplay: strings.TrimSuffix(dns.Fqdn(preferDomain), "."),
			matcher:       provider.GetIPMatcher(),
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	p := &PreferDomain{
		logger:               bp.L(),
		resolver:             resolver,
		rules:                rules,
		timeout:              timeout,
		cacheTTL:             cacheTTL,
		warmOnStart:          cfg.WarmOnStart,
		serveStale:           cfg.ServeStale,
		maxStale:             maxStale,
		ready:                bp.M().PluginsReady(),
		initialRetryInterval: initialWarmRetryInterval,
		initialAttempts:      initialWarmAttempts,
		refreshAdvance:       defaultRefreshAdvance,
		refreshSem:           make(chan struct{}, maxConcurrentRefreshes),
		cache:                make(map[string]cacheEntry),
		ctx:                  ctx,
		cancel:               cancel,
	}

	p.startWarmers()

	bp.L().Info("prefer_domain plugin loaded",
		zap.Int("rules", len(rules)),
		zap.String("resolver", cfg.Resolver),
		zap.Duration("timeout", p.timeout),
		zap.Duration("cache_ttl", p.cacheTTL),
		zap.Duration("refresh_advance", p.refreshAdvanceDuration()),
		zap.Duration("refresh_after", p.refreshDelay()),
		zap.Duration("max_stale", p.maxStale),
		zap.Int("initial_warm_attempts", p.initialAttempts),
		zap.Duration("initial_warm_retry_interval", p.initialRetryInterval),
		zap.Int("periodic_refresh_attempts", periodicRefreshAttempts),
		zap.Int("max_concurrent_refreshes", cap(p.refreshSem)))

	return p, nil
}

func (p *PreferDomain) Close() error {
	p.closeOnce.Do(func() {
		if p.cancel != nil {
			p.cancel()
		}
		p.schedulerWG.Wait()
		workersDone := make(chan struct{})
		go func() {
			p.workerWG.Wait()
			close(workersDone)
		}()
		closeWait := p.timeout + refreshSafetyMargin
		if closeWait <= 0 {
			closeWait = refreshSafetyMargin
		}
		if closeWait > maxWorkerCloseWait {
			closeWait = maxWorkerCloseWait
		}
		select {
		case <-workersDone:
		case <-time.After(closeWait):
			if p.logger != nil {
				p.logger.Warn("timed out waiting for preferred-domain background workers to stop",
					zap.Duration("waited", closeWait))
			}
		}
	})
	return nil
}

func (p *PreferDomain) Exec(ctx context.Context, qCtx *query_context.Context) error {
	if qCtx == nil {
		return nil
	}
	if internal, _ := qCtx.GetValue(internalQueryKey); internal == p {
		return nil
	}

	q := qCtx.Q()
	if len(q.Question) != 1 || q.Question[0].Qclass != dns.ClassINET {
		return nil
	}

	qType := q.Question[0].Qtype
	if qType != dns.TypeA && qType != dns.TypeAAAA {
		return nil
	}

	r := qCtx.R()
	if r == nil || r.Rcode != dns.RcodeSuccess {
		return nil
	}

	rule, addr, owner, ok := p.matchRule(r, qType)
	if !ok {
		return nil
	}

	preferredResp, _, err := p.getPreferredResponse(ctx, rule, qType)
	if err != nil {
		p.logger.Debug("preferred-domain cache unavailable, keep original response",
			zap.String("prefer_domain", rule.preferDisplay),
			zap.Stringer("matched_ip", addr),
			zap.Error(err))
		return nil
	}

	replacedResp, ok := buildReplacedResponse(r, preferredResp, qType, owner)
	if !ok {
		p.logger.Debug("preferred domain has no usable answer, keep original response",
			zap.String("prefer_domain", rule.preferDisplay),
			zap.Stringer("matched_ip", addr))
		return nil
	}

	upstreamOpt := qCtx.UpstreamOpt()
	qCtx.SetResponse(replacedResp)
	qCtx.SetUpstreamOpt(upstreamOpt)
	p.logger.Debug("response replaced by preferred domain",
		zap.String("qname", strings.TrimSuffix(q.Question[0].Name, ".")),
		zap.Uint16("qtype", qType),
		zap.String("ip_matcher", rule.ipMatcherTag),
		zap.Stringer("matched_ip", addr),
		zap.String("prefer_domain", rule.preferDisplay))
	return nil
}

func (p *PreferDomain) matchRule(r *dns.Msg, qType uint16) (*compiledRule, netip.Addr, string, bool) {
	if r == nil || (qType != dns.TypeA && qType != dns.TypeAAAA) {
		return nil, netip.Addr{}, "", false
	}
	addressRRSet := wantedAddressRRSet(r, qType)
	for i := range p.rules {
		rule := &p.rules[i]
		for _, rr := range addressRRSet {
			addr, ok := rrIP(rr)
			if !ok {
				continue
			}
			if rule.matcher != nil && rule.matcher.Match(addr) {
				return rule, addr, rr.Header().Name, true
			}
		}
	}
	return nil, netip.Addr{}, "", false
}

func (p *PreferDomain) getPreferredResponse(_ context.Context, rule *compiledRule, qType uint16) (*dns.Msg, bool, error) {
	key := cacheKey(rule.preferDomain, qType)
	now := time.Now()

	p.mu.RLock()
	ce, ok := p.cache[key]
	if ok && now.Before(ce.expires) && ce.msg != nil {
		msg := ce.msg.Copy()
		stored := ce.stored
		p.mu.RUnlock()
		if elapsed := now.Sub(stored); elapsed > 0 {
			subtractTTLToZero(msg, durationToTTLSeconds(elapsed))
		}
		return msg, false, nil
	}
	stale := ce
	p.mu.RUnlock()

	if msg, ok := p.getStaleResponse(stale, now); ok {
		return msg, true, nil
	}
	return nil, false, errPreferredCacheUnavailable
}

func (p *PreferDomain) getStaleResponse(ce cacheEntry, now time.Time) (*dns.Msg, bool) {
	if !p.serveStale || ce.msg == nil {
		return nil, false
	}
	if p.maxStale > 0 && (ce.expires.IsZero() || now.Sub(ce.expires) > p.maxStale) {
		return nil, false
	}

	msg := ce.msg.Copy()
	dnsutils.SetTTL(msg, 0)
	return msg, true
}

func (p *PreferDomain) resolvePreferred(parent context.Context, rule *compiledRule, qType uint16) (*dns.Msg, error) {
	return resolveDomain(parent, p.resolver, p.timeout, rule.preferDomain, qType, p)
}

func resolveDomain(parent context.Context, resolver sequence.Executable, timeout time.Duration, name string, qType uint16, internalPlugin *PreferDomain) (*dns.Msg, error) {
	if resolver == nil {
		return nil, errors.New("resolver is not configured")
	}

	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qType)
	q.RecursionDesired = true

	subCtx := query_context.NewContext(q)
	subCtx.StoreValue(internalQueryKey, internalPlugin)
	if err := resolver.Exec(ctx, subCtx); err != nil && !errors.Is(err, sequence.ErrExit) {
		if cause := context.Cause(parent); cause != nil {
			return nil, &preferredQueryError{err: cause}
		}
		return nil, &preferredQueryError{err: err, retryable: true}
	}
	if cause := context.Cause(ctx); cause != nil {
		if parentCause := context.Cause(parent); parentCause != nil {
			return nil, &preferredQueryError{err: parentCause}
		}
		return nil, &preferredQueryError{err: cause, retryable: true}
	}

	r := subCtx.R()
	if r == nil {
		if cause := context.Cause(parent); cause != nil {
			return nil, &preferredQueryError{err: cause}
		}
		return nil, &preferredQueryError{err: errors.New("resolver returned no response"), retryable: true}
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, &preferredQueryError{
			err:       fmt.Errorf("resolver returned rcode %s", dns.RcodeToString[r.Rcode]),
			retryable: r.Rcode == dns.RcodeServerFailure,
		}
	}
	if !hasWantedIP(r, qType) {
		return nil, &preferredQueryError{err: errors.New("resolver response has no wanted A/AAAA answer")}
	}
	return r.Copy(), nil
}

func (p *PreferDomain) storePreferred(rule *compiledRule, qType uint16, msg *dns.Msg) error {
	if msg == nil {
		return errors.New("cannot cache a nil preferred-domain response")
	}

	ttl := p.cacheDuration()
	key := cacheKey(rule.preferDomain, qType)
	if ttl <= 0 {
		// A refresh that cannot be cached must not destroy the previous entry;
		// that entry may be the only stale availability fallback.
		return errors.New("preferred-domain response has no positive internal cache TTL")
	}
	now := time.Now()

	p.mu.Lock()
	p.cache[key] = cacheEntry{
		msg:     msg.Copy(),
		stored:  now,
		expires: now.Add(ttl),
	}
	p.mu.Unlock()
	return nil
}

func (p *PreferDomain) startWarmers() {
	// Init requires a positive cache TTL. Keep this guard for directly
	// constructed test instances and embedders so an invalid zero TTL cannot
	// create a background busy loop.
	if p.cacheTTL <= 0 {
		return
	}
	p.startOnce.Do(func() {
		p.schedulerWG.Add(1)
		go func() {
			defer p.schedulerWG.Done()
			p.runWarmScheduler()
		}()
	})
}

func (p *PreferDomain) runWarmScheduler() {
	if p.ctx == nil {
		return
	}
	if p.ready != nil {
		select {
		case <-p.ctx.Done():
			return
		case <-p.ready:
		}
	}
	targets := p.getWarmTargets()
	for _, target := range targets {
		select {
		case <-p.ctx.Done():
			return
		default:
		}
		p.workerWG.Add(1)
		go func(target warmTarget) {
			defer p.workerWG.Done()
			p.runTargetWarmer(target)
		}(target)
	}
}

func (p *PreferDomain) runTargetWarmer(target warmTarget) {
	if !p.warmOnStart && !p.waitFor(p.refreshDelay()) {
		return
	}
	succeeded := p.runInitialWarmTarget(target)
	if p.ctx.Err() != nil {
		return
	}

	next := time.Now().Add(p.refreshDelay())
	if succeeded {
		next = p.nextRefreshAfterSuccess(target, time.Now())
	}
	for p.waitUntil(next) {
		err := p.runPeriodicRefreshTarget(target)
		completedAt := time.Now()
		if p.ctx.Err() != nil {
			return
		}
		if err != nil {
			// Only the background worker can recover the entry. A failed window
			// retains the old value and advances to the next cache-TTL-derived
			// window anchored to the last successful store.
			next = p.nextRefreshAfterFailure(target, next, completedAt)
			p.logPeriodicRefreshFailure(warmResult{
				target:     target,
				err:        err,
				retryAfter: next.Sub(completedAt),
			})
			continue
		}
		next = p.nextRefreshAfterSuccess(target, completedAt)
	}
}

// runPeriodicRefreshTarget performs at most two attempts in one refresh
// window. The second attempt starts immediately after the first failure so it
// can still complete within the fixed five-second pre-expiry window.
func (p *PreferDomain) runPeriodicRefreshTarget(target warmTarget) error {
	var err error
	for attempt := 1; attempt <= periodicRefreshAttempts; attempt++ {
		err = p.refreshTarget(target)
		if err == nil {
			return nil
		}
		if p.ctx != nil && p.ctx.Err() != nil {
			return err
		}
		if attempt < periodicRefreshAttempts {
			p.logger.Warn("preferred-domain refresh failed; retrying once",
				zap.String("prefer_domain", target.rule.preferDisplay),
				zap.Uint16("qtype", target.qType),
				zap.Int("attempt", attempt),
				zap.Int("max_attempts", periodicRefreshAttempts),
				zap.Error(err))
		}
	}
	return err
}

func (p *PreferDomain) runInitialWarmTarget(target warmTarget) bool {
	attempts := p.initialAttempts
	if attempts <= 0 {
		attempts = initialWarmAttempts
	}
	retryInterval := p.initialRetryInterval
	if retryInterval <= 0 {
		retryInterval = initialWarmRetryInterval
	}

	for attempt := 1; attempt <= attempts; attempt++ {
		err := p.refreshTarget(target)
		if err == nil {
			return true
		}
		if p.ctx.Err() != nil {
			return false
		}

		retryable := isRetryablePreferredQueryError(err)
		if retryable && attempt < attempts {
			p.logger.Warn("initial preferred-domain warm-up failed; retry scheduled",
				zap.String("prefer_domain", target.rule.preferDisplay),
				zap.Uint16("qtype", target.qType),
				zap.Int("attempt", attempt),
				zap.Int("max_attempts", attempts),
				zap.Duration("retry_after", retryInterval),
				zap.Error(err))
			if !p.waitFor(retryInterval) {
				return false
			}
			continue
		}

		message := "initial preferred-domain warm-up failed; waiting for next refresh window"
		if retryable {
			message = "initial preferred-domain warm-up exhausted retries; waiting for next refresh window"
		}
		p.logger.Warn(message,
			zap.String("prefer_domain", target.rule.preferDisplay),
			zap.Uint16("qtype", target.qType),
			zap.Int("attempts", attempt),
			zap.Error(err))
		return false
	}
	return false
}

func (p *PreferDomain) warmAll() {
	pluginCtx := p.ctx
	if pluginCtx == nil {
		pluginCtx = context.Background()
	}
	for _, target := range p.getWarmTargets() {
		select {
		case <-pluginCtx.Done():
			return
		default:
		}
		if err := p.runPeriodicRefreshTarget(target); err != nil {
			p.logPeriodicRefreshFailure(warmResult{target: target, err: err})
		}
	}
}

func (p *PreferDomain) refreshTarget(target warmTarget) error {
	pluginCtx := p.ctx
	if pluginCtx == nil {
		pluginCtx = context.Background()
	}
	if p.refreshSem != nil {
		select {
		case <-pluginCtx.Done():
			return context.Cause(pluginCtx)
		case p.refreshSem <- struct{}{}:
			defer func() { <-p.refreshSem }()
		}
	}
	msg, err := p.resolvePreferred(pluginCtx, target.rule, target.qType)
	if err != nil {
		return err
	}
	if cause := context.Cause(pluginCtx); cause != nil {
		return cause
	}
	return p.storePreferred(target.rule, target.qType, msg)
}

func (p *PreferDomain) getWarmTargets() []warmTarget {
	targets := make([]warmTarget, 0, len(p.rules)*2)
	seen := make(map[string]struct{}, len(p.rules)*2)
	for i := range p.rules {
		rule := &p.rules[i]
		for _, qType := range [...]uint16{dns.TypeA, dns.TypeAAAA} {
			key := cacheKey(rule.preferDomain, qType)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			targets = append(targets, warmTarget{rule: rule, qType: qType, key: key})
		}
	}
	return targets
}

func (p *PreferDomain) nextRefreshAfterSuccess(target warmTarget, now time.Time) time.Time {
	next := now.Add(p.refreshDelay())
	p.mu.RLock()
	ce, ok := p.cache[target.key]
	p.mu.RUnlock()
	if !ok || ce.msg == nil {
		return next
	}

	next = p.refreshDeadline(ce)
	minimumNext := now.Add(minimumRefreshDelay)
	if next.Before(minimumNext) {
		return minimumNext
	}
	return next
}

func (p *PreferDomain) nextRefreshAfterFailure(target warmTarget, scheduledAt, now time.Time) time.Time {
	p.mu.RLock()
	ce, ok := p.cache[target.key]
	p.mu.RUnlock()
	if !ok || ce.msg == nil || ce.stored.IsZero() || !ce.expires.After(ce.stored) {
		if scheduledAt.IsZero() {
			return now.Add(p.refreshDelay())
		}
		return advanceRefreshWindow(scheduledAt, p.cacheTTL, now)
	}

	ttl := ce.expires.Sub(ce.stored)
	next := ce.expires.Add(-p.refreshAdvanceDuration())
	return advanceRefreshWindow(next, ttl, now)
}

func advanceRefreshWindow(next time.Time, period time.Duration, now time.Time) time.Time {
	if next.After(now) {
		return next
	}
	if period <= 0 {
		return now.Add(minimumRefreshDelay)
	}
	// Windows stay anchored to their original origin. Skip every elapsed
	// window in one calculation so a delayed worker cannot burst.
	elapsed := now.Sub(next)
	steps := elapsed/period + 1
	if steps > time.Duration(1<<62)/period {
		return now.Add(period)
	}
	return next.Add(steps * period)
}

func (p *PreferDomain) refreshDeadline(ce cacheEntry) time.Time {
	return ce.expires.Add(-p.refreshAdvanceDuration())
}

func (p *PreferDomain) refreshAdvanceDuration() time.Duration {
	if p.refreshAdvance > 0 {
		return p.refreshAdvance
	}
	return defaultRefreshAdvance
}

// refreshDelay derives the background window from cache_ttl and always starts
// it exactly five seconds before the internal cache expires. Init rejects TTLs
// that are too short; the minimum guard protects directly constructed tests.
func (p *PreferDomain) refreshDelay() time.Duration {
	delay := p.cacheTTL - p.refreshAdvanceDuration()
	if delay < minimumRefreshDelay {
		return minimumRefreshDelay
	}
	return delay
}

func (p *PreferDomain) waitFor(d time.Duration) bool {
	if d <= 0 {
		select {
		case <-p.ctx.Done():
			return false
		default:
			return true
		}
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-p.ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (p *PreferDomain) waitUntil(when time.Time) bool {
	return p.waitFor(time.Until(when))
}

func (p *PreferDomain) logPeriodicRefreshFailure(result warmResult) {
	retryAfter := result.retryAfter
	if retryAfter <= 0 {
		retryAfter = p.refreshDelay()
	}
	p.logger.Warn("preferred-domain refresh failed twice; current cache state retained until next refresh window",
		zap.String("prefer_domain", result.target.rule.preferDisplay),
		zap.Uint16("qtype", result.target.qType),
		zap.Int("attempts", periodicRefreshAttempts),
		zap.Duration("retry_after", retryAfter),
		zap.Error(result.err))
}

func isRetryablePreferredQueryError(err error) bool {
	var queryErr *preferredQueryError
	return errors.As(err, &queryErr) && queryErr.retryable
}

func (p *PreferDomain) cacheDuration() time.Duration {
	return p.cacheTTL
}

func normalizeRuleArgs(cfg *Args) []RuleArgs {
	out := make([]RuleArgs, 0, len(cfg.Rules)+1)
	if ipMatcher := firstNonEmpty(cfg.IPMatcher, cfg.Matcher, cfg.IPSet, cfg.IPSetTag, cfg.IPSetDeprecated); ipMatcher != "" || firstNonEmpty(cfg.PreferDomain, cfg.Target, cfg.Prefer) != "" {
		out = append(out, RuleArgs{
			IPMatcher:       cfg.IPMatcher,
			Matcher:         cfg.Matcher,
			IPSet:           cfg.IPSet,
			IPSetTag:        cfg.IPSetTag,
			IPSetDeprecated: cfg.IPSetDeprecated,
			PreferDomain:    cfg.PreferDomain,
			Target:          cfg.Target,
			Prefer:          cfg.Prefer,
		})
	}
	out = append(out, cfg.Rules...)
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func parseFixedDuration(s string, defaultValue int64, unit time.Duration) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Duration(defaultValue) * unit, nil
	}

	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("must be an integer without a unit suffix")
	}
	if n < 0 {
		return 0, fmt.Errorf("duration must not be negative")
	}
	maxDuration := int64(^uint64(0) >> 1)
	if unit <= 0 || n > maxDuration/int64(unit) {
		return 0, fmt.Errorf("duration is too large")
	}
	return time.Duration(n) * unit, nil
}

func cacheKey(name string, qType uint16) string {
	return strings.ToLower(dns.Fqdn(name)) + "|" + strconv.Itoa(int(qType))
}

func rrIP(rr dns.RR) (netip.Addr, bool) {
	switch rr := rr.(type) {
	case *dns.A:
		return netIPToAddr(rr.A)
	case *dns.AAAA:
		return netIPToAddr(rr.AAAA)
	default:
		return netip.Addr{}, false
	}
}

func netIPToAddr(ip net.IP) (netip.Addr, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func hasWantedIP(r *dns.Msg, qType uint16) bool {
	return len(wantedAddressRRSet(r, qType)) > 0
}

// wantedAddressRRSet returns usable addresses belonging to the terminal owner
// of the response's CNAME chain. Responses without an echoed Question retain
// the legacy behavior and accept all usable addresses of the requested type.
func wantedAddressRRSet(r *dns.Msg, qType uint16) []dns.RR {
	if r == nil || (qType != dns.TypeA && qType != dns.TypeAAAA) {
		return nil
	}

	owner := ""
	restrictOwner := len(r.Question) == 1
	if restrictOwner {
		owner = dns.Fqdn(r.Question[0].Name)
		seen := make(map[string]struct{})
		for {
			ownerKey := strings.ToLower(owner)
			if _, duplicate := seen[ownerKey]; duplicate {
				return nil
			}
			seen[ownerKey] = struct{}{}

			nextOwner := ""
			for _, rr := range r.Answer {
				cname, ok := rr.(*dns.CNAME)
				if !ok || !strings.EqualFold(dns.Fqdn(cname.Hdr.Name), owner) {
					continue
				}
				nextOwner = dns.Fqdn(cname.Target)
				break
			}
			if nextOwner == "" {
				break
			}
			owner = nextOwner
		}
	}

	addresses := make([]dns.RR, 0, len(r.Answer))
	for _, rr := range r.Answer {
		if rr == nil || rr.Header() == nil || rr.Header().Rrtype != qType {
			continue
		}
		if restrictOwner && !strings.EqualFold(dns.Fqdn(rr.Header().Name), owner) {
			continue
		}
		if _, ok := rrIP(rr); ok {
			addresses = append(addresses, rr)
		}
	}
	return addresses
}

func durationToTTLSeconds(d time.Duration) uint32 {
	if d <= 0 {
		return 0
	}
	maxTTLDuration := time.Duration(^uint32(0)) * time.Second
	if d >= maxTTLDuration {
		return ^uint32(0)
	}
	sec := d / time.Second
	if d%time.Second != 0 {
		sec++
	}
	if sec <= 0 {
		return 1
	}
	return uint32(sec)
}

func subtractTTLToZero(m *dns.Msg, delta uint32) {
	for _, section := range [...][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			if rr == nil || rr.Header() == nil || rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			if rr.Header().Ttl > delta {
				rr.Header().Ttl -= delta
			} else {
				rr.Header().Ttl = 0
			}
		}
	}
}

func buildReplacedResponse(originalResp *dns.Msg, preferredResp *dns.Msg, qType uint16, owner string) (*dns.Msg, bool) {
	if originalResp == nil || preferredResp == nil || owner == "" {
		return nil, false
	}
	if qType != dns.TypeA && qType != dns.TypeAAAA {
		return nil, false
	}

	preferredRRSet := wantedAddressRRSet(preferredResp, qType)
	preferredAddresses := make([]dns.RR, 0, len(preferredRRSet))
	for _, rr := range preferredRRSet {
		switch rr := rr.(type) {
		case *dns.A:
			preferredAddresses = append(preferredAddresses, &dns.A{
				Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: rr.Hdr.Ttl},
				A:   append(net.IP(nil), rr.A...),
			})
		case *dns.AAAA:
			preferredAddresses = append(preferredAddresses, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: owner, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: rr.Hdr.Ttl},
				AAAA: append(net.IP(nil), rr.AAAA...),
			})
		}
	}

	if len(preferredAddresses) == 0 {
		return nil, false
	}

	replaced := originalResp.Copy()
	answers := make([]dns.RR, 0, len(replaced.Answer)+len(preferredAddresses))
	inserted := false
	for _, rr := range replaced.Answer {
		if rr == nil || rr.Header() == nil {
			answers = append(answers, rr)
			continue
		}

		sameOwner := strings.EqualFold(dns.Fqdn(rr.Header().Name), dns.Fqdn(owner))
		if sameOwner && rr.Header().Rrtype == qType {
			if !inserted {
				answers = append(answers, preferredAddresses...)
				inserted = true
			}
			continue
		}
		if sameOwner {
			if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == qType {
				continue
			}
		}
		answers = append(answers, rr)
	}
	if !inserted {
		return nil, false
	}

	// The address RRset is synthesized for the original response and can no
	// longer be claimed as authoritative or DNSSEC authenticated.
	replaced.Authoritative = false
	replaced.AuthenticatedData = false
	replaced.Answer = answers
	return replaced, true
}
