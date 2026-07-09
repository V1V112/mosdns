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
	"golang.org/x/sync/singleflight"
)

const (
	PluginType = "prefer_domain"

	defaultOriginalTimeoutMilliseconds = 300
	defaultTimeoutMilliseconds         = 500
	defaultWarmIntervalSeconds         = 300
)

type reuseOriginalResponseMode uint8

const (
	reuseOriginalNever reuseOriginalResponseMode = iota
	reuseOriginalOnNonMatch
	reuseOriginalOnFailure
	reuseOriginalAlways
	reuseOriginalDeferred
)

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
//     original_resolver: smartdns_direct # optional: resolve the original name when no response exists
//     original_timeout: 300 # milliseconds
//     exit_on_original_failure: false
//     reuse_original_response: defer # use "use_orig" later to promote it
//     resolver: fallback_direct
//     timeout: 500         # milliseconds
//     warm_interval: 300   # seconds
//     bind_ttl_to_warm_interval: true          # internal cache TTL = warm_interval + 1s
//     bind_response_ttl_to_warm_interval: false # optional: also force client-visible TTL
//     warm_on_start: true
//     serve_stale: true
//     max_stale: 3600      # seconds; 0 means unlimited
//     rules:
//   - ip_matcher: cf_manual_ip
//     prefer_domain: cf.example.com
//
// A later sequence rule can promote the deferred response and optionally fall
// back to its normal resolver when no deferred response is available:
//
//   - matches: qname $direct_domains
//     exec: use_orig $smartdns_direct
//
// For a single rule, top-level ip_matcher/prefer_domain are also accepted.
// Legacy ip_set/ip_set_tag/ipset fields are still accepted as aliases.
type Args struct {
	// Resolver resolves the configured preferred domain after an IP rule matches.
	Resolver string `yaml:"resolver"`

	// original_resolver optionally resolves the client-requested domain when
	// the plugin runs before any response has been produced. Its result is
	// used for IP matching and can optionally be reused as the response.
	OriginalResolver string `yaml:"original_resolver"`

	// original_timeout is always milliseconds. Default is 300.
	OriginalTimeout string `yaml:"original_timeout"`

	// exit_on_original_failure stops the current sequence with ErrExit when
	// original_resolver times out, fails, or returns no usable A/AAAA response.
	// Disabled by default so downstream fallback processing remains available.
	ExitOnOriginalFailure bool `yaml:"exit_on_original_failure"`

	// reuse_original_response controls whether a successful original_resolver
	// probe is reused when no replacement is made. "defer" stores it outside
	// qCtx.R so downstream domain matchers still run; use the sequence action
	// "use_orig" to promote it later. Supported values: never (default),
	// on_non_match, on_failure, always, defer.
	ReuseOriginalResponse string `yaml:"reuse_original_response"`

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

	// warm_interval is always seconds. Default is 300.
	// Set to 0/"0" to disable background warm-up.
	WarmInterval string `yaml:"warm_interval"`

	// cache_ttl is always milliseconds. Default 0 means derive TTL from the
	// preferred-domain answer.
	// Ignored for the internal cache when bind_ttl_to_warm_interval is enabled.
	CacheTTL string `yaml:"cache_ttl"`

	// bind_ttl_to_warm_interval forces only the internal preferred-domain cache TTL
	// to warm_interval + 1s. This keeps the cached preferred-domain answer valid
	// slightly longer than the next scheduled warm-up. Requires warm_interval > 0.
	BindTTLToWarmInterval bool `yaml:"bind_ttl_to_warm_interval"`

	// bind_response_ttl_to_warm_interval also forces the client-visible masked A/AAAA
	// answer TTL to warm_interval + 1s. Disabled by default so client-visible TTL
	// keeps the TTL from the preferred-domain A/AAAA answer. Requires
	// bind_ttl_to_warm_interval and warm_interval > 0 when enabled.
	BindResponseTTLToWarmInterval bool `yaml:"bind_response_ttl_to_warm_interval"`

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

type PreferDomain struct {
	logger *zap.Logger

	originalResolver sequence.Executable
	resolver         sequence.Executable
	rules            []compiledRule

	originalTimeout               time.Duration
	exitOnOriginalFailure         bool
	reuseOriginalResponse         reuseOriginalResponseMode
	timeout                       time.Duration
	warmInterval                  time.Duration
	cacheTTL                      time.Duration
	bindTTLToWarmInterval         bool
	bindResponseTTLToWarmInterval bool
	warmOnStart                   bool
	serveStale                    bool
	maxStale                     time.Duration

	mu    sync.RWMutex
	cache map[string]cacheEntry

	originalResolveGroup singleflight.Group
	resolveGroup         singleflight.Group

	ctx    context.Context
	cancel context.CancelFunc
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

	var originalResolver sequence.Executable
	if cfg.OriginalResolver != "" {
		originalResolverPlugin := bp.M().GetPlugin(cfg.OriginalResolver)
		if originalResolverPlugin == nil {
			return nil, fmt.Errorf("%s: original_resolver plugin %q not found", PluginType, cfg.OriginalResolver)
		}
		originalResolver = sequence.ToExecutable(originalResolverPlugin)
		if originalResolver == nil {
			return nil, fmt.Errorf("%s: original_resolver plugin %q is not executable", PluginType, cfg.OriginalResolver)
		}
	} else {
		if strings.TrimSpace(cfg.OriginalTimeout) != "" {
			return nil, fmt.Errorf("%s: original_timeout requires original_resolver", PluginType)
		}
		if cfg.ExitOnOriginalFailure {
			return nil, fmt.Errorf("%s: exit_on_original_failure requires original_resolver", PluginType)
		}
	}

	originalTimeout, err := parseFixedDuration(
		cfg.OriginalTimeout,
		defaultOriginalTimeoutMilliseconds,
		time.Millisecond,
	)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid original_timeout: %w", PluginType, err)
	}
	timeout, err := parseFixedDuration(
		cfg.Timeout,
		defaultTimeoutMilliseconds,
		time.Millisecond,
	)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid timeout: %w", PluginType, err)
	}
	warmInterval, err := parseFixedDuration(
		cfg.WarmInterval,
		defaultWarmIntervalSeconds,
		time.Second,
	)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid warm_interval: %w", PluginType, err)
	}
	cacheTTL, err := parseFixedDuration(cfg.CacheTTL, 0, time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid cache_ttl: %w", PluginType, err)
	}
	maxStale, err := parseFixedDuration(cfg.MaxStale, 0, time.Second)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid max_stale: %w", PluginType, err)
	}
	reuseOriginalResponse, err := parseReuseOriginalResponseMode(cfg.ReuseOriginalResponse)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid reuse_original_response: %w", PluginType, err)
	}
	if cfg.BindTTLToWarmInterval && warmInterval <= 0 {
		return nil, fmt.Errorf("%s: bind_ttl_to_warm_interval requires warm_interval > 0", PluginType)
	}
	if cfg.BindResponseTTLToWarmInterval && !cfg.BindTTLToWarmInterval {
		return nil, fmt.Errorf("%s: bind_response_ttl_to_warm_interval requires bind_ttl_to_warm_interval", PluginType)
	}
	if maxStale > 0 && !cfg.ServeStale {
		return nil, fmt.Errorf("%s: max_stale requires serve_stale", PluginType)
	}
	if reuseOriginalResponse != reuseOriginalNever && originalResolver == nil {
		return nil, fmt.Errorf("%s: reuse_original_response requires original_resolver", PluginType)
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
		logger:                        bp.L(),
		originalResolver:              originalResolver,
		resolver:                      resolver,
		rules:                         rules,
		originalTimeout:               originalTimeout,
		exitOnOriginalFailure:         cfg.ExitOnOriginalFailure,
		reuseOriginalResponse:         reuseOriginalResponse,
		timeout:                       timeout,
		warmInterval:                  warmInterval,
		cacheTTL:                      cacheTTL,
		bindTTLToWarmInterval:         cfg.BindTTLToWarmInterval,
		bindResponseTTLToWarmInterval: cfg.BindResponseTTLToWarmInterval,
		warmOnStart:                   cfg.WarmOnStart,
		serveStale:                    cfg.ServeStale,
		maxStale:                      maxStale,
		cache:                         make(map[string]cacheEntry),
		ctx:                           ctx,
		cancel:                        cancel,
	}

	p.startWarmers()

	bp.L().Info("prefer_domain plugin loaded",
		zap.Int("rules", len(rules)),
		zap.String("original_resolver", cfg.OriginalResolver),
		zap.Duration("original_timeout", p.originalTimeout),
		zap.Bool("exit_on_original_failure", p.exitOnOriginalFailure),
		zap.String("reuse_original_response", reuseOriginalResponse.String()),
		zap.String("resolver", cfg.Resolver),
		zap.Duration("timeout", p.timeout),
		zap.Duration("warm_interval", p.warmInterval),
		zap.Duration("max_stale", p.maxStale),
		zap.Bool("bind_ttl_to_warm_interval", p.bindTTLToWarmInterval),
		zap.Bool("bind_response_ttl_to_warm_interval", p.bindResponseTTLToWarmInterval))

	return p, nil
}

func (p *PreferDomain) Close() error {
	p.cancel()
	return nil
}

func (p *PreferDomain) Exec(ctx context.Context, qCtx *query_context.Context) error {
	q := qCtx.Q()
	if len(q.Question) != 1 || q.Question[0].Qclass != dns.ClassINET {
		return nil
	}

	qType := q.Question[0].Qtype
	if qType != dns.TypeA && qType != dns.TypeAAAA {
		return nil
	}

	r := qCtx.R()
	resolvedOriginal := false
	if r == nil && p.originalResolver != nil {
		var err error
		r, err = p.getOriginalResponse(ctx, q.Question[0].Name, qType)
		if err != nil {
			p.logger.Debug("failed to resolve original domain",
				zap.String("qname", strings.TrimSuffix(q.Question[0].Name, ".")),
				zap.Uint16("qtype", qType),
				zap.Bool("exit_sequence", p.exitOnOriginalFailure),
				zap.Error(err))
			if ctx.Err() != nil {
				return context.Cause(ctx)
			}
			if p.exitOnOriginalFailure {
				return sequence.ErrExit
			}
			return nil
		}
		resolvedOriginal = true
	}
	if r == nil || r.Rcode != dns.RcodeSuccess {
		return nil
	}

	rule, addr, ok := p.matchRule(r)
	if !ok {
		p.reuseOriginal(qCtx, q, r, resolvedOriginal, reuseOriginalOnNonMatch)
		return nil
	}

	preferredResp, stale, err := p.getPreferredResponse(ctx, rule, qType)
	if err != nil {
		p.logger.Debug("failed to resolve preferred domain, keep original response",
			zap.String("prefer_domain", rule.preferDisplay),
			zap.Stringer("matched_ip", addr),
			zap.Error(err))
		p.reuseOriginal(qCtx, q, r, resolvedOriginal, reuseOriginalOnFailure)
		return nil
	}

	forcedTTL := p.forcedResponseTTL()
	if stale {
		// Stale data is only an availability fallback. Do not let clients
		// extend its lifetime, even when response TTL binding is enabled.
		forcedTTL = 0
	}
	maskedResp, ok := buildMaskedResponse(q, preferredResp, forcedTTL)
	if !ok {
		p.logger.Debug("preferred domain has no usable answer, keep original response",
			zap.String("prefer_domain", rule.preferDisplay),
			zap.Stringer("matched_ip", addr))
		p.reuseOriginal(qCtx, q, r, resolvedOriginal, reuseOriginalOnFailure)
		return nil
	}

	qCtx.SetResponse(maskedResp)
	p.logger.Debug("response replaced by preferred domain",
		zap.String("qname", strings.TrimSuffix(q.Question[0].Name, ".")),
		zap.Uint16("qtype", qType),
		zap.String("ip_matcher", rule.ipMatcherTag),
		zap.Stringer("matched_ip", addr),
		zap.String("prefer_domain", rule.preferDisplay))
	return nil
}

func (p *PreferDomain) reuseOriginal(qCtx *query_context.Context, q, r *dns.Msg, resolvedOriginal bool, reason reuseOriginalResponseMode) {
	if !resolvedOriginal || qCtx == nil || q == nil || r == nil {
		return
	}
	if p.reuseOriginalResponse != reuseOriginalAlways &&
		p.reuseOriginalResponse != reuseOriginalDeferred &&
		p.reuseOriginalResponse != reason {
		return
	}

	reused := r.Copy()
	reused.Id = q.Id
	reused.Question = append([]dns.Question(nil), q.Question...)
	reused.Opcode = q.Opcode
	reused.RecursionDesired = q.RecursionDesired
	reused.CheckingDisabled = q.CheckingDisabled
	if p.reuseOriginalResponse == reuseOriginalDeferred {
		qCtx.StoreValue(query_context.KeyPreferOriginalResponse, reused)
		return
	}
	qCtx.SetResponse(reused)
}

func (p *PreferDomain) getOriginalResponse(ctx context.Context, name string, qType uint16) (*dns.Msg, error) {
	key := cacheKey(name, qType)
	resultCh := p.originalResolveGroup.DoChan(key, func() (any, error) {
		parent := p.ctx
		if parent == nil {
			parent = context.Background()
		}
		return resolveDomain(parent, p.originalResolver, p.originalTimeout, name, qType)
	})

	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case result := <-resultCh:
		if result.Err != nil {
			return nil, result.Err
		}
		msg, ok := result.Val.(*dns.Msg)
		if !ok || msg == nil {
			return nil, errors.New("original_resolver returned invalid shared result")
		}
		return msg.Copy(), nil
	}
}

func (p *PreferDomain) matchRule(r *dns.Msg) (*compiledRule, netip.Addr, bool) {
	for i := range p.rules {
		rule := &p.rules[i]
		for _, rr := range r.Answer {
			addr, ok := rrIP(rr)
			if !ok {
				continue
			}
			if rule.matcher != nil && rule.matcher.Match(addr) {
				return rule, addr, true
			}
		}
	}
	return nil, netip.Addr{}, false
}

func (p *PreferDomain) getPreferredResponse(ctx context.Context, rule *compiledRule, qType uint16) (*dns.Msg, bool, error) {
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

	resultCh := p.resolveAndStore(rule, qType, false)
	select {
	case <-ctx.Done():
		if msg, ok := p.getStaleResponse(stale, time.Now()); ok {
			return msg, true, nil
		}
		return nil, false, context.Cause(ctx)
	case result := <-resultCh:
		if result.Err != nil {
			if msg, ok := p.getStaleResponse(stale, time.Now()); ok {
				return msg, true, nil
			}
			return nil, false, result.Err
		}

		msg, ok := result.Val.(*dns.Msg)
		if !ok || msg == nil {
			return nil, false, errors.New("resolver returned invalid shared result")
		}
		return msg.Copy(), false, nil
	}
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

func (p *PreferDomain) resolveAndStore(rule *compiledRule, qType uint16, forceRefresh bool) <-chan singleflight.Result {
	key := cacheKey(rule.preferDomain, qType)
	return p.resolveGroup.DoChan(key, func() (any, error) {
		// Close the small race between the caller's cache lookup and joining
		// singleflight. A previous flight may have populated the cache in that
		// interval. Periodic warm-up deliberately bypasses this check.
		if !forceRefresh {
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
				return msg, nil
			}
			p.mu.RUnlock()
		}

		parent := p.ctx
		if parent == nil {
			parent = context.Background()
		}
		msg, err := p.resolvePreferred(parent, rule, qType)
		if err != nil {
			return nil, err
		}
		p.storePreferred(rule, qType, msg)
		return msg, nil
	})
}

func (p *PreferDomain) resolvePreferred(parent context.Context, rule *compiledRule, qType uint16) (*dns.Msg, error) {
	return resolveDomain(parent, p.resolver, p.timeout, rule.preferDomain, qType)
}

func resolveDomain(parent context.Context, resolver sequence.Executable, timeout time.Duration, name string, qType uint16) (*dns.Msg, error) {
	if resolver == nil {
		return nil, errors.New("resolver is not configured")
	}

	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qType)
	q.RecursionDesired = true

	subCtx := query_context.NewContext(q)
	if err := resolver.Exec(ctx, subCtx); err != nil && !errors.Is(err, sequence.ErrExit) {
		return nil, err
	}

	r := subCtx.R()
	if r == nil {
		return nil, errors.New("resolver returned no response")
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("resolver returned rcode %d", r.Rcode)
	}
	if !hasWantedIP(r, qType) {
		return nil, errors.New("resolver response has no wanted A/AAAA answer")
	}
	return r.Copy(), nil
}

func (p *PreferDomain) storePreferred(rule *compiledRule, qType uint16, msg *dns.Msg) {
	if msg == nil {
		return
	}

	ttl := p.cacheDuration(msg, qType)
	key := cacheKey(rule.preferDomain, qType)
	if ttl <= 0 {
		p.mu.Lock()
		delete(p.cache, key)
		p.mu.Unlock()
		return
	}
	now := time.Now()

	p.mu.Lock()
	p.cache[key] = cacheEntry{
		msg:     msg.Copy(),
		stored:  now,
		expires: now.Add(ttl),
	}
	p.mu.Unlock()
}

func (p *PreferDomain) startWarmers() {
	if p.warmOnStart {
		go p.warmAll()
	}
	if p.warmInterval > 0 {
		go p.warmLoop()
	}
}

func (p *PreferDomain) warmLoop() {
	t := time.NewTicker(p.warmInterval)
	defer t.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-t.C:
			p.warmAll()
		}
	}
}

func (p *PreferDomain) warmAll() {
	seen := make(map[string]struct{}, len(p.rules)*2)
	for i := range p.rules {
		rule := &p.rules[i]
		for _, qType := range []uint16{dns.TypeA, dns.TypeAAAA} {
			key := cacheKey(rule.preferDomain, qType)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}

			select {
			case <-p.ctx.Done():
				return
			default:
			}

			resultCh := p.resolveAndStore(rule, qType, true)
			select {
			case <-p.ctx.Done():
				return
			case result := <-resultCh:
				if result.Err == nil {
					continue
				}
				p.logger.Debug("preferred domain warm-up failed",
					zap.String("prefer_domain", rule.preferDisplay),
					zap.Uint16("qtype", qType),
					zap.Error(result.Err))
			}
		}
	}
}

func (p *PreferDomain) cacheDuration(msg *dns.Msg, qType uint16) time.Duration {
	if ttl := p.boundWarmTTL(); ttl > 0 {
		return ttl
	}

	ttl := p.cacheTTL
	if ttl <= 0 {
		ttl = ttlFromAnswer(msg, qType)
	}
	return ttl
}

func (p *PreferDomain) boundWarmTTL() time.Duration {
	if !p.bindTTLToWarmInterval || p.warmInterval <= 0 {
		return 0
	}
	return p.warmInterval + time.Second
}

func (p *PreferDomain) forcedResponseTTL() uint32 {
	if !p.bindResponseTTLToWarmInterval {
		return 0
	}
	return durationToTTLSeconds(p.boundWarmTTL())
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

func parseReuseOriginalResponseMode(s string) (reuseOriginalResponseMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "never":
		return reuseOriginalNever, nil
	case "on_non_match":
		return reuseOriginalOnNonMatch, nil
	case "on_failure":
		return reuseOriginalOnFailure, nil
	case "always":
		return reuseOriginalAlways, nil
	case "defer", "deferred":
		return reuseOriginalDeferred, nil
	default:
		return reuseOriginalNever, fmt.Errorf("must be one of never, on_non_match, on_failure, always, defer")
	}
}

func (m reuseOriginalResponseMode) String() string {
	switch m {
	case reuseOriginalOnNonMatch:
		return "on_non_match"
	case reuseOriginalOnFailure:
		return "on_failure"
	case reuseOriginalAlways:
		return "always"
	case reuseOriginalDeferred:
		return "defer"
	default:
		return "never"
	}
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
	for _, rr := range r.Answer {
		switch rr.(type) {
		case *dns.A:
			if qType == dns.TypeA {
				return true
			}
		case *dns.AAAA:
			if qType == dns.TypeAAAA {
				return true
			}
		}
	}
	return false
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

func ttlFromAnswer(r *dns.Msg, qType uint16) time.Duration {
	var minTTL uint32
	found := false
	for _, rr := range r.Answer {
		if rr == nil || rr.Header() == nil {
			continue
		}
		if qType == dns.TypeA && rr.Header().Rrtype != dns.TypeA {
			continue
		}
		if qType == dns.TypeAAAA && rr.Header().Rrtype != dns.TypeAAAA {
			continue
		}
		if !found || rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
			found = true
		}
	}
	if !found {
		return 0
	}
	return time.Duration(minTTL) * time.Second
}

func buildMaskedResponse(originalQ *dns.Msg, preferredResp *dns.Msg, forcedTTL uint32) (*dns.Msg, bool) {
	if originalQ == nil || preferredResp == nil || len(originalQ.Question) != 1 {
		return nil, false
	}
	q := originalQ.Question[0]
	if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
		return nil, false
	}

	masked := new(dns.Msg)
	masked.SetReply(originalQ)
	masked.Rcode = dns.RcodeSuccess
	masked.RecursionAvailable = preferredResp.RecursionAvailable
	// The owner name and answer records below are synthesized. They are not
	// authoritative or DNSSEC-authenticated for the original question.
	masked.Authoritative = false
	masked.AuthenticatedData = false
	masked.CheckingDisabled = originalQ.CheckingDisabled

	answers := make([]dns.RR, 0, len(preferredResp.Answer))
	for _, rr := range preferredResp.Answer {
		switch rr := rr.(type) {
		case *dns.A:
			if q.Qtype != dns.TypeA {
				continue
			}
			ttl := rr.Hdr.Ttl
			if forcedTTL > 0 {
				ttl = forcedTTL
			}
			answers = append(answers, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   append(net.IP(nil), rr.A...),
			})
		case *dns.AAAA:
			if q.Qtype != dns.TypeAAAA {
				continue
			}
			ttl := rr.Hdr.Ttl
			if forcedTTL > 0 {
				ttl = forcedTTL
			}
			answers = append(answers, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
				AAAA: append(net.IP(nil), rr.AAAA...),
			})
		}
	}

	if len(answers) == 0 {
		return nil, false
	}

	// The returned DNS message must look like it was answered for the original domain.
	// Do not leak the preferred domain or its CNAME chain to the client.
	masked.Answer = answers
	return masked, true
}
