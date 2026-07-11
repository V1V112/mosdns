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

	defaultTimeoutMilliseconds = 500
	defaultWarmIntervalSeconds = 300
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
// Run the plugin after the resolver whose response should be inspected:
//
//   - exec: [$smartdns_direct, $cf_prefer]
//
// For a single rule, top-level ip_matcher/prefer_domain are also accepted.
// Legacy ip_set/ip_set_tag/ipset fields are still accepted as aliases.
type Args struct {
	// Resolver resolves the configured preferred domain after an IP rule matches.
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

	resolver sequence.Executable
	rules    []compiledRule

	timeout                       time.Duration
	warmInterval                  time.Duration
	cacheTTL                      time.Duration
	bindTTLToWarmInterval         bool
	bindResponseTTLToWarmInterval bool
	warmOnStart                   bool
	serveStale                    bool
	maxStale                      time.Duration

	mu    sync.RWMutex
	cache map[string]cacheEntry

	resolveGroup singleflight.Group

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
	if cfg.BindTTLToWarmInterval && warmInterval <= 0 {
		return nil, fmt.Errorf("%s: bind_ttl_to_warm_interval requires warm_interval > 0", PluginType)
	}
	if cfg.BindResponseTTLToWarmInterval && !cfg.BindTTLToWarmInterval {
		return nil, fmt.Errorf("%s: bind_response_ttl_to_warm_interval requires bind_ttl_to_warm_interval", PluginType)
	}
	if maxStale > 0 && !cfg.ServeStale {
		return nil, fmt.Errorf("%s: max_stale requires serve_stale", PluginType)
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
		resolver:                      resolver,
		rules:                         rules,
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

	preferredResp, stale, err := p.getPreferredResponse(ctx, rule, qType)
	if err != nil {
		p.logger.Debug("failed to resolve preferred domain, keep original response",
			zap.String("prefer_domain", rule.preferDisplay),
			zap.Stringer("matched_ip", addr),
			zap.Error(err))
		return nil
	}

	forcedTTL := p.forcedResponseTTL()
	if stale {
		// Stale data is only an availability fallback. Do not let clients
		// extend its lifetime, even when response TTL binding is enabled.
		forcedTTL = 0
	}
	replacedResp, ok := buildReplacedResponse(r, preferredResp, qType, owner, forcedTTL)
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

func buildReplacedResponse(originalResp *dns.Msg, preferredResp *dns.Msg, qType uint16, owner string, forcedTTL uint32) (*dns.Msg, bool) {
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
			ttl := rr.Hdr.Ttl
			if forcedTTL > 0 {
				ttl = forcedTTL
			}
			preferredAddresses = append(preferredAddresses, &dns.A{
				Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   append(net.IP(nil), rr.A...),
			})
		case *dns.AAAA:
			ttl := rr.Hdr.Ttl
			if forcedTTL > 0 {
				ttl = forcedTTL
			}
			preferredAddresses = append(preferredAddresses, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: owner, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
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
