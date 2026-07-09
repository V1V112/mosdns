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
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const PluginType = "prefer_domain"

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
//     timeout: 2s          # number without unit means milliseconds
//     warm_interval: 5m    # number without unit means seconds
//     warm_on_start: true
//     serve_stale: true
//     rules:
//   - ip_matcher: cf_manual_ip
//     prefer_domain: cf.example.com
//
// For a single rule, top-level ip_matcher/prefer_domain are also accepted.
// Legacy ip_set/ip_set_tag/ipset fields are still accepted as aliases.
type Args struct {
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

	// timeout accepts Go duration strings ("2s", "500ms"). A plain number means milliseconds.
	Timeout string `yaml:"timeout"`

	// warm_interval accepts Go duration strings ("5m", "30s"). A plain number means seconds.
	// Set to 0/"0" to disable background warm-up.
	WarmInterval string `yaml:"warm_interval"`

	// cache_ttl accepts Go duration strings. A plain number means seconds.
	// 0 means derive TTL from the preferred-domain answer.
	CacheTTL string `yaml:"cache_ttl"`

	WarmOnStart bool `yaml:"warm_on_start"`
	ServeStale  bool `yaml:"serve_stale"`
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
	expires time.Time
}

type PreferDomain struct {
	logger *zap.Logger

	resolver sequence.Executable
	rules    []compiledRule

	timeout      time.Duration
	warmInterval time.Duration
	cacheTTL     time.Duration
	warmOnStart  bool
	serveStale   bool

	mu    sync.RWMutex
	cache map[string]cacheEntry

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

	timeout, err := parseDurationWithDefault(cfg.Timeout, 2*time.Second, time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid timeout: %w", PluginType, err)
	}
	warmInterval, err := parseDurationWithDefault(cfg.WarmInterval, 5*time.Minute, time.Second)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid warm_interval: %w", PluginType, err)
	}
	cacheTTL, err := parseDurationWithDefault(cfg.CacheTTL, 0, time.Second)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid cache_ttl: %w", PluginType, err)
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
		logger:       bp.L(),
		resolver:     resolver,
		rules:        rules,
		timeout:      timeout,
		warmInterval: warmInterval,
		cacheTTL:     cacheTTL,
		warmOnStart:  cfg.WarmOnStart,
		serveStale:   cfg.ServeStale,
		cache:        make(map[string]cacheEntry),
		ctx:          ctx,
		cancel:       cancel,
	}

	if p.warmInterval > 0 {
		go p.warmLoop()
	}

	bp.L().Info("prefer_domain plugin loaded",
		zap.Int("rules", len(rules)),
		zap.String("resolver", cfg.Resolver),
		zap.Duration("timeout", p.timeout),
		zap.Duration("warm_interval", p.warmInterval))

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
	if r == nil || r.Rcode != dns.RcodeSuccess {
		return nil
	}

	rule, addr, ok := p.matchRule(r)
	if !ok {
		return nil
	}

	preferredResp, err := p.getPreferredResponse(ctx, rule, qType)
	if err != nil {
		p.logger.Debug("failed to resolve preferred domain, keep original response",
			zap.String("prefer_domain", rule.preferDisplay),
			zap.Stringer("matched_ip", addr),
			zap.Error(err))
		return nil
	}

	maskedResp, ok := buildMaskedResponse(q, preferredResp)
	if !ok {
		p.logger.Debug("preferred domain has no usable answer, keep original response",
			zap.String("prefer_domain", rule.preferDisplay),
			zap.Stringer("matched_ip", addr))
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

func (p *PreferDomain) matchRule(r *dns.Msg) (*compiledRule, netip.Addr, bool) {
	for _, rr := range r.Answer {
		addr, ok := rrIP(rr)
		if !ok {
			continue
		}
		for i := range p.rules {
			rule := &p.rules[i]
			if rule.matcher != nil && rule.matcher.Match(addr) {
				return rule, addr, true
			}
		}
	}
	return nil, netip.Addr{}, false
}

func (p *PreferDomain) getPreferredResponse(ctx context.Context, rule *compiledRule, qType uint16) (*dns.Msg, error) {
	key := cacheKey(rule.preferDomain, qType)
	now := time.Now()

	p.mu.RLock()
	ce, ok := p.cache[key]
	if ok && now.Before(ce.expires) && ce.msg != nil {
		msg := ce.msg.Copy()
		p.mu.RUnlock()
		return msg, nil
	}
	stale := ce
	p.mu.RUnlock()

	msg, err := p.resolvePreferred(ctx, rule, qType)
	if err != nil {
		if p.serveStale && stale.msg != nil {
			return stale.msg.Copy(), nil
		}
		return nil, err
	}

	p.storePreferred(rule, qType, msg)
	return msg.Copy(), nil
}

func (p *PreferDomain) resolvePreferred(parent context.Context, rule *compiledRule, qType uint16) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(parent, p.timeout)
	defer cancel()

	q := new(dns.Msg)
	q.SetQuestion(rule.preferDomain, qType)
	q.RecursionDesired = true

	subCtx := query_context.NewContext(q)
	if err := p.resolver.Exec(ctx, subCtx); err != nil && !errors.Is(err, sequence.ErrExit) {
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
		return nil, errors.New("preferred domain response has no wanted A/AAAA answer")
	}
	return r.Copy(), nil
}

func (p *PreferDomain) storePreferred(rule *compiledRule, qType uint16, msg *dns.Msg) {
	if msg == nil {
		return
	}

	ttl := p.cacheTTL
	if ttl <= 0 {
		ttl = ttlFromAnswer(msg, qType)
	}
	if ttl <= 0 {
		ttl = 60 * time.Second
	}

	p.mu.Lock()
	p.cache[cacheKey(rule.preferDomain, qType)] = cacheEntry{
		msg:     msg.Copy(),
		expires: time.Now().Add(ttl),
	}
	p.mu.Unlock()
}

func (p *PreferDomain) warmLoop() {
	if p.warmOnStart {
		p.warmAll()
	}

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
	for i := range p.rules {
		rule := &p.rules[i]
		for _, qType := range []uint16{dns.TypeA, dns.TypeAAAA} {
			select {
			case <-p.ctx.Done():
				return
			default:
			}

			msg, err := p.resolvePreferred(p.ctx, rule, qType)
			if err != nil {
				p.logger.Debug("preferred domain warm-up failed",
					zap.String("prefer_domain", rule.preferDisplay),
					zap.Uint16("qtype", qType),
					zap.Error(err))
				continue
			}
			p.storePreferred(rule, qType, msg)
		}
	}
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

func parseDurationWithDefault(s string, def time.Duration, plainNumberUnit time.Duration) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return def, nil
	}
	if s == "0" {
		return 0, nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		if n < 0 {
			return 0, fmt.Errorf("duration must not be negative")
		}
		return time.Duration(n) * plainNumberUnit, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if d < 0 {
		return 0, fmt.Errorf("duration must not be negative")
	}
	return d, nil
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

func ttlFromAnswer(r *dns.Msg, qType uint16) time.Duration {
	var minTTL uint32
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
		if minTTL == 0 || rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
	}
	return time.Duration(minTTL) * time.Second
}

func buildMaskedResponse(originalQ *dns.Msg, preferredResp *dns.Msg) (*dns.Msg, bool) {
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
	masked.Authoritative = preferredResp.Authoritative
	masked.RecursionAvailable = preferredResp.RecursionAvailable
	masked.AuthenticatedData = preferredResp.AuthenticatedData
	masked.CheckingDisabled = preferredResp.CheckingDisabled

	answers := make([]dns.RR, 0, len(preferredResp.Answer))
	for _, rr := range preferredResp.Answer {
		switch rr := rr.(type) {
		case *dns.A:
			if q.Qtype != dns.TypeA {
				continue
			}
			answers = append(answers, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: rr.Hdr.Ttl},
				A:   append(net.IP(nil), rr.A...),
			})
		case *dns.AAAA:
			if q.Qtype != dns.TypeAAAA {
				continue
			}
			answers = append(answers, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: rr.Hdr.Ttl},
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
