package cache

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
	"github.com/miekg/dns"
)

const activeRefreshExcludeIPFileMaxLineSize = 1 << 20

// activeRefreshExcludeIPArgs is the normalized form of
// active_refresh.exclude_ip. The legacy scalar/list form is normalized into
// CIDRs; the structured form can populate all three fields.
type activeRefreshExcludeIPArgs struct {
	CIDRs  []string
	IPSets []string
	Files  []string
}

// activeRefreshPluginLookup resolves a plugin tag during cache
// initialization. Callers should normally pass bp.M().GetPlugin.
type activeRefreshPluginLookup func(tag string) any

// activeRefreshIPMatcherGroup implements OR matching over immutable local
// rules and provider-backed matchers. Provider matchers are captured once at
// initialization; providers that return a proxy matcher can still update their
// internal snapshots dynamically.
type activeRefreshIPMatcherGroup []netlist.Matcher

func (g activeRefreshIPMatcherGroup) Match(addr netip.Addr) bool {
	for _, matcher := range g {
		if matcher != nil && matcher.Match(addr) {
			return true
		}
	}
	return false
}

// normalizeActiveRefreshExcludeIP accepts both the legacy scalar/list form
// and the structured {cidrs, ip_sets, files} form.
func normalizeActiveRefreshExcludeIP(raw any) (activeRefreshExcludeIPArgs, error) {
	if raw == nil {
		return activeRefreshExcludeIPArgs{}, nil
	}

	rv := reflect.ValueOf(raw)
	if rv.IsValid() && rv.Kind() == reflect.String {
		cidrs := strings.Fields(rv.String())
		return activeRefreshExcludeIPArgs{CIDRs: cidrs}, nil
	}
	if rv.IsValid() && (rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array) {
		cidrs, err := activeRefreshExcludeIPStringList(raw, "active_refresh.exclude_ip", false)
		if err != nil {
			return activeRefreshExcludeIPArgs{}, err
		}
		return activeRefreshExcludeIPArgs{CIDRs: cidrs}, nil
	}

	m, err := activeRefreshExcludeIPMap(raw)
	if err != nil {
		return activeRefreshExcludeIPArgs{}, err
	}

	allowed := map[string]struct{}{
		"cidrs":   {},
		"ip_sets": {},
		"files":   {},
	}
	unknown := make([]string, 0)
	for key := range m {
		if _, ok := allowed[key]; !ok {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return activeRefreshExcludeIPArgs{}, fmt.Errorf(
			"active_refresh.exclude_ip contains unsupported field(s): %s",
			strings.Join(unknown, ", "),
		)
	}

	cidrs, err := activeRefreshExcludeIPStringList(m["cidrs"], "active_refresh.exclude_ip.cidrs", true)
	if err != nil {
		return activeRefreshExcludeIPArgs{}, err
	}
	ipSets, err := activeRefreshExcludeIPStringList(m["ip_sets"], "active_refresh.exclude_ip.ip_sets", true)
	if err != nil {
		return activeRefreshExcludeIPArgs{}, err
	}
	files, err := activeRefreshExcludeIPStringList(m["files"], "active_refresh.exclude_ip.files", true)
	if err != nil {
		return activeRefreshExcludeIPArgs{}, err
	}

	return activeRefreshExcludeIPArgs{
		CIDRs:  cidrs,
		IPSets: ipSets,
		Files:  files,
	}, nil
}

func activeRefreshExcludeIPMap(raw any) (map[string]any, error) {
	rv := reflect.ValueOf(raw)
	if !rv.IsValid() || rv.Kind() != reflect.Map {
		return nil, fmt.Errorf(
			"active_refresh.exclude_ip must be a string, list, or mapping with cidrs, ip_sets, and files; got %T",
			raw,
		)
	}

	m := make(map[string]any, rv.Len())
	iter := rv.MapRange()
	for iter.Next() {
		keyValue := iter.Key()
		if keyValue.Kind() == reflect.Interface {
			keyValue = keyValue.Elem()
		}
		if !keyValue.IsValid() || keyValue.Kind() != reflect.String {
			return nil, fmt.Errorf(
				"active_refresh.exclude_ip mapping contains a non-string key of type %s",
				iter.Key().Type(),
			)
		}
		key := keyValue.String()
		m[key] = iter.Value().Interface()
	}
	return m, nil
}

func activeRefreshExcludeIPStringList(raw any, field string, scalarAsSingle bool) ([]string, error) {
	if raw == nil {
		return nil, nil
	}
	rv := reflect.ValueOf(raw)
	if rv.IsValid() && rv.Kind() == reflect.String {
		s := rv.String()
		if scalarAsSingle {
			return []string{s}, nil
		}
		return strings.Fields(s), nil
	}

	if !rv.IsValid() || (rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array) {
		return nil, fmt.Errorf("%s must be a string or list of strings; got %T", field, raw)
	}

	result := make([]string, 0, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		value := rv.Index(i)
		if value.Kind() == reflect.Interface {
			if value.IsNil() {
				return nil, fmt.Errorf("%s[%d] must be a string; got <nil>", field, i)
			}
			value = value.Elem()
		}
		if value.Kind() != reflect.String {
			return nil, fmt.Errorf("%s[%d] must be a string; got %s", field, i, value.Type())
		}
		result = append(result, value.String())
	}
	return result, nil
}

// buildActiveRefreshExcludeIPMatcher normalizes and compiles all configured
// sources. Relative file paths are resolved against baseDir. All file I/O and
// plugin lookups happen exactly once during this call.
func buildActiveRefreshExcludeIPMatcher(
	raw any,
	baseDir string,
	lookup activeRefreshPluginLookup,
) (netlist.Matcher, error) {
	args, err := normalizeActiveRefreshExcludeIP(raw)
	if err != nil {
		return nil, err
	}
	return compileActiveRefreshExcludeIPMatcher(args, baseDir, lookup)
}

func compileActiveRefreshExcludeIPMatcher(
	args activeRefreshExcludeIPArgs,
	baseDir string,
	lookup activeRefreshPluginLookup,
) (netlist.Matcher, error) {
	local := netlist.NewList()
	for i, rule := range args.CIDRs {
		prefix, err := parseActiveRefreshExcludeIPPrefix(rule)
		if err != nil {
			return nil, fmt.Errorf(
				"active_refresh.exclude_ip.cidrs[%d]: invalid IP or CIDR %q: %w",
				i, rule, err,
			)
		}
		local.Append(prefix)
	}

	for i, configuredPath := range args.Files {
		if err := loadActiveRefreshExcludeIPFile(local, configuredPath, baseDir, i); err != nil {
			return nil, err
		}
	}

	matchers := make(activeRefreshIPMatcherGroup, 0, 1+len(args.IPSets))
	if local.Len() > 0 {
		local.Sort()
		matchers = append(matchers, local)
	}

	for i, untrimmedTag := range args.IPSets {
		tag := strings.TrimSpace(untrimmedTag)
		field := fmt.Sprintf("active_refresh.exclude_ip.ip_sets[%d]", i)
		if tag == "" {
			return nil, fmt.Errorf("%s: plugin tag is empty", field)
		}
		if lookup == nil {
			return nil, fmt.Errorf("%s: cannot resolve plugin %q without mosdns context", field, tag)
		}

		plugin := lookup(tag)
		if isNilActiveRefreshExcludeIPValue(plugin) {
			return nil, fmt.Errorf("%s: plugin %q not found", field, tag)
		}
		provider, ok := plugin.(data_provider.IPMatcherProvider)
		if !ok || isNilActiveRefreshExcludeIPValue(provider) {
			return nil, fmt.Errorf(
				"%s: plugin %q does not implement data_provider.IPMatcherProvider",
				field, tag,
			)
		}
		matcher := provider.GetIPMatcher()
		if isNilActiveRefreshExcludeIPValue(matcher) {
			return nil, fmt.Errorf("%s: plugin %q returned a nil IP matcher", field, tag)
		}
		matchers = append(matchers, matcher)
	}

	if len(matchers) == 0 {
		return nil, nil
	}
	return matchers, nil
}

func parseActiveRefreshExcludeIPPrefix(rule string) (netip.Prefix, error) {
	s := strings.TrimSpace(rule)
	if s == "" {
		return netip.Prefix{}, fmt.Errorf("empty IP or CIDR")
	}

	if strings.ContainsRune(s, '/') {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		if prefix.Addr().Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("scoped IPv6 addresses are not supported")
		}
		return prefix.Masked(), nil
	}

	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	if addr.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("scoped IPv6 addresses are not supported")
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func loadActiveRefreshExcludeIPFile(
	list *netlist.List,
	configuredPath string,
	baseDir string,
	fileIndex int,
) error {
	path := strings.TrimSpace(configuredPath)
	field := fmt.Sprintf("active_refresh.exclude_ip.files[%d]", fileIndex)
	if path == "" {
		return fmt.Errorf("%s: file path is empty", field)
	}

	resolvedPath := path
	if !filepath.IsAbs(resolvedPath) && baseDir != "" {
		resolvedPath = filepath.Join(baseDir, resolvedPath)
	}
	resolvedPath = filepath.Clean(resolvedPath)

	f, err := os.Open(resolvedPath)
	if err != nil {
		if resolvedPath == path {
			return fmt.Errorf("%s: failed to open %q: %w", field, path, err)
		}
		return fmt.Errorf(
			"%s: failed to open %q (resolved to %q): %w",
			field, path, resolvedPath, err,
		)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024), activeRefreshExcludeIPFileMaxLineSize)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if lineNumber == 1 {
			line = strings.TrimPrefix(line, "\ufeff")
		}
		if comment := strings.IndexByte(line, '#'); comment >= 0 {
			line = line[:comment]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		prefix, parseErr := parseActiveRefreshExcludeIPPrefix(line)
		if parseErr != nil {
			return fmt.Errorf(
				"%s: invalid IP or CIDR in %q at line %d: %q: %w",
				field, path, lineNumber, line, parseErr,
			)
		}
		list.Append(prefix)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("%s: failed to read %q at line %d: %w", field, path, lineNumber+1, err)
	}
	return nil
}

func isNilActiveRefreshExcludeIPValue(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

// responseMatchesActiveRefreshIP reports whether any A or AAAA record in the
// Answer section matches the compiled exclusion matcher. Other sections and RR
// types, including CNAME, are deliberately ignored.
func responseMatchesActiveRefreshIP(msg *dns.Msg, matcher netlist.Matcher) bool {
	if msg == nil || matcher == nil {
		return false
	}
	for _, rr := range msg.Answer {
		var addr netip.Addr
		var ok bool
		switch rr := rr.(type) {
		case *dns.A:
			addr, ok = netip.AddrFromSlice(rr.A)
			if ok {
				addr = addr.Unmap()
			}
		case *dns.AAAA:
			addr, ok = netip.AddrFromSlice(rr.AAAA)
		default:
			continue
		}
		if ok && matcher.Match(addr) {
			return true
		}
	}
	return false
}
