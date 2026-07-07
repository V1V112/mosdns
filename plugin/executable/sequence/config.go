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

package sequence

import (
	"fmt"
	"strings"
)

// RuleArgs is intentionally permissive because real-world configs often use
// both of these equivalent YAML forms:
//
//	matches: has_resp
//
// and:
//
//	matches:
//	  - has_resp
//
// Keeping Matches/Exec as any lets us normalize both forms here instead of
// forcing users to rewrite existing configuration files.
type RuleArgs struct {
	Matches any `yaml:"matches"`
	Exec    any `yaml:"exec"`
}

type ExecConfig struct {
	Tag  string
	Type string
	Args string
}

func parseArgs(ra RuleArgs) RuleConfig {
	var rc RuleConfig
	for _, s := range normalizeStringList(ra.Matches) {
		rc.Matches = append(rc.Matches, parseMatch(s))
	}

	for _, s := range normalizeStringList(ra.Exec) {
		rc.Execs = append(rc.Execs, parseExecStr(s))
	}
	return rc
}

func normalizeStringList(v any) []string {
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return nil
		}
		return []string{s}
	case []string:
		out := make([]string, 0, len(x))
		for _, item := range x {
			if s := strings.TrimSpace(item); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			s := strings.TrimSpace(fmt.Sprint(item))
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		s := strings.TrimSpace(fmt.Sprint(x))
		if s == "" || s == "<nil>" {
			return nil
		}
		return []string{s}
	}
}

func parseMatch(s string) MatchConfig {
	var mc MatchConfig
	s = strings.TrimSpace(s)
	s, reverse := trimPrefixField(s, "!")
	mc.Reverse = reverse
	p, args, _ := strings.Cut(s, " ")
	args = strings.TrimSpace(args)
	mc.Args = args
	if tag, ok := trimPrefixField(p, "$"); ok {
		mc.Tag = tag
	} else {
		mc.Type = p
	}
	return mc
}

func parseExecStr(s string) ExecConfig {
	var ec ExecConfig
	s = strings.TrimSpace(s)
	p, args, _ := strings.Cut(s, " ")
	args = strings.TrimSpace(args)
	p, ok := trimPrefixField(p, "$")
	if ok {
		ec.Tag = p
	} else {
		ec.Type = p
	}
	ec.Args = args
	return ec
}

type RuleConfig struct {
	Matches []MatchConfig
	Execs   []ExecConfig
}

type MatchConfig struct {
	Tag     string `yaml:"tag"`
	Type    string `yaml:"type"`
	Args    string `yaml:"args"`
	Reverse bool   `yaml:"reverse"`
}

func trimPrefixField(s, p string) (string, bool) {
	if strings.HasPrefix(s, p) {
		return strings.TrimSpace(strings.TrimPrefix(s, p)), true
	}
	return s, false
}
