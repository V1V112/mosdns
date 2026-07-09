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
	"reflect"
	"strings"
	"testing"
)

func Test_parseExecStr(t *testing.T) {
	tests := []struct {
		name     string
		args     string
		wantTag  string
		wantTyp  string
		wantArgs string
	}{
		{"", " $t1   a 1  ", "t1", "", "a 1"},
		{"", " typ   a 1  ", "", "typ", "a 1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseExecStr(tt.args)

			if got.Tag != tt.wantTag {
				t.Errorf("parseExecStr() gotTag = %v, want %v", got.Tag, tt.wantTag)
			}
			if got.Type != tt.wantTyp {
				t.Errorf("parseExecStr() gotTyp = %v, want %v", got.Type, tt.wantTyp)
			}
			if got.Args != tt.wantArgs {
				t.Errorf("parseExecStr() gotArgs = %v, want %v", got.Args, tt.wantArgs)
			}
		})
	}
}

func Test_parseMatch(t *testing.T) {
	tests := []struct {
		name string
		args string
		want MatchConfig
	}{
		{"", " $m1  a 1 ", MatchConfig{
			Tag:     "m1",
			Type:    "",
			Args:    "a 1",
			Reverse: false,
		}},
		{"", " ! typ  a 1 ", MatchConfig{
			Tag:     "",
			Type:    "typ",
			Args:    "a 1",
			Reverse: true,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseMatch(tt.args); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseMatch() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNormalizeStringListAcceptsStringForms(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want []string
	}{
		{name: "nil", in: nil, want: nil},
		{name: "scalar", in: "  has_resp  ", want: []string{"has_resp"}},
		{name: "string slice", in: []string{" has_resp ", "", "rcode 0"}, want: []string{"has_resp", "rcode 0"}},
		{name: "any slice", in: []any{" has_resp ", "", "rcode 0"}, want: []string{"has_resp", "rcode 0"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeStringList(tt.in)
			if err != nil {
				t.Fatalf("normalizeStringList() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("normalizeStringList() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestNormalizeStringListRejectsNonStrings(t *testing.T) {
	tests := []struct {
		name string
		in   any
	}{
		{name: "scalar number", in: 1},
		{name: "scalar bool", in: true},
		{name: "map", in: map[string]any{"exec": "accept"}},
		{name: "number in list", in: []any{"accept", 1}},
		{name: "nil in list", in: []any{"accept", nil}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := normalizeStringList(tt.in); err == nil {
				t.Fatal("normalizeStringList() accepted a non-string value")
			}
		})
	}
}

func TestParseArgsReportsFieldForInvalidType(t *testing.T) {
	if _, err := parseArgs(RuleArgs{Matches: []any{"has_resp", false}, Exec: "accept"}); err == nil || !strings.Contains(err.Error(), "matches") {
		t.Fatalf("parseArgs() matches error = %v", err)
	}
	if _, err := parseArgs(RuleArgs{Matches: "has_resp", Exec: []any{"accept", 1}}); err == nil || !strings.Contains(err.Error(), "exec") {
		t.Fatalf("parseArgs() exec error = %v", err)
	}
}
