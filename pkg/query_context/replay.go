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
 * along with mosdns.  If not, see <https://www.gnu.org/licenses/>.
 */

package query_context

import (
	"fmt"

	"github.com/miekg/dns"
)

// ReplaySnapshot is an immutable, compact copy of the request-side state a
// background replay needs. DNS messages are retained in wire form so a cache
// entry does not keep an object graph of questions, records and EDNS options
// alive. Values stored in Context remain shallow-copied, matching CopyTo and
// CopyWithoutResponse semantics. Client trace identity is omitted because a
// background executor must call RenewTrace immediately before replay.
type ReplaySnapshot struct {
	serverMeta ServerMeta
	queryWire  []byte
	compress   bool
	clientOpt  []byte
	respOpt    []byte

	values    []replayValue
	marks     []uint32
	fastFlags uint64
	fastQName string
	fastQType uint16
}

type replayValue struct {
	key   uint32
	value any
}

// SnapshotForReplay captures the request-side state of ctx. The returned
// snapshot can be shared by concurrent schedulers; ContextForReplay always
// materializes independent mutable state for an individual execution.
func (ctx *Context) SnapshotForReplay() (*ReplaySnapshot, error) {
	if ctx == nil || ctx.query == nil {
		return nil, fmt.Errorf("cannot snapshot a nil query context")
	}

	queryWire, err := ctx.query.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack replay query: %w", err)
	}
	clientOpt, err := packReplayOPT(ctx.clientOpt)
	if err != nil {
		return nil, fmt.Errorf("pack replay client OPT: %w", err)
	}
	respOpt, err := packReplayOPT(ctx.respOpt)
	if err != nil {
		return nil, fmt.Errorf("pack replay response OPT: %w", err)
	}

	serverMeta := ctx.ServerMeta
	serverMeta.FastCacheHits = 0
	s := &ReplaySnapshot{
		serverMeta: serverMeta,
		queryWire:  queryWire,
		compress:   ctx.query.Compress,
		clientOpt:  clientOpt,
		respOpt:    respOpt,
		fastFlags:  ctx.fastFlags,
		fastQName:  ctx.FastQName,
		fastQType:  ctx.FastQType,
	}
	if len(ctx.kv) > 0 {
		s.values = make([]replayValue, 0, len(ctx.kv))
		for k, v := range ctx.kv {
			s.values = append(s.values, replayValue{key: k, value: v})
		}
	}
	if len(ctx.marks) > 0 {
		s.marks = make([]uint32, 0, len(ctx.marks))
		for mark := range ctx.marks {
			s.marks = append(s.marks, mark)
		}
	}
	return s, nil
}

// ContextForReplay expands s into a fresh mutable Context. The response and
// upstream OPT are intentionally empty because a replay must execute the
// continuation as a new request.
func (s *ReplaySnapshot) ContextForReplay() (*Context, error) {
	if s == nil || len(s.queryWire) == 0 {
		return nil, fmt.Errorf("cannot materialize an empty replay snapshot")
	}

	q := new(dns.Msg)
	if err := q.Unpack(s.queryWire); err != nil {
		return nil, fmt.Errorf("unpack replay query: %w", err)
	}
	if len(q.Question) != 1 {
		return nil, fmt.Errorf("replay query has %d questions, want 1", len(q.Question))
	}
	q.Compress = s.compress
	clientOpt, err := unpackReplayOPT(s.clientOpt)
	if err != nil {
		return nil, fmt.Errorf("unpack replay client OPT: %w", err)
	}
	respOpt, err := unpackReplayOPT(s.respOpt)
	if err != nil {
		return nil, fmt.Errorf("unpack replay response OPT: %w", err)
	}

	ctx := &Context{
		ServerMeta: s.serverMeta,
		query:      q,
		clientOpt:  clientOpt,
		respOpt:    respOpt,
		fastFlags:  s.fastFlags,
		FastQName:  s.fastQName,
		FastQType:  s.fastQType,
	}
	if len(s.values) > 0 {
		ctx.kv = make(map[uint32]any, len(s.values))
		for _, value := range s.values {
			ctx.kv[value.key] = value.value
		}
	}
	if len(s.marks) > 0 {
		ctx.marks = make(map[uint32]struct{}, len(s.marks))
		for _, mark := range s.marks {
			ctx.marks[mark] = struct{}{}
		}
	}
	return ctx, nil
}

func packReplayOPT(opt *dns.OPT) ([]byte, error) {
	if opt == nil {
		return nil, nil
	}
	m := new(dns.Msg)
	m.Extra = []dns.RR{opt}
	return m.Pack()
}

func unpackReplayOPT(wire []byte) (*dns.OPT, error) {
	if len(wire) == 0 {
		return nil, nil
	}
	m := new(dns.Msg)
	if err := m.Unpack(wire); err != nil {
		return nil, err
	}
	if len(m.Extra) != 1 {
		return nil, fmt.Errorf("OPT envelope has %d records, want 1", len(m.Extra))
	}
	opt, ok := m.Extra[0].(*dns.OPT)
	if !ok {
		return nil, fmt.Errorf("OPT envelope contains %T", m.Extra[0])
	}
	return opt, nil
}
