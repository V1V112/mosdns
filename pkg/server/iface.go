package server

import (
	"context"
	"net/netip"

	"github.com/miekg/dns"
)

type Handler interface {
	Handle(ctx context.Context, q *dns.Msg, meta QueryMeta, packMsgPayload func(m *dns.Msg) (*[]byte, error)) (respPayload *[]byte)
}

type QueryMeta struct {
	FromUDP bool

	ClientAddr       netip.Addr
	ServerName       string
	UrlPath          string
	PreFastFlags     uint64
	PreFastDomainSet string
	// FastCacheHits is a one-shot aggregate carried by a fast-cache refresh
	// request. Zero means that no hit sample is available. EntryHandler moves
	// this value into query_context before executing plugins and clears it from
	// ServerMeta so background replays cannot count it again.
	FastCacheHits uint32
}
