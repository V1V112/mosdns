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
	RealClientAddr   netip.Addr // 仅审计用：由可信本机转发者(xdp-tool)经私有 EDNS 选项传入的真实客户端 IP；不参与路由/client_ip 匹配
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
