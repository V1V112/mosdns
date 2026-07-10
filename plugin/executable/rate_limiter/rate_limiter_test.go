package rate_limiter

import (
	"context"
	"net/netip"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
)

func TestMatchBypassesInternalCacheRefresh(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("example.org.", dns.TypeA)
	qCtx := query_context.NewContext(q)
	qCtx.MarkCacheRefresh()

	// A nil limiter is intentional: reaching it would panic and prove that the
	// internal refresh marker was not honored.
	limiter := &RateLimiter{}
	matched, err := limiter.Match(context.Background(), qCtx)
	if err != nil || !matched {
		t.Fatalf("internal refresh was not bypassed: matched=%v err=%v", matched, err)
	}
}

func TestInternalCacheRefreshDoesNotConsumeToken(t *testing.T) {
	limiter, err := New(Args{Qps: 0.000001, Burst: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer limiter.Close()

	q := new(dns.Msg)
	q.SetQuestion("example.org.", dns.TypeA)
	qCtx := query_context.NewContext(q)
	qCtx.ServerMeta.ClientAddr = netip.MustParseAddr("192.0.2.1")
	qCtx.MarkCacheRefresh()
	if matched, err := limiter.Match(context.Background(), qCtx); err != nil || !matched {
		t.Fatalf("internal refresh bypass failed: matched=%v err=%v", matched, err)
	}

	qCtx.DeleteValue(query_context.KeyCacheRefresh)
	if matched, err := limiter.Match(context.Background(), qCtx); err != nil || !matched {
		t.Fatalf("internal refresh consumed the only token: matched=%v err=%v", matched, err)
	}
	if matched, err := limiter.Match(context.Background(), qCtx); err != nil || matched {
		t.Fatalf("normal query did not consume the token: matched=%v err=%v", matched, err)
	}
}
