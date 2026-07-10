package query_summary

import (
	"context"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestSummaryLoggerSkipsInternalCacheRefresh(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := NewSummaryLogger(zap.New(core), "test summary")
	q := new(dns.Msg)
	q.SetQuestion("example.org.", dns.TypeA)
	qCtx := query_context.NewContext(q)
	qCtx.MarkCacheRefresh()

	if err := logger.Exec(context.Background(), qCtx, sequence.ChainWalker{}); err != nil {
		t.Fatal(err)
	}
	if got := logs.Len(); got != 0 {
		t.Fatalf("internal refresh produced %d summary logs, want 0", got)
	}

	qCtx.DeleteValue(query_context.KeyCacheRefresh)
	if err := logger.Exec(context.Background(), qCtx, sequence.ChainWalker{}); err != nil {
		t.Fatal(err)
	}
	if got := logs.Len(); got != 1 {
		t.Fatalf("normal query produced %d summary logs, want 1", got)
	}
}
