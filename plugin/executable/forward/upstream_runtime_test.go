package fastforward

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/upstream"
)

type runtimeTestUpstream struct{}

func (runtimeTestUpstream) ExchangeContext(context.Context, []byte) (*[]byte, error) {
	return nil, errors.New("completed query")
}

func (runtimeTestUpstream) Close() error { return nil }

func TestUpstreamWrapperCloseConcurrentRuntimeReports(t *testing.T) {
	pluginTag := t.Name()
	w := newRuntimeTestWrapper(t, pluginTag)
	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 853}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 32; j++ {
				w.OnConnectionEvent(upstream.EventConnOpen, remote)
				_, _ = w.ExchangeContext(context.Background(), nil)
				w.OnConnectionEvent(upstream.EventConnClose, remote)
			}
		}()
	}
	close(start)
	for i := 0; i < 32; i++ {
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	for _, status := range coremain.GetUpstreamRuntimeStatuses() {
		if status.PluginTag == pluginTag {
			t.Fatalf("closed upstream remains registered: %+v", status)
		}
	}
}

func TestUpstreamWrapperLateReportsDoNotAffectReplacement(t *testing.T) {
	pluginTag := t.Name()
	old := newRuntimeTestWrapper(t, pluginTag)
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	newRuntimeTestWrapper(t, pluginTag)

	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 853}
	old.OnConnectionEvent(upstream.EventConnOpen, remote)
	_, _ = old.ExchangeContext(context.Background(), nil)
	old.OnConnectionEvent(upstream.EventConnClose, remote)
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}

	var count int
	for _, status := range coremain.GetUpstreamRuntimeStatuses() {
		if status.PluginTag != pluginTag {
			continue
		}
		count++
		if status.Status != "unused" || status.ActiveConnections != 0 ||
			len(status.RemoteAddresses) != 0 || status.LastError != "" ||
			status.LastConnectTime != nil || status.LastActivityTime != nil {
			t.Fatalf("late reports changed replacement upstream: %+v", status)
		}
	}
	if count != 1 {
		t.Fatalf("registered upstream count = %d, want 1", count)
	}
}

func newRuntimeTestWrapper(t *testing.T, pluginTag string) *upstreamWrapper {
	t.Helper()
	w := newWrapper(0, UpstreamConfig{Tag: "resolver", Addr: "quic://127.0.0.1:853"}, pluginTag)
	w.u = runtimeTestUpstream{}
	w.registerRuntime(pluginTag)
	t.Cleanup(func() { _ = w.Close() })
	return w
}
