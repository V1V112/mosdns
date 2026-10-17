package aliapi

import (
	"context"
	"errors"
	"net"
	"net/http/httptrace"
	"sync"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/upstream"
)

type runtimeTestUpstream struct{}

func (runtimeTestUpstream) ExchangeContext(ctx context.Context, _ []byte) (*[]byte, error) {
	// Exercise AliAPI's HTTP connection callback without opening a socket.
	if trace := httptrace.ContextClientTrace(ctx); trace != nil && trace.GotConn != nil {
		trace.GotConn(httptrace.GotConnInfo{Conn: runtimeTestConn{}})
	}
	return nil, errors.New("completed query")
}

func (runtimeTestUpstream) Close() error { return nil }

type runtimeTestConn struct{ net.Conn }

func (runtimeTestConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 80}
}

func TestUpstreamWrapperCloseConcurrentRuntimeReports(t *testing.T) {
	for _, typ := range []string{"dns", "aliapi"} {
		t.Run(typ, func(t *testing.T) {
			pluginTag := t.Name()
			w := newRuntimeTestWrapper(t, pluginTag, typ)
			key := w.runtimeKey
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
			// Callback goroutines retain this wrapper after shutdown. The key
			// must remain immutable; the registry ignores reports after removal.
			if w.runtimeKey != key {
				t.Fatalf("Close changed runtime key from %q to %q", key, w.runtimeKey)
			}
			for _, status := range coremain.GetUpstreamRuntimeStatuses() {
				if status.PluginTag == pluginTag {
					t.Fatalf("closed upstream remains registered: %+v", status)
				}
			}
		})
	}
}

func TestUpstreamWrapperLateReportsDoNotAffectReplacement(t *testing.T) {
	for _, typ := range []string{"dns", "aliapi"} {
		t.Run(typ, func(t *testing.T) {
			pluginTag := t.Name()
			old := newRuntimeTestWrapper(t, pluginTag, typ)
			oldKey := old.runtimeKey
			if err := old.Close(); err != nil {
				t.Fatal(err)
			}
			replacement := newRuntimeTestWrapper(t, pluginTag, typ)
			if replacement.runtimeKey == oldKey {
				t.Fatal("replacement reused the closed upstream's runtime key")
			}

			remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 853}
			old.OnConnectionEvent(upstream.EventConnOpen, remote)
			if _, err := old.ExchangeContext(context.Background(), nil); err == nil {
				t.Fatal("fake upstream did not report the late exchange error")
			}
			old.OnConnectionEvent(upstream.EventConnClose, remote)
			if err := old.Close(); err != nil {
				t.Fatal(err)
			}
			if old.runtimeKey != oldKey {
				t.Fatalf("Close changed runtime key from %q to %q", oldKey, old.runtimeKey)
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
		})
	}
}

func newRuntimeTestWrapper(t *testing.T, pluginTag, typ string) *upstreamWrapper {
	t.Helper()
	w := newWrapper(0, UpstreamConfig{Tag: "resolver", Addr: "quic://127.0.0.1:853", Type: typ}, pluginTag)
	w.u = runtimeTestUpstream{}
	w.registerRuntime(pluginTag, "127.0.0.1:80")
	if w.runtimeKey == "" {
		t.Fatal("upstream runtime key is empty after registration")
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}
