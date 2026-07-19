package upstream

import (
	"net"
	"reflect"
	"sync"
	"testing"
)

type recordingEventObserver struct {
	events []Event
}

func (o *recordingEventObserver) OnEvent(event Event) {
	o.events = append(o.events, event)
}

type recordingDetailedEventObserver struct {
	events         []Event
	detailedEvents []Event
	remotes        []net.Addr
}

func (o *recordingDetailedEventObserver) OnEvent(event Event) {
	o.events = append(o.events, event)
}

func (o *recordingDetailedEventObserver) OnConnectionEvent(event Event, remote net.Addr) {
	o.detailedEvents = append(o.detailedEvents, event)
	o.remotes = append(o.remotes, remote)
}

type fixedAddr string

func (a fixedAddr) Network() string { return "test" }
func (a fixedAddr) String() string  { return string(a) }

type remoteAddrConn struct {
	net.Conn
	remote net.Addr
}

func (c *remoteAddrConn) RemoteAddr() net.Addr { return c.remote }

func TestWrapConnSupportsLegacyEventObserver(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })

	observer := new(recordingEventObserver)
	wrapped := wrapConn(client, observer)
	if got, want := observer.events, []Event{EventConnOpen}; !reflect.DeepEqual(got, want) {
		t.Fatalf("events after wrap = %v, want %v", got, want)
	}

	_ = wrapped.Close()
	_ = wrapped.Close()
	if got, want := observer.events, []Event{EventConnOpen, EventConnClose}; !reflect.DeepEqual(got, want) {
		t.Fatalf("events after repeated Close = %v, want %v", got, want)
	}
}

func TestWrapConnReportsRemoteAddressAndClosesOnce(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	wantRemote := fixedAddr("203.0.113.53:853")
	conn := &remoteAddrConn{Conn: client, remote: wantRemote}
	observer := new(recordingDetailedEventObserver)

	wrapped := wrapConn(conn, observer)
	if got, want := observer.events, []Event{EventConnOpen}; !reflect.DeepEqual(got, want) {
		t.Fatalf("legacy events after wrap = %v, want %v", got, want)
	}
	if got, want := observer.detailedEvents, []Event{EventConnOpen}; !reflect.DeepEqual(got, want) {
		t.Fatalf("detailed events after wrap = %v, want %v", got, want)
	}
	assertRemoteAddr(t, observer.remotes, wantRemote)

	const closers = 16
	var wg sync.WaitGroup
	wg.Add(closers)
	for i := 0; i < closers; i++ {
		go func() {
			defer wg.Done()
			_ = wrapped.Close()
		}()
	}
	wg.Wait()

	if got, want := observer.events, []Event{EventConnOpen, EventConnClose}; !reflect.DeepEqual(got, want) {
		t.Fatalf("legacy events after concurrent Close = %v, want %v", got, want)
	}
	if got, want := observer.detailedEvents, []Event{EventConnOpen, EventConnClose}; !reflect.DeepEqual(got, want) {
		t.Fatalf("detailed events after concurrent Close = %v, want %v", got, want)
	}
	assertRemoteAddr(t, observer.remotes, wantRemote, wantRemote)
}

func TestWrapConnNilAndNopObserver(t *testing.T) {
	if got := wrapConn(nil, new(recordingEventObserver)); got != nil {
		t.Fatalf("wrapConn(nil, observer) = %#v, want nil", got)
	}

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = server.Close() })
	if got := wrapConn(client, nopEO{}); got != client {
		t.Fatal("wrapConn changed a connection observed by nopEO")
	}
}

func assertRemoteAddr(t *testing.T, got []net.Addr, want ...net.Addr) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("remote address count = %d, want %d; got %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] == nil {
			t.Fatalf("remote address #%d is nil", i)
		}
		if got[i].Network() != want[i].Network() || got[i].String() != want[i].String() {
			t.Fatalf("remote address #%d = %s/%s, want %s/%s", i, got[i].Network(), got[i], want[i].Network(), want[i])
		}
	}
}
