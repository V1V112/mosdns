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

package upstream

import (
	"net"
	"sync/atomic"

	"github.com/quic-go/quic-go"
)

type Event int

const (
	EventConnOpen Event = iota
	EventConnClose
)

type EventObserver interface {
	OnEvent(typ Event)
}

// DetailedEventObserver is an optional extension implemented by observers that
// need the actual network peer. EventObserver is kept unchanged for backwards
// compatibility with external users of this package.
type DetailedEventObserver interface {
	OnConnectionEvent(typ Event, remote net.Addr)
}

type nopEO struct{}

func (n nopEO) OnEvent(_ Event) {}

type connWrapper struct {
	net.Conn
	closed atomic.Bool
	ob     EventObserver
	remote net.Addr
}

func notifyConnectionEvent(ob EventObserver, typ Event, remote net.Addr) {
	if ob == nil {
		return
	}
	ob.OnEvent(typ)
	if detailed, ok := ob.(DetailedEventObserver); ok {
		detailed.OnConnectionEvent(typ, remote)
	}
}

// wrapConn wraps c into a connWrapper so that we can observe the connection close.
// For convenient, if c is nil, wrapConn returns nil as well. If ob is nopEO, wrapConn
// returns c.
func wrapConn(c net.Conn, ob EventObserver) net.Conn {
	if c == nil {
		return nil
	}
	if _, ok := ob.(nopEO); ok {
		return c
	}
	remote := c.RemoteAddr()
	notifyConnectionEvent(ob, EventConnOpen, remote)
	return &connWrapper{
		Conn:   c,
		ob:     ob,
		remote: remote,
	}
}

func (c *connWrapper) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		notifyConnectionEvent(c.ob, EventConnClose, c.remote)
	}
	return c.Conn.Close()
}

// observeQUICConnection adapts a QUIC session to the same lifecycle events as
// net.Conn based transports.
func observeQUICConnection(c *quic.Conn, ob EventObserver) {
	if c == nil {
		return
	}
	if _, ok := ob.(nopEO); ok {
		return
	}
	remote := c.RemoteAddr()
	notifyConnectionEvent(ob, EventConnOpen, remote)
	go func() {
		<-c.Context().Done()
		notifyConnectionEvent(ob, EventConnClose, remote)
	}()
}
