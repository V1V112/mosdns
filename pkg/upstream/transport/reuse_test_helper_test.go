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

package transport

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
)

// dummyEchoNetConn is a TCP DNS echo connection with optional read/write
// failures and response latency. It is shared by the reusable-connection
// transport tests.
type dummyEchoNetConn struct {
	net.Conn
	rErrProb float64
	wErrProb float64

	closeOnce sync.Once
}

func newDummyEchoNetConn(rErrProb float64, rLatency time.Duration, wErrProb float64) NetConn {
	client, server := net.Pipe()
	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		defer client.Close()
		defer server.Close()

		for {
			m, err := dnsutils.ReadRawMsgFromTCP(server)
			if m != nil {
				go func() {
					defer pool.ReleaseBuf(m)
					if rLatency > 0 {
						timer := time.NewTimer(rLatency)
						defer timer.Stop()
						select {
						case <-timer.C:
						case <-ctx.Done():
							return
						}
					}

					// Keep concurrent callers overlapping so the reuse test can
					// assert the number of connections opened by the first wave.
					time.Sleep(time.Millisecond * time.Duration(rand.Intn(20)))
					_, _ = dnsutils.WriteRawMsgToTCP(server, *m)
				}()
			}
			if err != nil {
				return
			}
		}
	}()

	return &dummyEchoNetConn{
		Conn:     client,
		rErrProb: rErrProb,
		wErrProb: wErrProb,
	}
}

func probabilityTrue(p float64) bool {
	return rand.Float64() < p
}

func (d *dummyEchoNetConn) Read(p []byte) (n int, err error) {
	if probabilityTrue(d.rErrProb) {
		return 0, errors.New("read err")
	}
	return d.Conn.Read(p)
}

func (d *dummyEchoNetConn) Write(p []byte) (n int, err error) {
	if probabilityTrue(d.wErrProb) {
		return 0, errors.New("write err")
	}
	return d.Conn.Write(p)
}

func (d *dummyEchoNetConn) Close() error {
	var err error
	d.closeOnce.Do(func() {
		err = d.Conn.Close()
	})
	return err
}
