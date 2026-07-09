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

package cache

import (
	"bytes"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

func Test_cachePlugin_Dump(t *testing.T) {
	c := NewCache(&Args{Size: 16 * dumpBlockSize}, Opts{}) // Big enough to create dump fragments.

	resp := new(dns.Msg)
	resp.SetQuestion("test.", dns.TypeA)

	// Fix: Pack the dns.Msg to []byte because item.resp is now []byte
	packedResp, err := resp.Pack()
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	hourLater := now.Add(time.Hour)
	v := &item{
		resp:           packedResp,
		storedTime:     now,
		expirationTime: hourLater,
	}

	// Fill the cache
	for i := 0; i < 32*dumpBlockSize; i++ {
		c.backend.Store(key(strconv.Itoa(i)), v, hourLater)
	}

	buf := new(bytes.Buffer)
	enw, err := c.writeDump(buf)
	if err != nil {
		t.Fatal(err)
	}
	enr, err := c.readDump(buf)
	if err != nil {
		t.Fatal(err)
	}

	if enw != enr {
		t.Fatalf("read err, wrote %d entries, read %d", enw, enr)
	}
}

func TestActiveRefreshArgs_Unmarshal(t *testing.T) {
	raw := []byte(`
size: 1024
active_refresh:
  enabled: true
  threshold: 60
  interval: 30
  requery_timeout_ms: 5000
  workers: 16
  max_entries_per_scan: 256
  max_refresh_times: 0
  max_idle_time: 3600
  min_refresh_interval: 30
  exclude_ip:
    - 198.18.0.0/15
  exclude_domain:
    exps:
      - domain:fakeip.local
    files:
      - /tmp/no_active_refresh.txt
  fallback_probe:
    enabled: true
    timeout_ms: 60
    stale_extend_ttl: 60
    probes:
      - tcp:443
      - tcp:8443
      - ping
`)
	var args Args
	if err := yaml.Unmarshal(raw, &args); err != nil {
		t.Fatal(err)
	}
	args.init()

	ar := args.ActiveRefresh
	if !ar.Enabled {
		t.Fatal("active refresh should be enabled")
	}
	if ar.RequeryTimeoutMS != 5000 {
		t.Fatalf("requery timeout = %d, want 5000", ar.RequeryTimeoutMS)
	}
	if ar.MaxRefreshTimes != 0 {
		t.Fatalf("max refresh times = %d, want unlimited 0", ar.MaxRefreshTimes)
	}
	if len(ar.ExcludeIPs) != 1 || ar.ExcludeIPs[0] != "198.18.0.0/15" {
		t.Fatalf("exclude ip mismatch: %#v", ar.ExcludeIPs)
	}
	if len(ar.ExcludeDomain.Exps) != 1 || ar.ExcludeDomain.Exps[0] != "domain:fakeip.local" {
		t.Fatalf("exclude domain exps mismatch: %#v", ar.ExcludeDomain.Exps)
	}
	if !ar.FallbackProbe.Enabled || ar.FallbackProbe.TimeoutMS != 60 {
		t.Fatalf("fallback probe mismatch: %#v", ar.FallbackProbe)
	}
	if got := ar.FallbackProbe.Probes[1]; got != "tcp:8443" {
		t.Fatalf("probe order mismatch, got %s", got)
	}
}

func TestActiveRefresh_LowTTLThreshold(t *testing.T) {
	c := NewCache(&Args{
		ActiveRefresh: ActiveRefreshArgs{Threshold: 60},
	}, Opts{})
	defer c.Close()

	now := time.Now()
	v := &item{
		storedTime:     now,
		expirationTime: now.Add(30 * time.Second),
	}
	if c.needsActiveRefresh(v, now.Add(19*time.Second)) {
		t.Fatal("30s original ttl should not refresh with 11s remaining")
	}
	if !c.needsActiveRefresh(v, now.Add(20*time.Second)) {
		t.Fatal("30s original ttl should refresh with 10s remaining")
	}
}

func TestActiveRefresh_MaxRefreshTimesCountsAttempts(t *testing.T) {
	c := NewCache(&Args{
		ActiveRefresh: ActiveRefreshArgs{
			Enabled:         true,
			Threshold:       60,
			MaxRefreshTimes: 1,
		},
	}, Opts{})
	defer c.Close()

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	qCtx := query_context.NewContext(q)
	msgKeyBuf, bufPtr := getMsgKeyBytes(qCtx.Q(), qCtx, false)
	if msgKeyBuf == nil {
		t.Fatal("msg key is nil")
	}
	msgKey := string(msgKeyBuf)
	keyBufferPool.Put(bufPtr)

	now := time.Now()
	k := key(msgKey)
	v := &item{
		storedTime:     now.Add(-29 * time.Second),
		expirationTime: now.Add(1 * time.Second),
	}
	c.activeMeta.Store(k, &activeRefreshMeta{
		qCtx:         qCtx,
		lastAccess:   now,
		refreshCount: 1,
	})
	if task := c.makeActiveRefreshTask(k, v, now); task != nil {
		t.Fatal("active refresh should stop after max refresh attempts")
	}

	c.resetActiveRefreshMeta(msgKey, qCtx, sequence.ChainWalker{}, now)
	if task := c.makeActiveRefreshTask(k, v, now); task == nil {
		t.Fatal("true access should reset active refresh attempts")
	}
}

func TestActiveRefresh_ParseIPNetSupportsIPAndCIDR(t *testing.T) {
	ipNet, err := parseIPNet("198.18.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if !ipNet.Contains(net.ParseIP("198.18.0.1")) || ipNet.Contains(net.ParseIP("198.18.0.2")) {
		t.Fatalf("single ip net mismatch: %v", ipNet)
	}

	cidr, err := parseIPNet("198.18.0.0/15")
	if err != nil {
		t.Fatal(err)
	}
	if !cidr.Contains(net.ParseIP("198.19.255.255")) || cidr.Contains(net.ParseIP("198.20.0.1")) {
		t.Fatalf("cidr net mismatch: %v", cidr)
	}
}

func TestActiveRefresh_QuestionFromKey(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeAAAA)
	qCtx := query_context.NewContext(q)
	msgKeyBuf, bufPtr := getMsgKeyBytes(qCtx.Q(), qCtx, false)
	if msgKeyBuf == nil {
		t.Fatal("msg key is nil")
	}
	defer keyBufferPool.Put(bufPtr)

	question, ok := questionFromKey(key(string(msgKeyBuf)))
	if !ok {
		t.Fatal("failed to parse question from key")
	}
	if question.Name != "example.com." || question.Qtype != dns.TypeAAAA || question.Qclass != dns.ClassINET {
		t.Fatalf("question mismatch: %#v", question)
	}
}

func TestActiveRefresh_ExcludeDomainMatcher(t *testing.T) {
	m, err := buildActiveExcludeDomainMatcher(nil, ActiveRefreshDomainArgs{
		Exps: []string{"domain:fakeip.local", "full:test.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Match("a.fakeip.local."); !ok {
		t.Fatal("domain rule should match subdomain")
	}
	if _, ok := m.Match("test.example.com."); !ok {
		t.Fatal("full rule should match exact domain")
	}
	if _, ok := m.Match("a.test.example.com."); ok {
		t.Fatal("full rule should not match subdomain")
	}
}
