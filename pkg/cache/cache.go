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
	"github.com/IrineSistiana/mosdns/v5/pkg/concurrent_lru"
	"github.com/IrineSistiana/mosdns/v5/pkg/concurrent_map"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"sync/atomic"
	"time"
)

const (
	defaultCleanerInterval = time.Second * 10
)

type Key interface {
	concurrent_lru.Hashable
}

type Value interface {
	any
}

// RemovalCause describes why a value stopped being the value stored in a
// Cache.
type RemovalCause uint8

const (
	// RemovalCauseReplaced means Store or StoreIf overwrote an unexpired or
	// expired stored value with a new value.
	RemovalCauseReplaced RemovalCause = iota + 1
	// RemovalCauseExpired means Get, StoreIf, or the background cleaner removed
	// an expired value.
	RemovalCauseExpired
	// RemovalCauseCapacity means an entry was evicted to make room in the
	// capacity-limited cache.
	RemovalCauseCapacity
	// RemovalCauseFlushed means an entry was removed by Flush.
	RemovalCauseFlushed
)

// RemovalCallback is called when a stored value is replaced or removed.
//
// The callback is synchronous and always runs without an internal map-shard
// lock held, so it may call back into the Cache. Concurrent cache operations
// may invoke it concurrently and notifications may arrive out of mutation
// order. A mirror cache should compare value identity/version before removing
// a newer entry in response to an old notification. A callback must not panic;
// if it does, the mutation remains committed and later callbacks from the same
// batch are not run.
type RemovalCallback[K Key, V Value] func(key K, value V, cause RemovalCause)

// Cache is a simple map cache that stores values in memory.
// It is safe for concurrent use.
type Cache[K Key, V Value] struct {
	opts Opts

	closed      atomic.Bool
	closeNotify chan struct{}
	m           *concurrent_map.Map[K, *elem[V]]
}

type Opts struct {
	Size            int
	CleanerInterval time.Duration
}

func (opts *Opts) init() {
	utils.SetDefaultNum(&opts.Size, 1024)
	utils.SetDefaultNum(&opts.CleanerInterval, defaultCleanerInterval)
}

type elem[V Value] struct {
	v              V
	expirationTime time.Time
}

// New initializes a Cache.
// The default size is 1024. Because storage is sharded, positive sizes below
// the shard count have an effective maximum of one entry per shard.
// cleanerInterval specifies the interval that Cache scans
// and discards expired values. If cleanerInterval <= 0, a default
// interval will be used.
func New[K Key, V Value](opts Opts) *Cache[K, V] {
	return NewWithRemovalCallback[K, V](opts, nil)
}

// NewWithRemovalCallback initializes a Cache and reports every value that is
// replaced or removed. A nil callback disables notifications.
//
// Close only stops the cleaner; it does not remove entries and therefore does
// not emit removal callbacks.
func NewWithRemovalCallback[K Key, V Value](opts Opts, onRemoval RemovalCallback[K, V]) *Cache[K, V] {
	opts.init()
	var mapRemovalCallback concurrent_map.RemovalCallback[K, *elem[V]]
	if onRemoval != nil {
		mapRemovalCallback = func(key K, e *elem[V], cause concurrent_map.RemovalCause) {
			if e == nil {
				return
			}

			var cacheCause RemovalCause
			switch cause {
			case concurrent_map.RemovalCauseReplaced:
				cacheCause = RemovalCauseReplaced
			case concurrent_map.RemovalCauseDeleted:
				// Cache only deletes map entries when it has observed them as
				// expired, either on access, in StoreIf, or during GC.
				cacheCause = RemovalCauseExpired
			case concurrent_map.RemovalCauseCapacity:
				cacheCause = RemovalCauseCapacity
			case concurrent_map.RemovalCauseFlushed:
				cacheCause = RemovalCauseFlushed
			default:
				return
			}
			onRemoval(key, e.v, cacheCause)
		}
	}
	c := &Cache[K, V]{
		closeNotify: make(chan struct{}),
		m:           concurrent_map.NewMapCacheWithRemovalCallback[K, *elem[V]](opts.Size, mapRemovalCallback),
	}
	go c.gcLoop(opts.CleanerInterval)
	return c
}

// Close closes the inner cleaner of this cache.
func (c *Cache[K, V]) Close() error {
	if ok := c.closed.CompareAndSwap(false, true); ok {
		close(c.closeNotify)
	}
	return nil
}

// Get returns an unexpired value. If it observes an expired value, it removes
// that exact physical entry and reports RemovalCauseExpired; a concurrent fresh
// Store is not deleted.
func (c *Cache[K, V]) Get(key K) (v V, expirationTime time.Time, ok bool) {
	if e, hasEntry := c.m.Get(key); hasEntry {
		if e.expirationTime.Before(time.Now()) {
			// Delete only the element that was observed as expired. A concurrent
			// Store may already have installed a fresh element for the same key.
			c.m.TestAndSet(key, func(current *elem[V], ok bool) (newV *elem[V], setV, delV bool) {
				return nil, false, ok && current == e
			})
			return
		}
		return e.v, e.expirationTime, true
	}
	return
}

// Range calls f through all entries. It does not discard expired entries and
// therefore does not emit removal callbacks. If f returns an error, the same
// error is returned by Range. f runs with the entry's map-shard lock held and
// must not call back into this Cache.
func (c *Cache[K, V]) Range(f func(key K, v V, expirationTime time.Time) error) error {
	cf := func(key K, v *elem[V]) (newV *elem[V], setV bool, delV bool, err error) {
		return nil, false, false, f(key, v.v, v.expirationTime)
	}
	return c.m.RangeDo(cf)
}

// Store stores this kv in cache. If expirationTime is before time.Now(), Store
// is a no-op. Overwriting a physical entry, including an expired one, reports
// RemovalCauseReplaced. Displacing a different entry because the shard is full
// reports RemovalCauseCapacity.
func (c *Cache[K, V]) Store(key K, v V, expirationTime time.Time) {
	now := time.Now()
	if now.After(expirationTime) {
		return
	}

	e := &elem[V]{
		v:              v,
		expirationTime: expirationTime,
	}
	c.m.Set(key, e)
	return
}

// StoreIf atomically stores v when match accepts the current logical value.
// Expired values are presented to match as absent and are removed when match
// rejects them. The predicate and store run while holding the same underlying
// map-shard lock, so another Store, Get expiry deletion, or cache eviction
// cannot interleave between them.
//
// Replacing a physical entry reports RemovalCauseReplaced. If match rejects an
// expired physical entry, its deletion reports RemovalCauseExpired.
//
// match must be non-nil and must not call back into this Cache.
func (c *Cache[K, V]) StoreIf(key K, v V, expirationTime time.Time, match func(current V, ok bool) bool) bool {
	if match == nil || expirationTime.Before(time.Now()) {
		return false
	}

	stored := false
	c.m.TestAndSet(key, func(current *elem[V], ok bool) (newV *elem[V], setV, delV bool) {
		now := time.Now()
		if expirationTime.Before(now) {
			return nil, false, false
		}

		logicalOK := ok && !current.expirationTime.Before(now)
		var currentValue V
		if logicalOK {
			currentValue = current.v
		}
		if !match(currentValue, logicalOK) {
			return nil, false, ok && !logicalOK
		}

		stored = true
		return &elem[V]{v: v, expirationTime: expirationTime}, true, false
	})
	return stored
}

// ReplaceIf atomically replaces an unexpired value when match accepts it.
// An absent or expired current value never matches.
func (c *Cache[K, V]) ReplaceIf(key K, v V, expirationTime time.Time, match func(current V) bool) bool {
	if match == nil {
		return false
	}
	return c.StoreIf(key, v, expirationTime, func(current V, ok bool) bool {
		return ok && match(current)
	})
}

func (c *Cache[K, V]) gcLoop(interval time.Duration) {
	if interval <= 0 {
		interval = defaultCleanerInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.closeNotify:
			return
		case now := <-ticker.C:
			c.gc(now)
		}
	}
}

func (c *Cache[K, V]) gc(now time.Time) {
	f := func(key K, v *elem[V]) (newV *elem[V], setV, delV bool, err error) {
		return nil, false, now.After(v.expirationTime), nil
	}
	_ = c.m.RangeDo(f)
}

// Len returns the current size of this cache.
func (c *Cache[K, V]) Len() int {
	return c.m.Len()
}

// Flush removes all stored entries observed during its shard-by-shard pass and
// reports each with RemovalCauseFlushed. A concurrent Store may survive the
// pass. All callbacks run after the pass has released every map-shard lock.
func (c *Cache[K, V]) Flush() {
	c.m.Flush()
}
