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

package concurrent_map

import (
	"sync"
)

const (
	MapShardSize = 64
)

type Hashable interface {
	comparable
	Sum() uint64
}

type TestAndSetFunc[K comparable, V any] func(key K, v V, ok bool) (newV V, setV, deleteV bool)

// RemovalCause describes why a value stopped being the value stored for a key.
type RemovalCause uint8

const (
	// RemovalCauseReplaced means an existing value was overwritten by Set,
	// TestAndSet, or RangeDo.
	RemovalCauseReplaced RemovalCause = iota + 1
	// RemovalCauseDeleted means an existing value was explicitly deleted by
	// Del, TestAndSet, or RangeDo.
	RemovalCauseDeleted
	// RemovalCauseCapacity means an entry was evicted to make room in a
	// capacity-limited map.
	RemovalCauseCapacity
	// RemovalCauseFlushed means an entry was removed by Flush.
	RemovalCauseFlushed
)

// RemovalCallback is called when a stored value is replaced or removed.
//
// Callbacks are synchronous: the mutating method does not return until its
// callbacks return. They are always called after the relevant shard lock has
// been released, so a callback may call back into the map. Concurrent map
// operations may invoke the callback concurrently and their notifications may
// arrive in a different order from their mutations. Callers that mirror map
// state should therefore compare the removed value before deleting a newer
// value from the mirror. A callback must not panic; if it does, the mutation
// remains committed and later callbacks from the same batch are not run.
type RemovalCallback[K comparable, V any] func(key K, value V, cause RemovalCause)

type Map[K Hashable, V any] struct {
	shards    [MapShardSize]shard[K, V]
	onRemoval RemovalCallback[K, V]
}

func NewMap[K Hashable, V any]() *Map[K, V] {
	return NewMapWithRemovalCallback[K, V](nil)
}

// NewMapWithRemovalCallback returns an unbounded map that reports replaced and
// removed values to onRemoval. A nil callback disables notifications.
func NewMapWithRemovalCallback[K Hashable, V any](onRemoval RemovalCallback[K, V]) *Map[K, V] {
	m := new(Map[K, V])
	m.onRemoval = onRemoval
	for i := range m.shards {
		m.shards[i] = newShard[K, V](0)
	}
	return m
}

// NewMapCache returns a cache with a maximum size.
// Note that, because it has multiple (MapShardSize) shards, the actual maximum
// size is MapShardSize*max(1, size/MapShardSize) for a positive size.
// If size <=0, it's equal to NewMap().
func NewMapCache[K Hashable, V any](size int) *Map[K, V] {
	return NewMapCacheWithRemovalCallback[K, V](size, nil)
}

// NewMapCacheWithRemovalCallback is like NewMapCache and reports every value
// that is replaced or removed. In particular, capacity eviction is reported
// with RemovalCauseCapacity. A nil callback disables notifications.
func NewMapCacheWithRemovalCallback[K Hashable, V any](size int, onRemoval RemovalCallback[K, V]) *Map[K, V] {
	sizePreShard := size / MapShardSize
	if size > 0 && sizePreShard == 0 {
		sizePreShard = 1
	}
	m := new(Map[K, V])
	m.onRemoval = onRemoval
	for i := range m.shards {
		m.shards[i] = newShard[K, V](sizePreShard)
	}
	return m
}

func (m *Map[K, V]) getShard(key K) *shard[K, V] {
	return &m.shards[key.Sum()%MapShardSize]
}

func (m *Map[K, V]) Get(key K) (V, bool) {
	return m.getShard(key).get(key)
}

// Set stores v. Replacing an existing value reports RemovalCauseReplaced.
// Inserting into a full shard first reports the displaced entry with
// RemovalCauseCapacity.
func (m *Map[K, V]) Set(key K, v V) {
	removed, ok := m.getShard(key).set(key, v)
	m.notifyOne(removed, ok)
}

// Del deletes key. It reports RemovalCauseDeleted only when key existed.
func (m *Map[K, V]) Del(key K) {
	removed, ok := m.getShard(key).del(key)
	m.notifyOne(removed, ok)
}

// TestAndSet atomically evaluates f and applies the requested mutation. A set
// takes precedence if f requests both set and delete. The resulting
// replacement, deletion, or capacity eviction is reported after the shard is
// unlocked. No callback is emitted when f requests no effective mutation.
func (m *Map[K, V]) TestAndSet(key K, f func(v V, ok bool) (newV V, setV, delV bool)) {
	removed, ok := m.getShard(key).testAndSet(key, f)
	m.notifyOne(removed, ok)
}

// RangeDo applies f while each entry's shard is locked. f must not call back
// into the map. Replacements and deletions completed before f returns an error
// remain committed and are reported before RangeDo returns. Removal callbacks
// are deferred until no RangeDo shard lock is held.
func (m *Map[K, V]) RangeDo(f func(k K, v V) (newV V, setV, delV bool, err error)) error {
	var removals []removal[K, V]
	for i := range m.shards {
		removed, err := m.shards[i].rangeDo(f, m.onRemoval != nil)
		removals = append(removals, removed...)
		if err != nil {
			m.notify(removals)
			return err
		}
	}
	m.notify(removals)
	return nil
}

func (m *Map[K, V]) Len() int {
	l := 0
	for i := range m.shards {
		l += m.shards[i].len()
	}
	return l
}

// Flush removes the entries observed during its shard-by-shard pass and reports
// each with RemovalCauseFlushed. Like other concurrent Flush implementations,
// a concurrent Set may survive the pass. All callbacks are deferred until the
// pass has released every shard lock.
func (m *Map[K, V]) Flush() {
	var removals []removal[K, V]
	for i := range m.shards {
		removals = append(removals, m.shards[i].flush(m.onRemoval != nil)...)
	}
	m.notify(removals)
}

func (m *Map[K, V]) notifyOne(r removal[K, V], ok bool) {
	if ok && m.onRemoval != nil {
		m.onRemoval(r.key, r.value, r.cause)
	}
}

func (m *Map[K, V]) notify(removals []removal[K, V]) {
	if m.onRemoval == nil {
		return
	}
	for _, r := range removals {
		m.onRemoval(r.key, r.value, r.cause)
	}
}

type removal[K comparable, V any] struct {
	key   K
	value V
	cause RemovalCause
}

type shard[K comparable, V any] struct {
	l   sync.RWMutex
	max int // Negative or zero max means no limit.
	m   map[K]V
}

func newShard[K comparable, V any](max int) shard[K, V] {
	return shard[K, V]{
		max: max,
		m:   make(map[K]V),
	}
}

func (m *shard[K, V]) get(key K) (V, bool) {
	m.l.RLock()
	defer m.l.RUnlock()
	v, ok := m.m[key]
	return v, ok
}

func (m *shard[K, V]) set(key K, v V) (removal[K, V], bool) {
	m.l.Lock()
	defer m.l.Unlock()
	old, exists := m.m[key]
	var removed removal[K, V]
	var didRemove bool
	if !exists && m.max > 0 && len(m.m)+1 > m.max {
		for k, oldValue := range m.m {
			delete(m.m, k)
			removed = removal[K, V]{key: k, value: oldValue, cause: RemovalCauseCapacity}
			didRemove = true
			if len(m.m)+1 <= m.max {
				break
			}
		}
	} else if exists {
		removed = removal[K, V]{key: key, value: old, cause: RemovalCauseReplaced}
		didRemove = true
	}
	m.m[key] = v
	return removed, didRemove
}

func (m *shard[K, V]) del(key K) (removal[K, V], bool) {
	m.l.Lock()
	defer m.l.Unlock()
	old, ok := m.m[key]
	if !ok {
		return removal[K, V]{}, false
	}
	delete(m.m, key)
	return removal[K, V]{key: key, value: old, cause: RemovalCauseDeleted}, true
}

func (m *shard[K, V]) testAndSet(key K, f func(v V, ok bool) (newV V, setV, delV bool)) (removal[K, V], bool) {
	m.l.Lock()
	defer m.l.Unlock()
	v, ok := m.m[key]
	newV, setV, deleteV := f(v, ok)
	switch {
	case setV:
		if !ok && m.max > 0 && len(m.m)+1 > m.max {
			for k, oldValue := range m.m {
				delete(m.m, k)
				if len(m.m)+1 <= m.max {
					m.m[key] = newV
					return removal[K, V]{key: k, value: oldValue, cause: RemovalCauseCapacity}, true
				}
			}
		}
		m.m[key] = newV
		if ok {
			return removal[K, V]{key: key, value: v, cause: RemovalCauseReplaced}, true
		}
	case deleteV && ok:
		delete(m.m, key)
		return removal[K, V]{key: key, value: v, cause: RemovalCauseDeleted}, true
	}
	return removal[K, V]{}, false
}

func (m *shard[K, V]) len() int {
	m.l.RLock()
	defer m.l.RUnlock()
	return len(m.m)
}

func (m *shard[K, V]) flush(collectRemovals bool) []removal[K, V] {
	m.l.Lock()
	defer m.l.Unlock()
	var removals []removal[K, V]
	if collectRemovals {
		removals = make([]removal[K, V], 0, len(m.m))
		for k, v := range m.m {
			removals = append(removals, removal[K, V]{key: k, value: v, cause: RemovalCauseFlushed})
		}
	}
	m.m = make(map[K]V)
	return removals
}

func (m *shard[K, V]) rangeDo(
	f func(k K, v V) (newV V, setV, delV bool, err error),
	collectRemovals bool,
) ([]removal[K, V], error) {
	m.l.Lock()
	defer m.l.Unlock()
	var removals []removal[K, V]
	for k, v := range m.m {
		newV, setV, deleteV, err := f(k, v)
		if err != nil {
			return removals, err
		}
		switch {
		case setV:
			m.m[k] = newV
			if collectRemovals {
				removals = append(removals, removal[K, V]{key: k, value: v, cause: RemovalCauseReplaced})
			}
		case deleteV:
			delete(m.m, k)
			if collectRemovals {
				removals = append(removals, removal[K, V]{key: k, value: v, cause: RemovalCauseDeleted})
			}
		}
	}
	return removals, nil
}
