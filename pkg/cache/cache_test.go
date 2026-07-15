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
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testKey int

func (t testKey) Sum() uint64 {
	return uint64(t)
}

type controlledTestKeyState struct {
	calls   atomic.Int32
	blocked chan struct{}
	release chan struct{}
}

type controlledTestKey struct {
	state *controlledTestKeyState
}

func (k controlledTestKey) Sum() uint64 {
	if k.state.calls.Add(1) == 2 {
		close(k.state.blocked)
		<-k.state.release
	}
	return 0
}

func Test_Cache(t *testing.T) {
	c := New[testKey, int](Opts{
		Size: 1024,
	})
	for i := 0; i < 128; i++ {
		key := testKey(i)
		c.Store(key, i, time.Now().Add(time.Millisecond*200))
		v, _, ok := c.Get(key)

		if v != i {
			t.Fatal("cache kv mismatched")
		}
		if !ok {
			t.Fatal()
		}
	}

	for i := 0; i < 1024*4; i++ {
		key := testKey(i)
		c.Store(key, i, time.Now().Add(time.Millisecond*200))
	}

	if l := c.Len(); l > 1024 {
		t.Fatal("cache overflow")
	}
}

func Test_memCache_cleaner(t *testing.T) {
	c := New[testKey, int](Opts{
		Size:            1024,
		CleanerInterval: time.Millisecond * 10,
	})
	defer c.Close()
	for i := 0; i < 64; i++ {
		key := testKey(i)
		c.Store(key, i, time.Now().Add(time.Millisecond*10))
	}

	time.Sleep(time.Millisecond * 100)
	if c.Len() != 0 {
		t.Fatal()
	}
}

func Test_memCache_race(t *testing.T) {
	c := New[testKey, int](Opts{
		Size: 1024,
	})
	defer c.Close()

	wg := sync.WaitGroup{}
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 256; i++ {
				key := testKey(i)
				c.Store(key, i, time.Now().Add(time.Minute))
				_, _, _ = c.Get(key)
				c.gc(time.Now())
			}
		}()
	}
	wg.Wait()
}

func TestCacheReplaceIf(t *testing.T) {
	c := New[testKey, *int](Opts{Size: 1024})
	defer c.Close()

	key := testKey(1)
	oldValue := new(int)
	*oldValue = 1
	newValue := new(int)
	*newValue = 2
	c.Store(key, oldValue, time.Now().Add(time.Minute))

	replacementExpiration := time.Now().Add(2 * time.Minute)
	if replaced := c.ReplaceIf(key, newValue, replacementExpiration, func(current *int) bool {
		return current == oldValue
	}); !replaced {
		t.Fatal("matching current value was not replaced")
	}
	got, gotExpiration, ok := c.Get(key)
	if !ok || got != newValue {
		t.Fatalf("replacement result = (%p, %v), want (%p, true)", got, ok, newValue)
	}
	if !gotExpiration.Equal(replacementExpiration) {
		t.Fatalf("replacement expiration = %s, want %s", gotExpiration, replacementExpiration)
	}

	otherValue := new(int)
	if replaced := c.ReplaceIf(key, otherValue, time.Now().Add(time.Minute), func(current *int) bool {
		return current == oldValue
	}); replaced {
		t.Fatal("mismatched current value was replaced")
	}
	if got, _, ok := c.Get(key); !ok || got != newValue {
		t.Fatal("mismatched replacement changed the current value")
	}
}

func TestCacheStoreIfAbsentAndCapacity(t *testing.T) {
	c := New[testKey, int](Opts{Size: 64}) // One entry per map shard.
	defer c.Close()

	if stored := c.StoreIf(0, 1, time.Now().Add(time.Minute), func(_ int, ok bool) bool {
		return !ok
	}); !stored {
		t.Fatal("absent value was not stored")
	}
	if stored := c.StoreIf(0, 2, time.Now().Add(time.Minute), func(_ int, ok bool) bool {
		return !ok
	}); stored {
		t.Fatal("StoreIf(absent) overwrote an existing value")
	}
	if got, _, ok := c.Get(0); !ok || got != 1 {
		t.Fatalf("existing value = (%d, %v), want (1, true)", got, ok)
	}

	// Key 64 maps to the same shard as key 0. Conditional insertion must obey
	// the same capacity bound as Store.
	if stored := c.StoreIf(64, 2, time.Now().Add(time.Minute), func(_ int, ok bool) bool {
		return !ok
	}); !stored {
		t.Fatal("second absent value was not stored")
	}
	if got := c.Len(); got != 1 {
		t.Fatalf("conditional insertion exceeded shard capacity: len=%d", got)
	}
	if got, _, ok := c.Get(64); !ok || got != 2 {
		t.Fatalf("replacement value = (%d, %v), want (2, true)", got, ok)
	}
}

func TestCacheReplaceIfRejectsExpiredValues(t *testing.T) {
	c := New[testKey, *int](Opts{Size: 1024, CleanerInterval: time.Hour})
	defer c.Close()

	key := testKey(1)
	oldValue := new(int)
	newValue := new(int)
	c.m.Set(key, &elem[*int]{v: oldValue, expirationTime: time.Now().Add(-time.Second)})

	if replaced := c.ReplaceIf(key, newValue, time.Now().Add(time.Minute), func(current *int) bool {
		return current == oldValue
	}); replaced {
		t.Fatal("expired current value was replaced")
	}
	if _, _, ok := c.Get(key); ok {
		t.Fatal("expired current value was not removed")
	}

	c.Store(key, oldValue, time.Now().Add(time.Minute))
	if replaced := c.ReplaceIf(key, newValue, time.Now().Add(-time.Second), func(current *int) bool {
		return current == oldValue
	}); replaced {
		t.Fatal("replacement with an expired deadline succeeded")
	}
	if got, _, ok := c.Get(key); !ok || got != oldValue {
		t.Fatal("expired replacement changed the current value")
	}
}

func TestCacheReplaceIfHasSingleConcurrentWinner(t *testing.T) {
	c := New[testKey, *int](Opts{Size: 1024})
	defer c.Close()

	key := testKey(1)
	expected := new(int)
	c.Store(key, expected, time.Now().Add(time.Minute))

	const contenders = 32
	start := make(chan struct{})
	var winners atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func(value int) {
			defer wg.Done()
			<-start
			replacement := new(int)
			*replacement = value
			if c.ReplaceIf(key, replacement, time.Now().Add(time.Minute), func(current *int) bool {
				return current == expected
			}) {
				winners.Add(1)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if got := winners.Load(); got != 1 {
		t.Fatalf("successful concurrent replacements = %d, want 1", got)
	}
	if got, _, ok := c.Get(key); !ok || got == expected {
		t.Fatal("winning replacement was not stored")
	}
}

func TestCacheGetDoesNotDeleteConcurrentFreshStore(t *testing.T) {
	state := &controlledTestKeyState{
		blocked: make(chan struct{}),
		release: make(chan struct{}),
	}
	key := controlledTestKey{state: state}
	c := New[controlledTestKey, int](Opts{Size: 1024, CleanerInterval: time.Hour})
	defer c.Close()

	// Install an expired element directly, then reset the Sum call count. Get's
	// first Sum locates it; its second Sum pauses immediately before the atomic
	// conditional deletion.
	c.m.Set(key, &elem[int]{v: 1, expirationTime: time.Now().Add(-time.Second)})
	state.calls.Store(0)

	getDone := make(chan struct{})
	go func() {
		defer close(getDone)
		_, _, _ = c.Get(key)
	}()

	select {
	case <-state.blocked:
	case <-time.After(5 * time.Second):
		close(state.release)
		t.Fatal("Get did not reach the conditional expiry deletion")
	}
	c.Store(key, 2, time.Now().Add(time.Minute))
	close(state.release)
	select {
	case <-getDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Get did not finish after releasing the expiry deletion")
	}

	got, _, ok := c.Get(key)
	if !ok || got != 2 {
		t.Fatalf("fresh concurrent store = (%d, %v), want (2, true)", got, ok)
	}
}

type testCacheRemovalEvent struct {
	key   testKey
	value int
	cause RemovalCause
}

func TestCacheRemovalCallbackReportsReplacementCapacityExpiryGCAndFlush(t *testing.T) {
	var c *Cache[testKey, int]
	var eventsMu sync.Mutex
	var events []testCacheRemovalEvent
	c = NewWithRemovalCallback[testKey, int](
		Opts{Size: 64, CleanerInterval: time.Hour},
		func(key testKey, value int, cause RemovalCause) {
			// Len visits the callback's shard. It would deadlock if a map-shard
			// write lock were still held while the callback ran.
			_ = c.Len()
			eventsMu.Lock()
			events = append(events, testCacheRemovalEvent{key: key, value: value, cause: cause})
			eventsMu.Unlock()
		},
	)
	defer c.Close()

	run := func(name string, f func()) {
		t.Helper()
		done := make(chan struct{})
		go func() {
			defer close(done)
			f()
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s deadlocked in removal callback", name)
		}
	}

	future := time.Now().Add(time.Hour)
	c.Store(0, 10, future)
	run("Store replacement", func() { c.Store(0, 11, future) })
	run("Store capacity eviction", func() { c.Store(64, 12, future) })
	run("StoreIf replacement", func() {
		if !c.StoreIf(64, 13, future, func(current int, ok bool) bool {
			return ok && current == 12
		}) {
			t.Error("StoreIf did not replace matching value")
		}
	})

	// Get removes exactly the expired element it observed.
	c.m.Set(1, &elem[int]{v: 20, expirationTime: time.Now().Add(-time.Second)})
	run("Get expiry", func() {
		if _, _, ok := c.Get(1); ok {
			t.Error("Get returned an expired value")
		}
	})

	// A rejected StoreIf treats an expired current value as absent and removes
	// its stale physical entry.
	c.m.Set(2, &elem[int]{v: 30, expirationTime: time.Now().Add(-time.Second)})
	run("StoreIf expiry", func() {
		if c.StoreIf(2, 31, future, func(_ int, ok bool) bool { return ok }) {
			t.Error("StoreIf stored after rejecting an expired value")
		}
	})

	// GC reports every expired element it actually removes.
	c.m.Set(3, &elem[int]{v: 40, expirationTime: time.Now().Add(-time.Second)})
	run("GC expiry", func() { c.gc(time.Now()) })

	c.Store(4, 50, future)
	run("Flush", c.Flush)

	want := []testCacheRemovalEvent{
		{key: 0, value: 10, cause: RemovalCauseReplaced},
		{key: 0, value: 11, cause: RemovalCauseCapacity},
		{key: 64, value: 12, cause: RemovalCauseReplaced},
		{key: 1, value: 20, cause: RemovalCauseExpired},
		{key: 2, value: 30, cause: RemovalCauseExpired},
		{key: 3, value: 40, cause: RemovalCauseExpired},
		{key: 64, value: 13, cause: RemovalCauseFlushed},
		{key: 4, value: 50, cause: RemovalCauseFlushed},
	}
	eventsMu.Lock()
	defer eventsMu.Unlock()
	if len(events) != len(want) {
		t.Fatalf("removal events = %#v, want %#v", events, want)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("removal event %d = %#v, want %#v", i, events[i], want[i])
		}
	}
}

func TestCacheRemovalCallbackSkipsNoopStoreAndEmptyFlush(t *testing.T) {
	var calls atomic.Int32
	c := NewWithRemovalCallback[testKey, int](
		Opts{Size: 64, CleanerInterval: time.Hour},
		func(testKey, int, RemovalCause) {
			calls.Add(1)
		},
	)
	defer c.Close()

	c.Store(0, 1, time.Now().Add(-time.Second))
	if c.StoreIf(0, 1, time.Now().Add(-time.Second), func(int, bool) bool { return true }) {
		t.Fatal("StoreIf accepted an expired replacement deadline")
	}
	c.Flush()
	if got := calls.Load(); got != 0 {
		t.Fatalf("no-op operations emitted %d callbacks", got)
	}
}

func TestCacheExpiredEntryEmitsOneCallbackUnderConcurrentGet(t *testing.T) {
	var expirations atomic.Int32
	c := NewWithRemovalCallback[testKey, int](
		Opts{Size: 64, CleanerInterval: time.Hour},
		func(_ testKey, _ int, cause RemovalCause) {
			if cause == RemovalCauseExpired {
				expirations.Add(1)
			}
		},
	)
	defer c.Close()
	c.m.Set(0, &elem[int]{v: 1, expirationTime: time.Now().Add(-time.Second)})

	const readers = 32
	var wg sync.WaitGroup
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = c.Get(0)
		}()
	}
	wg.Wait()
	if got := expirations.Load(); got != 1 {
		t.Fatalf("expiration callbacks = %d, want 1", got)
	}
}
