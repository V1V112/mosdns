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
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testMapHashable uint64

func (h testMapHashable) Sum() uint64 {
	return uint64(h)
}

func Test_Map(t *testing.T) {
	m := NewMap[testMapHashable, int]()
	wg := sync.WaitGroup{}

	// test add
	for i := 0; i < 512; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.Set(testMapHashable(i), i)
		}()
	}
	wg.Wait()

	// test range
	wantErr := errors.New("")
	f := func(key testMapHashable, v int) (newV int, setV bool, deleteV bool, err error) {
		return 0, false, false, wantErr
	}
	if wantErr != m.RangeDo(f) {
		t.Fatal("range should return a error")
	}

	cc := make([]bool, 512)
	f = func(key testMapHashable, v int) (newV int, setV bool, deleteV bool, err error) {
		cc[key] = true
		return 0, false, false, nil
	}
	_ = m.RangeDo(f)
	for _, ok := range cc {
		if !ok {
			t.Fatal("test or range failed")
		}
	}

	// test get
	for i := 0; i < 512; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, ok := m.Get(testMapHashable(i))
			if !ok {
				t.Error()
				return
			}
			if v != i {
				t.Error()
				return
			}
		}()
	}
	wg.Wait()

	// test len
	if m.Len() != 512 {
		t.Fatal()
	}

	// test del
	for i := 0; i < 512; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.Del(testMapHashable(i))
		}()
	}
	wg.Wait()
	if m.Len() != 0 {
		t.Fatal()
	}
}

func TestConcurrentMap_TestAndSet(t *testing.T) {
	cm := NewMap[testMapHashable, int]()
	wg := sync.WaitGroup{}

	f := func(v int, ok bool) (newV int, setV bool, deleteV bool) {
		return 1, true, false
	}

	for i := 0; i < 512; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cm.TestAndSet(1, f)
		}()
	}
	wg.Wait()

	v, _ := cm.Get(1)
	if v != 1 {
		t.Fatal()
	}

	// test delete
	f = func(v int, ok bool) (newV int, setV bool, deleteV bool) {
		return 1, false, true
	}
	cm.TestAndSet(1, f)
	_, ok := cm.Get(1)
	if ok {
		t.Fatal()
	}
}

func TestMapCacheSmallPositiveSizeIsBounded(t *testing.T) {
	m := NewMapCache[testMapHashable, int](1)
	// Both keys land in shard zero, whose minimum positive capacity is one.
	m.Set(0, 1)
	m.Set(MapShardSize, 2)
	if got := m.Len(); got != 1 {
		t.Fatalf("small positive cache size is unbounded: len=%d", got)
	}
	if got, ok := m.Get(MapShardSize); !ok || got != 2 {
		t.Fatalf("latest value = (%d, %v), want (2, true)", got, ok)
	}
}

func TestMapCacheUpdatingExistingKeyDoesNotEvict(t *testing.T) {
	m := NewMapCache[testMapHashable, int](2 * MapShardSize)
	// Both keys land in shard zero, whose capacity is two.
	m.Set(0, 1)
	m.Set(MapShardSize, 2)
	m.Set(0, 3)
	if got := m.Len(); got != 2 {
		t.Fatalf("updating an existing key changed cache length: %d", got)
	}
	if got, ok := m.Get(0); !ok || got != 3 {
		t.Fatalf("updated value = (%d, %v), want (3, true)", got, ok)
	}
	if got, ok := m.Get(MapShardSize); !ok || got != 2 {
		t.Fatalf("peer value was evicted: (%d, %v)", got, ok)
	}
}

func TestConcurrentMap_GetSetFlush(t *testing.T) {
	const (
		goroutines = 8
		iterations = 1000
	)

	m := NewMap[testMapHashable, int]()
	start := make(chan struct{})
	var wg sync.WaitGroup

	for worker := 0; worker < goroutines; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < iterations; i++ {
				key := testMapHashable(worker*iterations + i)
				m.Set(key, i)
				m.Get(key)
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			m.Flush()
		}
	}()

	close(start)
	wg.Wait()

	m.Set(1, 1)
	if v, ok := m.Get(1); !ok || v != 1 {
		t.Fatalf("map is unusable after concurrent flush: got (%d, %v)", v, ok)
	}
	m.Flush()
	if got := m.Len(); got != 0 {
		t.Fatalf("Flush() left %d entries", got)
	}
}

type testRemovalEvent struct {
	key   testMapHashable
	value int
	cause RemovalCause
}

func TestMapRemovalCallbackReportsEveryMutationPath(t *testing.T) {
	var m *Map[testMapHashable, int]
	var eventsMu sync.Mutex
	var events []testRemovalEvent
	m = NewMapCacheWithRemovalCallback[testMapHashable, int](1, func(key testMapHashable, value int, cause RemovalCause) {
		// Every removal path below targets shard zero. These calls would
		// deadlock if the callback still held that shard's write lock.
		_, _ = m.Get(key)
		_ = m.Len()
		eventsMu.Lock()
		events = append(events, testRemovalEvent{key: key, value: value, cause: cause})
		eventsMu.Unlock()
	})

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

	m.Set(0, 10)
	run("Set replacement", func() { m.Set(0, 11) })
	run("Set capacity eviction", func() { m.Set(MapShardSize, 12) })
	run("TestAndSet replacement", func() {
		m.TestAndSet(MapShardSize, func(int, bool) (int, bool, bool) {
			return 13, true, false
		})
	})
	run("TestAndSet deletion", func() {
		m.TestAndSet(MapShardSize, func(int, bool) (int, bool, bool) {
			return 0, false, true
		})
	})
	m.Set(0, 20)
	run("TestAndSet capacity eviction", func() {
		m.TestAndSet(MapShardSize, func(int, bool) (int, bool, bool) {
			return 21, true, false
		})
	})
	run("Del", func() { m.Del(MapShardSize) })
	m.Set(0, 30)
	run("RangeDo replacement", func() {
		if err := m.RangeDo(func(key testMapHashable, value int) (int, bool, bool, error) {
			return value + 1, true, false, nil
		}); err != nil {
			t.Errorf("RangeDo: %v", err)
		}
	})
	run("RangeDo deletion", func() {
		if err := m.RangeDo(func(testMapHashable, int) (int, bool, bool, error) {
			return 0, false, true, nil
		}); err != nil {
			t.Errorf("RangeDo: %v", err)
		}
	})
	m.Set(0, 40)
	run("Flush", m.Flush)

	want := []testRemovalEvent{
		{key: 0, value: 10, cause: RemovalCauseReplaced},
		{key: 0, value: 11, cause: RemovalCauseCapacity},
		{key: MapShardSize, value: 12, cause: RemovalCauseReplaced},
		{key: MapShardSize, value: 13, cause: RemovalCauseDeleted},
		{key: 0, value: 20, cause: RemovalCauseCapacity},
		{key: MapShardSize, value: 21, cause: RemovalCauseDeleted},
		{key: 0, value: 30, cause: RemovalCauseReplaced},
		{key: 0, value: 31, cause: RemovalCauseDeleted},
		{key: 0, value: 40, cause: RemovalCauseFlushed},
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

func TestMapRemovalCallbackIsExactUnderConcurrentCapacityEviction(t *testing.T) {
	const entries = 64
	var evictions atomic.Int64
	m := NewMapCacheWithRemovalCallback[testMapHashable, int](1, func(_ testMapHashable, _ int, cause RemovalCause) {
		if cause == RemovalCauseCapacity {
			evictions.Add(1)
		}
	})

	var wg sync.WaitGroup
	for i := 0; i < entries; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Keep every key in shard zero, whose capacity is one.
			m.Set(testMapHashable(i*MapShardSize), i)
		}(i)
	}
	wg.Wait()

	if got := m.Len(); got != 1 {
		t.Fatalf("map len = %d, want 1", got)
	}
	if got := evictions.Load(); got != entries-1 {
		t.Fatalf("capacity callbacks = %d, want %d", got, entries-1)
	}
}

func TestMapRemovalCallbackSkipsNoopMutations(t *testing.T) {
	var calls atomic.Int32
	m := NewMapCacheWithRemovalCallback[testMapHashable, int](1, func(testMapHashable, int, RemovalCause) {
		calls.Add(1)
	})

	m.Del(0)
	m.TestAndSet(0, func(int, bool) (int, bool, bool) {
		return 0, false, true
	})
	if err := m.RangeDo(func(testMapHashable, int) (int, bool, bool, error) {
		return 0, false, false, nil
	}); err != nil {
		t.Fatal(err)
	}
	m.Flush()

	if got := calls.Load(); got != 0 {
		t.Fatalf("no-op mutations emitted %d callbacks", got)
	}
}

func TestMapRangeDoErrorReportsEarlierCommittedRemoval(t *testing.T) {
	wantErr := errors.New("stop")
	var events []testRemovalEvent
	m := NewMapWithRemovalCallback[testMapHashable, int](func(key testMapHashable, value int, cause RemovalCause) {
		events = append(events, testRemovalEvent{key: key, value: value, cause: cause})
	})
	m.Set(0, 10)
	m.Set(1, 11)

	err := m.RangeDo(func(key testMapHashable, value int) (int, bool, bool, error) {
		switch key {
		case 0:
			return 0, false, true, nil
		case 1:
			return 0, false, false, wantErr
		default:
			return value, false, false, nil
		}
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("RangeDo error = %v, want %v", err, wantErr)
	}
	want := []testRemovalEvent{{key: 0, value: 10, cause: RemovalCauseDeleted}}
	if len(events) != len(want) || events[0] != want[0] {
		t.Fatalf("removal events = %#v, want %#v", events, want)
	}
	if _, ok := m.Get(0); ok {
		t.Fatal("mutation completed before RangeDo error was rolled back")
	}
	if got, ok := m.Get(1); !ok || got != 11 {
		t.Fatalf("entry at error = (%d, %v), want (11, true)", got, ok)
	}
}

func TestMapFlushDefersCallbacksUntilAfterShardPass(t *testing.T) {
	var m *Map[testMapHashable, int]
	m = NewMapWithRemovalCallback[testMapHashable, int](func(key testMapHashable, _ int, cause RemovalCause) {
		if key == 0 && cause == RemovalCauseFlushed {
			// Key 1 belongs to a shard later in the Flush pass. It must not be
			// swept by the same Flush when stored from a callback.
			m.Set(1, 11)
		}
	})
	m.Set(0, 10)
	m.Flush()
	if got, ok := m.Get(1); !ok || got != 11 {
		t.Fatalf("callback store after Flush pass = (%d, %v), want (11, true)", got, ok)
	}
}

func BenchmarkConcurrentMap_Get_And_Set(b *testing.B) {
	keys := make([]testMapHashable, 2048)
	m := NewMap[testMapHashable, int]()
	for i := 0; i < 2048; i++ {
		key := testMapHashable(i)
		keys[i] = key
		m.Set(key, i)
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			i++
			key := keys[i%2048]
			m.Set(key, i)
			m.Get(key)
		}
	})
}

func Benchmark_RWMutexMap_Get_And_Set(b *testing.B) {
	keys := make([]int, 2048)
	rwm := new(sync.RWMutex)
	m := make(map[int]int, 2048)
	for i := 0; i < 2048; i++ {
		keys[i] = i
		m[i] = i
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			i++
			key := keys[i%2048]

			rwm.Lock()
			m[key] = i
			rwm.Unlock()

			rwm.RLock()
			_ = m[key]
			rwm.RUnlock()
		}
	})
}
