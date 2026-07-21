package coremain

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestNewMosdnsClosesPluginsReadyAfterAllPluginsLoad(t *testing.T) {
	const pluginType = "test_plugins_ready_success"
	useFreshAuditCollector(t)

	var readyDuringLoad <-chan struct{}
	RegNewPluginFunc(pluginType, func(bp *BP, _ any) (any, error) {
		readyDuringLoad = bp.M().PluginsReady()
		select {
		case <-readyDuringLoad:
			return nil, errors.New("plugins ready signal closed during plugin initialization")
		default:
			return struct{}{}, nil
		}
	}, func() any { return new(struct{}) })
	t.Cleanup(func() { DelPluginType(pluginType) })

	m, err := NewMosdns(&Config{Plugins: []PluginConfig{{
		Tag:  "ready-test",
		Type: pluginType,
		Args: &struct{}{},
	}}})
	if err != nil {
		t.Fatalf("NewMosdns() error = %v", err)
	}
	t.Cleanup(func() {
		m.CloseWithErr(nil)
		_ = m.GetSafeClose().WaitClosed()
	})

	if readyDuringLoad == nil {
		t.Fatal("plugin did not observe a ready channel")
	}
	if readyDuringLoad != m.PluginsReady() {
		t.Fatal("PluginsReady returned different channels")
	}
	select {
	case <-m.PluginsReady():
	default:
		t.Fatal("PluginsReady channel is open after NewMosdns returned successfully")
	}
	if !m.PluginsLoaded() {
		t.Fatal("PluginsLoaded() = false after PluginsReady channel closed")
	}
}

func TestNewMosdnsLeavesPluginsReadyOpenWhenPluginLoadFails(t *testing.T) {
	const pluginType = "test_plugins_ready_failure"
	wantErr := errors.New("intentional plugin load failure")
	useFreshAuditCollector(t)

	var failedMosdns *Mosdns
	RegNewPluginFunc(pluginType, func(bp *BP, _ any) (any, error) {
		failedMosdns = bp.M()
		return nil, wantErr
	}, func() any { return new(struct{}) })
	t.Cleanup(func() { DelPluginType(pluginType) })

	m, err := NewMosdns(&Config{Plugins: []PluginConfig{{
		Tag:  "ready-test-failure",
		Type: pluginType,
		Args: &struct{}{},
	}}})
	if m != nil {
		t.Fatal("NewMosdns() returned a non-nil instance after plugin load failure")
	}
	if err == nil || !strings.Contains(err.Error(), wantErr.Error()) {
		t.Fatalf("NewMosdns() error = %v, want an error containing %q", err, wantErr)
	}
	if failedMosdns == nil {
		t.Fatal("failing plugin did not capture its Mosdns instance")
	}
	select {
	case <-failedMosdns.PluginsReady():
		t.Fatal("PluginsReady channel closed after plugin load failure")
	default:
	}
	if failedMosdns.PluginsLoaded() {
		t.Fatal("PluginsLoaded() = true after plugin load failure")
	}
}

func TestMarkPluginsReadyIsConcurrentSafe(t *testing.T) {
	m := &Mosdns{pluginsReady: make(chan struct{})}

	const goroutines = 32
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			m.markPluginsReady()
		}()
	}
	wg.Wait()

	select {
	case <-m.PluginsReady():
	default:
		t.Fatal("PluginsReady channel is open after markPluginsReady")
	}
	if !m.PluginsLoaded() {
		t.Fatal("PluginsLoaded() = false after markPluginsReady")
	}
}

func TestNewTestMosdnsWithPluginsIsReady(t *testing.T) {
	m := NewTestMosdnsWithPlugins(make(map[string]any))

	select {
	case <-m.PluginsReady():
	default:
		t.Fatal("PluginsReady channel is open when test Mosdns is returned")
	}
	if !m.PluginsLoaded() {
		t.Fatal("PluginsLoaded() = false when test Mosdns is returned")
	}
}

func useFreshAuditCollector(t *testing.T) {
	t.Helper()
	previous := GlobalAuditCollector
	GlobalAuditCollector = NewAuditCollector(defaultAuditCapacity)
	t.Cleanup(func() { GlobalAuditCollector = previous })
}
