package coremain

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

func TestUpstreamRuntimeLifecycle(t *testing.T) {
	const pluginTag = "runtime-test-lifecycle"
	key := RegisterUpstreamRuntime(UpstreamRuntimeMeta{
		PluginTag:     pluginTag,
		Tag:           "cloudflare",
		Protocol:      "doh",
		Transport:     "https",
		ConfiguredAddr: "https://cloudflare-dns.com/dns-query",
		DialAddr:      "1.1.1.1:443",
		Socks5Addr:    "127.0.0.1:7890",
	})
	t.Cleanup(func() { UnregisterUpstreamRuntime(key) })

	item := findRuntimeStatus(t, pluginTag, "cloudflare")
	assertRuntimeField(t, item, "protocol", "doh")
	assertRuntimeField(t, item, "transport", "https")
	assertRuntimeField(t, item, "configured_addr", "https://cloudflare-dns.com/dns-query")
	assertRuntimeField(t, item, "dial_addr", "1.1.1.1:443")
	assertRuntimeField(t, item, "socks5", true)
	assertRuntimeField(t, item, "socks5_addr", "127.0.0.1:7890")
	assertRuntimeField(t, item, "status", "unused")
	assertRuntimeField(t, item, "active_connections", float64(0))

	remote := "1.1.1.1:443"
	ReportUpstreamConnection(key, remote, true)
	item = findRuntimeStatus(t, pluginTag, "cloudflare")
	assertRuntimeField(t, item, "status", "connected")
	assertRuntimeField(t, item, "active_connections", float64(1))
	assertStringSliceField(t, item, "remote_addresses", []string{remote})
	assertRFC3339Field(t, item, "last_connect_time")

	ReportUpstreamExchange(key, nil)
	item = findRuntimeStatus(t, pluginTag, "cloudflare")
	assertRuntimeField(t, item, "status", "connected")
	assertRuntimeField(t, item, "last_error", "")
	assertRFC3339Field(t, item, "last_activity_time")

	ReportUpstreamConnection(key, remote, false)
	item = findRuntimeStatus(t, pluginTag, "cloudflare")
	assertRuntimeField(t, item, "status", "idle")
	assertRuntimeField(t, item, "active_connections", float64(0))

	ReportUpstreamExchange(key, errors.New("query timeout"))
	item = findRuntimeStatus(t, pluginTag, "cloudflare")
	assertRuntimeField(t, item, "status", "failed")
	assertRuntimeField(t, item, "last_error", "query timeout")
	assertRFC3339Field(t, item, "last_activity_time")

	UnregisterUpstreamRuntime(key)
	for _, candidate := range runtimeStatusMaps(t) {
		if candidate["plugin_tag"] == pluginTag && candidate["tag"] == "cloudflare" {
			t.Fatalf("unregistered runtime is still present: %#v", candidate)
		}
	}
}

func TestUpstreamRuntimeProtocolStates(t *testing.T) {
	tests := []struct {
		protocol       string
		transport      string
		connectionless bool
	}{
		{protocol: "udp", transport: "udp", connectionless: true},
		{protocol: "tcp", transport: "tcp"},
		{protocol: "dot", transport: "tls"},
		{protocol: "doh", transport: "https"},
		{protocol: "doh3", transport: "quic"},
		{protocol: "doq", transport: "quic"},
		{protocol: "aliapi", transport: "http", connectionless: true},
	}

	for _, tt := range tests {
		t.Run(tt.protocol, func(t *testing.T) {
			pluginTag := "runtime-test-protocol-" + tt.protocol
			key := RegisterUpstreamRuntime(UpstreamRuntimeMeta{
				PluginTag: pluginTag,
				Tag:       "resolver",
				Protocol:  tt.protocol,
				Transport: tt.transport,
			})
			t.Cleanup(func() { UnregisterUpstreamRuntime(key) })

			item := findRuntimeStatus(t, pluginTag, "resolver")
			assertRuntimeField(t, item, "status", "unused")
			assertRuntimeField(t, item, "protocol", tt.protocol)
			assertRuntimeField(t, item, "transport", tt.transport)

			if tt.connectionless {
				remote := "192.0.2.53:53"
				ReportUpstreamRemoteAddress(key, remote, true)
				item = findRuntimeStatus(t, pluginTag, "resolver")
				assertStringSliceField(t, item, "remote_addresses", []string{remote})
				assertRuntimeField(t, item, "active_connections", float64(0))
				assertRFC3339Field(t, item, "last_connect_time")
				ReportUpstreamExchange(key, nil)
				item = findRuntimeStatus(t, pluginTag, "resolver")
				assertRuntimeField(t, item, "status", "ok")
			} else {
				remote := "192.0.2.53:853"
				ReportUpstreamConnection(key, remote, true)
				item = findRuntimeStatus(t, pluginTag, "resolver")
				assertRuntimeField(t, item, "status", "connected")
				ReportUpstreamConnection(key, remote, false)
				item = findRuntimeStatus(t, pluginTag, "resolver")
				assertRuntimeField(t, item, "status", "idle")
			}

			ReportUpstreamExchange(key, errors.New("protocol test failure"))
			item = findRuntimeStatus(t, pluginTag, "resolver")
			assertRuntimeField(t, item, "status", "failed")
		})
	}
}

func TestUpstreamRuntimeStatusesAreSortedAndIndependent(t *testing.T) {
	const prefix = "runtime-test-sort-"
	metas := []UpstreamRuntimeMeta{
		{PluginTag: prefix + "b", Tag: "z", Protocol: "udp", Transport: "udp"},
		{PluginTag: prefix + "a", Tag: "z", Protocol: "dot", Transport: "tls"},
		{PluginTag: prefix + "a", Tag: "a", Protocol: "doq", Transport: "quic"},
	}
	keys := make([]string, 0, len(metas))
	for _, meta := range metas {
		key := RegisterUpstreamRuntime(meta)
		keys = append(keys, key)
		t.Cleanup(func() { UnregisterUpstreamRuntime(key) })
	}
	const remote = "[2001:db8::53]:853"
	ReportUpstreamConnection(keys[2], remote, true)

	got := make([]string, 0, len(metas))
	for _, item := range runtimeStatusMaps(t) {
		pluginTag, _ := item["plugin_tag"].(string)
		if strings.HasPrefix(pluginTag, prefix) {
			got = append(got, pluginTag+"/"+item["tag"].(string))
		}
	}
	want := []string{
		prefix + "a/a",
		prefix + "a/z",
		prefix + "b/z",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("runtime status order = %v, want %v", got, want)
	}

	// A returned snapshot must not expose mutable registry storage. Mutating one
	// snapshot must have no effect on the next one.
	snapshot := GetUpstreamRuntimeStatuses()
	mutated := false
	for i := range snapshot {
		if snapshot[i].PluginTag == prefix+"a" && snapshot[i].Tag == "a" {
			if len(snapshot[i].RemoteAddresses) != 1 {
				t.Fatalf("RemoteAddresses = %v, want [%s]", snapshot[i].RemoteAddresses, remote)
			}
			snapshot[i].RemoteAddresses[0] = "caller-mutation:1"
			mutated = true
			break
		}
	}
	if !mutated {
		t.Fatal("registered runtime was absent from snapshot")
	}
	fresh := findRuntimeStatus(t, prefix+"a", "a")
	assertStringSliceField(t, fresh, "remote_addresses", []string{remote})
}

func TestUpstreamRuntimeRedactsSensitiveURLs(t *testing.T) {
	const pluginTag = "runtime-test-redaction"
	key := RegisterUpstreamRuntime(UpstreamRuntimeMeta{
		PluginTag: pluginTag,
		Tag:       "aliapi",
		Protocol:  "aliapi",
		Transport: "http",
	})
	t.Cleanup(func() { UnregisterUpstreamRuntime(key) })

	ReportUpstreamExchange(key, errors.New(`Get "http://user:password@223.5.5.5/resolve?uid=account&ak=secret&key=signature": timeout`))
	item := findRuntimeStatus(t, pluginTag, "aliapi")
	lastError, _ := item["last_error"].(string)
	for _, secret := range []string{"password", "account", "secret", "signature"} {
		if strings.Contains(lastError, secret) {
			t.Fatalf("last_error leaked %q: %s", secret, lastError)
		}
	}
	if !strings.Contains(lastError, "redacted") || !strings.Contains(lastError, "timeout") {
		t.Fatalf("last_error = %q, want redacted URL and preserved error reason", lastError)
	}
}

func TestUpstreamRuntimeRegistryConcurrentAccess(t *testing.T) {
	const pluginTag = "runtime-test-concurrent"
	key := RegisterUpstreamRuntime(UpstreamRuntimeMeta{
		PluginTag: pluginTag,
		Tag:       "resolver",
		Protocol:  "doh3",
		Transport: "quic",
	})
	t.Cleanup(func() { UnregisterUpstreamRuntime(key) })

	const (
		writers    = 12
		iterations = 100
	)
	start := make(chan struct{})
	errCh := make(chan error, writers+1)
	var wg sync.WaitGroup

	for writer := 0; writer < writers; writer++ {
		writer := writer
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			remote := fmt.Sprintf("192.0.2.%d:443", writer+1)
			for i := 0; i < iterations; i++ {
				ReportUpstreamConnection(key, remote, true)
				if i%5 == 0 {
					ReportUpstreamExchange(key, errors.New("temporary failure"))
				} else {
					ReportUpstreamExchange(key, nil)
				}
				ReportUpstreamConnection(key, remote, false)
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < writers*iterations; i++ {
			for _, item := range GetUpstreamRuntimeStatuses() {
				if item.ActiveConnections < 0 {
					errCh <- fmt.Errorf("active_connections became negative: %d", item.ActiveConnections)
					return
				}
			}
		}
	}()

	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}

	item := findRuntimeStatus(t, pluginTag, "resolver")
	assertRuntimeField(t, item, "active_connections", float64(0))
	assertRuntimeField(t, item, "status", "idle")
}

func TestGetUpstreamRuntimeStatusAPI(t *testing.T) {
	const pluginTag = "runtime-test-api"
	key := RegisterUpstreamRuntime(UpstreamRuntimeMeta{
		PluginTag:     pluginTag,
		Tag:           "google",
		Protocol:      "dot",
		Transport:     "tls",
		ConfiguredAddr: "tls://dns.google",
		DialAddr:      "8.8.8.8:853",
	})
	t.Cleanup(func() { UnregisterUpstreamRuntime(key) })
	ReportUpstreamConnection(key, "8.8.8.8:853", true)
	ReportUpstreamExchange(key, nil)

	router := chi.NewRouter()
	RegisterUpstreamAPI(router)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/upstream/status", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("GET status code = %d, want %d; body: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if got := recorder.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}

	var response struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	var item map[string]any
	for _, candidate := range response.Items {
		if candidate["plugin_tag"] == pluginTag && candidate["tag"] == "google" {
			item = candidate
			break
		}
	}
	if item == nil {
		t.Fatalf("response does not contain %s/google: %#v", pluginTag, response.Items)
	}

	assertRuntimeField(t, item, "protocol", "dot")
	assertRuntimeField(t, item, "transport", "tls")
	assertRuntimeField(t, item, "configured_addr", "tls://dns.google")
	assertRuntimeField(t, item, "dial_addr", "8.8.8.8:853")
	assertRuntimeField(t, item, "socks5", false)
	assertRuntimeField(t, item, "socks5_addr", "")
	assertRuntimeField(t, item, "status", "connected")
	assertRuntimeField(t, item, "active_connections", float64(1))
	assertStringSliceField(t, item, "remote_addresses", []string{"8.8.8.8:853"})
	assertRFC3339Field(t, item, "last_connect_time")
	assertRFC3339Field(t, item, "last_activity_time")
}

func runtimeStatusMaps(t *testing.T) []map[string]any {
	t.Helper()
	items, err := runtimeStatusMapsE()
	if err != nil {
		t.Fatal(err)
	}
	return items
}

func runtimeStatusMapsE() ([]map[string]any, error) {
	b, err := json.Marshal(GetUpstreamRuntimeStatuses())
	if err != nil {
		return nil, fmt.Errorf("marshal status snapshot: %w", err)
	}
	var items []map[string]any
	if err := json.Unmarshal(b, &items); err != nil {
		return nil, fmt.Errorf("decode status snapshot: %w", err)
	}
	return items, nil
}

func findRuntimeStatus(t *testing.T, pluginTag, tag string) map[string]any {
	t.Helper()
	for _, item := range runtimeStatusMaps(t) {
		if item["plugin_tag"] == pluginTag && item["tag"] == tag {
			return item
		}
	}
	t.Fatalf("runtime status %s/%s not found", pluginTag, tag)
	return nil
}

func assertRuntimeField(t *testing.T, item map[string]any, field string, want any) {
	t.Helper()
	if got := item[field]; !reflect.DeepEqual(got, want) {
		t.Fatalf("%s = %#v (%T), want %#v (%T); item: %#v", field, got, got, want, want, item)
	}
}

func assertStringSliceField(t *testing.T, item map[string]any, field string, want []string) {
	t.Helper()
	raw, ok := item[field].([]any)
	if !ok {
		t.Fatalf("%s has type %T, want JSON array; item: %#v", field, item[field], item)
	}
	got := make([]string, 0, len(raw))
	for _, value := range raw {
		s, ok := value.(string)
		if !ok {
			t.Fatalf("%s contains %T, want strings", field, value)
		}
		got = append(got, s)
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s = %v, want %v", field, got, want)
	}
}

func assertRFC3339Field(t *testing.T, item map[string]any, field string) {
	t.Helper()
	value, ok := item[field].(string)
	if !ok || value == "" {
		t.Fatalf("%s = %#v, want a non-empty RFC3339 timestamp", field, item[field])
	}
	if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
		t.Fatalf("%s = %q, want RFC3339 timestamp: %v", field, value, err)
	}
}
