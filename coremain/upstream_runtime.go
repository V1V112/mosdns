package coremain

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const maxRememberedUpstreamAddresses = 8

var upstreamErrorURLPattern = regexp.MustCompile(`(?i)https?://[^\s"']+`)

// UpstreamRuntimeMeta describes one configured upstream. It intentionally
// contains no dedicated API credentials, and runtime errors are sanitized
// before snapshots are exposed through the API.
type UpstreamRuntimeMeta struct {
	PluginTag      string
	Tag            string
	Protocol       string
	Transport      string
	ConfiguredAddr string
	DialAddr       string
	Socks5Addr     string
}

// UpstreamRuntimeStatus is the public, read-only runtime view used by the web
// panel. RemoteAddresses contains active peers when connections are open and
// falls back to the most recently seen peers while the upstream is idle.
type UpstreamRuntimeStatus struct {
	PluginTag         string     `json:"plugin_tag"`
	Tag               string     `json:"tag"`
	Protocol          string     `json:"protocol"`
	Transport         string     `json:"transport"`
	ConfiguredAddr    string     `json:"configured_addr"`
	DialAddr          string     `json:"dial_addr"`
	RemoteAddresses   []string   `json:"remote_addresses"`
	LastConnectTime   *time.Time `json:"last_connect_time,omitempty"`
	LastActivityTime  *time.Time `json:"last_activity_time,omitempty"`
	Status            string     `json:"status"`
	ActiveConnections int       `json:"active_connections"`
	Socks5           bool       `json:"socks5"`
	Socks5Addr       string     `json:"socks5_addr"`
	LastError        string     `json:"last_error"`
}

type upstreamRuntimeEntry struct {
	meta UpstreamRuntimeMeta

	activeAddresses map[string]int
	recentAddresses []string
	activeCount     int
	lastConnect     time.Time
	lastActivity    time.Time
	lastError       string
	lastExchangeOK  bool
	everExchanged   bool
}

var globalUpstreamRuntime = struct {
	sync.RWMutex
	seq     atomic.Uint64
	entries map[string]*upstreamRuntimeEntry
}{entries: make(map[string]*upstreamRuntimeEntry)}

// RegisterUpstreamRuntime starts tracking an active upstream and returns an
// opaque key for subsequent reports. An empty plugin tag is accepted for quick
// configurations, although those entries normally aren't shown in the panel.
func RegisterUpstreamRuntime(meta UpstreamRuntimeMeta) string {
	id := globalUpstreamRuntime.seq.Add(1)
	key := fmt.Sprintf("%s\x00%s\x00%d", meta.PluginTag, meta.Tag, id)
	globalUpstreamRuntime.Lock()
	globalUpstreamRuntime.entries[key] = &upstreamRuntimeEntry{
		meta:            meta,
		activeAddresses: make(map[string]int),
	}
	globalUpstreamRuntime.Unlock()
	return key
}

// UnregisterUpstreamRuntime removes an upstream when its owning plugin closes.
func UnregisterUpstreamRuntime(key string) {
	if key == "" {
		return
	}
	globalUpstreamRuntime.Lock()
	delete(globalUpstreamRuntime.entries, key)
	globalUpstreamRuntime.Unlock()
}

// ReportUpstreamConnection records an opened or closed network connection.
// remote should be the actual network peer in host:port form when available.
func ReportUpstreamConnection(key, remote string, opened bool) {
	if key == "" {
		return
	}
	now := time.Now().UTC()
	globalUpstreamRuntime.Lock()
	e := globalUpstreamRuntime.entries[key]
	if e != nil {
		remote = strings.TrimSpace(remote)
		if opened {
			e.activeCount++
			e.lastConnect = now
			if remote != "" {
				e.activeAddresses[remote]++
				e.rememberAddress(remote)
			}
		} else {
			if e.activeCount > 0 {
				e.activeCount--
			}
			if remote != "" {
				if n := e.activeAddresses[remote]; n > 1 {
					e.activeAddresses[remote] = n - 1
				} else {
					delete(e.activeAddresses, remote)
				}
			}
		}
	}
	globalUpstreamRuntime.Unlock()
}

// ReportUpstreamRemoteAddress remembers a peer observed by a request-level
// transport hook. It is used by transports such as an HTTP API where the
// standard library owns the connection lifecycle. newlyConnected distinguishes
// a fresh connection from a pooled connection being reused.
func ReportUpstreamRemoteAddress(key, remote string, newlyConnected bool) {
	if key == "" {
		return
	}
	remote = strings.TrimSpace(remote)
	if remote == "" {
		return
	}
	globalUpstreamRuntime.Lock()
	if e := globalUpstreamRuntime.entries[key]; e != nil {
		if newlyConnected {
			e.lastConnect = time.Now().UTC()
		}
		e.rememberAddress(remote)
	}
	globalUpstreamRuntime.Unlock()
}

// ReportUpstreamExchange records completion of an upstream request. Successful
// traffic clears the previous transient error.
func ReportUpstreamExchange(key string, err error) {
	if key == "" {
		return
	}
	now := time.Now().UTC()
	lastError := ""
	if err != nil {
		lastError = sanitizeUpstreamError(err.Error())
	}
	globalUpstreamRuntime.Lock()
	e := globalUpstreamRuntime.entries[key]
	if e != nil {
		e.lastActivity = now
		e.everExchanged = true
		e.lastExchangeOK = err == nil
		e.lastError = lastError
	}
	globalUpstreamRuntime.Unlock()
}

func (e *upstreamRuntimeEntry) rememberAddress(remote string) {
	for i, addr := range e.recentAddresses {
		if addr == remote {
			copy(e.recentAddresses[i:], e.recentAddresses[i+1:])
			e.recentAddresses[len(e.recentAddresses)-1] = remote
			return
		}
	}
	e.recentAddresses = append(e.recentAddresses, remote)
	if len(e.recentAddresses) > maxRememberedUpstreamAddresses {
		e.recentAddresses = append([]string(nil), e.recentAddresses[len(e.recentAddresses)-maxRememberedUpstreamAddresses:]...)
	}
}

func sanitizeUpstreamError(s string) string {
	s = upstreamErrorURLPattern.ReplaceAllStringFunc(s, func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil {
			return "<redacted-url>"
		}
		if u.User != nil {
			u.User = url.User("redacted")
		}
		if u.RawQuery != "" || u.ForceQuery {
			u.RawQuery = "redacted"
			u.ForceQuery = false
		}
		return u.String()
	})

	const maxRunes = 512
	runes := []rune(s)
	if len(runes) <= maxRunes {
		return s
	}
	return string(runes[:maxRunes]) + "..."
}

// GetUpstreamRuntimeStatuses returns a stable snapshot sorted by plugin and
// upstream tag. Callers can safely retain or encode the returned values.
func GetUpstreamRuntimeStatuses() []UpstreamRuntimeStatus {
	globalUpstreamRuntime.RLock()
	statuses := make([]UpstreamRuntimeStatus, 0, len(globalUpstreamRuntime.entries))
	for _, e := range globalUpstreamRuntime.entries {
		addresses := make([]string, 0, len(e.activeAddresses))
		if e.activeCount > 0 {
			for addr := range e.activeAddresses {
				addresses = append(addresses, addr)
			}
			sort.Strings(addresses)
		} else {
			addresses = append(addresses, e.recentAddresses...)
		}

		status := upstreamRuntimeState(e)
		activeConnections := e.activeCount
		if e.meta.Protocol == "udp" || e.meta.Protocol == "aliapi" {
			// A connected UDP socket and an HTTP client's private pool are
			// implementation details, not persistent DNS sessions.
			activeConnections = 0
		}
		s := UpstreamRuntimeStatus{
			PluginTag:         e.meta.PluginTag,
			Tag:               e.meta.Tag,
			Protocol:          e.meta.Protocol,
			Transport:         e.meta.Transport,
			ConfiguredAddr:    e.meta.ConfiguredAddr,
			DialAddr:          e.meta.DialAddr,
			RemoteAddresses:   addresses,
			Status:            status,
			ActiveConnections: activeConnections,
			Socks5:            e.meta.Socks5Addr != "",
			Socks5Addr:        e.meta.Socks5Addr,
			LastError:         e.lastError,
		}
		if !e.lastConnect.IsZero() {
			t := e.lastConnect
			s.LastConnectTime = &t
		}
		if !e.lastActivity.IsZero() {
			t := e.lastActivity
			s.LastActivityTime = &t
		}
		statuses = append(statuses, s)
	}
	globalUpstreamRuntime.RUnlock()

	sort.Slice(statuses, func(i, j int) bool {
		if statuses[i].PluginTag != statuses[j].PluginTag {
			return statuses[i].PluginTag < statuses[j].PluginTag
		}
		if statuses[i].Tag != statuses[j].Tag {
			return statuses[i].Tag < statuses[j].Tag
		}
		return statuses[i].ConfiguredAddr < statuses[j].ConfiguredAddr
	})
	return statuses
}

func upstreamRuntimeState(e *upstreamRuntimeEntry) string {
	// UDP and HTTP APIs don't expose a meaningful persistent-session state.
	// Their status reflects the latest completed exchange instead.
	if e.meta.Protocol == "udp" || e.meta.Protocol == "aliapi" {
		if !e.everExchanged {
			return "unused"
		}
		if e.lastExchangeOK {
			return "ok"
		}
		return "failed"
	}
	if e.activeCount > 0 {
		return "connected"
	}
	if e.everExchanged && !e.lastExchangeOK {
		return "failed"
	}
	if e.everExchanged || !e.lastConnect.IsZero() {
		return "idle"
	}
	return "unused"
}
