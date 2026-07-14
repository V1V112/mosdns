package coremain

import (
	"encoding/json"
	"net/http"
	"sort"

	"github.com/go-chi/chi/v5"
)

// ListPluginCapability is implemented by plugins that expose compatible
// /show and /post text-list APIs.
type ListPluginCapability interface {
	ListPluginKind() string
	ListPluginWritable() bool
}

type listPluginInfo struct {
	Tag      string `json:"tag"`
	Kind     string `json:"kind"`
	Writable bool   `json:"writable"`
}

// RegisterListPluginsAPI exposes the list capabilities of loaded plugins so
// the dashboard does not need to guess or hard-code plugin tags.
func RegisterListPluginsAPI(router *chi.Mux, m *Mosdns) {
	router.Get("/api/v1/list-plugins", func(w http.ResponseWriter, r *http.Request) {
		plugins := make([]listPluginInfo, 0)
		for tag, plugin := range m.plugins {
			capability, ok := plugin.(ListPluginCapability)
			if !ok {
				continue
			}
			plugins = append(plugins, listPluginInfo{
				Tag:      tag,
				Kind:     capability.ListPluginKind(),
				Writable: capability.ListPluginWritable(),
			})
		}
		sort.Slice(plugins, func(i, j int) bool { return plugins[i].Tag < plugins[j].Tag })
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(plugins)
	})
}
