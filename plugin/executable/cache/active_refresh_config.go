package cache

import (
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

var removedActiveRefreshFields = map[string]string{
	"interval":             "active_refresh.interval has been removed; refresh scheduling is now TTL-based and dynamic",
	"min_refresh_interval": "active_refresh.min_refresh_interval has been removed; retry intervals are now calculated dynamically",
	"max_entries_per_scan": "active_refresh.max_entries_per_scan has been removed; use max_tasks_per_batch instead",
}

// ValidateRawConfig runs before mapstructure decoding. It provides explicit
// migration errors for removed fields and preserves whether zero-valued fields
// such as max_retry_times and max_idle_time were intentionally configured.
func (a *Args) ValidateRawConfig(raw any) error {
	root, ok := rawStringMap(raw)
	if !ok {
		return nil
	}
	activeRaw, exists := root["active_refresh"]
	if !exists {
		return nil
	}
	active, ok := rawStringMap(activeRaw)
	if !ok {
		return nil
	}
	for _, field := range []string{"interval", "min_refresh_interval", "max_entries_per_scan"} {
		if _, exists := active[field]; exists {
			return fmt.Errorf("%s", removedActiveRefreshFields[field])
		}
	}
	if _, exists := active["max_retry_times"]; exists {
		a.ActiveRefresh.maxRetryTimesConfigured = true
	}
	if _, exists := active["max_idle_time"]; exists {
		a.ActiveRefresh.maxIdleTimeConfigured = true
	}
	for _, field := range []string{
		"threshold", "requery_timeout_ms", "workers", "max_refresh_qps",
		"refresh_burst", "max_tasks_per_batch", "max_pending_tasks",
	} {
		if value, exists := active[field]; exists {
			n, err := rawNumber(value)
			if err != nil {
				return fmt.Errorf("active_refresh.%s must be a finite number", field)
			}
			if n <= 0 {
				return fmt.Errorf("active_refresh.%s must be greater than 0", field)
			}
		}
	}
	for _, field := range []string{"max_retry_times", "max_refresh_times", "max_idle_time"} {
		if value, exists := active[field]; exists {
			n, err := rawNumber(value)
			if err != nil {
				return fmt.Errorf("active_refresh.%s must be a finite number", field)
			}
			if n < 0 {
				return fmt.Errorf("active_refresh.%s must be greater than or equal to 0", field)
			}
		}
	}
	return nil
}

func rawStringMap(raw any) (map[string]any, bool) {
	rv := reflect.ValueOf(raw)
	if !rv.IsValid() || rv.Kind() != reflect.Map {
		return nil, false
	}
	out := make(map[string]any, rv.Len())
	iter := rv.MapRange()
	for iter.Next() {
		key := iter.Key()
		if key.Kind() == reflect.Interface {
			if key.IsNil() {
				return nil, false
			}
			key = key.Elem()
		}
		if key.Kind() != reflect.String {
			return nil, false
		}
		value := iter.Value()
		if value.Kind() == reflect.Interface && !value.IsNil() {
			value = value.Elem()
		}
		var v any
		if value.IsValid() {
			v = value.Interface()
		}
		out[strings.ToLower(key.String())] = v
	}
	return out, true
}

func rawNumber(v any) (float64, error) {
	if v == nil {
		return 0, fmt.Errorf("number is nil")
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Interface {
		rv = rv.Elem()
	}
	var n float64
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n = float64(rv.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n = float64(rv.Uint())
	case reflect.Float32, reflect.Float64:
		n = rv.Float()
	case reflect.String:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(rv.String()), 64)
		if err != nil {
			return 0, err
		}
		n = parsed
	default:
		return 0, fmt.Errorf("not a number")
	}
	if math.IsNaN(n) || math.IsInf(n, 0) {
		return 0, fmt.Errorf("number must be finite")
	}
	return n, nil
}

// validateActiveRefreshBeforeDefaults rejects explicit negative/non-finite
// programmatic values before defaults are applied. Zero remains the historical
// programmatic sentinel for "not specified". Presence-aware WeakDecode and
// direct YAML paths can preserve zero for non-negative controls such as
// max_retry_times, max_refresh_times and max_idle_time.
func validateActiveRefreshBeforeDefaults(a *ActiveRefreshArgs) error {
	if a == nil {
		return fmt.Errorf("active_refresh configuration is nil")
	}
	for field, value := range map[string]float64{
		"threshold":           float64(a.Threshold),
		"requery_timeout_ms":  float64(a.RequeryTimeoutMS),
		"workers":             float64(a.Workers),
		"max_refresh_qps":     a.MaxRefreshQPS,
		"refresh_burst":       float64(a.RefreshBurst),
		"max_tasks_per_batch": float64(a.MaxTasksPerBatch),
		"max_pending_tasks":   float64(a.MaxPendingTasks),
		"max_retry_times":     float64(a.MaxRetryTimes),
		"max_refresh_times":   float64(a.MaxRefreshTimes),
		"max_idle_time":       float64(a.MaxIdleTime),
	} {
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return fmt.Errorf("active_refresh.%s must be finite", field)
		}
		if value < 0 {
			return fmt.Errorf("active_refresh.%s must be greater than or equal to 0", field)
		}
	}
	return nil
}

func validateActiveRefreshArgs(a *ActiveRefreshArgs) error {
	if a == nil {
		return fmt.Errorf("active_refresh configuration is nil")
	}
	switch {
	case a.Threshold <= 0:
		return fmt.Errorf("active_refresh.threshold must be greater than 0")
	case a.RequeryTimeoutMS <= 0:
		return fmt.Errorf("active_refresh.requery_timeout_ms must be greater than 0")
	case a.Workers <= 0:
		return fmt.Errorf("active_refresh.workers must be greater than 0")
	case a.Workers > maxActiveRefreshWorkers:
		return fmt.Errorf("active_refresh.workers must not exceed %d", maxActiveRefreshWorkers)
	case math.IsNaN(a.MaxRefreshQPS) || math.IsInf(a.MaxRefreshQPS, 0):
		return fmt.Errorf("active_refresh.max_refresh_qps must be finite")
	case a.MaxRefreshQPS <= 0:
		return fmt.Errorf("active_refresh.max_refresh_qps must be greater than 0")
	case a.RefreshBurst <= 0:
		return fmt.Errorf("active_refresh.refresh_burst must be greater than 0")
	case a.MaxTasksPerBatch <= 0:
		return fmt.Errorf("active_refresh.max_tasks_per_batch must be greater than 0")
	case a.MaxPendingTasks <= 0:
		return fmt.Errorf("active_refresh.max_pending_tasks must be greater than 0")
	case a.MaxRetryTimes < 0:
		return fmt.Errorf("active_refresh.max_retry_times must be greater than or equal to 0")
	case a.MaxRefreshTimes < 0:
		return fmt.Errorf("active_refresh.max_refresh_times must be greater than or equal to 0")
	case a.MaxIdleTime < 0:
		return fmt.Errorf("active_refresh.max_idle_time must be greater than or equal to 0")
	}
	return nil
}

func validateActiveRefreshYAMLNode(node *yaml.Node) (maxRetryConfigured, maxIdleConfigured bool, err error) {
	if node == nil || node.Kind != yaml.MappingNode {
		return false, false, nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		field := strings.ToLower(node.Content[i].Value)
		if message, removed := removedActiveRefreshFields[field]; removed {
			return false, false, fmt.Errorf("%s", message)
		}
		if field == "max_retry_times" {
			maxRetryConfigured = true
		}
		if field == "max_idle_time" {
			maxIdleConfigured = true
		}
		valueNode := node.Content[i+1]
		strictlyPositive := field == "threshold" || field == "requery_timeout_ms" ||
			field == "workers" || field == "max_refresh_qps" || field == "refresh_burst" ||
			field == "max_tasks_per_batch" || field == "max_pending_tasks"
		nonNegative := field == "max_retry_times" || field == "max_refresh_times" || field == "max_idle_time"
		if strictlyPositive || nonNegative {
			var raw any
			if decodeErr := valueNode.Decode(&raw); decodeErr != nil {
				return false, false, fmt.Errorf("active_refresh.%s must be a number: %w", field, decodeErr)
			}
			n, numberErr := rawNumber(raw)
			if numberErr != nil {
				return false, false, fmt.Errorf("active_refresh.%s must be a finite number", field)
			}
			if strictlyPositive && n <= 0 {
				return false, false, fmt.Errorf("active_refresh.%s must be greater than 0", field)
			}
			if nonNegative && n < 0 {
				return false, false, fmt.Errorf("active_refresh.%s must be greater than or equal to 0", field)
			}
		}
	}
	return maxRetryConfigured, maxIdleConfigured, nil
}
