package coremain

import "testing"

func TestNewBPHasNoImplicitConfigBaseDir(t *testing.T) {
	m := NewTestMosdnsWithPlugins(make(map[string]any))
	if got := NewBP("test", m).ConfigBaseDir(); got != "" {
		t.Fatalf("ConfigBaseDir() = %q, want empty", got)
	}
}

func TestLoadPluginsFromCfgPassesSourceBaseDir(t *testing.T) {
	const pluginType = "test_config_base_dir"
	const wantBaseDir = "/config/source"

	var gotBaseDir string
	RegNewPluginFunc(pluginType, func(bp *BP, _ any) (any, error) {
		gotBaseDir = bp.ConfigBaseDir()
		return struct{}{}, nil
	}, func() any { return new(struct{}) })
	t.Cleanup(func() { DelPluginType(pluginType) })

	m := NewTestMosdnsWithPlugins(make(map[string]any))
	cfg := &Config{
		baseDir: wantBaseDir,
		Plugins: []PluginConfig{{
			Tag:  "test",
			Type: pluginType,
			Args: &struct{}{},
		}},
	}
	if err := m.loadPluginsFromCfg(cfg, 0); err != nil {
		t.Fatal(err)
	}
	if gotBaseDir != wantBaseDir {
		t.Fatalf("ConfigBaseDir() = %q, want %q", gotBaseDir, wantBaseDir)
	}
}
