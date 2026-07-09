package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDefaultIsValid(t *testing.T) {
	cfg := Default()
	if err := cfg.validate(); err != nil {
		t.Fatalf("Default() must validate: %v", err)
	}
	if len(cfg.Warnings) != 0 {
		t.Fatalf("Default() must have no warnings, got %v", cfg.Warnings)
	}
}

func TestSkelConfigLoads(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "bootstrap", "skel", "etc", "gated", "config.yaml"))
	if err != nil {
		t.Fatalf("shipped skel config must load: %v", err)
	}
	if len(cfg.Warnings) != 0 {
		t.Fatalf("shipped skel config must have no warnings, got %v", cfg.Warnings)
	}
}

func TestDurationUnmarshal(t *testing.T) {
	var s struct {
		D Duration `yaml:"d"`
	}
	if err := yaml.Unmarshal([]byte(`d: 30m`), &s); err != nil {
		t.Fatal(err)
	}
	if s.D.Std() != 30*time.Minute {
		t.Fatalf("want 30m, got %s", s.D.Std())
	}
	if err := yaml.Unmarshal([]byte(`d: banana`), &s); err == nil {
		t.Fatal("invalid duration must error")
	}
}

func TestLoadPartialOverride(t *testing.T) {
	path := writeTemp(t, "api:\n  enabled: true\n  token: secret\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.API.Enabled || cfg.API.Token != "secret" {
		t.Fatal("override not applied")
	}
	// Defaults must survive a sparse file.
	if cfg.Entrypoints.HTTPS.Listen != "0.0.0.0:443" || !cfg.Entrypoints.HTTPS.HTTP3 {
		t.Fatal("defaults lost on partial load")
	}
	if cfg.Health.MaxFails != 3 || cfg.Health.Cooldown.Std() != 30*time.Second {
		t.Fatal("health defaults lost on partial load")
	}
}

func TestAPIRequiresToken(t *testing.T) {
	path := writeTemp(t, "api:\n  enabled: true\n")
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "api.token") {
		t.Fatalf("api.enabled without token must fail, got %v", err)
	}
}

func TestTrustedProxiesWarnings(t *testing.T) {
	path := writeTemp(t, "proxy:\n  trusted_proxies: [\"10.0.0.0/8\", \"not-a-cidr\", \"192.168.1.1\"]\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Proxy.TrustedProxies) != 2 {
		t.Fatalf("valid entries must be kept, got %v", cfg.Proxy.TrustedProxies)
	}
	if len(cfg.Warnings) != 1 || !strings.Contains(cfg.Warnings[0], "not-a-cidr") {
		t.Fatalf("invalid entry must produce a warning, got %v", cfg.Warnings)
	}
}

func TestCompressionUnknownAlgorithm(t *testing.T) {
	path := writeTemp(t, "compression:\n  algorithms: [gzip, snappy]\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Compression.Algorithms) != 1 || cfg.Compression.Algorithms[0] != "gzip" {
		t.Fatalf("unknown algorithm must be skipped, got %v", cfg.Compression.Algorithms)
	}
	if len(cfg.Warnings) != 1 {
		t.Fatalf("unknown algorithm must produce a warning, got %v", cfg.Warnings)
	}
}

func TestManagerReloadKeepsLastGood(t *testing.T) {
	path := writeTemp(t, "tls:\n  min_version: \"1.3\"\n")
	m, err := NewManager(path)
	if err != nil {
		t.Fatal(err)
	}
	if m.Get().TLS.MinVersion != "1.3" {
		t.Fatal("initial load broken")
	}

	// A broken rewrite must not replace the running config.
	if err := os.WriteFile(path, []byte("tls:\n  min_version: \"9.9\"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := m.Reload(); err == nil {
		t.Fatal("invalid reload must error")
	}
	if m.Get().TLS.MinVersion != "1.3" {
		t.Fatal("running config replaced by a broken one")
	}
	if m.LastError() == "" {
		t.Fatal("LastError must report the pending reload error")
	}

	// A valid rewrite clears the error and swaps the config.
	if err := os.WriteFile(path, []byte("tls:\n  min_version: \"1.2\"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := m.Reload(); err != nil {
		t.Fatal(err)
	}
	if m.Get().TLS.MinVersion != "1.2" || m.LastError() != "" {
		t.Fatal("valid reload must swap config and clear LastError")
	}
}
