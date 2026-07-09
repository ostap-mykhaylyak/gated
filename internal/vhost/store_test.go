package vhost

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/ostap-mykhaylyak/gated/internal/config"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
}

const validVhost = `
hosts: ["app.test", "www.app.test"]
redirect_to_https: false
backends:
  - url: "http://127.0.0.1:8080"
`

func TestLoadAllSkipsInvalid(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "app.yaml", validVhost)
	write(t, dir, "broken.yaml", "hosts: [x.test]\nbackends: []\n") // no backends
	write(t, dir, "ignored.yaml.example", validVhost)               // never loaded

	s := NewStore(dir, discard)
	s.LoadAll(config.Default())

	if v := s.Lookup("app.test"); v == nil {
		t.Fatal("valid vhost not loaded")
	}
	if v := s.Lookup("WWW.App.Test:443"); v == nil {
		t.Fatal("lookup must normalize case and port")
	}
	if v := s.Lookup("x.test"); v != nil {
		t.Fatal("invalid vhost must be skipped")
	}
	if s.Count() != 2 {
		t.Fatalf("want 2 hostnames, got %d", s.Count())
	}
}

func TestLastGoodSurvivesBrokenRewrite(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "app.yaml", validVhost)

	s := NewStore(dir, discard)
	s.LoadAll(config.Default())
	before := s.Lookup("app.test")
	if before == nil {
		t.Fatal("initial load failed")
	}

	// Break the file: the last good version must keep serving.
	write(t, dir, "app.yaml", "hosts: [app.test]\nbackends: []\n")
	s.LoadAll(config.Default())
	after := s.Lookup("app.test")
	if after == nil {
		t.Fatal("vhost lost after broken rewrite")
	}
	if after != before {
		t.Fatal("broken rewrite must keep the previous version")
	}

	// Deleting the file removes the vhost.
	os.Remove(filepath.Join(dir, "app.yaml"))
	s.LoadAll(config.Default())
	if s.Lookup("app.test") != nil {
		t.Fatal("deleted file must remove the vhost")
	}
}

func TestInheritedDefaults(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "app.yaml", validVhost)

	cfg := config.Default()
	s := NewStore(dir, discard)
	s.LoadAll(cfg)

	v := s.Lookup("app.test")
	if v.LoadBalancing.Strategy != "round_robin" {
		t.Fatalf("default strategy wrong: %s", v.LoadBalancing.Strategy)
	}
	if v.LoadBalancing.Health.Passive.MaxFails != cfg.Health.MaxFails {
		t.Fatal("passive health must inherit the global default")
	}
	if !v.Comp.Enabled || v.Comp.MinSize != cfg.Compression.MinSize {
		t.Fatal("compression must inherit the global default")
	}
	if v.Pool == nil {
		t.Fatal("pool not built")
	}
}

func TestExampleVhostSchemaLoads(t *testing.T) {
	// The shipped .example file must always match the real schema.
	data, err := os.ReadFile(filepath.Join("..", "bootstrap", "skel", "etc", "gated", "vhosts", "example.com.yaml.example"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write(t, dir, "example.com.yaml", string(data))

	s := NewStore(dir, discard)
	s.LoadAll(config.Default())
	if s.Lookup("example.com") == nil {
		t.Fatal("shipped example vhost must load against the current schema")
	}
}
