package secret

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// File permissions are only meaningfully enforced on Unix (the
// production target); Windows dev machines ignore them.
var runtimePermsMatter = runtime.GOOS != "windows"

func TestConfiguredWins(t *testing.T) {
	got, err := LoadOrCreate("my-key", filepath.Join(t.TempDir(), "unused"))
	if err != nil {
		t.Fatal(err)
	}
	if got != "my-key" {
		t.Fatalf("configured secret must win, got %q", got)
	}
}

func TestGeneratesAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "secret")

	first, err := LoadOrCreate("", path)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) < 32 {
		t.Fatalf("generated key too short: %d", len(first))
	}
	// The file is created with restrictive perms.
	if fi, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if runtimePermsMatter && fi.Mode().Perm() != 0o600 {
		t.Fatalf("secret file perms = %o, want 600", fi.Mode().Perm())
	}

	// A second load returns the SAME key (persisted, survives restart).
	second, err := LoadOrCreate("", path)
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Fatal("persisted secret must be stable across loads")
	}
}
