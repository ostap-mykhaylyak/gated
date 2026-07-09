package logging

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/ostap-mykhaylyak/gated/internal/paths"
)

func TestOpenWriteReopenClose(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	s.Service.Info("hello", "k", "v")
	s.Access.Info("req", "path", "/")

	svcPath := filepath.Join(dir, paths.ServiceLog)

	// Simulate logrotate: move the file away, SIGHUP-style reopen must
	// recreate it and keep logging. Renaming an open file is a Unix
	// semantic (the production target); on Windows dev machines only
	// the in-place reopen is exercised.
	rotated := runtime.GOOS != "windows"
	if rotated {
		if err := os.Rename(svcPath, svcPath+".1"); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Reopen(); err != nil {
		t.Fatal(err)
	}
	s.Service.Info("after rotate")

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(svcPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("no log line written after reopen")
	}
	if rotated {
		old, err := os.ReadFile(svcPath + ".1")
		if err != nil {
			t.Fatal(err)
		}
		if len(old) == 0 {
			t.Fatal("pre-rotation lines lost")
		}
	}
}
