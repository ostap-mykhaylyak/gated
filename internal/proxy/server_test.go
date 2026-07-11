package proxy

import (
	"errors"
	"strings"
	"syscall"
	"testing"
)

func TestBindErrorHint(t *testing.T) {
	// An address-in-use on a wildcard bind gets the public-IP hint.
	err := bindError("http", "0.0.0.0:80", syscall.EADDRINUSE)
	if !strings.Contains(err.Error(), "already holds this port") ||
		!strings.Contains(err.Error(), "public IP") {
		t.Fatalf("wildcard EADDRINUSE must hint at the public IP, got: %v", err)
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatal("bindError must wrap the underlying error")
	}

	// A specific-address bind gets the port hint but not the wildcard note.
	err = bindError("https", "203.0.113.10:443", syscall.EADDRINUSE)
	if strings.Contains(err.Error(), "0.0.0.0 overlaps") {
		t.Fatalf("specific-address bind must not mention the wildcard overlap: %v", err)
	}

	// Unrelated errors pass through without the port hint.
	err = bindError("http", "0.0.0.0:80", errors.New("permission denied"))
	if strings.Contains(err.Error(), "already holds this port") {
		t.Fatalf("non-EADDRINUSE must not get the port hint: %v", err)
	}
}
