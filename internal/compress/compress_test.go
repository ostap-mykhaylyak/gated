package compress

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNegotiate(t *testing.T) {
	algos := []string{"zstd", "br", "gzip"}
	cases := []struct {
		ae   string
		want string
	}{
		{"gzip, deflate, br", "br"},
		{"gzip", "gzip"},
		{"gzip;q=0, br", "br"},
		{"identity", ""},
		{"", ""},
		{"zstd;q=0.5, gzip", "zstd"}, // preference order is the server's
	}
	for _, c := range cases {
		if got := Negotiate(c.ae, algos); got != c.want {
			t.Errorf("Negotiate(%q) = %q, want %q", c.ae, got, c.want)
		}
	}
}

func TestGzipRoundTrip(t *testing.T) {
	body := strings.Repeat("hello gated ", 200)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()

	w, finish := Wrap(rec, req, Settings{Enabled: true, Algorithms: []string{"gzip"}, MinSize: 64})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, body)
	finish()

	if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q", got)
	}
	zr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != body {
		t.Fatal("gzip round trip corrupted the body")
	}
}

func TestSkipSmallAndBinary(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")

	// Small response (declared Content-Length under min_size).
	rec := httptest.NewRecorder()
	w, finish := Wrap(rec, req, Settings{Enabled: true, Algorithms: []string{"gzip"}, MinSize: 1024})
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Length", "5")
	io.WriteString(w, "small")
	finish()
	if rec.Header().Get("Content-Encoding") != "" {
		t.Fatal("small response must not be compressed")
	}

	// Incompressible content type.
	rec = httptest.NewRecorder()
	w, finish = Wrap(rec, req, Settings{Enabled: true, Algorithms: []string{"gzip"}, MinSize: 0})
	w.Header().Set("Content-Type", "image/png")
	io.WriteString(w, "PNGDATA")
	finish()
	if rec.Header().Get("Content-Encoding") != "" {
		t.Fatal("binary response must not be compressed")
	}

	// Already encoded by the backend.
	rec = httptest.NewRecorder()
	w, finish = Wrap(rec, req, Settings{Enabled: true, Algorithms: []string{"gzip"}, MinSize: 0})
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Encoding", "br")
	io.WriteString(w, "already")
	finish()
	if got := rec.Header().Get("Content-Encoding"); got != "br" {
		t.Fatalf("pre-encoded response must pass through, got %q", got)
	}
}

func TestAddVaryIdempotent(t *testing.T) {
	h := http.Header{}
	AddVary(h, "Accept-Encoding")
	AddVary(h, "Accept-Encoding") // repeat: must not duplicate
	AddVary(h, "accept-encoding") // case-insensitive: still no duplicate
	if got := h.Values("Vary"); len(got) != 1 || got[0] != "Accept-Encoding" {
		t.Fatalf("Vary = %v, want a single Accept-Encoding", got)
	}

	// A backend that already listed the token (with others) is respected.
	h2 := http.Header{}
	h2.Set("Vary", "Cookie, Accept-Encoding")
	AddVary(h2, "Accept-Encoding")
	if got := h2.Values("Vary"); len(got) != 1 {
		t.Fatalf("must not add a duplicate line, got %v", got)
	}

	// A different token is appended.
	AddVary(h2, "Origin")
	if len(h2.Values("Vary")) != 2 {
		t.Fatalf("Origin must be added, got %v", h2.Values("Vary"))
	}
}
