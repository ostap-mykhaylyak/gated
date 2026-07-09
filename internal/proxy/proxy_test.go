package proxy

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ostap-mykhaylyak/gated/internal/certs"
	"github.com/ostap-mykhaylyak/gated/internal/config"
	"github.com/ostap-mykhaylyak/gated/internal/logging"
	"github.com/ostap-mykhaylyak/gated/internal/metrics"
	"github.com/ostap-mykhaylyak/gated/internal/vhost"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

// newTestProxy wires a full Proxy against a temp config and vhost dir.
func newTestProxy(t *testing.T, globalYAML string, vhostFiles map[string]string) *Proxy {
	t.Helper()

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(globalYAML), 0o640); err != nil {
		t.Fatal(err)
	}
	mgr, err := config.NewManager(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	vdir := t.TempDir()
	for name, content := range vhostFiles {
		if err := os.WriteFile(filepath.Join(vdir, name), []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	store := vhost.NewStore(vdir, discard)
	store.LoadAll(mgr.Get())

	logs, err := logging.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logs.Close(); store.Close() })

	return New(mgr, store, certs.New(t.TempDir()), metrics.New(), logs)
}

func vhostYAML(backendURL string, extra string) string {
	return fmt.Sprintf("hosts: [\"app.test\"]\nredirect_to_https: false\nbackends:\n  - url: %q\n%s", backendURL, extra)
}

func TestProxyEndToEnd(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Got-XFF", r.Header.Get("X-Forwarded-For"))
		w.Header().Set("X-Got-Host", r.Host)
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "hello from backend")
	}))
	defer backend.Close()

	p := newTestProxy(t, "{}\n", map[string]string{"app.yaml": vhostYAML(backend.URL, "")})
	h := p.Handler(false)

	req := httptest.NewRequest("GET", "http://app.test/some/path", nil)
	req.Host = "app.test"
	req.RemoteAddr = "203.0.113.9:5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "hello from backend" {
		t.Fatalf("body = %q", rec.Body.String())
	}
	if got := rec.Header().Get("X-Got-XFF"); got != "203.0.113.9" {
		t.Fatalf("backend saw X-Forwarded-For = %q", got)
	}
	if got := rec.Header().Get("X-Got-Host"); got != "app.test" {
		t.Fatalf("backend saw Host = %q (original Host must be preserved)", got)
	}
}

func TestUnknownHost404(t *testing.T) {
	p := newTestProxy(t, "{}\n", nil)
	req := httptest.NewRequest("GET", "http://nobody.test/", nil)
	req.Host = "nobody.test"
	rec := httptest.NewRecorder()
	p.Handler(false).ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown host must 404, got %d", rec.Code)
	}
}

func TestRedirectToHTTPS(t *testing.T) {
	p := newTestProxy(t, "{}\n", map[string]string{
		"app.yaml": "hosts: [\"app.test\"]\nbackends:\n  - url: \"http://127.0.0.1:9\"\n", // redirect defaults to true
	})
	req := httptest.NewRequest("GET", "http://app.test/x?y=1", nil)
	req.Host = "app.test"
	rec := httptest.NewRecorder()
	p.Handler(false).ServeHTTP(rec, req)
	if rec.Code != http.StatusPermanentRedirect {
		t.Fatalf("want 308, got %d", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "https://app.test/x?y=1" {
		t.Fatalf("Location = %q", got)
	}
}

func TestACMEPassthrough(t *testing.T) {
	acme := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "token-for-"+r.URL.Path)
	}))
	defer acme.Close()

	global := fmt.Sprintf("acme:\n  passthrough: true\n  upstream: %q\n", acme.URL)
	p := newTestProxy(t, global, nil) // NO vhost: passthrough must work anyway

	req := httptest.NewRequest("GET", "http://new.test/.well-known/acme-challenge/abc", nil)
	req.Host = "new.test"
	rec := httptest.NewRecorder()
	p.Handler(false).ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Body.String() != "token-for-/.well-known/acme-challenge/abc" {
		t.Fatalf("acme passthrough broken: %d %q", rec.Code, rec.Body.String())
	}
}

func TestRetryOnDeadBackend(t *testing.T) {
	alive := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "alive")
	}))
	defer alive.Close()

	// First backend refuses connections (port 9, discard), second works.
	vh := fmt.Sprintf("hosts: [\"app.test\"]\nredirect_to_https: false\nbackends:\n  - url: \"http://127.0.0.1:9\"\n  - url: %q\n", alive.URL)
	p := newTestProxy(t, "{}\n", map[string]string{"app.yaml": vh})

	// round_robin will hit the dead one for half the requests: every
	// request must still succeed via retry.
	for i := 0; i < 4; i++ {
		req := httptest.NewRequest("GET", "http://app.test/", nil)
		req.Host = "app.test"
		rec := httptest.NewRecorder()
		p.Handler(false).ServeHTTP(rec, req)
		if rec.Code != 200 || rec.Body.String() != "alive" {
			t.Fatalf("attempt %d: %d %q", i, rec.Code, rec.Body.String())
		}
	}
}

func TestCompressionApplied(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		for i := 0; i < 200; i++ {
			io.WriteString(w, "lorem ipsum dolor sit amet ")
		}
	}))
	defer backend.Close()

	p := newTestProxy(t, "{}\n", map[string]string{"app.yaml": vhostYAML(backend.URL, "")})
	req := httptest.NewRequest("GET", "http://app.test/", nil)
	req.Host = "app.test"
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	p.Handler(false).ServeHTTP(rec, req)

	if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q", got)
	}
}
