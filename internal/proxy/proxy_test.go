package proxy

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ostap-mykhaylyak/gated/internal/certs"
	"github.com/ostap-mykhaylyak/gated/internal/challenge"
	"github.com/ostap-mykhaylyak/gated/internal/config"
	"github.com/ostap-mykhaylyak/gated/internal/logging"
	"github.com/ostap-mykhaylyak/gated/internal/metrics"
	"github.com/ostap-mykhaylyak/gated/internal/pages"
	"github.com/ostap-mykhaylyak/gated/internal/vhost"
	"github.com/ostap-mykhaylyak/gated/internal/waf"
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
	m := metrics.New()
	wafEngine := waf.New(t.TempDir(), logs.WAF, m)
	wafEngine.LoadAll()
	t.Cleanup(func() { logs.Close(); store.Close(); wafEngine.Close() })

	pg, err := pages.New("")
	if err != nil {
		t.Fatal(err)
	}
	chal := challenge.NewManager("test-secret", 0, time.Minute)
	return New(mgr, store, certs.New(t.TempDir()), wafEngine, nil, chal, pg, m, logs)
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

// wafProxy wires a proxy with the WAF enabled globally and one rule
// file, plus one vhost that inherits the global WAF policy.
func wafProxy(t *testing.T, backendURL, wafRules string) http.Handler {
	t.Helper()

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	wdir := t.TempDir()
	if err := os.WriteFile(filepath.Join(wdir, "rules.yaml"), []byte(wafRules), 0o640); err != nil {
		t.Fatal(err)
	}
	global := "waf:\n  enabled: true\n  mode: block\n  rules_dir: " + wdir + "\n"
	if err := os.WriteFile(cfgPath, []byte(global), 0o640); err != nil {
		t.Fatal(err)
	}
	mgr, err := config.NewManager(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	vdir := t.TempDir()
	os.WriteFile(filepath.Join(vdir, "app.yaml"), []byte(vhostYAML(backendURL, "")), 0o640)
	store := vhost.NewStore(vdir, discard)
	store.LoadAll(mgr.Get())

	logs, _ := logging.Open(t.TempDir())
	m := metrics.New()
	wafEngine := waf.New(wdir, logs.WAF, m)
	wafEngine.LoadAll()
	t.Cleanup(func() { logs.Close(); store.Close(); wafEngine.Close() })

	pg, _ := pages.New("")
	chal := challenge.NewManager("test-secret", 0, time.Minute)
	return New(mgr, store, certs.New(t.TempDir()), wafEngine, nil, chal, pg, m, logs).Handler(true)
}

func TestWAFBlocksThroughProxy(t *testing.T) {
	hits := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		io.WriteString(w, "reached backend")
	}))
	defer backend.Close()

	h := wafProxy(t, backend.URL, `
rules:
  - id: "942100"
    msg: "SQLi"
    action: block
    status: 403
    match:
      - field: arg
        operator: rx
        transform: [lowercase, urldecode]
        patterns: ['union\s+select']
`)

	// Malicious request: blocked with 403, backend never reached.
	req := httptest.NewRequest("GET", "https://app.test/?q=1+UNION+SELECT", nil)
	req.Host = "app.test"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("malicious request must be 403, got %d", rec.Code)
	}
	if hits != 0 {
		t.Fatal("backend must not be reached for a blocked request")
	}

	// Clean request: passes through to the backend.
	req = httptest.NewRequest("GET", "https://app.test/?q=hello", nil)
	req.Host = "app.test"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Body.String() != "reached backend" {
		t.Fatalf("clean request must pass: %d %q", rec.Code, rec.Body.String())
	}
}

func TestWAFBodyBlockThroughProxy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prove the body is still intact for the backend after WAF buffering.
		b, _ := io.ReadAll(r.Body)
		io.WriteString(w, "got:"+string(b))
	}))
	defer backend.Close()

	h := wafProxy(t, backend.URL, `
rules:
  - id: "body-xss"
    action: block
    match:
      - field: body
        operator: contains
        patterns: ["<script"]
`)

	// Clean POST body reaches the backend unchanged (buffer + replay).
	req := httptest.NewRequest("POST", "https://app.test/submit", strings.NewReader("name=alice"))
	req.Host = "app.test"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Body.String() != "got:name=alice" {
		t.Fatalf("clean body must reach backend intact: %d %q", rec.Code, rec.Body.String())
	}

	// Malicious body blocked.
	req = httptest.NewRequest("POST", "https://app.test/submit", strings.NewReader("c=<script>x</script>"))
	req.Host = "app.test"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("malicious body must be 403, got %d", rec.Code)
	}
}

func TestChallengeFlowThroughProxy(t *testing.T) {
	reached := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached++
		io.WriteString(w, "backend")
	}))
	defer backend.Close()

	h := wafProxy(t, backend.URL, `
rules:
  - id: "geo-challenge-us"
    action: challenge
    match:
      - field: path
        operator: prefix
        patterns: ["/"]
`)

	// First request with no clearance: served the interstitial (403),
	// backend not reached.
	req := httptest.NewRequest("GET", "https://app.test/", nil)
	req.Host = "app.test"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("challenge must return 403 interstitial, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Checking your browser") {
		t.Fatal("challenge page not served")
	}
	if reached != 0 {
		t.Fatal("backend must not be reached before clearance")
	}
	if rec.Header().Get("Gated-Ray-Id") == "" {
		t.Fatal("Ray ID header missing")
	}

	// Solve the challenge: POST the token to /.gated/challenge and get
	// the clearance cookie.
	token := extractToken(t, rec.Body.String())
	solve := httptest.NewRequest("POST", "https://app.test/.gated/challenge",
		strings.NewReader(`{"token":"`+token+`","nonce":""}`))
	solve.Host = "app.test"
	solve.Header.Set("Content-Type", "application/json")
	sRec := httptest.NewRecorder()
	h.ServeHTTP(sRec, solve)
	if sRec.Code != 200 {
		t.Fatalf("challenge solve must succeed, got %d: %s", sRec.Code, sRec.Body.String())
	}
	cookies := sRec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no clearance cookie issued")
	}

	// Retry with the clearance cookie: passes through to the backend.
	req2 := httptest.NewRequest("GET", "https://app.test/", nil)
	req2.Host = "app.test"
	for _, ck := range cookies {
		req2.AddCookie(ck)
	}
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != 200 || rec2.Body.String() != "backend" {
		t.Fatalf("cleared client must reach backend: %d %q", rec2.Code, rec2.Body.String())
	}
}

// extractToken pulls the token literal out of the challenge page JS
// (var token = "....";).
func extractToken(t *testing.T, body string) string {
	t.Helper()
	const marker = "var token = "
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatal("token not found in challenge page")
	}
	rest := body[i+len(marker):]
	start := strings.IndexByte(rest, '"')
	end := strings.IndexByte(rest[start+1:], '"')
	return rest[start+1 : start+1+end]
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
