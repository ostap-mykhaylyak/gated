package proxy

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
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
	"github.com/ostap-mykhaylyak/gated/internal/session"
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
	wafEngine := waf.New(t.TempDir(), "", "", logs.WAF, m)
	wafEngine.LoadAll()
	t.Cleanup(func() { logs.Close(); store.Close(); wafEngine.Close() })

	pg, err := pages.New("")
	if err != nil {
		t.Fatal(err)
	}
	chal := challenge.NewManager("test-secret", 0, time.Minute)
	sess := session.NewManager("test-session-secret", time.Hour)
	return New(mgr, store, certs.New(t.TempDir()), wafEngine, nil, chal, sess, pg, m, logs)
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

func TestForwardedHTTPSHeaders(t *testing.T) {
	// The backend must see the request as HTTPS (X-Forwarded-Proto/Ssl/
	// Port), so a CMS behind gated does not force-redirect to https and
	// loop.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Proto", r.Header.Get("X-Forwarded-Proto"))
		w.Header().Set("X-Seen-Ssl", r.Header.Get("X-Forwarded-Ssl"))
		w.Header().Set("X-Seen-Port", r.Header.Get("X-Forwarded-Port"))
		io.WriteString(w, "ok")
	}))
	defer backend.Close()

	p := newTestProxy(t, "{}\n", map[string]string{"app.yaml": vhostYAML(backend.URL, "")})
	req := httptest.NewRequest("GET", "https://app.test/", nil)
	req.Host = "app.test"
	rec := httptest.NewRecorder()
	p.Handler(true).ServeHTTP(rec, req) // secure listener

	if got := rec.Header().Get("X-Seen-Proto"); got != "https" {
		t.Fatalf("X-Forwarded-Proto = %q, want https", got)
	}
	if got := rec.Header().Get("X-Seen-Ssl"); got != "on" {
		t.Fatalf("X-Forwarded-Ssl = %q, want on", got)
	}
	if got := rec.Header().Get("X-Seen-Port"); got != "443" {
		t.Fatalf("X-Forwarded-Port = %q, want 443", got)
	}
}

func TestRedirectLoopBreak(t *testing.T) {
	// A CMS that force-redirects its own host to http:// would loop; on
	// the HTTPS listener gated upgrades the Location to https://.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/self":
			http.Redirect(w, r, "http://app.test/dashboard", http.StatusFound)
		case "/ext":
			http.Redirect(w, r, "http://other.example/x", http.StatusFound)
		}
	}))
	defer backend.Close()

	p := newTestProxy(t, "{}\n", map[string]string{"app.yaml": vhostYAML(backend.URL, "")})

	// Own-host http redirect -> upgraded to https.
	req := httptest.NewRequest("GET", "https://app.test/self", nil)
	req.Host = "app.test"
	rec := httptest.NewRecorder()
	p.Handler(true).ServeHTTP(rec, req)
	if got := rec.Header().Get("Location"); got != "https://app.test/dashboard" {
		t.Fatalf("own-host redirect not upgraded: %q", got)
	}

	// Redirect to a different host is left untouched.
	req = httptest.NewRequest("GET", "https://app.test/ext", nil)
	req.Host = "app.test"
	rec = httptest.NewRecorder()
	p.Handler(true).ServeHTTP(rec, req)
	if got := rec.Header().Get("Location"); got != "http://other.example/x" {
		t.Fatalf("external redirect must not be rewritten: %q", got)
	}
}

func TestProtocolUpgrade(t *testing.T) {
	// A backend that speaks a trivial "echo" upgrade protocol: it
	// hijacks the connection, sends 101, then echoes bytes. This
	// exercises the same path as WebSocket (Connection: Upgrade +
	// bidirectional stream after hijack).
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "echo" {
			http.Error(w, "not an upgrade", http.StatusBadRequest)
			return
		}
		conn, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("backend hijack: %v", err)
			return
		}
		defer conn.Close()
		conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n"))
		io.Copy(conn, conn) // echo until the client closes
	}))
	defer backend.Close()

	// Serve gated through a real server so the connection can be
	// hijacked (a ResponseRecorder cannot).
	p := newTestProxy(t, "{}\n", map[string]string{"app.yaml": vhostYAML(backend.URL, "")})
	front := httptest.NewServer(p.Handler(false))
	defer front.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(front.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Raw upgrade handshake, Host routes to the vhost.
	fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: app.test\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")

	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "101") {
		t.Fatalf("expected 101 Switching Protocols, got %q (err %v)", status, err)
	}
	// Drain the rest of the response headers.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}

	// The tunnel is open: send bytes, expect them echoed back.
	fmt.Fprint(conn, "ping")
	buf := make([]byte, 4)
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("reading echo: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo mismatch: %q", buf)
	}
}

func TestHTTPSBackend(t *testing.T) {
	// A TLS backend with a self-signed cert on its own :443-style port.
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Proto", "https-backend")
		io.WriteString(w, "secure backend")
	}))
	defer backend.Close()

	// backend_tls.insecure_skip_verify lets gated accept the self-signed
	// cert; the backend URL is https:// (not 127.0.0.1:80).
	vh := "hosts: [\"app.test\"]\nredirect_to_https: false\n" +
		"backend_tls:\n  insecure_skip_verify: true\n" +
		"backends:\n  - url: \"" + backend.URL + "\"\n"
	p := newTestProxy(t, "{}\n", map[string]string{"app.yaml": vh})

	req := httptest.NewRequest("GET", "http://app.test/", nil)
	req.Host = "app.test"
	rec := httptest.NewRecorder()
	p.Handler(false).ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Body.String() != "secure backend" {
		t.Fatalf("https backend proxy failed: %d %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Proto") != "https-backend" {
		t.Fatal("response did not come from the TLS backend")
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
	wafEngine := waf.New(wdir, "", "", logs.WAF, m)
	wafEngine.LoadAll()
	t.Cleanup(func() { logs.Close(); store.Close(); wafEngine.Close() })

	pg, _ := pages.New("")
	chal := challenge.NewManager("test-secret", 0, time.Minute)
	sess := session.NewManager("test-session-secret", time.Hour)
	return New(mgr, store, certs.New(t.TempDir()), wafEngine, nil, chal, sess, pg, m, logs).Handler(true)
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

func TestSessionGateThroughProxy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "add-to-cart") {
			io.WriteString(w, "added")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, "<html>shop</html>")
	}))
	defer backend.Close()

	h := wafProxy(t, backend.URL, `
rules:
  - id: "wc-add-to-cart-session"
    action: block
    match:
      - field: query
        operator: contains
        patterns: ["add-to-cart="]
      - field: session
        operator: eq
        patterns: ["none"]
`)

	// 1. Direct add-to-cart with no prior visit: blocked (403).
	req := httptest.NewRequest("GET", "https://shop.test/?add-to-cart=42", nil)
	req.Host = "app.test"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("direct add-to-cart must be blocked, got %d", rec.Code)
	}

	// 2. Visit a normal HTML page: gated issues the visit cookie.
	visit := httptest.NewRequest("GET", "https://app.test/shop", nil)
	visit.Host = "app.test"
	vRec := httptest.NewRecorder()
	h.ServeHTTP(vRec, visit)
	var visitCookie *http.Cookie
	for _, ck := range vRec.Result().Cookies() {
		if ck.Name == "gated_visit" {
			visitCookie = ck
		}
	}
	if visitCookie == nil {
		t.Fatal("visit cookie not issued on HTML page load")
	}

	// 3. add-to-cart WITH the visit cookie: allowed through.
	req2 := httptest.NewRequest("GET", "https://app.test/?add-to-cart=42", nil)
	req2.Host = "app.test"
	req2.AddCookie(visitCookie)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != 200 || rec2.Body.String() != "added" {
		t.Fatalf("add-to-cart with prior visit must pass: %d %q", rec2.Code, rec2.Body.String())
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
