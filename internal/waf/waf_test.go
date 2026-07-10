package waf

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ostap-mykhaylyak/gated/internal/metrics"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

func newEngine(t *testing.T, files map[string]string) *Engine {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	e := New(dir, discard, metrics.New())
	e.LoadAll()
	t.Cleanup(e.Close)
	return e
}

func req(method, target string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	return r
}

var block = Policy{Enabled: true}

func TestBlockSQLi(t *testing.T) {
	e := newEngine(t, map[string]string{"sqli.yaml": `
group: sqli
rules:
  - id: "942100"
    msg: "SQL injection"
    severity: critical
    action: block
    status: 403
    match:
      - field: arg
        operator: rx
        transform: [lowercase, urldecode]
        patterns: ['union\s+select', "or\\s+1=1"]
`})
	if e.Count() != 1 {
		t.Fatalf("want 1 rule, got %d", e.Count())
	}

	dec, _ := e.Evaluate(NewContext(req("GET", "/?q=1+UNION+SELECT+password"), "1.2.3.4", ""), block)
	if !dec.Block || dec.Status != 403 || dec.RuleID != "942100" {
		t.Fatalf("SQLi must be blocked: %+v", dec)
	}

	dec, _ = e.Evaluate(NewContext(req("GET", "/?q=hello"), "1.2.3.4", ""), block)
	if dec.Block {
		t.Fatal("benign request must pass")
	}
}

func TestDetectModeDoesNotBlock(t *testing.T) {
	e := newEngine(t, map[string]string{"x.yaml": `
rules:
  - id: "test"
    action: block
    match:
      - field: path
        operator: prefix
        patterns: ["/admin"]
`})
	dec, _ := e.Evaluate(NewContext(req("GET", "/admin"), "1.2.3.4", ""), Policy{Enabled: true, Detect: true})
	if dec.Block {
		t.Fatal("detect mode must never block")
	}
}

func TestAllowlistWins(t *testing.T) {
	e := newEngine(t, map[string]string{"x.yaml": `
rules:
  - id: "allow-health"
    action: allow
    match:
      - field: path
        operator: eq
        patterns: ["/healthz"]
  - id: "block-all-admin"
    action: block
    match:
      - field: path
        operator: prefix
        patterns: ["/health"]
`})
	// /healthz matches the block rule's prefix too, but allow wins.
	dec, _ := e.Evaluate(NewContext(req("GET", "/healthz"), "1.2.3.4", ""), block)
	if dec.Block {
		t.Fatal("allowlisted path must pass")
	}
	dec, _ = e.Evaluate(NewContext(req("GET", "/health-secret"), "1.2.3.4", ""), block)
	if !dec.Block {
		t.Fatal("non-allowlisted path must be blocked")
	}
}

func TestExcludePerVhost(t *testing.T) {
	e := newEngine(t, map[string]string{"x.yaml": `
rules:
  - id: "noisy"
    action: block
    match:
      - field: path
        operator: prefix
        patterns: ["/api"]
`})
	pol := Policy{Enabled: true, Exclude: map[string]bool{"noisy": true}}
	dec, _ := e.Evaluate(NewContext(req("GET", "/api/x"), "1.2.3.4", ""), pol)
	if dec.Block {
		t.Fatal("excluded rule must not fire for this vhost")
	}
}

func TestBodyInspection(t *testing.T) {
	e := newEngine(t, map[string]string{"x.yaml": `
rules:
  - id: "body-xss"
    action: block
    match:
      - field: body
        operator: contains
        patterns: ["<script"]
`})
	if !e.NeedsBody() {
		t.Fatal("engine must report it needs the body")
	}
	dec, _ := e.Evaluate(NewContext(req("POST", "/"), "1.2.3.4", "name=<script>alert(1)</script>"), block)
	if !dec.Block {
		t.Fatal("XSS in body must be blocked")
	}
}

func TestFail2banBanOnStatus(t *testing.T) {
	e := newEngine(t, map[string]string{"f2b.yaml": `
rules:
  - id: "login-bruteforce"
    msg: "too many failed logins"
    action: ban
    match:
      - field: path
        operator: eq
        patterns: ["/wp-login.php"]
    track:
      threshold: 3
      window: 10m
      ban_time: 1h
      on_status: [401, 403]
`})
	ip := "9.9.9.9"
	// Three failed logins (401) trip the ban.
	for i := 0; i < 3; i++ {
		_, pending := e.Evaluate(NewContext(req("POST", "/wp-login.php"), ip, ""), block)
		if len(pending) != 1 {
			t.Fatalf("attempt %d: want 1 pending status-tracked rule, got %d", i, len(pending))
		}
		e.ObserveResponse(pending, ip, 401)
	}
	if e.ActiveBans() != 1 {
		t.Fatalf("want 1 active ban, got %d", e.ActiveBans())
	}
	// The now-banned IP is blocked on its next request, anywhere.
	dec, _ := e.Evaluate(NewContext(req("GET", "/"), ip, ""), block)
	if !dec.Block || dec.RuleID != "@ban" {
		t.Fatalf("banned IP must be blocked: %+v", dec)
	}
	// A different IP is unaffected.
	dec, _ = e.Evaluate(NewContext(req("GET", "/"), "10.0.0.1", ""), block)
	if dec.Block {
		t.Fatal("unrelated IP must not be banned")
	}
}

func TestRequestFrequencyBan(t *testing.T) {
	e := newEngine(t, map[string]string{"f2b.yaml": `
rules:
  - id: "scan"
    action: ban
    match:
      - field: path
        operator: prefix
        patterns: ["/.env"]
    track:
      threshold: 2
      window: 1m
      ban_time: 30m
`})
	ip := "7.7.7.7"
	// First hit: matched, counted, not yet banned -> not blocked (ban action).
	dec, _ := e.Evaluate(NewContext(req("GET", "/.env"), ip, ""), block)
	if dec.Block {
		t.Fatal("first probe should not block yet")
	}
	// Second hit trips the threshold -> banned and blocked.
	dec, _ = e.Evaluate(NewContext(req("GET", "/.env.bak"), ip, ""), block)
	if !dec.Block {
		t.Fatal("second probe must trip the ban")
	}
}

func TestInvalidRuleSkipped(t *testing.T) {
	e := newEngine(t, map[string]string{"x.yaml": `
rules:
  - id: "good"
    action: block
    match:
      - field: path
        operator: eq
        patterns: ["/x"]
  - id: "bad-regex"
    action: block
    match:
      - field: path
        operator: rx
        patterns: ["("]
  - id: "unknown-field"
    action: block
    match:
      - field: nope
        patterns: ["y"]
`})
	// Only the valid rule survives; the file is not rejected wholesale.
	if e.Count() != 1 {
		t.Fatalf("want 1 valid rule loaded, got %d", e.Count())
	}
}

func TestNumericOperatorWithLength(t *testing.T) {
	e := newEngine(t, map[string]string{"x.yaml": `
rules:
  - id: "long-ua"
    action: block
    match:
      - field: header
        name: User-Agent
        operator: gt
        transform: [length]
        patterns: ["10"]
`})
	r := req("GET", "/")
	r.Header.Set("User-Agent", "short")
	if dec, _ := e.Evaluate(NewContext(r, "1.1.1.1", ""), block); dec.Block {
		t.Fatal("short UA must pass")
	}
	r = req("GET", "/")
	r.Header.Set("User-Agent", strings.Repeat("A", 50))
	if dec, _ := e.Evaluate(NewContext(r, "1.1.1.1", ""), block); !dec.Block {
		t.Fatal("long UA must be blocked")
	}
}

func TestGeoIPCountryBlock(t *testing.T) {
	e := newEngine(t, map[string]string{"geo.yaml": `
rules:
  - id: "geo-block-cn"
    msg: "Blocked country"
    action: block
    status: 403
    match:
      - field: country
        operator: eq
        patterns: ["CN", "RU"]
`})
	if !e.NeedsGeo() {
		t.Fatal("engine must report it needs geo resolution")
	}

	// Client resolved to CN: blocked.
	ctx := NewContext(req("GET", "/"), "1.2.3.4", "")
	ctx.SetGeo("CN", "AS", "AS4134")
	if dec, _ := e.Evaluate(ctx, block); !dec.Block || dec.Status != 403 {
		t.Fatalf("CN client must be blocked: %+v", dec)
	}

	// Client resolved to IT: passes.
	ctx = NewContext(req("GET", "/"), "5.6.7.8", "")
	ctx.SetGeo("IT", "EU", "AS3269")
	if dec, _ := e.Evaluate(ctx, block); dec.Block {
		t.Fatal("IT client must pass")
	}

	// Unknown country (no geo set / db miss): the eq rule does not match.
	ctx = NewContext(req("GET", "/"), "9.9.9.9", "")
	if dec, _ := e.Evaluate(ctx, block); dec.Block {
		t.Fatal("unknown country must not match an eq rule")
	}
}

func TestGeoIPAllowlistNegate(t *testing.T) {
	// "block every country NOT in the allowlist" via negate.
	e := newEngine(t, map[string]string{"geo.yaml": `
rules:
  - id: "geo-allow-only"
    action: block
    match:
      - field: country
        operator: eq
        negate: true
        patterns: ["IT", "US"]
`})
	ctx := NewContext(req("GET", "/"), "1.1.1.1", "")
	ctx.SetGeo("IT", "EU", "")
	if dec, _ := e.Evaluate(ctx, block); dec.Block {
		t.Fatal("allowlisted country must pass")
	}
	ctx = NewContext(req("GET", "/"), "1.1.1.1", "")
	ctx.SetGeo("CN", "AS", "")
	if dec, _ := e.Evaluate(ctx, block); !dec.Block {
		t.Fatal("non-allowlisted country must be blocked")
	}
}

func TestChallengeAction(t *testing.T) {
	e := newEngine(t, map[string]string{"x.yaml": `
rules:
  - id: "challenge-us"
    action: challenge
    match:
      - field: country
        operator: eq
        patterns: ["US"]
`})
	ctx := NewContext(req("GET", "/"), "1.2.3.4", "")
	ctx.SetGeo("US", "NA", "")
	dec, _ := e.Evaluate(ctx, block)
	if !dec.Challenge || dec.Block {
		t.Fatalf("US must be challenged, not blocked: %+v", dec)
	}

	// Non-US: no challenge.
	ctx = NewContext(req("GET", "/"), "1.2.3.4", "")
	ctx.SetGeo("IT", "EU", "")
	if dec, _ := e.Evaluate(ctx, block); dec.Challenge || dec.Block {
		t.Fatalf("IT must pass: %+v", dec)
	}
}

func TestBlockWinsOverChallenge(t *testing.T) {
	// A block rule and a challenge rule both match; block must win.
	e := newEngine(t, map[string]string{"x.yaml": `
rules:
  - id: "challenge-all"
    action: challenge
    match:
      - field: path
        operator: prefix
        patterns: ["/"]
  - id: "block-admin"
    action: block
    match:
      - field: path
        operator: prefix
        patterns: ["/admin"]
`})
	dec, _ := e.Evaluate(NewContext(req("GET", "/admin"), "1.2.3.4", ""), block)
	if !dec.Block || dec.RuleID != "block-admin" {
		t.Fatalf("block must win over challenge: %+v", dec)
	}
	// A non-admin path only matches the challenge rule.
	dec, _ = e.Evaluate(NewContext(req("GET", "/home"), "1.2.3.4", ""), block)
	if !dec.Challenge || dec.Block {
		t.Fatalf("non-admin path must be challenged: %+v", dec)
	}
}

func TestChallengeDetectMode(t *testing.T) {
	e := newEngine(t, map[string]string{"x.yaml": `
rules:
  - id: "challenge-all"
    action: challenge
    match:
      - field: path
        operator: prefix
        patterns: ["/"]
`})
	dec, _ := e.Evaluate(NewContext(req("GET", "/"), "1.2.3.4", ""), Policy{Enabled: true, Detect: true})
	if dec.Challenge || dec.Block {
		t.Fatal("detect mode must not enforce a challenge")
	}
}

func TestSessionField(t *testing.T) {
	// WooCommerce add-to-cart requires a prior visit.
	e := newEngine(t, map[string]string{"x.yaml": `
rules:
  - id: "wc-add-to-cart-session"
    msg: "add-to-cart without session"
    action: block
    match:
      - field: query
        operator: contains
        patterns: ["add-to-cart="]
      - field: session
        operator: eq
        patterns: ["none"]
`})
	if !e.NeedsSession() {
		t.Fatal("engine must report it needs the session field")
	}

	// Direct add-to-cart with no session: blocked.
	ctx := NewContext(req("GET", "/?add-to-cart=99"), "1.2.3.4", "")
	ctx.SetSession(false)
	if dec, _ := e.Evaluate(ctx, block); !dec.Block {
		t.Fatal("add-to-cart without a prior visit must be blocked")
	}

	// Same request with a valid visit: passes.
	ctx = NewContext(req("GET", "/?add-to-cart=99"), "1.2.3.4", "")
	ctx.SetSession(true)
	if dec, _ := e.Evaluate(ctx, block); dec.Block {
		t.Fatal("add-to-cart with a prior visit must pass")
	}

	// A normal page load (no add-to-cart) is never affected.
	ctx = NewContext(req("GET", "/shop"), "1.2.3.4", "")
	ctx.SetSession(false)
	if dec, _ := e.Evaluate(ctx, block); dec.Block {
		t.Fatal("normal navigation must not be blocked")
	}
}

func TestSessionFailsOpenWhenUnresolved(t *testing.T) {
	// If the session field is never resolved (subsystem inactive), the
	// "none" rule must not fire — fail open, don't block everything.
	e := newEngine(t, map[string]string{"x.yaml": `
rules:
  - id: "needs-session"
    action: block
    match:
      - field: session
        operator: eq
        patterns: ["none"]
`})
	ctx := NewContext(req("GET", "/?add-to-cart=1"), "1.2.3.4", "") // SetSession not called
	if dec, _ := e.Evaluate(ctx, block); dec.Block {
		t.Fatal("unresolved session must fail open (not block)")
	}
}

func TestShippedExampleRulesLoad(t *testing.T) {
	// The rules shipped in skel must always compile against the engine.
	src := filepath.Join("..", "bootstrap", "skel", "etc", "gated", "waf")
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	loaded := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dir, e.Name()), data, 0o640)
		loaded++
	}
	eng := New(dir, discard, metrics.New())
	eng.LoadAll()
	t.Cleanup(eng.Close)
	if loaded == 0 || eng.Count() == 0 {
		t.Fatalf("shipped example rules must load: files=%d rules=%d", loaded, eng.Count())
	}
}
