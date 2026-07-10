package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ostap-mykhaylyak/gated/internal/config"
	"github.com/ostap-mykhaylyak/gated/internal/metrics"
	"github.com/ostap-mykhaylyak/gated/internal/status"
	"github.com/ostap-mykhaylyak/gated/internal/vhost"
	"github.com/ostap-mykhaylyak/gated/internal/waf"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

const testToken = "test-secret-token"

type fixture struct {
	handler http.Handler
	store   *vhost.Store
	dir     string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	global := "api:\n  enabled: true\n  token: " + testToken + "\n"
	if err := os.WriteFile(cfgPath, []byte(global), 0o640); err != nil {
		t.Fatal(err)
	}
	mgr, err := config.NewManager(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	vdir := t.TempDir()
	store := vhost.NewStore(vdir, discard)
	store.LoadAll(mgr.Get())
	t.Cleanup(store.Close)

	wafEngine := waf.New(t.TempDir(), discard, metrics.New())
	wafEngine.LoadAll()
	t.Cleanup(wafEngine.Close)
	collect := status.NewCollector("test", mgr, store, wafEngine, metrics.New(), t.TempDir())
	s := New(mgr, store, collect, discard, vdir)
	return &fixture{handler: s.Handler(), store: store, dir: vdir}
}

func (f *fixture) do(t *testing.T, method, path, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

const testVhost = `hosts: ["api-test.example"]
redirect_to_https: false
backends:
  - url: "http://127.0.0.1:8080"
`

func TestAuth(t *testing.T) {
	f := newFixture(t)
	if rec := f.do(t, "GET", "/status", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token must 401, got %d", rec.Code)
	}
	if rec := f.do(t, "GET", "/status", "", "wrong"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token must 401, got %d", rec.Code)
	}
	if rec := f.do(t, "GET", "/status", "", testToken); rec.Code != http.StatusOK {
		t.Fatalf("valid token must 200, got %d", rec.Code)
	}
	// /healthz is the only anonymous endpoint.
	if rec := f.do(t, "GET", "/healthz", "", ""); rec.Code == http.StatusUnauthorized {
		t.Fatal("/healthz must not require a token")
	}
}

func TestConfigRedacted(t *testing.T) {
	f := newFixture(t)
	rec := f.do(t, "GET", "/config", "", testToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, testToken) {
		t.Fatal("token leaked in GET /config")
	}
	if !strings.Contains(body, "***") {
		t.Fatal("token must be redacted as ***")
	}
}

func TestVhostLifecycle(t *testing.T) {
	f := newFixture(t)

	// Invalid body: 400 and nothing persisted.
	rec := f.do(t, "PUT", "/vhosts/app", "hosts: [x.test]\nbackends: []\n", testToken)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid vhost must 400, got %d: %s", rec.Code, rec.Body)
	}
	if _, err := os.Stat(filepath.Join(f.dir, "app.yaml")); err == nil {
		t.Fatal("invalid vhost must not be persisted")
	}

	// Create: 201, file on disk, store serving it.
	rec = f.do(t, "PUT", "/vhosts/app", testVhost, testToken)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create must 201, got %d: %s", rec.Code, rec.Body)
	}
	if f.store.Lookup("api-test.example") == nil {
		t.Fatal("store not reloaded after PUT")
	}

	// Read back the raw file.
	rec = f.do(t, "GET", "/vhosts/app", "", testToken)
	if rec.Code != http.StatusOK || rec.Body.String() != testVhost {
		t.Fatalf("GET vhost mismatch: %d %q", rec.Code, rec.Body.String())
	}

	// Update: 200, previous version archived.
	v2 := strings.Replace(testVhost, "8080", "9090", 1)
	if rec = f.do(t, "PUT", "/vhosts/app", v2, testToken); rec.Code != http.StatusOK {
		t.Fatalf("update must 200, got %d", rec.Code)
	}
	rec = f.do(t, "GET", "/vhosts/app/history", "", testToken)
	var hist struct {
		Versions []versionInfo `json:"versions"`
	}
	json.Unmarshal(rec.Body.Bytes(), &hist)
	if len(hist.Versions) != 1 {
		t.Fatalf("want 1 archived version, got %d", len(hist.Versions))
	}

	// Rollback to the archived version: content back to v1.
	if rec = f.do(t, "POST", "/vhosts/app/rollback", "", testToken); rec.Code != http.StatusOK {
		t.Fatalf("rollback must 200, got %d: %s", rec.Code, rec.Body)
	}
	rec = f.do(t, "GET", "/vhosts/app", "", testToken)
	if !strings.Contains(rec.Body.String(), "8080") {
		t.Fatal("rollback did not restore v1")
	}

	// Delete: file gone, host no longer served.
	if rec = f.do(t, "DELETE", "/vhosts/app", "", testToken); rec.Code != http.StatusOK {
		t.Fatalf("delete must 200, got %d", rec.Code)
	}
	if rec = f.do(t, "GET", "/vhosts/app", "", testToken); rec.Code != http.StatusNotFound {
		t.Fatalf("deleted vhost must 404, got %d", rec.Code)
	}
	if f.store.Lookup("api-test.example") != nil {
		t.Fatal("store still serving a deleted vhost")
	}
}

func TestVhostNameValidation(t *testing.T) {
	f := newFixture(t)
	// A traversal attempt is rejected either by our name check (400),
	// by routing (404/405) or by the mux's path cleaning (301/307
	// redirect, which never reaches a handler). Never a 2xx.
	for _, bad := range []string{".hidden", "a%2Fb", "..", ".history"} {
		rec := f.do(t, "PUT", "/vhosts/"+bad, testVhost, testToken)
		if rec.Code >= 200 && rec.Code < 300 {
			t.Fatalf("name %q must be rejected, got %d", bad, rec.Code)
		}
	}
	if _, err := os.Stat(filepath.Join(f.dir, ".hidden.yaml")); err == nil {
		t.Fatal("dot-prefixed vhost file must never be created")
	}
}

func TestStatusIncludesVhosts(t *testing.T) {
	f := newFixture(t)
	f.do(t, "PUT", "/vhosts/app", testVhost, testToken)

	rec := f.do(t, "GET", "/status", "", testToken)
	var snap status.Snapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	if snap.Vhosts == nil || snap.Vhosts.Files != 1 || snap.Vhosts.Hosts != 1 {
		t.Fatalf("vhosts section wrong: %+v", snap.Vhosts)
	}
	if len(snap.Vhosts.Items) != 1 || len(snap.Vhosts.Items[0].Backends) != 1 {
		t.Fatalf("vhost items wrong: %+v", snap.Vhosts.Items)
	}
}
