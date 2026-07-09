package balancer

import (
	"net/http/httptest"
	"testing"
	"time"
)

func testConf(strategy string, backends ...BackendConf) Conf {
	return Conf{
		Strategy: strategy,
		Backends: backends,
		Health:   HealthConf{MaxFails: 3, Cooldown: 30 * time.Second},
	}
}

func pickN(t *testing.T, p *Pool, n int) map[string]int {
	t.Helper()
	req := httptest.NewRequest("GET", "/", nil)
	got := map[string]int{}
	for i := 0; i < n; i++ {
		b := p.Pick(req, "203.0.113.7")
		if b == nil {
			t.Fatal("Pick returned nil with available backends")
		}
		got[b.URL.String()]++
	}
	return got
}

func TestRoundRobinWeighted(t *testing.T) {
	p, err := New(testConf("round_robin",
		BackendConf{URL: "http://a:1", Weight: 2},
		BackendConf{URL: "http://b:1", Weight: 1},
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := pickN(t, p, 30)
	if got["http://a:1"] != 20 || got["http://b:1"] != 10 {
		t.Fatalf("weighted distribution broken: %v", got)
	}
}

func TestBackupFailover(t *testing.T) {
	p, err := New(testConf("round_robin",
		BackendConf{URL: "http://primary:1"},
		BackendConf{URL: "http://backup:1", Backup: true},
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/", nil)

	b := p.Pick(req, "ip")
	if b.URL.Host != "primary:1" {
		t.Fatalf("backup used while primary is up: %s", b.URL)
	}
	// MaxFails=3 consecutive failures put the primary in cooldown.
	for i := 0; i < 3; i++ {
		p.Report(b, false)
	}
	if b.Available() {
		t.Fatal("primary must be down after max_fails")
	}
	if got := p.Pick(req, "ip"); got.URL.Host != "backup:1" {
		t.Fatalf("backup not used with primary down: %s", got.URL)
	}
}

func TestLeastConn(t *testing.T) {
	p, err := New(testConf("least_conn",
		BackendConf{URL: "http://a:1"},
		BackendConf{URL: "http://b:1"},
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/", nil)
	a := p.Backends()[0]
	a.Acquire()
	defer a.Release()
	if got := p.Pick(req, "ip"); got.URL.Host != "b:1" {
		t.Fatalf("least_conn must avoid the busy backend, picked %s", got.URL)
	}
}

func TestIPHashStable(t *testing.T) {
	p, err := New(testConf("ip_hash",
		BackendConf{URL: "http://a:1"},
		BackendConf{URL: "http://b:1"},
		BackendConf{URL: "http://c:1"},
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/", nil)
	first := p.Pick(req, "198.51.100.23")
	for i := 0; i < 10; i++ {
		if got := p.Pick(req, "198.51.100.23"); got != first {
			t.Fatal("ip_hash affinity not stable")
		}
	}
}

func TestStickyCookieWins(t *testing.T) {
	conf := testConf("round_robin",
		BackendConf{URL: "http://a:1"},
		BackendConf{URL: "http://b:1"},
	)
	conf.Sticky = StickyConf{Enabled: true, Cookie: "aff", TTL: time.Hour}
	p, err := New(conf, nil)
	if err != nil {
		t.Fatal(err)
	}
	target := p.Backends()[1]
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Cookie", "aff="+target.ID)
	for i := 0; i < 5; i++ {
		if got := p.Pick(req, "ip"); got != target {
			t.Fatal("sticky cookie must pin the backend")
		}
	}
}

func TestStateCarriedAcrossRebuild(t *testing.T) {
	conf := testConf("round_robin",
		BackendConf{URL: "http://a:1"},
		BackendConf{URL: "http://b:1"},
	)
	p1, err := New(conf, nil)
	if err != nil {
		t.Fatal(err)
	}
	a1 := p1.Backends()[0]
	for i := 0; i < 3; i++ {
		p1.Report(a1, false) // a goes down
	}
	a1.Acquire() // one request in flight on the old pool object

	p2, err := New(conf, p1)
	if err != nil {
		t.Fatal(err)
	}
	a2 := p2.Backends()[0]
	if a2.Available() {
		t.Fatal("down state lost across rebuild")
	}
	if a2.Active() != 1 {
		t.Fatalf("in-flight counter lost across rebuild: %d", a2.Active())
	}
	// The old object releases AFTER the rebuild: the shared state must
	// see it (this is why state is a shared pointer, not a copy).
	a1.Release()
	if a2.Active() != 0 {
		t.Fatalf("release on old object not visible on new pool: %d", a2.Active())
	}
}
