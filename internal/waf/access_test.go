package waf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ostap-mykhaylyak/gated/internal/metrics"
)

// accessEngine builds an engine with allow/deny dirs seeded from the
// given file map (name -> content), plus optional YAML rules.
func accessEngine(t *testing.T, allow, deny map[string]string, rules string) *Engine {
	t.Helper()
	rulesDir := t.TempDir()
	if rules != "" {
		os.WriteFile(filepath.Join(rulesDir, "r.yaml"), []byte(rules), 0o640)
	}
	allowDir := t.TempDir()
	for n, c := range allow {
		os.WriteFile(filepath.Join(allowDir, n), []byte(c), 0o640)
	}
	denyDir := t.TempDir()
	for n, c := range deny {
		os.WriteFile(filepath.Join(denyDir, n), []byte(c), 0o640)
	}
	e := New(rulesDir, allowDir, denyDir, discard, metrics.New())
	e.LoadAll()
	e.LoadAccess()
	t.Cleanup(e.Close)
	return e
}

func ctxIP(ip string) *evalCtx { return NewContext(req("GET", "/"), ip, "") }

func TestBlacklistIPAndCIDR(t *testing.T) {
	e := accessEngine(t, nil, map[string]string{
		"bad.ips": "192.0.2.66\n198.51.100.0/24  # a whole range\n2001:db8::/32\n",
	}, "")

	for _, ip := range []string{"192.0.2.66", "198.51.100.17", "2001:db8::5"} {
		if dec, _ := e.Evaluate(ctxIP(ip), block); !dec.Block || dec.RuleID != "@blacklist" {
			t.Fatalf("%s must be blacklisted: %+v", ip, dec)
		}
	}
	// An address outside every range passes.
	if dec, _ := e.Evaluate(ctxIP("203.0.113.5"), block); dec.Block {
		t.Fatal("unlisted IP must pass")
	}
	aIP, dIP, _, _ := e.AccessCounts()
	if aIP != 0 || dIP != 3 {
		t.Fatalf("counts wrong: allowIP=%d denyIP=%d", aIP, dIP)
	}
}

func TestWhitelistWinsOverBlacklist(t *testing.T) {
	e := accessEngine(t,
		map[string]string{"ok.ips": "203.0.113.9\n"},
		map[string]string{"bad.ips": "203.0.113.0/24\n"}, // covers .9 too
		"")
	// .9 is in both lists: whitelist wins.
	if dec, _ := e.Evaluate(ctxIP("203.0.113.9"), block); dec.Block {
		t.Fatal("whitelisted IP must win over the blacklist")
	}
	// .10 is only blacklisted.
	if dec, _ := e.Evaluate(ctxIP("203.0.113.10"), block); !dec.Block {
		t.Fatal("blacklisted (non-whitelisted) IP must be blocked")
	}
}

func TestWhitelistBypassesRules(t *testing.T) {
	// A blocking rule that would fire for everyone, plus a whitelist.
	e := accessEngine(t,
		map[string]string{"ok.ips": "10.0.0.1\n"}, nil, `
rules:
  - id: "block-all"
    action: block
    match:
      - field: path
        operator: prefix
        patterns: ["/"]
`)
	if dec, _ := e.Evaluate(ctxIP("10.0.0.1"), block); dec.Block {
		t.Fatal("whitelisted IP must bypass all rules")
	}
	if dec, _ := e.Evaluate(ctxIP("10.0.0.2"), block); !dec.Block {
		t.Fatal("non-whitelisted IP must still hit the rule")
	}
}

func TestASNAccessLists(t *testing.T) {
	e := accessEngine(t,
		map[string]string{"good.asn": "AS15169  # Google\n"},
		map[string]string{"bad.asn": "14061\nAS16509\n"}, "")

	if !e.NeedsGeo() {
		t.Fatal("ASN lists must make the engine require geo/ASN resolution")
	}

	// Whitelisted ASN bypasses.
	c := ctxIP("8.8.8.8")
	c.SetGeo("US", "NA", "AS15169")
	if dec, _ := e.Evaluate(c, block); dec.Block {
		t.Fatal("whitelisted ASN must pass")
	}
	// Blacklisted ASN blocked.
	c = ctxIP("1.2.3.4")
	c.SetGeo("US", "NA", "AS14061")
	if dec, _ := e.Evaluate(c, block); !dec.Block || dec.RuleID != "@blacklist" {
		t.Fatal("blacklisted ASN must be blocked")
	}
	// Unlisted ASN passes.
	c = ctxIP("5.6.7.8")
	c.SetGeo("IT", "EU", "AS3269")
	if dec, _ := e.Evaluate(c, block); dec.Block {
		t.Fatal("unlisted ASN must pass")
	}
	_, _, aASN, dASN := e.AccessCounts()
	if aASN != 1 || dASN != 2 {
		t.Fatalf("asn counts wrong: allow=%d deny=%d", aASN, dASN)
	}
}

func TestAccessInvalidEntriesSkipped(t *testing.T) {
	e := accessEngine(t, nil, map[string]string{
		"bad.ips": "not-an-ip\n192.0.2.5\n999.999.0.0/8\n",
		"bad.asn": "hello\nAS42\n",
	}, "")
	_, dIP, _, dASN := e.AccessCounts()
	if dIP != 1 {
		t.Fatalf("only the valid IP must load, got %d", dIP)
	}
	if dASN != 1 {
		t.Fatalf("only the valid ASN must load, got %d", dASN)
	}
}

func TestShippedAccessExamplesLoad(t *testing.T) {
	// The shipped example.ips/.asn are all comments: they must parse to
	// empty lists without warnings-as-errors.
	base := filepath.Join("..", "bootstrap", "skel", "etc", "gated")
	e := New(t.TempDir(), filepath.Join(base, "allow"), filepath.Join(base, "deny"), discard, metrics.New())
	e.LoadAccess()
	t.Cleanup(e.Close)
	if aIP, dIP, aASN, dASN := e.AccessCounts(); aIP+dIP+aASN+dASN != 0 {
		t.Fatalf("shipped examples must be empty (all commented): %d/%d/%d/%d", aIP, dIP, aASN, dASN)
	}
}
