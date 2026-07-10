package geoip

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestMissingDatabaseIsGraceful(t *testing.T) {
	// A path that does not exist must not crash New/Lookup; it just
	// yields an unloaded resolver returning empty results, so geo WAF
	// rules simply never fire until the database appears.
	r := New(filepath.Join(t.TempDir(), "nope.mmdb"), "", discard)
	defer r.Close()

	if r.Loaded() {
		t.Fatal("resolver must not report loaded without a database")
	}
	g := r.Lookup("8.8.8.8")
	if g.Country != "" || g.Continent != "" || g.ASN != "" {
		t.Fatalf("missing db must yield empty Geo, got %+v", g)
	}
}

func TestLookupInvalidIP(t *testing.T) {
	r := New(filepath.Join(t.TempDir(), "nope.mmdb"), "", discard)
	defer r.Close()
	if g := r.Lookup("not-an-ip"); g != (Geo{}) {
		t.Fatalf("invalid IP must yield empty Geo, got %+v", g)
	}
}

func TestNilResolverLoaded(t *testing.T) {
	// Disabled geoip is represented by a nil *Resolver passed through
	// the status GeoIPProvider interface: Loaded must be safe on it.
	var r *Resolver
	if r.Loaded() {
		t.Fatal("nil resolver must report not loaded")
	}
}
