// Package geoip resolves a client IP to its country, continent and ASN
// using MaxMind .mmdb databases from the conventional Ubuntu location
// (/usr/share/GeoIP/GeoLite2-*.mmdb, kept fresh by geoipupdate).
//
// Databases are hot-swapped: a background poller reopens a file when
// its mtime changes (geoipupdate replaces it atomically), so a weekly
// refresh is picked up without a restart. A missing database is not
// fatal: lookups return an empty Geo and the matching WAF rules simply
// never fire.
package geoip

import (
	"log/slog"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// Geo is the resolved location of an IP. Empty fields mean "unknown"
// (database missing, private IP, or not found).
type Geo struct {
	Country   string // ISO 3166-1 alpha-2, e.g. "CN"
	Continent string // e.g. "AS"
	ASN       string // e.g. "AS15169"
}

// readers is the atomically-swapped pair of open databases.
type readers struct {
	country *maxminddb.Reader
	asn     *maxminddb.Reader
}

// Resolver holds the open databases and reloads them on change.
type Resolver struct {
	countryPath string
	asnPath     string
	log         *slog.Logger

	cur  atomic.Pointer[readers]
	mu   sync.Mutex
	cMod time.Time
	aMod time.Time

	stop chan struct{}
	once sync.Once
}

// New opens the databases at the given paths (asnPath may be empty).
// It always returns a usable Resolver, even if a file is missing.
func New(countryPath, asnPath string, log *slog.Logger) *Resolver {
	r := &Resolver{countryPath: countryPath, asnPath: asnPath, log: log, stop: make(chan struct{})}
	r.cur.Store(&readers{})
	r.reload()
	return r
}

// Loaded reports whether the country database is currently open. Safe
// on a nil receiver (geoip disabled).
func (r *Resolver) Loaded() bool { return r != nil && r.cur.Load().country != nil }

// Lookup resolves ipStr. Never errors: unknown pieces are left empty.
func (r *Resolver) Lookup(ipStr string) Geo {
	rd := r.cur.Load()
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return Geo{}
	}
	var g Geo
	if rd.country != nil {
		var rec struct {
			Country struct {
				ISOCode string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
			Continent struct {
				Code string `maxminddb:"code"`
			} `maxminddb:"continent"`
		}
		if err := rd.country.Lookup(ip, &rec); err == nil {
			g.Country = rec.Country.ISOCode
			g.Continent = rec.Continent.Code
		}
	}
	if rd.asn != nil {
		var rec struct {
			Number uint `maxminddb:"autonomous_system_number"`
		}
		if err := rd.asn.Lookup(ip, &rec); err == nil && rec.Number != 0 {
			g.ASN = "AS" + strconv.FormatUint(uint64(rec.Number), 10)
		}
	}
	return g
}

// Watch reloads the databases when their files change, until stop.
func (r *Resolver) Watch(stop <-chan struct{}) {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-r.stop:
				return
			case <-t.C:
				r.reload()
			}
		}
	}()
}

// reload opens any database whose mtime changed and swaps the pair
// atomically. Old readers are closed after a grace period so in-flight
// lookups holding the previous pointer are unaffected.
func (r *Resolver) reload() {
	r.mu.Lock()
	defer r.mu.Unlock()

	old := r.cur.Load()
	next := &readers{country: old.country, asn: old.asn}
	changed := false

	if rd, mod, ok := r.maybeOpen(r.countryPath, r.cMod, "country"); ok {
		next.country, r.cMod, changed = rd, mod, true
	}
	if r.asnPath != "" {
		if rd, mod, ok := r.maybeOpen(r.asnPath, r.aMod, "asn"); ok {
			next.asn, r.aMod, changed = rd, mod, true
		}
	}
	if !changed {
		return
	}
	r.cur.Store(next)

	// Close superseded readers late; a concurrent lookup may still hold
	// the old pair.
	if old.country != nil && old.country != next.country {
		closeLater(old.country)
	}
	if old.asn != nil && old.asn != next.asn {
		closeLater(old.asn)
	}
}

// maybeOpen opens path if it exists and its mtime differs from known.
// Returns the new reader and mtime, or ok=false if nothing to do.
func (r *Resolver) maybeOpen(path string, known time.Time, label string) (*maxminddb.Reader, time.Time, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, known, false
	}
	if fi.ModTime().Equal(known) {
		return nil, known, false
	}
	rd, err := maxminddb.Open(path)
	if err != nil {
		r.log.Error("geoip database open failed", "db", label, "path", path, "error", err)
		return nil, known, false
	}
	r.log.Info("geoip database loaded", "db", label, "path", path, "nodes", rd.Metadata.NodeCount)
	return rd, fi.ModTime(), true
}

// Close stops the poller and closes the open databases.
func (r *Resolver) Close() {
	r.once.Do(func() {
		close(r.stop)
		rd := r.cur.Load()
		if rd.country != nil {
			rd.country.Close()
		}
		if rd.asn != nil {
			rd.asn.Close()
		}
	})
}

func closeLater(rd *maxminddb.Reader) {
	time.AfterFunc(30*time.Second, func() { rd.Close() })
}
