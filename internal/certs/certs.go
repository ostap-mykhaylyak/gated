// Package certs loads and caches TLS certificates from the
// conventional Let's Encrypt layout (<dir>/<name>/fullchain.pem +
// privkey.pem) or from explicit file pairs.
//
// Renewal hot-swap: instead of watching the letsencrypt archive (the
// files under live/ are symlinks), every cached entry is re-stat'ed at
// most once per TTL (30s); a changed mtime triggers a reload. A
// renewed certificate is therefore picked up within TTL, with zero
// downtime and no fsnotify complexity.
package certs

import (
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Store is the certificate cache.
type Store struct {
	leDir string
	ttl   time.Duration

	mu    sync.Mutex
	cache map[string]*entry // keyed by cert file path
}

type entry struct {
	cert    *tls.Certificate
	keyPath string
	checked time.Time
	mtime   time.Time
}

// New returns a Store reading Let's Encrypt certificates under leDir.
func New(leDir string) *Store {
	return &Store{leDir: leDir, ttl: 30 * time.Second, cache: map[string]*entry{}}
}

// GetLE returns the certificate for the conventional certbot name:
// <leDir>/<name>/fullchain.pem + privkey.pem.
func (s *Store) GetLE(name string) (*tls.Certificate, error) {
	if name == "" || strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return nil, fmt.Errorf("invalid certificate name %q", name)
	}
	dir := filepath.Join(s.leDir, name)
	return s.GetPair(filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem"))
}

// GetPair returns the certificate for an explicit cert/key file pair,
// reloading it when the cert file's mtime changes (checked at most
// once per TTL). If a reload fails, the cached certificate keeps being
// served rather than breaking live handshakes.
func (s *Store) GetPair(certFile, keyFile string) (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	e := s.cache[certFile]
	if e != nil && now.Sub(e.checked) < s.ttl {
		return e.cert, nil
	}

	fi, err := os.Stat(certFile)
	if err != nil {
		if e != nil {
			e.checked = now
			return e.cert, nil
		}
		return nil, err
	}
	if e != nil && fi.ModTime().Equal(e.mtime) {
		e.checked = now
		return e.cert, nil
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		if e != nil {
			e.checked = now
			return e.cert, nil
		}
		return nil, fmt.Errorf("load certificate: %w", err)
	}
	s.cache[certFile] = &entry{cert: &cert, keyPath: keyFile, checked: now, mtime: fi.ModTime()}
	return &cert, nil
}
