package vhost

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/ostap-mykhaylyak/gated/internal/config"
)

// Store holds the current vhosts behind an atomic pointer: Lookup is
// cheap and safe on the hot path.
type Store struct {
	dir string
	log *slog.Logger

	mu     sync.Mutex        // serializes LoadAll
	byFile map[string]*VHost // filename → last good version
	byHost atomic.Pointer[map[string]*VHost]
}

// NewStore returns an empty Store for dir. Call LoadAll to populate.
func NewStore(dir string, log *slog.Logger) *Store {
	s := &Store{dir: dir, log: log, byFile: map[string]*VHost{}}
	empty := map[string]*VHost{}
	s.byHost.Store(&empty)
	return s
}

// Lookup returns the vhost serving host (normalized), or nil: the
// caller answers 404 (no catch-all by design).
func (s *Store) Lookup(host string) *VHost {
	return (*s.byHost.Load())[normalizeHost(host)]
}

// Count returns the number of hostnames currently served.
func (s *Store) Count() int { return len(*s.byHost.Load()) }

// LoadAll (re)loads every *.yaml file in the directory. Per-file
// last-good rule: a file that fails to parse/validate keeps its
// previous version if it had one, or is skipped. Pools of removed or
// replaced vhosts are closed; replaced pools hand their runtime state
// over to the new ones (diff by backend URL).
func (s *Store) LoadAll(cfg *config.Config) {
	s.mu.Lock()
	defer s.mu.Unlock()

	files, err := filepath.Glob(filepath.Join(s.dir, "*.yaml"))
	if err != nil {
		s.log.Error("vhost scan failed", "dir", s.dir, "error", err)
		return
	}
	more, _ := filepath.Glob(filepath.Join(s.dir, "*.yml"))
	files = append(files, more...)
	sort.Strings(files)

	newByFile := make(map[string]*VHost, len(files))
	for _, f := range files {
		base := filepath.Base(f)
		v, err := loadFile(f, cfg, s.byFile[base])
		if err != nil {
			if prev := s.byFile[base]; prev != nil {
				s.log.Error("vhost reload failed, keeping last good version", "file", base, "error", err)
				newByFile[base] = prev
			} else {
				s.log.Error("vhost skipped", "file", base, "error", err)
			}
			continue
		}
		v.Name = strings.TrimSuffix(strings.TrimSuffix(base, ".yaml"), ".yml")
		newByFile[base] = v
	}

	// Host map: first file (alphabetically) wins on duplicates.
	byHost := map[string]*VHost{}
	bases := make([]string, 0, len(newByFile))
	for b := range newByFile {
		bases = append(bases, b)
	}
	sort.Strings(bases)
	for _, base := range bases {
		v := newByFile[base]
		for _, h := range v.Hosts {
			if other, dup := byHost[h]; dup {
				s.log.Warn("duplicate host, keeping first definition",
					"host", h, "kept", other.Name, "skipped", v.Name)
				continue
			}
			byHost[h] = v
		}
	}

	// Close pools that are gone or were replaced (the new pool already
	// carried the runtime state over in loadFile).
	for base, old := range s.byFile {
		if nv, ok := newByFile[base]; !ok || nv != old {
			if old.Pool != nil {
				old.Pool.Close()
			}
		}
	}

	s.byFile = newByFile
	s.byHost.Store(&byHost)
	s.log.Info("vhosts loaded", "files", len(newByFile), "hosts", len(byHost))
}

// Watch reloads the directory on any change to a *.yaml/*.yml file,
// coalescing bursts of events (editors, git checkout) into one reload.
func (s *Store) Watch(stop <-chan struct{}, getCfg func() *config.Config) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("vhost watch: %w", err)
	}
	if err := w.Add(s.dir); err != nil {
		w.Close()
		return fmt.Errorf("vhost watch: %w", err)
	}

	go func() {
		defer w.Close()
		var pending <-chan time.Time
		for {
			select {
			case <-stop:
				return
			case ev, ok := <-w.Events:
				if !ok {
					return
				}
				name := strings.ToLower(ev.Name)
				if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
					continue
				}
				pending = time.After(200 * time.Millisecond)
			case err, ok := <-w.Errors:
				if !ok {
					return
				}
				s.log.Error("vhost watch error", "error", err)
			case <-pending:
				pending = nil
				s.LoadAll(getCfg())
			}
		}
	}()
	return nil
}

// BackendInfo is the runtime view of one backend, for status/API.
type BackendInfo struct {
	URL    string `json:"url"`
	Up     bool   `json:"up"`
	Backup bool   `json:"backup"`
	Active int64  `json:"active"`
}

// Info is the runtime view of one vhost, for status/API. Field names
// are stable across versions.
type Info struct {
	Name     string        `json:"name"`
	Hosts    []string      `json:"hosts"`
	Strategy string        `json:"strategy"`
	Backends []BackendInfo `json:"backends"`
}

// Snapshot returns a point-in-time view of the loaded vhosts and the
// runtime state of their backends, sorted by name.
func (s *Store) Snapshot() []Info {
	s.mu.Lock()
	defer s.mu.Unlock()

	bases := make([]string, 0, len(s.byFile))
	for b := range s.byFile {
		bases = append(bases, b)
	}
	sort.Strings(bases)

	out := make([]Info, 0, len(bases))
	for _, base := range bases {
		v := s.byFile[base]
		info := Info{Name: v.Name, Hosts: v.Hosts, Strategy: v.LoadBalancing.Strategy}
		for _, b := range v.Pool.Backends() {
			info.Backends = append(info.Backends, BackendInfo{
				URL:    b.URL.String(),
				Up:     b.Available(),
				Backup: b.Backup,
				Active: b.Active(),
			})
		}
		out = append(out, info)
	}
	return out
}

// Close closes every pool (stops active probers). Called on shutdown.
func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.byFile {
		if v.Pool != nil {
			v.Pool.Close()
		}
	}
}
