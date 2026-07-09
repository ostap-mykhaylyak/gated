// Package logging provides the independent JSON log streams of gated.
//
// Observability is reading log files: no dashboard, no rotation logic
// in the binary. Rotation is delegated to logrotate, which sends
// SIGHUP; the daemon then calls Reopen on every stream.
package logging

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/ostap-mykhaylyak/gated/internal/paths"
)

// reopenFile is an *os.File that can be reopened in place (logrotate
// hook). Writes are serialized with a mutex so a reopen never races a
// log line.
type reopenFile struct {
	mu   sync.Mutex
	path string
	f    *os.File
}

func openFile(path string) (*reopenFile, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, err
	}
	return &reopenFile{path: path, f: f}, nil
}

func (r *reopenFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Write(p)
}

func (r *reopenFile) Reopen() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	old := r.f
	r.f = f
	return old.Close()
}

func (r *reopenFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}

// Streams holds one independent *slog.Logger per concern.
type Streams struct {
	Service *slog.Logger // daemon lifecycle, config reloads, errors
	Access  *slog.Logger // one line per proxied request
	Backend *slog.Logger // backend failures, health state changes
	API     *slog.Logger // management API audit trail

	files []*reopenFile
}

// Open opens all log streams under dir (production: paths.LogDir).
func Open(dir string) (*Streams, error) {
	s := &Streams{}
	for _, def := range []struct {
		name string
		dst  **slog.Logger
	}{
		{paths.ServiceLog, &s.Service},
		{paths.AccessLog, &s.Access},
		{paths.BackendLog, &s.Backend},
		{paths.APILog, &s.API},
	} {
		rf, err := openFile(filepath.Join(dir, def.name))
		if err != nil {
			s.Close()
			return nil, err
		}
		s.files = append(s.files, rf)
		*def.dst = slog.New(slog.NewJSONHandler(rf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	return s, nil
}

// Reopen reopens every log file. Called on SIGHUP (logrotate hook).
func (s *Streams) Reopen() error {
	var errs []error
	for _, f := range s.files {
		if err := f.Reopen(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Close closes every log file. Called on shutdown.
func (s *Streams) Close() error {
	var errs []error
	for _, f := range s.files {
		if err := f.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
