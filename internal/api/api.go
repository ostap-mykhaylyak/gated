// Package api implements the optional management REST API (disabled
// by default). It is a privileged surface: bearer-token auth on every
// request (except /healthz), mounted on its OWN listener — never the
// public entrypoint — and every call is audited on the api log stream.
//
// The global config stays file-managed and read-only; the API mutates
// ONLY the per-vhost files, with the validate → snapshot → atomic
// write → reload cycle. Every write is versioned under
// vhosts/.history/ and can be rolled back.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/ostap-mykhaylyak/gated/internal/config"
	"github.com/ostap-mykhaylyak/gated/internal/status"
	"github.com/ostap-mykhaylyak/gated/internal/vhost"
)

// Server is the management API server.
type Server struct {
	cfg     *config.Manager
	vhosts  *vhost.Store
	collect func() *status.Snapshot
	log     *slog.Logger
	dir     string // vhosts directory
	histDir string // vhosts/.history (invisible to the vhost store)

	mu  sync.Mutex // single writer for every mutation
	srv *http.Server
}

// New wires the API server; call Start to bind it (no-op if disabled).
func New(cfg *config.Manager, vhosts *vhost.Store, collect func() *status.Snapshot, log *slog.Logger, vhostsDir string) *Server {
	return &Server{
		cfg:     cfg,
		vhosts:  vhosts,
		collect: collect,
		log:     log,
		dir:     vhostsDir,
		histDir: filepath.Join(vhostsDir, ".history"),
	}
}

// Start binds the API listener when api.enabled is true. Toggling the
// API (or changing its listen address / TLS material) requires a
// restart; the token is read per-request and hot-reloads.
func (s *Server) Start() error {
	c := s.cfg.Get()
	if !c.API.Enabled {
		return nil
	}
	s.srv = &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: c.Proxy.ReadHeaderTimeout.Std(),
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelError),
	}
	ln, err := net.Listen("tcp", c.API.Listen)
	if err != nil {
		return fmt.Errorf("bind api: %w", err)
	}
	go func() {
		var err error
		if c.API.TLS.CertFile != "" && c.API.TLS.KeyFile != "" {
			err = s.srv.ServeTLS(ln, c.API.TLS.CertFile, c.API.TLS.KeyFile)
		} else {
			err = s.srv.Serve(ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("api server error", "error", err)
		}
	}()
	s.log.Info("management api listening", "addr", c.API.Listen)
	return nil
}

// Shutdown drains the API server within ctx (no-op if disabled).
func (s *Server) Shutdown(ctx context.Context) {
	if s.srv != nil {
		s.srv.Shutdown(ctx)
	}
}

// Handler builds the routed, authenticated handler (exported for tests).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /status", s.status)
	mux.HandleFunc("GET /metrics", s.metrics)
	mux.HandleFunc("GET /config", s.config)
	mux.HandleFunc("POST /reload", s.reload)
	mux.HandleFunc("GET /vhosts", s.listVhosts)
	mux.HandleFunc("GET /vhosts/{name}", s.getVhost)
	mux.HandleFunc("PUT /vhosts/{name}", s.putVhost)
	mux.HandleFunc("DELETE /vhosts/{name}", s.deleteVhost)
	mux.HandleFunc("GET /vhosts/{name}/history", s.vhostHistory)
	mux.HandleFunc("POST /vhosts/{name}/rollback", s.rollbackVhost)
	return s.wrap(mux)
}

// wrap adds the audit log line and bearer auth. /healthz is the only
// anonymous endpoint (LB/k8s probes), read-only by construction.
func (s *Server) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		aw := &auditWriter{ResponseWriter: w}
		defer func() {
			s.log.Info("api",
				"method", r.Method,
				"path", r.URL.Path,
				"status", aw.status,
				"remote", r.RemoteAddr,
			)
		}()
		if r.URL.Path != "/healthz" {
			token := s.cfg.Get().API.Token
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if token == "" ||
				subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				writeErr(aw, http.StatusUnauthorized, "missing or invalid token")
				return
			}
		}
		next.ServeHTTP(aw, r)
	})
}

// --- read-only endpoints -------------------------------------------------

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	snap := s.collect()
	code := http.StatusOK
	if snap.Status == status.Crit {
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, map[string]string{"status": snap.Status})
}

func (s *Server) status(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.collect())
}

func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.collect().Live)
}

// config returns the CURRENT global config, redacted: secrets never
// leave the daemon. YAML out, like the file it mirrors.
func (s *Server) config(w http.ResponseWriter, _ *http.Request) {
	c := *s.cfg.Get() // shallow copy; nested sections are values
	if c.API.Token != "" {
		c.API.Token = "***"
	}
	data, err := yaml.Marshal(&c)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Write(data)
}

// reload re-reads the global config (same path as SIGHUP/fsnotify) and
// re-resolves the vhosts. Idempotent.
func (s *Server) reload(w http.ResponseWriter, _ *http.Request) {
	if err := s.cfg.Reload(); err != nil {
		writeErr(w, http.StatusBadRequest, "reload failed: "+err.Error())
		return
	}
	cfg := s.cfg.Get()
	s.vhosts.LoadAll(cfg)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "warnings": cfg.Warnings})
}

// --- plumbing ------------------------------------------------------------

// auditWriter records the status code for the audit log line.
type auditWriter struct {
	http.ResponseWriter
	status int
}

func (a *auditWriter) WriteHeader(code int) {
	if a.status == 0 {
		a.status = code
	}
	a.ResponseWriter.WriteHeader(code)
}

func (a *auditWriter) Write(p []byte) (int, error) {
	if a.status == 0 {
		a.status = http.StatusOK
	}
	return a.ResponseWriter.Write(p)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
