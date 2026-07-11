package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"syscall"

	"github.com/quic-go/quic-go/http3"
)

// bindError wraps a listener bind failure, adding an actionable hint
// when the port is already taken — the usual cause being another server
// (e.g. nginx) already on this address. A wildcard 0.0.0.0 bind also
// collides with anything on 127.0.0.1 on the same port.
func bindError(name, addr string, err error) error {
	if errors.Is(err, syscall.EADDRINUSE) {
		hint := "another process already holds this port (check: ss -ltnp)"
		if strings.HasPrefix(addr, "0.0.0.0:") || strings.HasPrefix(addr, ":") {
			hint += "; note 0.0.0.0 overlaps 127.0.0.1 — if nginx is on loopback, bind gated to the public IP instead"
		}
		return fmt.Errorf("bind %s (%s): %w — %s", name, addr, err, hint)
	}
	return fmt.Errorf("bind %s (%s): %w", name, addr, err)
}

// GetCertificate is the SNI callback of the TLS listeners: SNI → vhost
// → certificate (explicit pair, forced cert_name, or conventional
// Let's Encrypt lookup by host then by the vhost's first host). An
// unknown SNI refuses the handshake, consistent with the plain 404 for
// unknown Hosts.
func (p *Proxy) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := normalizeHost(hello.ServerName)
	if host == "" {
		return nil, errors.New("missing SNI")
	}
	v := p.vhosts.Lookup(host)
	if v == nil {
		return nil, fmt.Errorf("unknown host %q", host)
	}
	if v.TLS.CertFile != "" {
		return p.certs.GetPair(v.TLS.CertFile, v.TLS.KeyFile)
	}
	candidates := []string{host}
	if v.TLS.CertName != "" {
		candidates = []string{v.TLS.CertName}
	} else if len(v.Hosts) > 0 && v.Hosts[0] != host {
		candidates = append(candidates, v.Hosts[0])
	}
	var lastErr error
	for _, name := range candidates {
		cert, err := p.certs.GetLE(name)
		if err == nil {
			return cert, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("no certificate for %q: %w", host, lastErr)
}

// Server runs the three public listeners: :80 TCP, :443 TCP (HTTP/1.1
// + HTTP/2) and :443 UDP (HTTP/3), all sharing the same handler chain.
type Server struct {
	p        *Proxy
	httpSrv  *http.Server
	httpsSrv *http.Server
	h3       *http3.Server
	errLog   *slog.Logger
}

// NewServer wires the listeners from the CURRENT config. Entrypoint
// addresses, TLS min version and http3 on/off are bound at startup
// (changing them requires a restart); everything else hot-reloads.
func NewServer(p *Proxy) *Server {
	return &Server{p: p, errLog: p.logs.Service}
}

// Start binds all listeners and begins serving in goroutines. A bind
// failure on either TCP port is fatal (returned); an HTTP/3 UDP
// failure is logged but not fatal.
func (s *Server) Start() error {
	cfg := s.p.cfg.Get()
	errorLog := slog.NewLogLogger(s.errLog.Handler(), slog.LevelError)

	// Plain HTTP entrypoint.
	s.httpSrv = &http.Server{
		Handler:           s.p.Handler(false),
		ReadHeaderTimeout: cfg.Proxy.ReadHeaderTimeout.Std(),
		ErrorLog:          errorLog,
	}
	httpLn, err := net.Listen("tcp", cfg.Entrypoints.HTTP.Listen)
	if err != nil {
		return bindError("http", cfg.Entrypoints.HTTP.Listen, err)
	}
	go func() {
		if err := s.httpSrv.Serve(httpLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.errLog.Error("http server error", "error", err)
		}
	}()
	s.errLog.Info("listening", "entrypoint", "http", "addr", cfg.Entrypoints.HTTP.Listen)

	// HTTPS entrypoint (HTTP/1.1 + HTTP/2 via ServeTLS).
	tlsCfg := &tls.Config{
		GetCertificate: s.p.GetCertificate,
		MinVersion:     minTLSVersion(cfg.TLS.MinVersion),
	}
	s.httpsSrv = &http.Server{
		Handler:           s.p.Handler(true),
		ReadHeaderTimeout: cfg.Proxy.ReadHeaderTimeout.Std(),
		TLSConfig:         tlsCfg,
		ErrorLog:          errorLog,
	}
	httpsLn, err := net.Listen("tcp", cfg.Entrypoints.HTTPS.Listen)
	if err != nil {
		httpLn.Close()
		return bindError("https", cfg.Entrypoints.HTTPS.Listen, err)
	}
	go func() {
		if err := s.httpsSrv.ServeTLS(httpsLn, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.errLog.Error("https server error", "error", err)
		}
	}()
	s.errLog.Info("listening", "entrypoint", "https", "addr", cfg.Entrypoints.HTTPS.Listen)

	// HTTP/3 (QUIC) on the same address, UDP.
	if cfg.Entrypoints.HTTPS.HTTP3 {
		s.h3 = &http3.Server{
			Addr:      cfg.Entrypoints.HTTPS.Listen,
			Handler:   s.p.Handler(true),
			TLSConfig: http3.ConfigureTLSConfig(tlsCfg),
		}
		go func() {
			if err := s.h3.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.errLog.Error("http3 server error", "error", err)
			}
		}()
		s.errLog.Info("listening", "entrypoint", "http3", "addr", cfg.Entrypoints.HTTPS.Listen, "proto", "udp")
	}
	return nil
}

// Shutdown drains the TCP servers within ctx and closes the QUIC one.
func (s *Server) Shutdown(ctx context.Context) {
	if s.httpSrv != nil {
		s.httpSrv.Shutdown(ctx)
	}
	if s.httpsSrv != nil {
		s.httpsSrv.Shutdown(ctx)
	}
	if s.h3 != nil {
		s.h3.Close()
	}
}

func minTLSVersion(v string) uint16 {
	if v == "1.3" {
		return tls.VersionTLS13
	}
	return tls.VersionTLS12
}
