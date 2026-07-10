// Package proxy is the HTTP entry point of gated: routing by Host,
// reverse proxying with retries, real IP resolution, ACME passthrough,
// HTTPS redirect, Early Hints, compression and the TLS/HTTP3 servers.
//
// Layer order (outside → backend):
//
//	metrics → access log → real IP → ACME passthrough
//	→ vhost lookup (miss ⇒ 404) → redirect_to_https → early hints
//	→ compression → balancer pick → reverse proxy (with retries)
package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/ostap-mykhaylyak/gated/internal/balancer"
	"github.com/ostap-mykhaylyak/gated/internal/certs"
	"github.com/ostap-mykhaylyak/gated/internal/challenge"
	"github.com/ostap-mykhaylyak/gated/internal/compress"
	"github.com/ostap-mykhaylyak/gated/internal/config"
	"github.com/ostap-mykhaylyak/gated/internal/geoip"
	"github.com/ostap-mykhaylyak/gated/internal/logging"
	"github.com/ostap-mykhaylyak/gated/internal/metrics"
	"github.com/ostap-mykhaylyak/gated/internal/pages"
	"github.com/ostap-mykhaylyak/gated/internal/vhost"
	"github.com/ostap-mykhaylyak/gated/internal/waf"
)

// challengePath is the reserved endpoint the interstitial JS posts to.
const challengePath = "/.gated/challenge"

// Proxy holds the wiring shared by every request.
type Proxy struct {
	cfg       *config.Manager
	vhosts    *vhost.Store
	certs     *certs.Store
	waf       *waf.Engine
	geoip     *geoip.Resolver // nil when geoip is disabled
	challenge *challenge.Manager
	pages     *pages.Pages
	m         *metrics.Metrics
	logs      *logging.Streams

	transport  *http.Transport
	resolver   resolverHolder
	discardLog *log.Logger
}

// New builds the Proxy. The backend transport is created once (its
// ResponseHeaderTimeout comes from the initial config; changing
// backend_timeout requires a restart, unlike everything else).
func New(cfg *config.Manager, vhosts *vhost.Store, certStore *certs.Store, wafEngine *waf.Engine, geo *geoip.Resolver, chal *challenge.Manager, pg *pages.Pages, m *metrics.Metrics, logs *logging.Streams) *Proxy {
	c := cfg.Get()
	return &Proxy{
		cfg:       cfg,
		vhosts:    vhosts,
		certs:     certStore,
		waf:       wafEngine,
		geoip:     geo,
		challenge: chal,
		pages:     pg,
		m:         m,
		logs:      logs,
		transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          512,
			MaxIdleConnsPerHost:   64,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
			ResponseHeaderTimeout: c.Proxy.BackendTimeout.Std(),
			// Backends' encodings pass through untouched; gated does
			// its own compression on the client side.
			DisableCompression: true,
		},
		discardLog: log.New(io.Discard, "", 0),
	}
}

// Handler returns the entrypoint handler; secure distinguishes the
// HTTPS listener from the plain HTTP one.
func (p *Proxy) Handler(secure bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		done := p.m.RequestStart()
		sw := &statusWriter{ResponseWriter: w}
		cfg := p.cfg.Get()
		clientIP := p.resolver.get(cfg).clientIP(r)
		host := normalizeHost(r.Host)
		reqID := newRequestID()
		sw.Header().Set("Gated-Ray-Id", reqID)

		var backendURL string
		var failed bool
		var wafPending []*waf.Rule
		defer func() {
			done(sw.bytes, failed || sw.status >= 500)
			if len(wafPending) > 0 {
				p.waf.ObserveResponse(wafPending, clientIP, sw.status)
			}
			p.logs.Access.Info("request",
				"ray_id", reqID,
				"host", host,
				"method", r.Method,
				"path", r.URL.Path,
				"proto", r.Proto,
				"status", sw.status,
				"bytes", sw.bytes,
				"duration_ms", float64(time.Since(start).Microseconds())/1000.0,
				"client_ip", clientIP,
				"backend", backendURL,
				"tls", secure,
			)
		}()

		// ACME passthrough BEFORE vhost lookup: renewals must work
		// even for hosts not configured in gated yet.
		if !secure && cfg.ACME.Passthrough &&
			strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			p.acmePassthrough(sw, r, cfg)
			return
		}

		// Challenge-solving endpoint: handled before WAF/vhost so the
		// interstitial's own POST is never inspected or blocked.
		if r.URL.Path == challengePath {
			p.solveChallenge(sw, r, clientIP)
			return
		}

		v := p.vhosts.Lookup(host)
		if v == nil {
			p.pages.Message(sw, pages.MessageData{
				Code: http.StatusNotFound, Title: "Not Found",
				Message: "This host is not configured on this server.",
				Host:    host, RequestID: reqID,
			})
			return
		}

		// WAF: inspect the request before anything is proxied. Runs on
		// both listeners so blocks and bans apply to :80 too.
		if v.WAFPol.Enabled {
			var body string
			if p.waf.NeedsBody() {
				body = bufferBody(r, cfg.WAF.MaxBodyBytes)
			}
			wctx := waf.NewContext(r, clientIP, body)
			if p.geoip != nil && p.waf.NeedsGeo() {
				g := p.geoip.Lookup(clientIP)
				wctx.SetGeo(g.Country, g.Continent, g.ASN)
			}
			dec, pending := p.waf.Evaluate(wctx, v.WAFPol)
			wafPending = pending
			if dec.Block {
				p.m.WAFBlock()
				p.logs.WAF.Info("waf enforce", "ray_id", reqID, "action", "block",
					"rule", dec.RuleID, "ip", clientIP, "host", host, "path", r.URL.Path)
				p.pages.Message(sw, pages.MessageData{
					Code: dec.Status, Title: "Request Blocked",
					Message: "This request was blocked by the security rules. If you believe this is an error, contact the site administrator.",
					Host:    host, RequestID: reqID,
				})
				return
			}
			// Challenge: unless the client already holds a valid
			// clearance cookie, present the interstitial. Prefer HTTPS
			// so the (optional) SubtleCrypto PoW has a secure context.
			if dec.Challenge && !p.challenge.HasClearance(r, clientIP) {
				if !secure && v.RedirectToHTTPS {
					http.Redirect(sw, r, "https://"+host+r.URL.RequestURI(), http.StatusPermanentRedirect)
					return
				}
				p.m.WAFChallenge()
				p.logs.WAF.Info("waf enforce", "ray_id", reqID, "action", "challenge",
					"rule", dec.RuleID, "ip", clientIP, "host", host, "path", r.URL.Path)
				token, c := p.challenge.Issue()
				p.pages.Challenge(sw, pages.ChallengeData{
					Token: token, C: c, Difficulty: p.challenge.Difficulty(),
					Endpoint: challengePath, Host: host, RequestID: reqID,
				})
				return
			}
		}

		if !secure && v.RedirectToHTTPS {
			http.Redirect(sw, r, "https://"+host+r.URL.RequestURI(), http.StatusPermanentRedirect)
			return
		}

		if secure && cfg.Entrypoints.HTTPS.HTTP3 {
			if _, port, err := net.SplitHostPort(cfg.Entrypoints.HTTPS.Listen); err == nil {
				sw.Header().Set("Alt-Svc", `h3=":`+port+`"; ma=86400`)
			}
		}

		// 103 Early Hints, sent before contacting the backend. The
		// Link headers intentionally remain on the final response too.
		if len(v.EarlyHints) > 0 {
			for _, hint := range v.EarlyHints {
				sw.Header().Add("Link", hint)
			}
			sw.WriteHeader(http.StatusEarlyHints)
		}

		cw, finish := compress.Wrap(sw, r, v.Comp)
		defer finish()

		// Balancer + retries: a transport-level failure on a
		// replayable request (no body consumed, nothing written to the
		// client) moves on to the next backend.
		for attempt := 0; attempt < len(v.Backends); attempt++ {
			b := v.Pool.Pick(r, clientIP)
			if b == nil {
				failed = true
				p.pages.Message(cw, pages.MessageData{
					Code: http.StatusServiceUnavailable, Title: "Service Unavailable",
					Message: "No backend server is available to handle your request right now. Please try again shortly.",
					Host:    host, RequestID: reqID,
				})
				return
			}
			backendURL = b.URL.String()

			if st := v.Pool.Sticky(); st.Enabled {
				if c, err := r.Cookie(st.Cookie); err != nil || c.Value != b.ID {
					ck := http.Cookie{
						Name:     st.Cookie,
						Value:    b.ID,
						Path:     "/",
						MaxAge:   int(st.TTL.Seconds()),
						HttpOnly: true,
						Secure:   secure,
						SameSite: http.SameSiteLaxMode,
					}
					// Set (not Add): a retry replaces the previous
					// attempt's cookie instead of stacking it.
					cw.Header().Set("Set-Cookie", ck.String())
				}
			}

			err, wrote := p.forward(cw, r, b, clientIP, secure)
			v.Pool.Report(b, err == nil)
			if err == nil {
				return
			}
			p.logs.Backend.Error("backend error",
				"host", host, "backend", backendURL, "error", err)
			if wrote || errors.Is(err, context.Canceled) || r.ContentLength != 0 {
				failed = true
				return
			}
		}
		failed = true
		p.pages.Message(cw, pages.MessageData{
			Code: http.StatusBadGateway, Title: "Backend Down",
			Message: "The upstream server is unreachable or returned an invalid response. Please try again later.",
			Host:    host, RequestID: reqID,
		})
	})
}

// solveChallenge handles POST /.gated/challenge: it verifies the
// interstitial's token (and PoW, if any) and, on success, issues the
// clearance cookie the client replays on its next request.
func (p *Proxy) solveChallenge(w http.ResponseWriter, r *http.Request, clientIP string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Token string `json:"token"`
		Nonce string `json:"nonce"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&body); err != nil {
		http.Error(w, `{"ok":false}`, http.StatusBadRequest)
		return
	}
	ck, ok := p.challenge.Verify(body.Token, body.Nonce, clientIP)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `{"ok":false}`)
		return
	}
	ck.Secure = r.TLS != nil
	http.SetCookie(w, ck)
	p.m.WAFClear()
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, `{"ok":true}`)
}

// newRequestID returns a short random hex id used as the response
// "Ray ID" and access-log correlation key.
func newRequestID() string {
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// forward proxies the request to one backend. Returns the transport
// error (nil on success) and whether anything was written to the
// client (which forbids retrying).
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, b *balancer.Backend, clientIP string, secure bool) (error, bool) {
	b.Acquire()
	defer b.Release()

	tw := &trackWriter{ResponseWriter: w}
	var errOut error
	scheme := "http"
	if secure {
		scheme = "https"
	}
	rp := &httputil.ReverseProxy{
		Transport: p.transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(b.URL)
			pr.Out.Host = r.Host // preserve the original Host header
			pr.Out.Header.Set("X-Forwarded-For", clientIP)
			pr.Out.Header.Set("X-Real-IP", clientIP)
			pr.Out.Header.Set("X-Forwarded-Proto", scheme)
			pr.Out.Header.Set("X-Forwarded-Host", r.Host)
		},
		ErrorHandler: func(_ http.ResponseWriter, _ *http.Request, err error) {
			// Record only: the caller decides (retry / 502). Nothing
			// is written so the response stays retryable.
			errOut = err
		},
		ErrorLog: p.discardLog,
	}
	rp.ServeHTTP(tw, r)
	return errOut, tw.wrote
}

// acmePassthrough forwards HTTP-01 challenges to the local nginx.
func (p *Proxy) acmePassthrough(w http.ResponseWriter, r *http.Request, cfg *config.Config) {
	u, err := url.Parse(cfg.ACME.Upstream)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	rp := &httputil.ReverseProxy{
		Transport: p.transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(u)
			pr.Out.Host = r.Host
		},
		ErrorHandler: func(rw http.ResponseWriter, _ *http.Request, err error) {
			p.logs.Backend.Error("acme passthrough error", "error", err)
			rw.WriteHeader(http.StatusBadGateway)
		},
		ErrorLog: p.discardLog,
	}
	rp.ServeHTTP(w, r)
}

// statusWriter records final status and bytes for metrics/access log.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (sw *statusWriter) WriteHeader(code int) {
	if code >= 200 {
		sw.status = code
	}
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusWriter) Write(p []byte) (int, error) {
	if sw.status == 0 {
		sw.status = http.StatusOK
	}
	n, err := sw.ResponseWriter.Write(p)
	sw.bytes += int64(n)
	return n, err
}

func (sw *statusWriter) Flush() {
	http.NewResponseController(sw.ResponseWriter).Flush()
}

// trackWriter records whether the response has started (headers or
// body sent), which forbids retrying on another backend.
type trackWriter struct {
	http.ResponseWriter
	wrote bool
}

func (tw *trackWriter) WriteHeader(code int) {
	if code >= 200 {
		tw.wrote = true
	}
	tw.ResponseWriter.WriteHeader(code)
}

func (tw *trackWriter) Write(p []byte) (int, error) {
	tw.wrote = true
	return tw.ResponseWriter.Write(p)
}

func (tw *trackWriter) Flush() {
	http.NewResponseController(tw.ResponseWriter).Flush()
}

// bufferBody reads the request body (up to limit) into memory for WAF
// inspection and replaces r.Body with a replayable reader, so the
// proxy still forwards it intact. Bodies larger than the limit, or of
// unknown length, are skipped (not inspected) to avoid buffering
// arbitrary uploads.
func bufferBody(r *http.Request, limit int64) string {
	if r.Body == nil || limit <= 0 || r.ContentLength <= 0 || r.ContentLength > limit {
		return ""
	}
	buf, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		r.Body = io.NopCloser(bytes.NewReader(buf))
		return ""
	}
	r.Body = io.NopCloser(bytes.NewReader(buf))
	return string(buf)
}

// normalizeHost lowercases and strips port and trailing dot.
func normalizeHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}
