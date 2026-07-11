// Package proxy is the HTTP entry point of gated: routing by Host,
// reverse proxying with retries, real IP resolution, HTTPS redirect,
// Early Hints, compression and the TLS/HTTP3 servers.
//
// Layer order (outside → backend):
//
//	metrics → access log → real IP → vhost lookup (miss ⇒ 404)
//	→ redirect_to_https → early hints → compression → balancer pick
//	→ reverse proxy (with retries)
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
	"strconv"
	"strings"
	"time"

	"github.com/ostap-mykhaylyak/gated/internal/balancer"
	"github.com/ostap-mykhaylyak/gated/internal/cache"
	"github.com/ostap-mykhaylyak/gated/internal/certs"
	"github.com/ostap-mykhaylyak/gated/internal/challenge"
	"github.com/ostap-mykhaylyak/gated/internal/compress"
	"github.com/ostap-mykhaylyak/gated/internal/config"
	"github.com/ostap-mykhaylyak/gated/internal/geoip"
	"github.com/ostap-mykhaylyak/gated/internal/logging"
	"github.com/ostap-mykhaylyak/gated/internal/metrics"
	"github.com/ostap-mykhaylyak/gated/internal/pages"
	"github.com/ostap-mykhaylyak/gated/internal/session"
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
	session   *session.Manager
	pages     *pages.Pages
	cache     *cache.Store
	m         *metrics.Metrics
	logs      *logging.Streams

	resolver   resolverHolder
	discardLog *log.Logger
}

// New builds the Proxy. Backend transports are per-vhost (built by the
// vhost store); the Proxy keeps only the shared request wiring.
func New(cfg *config.Manager, vhosts *vhost.Store, certStore *certs.Store, wafEngine *waf.Engine, geo *geoip.Resolver, chal *challenge.Manager, sess *session.Manager, pg *pages.Pages, cacheStore *cache.Store, m *metrics.Metrics, logs *logging.Streams) *Proxy {
	return &Proxy{
		cfg:        cfg,
		vhosts:     vhosts,
		certs:      certStore,
		waf:        wafEngine,
		geoip:      geo,
		challenge:  chal,
		session:    sess,
		pages:      pg,
		cache:      cacheStore,
		m:          m,
		logs:       logs,
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

		// Response-header mutations apply to every response of this
		// vhost (proxied pages included), enforced in sw.WriteHeader.
		if hasHeaderOps(v.Headers.Response) {
			sw.respOps, sw.hasOps = v.Headers.Response, true
		}

		// CORS: set the headers for an allowed Origin and short-circuit
		// preflight OPTIONS before the WAF/backend.
		if applyCORS(sw, r, v.CORS) {
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
			if p.session != nil && p.waf.NeedsSession() {
				wctx.SetSession(p.session.Valid(r))
			}
			dec, pending := p.waf.Evaluate(wctx, v.WAFPol)
			wafPending = pending
			if dec.Block {
				p.m.WAFBlock()
				action := "block"
				title := "Request Blocked"
				message := "This request was blocked by the security rules. If you believe this is an error, contact the site administrator."
				if dec.Status == http.StatusTooManyRequests {
					action, title = "rate_limit", "Too Many Requests"
					message = "You are sending requests too quickly. Please slow down and try again shortly."
					if dec.RetryAfter > 0 {
						sw.Header().Set("Retry-After", strconv.Itoa(int(dec.RetryAfter.Seconds())+1))
					}
				}
				p.logs.WAF.Info("waf enforce", "ray_id", reqID, "action", action,
					"rule", dec.RuleID, "ip", clientIP, "host", host, "path", r.URL.Path)
				p.pages.Message(sw, pages.MessageData{
					Code: dec.Status, Title: title,
					Message: message, Host: host, RequestID: reqID,
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

		// Protocol upgrades (WebSocket and any other Connection: Upgrade)
		// are streamed bidirectionally by ReverseProxy after hijacking
		// the connection: skip Early Hints and compression for them.
		upgrade := isUpgradeRequest(r)

		// 103 Early Hints, sent before contacting the backend. The
		// Link headers intentionally remain on the final response too.
		if len(v.EarlyHints) > 0 && !upgrade {
			for _, hint := range v.EarlyHints {
				sw.Header().Add("Link", hint)
			}
			sw.WriteHeader(http.StatusEarlyHints)
		}

		// Issue the prior-visit marker on normal HTML page loads, so a
		// later request to a session-protected endpoint carries it. Only
		// when a loaded rule actually uses the session field.
		issueVisit := v.WAFPol.Enabled && p.session != nil && p.waf.NeedsSession() &&
			r.Method == http.MethodGet && !p.session.Valid(r)

		// Request-header mutations toward the backend (WAF already ran).
		if hasHeaderOps(v.Headers.Request) {
			applyHeaderOps(r.Header, v.Headers.Request)
		}

		// Response cache: on a cacheable request, serve a live hit
		// directly (after the WAF, so bans/limits still apply). On a
		// miss, remember the key to store the response below.
		var cacheStoreKey string
		if v.Cache.Enabled && !upgrade && cacheableRequest(r, &v.Cache) {
			key := cacheKey(r, host)
			if e, ok := p.cache.Get(key); ok {
				p.m.CacheHit()
				hw, finish := compress.Wrap(sw, r, v.Comp)
				serveFromCache(hw, e)
				finish()
				return
			}
			p.m.CacheMiss()
			cacheStoreKey = key
		}

		// Path routing: pick the matching route's pool (or a canary
		// split), and apply any path rewrite before proxying. No match
		// falls back to the vhost's default backends.
		pool := v.Pool
		if route := v.MatchRoute(r.Method, r.URL.Path); route != nil {
			if route.Pool != nil {
				pool = route.Pool
			}
			if route.Hit(r) {
				pool = route.Canary.Pool
			}
			if np := route.RewritePath(r.URL.Path); np != r.URL.Path {
				r.URL.Path = np
				r.URL.RawPath = ""
			}
		}

		// The client-facing writer: raw for upgrades (so the hijack can
		// take over the connection), compressed otherwise.
		cw := http.ResponseWriter(sw)
		finish := func() {}
		if !upgrade {
			cw, finish = compress.Wrap(sw, r, v.Comp)
		}
		defer finish()

		// On a cache miss, tee the uncompressed backend response into a
		// buffer so it can be stored after a successful proxy.
		var capture *cacheWriter
		backendW := cw
		if cacheStoreKey != "" {
			capture = &cacheWriter{ResponseWriter: cw, limit: v.Cache.MaxObjectBytes}
			backendW = capture
			cw.Header().Set("X-Cache", "MISS")
		}

		// Balancer + retries: a transport-level failure on a
		// replayable request (no body consumed, nothing written to the
		// client) moves on to the next backend.
		reqScheme := "http"
		if secure {
			reqScheme = "https"
		}
		for attempt := 0; attempt < len(pool.Backends()); attempt++ {
			b := pool.Pick(r, clientIP, reqScheme)
			if b == nil {
				failed = true
				// Loud, specific reason: a configured scheme with no
				// usable backend is almost always all backends of that
				// scheme being down (see the earlier backend errors).
				hint := "all backends are down"
				if v.Pool.HasScheme(reqScheme) {
					hint = "all " + reqScheme + ":// backends are down — see earlier backend errors in this log"
				}
				p.logs.Backend.Error("no backend available", "ray_id", reqID,
					"host", host, "scheme", reqScheme, "reason", hint)
				p.pages.Message(cw, pages.MessageData{
					Code: http.StatusServiceUnavailable, Title: "Service Unavailable",
					Message: "No backend server is available to handle your request right now. Please try again shortly.",
					Host:    host, RequestID: reqID,
				})
				return
			}
			backendURL = b.URL.String()

			if st := pool.Sticky(); st.Enabled {
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

			err, wrote := p.forward(backendW, r, b, clientIP, secure, issueVisit, v.Transport, v.Hosts)
			pool.Report(b, err == nil)
			if err == nil {
				if capture != nil {
					if e := entryFrom(capture, cw.Header(), &v.Cache); e != nil {
						p.cache.Set(cacheStoreKey, e)
					}
				}
				return
			}
			if hint := certHint(err); hint != "" {
				p.logs.Backend.Error("backend error", "ray_id", reqID,
					"host", host, "backend", backendURL, "error", err, "hint", hint)
			} else {
				p.logs.Backend.Error("backend error", "ray_id", reqID,
					"host", host, "backend", backendURL, "error", err)
			}
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

// upgradeLocation rewrites a redirect's Location from http:// to
// https:// when it points at one of the vhost's own hosts. This breaks
// the classic reverse-proxy loop where a TLS-terminated CMS redirects
// its own host back to plaintext. Redirects to other hosts, or already
// https, are left untouched.
func upgradeLocation(resp *http.Response, hosts []string) {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return
	}
	u, err := url.Parse(loc)
	if err != nil || u.Scheme != "http" {
		return
	}
	if !hostInList(normalizeHost(u.Host), hosts) {
		return
	}
	u.Scheme = "https"
	resp.Header.Set("Location", u.String())
}

func hostInList(host string, hosts []string) bool {
	for _, h := range hosts {
		if h == host {
			return true
		}
	}
	return false
}

// requestURL reconstructs the absolute URL the client requested.
func requestURL(r *http.Request, secure bool) string {
	scheme := "http"
	if secure {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.RequestURI()
}

// selfRedirect reports whether a redirect response points back at the
// exact URL that was just requested (scheme+host+path+query) — a loop
// the client can never escape.
func selfRedirect(resp *http.Response, r *http.Request, secure bool) bool {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return false
	}
	scheme := "http"
	if secure {
		scheme = "https"
	}
	base := &url.URL{Scheme: scheme, Host: r.Host, Path: r.URL.Path, RawQuery: r.URL.RawQuery}
	u, err := url.Parse(loc)
	if err != nil {
		return false
	}
	abs := base.ResolveReference(u)
	return abs.Scheme == base.Scheme &&
		normalizeHost(abs.Host) == normalizeHost(base.Host) &&
		abs.Path == base.Path && abs.RawQuery == base.RawQuery
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
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, b *balancer.Backend, clientIP string, secure, issueVisit bool, transport http.RoundTripper, hosts []string) (error, bool) {
	b.Acquire()
	defer b.Release()

	tw := &trackWriter{ResponseWriter: w}
	var errOut error
	scheme, sslOn, fwdPort := "http", "off", "80"
	if secure {
		scheme, sslOn, fwdPort = "https", "on", "443"
	}
	rp := &httputil.ReverseProxy{
		Transport: transport,
		ModifyResponse: func(resp *http.Response) error {
			// Mark the browser as "visited" on a successful HTML page,
			// so a session-protected endpoint later sees the cookie.
			if issueVisit && resp.StatusCode >= 200 && resp.StatusCode < 300 &&
				strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
				resp.Header.Add("Set-Cookie", p.session.Cookie(secure).String())
			}
			// Anti-loop: when we terminate TLS but a CMS emits an
			// absolute http:// redirect to its own host (because it
			// still thinks the request was plaintext), upgrade the
			// Location to https:// so the client does not bounce back
			// into an endless redirect.
			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				if secure {
					upgradeLocation(resp, hosts)
				}
				// Surface a redirect loop: a backend that redirects to
				// the exact URL just requested (e.g. nginx forcing
				// http->https on the port gated proxies to) can never
				// resolve. Log it so it is not a silent browser loop.
				if selfRedirect(resp, r, secure) {
					p.logs.Backend.Warn("backend redirect loop",
						"url", requestURL(r, secure),
						"location", resp.Header.Get("Location"),
						"hint", "backend redirects to the same URL; if it forces HTTP->HTTPS, point the backend at its https:// port")
				}
			}
			return nil
		},
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(b.URL)
			pr.Out.Host = r.Host // preserve the original Host header
			pr.Out.Header.Set("X-Forwarded-For", clientIP)
			pr.Out.Header.Set("X-Real-IP", clientIP)
			pr.Out.Header.Set("X-Forwarded-Proto", scheme)
			pr.Out.Header.Set("X-Forwarded-Host", r.Host)
			// Extra hints so CMSes that ignore X-Forwarded-Proto still
			// detect HTTPS and avoid the "force SSL" redirect loop.
			pr.Out.Header.Set("X-Forwarded-Ssl", sslOn)
			pr.Out.Header.Set("X-Forwarded-Port", fwdPort)
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

// statusWriter records final status and bytes for metrics/access log,
// and applies the vhost's response-header mutations on the final
// header — covering both proxied responses and gated-generated pages.
type statusWriter struct {
	http.ResponseWriter
	status  int
	bytes   int64
	respOps vhost.HeaderOps
	opsDone bool
	hasOps  bool
}

func (sw *statusWriter) WriteHeader(code int) {
	if code >= 200 {
		sw.status = code
		if sw.hasOps && !sw.opsDone {
			sw.opsDone = true
			applyHeaderOps(sw.Header(), sw.respOps)
		}
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

// Unwrap lets http.ResponseController reach the underlying writer's
// Hijack (needed for WebSocket / protocol upgrades) and Flush.
func (sw *statusWriter) Unwrap() http.ResponseWriter { return sw.ResponseWriter }

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

// Unwrap exposes the underlying writer for Hijack/Flush during upgrades.
func (tw *trackWriter) Unwrap() http.ResponseWriter { return tw.ResponseWriter }

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

// applyHeaderOps mutates h: Remove first, then Set (override), then Add.
func applyHeaderOps(h http.Header, ops vhost.HeaderOps) {
	for _, k := range ops.Remove {
		h.Del(k)
	}
	for k, v := range ops.Set {
		h.Set(k, v)
	}
	for k, v := range ops.Add {
		h.Add(k, v)
	}
}

// hasHeaderOps reports whether ops does anything.
func hasHeaderOps(ops vhost.HeaderOps) bool {
	return len(ops.Set) > 0 || len(ops.Add) > 0 || len(ops.Remove) > 0
}

// applyCORS handles cross-origin requests: it sets the CORS response
// headers for an allowed Origin and answers preflight OPTIONS directly.
// Returns true when the request was fully handled (preflight).
func applyCORS(w http.ResponseWriter, r *http.Request, c vhost.CORS) bool {
	if !c.Enabled {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	allow := corsAllowedOrigin(origin, c.AllowOrigins, c.AllowCredentials)
	if allow == "" {
		return false // origin not allowed: emit no CORS headers
	}
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", allow)
	if allow != "*" {
		h.Add("Vary", "Origin")
	}
	if c.AllowCredentials {
		h.Set("Access-Control-Allow-Credentials", "true")
	}
	if len(c.ExposeHeaders) > 0 {
		h.Set("Access-Control-Expose-Headers", strings.Join(c.ExposeHeaders, ", "))
	}
	// Preflight: answer directly, do not reach the backend.
	if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
		if len(c.AllowMethods) > 0 {
			h.Set("Access-Control-Allow-Methods", strings.Join(c.AllowMethods, ", "))
		}
		if len(c.AllowHeaders) > 0 {
			h.Set("Access-Control-Allow-Headers", strings.Join(c.AllowHeaders, ", "))
		}
		if c.MaxAge.Std() > 0 {
			h.Set("Access-Control-Max-Age", strconv.Itoa(int(c.MaxAge.Std().Seconds())))
		}
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	return false
}

// corsAllowedOrigin returns the value for Access-Control-Allow-Origin,
// or "" if the origin is not allowed. A "*" allowlist echoes the origin
// when credentials are enabled (wildcard + credentials is invalid).
func corsAllowedOrigin(origin string, allow []string, credentials bool) string {
	for _, a := range allow {
		if a == "*" {
			if credentials {
				return origin
			}
			return "*"
		}
		if a == origin {
			return origin
		}
	}
	return ""
}

// isUpgradeRequest reports whether the request asks to switch protocol
// (WebSocket, or any other Connection: Upgrade token).
func isUpgradeRequest(r *http.Request) bool {
	if r.Header.Get("Upgrade") == "" {
		return false
	}
	for _, v := range r.Header["Connection"] {
		if strings.Contains(strings.ToLower(v), "upgrade") {
			return true
		}
	}
	return false
}

// normalizeHost lowercases and strips port and trailing dot.
func normalizeHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}
