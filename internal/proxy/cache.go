package proxy

import (
	"bytes"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ostap-mykhaylyak/gated/internal/cache"
	"github.com/ostap-mykhaylyak/gated/internal/vhost"
)

// cacheKey identifies a cached response: method + host + full URI. Built
// from the ORIGINAL request, before any route rewrite.
func cacheKey(r *http.Request, host string) string {
	return r.Method + "\x00" + host + "\x00" + r.URL.RequestURI()
}

// cacheableRequest reports whether the request is eligible for caching
// (idempotent method, no client no-store, not bypassed).
func cacheableRequest(r *http.Request, c *vhost.Cache) bool {
	if r.Method != http.MethodGet {
		return false
	}
	if !c.PathEligible(r.URL.Path) {
		return false
	}
	if strings.Contains(strings.ToLower(r.Header.Get("Cache-Control")), "no-store") {
		return false
	}
	return !c.Bypassed(r)
}

// serveFromCache writes a cached entry to w (which may be a compressing
// writer, so the stored uncompressed body is re-encoded per client).
func serveFromCache(w http.ResponseWriter, e *cache.Entry) {
	h := w.Header()
	for k, vs := range e.Header {
		for _, v := range vs {
			h.Add(k, v)
		}
	}
	h.Set("X-Cache", "HIT")
	h.Set("Age", strconv.Itoa(int(time.Until(e.Expires).Seconds()))) // rough remaining TTL
	w.WriteHeader(e.Status)
	w.Write(e.Body)
}

// ttlFor decides how long a response may be cached, or 0 = do not cache.
// Backend Cache-Control wins; otherwise the vhost TTL, or the micro-TTL
// for HTML.
func ttlFor(resp http.Header, status int, c *vhost.Cache) time.Duration {
	if !c.CacheableStatusOK(status) {
		return 0
	}
	// User-specific or explicitly uncacheable responses are never stored.
	if resp.Get("Set-Cookie") != "" {
		return 0
	}
	if v := strings.ToLower(resp.Get("Vary")); strings.Contains(v, "cookie") ||
		strings.Contains(v, "authorization") || strings.TrimSpace(v) == "*" {
		return 0
	}
	cc := strings.ToLower(resp.Get("Cache-Control"))
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "no-cache") || strings.Contains(cc, "private") {
		return 0
	}
	if d, ok := maxAge(cc); ok {
		return d
	}
	if c.MicroTTL.Std() > 0 && strings.HasPrefix(resp.Get("Content-Type"), "text/html") {
		return c.MicroTTL.Std()
	}
	return c.TTL.Std()
}

// maxAge parses "max-age=N" (or "s-maxage=N") from a Cache-Control value.
func maxAge(cc string) (time.Duration, bool) {
	for _, tok := range []string{"s-maxage=", "max-age="} {
		if i := strings.Index(cc, tok); i >= 0 {
			rest := cc[i+len(tok):]
			end := strings.IndexAny(rest, ", ")
			if end >= 0 {
				rest = rest[:end]
			}
			if n, err := strconv.Atoi(strings.TrimSpace(rest)); err == nil && n > 0 {
				return time.Duration(n) * time.Second, true
			}
		}
	}
	return 0, false
}

// cacheWriter tees the (uncompressed) backend response body into a
// buffer, up to a limit, so a cacheable response can be stored while it
// streams to the client. It sits before the compression writer.
type cacheWriter struct {
	http.ResponseWriter
	limit    int64
	status   int
	buf      bytes.Buffer
	overflow bool
}

func (cw *cacheWriter) WriteHeader(code int) {
	if code >= 200 && cw.status == 0 {
		cw.status = code
	}
	cw.ResponseWriter.WriteHeader(code)
}

func (cw *cacheWriter) Write(p []byte) (int, error) {
	if cw.status == 0 {
		cw.status = http.StatusOK
	}
	if !cw.overflow {
		if int64(cw.buf.Len())+int64(len(p)) > cw.limit {
			cw.overflow = true
			cw.buf.Reset()
		} else {
			cw.buf.Write(p)
		}
	}
	return cw.ResponseWriter.Write(p)
}

// Unwrap exposes the wrapped writer for Hijack/Flush.
func (cw *cacheWriter) Unwrap() http.ResponseWriter { return cw.ResponseWriter }

// entryFrom builds a cache entry from a completed cacheWriter, or nil
// when the response should not be stored.
func entryFrom(cw *cacheWriter, respHeader http.Header, c *vhost.Cache) *cache.Entry {
	if cw.overflow {
		return nil
	}
	ttl := ttlFor(respHeader, cw.status, c)
	if ttl <= 0 {
		return nil
	}
	// Store an uncompressed representation: drop the encoding/length that
	// the compression layer set, keep the rest.
	h := make(http.Header, len(respHeader))
	for k, vs := range respHeader {
		switch http.CanonicalHeaderKey(k) {
		case "Content-Encoding", "Content-Length", "Transfer-Encoding", "Connection", "Gated-Ray-Id":
			continue
		}
		h[k] = append([]string(nil), vs...)
	}
	body := append([]byte(nil), cw.buf.Bytes()...)
	return &cache.Entry{Status: cw.status, Header: h, Body: body, Expires: time.Now().Add(ttl)}
}
