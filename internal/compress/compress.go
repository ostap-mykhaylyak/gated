// Package compress negotiates and applies response compression
// (zstd, brotli, gzip) as a http.ResponseWriter wrapper.
package compress

import (
	"compress/gzip"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// Settings is the resolved (global + per-vhost override) compression
// configuration.
type Settings struct {
	Enabled    bool
	Algorithms []string // preference order
	MinSize    int      // bytes below which responses stay uncompressed
}

// Known reports whether name is a supported algorithm.
func Known(name string) bool {
	switch name {
	case "gzip", "br", "zstd":
		return true
	}
	return false
}

// Negotiate returns the first algorithm (in server preference order)
// that the client accepts, or "" if none.
func Negotiate(acceptEncoding string, algorithms []string) string {
	if acceptEncoding == "" {
		return ""
	}
	accepted := map[string]bool{}
	for _, part := range strings.Split(acceptEncoding, ",") {
		token := strings.TrimSpace(part)
		if i := strings.IndexByte(token, ';'); i >= 0 {
			// A quality of 0 explicitly refuses the encoding.
			params := strings.ToLower(strings.ReplaceAll(token[i+1:], " ", ""))
			if strings.HasPrefix(params, "q=") {
				if q, err := strconv.ParseFloat(params[2:], 64); err == nil && q == 0 {
					continue
				}
			}
			token = token[:i]
		}
		accepted[strings.ToLower(strings.TrimSpace(token))] = true
	}
	for _, a := range algorithms {
		if accepted[a] {
			return a
		}
	}
	return ""
}

// compressible content types (prefix match on "text/", exact on the rest).
var compressibleTypes = map[string]bool{
	"application/json":          true,
	"application/javascript":    true,
	"application/xml":           true,
	"application/xhtml+xml":     true,
	"application/rss+xml":       true,
	"application/atom+xml":      true,
	"application/manifest+json": true,
	"application/wasm":          true,
	"image/svg+xml":             true,
}

func compressible(contentType string) bool {
	if i := strings.IndexByte(contentType, ';'); i >= 0 {
		contentType = contentType[:i]
	}
	contentType = strings.TrimSpace(strings.ToLower(contentType))
	// Server-Sent Events must stream unbuffered: never compress them.
	if contentType == "text/event-stream" {
		return false
	}
	if strings.HasPrefix(contentType, "text/") {
		return true
	}
	return compressibleTypes[contentType]
}

// Wrap returns a ResponseWriter that compresses the response when the
// negotiation succeeds and the response qualifies (size, content type,
// not already encoded). The returned finish func MUST be deferred: it
// flushes the encoder trailer.
func Wrap(w http.ResponseWriter, r *http.Request, s Settings) (http.ResponseWriter, func()) {
	if !s.Enabled || len(s.Algorithms) == 0 || r.Method == http.MethodHead {
		return w, func() {}
	}
	encoding := Negotiate(r.Header.Get("Accept-Encoding"), s.Algorithms)
	if encoding == "" {
		return w, func() {}
	}
	cw := &writer{ResponseWriter: w, settings: s, encoding: encoding}
	return cw, cw.finish
}

// writer decides once, at the first WriteHeader/Write, whether the
// response qualifies for compression.
type writer struct {
	http.ResponseWriter
	settings Settings
	encoding string
	enc      io.WriteCloser
	decided  bool
	skip     bool
}

func (cw *writer) WriteHeader(code int) {
	// 1xx informational responses (e.g. 103 Early Hints) pass through
	// without finalizing the compression decision.
	if code < 200 {
		cw.ResponseWriter.WriteHeader(code)
		return
	}
	if !cw.decided {
		cw.decide(code)
	}
	cw.ResponseWriter.WriteHeader(code)
}

func (cw *writer) Write(p []byte) (int, error) {
	if !cw.decided {
		cw.WriteHeader(http.StatusOK)
	}
	if cw.skip {
		return cw.ResponseWriter.Write(p)
	}
	return cw.enc.Write(p)
}

func (cw *writer) decide(code int) {
	cw.decided = true
	h := cw.Header()
	switch {
	case code == http.StatusNoContent || code == http.StatusNotModified:
		cw.skip = true
	case h.Get("Content-Encoding") != "":
		cw.skip = true // backend already encoded it: pass through
	case !compressible(h.Get("Content-Type")):
		cw.skip = true
	default:
		if cl := h.Get("Content-Length"); cl != "" {
			if n, err := strconv.Atoi(cl); err == nil && n < cw.settings.MinSize {
				cw.skip = true
				return
			}
		}
		h.Set("Content-Encoding", cw.encoding)
		h.Del("Content-Length")
		AddVary(h, "Accept-Encoding")
		cw.enc = newEncoder(cw.encoding, cw.ResponseWriter)
	}
}

// AddVary appends token to the Vary header only if it is not already
// present (case-insensitive), so repeated passes — a compressing miss
// stored in cache, then a compressing cache hit, plus a backend that
// already set Vary — do not duplicate the token.
func AddVary(h http.Header, token string) {
	for _, v := range h.Values("Vary") {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return
			}
		}
	}
	h.Add("Vary", token)
}

func (cw *writer) finish() {
	if cw.enc != nil {
		cw.enc.Close()
	}
}

// Flush supports streaming responses (SSE, chunked HTML).
func (cw *writer) Flush() {
	if cw.enc != nil {
		if f, ok := cw.enc.(interface{ Flush() error }); ok {
			f.Flush()
		}
	}
	http.NewResponseController(cw.ResponseWriter).Flush()
}

// Unwrap exposes the wrapped writer so http.ResponseController can
// reach its Hijack (protocol upgrades) and other optional methods.
func (cw *writer) Unwrap() http.ResponseWriter { return cw.ResponseWriter }

func newEncoder(name string, w io.Writer) io.WriteCloser {
	switch name {
	case "gzip":
		return gzip.NewWriter(w)
	case "br":
		return brotli.NewWriterLevel(w, 5)
	case "zstd":
		zw, _ := zstd.NewWriter(w, zstd.WithEncoderLevel(zstd.SpeedDefault))
		return zw
	}
	panic("unreachable: unknown encoding " + name)
}
