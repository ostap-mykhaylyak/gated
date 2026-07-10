// Package session implements the lightweight "prior visit" marker used
// by the WAF `session` field: gated sets a signed cookie when a browser
// loads a normal HTML page, so sensitive endpoints (e.g. WooCommerce
// add-to-cart) can be rejected when called directly without a prior
// visit — a common database-flood pattern.
//
// It is intentionally not bound to the client IP (a visit marker, not
// an auth token): the goal is to require that a real page was rendered
// first, not to prevent cookie sharing.
package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// VisitCookie is the cookie name set on a normal page visit.
const VisitCookie = "gated_visit"

// Manager issues and verifies the visit cookie.
type Manager struct {
	secret []byte
	ttl    time.Duration
}

// NewManager returns a Manager signing with secret (must be non-empty;
// the caller resolves a persistent key).
func NewManager(secret string, ttl time.Duration) *Manager {
	if ttl <= 0 {
		ttl = 2 * time.Hour
	}
	return &Manager{secret: []byte(secret), ttl: ttl}
}

type payload struct {
	Exp int64 `json:"e"`
}

// Cookie builds a fresh visit cookie (Secure when served over TLS).
func (m *Manager) Cookie(secure bool) *http.Cookie {
	p := payload{Exp: time.Now().Add(m.ttl).UnixNano()}
	return &http.Cookie{
		Name:     VisitCookie,
		Value:    m.sign(p),
		Path:     "/",
		MaxAge:   int(m.ttl.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
}

// Valid reports whether the request carries a valid, unexpired visit
// cookie.
func (m *Manager) Valid(r *http.Request) bool {
	ck, err := r.Cookie(VisitCookie)
	if err != nil {
		return false
	}
	var p payload
	if !m.unsign(ck.Value, &p) {
		return false
	}
	return time.Now().UnixNano() <= p.Exp
}

func (m *Manager) sign(v any) string {
	body, _ := json.Marshal(v)
	mac := hmac.New(sha256.New, m.secret)
	mac.Write(body)
	return base64.RawURLEncoding.EncodeToString(body) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (m *Manager) unsign(s string, v any) bool {
	dot := strings.IndexByte(s, '.')
	if dot < 0 {
		return false
	}
	body, err := base64.RawURLEncoding.DecodeString(s[:dot])
	if err != nil {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(s[dot+1:])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, m.secret)
	mac.Write(body)
	if subtle.ConstantTimeCompare(sig, mac.Sum(nil)) != 1 {
		return false
	}
	return json.Unmarshal(body, v) == nil
}
