// Package challenge implements the browser-challenge mechanism behind
// the WAF "challenge" action: an interstitial that must execute JS
// (and optionally solve a small SHA-256 proof of work) to obtain a
// signed, short-lived clearance cookie bound to the client IP.
//
// It is deliberately self-contained (HMAC-signed tokens, no server-
// side session store): a passed challenge is entirely represented by
// the clearance cookie, so it scales and survives across workers.
package challenge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"
)

// ClearanceCookie is the cookie name issued to a passed client.
const ClearanceCookie = "gated_clearance"

// Manager issues and verifies challenge tokens and clearance cookies.
type Manager struct {
	secret     []byte
	difficulty int
	ttl        time.Duration
}

// NewManager returns a Manager. An empty secret means a random key is
// generated per process start (clearances then reset on restart).
func NewManager(secret string, difficulty int, ttl time.Duration) *Manager {
	s := []byte(secret)
	if len(s) == 0 {
		s = make([]byte, 32)
		rand.Read(s)
	}
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	return &Manager{secret: s, difficulty: difficulty, ttl: ttl}
}

// Difficulty is the PoW leading-zero-bit target (0 = JS challenge only).
func (m *Manager) Difficulty() int { return m.difficulty }

// tokenPayload is embedded (signed) in a challenge token.
type tokenPayload struct {
	C   string `json:"c"` // random challenge string, PoW input
	Exp int64  `json:"e"` // unix nanos
	D   int    `json:"d"` // difficulty
}

// clearancePayload is embedded (signed) in a clearance cookie.
type clearancePayload struct {
	Exp int64  `json:"e"`
	IP  string `json:"i"` // hash of the client IP, not the IP itself
}

// Issue returns a fresh challenge token and its PoW input string C.
// The token is valid for a short window (2 minutes).
func (m *Manager) Issue() (token, c string) {
	raw := make([]byte, 16)
	rand.Read(raw)
	c = base64.RawURLEncoding.EncodeToString(raw)
	p := tokenPayload{C: c, Exp: time.Now().Add(2 * time.Minute).UnixNano(), D: m.difficulty}
	return m.sign(p), c
}

// Verify checks a solved token and, on success, returns the clearance
// cookie to set. nonce is the PoW solution (ignored when difficulty 0).
func (m *Manager) Verify(token, nonce, clientIP string) (*http.Cookie, bool) {
	var p tokenPayload
	if !m.unsign(token, &p) {
		return nil, false
	}
	if time.Now().UnixNano() > p.Exp {
		return nil, false
	}
	if p.D > 0 && !powOK(p.C, nonce, p.D) {
		return nil, false
	}
	return m.clearance(clientIP), true
}

// HasClearance reports whether the request carries a valid clearance
// cookie for this client IP.
func (m *Manager) HasClearance(r *http.Request, clientIP string) bool {
	ck, err := r.Cookie(ClearanceCookie)
	if err != nil {
		return false
	}
	var p clearancePayload
	if !m.unsign(ck.Value, &p) {
		return false
	}
	if time.Now().UnixNano() > p.Exp {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(p.IP), []byte(m.ipHash(clientIP))) == 1
}

// clearance builds the clearance cookie for clientIP.
func (m *Manager) clearance(clientIP string) *http.Cookie {
	p := clearancePayload{Exp: time.Now().Add(m.ttl).UnixNano(), IP: m.ipHash(clientIP)}
	return &http.Cookie{
		Name:     ClearanceCookie,
		Value:    m.sign(p),
		Path:     "/",
		MaxAge:   int(m.ttl.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

func (m *Manager) ipHash(ip string) string {
	h := hmac.New(sha256.New, m.secret)
	h.Write([]byte("ip:" + ip))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:12])
}

// sign serializes v to JSON and returns base64(json) + "." + base64(hmac).
func (m *Manager) sign(v any) string {
	body, _ := json.Marshal(v)
	mac := hmac.New(sha256.New, m.secret)
	mac.Write(body)
	return base64.RawURLEncoding.EncodeToString(body) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// unsign verifies the signature and decodes the payload into v.
func (m *Manager) unsign(s string, v any) bool {
	dot := -1
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			dot = i
			break
		}
	}
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

// powOK verifies that sha256(c + ":" + nonce) has at least d leading
// zero bits.
func powOK(c, nonce string, d int) bool {
	sum := sha256.Sum256([]byte(c + ":" + nonce))
	return leadingZeroBits(sum[:]) >= d
}

func leadingZeroBits(b []byte) int {
	n := 0
	for _, x := range b {
		if x == 0 {
			n += 8
			continue
		}
		for bit := 7; bit >= 0; bit-- {
			if x&(1<<uint(bit)) == 0 {
				n++
			} else {
				return n
			}
		}
	}
	return n
}
