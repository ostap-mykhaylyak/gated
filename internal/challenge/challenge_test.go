package challenge

import (
	"crypto/sha256"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestJSChallengeRoundTrip(t *testing.T) {
	m := NewManager("secret", 0, time.Minute)
	token, _ := m.Issue()

	// difficulty 0: nonce is ignored, verify succeeds and issues a cookie.
	ck, ok := m.Verify(token, "", "203.0.113.5")
	if !ok || ck == nil {
		t.Fatal("valid token must verify at difficulty 0")
	}

	// The clearance cookie is accepted for the same IP...
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(ck)
	if !m.HasClearance(r, "203.0.113.5") {
		t.Fatal("clearance must be valid for the issuing IP")
	}
	// ...and rejected for a different IP (cookie theft across IPs).
	if m.HasClearance(r, "198.51.100.9") {
		t.Fatal("clearance must be bound to the client IP")
	}
}

func TestTamperedTokenRejected(t *testing.T) {
	m := NewManager("secret", 0, time.Minute)
	token, _ := m.Issue()
	if _, ok := m.Verify(token+"x", "", "1.2.3.4"); ok {
		t.Fatal("tampered token must not verify")
	}
	// A token signed with a different secret must not verify.
	other := NewManager("other-secret", 0, time.Minute)
	ot, _ := other.Issue()
	if _, ok := m.Verify(ot, "", "1.2.3.4"); ok {
		t.Fatal("token from a different secret must not verify")
	}
}

func TestExpiredClearance(t *testing.T) {
	m := NewManager("secret", 0, time.Millisecond)
	ck, ok := m.Verify(firstToken(m), "", "1.2.3.4")
	if !ok {
		t.Fatal("verify failed")
	}
	time.Sleep(5 * time.Millisecond)
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(ck)
	if m.HasClearance(r, "1.2.3.4") {
		t.Fatal("expired clearance must be rejected")
	}
}

func TestProofOfWork(t *testing.T) {
	const difficulty = 8
	m := NewManager("secret", difficulty, time.Minute)
	token, c := m.Issue()

	// A wrong nonce must fail.
	if _, ok := m.Verify(token, "0", "1.2.3.4"); ok {
		// "0" might accidentally satisfy 8 bits; guard by checking.
		if leadingZeroBits(sha(c, "0")) < difficulty {
			t.Fatal("verify accepted an invalid PoW nonce")
		}
	}

	// Solve the PoW the same way the browser would, then verify.
	nonce := solve(c, difficulty)
	if _, ok := m.Verify(token, nonce, "1.2.3.4"); !ok {
		t.Fatalf("verify rejected a valid PoW nonce %q", nonce)
	}
}

func TestNoClearanceCookie(t *testing.T) {
	m := NewManager("secret", 0, time.Minute)
	if m.HasClearance(httptest.NewRequest("GET", "/", nil), "1.2.3.4") {
		t.Fatal("a request without the cookie must not have clearance")
	}
}

// helpers

func firstToken(m *Manager) string { tok, _ := m.Issue(); return tok }

func sha(c, nonce string) []byte {
	sum := sha256.Sum256([]byte(c + ":" + nonce))
	return sum[:]
}

func solve(c string, difficulty int) string {
	for i := 0; ; i++ {
		if leadingZeroBits(sha(c, strconv.Itoa(i))) >= difficulty {
			return strconv.Itoa(i)
		}
	}
}
