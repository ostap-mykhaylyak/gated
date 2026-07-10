package session

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestVisitCookieRoundTrip(t *testing.T) {
	m := NewManager("a-secret-key", time.Hour)
	ck := m.Cookie(true)
	if ck.Name != VisitCookie || !ck.HttpOnly || !ck.Secure {
		t.Fatalf("cookie flags wrong: %+v", ck)
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(ck)
	if !m.Valid(r) {
		t.Fatal("freshly issued visit cookie must be valid")
	}
}

func TestNoCookieIsInvalid(t *testing.T) {
	m := NewManager("secret", time.Hour)
	if m.Valid(httptest.NewRequest("GET", "/", nil)) {
		t.Fatal("a request without the visit cookie must be invalid")
	}
}

func TestTamperedAndForeignSecret(t *testing.T) {
	m := NewManager("secret", time.Hour)
	ck := m.Cookie(false)
	ck.Value += "x"
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(ck)
	if m.Valid(r) {
		t.Fatal("tampered cookie must be invalid")
	}

	other := NewManager("different-secret", time.Hour)
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.AddCookie(other.Cookie(false))
	if m.Valid(r2) {
		t.Fatal("cookie signed with another secret must be invalid")
	}
}

func TestExpiredVisit(t *testing.T) {
	m := NewManager("secret", time.Millisecond)
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(m.Cookie(false))
	time.Sleep(5 * time.Millisecond)
	if m.Valid(r) {
		t.Fatal("expired visit cookie must be invalid")
	}
}
