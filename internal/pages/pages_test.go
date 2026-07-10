package pages

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMessagePage(t *testing.T) {
	p, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	p.Message(rec, MessageData{Code: 503, Title: "Service Unavailable",
		Message: "backend down", Host: "app.test", RequestID: "abc123"})

	if rec.Code != 503 {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content-type = %q", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{"503", "Service Unavailable", "backend down", "app.test", "abc123", "gated"} {
		if !strings.Contains(body, want) {
			t.Fatalf("page missing %q", want)
		}
	}
}

func TestChallengePageEmbedsToken(t *testing.T) {
	p, _ := New("")
	rec := httptest.NewRecorder()
	p.Challenge(rec, ChallengeData{Token: "tok.sig", C: "chal", Difficulty: 12,
		Endpoint: "/.gated/challenge", Host: "app.test", RequestID: "ray1"})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("challenge page must be 403, got %d", rec.Code)
	}
	body := rec.Body.String()
	// html/template renders JS-context strings as quoted literals.
	for _, want := range []string{`"tok.sig"`, `"chal"`, "12", `"/.gated/challenge"`, "Checking your browser"} {
		if !strings.Contains(body, want) {
			t.Fatalf("challenge page missing %q", want)
		}
	}
}

func TestOverrideFromDir(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "message.html"), []byte("CUSTOM {{.Code}} {{.RequestID}}"), 0o640)

	p, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	p.Message(rec, MessageData{Code: 404, RequestID: "xyz"})
	if got := rec.Body.String(); got != "CUSTOM 404 xyz" {
		t.Fatalf("override not applied: %q", got)
	}
}
