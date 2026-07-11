package proxy

import (
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
)

func TestCertHint(t *testing.T) {
	// A cert verification error yields an actionable hint.
	if h := certHint(x509.UnknownAuthorityError{}); h == "" || !strings.Contains(h, "insecure_skip_verify") {
		t.Fatalf("cert error must produce an insecure_skip_verify hint, got %q", h)
	}
	if h := certHint(errors.New("connection refused")); h != "" {
		t.Fatalf("non-cert error must have no hint, got %q", h)
	}
}

func TestIsNavigation(t *testing.T) {
	nav := func(secFetch, accept string) bool {
		r := httptest.NewRequest("GET", "/", nil)
		if secFetch != "" {
			r.Header.Set("Sec-Fetch-Dest", secFetch)
		}
		if accept != "" {
			r.Header.Set("Accept", accept)
		}
		return isNavigation(r)
	}
	if !nav("document", "") {
		t.Fatal("Sec-Fetch-Dest: document must be a navigation")
	}
	if nav("image", "") {
		t.Fatal("an image sub-resource must not be a navigation")
	}
	if nav("style", "text/css,*/*;q=0.1") {
		t.Fatal("a style sub-resource must not be a navigation")
	}
	if !nav("", "text/html,application/xhtml+xml,application/xml;q=0.9") {
		t.Fatal("no Sec-Fetch + Accept text/html must be a navigation")
	}
	if nav("", "image/avif,image/webp,image/apng,*/*") {
		t.Fatal("no Sec-Fetch + image Accept must not be a navigation")
	}
}

func TestSelfRedirectDetection(t *testing.T) {
	req := httptest.NewRequest("GET", "https://www.petralito.it/", nil)
	req.Host = "www.petralito.it"

	// Absolute self-redirect (nginx force-SSL to the same URL) → loop.
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("Location", "https://www.petralito.it/")
	if !selfRedirect(resp, req, true) {
		t.Fatal("absolute same-URL redirect must be detected as a loop")
	}

	// Relative self-redirect ("/") also resolves to the same URL.
	resp.Header.Set("Location", "/")
	if !selfRedirect(resp, req, true) {
		t.Fatal("relative same-path redirect must be detected as a loop")
	}

	// Redirect to a different path is fine.
	resp.Header.Set("Location", "https://www.petralito.it/login")
	if selfRedirect(resp, req, true) {
		t.Fatal("redirect to a different path must not be flagged")
	}

	// Redirect to another host is fine.
	resp.Header.Set("Location", "https://other.example/")
	if selfRedirect(resp, req, true) {
		t.Fatal("redirect to another host must not be flagged")
	}

	// No Location: not a redirect loop.
	resp.Header.Del("Location")
	if selfRedirect(resp, req, true) {
		t.Fatal("no Location must not be flagged")
	}
}

func TestBindErrorHint(t *testing.T) {
	// An address-in-use on a wildcard bind gets the public-IP hint.
	err := bindError("http", "0.0.0.0:80", syscall.EADDRINUSE)
	if !strings.Contains(err.Error(), "already holds this port") ||
		!strings.Contains(err.Error(), "public IP") {
		t.Fatalf("wildcard EADDRINUSE must hint at the public IP, got: %v", err)
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatal("bindError must wrap the underlying error")
	}

	// A specific-address bind gets the port hint but not the wildcard note.
	err = bindError("https", "203.0.113.10:443", syscall.EADDRINUSE)
	if strings.Contains(err.Error(), "0.0.0.0 overlaps") {
		t.Fatalf("specific-address bind must not mention the wildcard overlap: %v", err)
	}

	// Unrelated errors pass through without the port hint.
	err = bindError("http", "0.0.0.0:80", errors.New("permission denied"))
	if strings.Contains(err.Error(), "already holds this port") {
		t.Fatalf("non-EADDRINUSE must not get the port hint: %v", err)
	}
}
