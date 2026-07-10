package cache

import (
	"net/http"
	"testing"
	"time"
)

func entry(body string, ttl time.Duration) *Entry {
	return &Entry{Status: 200, Header: http.Header{"Content-Type": {"text/html"}}, Body: []byte(body), Expires: time.Now().Add(ttl)}
}

func TestGetSetExpiry(t *testing.T) {
	s := New(1 << 20)
	if _, ok := s.Get("k"); ok {
		t.Fatal("empty cache must miss")
	}
	s.Set("k", entry("hello", time.Minute))
	e, ok := s.Get("k")
	if !ok || string(e.Body) != "hello" {
		t.Fatalf("expected hit, got %v %q", ok, e)
	}

	s.Set("exp", entry("x", time.Millisecond))
	time.Sleep(5 * time.Millisecond)
	if _, ok := s.Get("exp"); ok {
		t.Fatal("expired entry must miss")
	}
}

func TestLRUEviction(t *testing.T) {
	// Budget fits two of these ~89-byte entries; a third evicts the
	// least-recently-used one.
	s := New(200)
	s.Set("a", entry("aaaa", time.Minute))
	s.Set("b", entry("bbbb", time.Minute))
	// Touch a so b is the LRU.
	s.Get("a")
	s.Set("c", entry("cccc", time.Minute))

	if _, ok := s.Get("b"); ok {
		t.Fatal("b should have been evicted as least-recently-used")
	}
	if _, ok := s.Get("a"); !ok {
		t.Fatal("a should still be present")
	}
	if _, ok := s.Get("c"); !ok {
		t.Fatal("c should be present")
	}
}

func TestOversizedNotStored(t *testing.T) {
	s := New(100)
	s.Set("big", entry("this body is definitely larger than the whole tiny budget of one hundred bytes for sure yes", time.Minute))
	if _, ok := s.Get("big"); ok {
		t.Fatal("entry larger than the budget must not be stored")
	}
}

func TestDisabledStore(t *testing.T) {
	s := New(0)
	s.Set("k", entry("x", time.Minute))
	if _, ok := s.Get("k"); ok {
		t.Fatal("a zero-size cache must never store")
	}
	var nilStore *Store
	nilStore.Set("k", entry("x", time.Minute)) // must not panic
	if _, ok := nilStore.Get("k"); ok {
		t.Fatal("nil store must miss")
	}
}
