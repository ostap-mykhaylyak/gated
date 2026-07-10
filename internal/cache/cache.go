// Package cache is a bounded in-memory HTTP response cache with LRU
// eviction. It stores the UNCOMPRESSED backend response; the proxy
// re-compresses per client on serve, so one entry serves gzip/br/zstd
// and identity alike.
package cache

import (
	"container/list"
	"net/http"
	"sync"
	"time"
)

// Entry is one cached response.
type Entry struct {
	Status  int
	Header  http.Header
	Body    []byte
	Expires time.Time
}

func (e *Entry) size() int64 {
	n := int64(len(e.Body)) + 64
	for k, vs := range e.Header {
		n += int64(len(k))
		for _, v := range vs {
			n += int64(len(v))
		}
	}
	return n
}

type node struct {
	key   string
	entry *Entry
	bytes int64
}

// Store is a thread-safe LRU cache bounded by total bytes.
type Store struct {
	mu    sync.Mutex
	max   int64
	bytes int64
	ll    *list.List // front = most recently used
	items map[string]*list.Element
}

// New returns a Store holding at most max bytes (max <= 0 disables it).
func New(max int64) *Store {
	return &Store{max: max, ll: list.New(), items: map[string]*list.Element{}}
}

// Get returns a live (non-expired) entry, moving it to most-recent.
func (s *Store) Get(key string) (*Entry, bool) {
	if s == nil || s.max <= 0 {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	el, ok := s.items[key]
	if !ok {
		return nil, false
	}
	n := el.Value.(*node)
	if time.Now().After(n.entry.Expires) {
		s.removeElement(el)
		return nil, false
	}
	s.ll.MoveToFront(el)
	return n.entry, true
}

// Set stores an entry, evicting least-recently-used entries to stay
// within the byte budget. Entries larger than the whole budget are
// dropped.
func (s *Store) Set(key string, e *Entry) {
	if s == nil || s.max <= 0 {
		return
	}
	sz := e.size()
	if sz > s.max {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.items[key]; ok {
		s.removeElement(el)
	}
	el := s.ll.PushFront(&node{key: key, entry: e, bytes: sz})
	s.items[key] = el
	s.bytes += sz
	for s.bytes > s.max {
		back := s.ll.Back()
		if back == nil {
			break
		}
		s.removeElement(back)
	}
}

func (s *Store) removeElement(el *list.Element) {
	n := el.Value.(*node)
	s.ll.Remove(el)
	delete(s.items, n.key)
	s.bytes -= n.bytes
}

// Stats returns the current entry count and byte size.
func (s *Store) Stats() (entries int, bytes int64) {
	if s == nil {
		return 0, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items), s.bytes
}
