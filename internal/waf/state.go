package waf

import (
	"sync"
	"time"
)

// stateStore holds the fail2ban-style runtime state: per-(rule,IP)
// fixed-window counters and per-IP bans. In-memory only: bans do not
// survive a restart (acceptable for a short-lived edge ban).
type stateStore struct {
	mu   sync.Mutex
	hits map[string]*counter // key: ruleID + "\x00" + ip
	bans map[string]int64    // key: ip -> ban-until (unix nanos)
	stop chan struct{}
	once sync.Once
}

type counter struct {
	count       int
	windowStart int64 // unix nanos
}

func newStateStore() *stateStore {
	s := &stateStore{
		hits: map[string]*counter{},
		bans: map[string]int64{},
		stop: make(chan struct{}),
	}
	go s.gc()
	return s
}

// banned reports whether ip is currently banned.
func (s *stateStore) banned(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	until, ok := s.bans[ip]
	if !ok {
		return false
	}
	if time.Now().UnixNano() >= until {
		delete(s.bans, ip)
		return false
	}
	return true
}

// hit records one match of a tracked rule for ip and reports whether
// this hit pushed it over the threshold (i.e. a ban was just applied).
// Fixed-window counting: the window resets once it elapses.
func (s *stateStore) hit(ruleID, ip string, t *Track) bool {
	now := time.Now().UnixNano()
	key := ruleID + "\x00" + ip

	s.mu.Lock()
	defer s.mu.Unlock()

	// Already banned: keep it banned, don't double-count.
	if until, ok := s.bans[ip]; ok && now < until {
		return false
	}

	c := s.hits[key]
	if c == nil || now-c.windowStart > int64(t.Window.Std()) {
		c = &counter{windowStart: now}
		s.hits[key] = c
	}
	c.count++
	if c.count >= t.Threshold {
		s.bans[ip] = now + int64(t.BanTime.Std())
		delete(s.hits, key)
		return true
	}
	return false
}

// activeBans returns the number of non-expired bans (for status).
func (s *stateStore) activeBans() int {
	now := time.Now().UnixNano()
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, until := range s.bans {
		if now < until {
			n++
		}
	}
	return n
}

// gc periodically purges expired bans and stale counters.
func (s *stateStore) gc() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			now := time.Now().UnixNano()
			s.mu.Lock()
			for ip, until := range s.bans {
				if now >= until {
					delete(s.bans, ip)
				}
			}
			// Counters older than an hour are certainly past any window.
			for k, c := range s.hits {
				if now-c.windowStart > int64(time.Hour) {
					delete(s.hits, k)
				}
			}
			s.mu.Unlock()
		}
	}
}

func (s *stateStore) close() { s.once.Do(func() { close(s.stop) }) }
