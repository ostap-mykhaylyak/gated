// Package balancer implements the load-balancing pool: pluggable
// strategies, per-backend runtime health state (passive + optional
// active probing), backup backends and sticky-session support.
//
// The pool owns runtime state (fails, cooldowns, in-flight counters):
// a config reload rebuilds the pool but carries the state over for
// backends whose URL is unchanged, so a vhost rewrite never resets
// backend health.
package balancer

import (
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// BackendConf is the static configuration of one backend.
type BackendConf struct {
	URL    string
	Weight int // < 1 is normalized to 1
	Backup bool
}

// StickyConf configures cookie-based session affinity, orthogonal to
// the strategy.
type StickyConf struct {
	Enabled bool
	Cookie  string
	TTL     time.Duration
}

// ActiveConf configures the optional out-of-band health prober.
type ActiveConf struct {
	Path         string
	Interval     time.Duration
	Timeout      time.Duration
	ExpectStatus int
}

// HealthConf configures health checking. Passive checking (MaxFails /
// Cooldown) is always on; Active is optional.
type HealthConf struct {
	MaxFails int
	Cooldown time.Duration
	Active   *ActiveConf
}

// Conf is the full pool configuration.
type Conf struct {
	Strategy string
	Backends []BackendConf
	Sticky   StickyConf
	Health   HealthConf
}

// state is the runtime state of a backend. It is a separate,
// pointer-shared struct so that a pool rebuild can hand the SAME state
// to the new Backend object: in-flight requests still referencing the
// old object keep decrementing the shared counter.
type state struct {
	fails     atomic.Int32
	downUntil atomic.Int64 // unix nanos; 0 = up
	active    atomic.Int64 // in-flight requests
}

// Backend is one upstream server plus its shared runtime state.
type Backend struct {
	URL    *url.URL
	Weight int
	Backup bool
	ID     string // stable hash of the URL, used as sticky cookie value

	st *state
}

// Available reports whether the backend may receive traffic now.
func (b *Backend) Available() bool {
	du := b.st.downUntil.Load()
	return du == 0 || time.Now().UnixNano() >= du
}

// Acquire/Release track in-flight requests (least_conn input).
func (b *Backend) Acquire() { b.st.active.Add(1) }
func (b *Backend) Release() { b.st.active.Add(-1) }

// Active returns the current number of in-flight requests.
func (b *Backend) Active() int64 { return b.st.active.Load() }

// Pool selects backends for one vhost.
type Pool struct {
	all       []*Backend
	primaries []*Backend
	backups   []*Backend
	strategy  Strategy
	sticky    StickyConf
	health    HealthConf

	rr        atomic.Uint64
	stop      chan struct{}
	closeOnce sync.Once
}

// New builds a pool. If prev is non-nil, runtime state is carried over
// for backends whose URL is unchanged.
func New(conf Conf, prev *Pool) (*Pool, error) {
	factory, ok := strategies[conf.Strategy]
	if !ok {
		return nil, fmt.Errorf("unknown load balancing strategy %q", conf.Strategy)
	}
	prevState := map[string]*state{}
	if prev != nil {
		for _, b := range prev.all {
			prevState[b.URL.String()] = b.st
		}
	}

	p := &Pool{
		strategy: factory(),
		sticky:   conf.Sticky,
		health:   conf.Health,
		stop:     make(chan struct{}),
	}
	for _, bc := range conf.Backends {
		u, err := url.Parse(bc.URL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf("invalid backend url %q", bc.URL)
		}
		w := bc.Weight
		if w < 1 {
			w = 1
		}
		b := &Backend{URL: u, Weight: w, Backup: bc.Backup, ID: idFor(u), st: &state{}}
		if st := prevState[u.String()]; st != nil {
			b.st = st
		}
		p.all = append(p.all, b)
		if bc.Backup {
			p.backups = append(p.backups, b)
		} else {
			p.primaries = append(p.primaries, b)
		}
	}
	if len(p.all) == 0 {
		return nil, errors.New("no backends configured")
	}
	// All-backup pools make no sense: treat them all as primaries.
	if len(p.primaries) == 0 {
		p.primaries, p.backups = p.backups, nil
	}
	if conf.Health.Active != nil {
		p.startProber(*conf.Health.Active)
	}
	return p, nil
}

// Sticky returns the sticky-session configuration.
func (p *Pool) Sticky() StickyConf { return p.sticky }

// Backends returns all backends (for status/introspection).
func (p *Pool) Backends() []*Backend { return p.all }

// Close stops the active prober, if any. Safe to call more than once.
func (p *Pool) Close() { p.closeOnce.Do(func() { close(p.stop) }) }

// Pick selects a backend: available primaries first, then available
// backups. Sticky affinity, when enabled and valid, wins over the
// strategy. Returns nil when nothing is available.
func (p *Pool) Pick(req *http.Request, clientIP string) *Backend {
	cands := available(p.primaries)
	if len(cands) == 0 {
		cands = available(p.backups)
	}
	if len(cands) == 0 {
		return nil
	}
	if p.sticky.Enabled {
		if c, err := req.Cookie(p.sticky.Cookie); err == nil {
			for _, b := range cands {
				if b.ID == c.Value {
					return b
				}
			}
		}
	}
	if len(cands) == 1 {
		return cands[0]
	}
	return p.strategy.pick(p, cands, req, clientIP)
}

// Report feeds the passive health check with the outcome of a proxied
// request: after MaxFails consecutive transport failures the backend
// is put in cooldown, then retried automatically.
func (p *Pool) Report(b *Backend, success bool) {
	if success {
		b.st.fails.Store(0)
		return
	}
	if int(b.st.fails.Add(1)) >= p.health.MaxFails {
		b.st.fails.Store(0)
		b.st.downUntil.Store(time.Now().Add(p.health.Cooldown).UnixNano())
	}
}

// startProber runs the optional active health check loop until Close.
func (p *Pool) startProber(a ActiveConf) {
	client := &http.Client{
		Timeout: a.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	go func() {
		t := time.NewTicker(a.Interval)
		defer t.Stop()
		for {
			select {
			case <-p.stop:
				return
			case <-t.C:
				for _, b := range p.all {
					probeURL := b.URL.Scheme + "://" + b.URL.Host + a.Path
					resp, err := client.Get(probeURL)
					ok := err == nil && resp.StatusCode == a.ExpectStatus
					if resp != nil {
						io.Copy(io.Discard, resp.Body)
						resp.Body.Close()
					}
					if ok {
						b.st.fails.Store(0)
						b.st.downUntil.Store(0)
					} else {
						// Down until (at least) the next probe round.
						b.st.downUntil.Store(time.Now().Add(a.Interval + a.Timeout).UnixNano())
					}
				}
			}
		}
	}()
}

func available(backends []*Backend) []*Backend {
	out := make([]*Backend, 0, len(backends))
	for _, b := range backends {
		if b.Available() {
			out = append(out, b)
		}
	}
	return out
}

func idFor(u *url.URL) string {
	h := fnv.New64a()
	h.Write([]byte(u.String()))
	return fmt.Sprintf("%016x", h.Sum64())
}
