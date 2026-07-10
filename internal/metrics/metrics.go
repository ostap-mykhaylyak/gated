// Package metrics keeps live in-memory counters, updated on the hot
// path at near-zero cost with sync/atomic. Snapshot() is the single
// source of truth consumed by the status socket (and, later, by the
// management API).
package metrics

import (
	"sync/atomic"
	"time"
)

// Metrics is the daemon-wide collector.
type Metrics struct {
	start time.Time

	requestsTotal atomic.Int64
	errorsTotal   atomic.Int64
	bytesOut      atomic.Int64
	inFlight      atomic.Int64

	wafInspected atomic.Int64
	wafBlocked   atomic.Int64
	wafBanned    atomic.Int64
}

// WAF counters, updated on the hot path by the WAF engine.
func (m *Metrics) WAFInspect() { m.wafInspected.Add(1) }
func (m *Metrics) WAFBlock()   { m.wafBlocked.Add(1) }
func (m *Metrics) WAFBan()     { m.wafBanned.Add(1) }

// New returns a Metrics anchored at the current time.
func New() *Metrics { return &Metrics{start: time.Now()} }

// RequestStart records an incoming request and returns the completion
// callback, to be deferred by the handler.
func (m *Metrics) RequestStart() func(bytes int64, failed bool) {
	m.requestsTotal.Add(1)
	m.inFlight.Add(1)
	return func(bytes int64, failed bool) {
		m.inFlight.Add(-1)
		m.bytesOut.Add(bytes)
		if failed {
			m.errorsTotal.Add(1)
		}
	}
}

// Snapshot is a coherent, JSON-serializable view of the live state.
// Field names are stable across versions: dashboards build on them.
type Snapshot struct {
	UptimeSeconds    float64   `json:"uptime_seconds"`
	RequestsTotal    int64     `json:"requests_total"`
	RequestsInFlight int64     `json:"requests_in_flight"`
	ErrorsTotal      int64     `json:"errors_total"`
	BytesOutTotal    int64     `json:"bytes_out_total"`
	WAFInspected     int64     `json:"waf_inspected"`
	WAFBlocked       int64     `json:"waf_blocked"`
	WAFBanned        int64     `json:"waf_banned"`
	Timestamp        time.Time `json:"timestamp"`
}

// Snapshot reads all counters atomically.
func (m *Metrics) Snapshot() Snapshot {
	return Snapshot{
		UptimeSeconds:    time.Since(m.start).Seconds(),
		RequestsTotal:    m.requestsTotal.Load(),
		RequestsInFlight: m.inFlight.Load(),
		ErrorsTotal:      m.errorsTotal.Load(),
		BytesOutTotal:    m.bytesOut.Load(),
		WAFInspected:     m.wafInspected.Load(),
		WAFBlocked:       m.wafBlocked.Load(),
		WAFBanned:        m.wafBanned.Load(),
		Timestamp:        time.Now().UTC(),
	}
}
