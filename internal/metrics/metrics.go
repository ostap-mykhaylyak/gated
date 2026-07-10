// Package metrics keeps live in-memory counters, updated on the hot
// path at near-zero cost with sync/atomic. Snapshot() is the single
// source of truth consumed by the status socket (and, later, by the
// management API).
package metrics

import (
	"sort"
	"sync/atomic"
	"time"
)

// latencyBoundsMs are the upper edges (milliseconds) of the fixed
// request-latency histogram buckets. A request is counted in the first
// bucket whose edge is >= its latency; anything slower lands in the
// overflow bucket.
var latencyBoundsMs = []float64{1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000}

// histogram is a lock-free fixed-bucket latency histogram.
type histogram struct {
	buckets []atomic.Int64 // len(latencyBoundsMs)+1 (last = overflow)
}

func newHistogram() *histogram {
	return &histogram{buckets: make([]atomic.Int64, len(latencyBoundsMs)+1)}
}

func (h *histogram) observe(d time.Duration) {
	ms := float64(d) / float64(time.Millisecond)
	h.buckets[sort.SearchFloat64s(latencyBoundsMs, ms)].Add(1)
}

// percentiles returns, for each p in [0,1], the upper edge (ms) of the
// bucket where the cumulative count crosses p. Zero when no data.
func (h *histogram) percentiles(ps ...float64) []float64 {
	counts := make([]int64, len(h.buckets))
	var total int64
	for i := range h.buckets {
		counts[i] = h.buckets[i].Load()
		total += counts[i]
	}
	out := make([]float64, len(ps))
	if total == 0 {
		return out
	}
	for j, p := range ps {
		target := int64(float64(total) * p)
		if target < 1 {
			target = 1
		}
		var cum int64
		for i, c := range counts {
			cum += c
			if cum >= target {
				if i < len(latencyBoundsMs) {
					out[j] = latencyBoundsMs[i]
				} else {
					out[j] = latencyBoundsMs[len(latencyBoundsMs)-1] // overflow: report the max edge
				}
				break
			}
		}
	}
	return out
}

// Metrics is the daemon-wide collector.
type Metrics struct {
	start time.Time
	lat   *histogram

	requestsTotal atomic.Int64
	errorsTotal   atomic.Int64
	bytesOut      atomic.Int64
	inFlight      atomic.Int64

	wafInspected  atomic.Int64
	wafBlocked    atomic.Int64
	wafBanned     atomic.Int64
	wafChallenged atomic.Int64
	wafCleared    atomic.Int64

	cacheHits   atomic.Int64
	cacheMisses atomic.Int64
}

// Cache counters.
func (m *Metrics) CacheHit()  { m.cacheHits.Add(1) }
func (m *Metrics) CacheMiss() { m.cacheMisses.Add(1) }

// WAF counters, updated on the hot path by the WAF engine.
func (m *Metrics) WAFInspect()   { m.wafInspected.Add(1) }
func (m *Metrics) WAFBlock()     { m.wafBlocked.Add(1) }
func (m *Metrics) WAFBan()       { m.wafBanned.Add(1) }
func (m *Metrics) WAFChallenge() { m.wafChallenged.Add(1) }
func (m *Metrics) WAFClear()     { m.wafCleared.Add(1) }

// New returns a Metrics anchored at the current time.
func New() *Metrics { return &Metrics{start: time.Now(), lat: newHistogram()} }

// RequestStart records an incoming request and returns the completion
// callback, to be deferred by the handler. The callback measures the
// request latency itself, so callers need not time anything.
func (m *Metrics) RequestStart() func(bytes int64, failed bool) {
	m.requestsTotal.Add(1)
	m.inFlight.Add(1)
	t0 := time.Now()
	return func(bytes int64, failed bool) {
		m.inFlight.Add(-1)
		m.bytesOut.Add(bytes)
		if failed {
			m.errorsTotal.Add(1)
		}
		m.lat.observe(time.Since(t0))
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
	WAFChallenged    int64     `json:"waf_challenged"`
	WAFCleared       int64     `json:"waf_cleared"`
	P50LatencyMs     float64   `json:"p50_latency_ms"`
	P95LatencyMs     float64   `json:"p95_latency_ms"`
	P99LatencyMs     float64   `json:"p99_latency_ms"`
	CacheHits        int64     `json:"cache_hits"`
	CacheMisses      int64     `json:"cache_misses"`
	Timestamp        time.Time `json:"timestamp"`
}

// Snapshot reads all counters atomically.
func (m *Metrics) Snapshot() Snapshot {
	lp := m.lat.percentiles(0.50, 0.95, 0.99)
	return Snapshot{
		UptimeSeconds:    time.Since(m.start).Seconds(),
		RequestsTotal:    m.requestsTotal.Load(),
		RequestsInFlight: m.inFlight.Load(),
		ErrorsTotal:      m.errorsTotal.Load(),
		BytesOutTotal:    m.bytesOut.Load(),
		WAFInspected:     m.wafInspected.Load(),
		WAFBlocked:       m.wafBlocked.Load(),
		WAFBanned:        m.wafBanned.Load(),
		WAFChallenged:    m.wafChallenged.Load(),
		WAFCleared:       m.wafCleared.Load(),
		P50LatencyMs:     lp[0],
		P95LatencyMs:     lp[1],
		P99LatencyMs:     lp[2],
		CacheHits:        m.cacheHits.Load(),
		CacheMisses:      m.cacheMisses.Load(),
		Timestamp:        time.Now().UTC(),
	}
}
