package balancer

import (
	"hash/fnv"
	"math/rand/v2"
	"net/http"
)

// Strategy picks one backend among the available candidates. New
// strategies are added here and registered by name; the rest of the
// codebase is untouched.
type Strategy interface {
	pick(p *Pool, cands []*Backend, req *http.Request, clientIP string) *Backend
}

var strategies = map[string]func() Strategy{
	"round_robin": func() Strategy { return roundRobin{} },
	"least_conn":  func() Strategy { return leastConn{} },
	"ip_hash":     func() Strategy { return ipHash{} },
	"uri_hash":    func() Strategy { return uriHash{} },
	"random":      func() Strategy { return randomPick{} },
}

// KnownStrategy reports whether name is a registered strategy.
func KnownStrategy(name string) bool {
	_, ok := strategies[name]
	return ok
}

// totalWeight sums candidate weights (each >= 1 by construction).
func totalWeight(cands []*Backend) int {
	t := 0
	for _, b := range cands {
		t += b.Weight
	}
	return t
}

// atWeight maps n in [0, totalWeight) onto a backend by cumulative
// weight ranges.
func atWeight(cands []*Backend, n int) *Backend {
	for _, b := range cands {
		if n < b.Weight {
			return b
		}
		n -= b.Weight
	}
	return cands[len(cands)-1]
}

// roundRobin: weighted rotation via a pool-wide atomic counter.
type roundRobin struct{}

func (roundRobin) pick(p *Pool, cands []*Backend, _ *http.Request, _ string) *Backend {
	n := int((p.rr.Add(1) - 1) % uint64(totalWeight(cands)))
	return atWeight(cands, n)
}

// leastConn: fewest in-flight requests, weighted (active/weight).
type leastConn struct{}

func (leastConn) pick(_ *Pool, cands []*Backend, _ *http.Request, _ string) *Backend {
	best := cands[0]
	for _, b := range cands[1:] {
		// b.active/b.weight < best.active/best.weight, without division.
		if b.Active()*int64(best.Weight) < best.Active()*int64(b.Weight) {
			best = b
		}
	}
	return best
}

// ipHash: client affinity by (real) IP.
type ipHash struct{}

func (ipHash) pick(_ *Pool, cands []*Backend, _ *http.Request, clientIP string) *Backend {
	return atWeight(cands, hash32(clientIP)%totalWeight(cands))
}

// uriHash: affinity by request path (useful for caches behind gated).
type uriHash struct{}

func (uriHash) pick(_ *Pool, cands []*Backend, req *http.Request, _ string) *Backend {
	return atWeight(cands, hash32(req.URL.Path)%totalWeight(cands))
}

// randomPick: weighted random choice.
type randomPick struct{}

func (randomPick) pick(_ *Pool, cands []*Backend, _ *http.Request, _ string) *Backend {
	return atWeight(cands, rand.IntN(totalWeight(cands)))
}

func hash32(s string) int {
	h := fnv.New32a()
	h.Write([]byte(s))
	return int(h.Sum32() & 0x7fffffff)
}
