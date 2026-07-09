package proxy

import (
	"net"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/ostap-mykhaylyak/gated/internal/config"
)

// ipResolver resolves the real client IP: the connection's remote
// address, unless it belongs to a trusted proxy — then the configured
// header is walked right-to-left and the first untrusted hop wins.
type ipResolver struct {
	nets   []*net.IPNet
	header string
}

func newIPResolver(entries []string, header string) *ipResolver {
	r := &ipResolver{header: header}
	for _, e := range entries {
		if _, n, err := net.ParseCIDR(e); err == nil {
			r.nets = append(r.nets, n)
			continue
		}
		if ip := net.ParseIP(e); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			r.nets = append(r.nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
		// invalid entries were already skipped (with a warning) by
		// config validation
	}
	return r
}

func (r *ipResolver) trusted(ip net.IP) bool {
	for _, n := range r.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (r *ipResolver) clientIP(req *http.Request) string {
	remote := req.RemoteAddr
	if h, _, err := net.SplitHostPort(remote); err == nil {
		remote = h
	}
	rip := net.ParseIP(remote)
	if rip == nil || len(r.nets) == 0 || !r.trusted(rip) {
		return remote
	}

	// The peer is a trusted proxy: walk the header right-to-left and
	// return the first hop that is NOT a trusted proxy itself.
	var chain []string
	for _, v := range req.Header.Values(r.header) {
		for _, part := range strings.Split(v, ",") {
			if p := strings.TrimSpace(part); p != "" {
				chain = append(chain, p)
			}
		}
	}
	for i := len(chain) - 1; i >= 0; i-- {
		ip := net.ParseIP(chain[i])
		if ip == nil {
			break // garbage in the chain: stop trusting it
		}
		if !r.trusted(ip) {
			return chain[i]
		}
	}
	if len(chain) > 0 {
		if ip := net.ParseIP(chain[0]); ip != nil {
			return chain[0] // every hop trusted: leftmost is the client
		}
	}
	return remote
}

// resolverCache memoizes the resolver per *config.Config pointer, so a
// hot reload transparently swaps it while the hot path stays cheap.
type resolverCache struct {
	cfg *config.Config
	r   *ipResolver
}

type resolverHolder struct {
	p atomic.Pointer[resolverCache]
}

func (h *resolverHolder) get(cfg *config.Config) *ipResolver {
	if rc := h.p.Load(); rc != nil && rc.cfg == cfg {
		return rc.r
	}
	r := newIPResolver(cfg.Proxy.TrustedProxies, cfg.Proxy.RealIPHeader)
	h.p.Store(&resolverCache{cfg: cfg, r: r})
	return r
}
