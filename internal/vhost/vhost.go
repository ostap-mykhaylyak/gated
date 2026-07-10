// Package vhost loads and validates the per-virtual-host configuration
// files (/etc/gated/vhosts/*.yaml, one file per vhost) and keeps them
// hot-reloaded in a Store.
//
// Reload rule: an invalid file NEVER touches the running state. If the
// vhost was already loaded, its last good version keeps serving
// (Traefik behavior); the error is logged. A deleted file removes the
// vhost.
package vhost

import (
	"crypto/tls"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/quic-go/quic-go/http3"
	"gopkg.in/yaml.v3"

	"github.com/ostap-mykhaylyak/gated/internal/balancer"
	"github.com/ostap-mykhaylyak/gated/internal/compress"
	"github.com/ostap-mykhaylyak/gated/internal/config"
	"github.com/ostap-mykhaylyak/gated/internal/waf"
)

// TLSConf selects the certificate for the vhost. Empty = conventional
// Let's Encrypt lookup by host name.
type TLSConf struct {
	CertName string `yaml:"cert_name"` // force a letsencrypt dir name
	CertFile string `yaml:"cert_file"` // full override outside letsencrypt
	KeyFile  string `yaml:"key_file"`
}

// BackendConf is one upstream in the vhost file. URL carries the full
// address: scheme (http/https), any IP or hostname, and any port —
// e.g. "http://192.168.1.50:8080" or "https://10.0.0.5:443".
type BackendConf struct {
	URL    string `yaml:"url"`
	Weight int    `yaml:"weight"`
	Backup bool   `yaml:"backup"`
}

// BackendTLS tunes the TLS handshake gated performs toward HTTPS
// backends. It only matters when a backend URL uses https://.
type BackendTLS struct {
	// ServerName overrides the SNI / certificate-verification name.
	// Needed when the backend is addressed by IP but presents a cert
	// for a hostname (e.g. the public host). Empty = use the backend
	// URL host.
	ServerName string `yaml:"server_name"`
	// InsecureSkipVerify accepts self-signed or mismatched backend
	// certificates (use only on a trusted private network).
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
}

// Sticky configures cookie-based session affinity.
type Sticky struct {
	Enabled bool            `yaml:"enabled"`
	Cookie  string          `yaml:"cookie"`
	TTL     config.Duration `yaml:"ttl"`
}

// PassiveHealth mirrors the global health defaults, per-vhost.
type PassiveHealth struct {
	MaxFails int             `yaml:"max_fails"`
	Cooldown config.Duration `yaml:"cooldown"`
}

// ActiveHealth configures the optional out-of-band prober.
type ActiveHealth struct {
	Enabled      bool            `yaml:"enabled"`
	Path         string          `yaml:"path"`
	Interval     config.Duration `yaml:"interval"`
	Timeout      config.Duration `yaml:"timeout"`
	ExpectStatus int             `yaml:"expect_status"`
}

// HealthConf groups passive + active health checking.
type HealthConf struct {
	Passive PassiveHealth `yaml:"passive"`
	Active  ActiveHealth  `yaml:"active"`
}

// LB is the load balancing section.
type LB struct {
	Strategy string     `yaml:"strategy"`
	Sticky   Sticky     `yaml:"sticky"`
	Health   HealthConf `yaml:"health"`
}

// Compression overrides the global defaults; nil pointers mean
// "inherit".
type Compression struct {
	Enabled    *bool    `yaml:"enabled"`
	Algorithms []string `yaml:"algorithms"`
	MinSize    *int     `yaml:"min_size"`
}

// WAFOverride tweaks the WAF for this vhost; nil pointers mean
// "inherit the global setting".
type WAFOverride struct {
	Enabled *bool    `yaml:"enabled"`
	Mode    string   `yaml:"mode"`    // block | detect; empty = inherit
	Exclude []string `yaml:"exclude"` // rule IDs to skip on this vhost
}

// HeaderOps mutates a header set: Remove runs first, then Set
// (overrides), then Add (appends).
type HeaderOps struct {
	Set    map[string]string `yaml:"set"`
	Add    map[string]string `yaml:"add"`
	Remove []string          `yaml:"remove"`
}

// Headers holds request- and response-header mutations for the vhost
// (e.g. security headers on responses, custom headers to the backend).
type Headers struct {
	Request  HeaderOps `yaml:"request"`
	Response HeaderOps `yaml:"response"`
}

// Route matches a subset of a vhost's requests by path (and optionally
// method) and can send them to their own backends, rewrite the path,
// and/or split a share to a canary. Routes are tried in order; the
// first match wins. A request matching no route uses the vhost's
// default backends.
type Route struct {
	PathPrefix     string        `yaml:"path_prefix"`
	PathRegex      string        `yaml:"path_regex"`
	Methods        []string      `yaml:"methods"`
	Backends       []BackendConf `yaml:"backends"`        // empty = vhost default backends
	StripPrefix    string        `yaml:"strip_prefix"`    // remove this prefix before proxying
	RewriteRegex   string        `yaml:"rewrite_regex"`   // regex applied to the path
	RewriteReplace string        `yaml:"rewrite_replace"` // replacement for rewrite_regex
	Canary         *Canary       `yaml:"canary"`

	Pool    *balancer.Pool `yaml:"-"`
	regex   *regexp.Regexp
	rewrite *regexp.Regexp
	methods map[string]bool
}

// Canary sends a share of a route's traffic to an alternate backend set
// (blue-green / canary). Selection is by header, then cookie, then a
// random weight (percent).
type Canary struct {
	Backends    []BackendConf `yaml:"backends"`
	Weight      int           `yaml:"weight"`       // 0-100 percent routed to the canary
	Header      string        `yaml:"header"`       // route to canary if this header is present
	HeaderValue string        `yaml:"header_value"` // ...and equals this value (optional)
	Cookie      string        `yaml:"cookie"`       // route to canary if this cookie is present

	Pool *balancer.Pool `yaml:"-"`
}

// Hit reports whether the request should go to the canary pool.
func (r *Route) Hit(req *http.Request) bool {
	c := r.Canary
	if c == nil || c.Pool == nil {
		return false
	}
	if c.Header != "" {
		v := req.Header.Get(c.Header)
		if c.HeaderValue != "" {
			return v == c.HeaderValue
		}
		return v != ""
	}
	if c.Cookie != "" {
		_, err := req.Cookie(c.Cookie)
		return err == nil
	}
	if c.Weight > 0 {
		return rand.IntN(100) < c.Weight
	}
	return false
}

// RewritePath applies the route's strip_prefix and/or regex rewrite to
// path, returning the possibly-rewritten path.
func (r *Route) RewritePath(path string) string {
	if r.StripPrefix != "" && strings.HasPrefix(path, r.StripPrefix) {
		path = path[len(r.StripPrefix):]
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
	}
	if r.rewrite != nil {
		path = r.rewrite.ReplaceAllString(path, r.RewriteReplace)
	}
	return path
}

// Cache is the per-vhost response-cache policy.
type Cache struct {
	Enabled         bool            `yaml:"enabled"`
	TTL             config.Duration `yaml:"ttl"`              // fallback TTL when the backend sets no Cache-Control max-age
	MicroTTL        config.Duration `yaml:"micro_ttl"`        // short TTL for text/html without Cache-Control (spike shield)
	MaxObjectBytes  int64           `yaml:"max_object_bytes"` // largest response cached; default 5 MiB
	CacheableStatus []int           `yaml:"cacheable_status"` // default [200]
	BypassCookies   []string        `yaml:"bypass_cookies"`   // request cookie name prefixes that skip the cache

	statusOK map[int]bool `yaml:"-"`
}

// resolveCache fills the cache policy defaults after parsing.
func (v *VHost) resolveCache() {
	if !v.Cache.Enabled {
		return
	}
	if v.Cache.MaxObjectBytes <= 0 {
		v.Cache.MaxObjectBytes = 5 * 1024 * 1024
	}
	if len(v.Cache.CacheableStatus) == 0 {
		v.Cache.CacheableStatus = []int{200}
	}
	v.Cache.statusOK = make(map[int]bool, len(v.Cache.CacheableStatus))
	for _, s := range v.Cache.CacheableStatus {
		v.Cache.statusOK[s] = true
	}
}

// CacheableStatusOK reports whether status may be cached for this vhost.
func (c *Cache) CacheableStatusOK(status int) bool { return c.statusOK[status] }

// Bypassed reports whether the request must skip the cache (a bypass
// cookie by name prefix, or an Authorization header).
func (c *Cache) Bypassed(r *http.Request) bool {
	if r.Header.Get("Authorization") != "" {
		return true
	}
	for _, ck := range r.Cookies() {
		for _, pref := range c.BypassCookies {
			if strings.HasPrefix(ck.Name, pref) {
				return true
			}
		}
	}
	return false
}

// CORS configures cross-origin resource sharing for the vhost.
type CORS struct {
	Enabled          bool            `yaml:"enabled"`
	AllowOrigins     []string        `yaml:"allow_origins"` // exact origins or "*"
	AllowMethods     []string        `yaml:"allow_methods"`
	AllowHeaders     []string        `yaml:"allow_headers"`
	ExposeHeaders    []string        `yaml:"expose_headers"`
	AllowCredentials bool            `yaml:"allow_credentials"`
	MaxAge           config.Duration `yaml:"max_age"`
}

// VHost is one parsed and validated virtual host.
type VHost struct {
	Hosts           []string      `yaml:"hosts"`
	TLS             TLSConf       `yaml:"tls"`
	RedirectToHTTPS bool          `yaml:"redirect_to_https"`
	EarlyHints      []string      `yaml:"early_hints"`
	Backends        []BackendConf `yaml:"backends"`
	BackendTLS      BackendTLS    `yaml:"backend_tls"`
	BackendProtocol string        `yaml:"backend_protocol"` // auto | http1 | http3
	LoadBalancing   LB            `yaml:"load_balancing"`
	Compression     Compression   `yaml:"compression"`
	Headers         Headers       `yaml:"headers"`
	CORS            CORS          `yaml:"cors"`
	Cache           Cache         `yaml:"cache"`
	Routes          []Route       `yaml:"routes"`
	WAF             WAFOverride   `yaml:"waf"`

	// Resolved at load time, not part of the YAML.
	Name      string            `yaml:"-"` // file base name without extension
	Comp      compress.Settings `yaml:"-"` // global defaults + overrides
	WAFPol    waf.Policy        `yaml:"-"` // global WAF + overrides
	Pool      *balancer.Pool    `yaml:"-"`
	Transport http.RoundTripper `yaml:"-"` // backend transport (per-vhost TLS/protocol)
}

// defaults returns a VHost pre-filled with production defaults; the
// health section inherits the global config.
func defaults(cfg *config.Config) *VHost {
	return &VHost{
		RedirectToHTTPS: true,
		BackendProtocol: "auto",
		LoadBalancing: LB{
			Strategy: "round_robin",
			Sticky:   Sticky{Cookie: "gated_affinity", TTL: config.Duration(time.Hour)},
			Health: HealthConf{
				Passive: PassiveHealth{MaxFails: cfg.Health.MaxFails, Cooldown: cfg.Health.Cooldown},
				Active: ActiveHealth{
					Path:         "/healthz",
					Interval:     config.Duration(10 * time.Second),
					Timeout:      config.Duration(2 * time.Second),
					ExpectStatus: 200,
				},
			},
		},
	}
}

// Validate parses and validates a vhost document without touching any
// runtime state (no pool is built). Used by the management API before
// persisting a file.
func Validate(data []byte, cfg *config.Config) error {
	v := defaults(cfg)
	if err := yaml.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parse vhost: %w", err)
	}
	return v.validate()
}

// loadFile parses one vhost file on top of the defaults, validates it
// and builds its pool, carrying runtime state over from prev (the
// previous version of the SAME file), if any.
func loadFile(path string, cfg *config.Config, prev *VHost) (*VHost, error) {
	v := defaults(cfg)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read vhost: %w", err)
	}
	if err := yaml.Unmarshal(data, v); err != nil {
		return nil, fmt.Errorf("parse vhost: %w", err)
	}
	if err := v.validate(); err != nil {
		return nil, err
	}
	v.resolveCompression(cfg)
	v.resolveWAF(cfg)
	v.resolveCache()

	var prevPool *balancer.Pool
	if prev != nil {
		prevPool = prev.Pool
	}
	pool, err := balancer.New(v.poolConf(), prevPool)
	if err != nil {
		return nil, err
	}
	v.Pool = pool

	// Build per-route and canary pools (fresh each reload; they share
	// the vhost's backend transport and load-balancing settings).
	for i := range v.Routes {
		rt := &v.Routes[i]
		if len(rt.Backends) > 0 {
			p, err := balancer.New(v.poolConfWith(rt.Backends), nil)
			if err != nil {
				return nil, fmt.Errorf("routes[%d]: %w", i, err)
			}
			rt.Pool = p
		}
		if rt.Canary != nil && len(rt.Canary.Backends) > 0 {
			p, err := balancer.New(v.poolConfWith(rt.Canary.Backends), nil)
			if err != nil {
				return nil, fmt.Errorf("routes[%d].canary: %w", i, err)
			}
			rt.Canary.Pool = p
		}
	}

	// Reuse the previous transport when the TLS settings and protocol
	// are unchanged, to preserve backend keep-alive connections across
	// reloads.
	if prev != nil && prev.Transport != nil &&
		prev.BackendTLS == v.BackendTLS && prev.BackendProtocol == v.BackendProtocol {
		v.Transport = prev.Transport
	} else {
		v.Transport = buildTransport(cfg, v.BackendTLS, v.BackendProtocol)
	}
	return v, nil
}

// backendTLSConfig builds the client TLS config for HTTPS backends, or
// nil when no override is needed.
func backendTLSConfig(btls BackendTLS) *tls.Config {
	if btls.ServerName == "" && !btls.InsecureSkipVerify {
		return nil
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         btls.ServerName,
		InsecureSkipVerify: btls.InsecureSkipVerify,
	}
}

// buildTransport creates the backend transport for a vhost. proto
// selects the wire protocol toward the upstream:
//
//	auto  - HTTP/2 over TLS when the backend negotiates it (ALPN),
//	        HTTP/1.1 otherwise. Best default for remote backends.
//	http1 - force HTTP/1.1 (disable h2 negotiation).
//	http3 - HTTP/3 over QUIC (requires https:// backends).
func buildTransport(cfg *config.Config, btls BackendTLS, proto string) http.RoundTripper {
	if proto == "http3" {
		tc := backendTLSConfig(btls)
		if tc == nil {
			tc = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		return &http3.Transport{TLSClientConfig: tc}
	}

	tr := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          512,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		ResponseHeaderTimeout: cfg.Proxy.BackendTimeout.Std(),
		// Backends' encodings pass through untouched; gated does its own
		// compression on the client side.
		DisableCompression: true,
		// Negotiate HTTP/2 over TLS even though we set a custom
		// DialContext (which otherwise disables the auto-upgrade).
		ForceAttemptHTTP2: proto == "auto",
	}
	tr.TLSClientConfig = backendTLSConfig(btls)
	if proto == "http1" {
		// Belt and suspenders: refuse the h2 ALPN protocol entirely.
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	return tr
}

func (v *VHost) validate() error {
	if len(v.Hosts) == 0 {
		return fmt.Errorf("hosts is required")
	}
	for i, h := range v.Hosts {
		h = normalizeHost(h)
		if h == "" || strings.ContainsAny(h, "/ \t") {
			return fmt.Errorf("invalid host %q", v.Hosts[i])
		}
		v.Hosts[i] = h
	}

	switch v.BackendProtocol {
	case "", "auto", "http1", "http3":
	default:
		return fmt.Errorf("backend_protocol must be auto, http1 or http3, got %q", v.BackendProtocol)
	}

	if len(v.Backends) == 0 {
		return fmt.Errorf("backends is required")
	}
	for i, b := range v.Backends {
		u, err := url.Parse(b.URL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("backends[%d].url must be a valid http(s) URL, got %q", i, b.URL)
		}
		if b.Weight < 0 {
			return fmt.Errorf("backends[%d].weight must be >= 0", i)
		}
		if v.BackendProtocol == "http3" && u.Scheme != "https" {
			return fmt.Errorf("backends[%d]: backend_protocol http3 requires an https:// backend, got %q", i, b.URL)
		}
	}

	if !balancer.KnownStrategy(v.LoadBalancing.Strategy) {
		return fmt.Errorf("load_balancing.strategy: unknown strategy %q", v.LoadBalancing.Strategy)
	}
	if v.LoadBalancing.Sticky.Enabled && strings.TrimSpace(v.LoadBalancing.Sticky.Cookie) == "" {
		return fmt.Errorf("load_balancing.sticky.cookie is required when sticky is enabled")
	}
	if v.LoadBalancing.Health.Passive.MaxFails < 1 {
		return fmt.Errorf("load_balancing.health.passive.max_fails must be >= 1")
	}
	if v.LoadBalancing.Health.Passive.Cooldown.Std() <= 0 {
		return fmt.Errorf("load_balancing.health.passive.cooldown must be positive")
	}
	if a := v.LoadBalancing.Health.Active; a.Enabled {
		if !strings.HasPrefix(a.Path, "/") {
			return fmt.Errorf("load_balancing.health.active.path must start with /")
		}
		if a.Interval.Std() <= 0 || a.Timeout.Std() <= 0 {
			return fmt.Errorf("load_balancing.health.active interval and timeout must be positive")
		}
		if a.ExpectStatus < 100 || a.ExpectStatus > 599 {
			return fmt.Errorf("load_balancing.health.active.expect_status must be a valid HTTP status")
		}
	}

	for _, a := range v.Compression.Algorithms {
		if !compress.Known(a) {
			return fmt.Errorf("compression.algorithms: unknown algorithm %q", a)
		}
	}

	switch v.WAF.Mode {
	case "", "block", "detect":
	default:
		return fmt.Errorf("waf.mode must be \"block\" or \"detect\", got %q", v.WAF.Mode)
	}

	if (v.TLS.CertFile == "") != (v.TLS.KeyFile == "") {
		return fmt.Errorf("tls.cert_file and tls.key_file must be set together")
	}

	for i := range v.Routes {
		if err := v.Routes[i].validate(v); err != nil {
			return fmt.Errorf("routes[%d]: %w", i, err)
		}
	}
	return nil
}

// validate checks and compiles one route.
func (rt *Route) validate(v *VHost) error {
	if rt.PathPrefix == "" && rt.PathRegex == "" {
		return fmt.Errorf("path_prefix or path_regex is required")
	}
	if rt.PathPrefix != "" && rt.PathRegex != "" {
		return fmt.Errorf("path_prefix and path_regex are mutually exclusive")
	}
	if rt.PathRegex != "" {
		re, err := regexp.Compile(rt.PathRegex)
		if err != nil {
			return fmt.Errorf("path_regex: %w", err)
		}
		rt.regex = re
	}
	if len(rt.Methods) > 0 {
		rt.methods = make(map[string]bool, len(rt.Methods))
		for _, m := range rt.Methods {
			rt.methods[strings.ToUpper(m)] = true
		}
	}
	if rt.RewriteRegex != "" {
		re, err := regexp.Compile(rt.RewriteRegex)
		if err != nil {
			return fmt.Errorf("rewrite_regex: %w", err)
		}
		rt.rewrite = re
	}
	if err := validateBackends(rt.Backends, v.BackendProtocol); err != nil {
		return err
	}
	if c := rt.Canary; c != nil {
		if c.Weight < 0 || c.Weight > 100 {
			return fmt.Errorf("canary.weight must be between 0 and 100")
		}
		if len(c.Backends) == 0 {
			return fmt.Errorf("canary requires backends")
		}
		if err := validateBackends(c.Backends, v.BackendProtocol); err != nil {
			return fmt.Errorf("canary: %w", err)
		}
	}
	return nil
}

// validateBackends checks a backend list (shared by vhost and routes).
func validateBackends(backends []BackendConf, proto string) error {
	for i, b := range backends {
		u, err := url.Parse(b.URL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("backends[%d].url must be a valid http(s) URL, got %q", i, b.URL)
		}
		if b.Weight < 0 {
			return fmt.Errorf("backends[%d].weight must be >= 0", i)
		}
		if proto == "http3" && u.Scheme != "https" {
			return fmt.Errorf("backends[%d]: backend_protocol http3 requires an https:// backend", i)
		}
	}
	return nil
}

// resolveCompression merges the global defaults with the per-vhost
// overrides into the final settings used on the hot path.
func (v *VHost) resolveCompression(cfg *config.Config) {
	v.Comp = compress.Settings{
		Enabled:    cfg.Compression.Enabled,
		Algorithms: cfg.Compression.Algorithms,
		MinSize:    cfg.Compression.MinSize,
	}
	if v.Compression.Enabled != nil {
		v.Comp.Enabled = *v.Compression.Enabled
	}
	if len(v.Compression.Algorithms) > 0 {
		v.Comp.Algorithms = v.Compression.Algorithms
	}
	if v.Compression.MinSize != nil {
		v.Comp.MinSize = *v.Compression.MinSize
	}
}

// resolveWAF merges the global WAF settings with the per-vhost
// override into the policy used on the hot path.
func (v *VHost) resolveWAF(cfg *config.Config) {
	pol := waf.Policy{
		Enabled: cfg.WAF.Enabled,
		Detect:  cfg.WAF.Mode == "detect",
	}
	if v.WAF.Enabled != nil {
		pol.Enabled = *v.WAF.Enabled
	}
	if v.WAF.Mode != "" {
		pol.Detect = v.WAF.Mode == "detect"
	}
	if len(v.WAF.Exclude) > 0 {
		pol.Exclude = make(map[string]bool, len(v.WAF.Exclude))
		for _, id := range v.WAF.Exclude {
			pol.Exclude[id] = true
		}
	}
	v.WAFPol = pol
}

func (v *VHost) poolConf() balancer.Conf { return v.poolConfWith(v.Backends) }

// poolConfWith builds a pool config from the vhost's load-balancing
// settings but an arbitrary backend set (used by routes and canaries).
func (v *VHost) poolConfWith(backends []BackendConf) balancer.Conf {
	conf := balancer.Conf{
		Strategy: v.LoadBalancing.Strategy,
		Sticky: balancer.StickyConf{
			Enabled: v.LoadBalancing.Sticky.Enabled,
			Cookie:  v.LoadBalancing.Sticky.Cookie,
			TTL:     v.LoadBalancing.Sticky.TTL.Std(),
		},
		Health: balancer.HealthConf{
			MaxFails: v.LoadBalancing.Health.Passive.MaxFails,
			Cooldown: v.LoadBalancing.Health.Passive.Cooldown.Std(),
		},
	}
	if a := v.LoadBalancing.Health.Active; a.Enabled {
		conf.Health.Active = &balancer.ActiveConf{
			Path:         a.Path,
			Interval:     a.Interval.Std(),
			Timeout:      a.Timeout.Std(),
			ExpectStatus: a.ExpectStatus,
		}
	}
	for _, b := range backends {
		conf.Backends = append(conf.Backends, balancer.BackendConf{
			URL: b.URL, Weight: b.Weight, Backup: b.Backup,
		})
	}
	return conf
}

// MatchRoute returns the first route matching the method and path, or
// nil when none match (the vhost's default backends are then used).
func (v *VHost) MatchRoute(method, path string) *Route {
	for i := range v.Routes {
		rt := &v.Routes[i]
		if len(rt.methods) > 0 && !rt.methods[method] {
			continue
		}
		if rt.regex != nil {
			if rt.regex.MatchString(path) {
				return rt
			}
			continue
		}
		if strings.HasPrefix(path, rt.PathPrefix) {
			return rt
		}
	}
	return nil
}

// ClosePools closes the default pool plus every route/canary pool.
func (v *VHost) ClosePools() {
	if v.Pool != nil {
		v.Pool.Close()
	}
	for i := range v.Routes {
		if v.Routes[i].Pool != nil {
			v.Routes[i].Pool.Close()
		}
		if v.Routes[i].Canary != nil && v.Routes[i].Canary.Pool != nil {
			v.Routes[i].Canary.Pool.Close()
		}
	}
}

// normalizeHost lowercases and strips port and trailing dot.
func normalizeHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}
