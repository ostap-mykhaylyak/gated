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
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

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

// VHost is one parsed and validated virtual host.
type VHost struct {
	Hosts           []string      `yaml:"hosts"`
	TLS             TLSConf       `yaml:"tls"`
	RedirectToHTTPS bool          `yaml:"redirect_to_https"`
	EarlyHints      []string      `yaml:"early_hints"`
	Backends        []BackendConf `yaml:"backends"`
	BackendTLS      BackendTLS    `yaml:"backend_tls"`
	LoadBalancing   LB            `yaml:"load_balancing"`
	Compression     Compression   `yaml:"compression"`
	WAF             WAFOverride   `yaml:"waf"`

	// Resolved at load time, not part of the YAML.
	Name      string            `yaml:"-"` // file base name without extension
	Comp      compress.Settings `yaml:"-"` // global defaults + overrides
	WAFPol    waf.Policy        `yaml:"-"` // global WAF + overrides
	Pool      *balancer.Pool    `yaml:"-"`
	Transport *http.Transport   `yaml:"-"` // backend transport (per-vhost TLS)
}

// defaults returns a VHost pre-filled with production defaults; the
// health section inherits the global config.
func defaults(cfg *config.Config) *VHost {
	return &VHost{
		RedirectToHTTPS: true,
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

	var prevPool *balancer.Pool
	if prev != nil {
		prevPool = prev.Pool
	}
	pool, err := balancer.New(v.poolConf(), prevPool)
	if err != nil {
		return nil, err
	}
	v.Pool = pool

	// Reuse the previous transport when the TLS settings are unchanged,
	// to preserve backend keep-alive connections across reloads.
	if prev != nil && prev.Transport != nil && prev.BackendTLS == v.BackendTLS {
		v.Transport = prev.Transport
	} else {
		v.Transport = buildTransport(cfg, v.BackendTLS)
	}
	return v, nil
}

// buildTransport creates the backend transport for a vhost, applying
// the per-vhost TLS settings for HTTPS upstreams.
func buildTransport(cfg *config.Config, btls BackendTLS) *http.Transport {
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
	}
	if btls.ServerName != "" || btls.InsecureSkipVerify {
		tr.TLSClientConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			ServerName:         btls.ServerName,
			InsecureSkipVerify: btls.InsecureSkipVerify,
		}
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

func (v *VHost) poolConf() balancer.Conf {
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
	for _, b := range v.Backends {
		conf.Backends = append(conf.Backends, balancer.BackendConf{
			URL: b.URL, Weight: b.Weight, Backup: b.Backup,
		})
	}
	return conf
}

// normalizeHost lowercases and strips port and trailing dot.
func normalizeHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}
