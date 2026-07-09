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
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ostap-mykhaylyak/gated/internal/balancer"
	"github.com/ostap-mykhaylyak/gated/internal/compress"
	"github.com/ostap-mykhaylyak/gated/internal/config"
)

// TLSConf selects the certificate for the vhost. Empty = conventional
// Let's Encrypt lookup by host name.
type TLSConf struct {
	CertName string `yaml:"cert_name"` // force a letsencrypt dir name
	CertFile string `yaml:"cert_file"` // full override outside letsencrypt
	KeyFile  string `yaml:"key_file"`
}

// BackendConf is one upstream in the vhost file.
type BackendConf struct {
	URL    string `yaml:"url"`
	Weight int    `yaml:"weight"`
	Backup bool   `yaml:"backup"`
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

// VHost is one parsed and validated virtual host.
type VHost struct {
	Hosts           []string      `yaml:"hosts"`
	TLS             TLSConf       `yaml:"tls"`
	RedirectToHTTPS bool          `yaml:"redirect_to_https"`
	EarlyHints      []string      `yaml:"early_hints"`
	Backends        []BackendConf `yaml:"backends"`
	LoadBalancing   LB            `yaml:"load_balancing"`
	Compression     Compression   `yaml:"compression"`

	// Resolved at load time, not part of the YAML.
	Name string            `yaml:"-"` // file base name without extension
	Comp compress.Settings `yaml:"-"` // global defaults + overrides
	Pool *balancer.Pool    `yaml:"-"`
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

	var prevPool *balancer.Pool
	if prev != nil {
		prevPool = prev.Pool
	}
	pool, err := balancer.New(v.poolConf(), prevPool)
	if err != nil {
		return nil, err
	}
	v.Pool = pool
	return v, nil
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
