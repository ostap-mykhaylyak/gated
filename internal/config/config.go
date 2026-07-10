// Package config loads and validates the GLOBAL gated configuration
// (/etc/gated/config.yaml) and provides hot-reload via fsnotify.
//
// Per-virtual-host configuration (one file per vhost under
// /etc/gated/vhosts/) is handled by internal/vhost, not here.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ostap-mykhaylyak/gated/internal/paths"
)

// Duration wraps time.Duration to accept human-friendly YAML values
// such as "30m", "24h", "5s".
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler via time.ParseDuration.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

// MarshalYAML renders the duration back in its string form.
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// Std returns the value as a standard time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// Config is the global configuration. Every field has a production
// default (see Default), so the operator's config.yaml may be sparse.
type Config struct {
	Entrypoints Entrypoints `yaml:"entrypoints"`
	TLS         TLS         `yaml:"tls"`
	ACME        ACME        `yaml:"acme"`
	Proxy       Proxy       `yaml:"proxy"`
	Compression Compression `yaml:"compression"`
	Health      Health      `yaml:"health"`
	GeoIP       GeoIP       `yaml:"geoip"`
	Cache       Cache       `yaml:"cache"`
	WAF         WAF         `yaml:"waf"`
	Challenge   Challenge   `yaml:"challenge"`
	Session     Session     `yaml:"session"`
	Pages       Pages       `yaml:"pages"`
	API         API         `yaml:"api"`

	// Warnings collects non-fatal issues found by validate()
	// (e.g. invalid list entries that were skipped). Never fatal.
	Warnings []string `yaml:"-"`
}

// Entrypoints are the public listeners.
type Entrypoints struct {
	HTTP  HTTPEntrypoint  `yaml:"http"`
	HTTPS HTTPSEntrypoint `yaml:"https"`
}

// HTTPEntrypoint is the plain-HTTP listener.
type HTTPEntrypoint struct {
	Listen string `yaml:"listen"`
}

// HTTPSEntrypoint is the TLS listener; HTTP3 adds a QUIC listener on
// the same UDP port, advertised via Alt-Svc.
type HTTPSEntrypoint struct {
	Listen string `yaml:"listen"`
	HTTP3  bool   `yaml:"http3"`
}

// TLS holds certificate lookup settings.
type TLS struct {
	LetsEncryptDir string `yaml:"letsencrypt_dir"`
	MinVersion     string `yaml:"min_version"` // "1.2" or "1.3"
}

// ACME configures the passthrough of HTTP-01 challenges to the local
// nginx, which owns certificate issuance/renewal on this server.
type ACME struct {
	Passthrough bool   `yaml:"passthrough"`
	Upstream    string `yaml:"upstream"`
}

// Proxy holds global proxying behavior.
type Proxy struct {
	TrustedProxies    []string `yaml:"trusted_proxies"` // CIDRs or IPs
	RealIPHeader      string   `yaml:"real_ip_header"`
	ReadHeaderTimeout Duration `yaml:"read_header_timeout"`
	BackendTimeout    Duration `yaml:"backend_timeout"`
}

// Compression is the global default, overridable per-vhost.
type Compression struct {
	Enabled    bool     `yaml:"enabled"`
	Algorithms []string `yaml:"algorithms"` // preference order: zstd, br, gzip
	MinSize    int      `yaml:"min_size"`   // bytes below which no compression
}

// Health is the global default for passive backend health checking,
// overridable per-vhost.
type Health struct {
	MaxFails int      `yaml:"max_fails"`
	Cooldown Duration `yaml:"cooldown"`
}

// GeoIP configures MaxMind database lookups, consumed by the WAF via
// the country/continent/asn rule fields. Databases live at the
// conventional Ubuntu path and are hot-swapped on refresh.
type GeoIP struct {
	Enabled   bool   `yaml:"enabled"`
	CountryDB string `yaml:"country_db"`
	ASNDB     string `yaml:"asn_db"` // optional
}

// Cache configures the shared in-memory response cache. It is always
// allocated; a vhost opts in via its own cache section.
type Cache struct {
	MaxSizeBytes int64 `yaml:"max_size_bytes"`
}

// WAF configures the web application firewall. Rules live in RulesDir
// (one group per YAML file), hot-reloaded. Mode "block" enforces,
// "detect" only logs matches (for tuning). Per-vhost overrides exist.
type WAF struct {
	Enabled      bool   `yaml:"enabled"`
	RulesDir     string `yaml:"rules_dir"`
	AllowDir     string `yaml:"allow_dir"`      // folder of *.ips / *.asn whitelists
	DenyDir      string `yaml:"deny_dir"`       // folder of *.ips / *.asn blacklists
	Mode         string `yaml:"mode"`           // block | detect
	MaxBodyBytes int64  `yaml:"max_body_bytes"` // request body inspected up to this size
}

// Challenge configures the browser-challenge action: an interstitial
// page that must execute JS (and optionally solve a SHA-256 proof of
// work) to obtain a signed clearance cookie.
type Challenge struct {
	Secret       string   `yaml:"secret"`        // HMAC key; empty = random per start
	Difficulty   int      `yaml:"difficulty"`    // PoW leading zero bits; 0 = JS challenge only
	ClearanceTTL Duration `yaml:"clearance_ttl"` // how long a passed challenge lasts
}

// Session configures the "prior visit" marker used by the WAF session
// field. gated sets a signed visit cookie on HTML page loads; a rule
// can then require it on sensitive endpoints.
type Session struct {
	Secret string   `yaml:"secret"` // HMAC key; empty = persistent key file
	TTL    Duration `yaml:"ttl"`    // how long a visit marker is valid
}

// Pages configures the styled error/challenge pages. Built-in
// templates are used unless an override file exists in Dir.
type Pages struct {
	Dir string `yaml:"dir"` // optional; contains message.html / challenge.html
}

// API configures the optional management REST API (disabled by default).
type API struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
	Token   string `yaml:"token"`
	TLS     APITLS `yaml:"tls"`
}

// APITLS is the optional TLS material for a non-loopback API listener.
type APITLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// Default returns the configuration with ALL production defaults, so
// the operator's config.yaml may be sparse or even empty.
func Default() *Config {
	return &Config{
		Entrypoints: Entrypoints{
			HTTP:  HTTPEntrypoint{Listen: "0.0.0.0:80"},
			HTTPS: HTTPSEntrypoint{Listen: "0.0.0.0:443", HTTP3: true},
		},
		TLS: TLS{
			LetsEncryptDir: paths.LetsEncryptDir,
			MinVersion:     "1.2",
		},
		ACME: ACME{
			Passthrough: true,
			Upstream:    "http://127.0.0.1:80",
		},
		Proxy: Proxy{
			RealIPHeader:      "X-Forwarded-For",
			ReadHeaderTimeout: Duration(10 * time.Second),
			BackendTimeout:    Duration(60 * time.Second),
		},
		Compression: Compression{
			Enabled:    true,
			Algorithms: []string{"zstd", "br", "gzip"},
			MinSize:    1024,
		},
		Health: Health{
			MaxFails: 3,
			Cooldown: Duration(30 * time.Second),
		},
		GeoIP: GeoIP{
			Enabled:   false,
			CountryDB: "/usr/share/GeoIP/GeoLite2-Country.mmdb",
			ASNDB:     "",
		},
		Cache: Cache{
			MaxSizeBytes: 256 * 1024 * 1024, // 256 MiB shared cache
		},
		WAF: WAF{
			Enabled:      false,
			RulesDir:     paths.WAFDir,
			AllowDir:     paths.AllowDir,
			DenyDir:      paths.DenyDir,
			Mode:         "block",
			MaxBodyBytes: 128 * 1024,
		},
		Challenge: Challenge{
			Secret:       "",
			Difficulty:   4,
			ClearanceTTL: Duration(30 * time.Minute),
		},
		Session: Session{
			Secret: "",
			TTL:    Duration(2 * time.Hour),
		},
		Pages: Pages{
			Dir: paths.PagesDir,
		},
		API: API{
			Enabled: false,
			Listen:  "127.0.0.1:9090",
		},
	}
}

// Load reads the YAML file at path on top of Default() and validates
// the result.
func Load(path string) (*Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

var knownAlgorithms = map[string]bool{"gzip": true, "br": true, "zstd": true}

// validate checks the minimal invariants. Invalid list entries are
// never fatal: they are skipped and collected in Warnings.
func (c *Config) validate() error {
	if _, _, err := net.SplitHostPort(c.Entrypoints.HTTP.Listen); err != nil {
		return fmt.Errorf("entrypoints.http.listen: %w", err)
	}
	if _, _, err := net.SplitHostPort(c.Entrypoints.HTTPS.Listen); err != nil {
		return fmt.Errorf("entrypoints.https.listen: %w", err)
	}

	switch c.TLS.MinVersion {
	case "1.2", "1.3":
	default:
		return fmt.Errorf("tls.min_version must be \"1.2\" or \"1.3\", got %q", c.TLS.MinVersion)
	}
	if c.TLS.LetsEncryptDir == "" {
		return fmt.Errorf("tls.letsencrypt_dir is required")
	}

	if c.ACME.Passthrough {
		u, err := url.Parse(c.ACME.Upstream)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("acme.upstream must be a valid http(s) URL, got %q", c.ACME.Upstream)
		}
	}

	// Invalid trusted_proxies entries are skipped with a warning: a bad
	// line must not prevent the (re)load.
	valid := c.Proxy.TrustedProxies[:0]
	for _, e := range c.Proxy.TrustedProxies {
		if _, _, err := net.ParseCIDR(e); err == nil {
			valid = append(valid, e)
			continue
		}
		if net.ParseIP(e) != nil {
			valid = append(valid, e)
			continue
		}
		c.Warnings = append(c.Warnings, fmt.Sprintf("proxy.trusted_proxies: skipping invalid entry %q", e))
	}
	c.Proxy.TrustedProxies = valid

	if c.Proxy.RealIPHeader == "" {
		return fmt.Errorf("proxy.real_ip_header is required")
	}
	if c.Proxy.ReadHeaderTimeout.Std() <= 0 {
		return fmt.Errorf("proxy.read_header_timeout must be positive")
	}
	if c.Proxy.BackendTimeout.Std() <= 0 {
		return fmt.Errorf("proxy.backend_timeout must be positive")
	}

	// Unknown compression algorithms are skipped with a warning.
	algos := c.Compression.Algorithms[:0]
	for _, a := range c.Compression.Algorithms {
		if knownAlgorithms[a] {
			algos = append(algos, a)
			continue
		}
		c.Warnings = append(c.Warnings, fmt.Sprintf("compression.algorithms: skipping unknown algorithm %q", a))
	}
	c.Compression.Algorithms = algos
	if c.Compression.MinSize < 0 {
		return fmt.Errorf("compression.min_size must be >= 0")
	}

	if c.Health.MaxFails < 1 {
		return fmt.Errorf("health.max_fails must be >= 1")
	}
	if c.Health.Cooldown.Std() <= 0 {
		return fmt.Errorf("health.cooldown must be positive")
	}

	if c.GeoIP.Enabled && c.GeoIP.CountryDB == "" {
		return fmt.Errorf("geoip.country_db is required when geoip.enabled is true")
	}

	if c.Cache.MaxSizeBytes < 0 {
		return fmt.Errorf("cache.max_size_bytes must be >= 0")
	}

	switch c.WAF.Mode {
	case "block", "detect":
	default:
		return fmt.Errorf("waf.mode must be \"block\" or \"detect\", got %q", c.WAF.Mode)
	}

	if c.Challenge.Difficulty < 0 || c.Challenge.Difficulty > 24 {
		return fmt.Errorf("challenge.difficulty must be between 0 and 24")
	}
	if c.Challenge.ClearanceTTL.Std() <= 0 {
		return fmt.Errorf("challenge.clearance_ttl must be positive")
	}
	if c.Session.TTL.Std() <= 0 {
		return fmt.Errorf("session.ttl must be positive")
	}
	if c.WAF.Enabled && c.WAF.RulesDir == "" {
		return fmt.Errorf("waf.rules_dir is required when waf.enabled is true")
	}
	if c.WAF.MaxBodyBytes < 0 {
		return fmt.Errorf("waf.max_body_bytes must be >= 0")
	}

	if c.API.Enabled {
		if strings.TrimSpace(c.API.Token) == "" || c.API.Token == "***" {
			return fmt.Errorf("api.token is required when api.enabled is true")
		}
		host, _, err := net.SplitHostPort(c.API.Listen)
		if err != nil {
			return fmt.Errorf("api.listen: %w", err)
		}
		if !isLoopback(host) && (c.API.TLS.CertFile == "" || c.API.TLS.KeyFile == "") {
			c.Warnings = append(c.Warnings, "api.listen is not loopback and api.tls is not configured: the token travels in cleartext")
		}
	}

	return nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// firstRunDir is only used by Watch to resolve the directory to watch;
// editors and the management API replace the file atomically (rename),
// so watching the parent directory is the reliable pattern.
func watchDir(path string) string { return filepath.Dir(path) }
