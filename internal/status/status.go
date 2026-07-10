// Package status implements the daemon's status snapshot, the local
// Unix socket that serves it, and the CLI client behind --status.
//
// The daemon is the single source of truth about its own state: the
// client never reconstructs state from disk (beyond a minimal "is the
// config on disk valid" hint when the daemon is down).
package status

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ostap-mykhaylyak/gated/internal/config"
	"github.com/ostap-mykhaylyak/gated/internal/metrics"
	"github.com/ostap-mykhaylyak/gated/internal/vhost"
)

// WAFProvider is the subset of the WAF engine the status collector
// needs (kept as an interface to avoid a hard dependency).
type WAFProvider interface {
	Count() int
	ActiveBans() int
}

// GeoIPProvider is the subset of the GeoIP resolver the status
// collector needs. May be nil (geoip disabled).
type GeoIPProvider interface {
	Loaded() bool
}

// Check statuses, ordered by severity. Exit codes follow the Nagios
// convention: 0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN.
const (
	OK       = "ok"
	Warn     = "warn"
	Crit     = "crit"
	Unknown  = "unknown"
	ExitOK   = 0
	ExitWarn = 1
	ExitCrit = 2
	ExitUnk  = 3
)

// Check is a single named health check; monitors can alert on
// individual checks as well as on the aggregate status.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok | warn | crit
	Detail string `json:"detail"`
}

// ServiceInfo describes the running daemon.
type ServiceInfo struct {
	Active        bool    `json:"active"`
	PID           int     `json:"pid,omitempty"`
	UptimeSeconds float64 `json:"uptime_seconds,omitempty"`
}

// ConfigInfo describes the loaded (or on-disk) configuration.
type ConfigInfo struct {
	Path     string   `json:"path"`
	Valid    bool     `json:"valid"`
	Error    string   `json:"error,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// VhostsSection describes the loaded vhosts and their backends.
type VhostsSection struct {
	Files int          `json:"files"`
	Hosts int          `json:"hosts"`
	Items []vhost.Info `json:"items"`
}

// WAFSection describes the WAF engine state.
type WAFSection struct {
	Enabled    bool  `json:"enabled"`
	Rules      int   `json:"rules"`
	ActiveBans int   `json:"active_bans"`
	Blocked    int64 `json:"blocked"`
	Banned     int64 `json:"banned"`
}

// GeoIPSection describes the GeoIP resolver state.
type GeoIPSection struct {
	Enabled bool `json:"enabled"`
	Loaded  bool `json:"loaded"`
}

// Snapshot is the full status document served over the socket.
// Field names are stable across versions.
type Snapshot struct {
	Status    string            `json:"status"` // ok | warn | crit | unknown
	Version   string            `json:"version"`
	Service   ServiceInfo       `json:"service"`
	Config    ConfigInfo        `json:"config"`
	Vhosts    *VhostsSection    `json:"vhosts,omitempty"` // only when the daemon answered
	WAF       *WAFSection       `json:"waf,omitempty"`    // only when the daemon answered
	GeoIP     *GeoIPSection     `json:"geoip,omitempty"`  // only when the daemon answered
	Checks    []Check           `json:"checks"`
	Live      *metrics.Snapshot `json:"live,omitempty"` // only when the daemon answered
	Timestamp time.Time         `json:"timestamp"`
}

// ExitCode maps the aggregate status onto the Nagios exit codes.
func ExitCode(status string) int {
	switch status {
	case OK:
		return ExitOK
	case Warn:
		return ExitWarn
	case Crit:
		return ExitCrit
	default:
		return ExitUnk
	}
}

// worst aggregates check statuses; the worst one wins.
func worst(checks []Check) string {
	agg := OK
	for _, c := range checks {
		switch c.Status {
		case Crit:
			return Crit
		case Warn:
			agg = Warn
		}
	}
	return agg
}

// NewCollector builds the snapshot function the daemon serves on the
// socket. It computes the checks at request time from state the daemon
// already holds.
func NewCollector(version string, mgr *config.Manager, vhosts *vhost.Store, wafEngine WAFProvider, geo GeoIPProvider, m *metrics.Metrics, logDir string) func() *Snapshot {
	start := time.Now()
	return func() *Snapshot {
		cfg := mgr.Get()
		snap := &Snapshot{
			Version: version,
			Service: ServiceInfo{
				Active:        true,
				PID:           os.Getpid(),
				UptimeSeconds: time.Since(start).Seconds(),
			},
			Config: ConfigInfo{
				Path:     mgr.Path(),
				Valid:    true,
				Warnings: cfg.Warnings,
			},
			Timestamp: time.Now().UTC(),
		}

		var checks []Check
		if e := mgr.LastError(); e != "" {
			// The running config is still the previous valid one, but a
			// reload is pending with an error the operator must fix.
			checks = append(checks, Check{"config", Crit, "pending reload error: " + e})
			snap.Config.Error = e
		} else {
			checks = append(checks, Check{"config", OK, "loaded and valid"})
		}
		if len(cfg.Warnings) > 0 {
			checks = append(checks, Check{"config_warnings", Warn, cfg.Warnings[0]})
		}
		if err := checkWritable(logDir); err != nil {
			checks = append(checks, Check{"log_dir", Crit, "not writable: " + err.Error()})
		} else {
			checks = append(checks, Check{"log_dir", OK, "writable"})
		}

		live := m.Snapshot()
		snap.WAF = &WAFSection{
			Enabled:    cfg.WAF.Enabled,
			Rules:      wafEngine.Count(),
			ActiveBans: wafEngine.ActiveBans(),
			Blocked:    live.WAFBlocked,
			Banned:     live.WAFBanned,
		}

		if cfg.GeoIP.Enabled {
			loaded := geo != nil && geo.Loaded()
			snap.GeoIP = &GeoIPSection{Enabled: true, Loaded: loaded}
			if !loaded {
				checks = append(checks, Check{"geoip", Warn, "enabled but database not loaded"})
			} else {
				checks = append(checks, Check{"geoip", OK, "database loaded"})
			}
		}

		items := vhosts.Snapshot()
		snap.Vhosts = &VhostsSection{Files: len(items), Hosts: vhosts.Count(), Items: items}
		if len(items) == 0 {
			checks = append(checks, Check{"vhosts", Warn, "no vhosts loaded (serving only 404s)"})
		} else {
			down := 0
			for _, v := range items {
				for _, b := range v.Backends {
					if !b.Up {
						down++
					}
				}
			}
			if down > 0 {
				checks = append(checks, Check{"vhosts", Warn, fmt.Sprintf("%d backend(s) down", down)})
			} else {
				checks = append(checks, Check{"vhosts", OK, fmt.Sprintf("%d file(s), %d host(s)", len(items), vhosts.Count())})
			}
		}

		snap.Live = &live
		snap.Checks = checks
		snap.Status = worst(checks)
		return snap
	}
}

func checkWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".gated-writecheck-*")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}

// notRunning builds the fallback snapshot when the socket is
// unreachable: the service is considered down; the only extra hint is
// whether a config exists on disk and parses, to distinguish
// "installed but stopped" from "not installed".
func notRunning(version, cfgPath string) *Snapshot {
	snap := &Snapshot{
		Status:    Crit,
		Version:   version,
		Service:   ServiceInfo{Active: false},
		Config:    ConfigInfo{Path: cfgPath},
		Timestamp: time.Now().UTC(),
	}
	snap.Checks = append(snap.Checks, Check{"service", Crit, "not running (status socket unreachable)"})

	if _, err := os.Stat(cfgPath); err != nil {
		snap.Checks = append(snap.Checks, Check{"config_on_disk", Warn, "absent (not installed?)"})
		return snap
	}
	if _, err := config.Load(cfgPath); err != nil {
		snap.Config.Error = err.Error()
		snap.Checks = append(snap.Checks, Check{"config_on_disk", Crit, err.Error()})
		return snap
	}
	snap.Config.Valid = true
	snap.Checks = append(snap.Checks, Check{"config_on_disk", OK, "valid (installed but stopped)"})
	return snap
}

// socketDir returns the directory that must exist before listening.
func socketDir(sock string) string { return filepath.Dir(sock) }
