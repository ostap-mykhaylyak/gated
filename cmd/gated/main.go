// gated - reverse proxy and load balancer.
//
// Without flags the binary starts the daemon (what the systemd unit
// does). Lifecycle flags (--init, --purge) act on the filesystem from
// the standalone binary; client flags (--status, --watch) query the
// RUNNING daemon through its local Unix socket.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ostap-mykhaylyak/gated/internal/api"
	"github.com/ostap-mykhaylyak/gated/internal/bootstrap"
	"github.com/ostap-mykhaylyak/gated/internal/certs"
	"github.com/ostap-mykhaylyak/gated/internal/config"
	"github.com/ostap-mykhaylyak/gated/internal/geoip"
	"github.com/ostap-mykhaylyak/gated/internal/logging"
	"github.com/ostap-mykhaylyak/gated/internal/metrics"
	"github.com/ostap-mykhaylyak/gated/internal/paths"
	"github.com/ostap-mykhaylyak/gated/internal/proxy"
	"github.com/ostap-mykhaylyak/gated/internal/status"
	"github.com/ostap-mykhaylyak/gated/internal/vhost"
	"github.com/ostap-mykhaylyak/gated/internal/waf"
)

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	// --- lifecycle: act on the filesystem, standalone binary ---
	initOnly := flag.Bool("init", false, "create the default filesystem layout and install the service, then exit")
	purge := flag.Bool("purge", false, "remove ALL config, data and logs, then exit")
	assumeYes := flag.Bool("yes", false, "skip the confirmation prompt for --purge")

	// --- client: query the running daemon via its local socket ---
	statusFlag := flag.Bool("status", false, "query the running service, print status, exit")
	statusJSON := flag.Bool("status-json", false, "machine-readable status (implies --status)")
	watch := flag.Duration("watch", 0, "refresh --status every interval (e.g. 2s), like top")

	// --- misc ---
	showVersion := flag.Bool("version", false, "print version and exit")
	cfgPath := flag.String("config", paths.ConfigFile, "config file (testing override)")
	flag.Parse()

	switch {
	case *showVersion:
		fmt.Println("gated", version)
		return
	case *initOnly:
		fatalIf(bootstrap.Init(version, os.Stdout))
		return
	case *purge:
		fatalIf(bootstrap.Purge(*assumeYes, os.Stdin, os.Stdout))
		return
	case *statusFlag || *statusJSON || *watch > 0:
		os.Exit(status.Run(version, paths.Socket, *cfgPath, *statusJSON, *watch))
	}

	fatalIf(runDaemon(*cfgPath))
}

func runDaemon(cfgPath string) error {
	// First execution without a config: auto-provision the default
	// layout from the embedded skel, warn on stderr and keep going.
	if cfgPath == paths.ConfigFile {
		if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "gated: no config found, provisioning default layout")
			if err := bootstrap.EnsureLayout(os.Stderr); err != nil {
				return err
			}
		}
	}

	mgr, err := config.NewManager(cfgPath)
	if err != nil {
		return err
	}

	logs, err := logging.Open(paths.LogDir)
	if err != nil {
		return err
	}
	defer logs.Close()

	logs.Service.Info("starting", "version", version, "config", cfgPath, "pid", os.Getpid())
	for _, w := range mgr.Get().Warnings {
		logs.Service.Warn("config warning", "warning", w)
	}

	m := metrics.New()
	stop := make(chan struct{})

	// Certificate cache (conventional Let's Encrypt layout).
	certStore := certs.New(mgr.Get().TLS.LetsEncryptDir)

	// GeoIP resolver (nil when disabled). Consumed by the WAF via the
	// country/continent/asn rule fields; hot-swapped on db refresh.
	var geo *geoip.Resolver
	if gc := mgr.Get().GeoIP; gc.Enabled {
		geo = geoip.New(gc.CountryDB, gc.ASNDB, logs.Service)
		geo.Watch(stop)
		defer geo.Close()
		if !geo.Loaded() {
			logs.Service.Warn("geoip enabled but country database not loaded", "path", gc.CountryDB)
		}
	}

	// WAF engine (rules hot-reloaded from their directory). Loaded
	// before the vhosts, whose policies reference it.
	wafEngine := waf.New(mgr.Get().WAF.RulesDir, logs.WAF, m)
	wafEngine.LoadAll()
	if err := wafEngine.Watch(stop); err != nil {
		return err
	}
	defer wafEngine.Close()

	// Vhost store (one YAML per vhost, hot-reloaded, last-good on errors).
	vhosts := vhost.NewStore(paths.VhostsDir, logs.Service)
	vhosts.LoadAll(mgr.Get())
	if err := vhosts.Watch(stop, mgr.Get); err != nil {
		return err
	}

	// A global config reload re-resolves the vhosts too (inherited
	// health/compression defaults may have changed).
	err = mgr.Watch(stop,
		func(err error) { logs.Service.Error("config reload failed", "error", err) },
		func(cfg *config.Config) {
			logs.Service.Info("config reloaded", "warnings", len(cfg.Warnings))
			for _, w := range cfg.Warnings {
				logs.Service.Warn("config warning", "warning", w)
			}
			vhosts.LoadAll(cfg)
		})
	if err != nil {
		return err
	}

	// Local status socket: the IPC channel behind --status. If it
	// fails the daemon still serves; --status will report not running.
	collect := status.NewCollector(version, mgr, vhosts, wafEngine, geo, m, paths.LogDir)
	statusSrv, err := status.Serve(paths.Socket, collect)
	if err != nil {
		logs.Service.Error("status socket unavailable", "error", err)
	}

	// Public entrypoints: :80, :443 TCP (h1+h2), :443 UDP (h3).
	prx := proxy.New(mgr, vhosts, certStore, wafEngine, geo, m, logs)
	srv := proxy.NewServer(prx)
	if err := srv.Start(); err != nil {
		return err
	}

	// Optional management REST API on its own listener (no-op unless
	// api.enabled is true in the config).
	apiSrv := api.New(mgr, vhosts, collect, logs.API, paths.VhostsDir)
	if err := apiSrv.Start(); err != nil {
		return err
	}

	// Single signal loop: SIGHUP reopens logs (logrotate hook),
	// SIGTERM/SIGINT shut down gracefully.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for s := range sig {
		if s == syscall.SIGHUP {
			logs.Service.Info("SIGHUP received, reopening log files")
			if err := logs.Reopen(); err != nil {
				logs.Service.Error("log reopen failed", "error", err)
			}
			continue
		}
		logs.Service.Info("shutting down", "signal", s.String())
		close(stop)
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		srv.Shutdown(ctx)
		apiSrv.Shutdown(ctx)
		cancel()
		vhosts.Close()
		if statusSrv != nil {
			statusSrv.Close()
		}
		logs.Service.Info("shutdown complete")
		return nil
	}
	return nil
}

func fatalIf(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "gated:", err)
		os.Exit(1)
	}
}
