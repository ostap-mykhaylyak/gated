package status

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// Query connects to the daemon's status socket and returns the
// snapshot it serves. Read-only, no side effects, safe to run in
// parallel with the daemon.
func Query(sock string, timeout time.Duration) (*Snapshot, error) {
	conn, err := net.DialTimeout("unix", sock, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(timeout))
	var snap Snapshot
	if err := json.NewDecoder(conn).Decode(&snap); err != nil {
		return nil, err
	}
	return &snap, nil
}

// Run implements the --status / --status-json / --watch CLI and
// returns the process exit code (Nagios convention).
func Run(version, sock, cfgPath string, jsonOut bool, watch time.Duration) int {
	if watch <= 0 {
		snap := fetch(version, sock, cfgPath)
		print(snap, jsonOut, nil, 0)
		return ExitCode(snap.Status)
	}

	// Live mode: redraw in a loop like top (or one JSON line per tick
	// with --status-json, suitable for piping to a collector).
	// Ctrl-C exits.
	var prev *Snapshot
	var prevAt time.Time
	for {
		snap := fetch(version, sock, cfgPath)
		if !jsonOut {
			fmt.Print("\033[2J\033[H") // clear screen, home cursor
		}
		print(snap, jsonOut, prev, time.Since(prevAt))
		prev, prevAt = snap, time.Now()
		time.Sleep(watch)
	}
}

func fetch(version, sock, cfgPath string) *Snapshot {
	snap, err := Query(sock, 2*time.Second)
	if err != nil {
		return notRunning(version, cfgPath)
	}
	return snap
}

func print(snap *Snapshot, jsonOut bool, prev *Snapshot, elapsed time.Duration) {
	if jsonOut {
		json.NewEncoder(os.Stdout).Encode(snap)
		return
	}
	if prev == nil {
		fmt.Println(summaryLine(snap))
		return
	}
	// watch mode: multi-line view with rates computed between ticks.
	fmt.Println(summaryLine(snap))
	fmt.Printf("config:   %s (%s)\n", boolWord(snap.Config.Valid, "valid", "INVALID"), snap.Config.Path)
	if snap.Live != nil {
		var reqRate, errRate float64
		if prev.Live != nil && elapsed > 0 {
			reqRate = float64(snap.Live.RequestsTotal-prev.Live.RequestsTotal) / elapsed.Seconds()
			errRate = float64(snap.Live.ErrorsTotal-prev.Live.ErrorsTotal) / elapsed.Seconds()
		}
		fmt.Printf("requests: %d total, %d in-flight, %.1f req/s\n",
			snap.Live.RequestsTotal, snap.Live.RequestsInFlight, reqRate)
		fmt.Printf("errors:   %d total, %.1f err/s\n", snap.Live.ErrorsTotal, errRate)
		fmt.Printf("bytes:    %s out\n", humanBytes(snap.Live.BytesOutTotal))
	}
	if snap.WAF != nil && snap.WAF.Enabled {
		fmt.Printf("waf:      %d rules, %d active bans, %d blocked, %d banned, %d challenged, %d cleared\n",
			snap.WAF.Rules, snap.WAF.ActiveBans, snap.WAF.Blocked, snap.WAF.Banned,
			snap.WAF.Challenged, snap.WAF.Cleared)
		fmt.Printf("access:   allow %d ips / %d asn, deny %d ips / %d asn\n",
			snap.WAF.AllowIPs, snap.WAF.AllowASN, snap.WAF.DenyIPs, snap.WAF.DenyASN)
	}
	if snap.GeoIP != nil && snap.GeoIP.Enabled {
		fmt.Printf("geoip:    database %s\n", boolWord(snap.GeoIP.Loaded, "loaded", "NOT loaded"))
	}
	if snap.Vhosts != nil {
		for _, v := range snap.Vhosts.Items {
			states := make([]string, 0, len(v.Backends))
			for _, b := range v.Backends {
				state := "up"
				if !b.Up {
					state = "DOWN"
				}
				states = append(states, fmt.Sprintf("%s %s (%d)", b.URL, state, b.Active))
			}
			fmt.Printf("vhost %-20s %s\n", v.Name+":", strings.Join(states, ", "))
		}
	}
	parts := make([]string, 0, len(snap.Checks))
	for _, c := range snap.Checks {
		parts = append(parts, c.Name+"="+c.Status)
	}
	fmt.Printf("checks:   %s\n", strings.Join(parts, " "))
}

func summaryLine(snap *Snapshot) string {
	label := map[string]string{OK: "OK", Warn: "WARNING", Crit: "CRITICAL"}[snap.Status]
	if label == "" {
		label = "UNKNOWN"
	}
	if !snap.Service.Active {
		detail := "config on disk: absent"
		for _, c := range snap.Checks {
			if c.Name == "config_on_disk" {
				switch c.Status {
				case OK:
					detail = "config on disk: valid"
				case Crit:
					detail = "config on disk: invalid"
				}
			}
		}
		return fmt.Sprintf("gated %s - service not running (%s)", label, detail)
	}
	uptime := time.Duration(snap.Service.UptimeSeconds * float64(time.Second)).Round(time.Second)
	line := fmt.Sprintf("gated %s - active, pid %d, uptime %s, config %s",
		label, snap.Service.PID, uptime, boolWord(snap.Config.Valid && snap.Config.Error == "", "valid", "reload pending"))
	if snap.Vhosts != nil {
		line += fmt.Sprintf(", %d vhost(s)/%d host(s)", snap.Vhosts.Files, snap.Vhosts.Hosts)
	}
	if snap.WAF != nil && snap.WAF.Enabled {
		line += fmt.Sprintf(", waf %d rules/%d bans", snap.WAF.Rules, snap.WAF.ActiveBans)
	}
	if snap.Live != nil {
		line += fmt.Sprintf(", in-flight %d, requests %d, errors %d",
			snap.Live.RequestsInFlight, snap.Live.RequestsTotal, snap.Live.ErrorsTotal)
	}
	return line
}

func boolWord(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
