// Package bootstrap provides the lifecycle operations of the bare
// binary: first-run auto-provisioning, the --init turnkey installer
// and the --purge destructive reset. It embeds the default filesystem
// skeleton (skel/) and the systemd unit.
package bootstrap

import (
	"bufio"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ostap-mykhaylyak/gated/internal/paths"
)

//go:embed all:skel
var skelFS embed.FS

//go:embed gated.service
var UnitFile []byte

// skel source paths inside the embedded FS.
const (
	skelConfig    = "skel/etc/gated/config.yaml"
	skelVhostDir  = "skel/etc/gated/vhosts"
	skelWAFDir    = "skel/etc/gated/waf"
	skelAllowDir  = "skel/etc/gated/allow"
	skelDenyDir   = "skel/etc/gated/deny"
	skelLogrotate = "skel/etc/logrotate.d/gated"
)

// EnsureLayout creates the default filesystem layout and installs the
// default config WITHOUT overwriting an existing one. Used both by
// --init and by the first daemon start without a config.
func EnsureLayout(out io.Writer) error {
	for _, dir := range []string{paths.ConfigDir, paths.VhostsDir, paths.WAFDir, paths.AllowDir, paths.DenyDir, paths.PagesDir, paths.LogDir} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	created, err := installIfMissing(skelConfig, paths.ConfigFile, 0o640)
	if err != nil {
		return err
	}
	if created {
		fmt.Fprintf(out, "gated: installed default config at %s\n", paths.ConfigFile)
	}
	// Install the starter files of each skel directory (without
	// overwriting operator edits).
	for _, d := range []struct{ src, dst string }{
		{skelVhostDir, paths.VhostsDir},
		{skelWAFDir, paths.WAFDir},
		{skelAllowDir, paths.AllowDir},
		{skelDenyDir, paths.DenyDir},
	} {
		entries, err := skelFS.ReadDir(d.src)
		if err != nil {
			return fmt.Errorf("embedded skel: %w", err)
		}
		for _, e := range entries {
			dst := filepath.Join(d.dst, e.Name())
			if _, err := installIfMissing(d.src+"/"+e.Name(), dst, 0o640); err != nil {
				return err
			}
		}
	}
	return nil
}

// installIfMissing copies an embedded skel file to dst unless dst
// already exists (operator files are never overwritten).
func installIfMissing(src, dst string, perm fs.FileMode) (bool, error) {
	if _, err := os.Stat(dst); err == nil {
		return false, nil
	}
	data, err := skelFS.ReadFile(src)
	if err != nil {
		return false, fmt.Errorf("embedded skel: %w", err)
	}
	if err := os.WriteFile(dst, data, perm); err != nil {
		return false, fmt.Errorf("install %s: %w", dst, err)
	}
	return true, nil
}

// Init is the turnkey installer behind --init: layout, binary in
// /sbin, systemd unit, logrotate policy. Lifecycle mode: it acts on
// the filesystem and does NOT assume a running service.
func Init(version string, out io.Writer) error {
	if err := requireRootLinux("--init"); err != nil {
		return err
	}
	if err := EnsureLayout(out); err != nil {
		return err
	}

	// Copy the running executable to /sbin/gated (unless it already is).
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate executable: %w", err)
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		return fmt.Errorf("locate executable: %w", err)
	}
	if self != paths.Binary {
		if err := copyFile(self, paths.Binary, 0o755); err != nil {
			return fmt.Errorf("install binary: %w", err)
		}
		fmt.Fprintf(out, "gated: installed binary at %s\n", paths.Binary)
	}

	if err := os.WriteFile(paths.UnitFile, UnitFile, 0o644); err != nil {
		return fmt.Errorf("install systemd unit: %w", err)
	}
	fmt.Fprintf(out, "gated: installed systemd unit at %s\n", paths.UnitFile)

	data, err := skelFS.ReadFile(skelLogrotate)
	if err != nil {
		return fmt.Errorf("embedded skel: %w", err)
	}
	if err := os.WriteFile(paths.LogrotateFile, data, 0o644); err != nil {
		return fmt.Errorf("install logrotate policy: %w", err)
	}
	fmt.Fprintf(out, "gated: installed logrotate policy at %s\n", paths.LogrotateFile)

	fmt.Fprintf(out, `
gated %s installed. Next steps:

  1. review %s
  2. add your virtual hosts under %s/ (see example.com.yaml.example)
  3. for HTTP/3, raise the UDP buffers (quic-go needs them under load):
       echo 'net.core.rmem_max=7500000' > /etc/sysctl.d/99-gated.conf
       echo 'net.core.wmem_max=7500000' >> /etc/sysctl.d/99-gated.conf
       sysctl --system
  4. systemctl daemon-reload
  5. systemctl enable --now gated
  6. gated --status
`, version, paths.ConfigFile, paths.VhostsDir)
	return nil
}

// PurgeTargets returns, in one place, everything the app creates at
// runtime. The purge stays automatically aligned with the layout.
func PurgeTargets() []string {
	return []string{paths.ConfigDir, paths.LogDir, paths.RunDir}
}

// allowedPurgePrefixes guards against a misconfigured paths package in
// a custom build: purge refuses to touch anything outside these.
var allowedPurgePrefixes = []string{"/etc/gated", "/var/log/gated", "/run/gated"}

// Purge is the destructive reset behind --purge: removes ALL config,
// data and logs, returning the host to "never installed". It is NOT
// uninstall (binary and systemd unit are left in place).
func Purge(assumeYes bool, in io.Reader, out io.Writer) error {
	if err := requireRootLinux("--purge"); err != nil {
		return err
	}

	// Never delete data under a live process.
	if err := exec.Command("systemctl", "is-active", "--quiet", "gated.service").Run(); err == nil {
		return fmt.Errorf("service is running: stop it first (systemctl stop gated)")
	}

	targets := PurgeTargets()
	for _, t := range targets {
		if !purgeAllowed(t) {
			return fmt.Errorf("refusing to remove unexpected path %q", t)
		}
	}

	fmt.Fprintln(out, "The following paths and ALL their contents will be removed:")
	for _, t := range targets {
		fmt.Fprintln(out, "  ", t)
	}
	if !assumeYes {
		if !stdinIsTerminal(in) {
			return fmt.Errorf("refusing to purge without --yes (stdin is not a terminal)")
		}
		fmt.Fprint(out, "Type 'yes' to confirm: ")
		line, _ := bufio.NewReader(in).ReadString('\n')
		if strings.TrimSpace(line) != "yes" {
			return fmt.Errorf("aborted")
		}
	}

	var errs []string
	removed := 0
	for _, t := range targets {
		if _, err := os.Stat(t); os.IsNotExist(err) {
			continue
		}
		if err := os.RemoveAll(t); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		fmt.Fprintln(out, "removed", t)
		removed++
	}
	fmt.Fprintf(out, "removed %d path(s)\n", removed)
	fmt.Fprintln(out, "run 'gated --init' (or simply 'gated') to provision from scratch")
	if len(errs) > 0 {
		return fmt.Errorf("some paths could not be removed: %s", strings.Join(errs, "; "))
	}
	return nil
}

func purgeAllowed(path string) bool {
	if path == "" || path == "/" {
		return false
	}
	for _, p := range allowedPurgePrefixes {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

func requireRootLinux(op string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("%s only runs on Linux", op)
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("%s requires root", op)
	}
	return nil
}

func stdinIsTerminal(in io.Reader) bool {
	f, ok := in.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func copyFile(src, dst string, perm fs.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	// Write to a temp file in the same dir and rename: atomic, and it
	// works even while the destination is being executed.
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}
