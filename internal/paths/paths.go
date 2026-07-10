// Package paths centralizes the hardcoded FHS layout of gated.
//
// Production code relies ONLY on these constants; overrides (e.g. the
// --config flag) exist solely for testing.
package paths

const (
	// Binary is where the installed executable lives.
	Binary = "/sbin/gated"

	// ConfigDir holds all configuration (read-only at runtime unless the
	// management API is enabled, which writes vhost files only).
	ConfigDir  = "/etc/gated"
	ConfigFile = ConfigDir + "/config.yaml"

	// VhostsDir holds one YAML file per virtual host.
	VhostsDir = ConfigDir + "/vhosts"

	// WAFDir holds the WAF rule files (one group per YAML file).
	WAFDir = ConfigDir + "/waf"

	// LogDir holds all log files and runtime state. It is the only
	// path the daemon is guaranteed to be able to write to.
	LogDir = "/var/log/gated"

	// RunDir holds the local status socket (tmpfs, managed by systemd
	// via RuntimeDirectory=).
	RunDir = "/run/gated"
	Socket = RunDir + "/gated.sock"

	// LetsEncryptDir is the conventional certbot live directory used
	// for automatic certificate lookup (overridable in config.yaml).
	LetsEncryptDir = "/etc/letsencrypt/live"

	// Deploy targets used by --init.
	UnitFile      = "/etc/systemd/system/gated.service"
	LogrotateFile = "/etc/logrotate.d/gated"
)

// Log file names, to be joined with LogDir.
const (
	ServiceLog = "gated.log"
	AccessLog  = "access.log"
	BackendLog = "backend.log"
	APILog     = "api.log"
	WAFLog     = "waf.log"
)
