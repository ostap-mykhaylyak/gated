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

	// AllowDir and DenyDir hold folder-based IP/ASN access lists
	// (*.ips and *.asn files): whitelist and blacklist respectively.
	AllowDir = ConfigDir + "/allow"
	DenyDir  = ConfigDir + "/deny"

	// PagesDir holds optional overrides for the styled error/challenge
	// pages (message.html, challenge.html).
	PagesDir = ConfigDir + "/pages"

	// LogDir holds all log files and runtime state. It is the only
	// path the daemon is guaranteed to be able to write to.
	LogDir = "/var/log/gated"

	// RunDir holds the local status socket (tmpfs, managed by systemd
	// via RuntimeDirectory=).
	RunDir = "/run/gated"
	Socket = RunDir + "/gated.sock"

	// Secret files: persistent HMAC keys for challenge clearances and
	// session cookies, generated on first run under the writable state
	// dir (LogDir) so signed cookies survive restarts.
	ChallengeSecretFile = LogDir + "/challenge.secret"
	SessionSecretFile   = LogDir + "/session.secret"

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
