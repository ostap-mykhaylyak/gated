package waf

import (
	"bufio"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Access lists are folder-based, hot-reloaded IP/ASN allow and deny
// lists, independent of the YAML rules:
//
//	<allow_dir>/*.ips   one IP or CIDR per line   -> whitelist by address
//	<allow_dir>/*.asn   one ASN per line          -> whitelist by network
//	<deny_dir>/*.ips    one IP or CIDR per line   -> blacklist by address
//	<deny_dir>/*.asn    one ASN per line          -> blacklist by network
//
// A whitelisted client bypasses the WAF entirely (wins over bans and
// the blacklist); a blacklisted client is blocked outright. ASN lists
// require geoip (with an ASN database) to resolve the client's network.

// ipset is an IP/CIDR membership set, split by family for a cheaper
// scan on the hot path.
type ipset struct {
	v4 []netip.Prefix
	v6 []netip.Prefix
}

func (s *ipset) add(p netip.Prefix) {
	if p.Addr().Is4() {
		s.v4 = append(s.v4, p)
	} else {
		s.v6 = append(s.v6, p)
	}
}

func (s *ipset) contains(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	list := s.v6
	if a.Is4() {
		list = s.v4
	}
	for _, p := range list {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (s *ipset) len() int { return len(s.v4) + len(s.v6) }

// accessSet is the immutable, atomically-swapped allow/deny state.
type accessSet struct {
	allowIP  ipset
	denyIP   ipset
	allowASN map[uint32]bool
	denyASN  map[uint32]bool
}

func newAccessSet() *accessSet {
	return &accessSet{allowASN: map[uint32]bool{}, denyASN: map[uint32]bool{}}
}

// needASN reports whether any ASN list is populated (so the proxy must
// resolve the client's ASN via geoip).
func (a *accessSet) needASN() bool { return len(a.allowASN) > 0 || len(a.denyASN) > 0 }

// allowed reports whether the client is whitelisted by IP or ASN.
func (a *accessSet) allowed(addr netip.Addr, asn uint32, hasASN bool) bool {
	return a.allowIP.contains(addr) || (hasASN && a.allowASN[asn])
}

// denied reports whether the client is blacklisted by IP or ASN.
func (a *accessSet) denied(addr netip.Addr, asn uint32, hasASN bool) bool {
	return a.denyIP.contains(addr) || (hasASN && a.denyASN[asn])
}

// loadAccess builds an accessSet from the allow and deny directories.
// Unparseable lines are skipped with a warning; a missing directory is
// simply empty.
func loadAccess(allowDir, denyDir string, log *slog.Logger) *accessSet {
	a := newAccessSet()
	loadDir(allowDir, &a.allowIP, a.allowASN, log)
	loadDir(denyDir, &a.denyIP, a.denyASN, log)
	return a
}

func loadDir(dir string, ips *ipset, asns map[uint32]bool, log *slog.Logger) {
	if dir == "" {
		return
	}
	ipFiles, _ := filepath.Glob(filepath.Join(dir, "*.ips"))
	for _, f := range ipFiles {
		parseLines(f, log, func(line string) {
			p, err := parsePrefix(line)
			if err != nil {
				log.Warn("access list: skipping invalid ip/cidr", "file", filepath.Base(f), "entry", line)
				return
			}
			ips.add(p)
		})
	}
	asnFiles, _ := filepath.Glob(filepath.Join(dir, "*.asn"))
	for _, f := range asnFiles {
		parseLines(f, log, func(line string) {
			n, ok := parseASN(line)
			if !ok {
				log.Warn("access list: skipping invalid asn", "file", filepath.Base(f), "entry", line)
				return
			}
			asns[n] = true
		})
	}
}

// parseLines reads a list file, stripping blank lines and # comments
// (whole-line or trailing), and calls fn for each entry.
func parseLines(path string, log *slog.Logger, fn func(string)) {
	f, err := os.Open(path)
	if err != nil {
		log.Error("access list unreadable", "file", filepath.Base(path), "error", err)
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fn(line)
	}
}

// parsePrefix accepts a bare IP (turned into a host prefix) or a CIDR.
func parsePrefix(s string) (netip.Prefix, error) {
	if strings.ContainsRune(s, '/') {
		return netip.ParsePrefix(s)
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return addr.Prefix(addr.BitLen())
}

// parseASN accepts "AS15169" or "15169".
func parseASN(s string) (uint32, bool) {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == 'A' || s[0] == 'a') && (s[1] == 'S' || s[1] == 's') {
		s = s[2:]
	}
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true
}
