// Package waf is the web application firewall of gated: a rule engine
// whose YAML schema is a superset of ModSecurity/Coraza SecRule, able
// to represent Nuclei matchers and fail2ban filters too (see
// docs/waf-conversion-prompt.md).
//
// A rule fires when ALL of its conditions match (AND); a condition
// matches when ANY of its patterns match (OR) after transforms.
// Actions: allow (whitelist, wins over everything), block (deny with a
// status), log (record only), ban (fail2ban-style, via track).
package waf

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/ostap-mykhaylyak/gated/internal/config"
)

// Field identifies which part of the request (or response) a condition
// inspects. Mirrors the common ModSecurity variables.
type Field string

const (
	FieldMethod Field = "method" // REQUEST_METHOD
	FieldPath   Field = "path"   // REQUEST_FILENAME (URL path, no query)
	FieldQuery  Field = "query"  // QUERY_STRING (raw)
	FieldURI    Field = "uri"    // REQUEST_URI (path?query)
	FieldHeader Field = "header" // REQUEST_HEADERS[:name]
	FieldCookie Field = "cookie" // REQUEST_COOKIES[:name]
	FieldArg    Field = "arg"    // ARGS[:name] (query + form)
	FieldBody   Field = "body"   // REQUEST_BODY (up to max_body_bytes)
	FieldIP     Field = "ip"     // REMOTE_ADDR (resolved real IP)
)

var knownFields = map[Field]bool{
	FieldMethod: true, FieldPath: true, FieldQuery: true, FieldURI: true,
	FieldHeader: true, FieldCookie: true, FieldArg: true, FieldBody: true, FieldIP: true,
}

// Operator is the comparison applied to each extracted value.
type Operator string

const (
	OpRx       Operator = "rx"       // regular expression (@rx)
	OpPm       Operator = "pm"       // phrase set, case-insensitive substring (@pm)
	OpContains Operator = "contains" // substring (@contains)
	OpEq       Operator = "eq"       // exact string equality (@streq)
	OpPrefix   Operator = "prefix"   // @beginsWith
	OpSuffix   Operator = "suffix"   // @endsWith
	OpIP       Operator = "ip"       // IP within any CIDR/address (@ipMatch)
	OpGt       Operator = "gt"       // numeric >
	OpGe       Operator = "ge"       // numeric >=
	OpLt       Operator = "lt"       // numeric <
	OpLe       Operator = "le"       // numeric <=
)

var knownOps = map[Operator]bool{
	OpRx: true, OpPm: true, OpContains: true, OpEq: true, OpPrefix: true,
	OpSuffix: true, OpIP: true, OpGt: true, OpGe: true, OpLt: true, OpLe: true,
}

// Action decides what happens when a rule fires.
type Action string

const (
	ActionBlock Action = "block" // deny with Status
	ActionLog   Action = "log"   // record only, keep processing
	ActionAllow Action = "allow" // whitelist: stop and let the request through
	ActionBan   Action = "ban"   // count and, past threshold, ban the client IP
)

var knownActions = map[Action]bool{
	ActionBlock: true, ActionLog: true, ActionAllow: true, ActionBan: true,
}

// Severity is informational, surfaced in logs and metrics.
type Severity string

// Track turns a rule into a stateful counter (fail2ban semantics):
// count matches per client IP and ban it once Threshold is reached
// within Window, for BanTime. When OnStatus is set, counting happens
// at RESPONSE time and only for those status codes (e.g. 401 on a
// login path = a failed attempt).
type Track struct {
	Threshold int             `yaml:"threshold"`
	Window    config.Duration `yaml:"window"`
	BanTime   config.Duration `yaml:"ban_time"`
	OnStatus  []int           `yaml:"on_status"`
}

// Condition is one matchable clause.
type Condition struct {
	Field     Field    `yaml:"field"`
	Name      string   `yaml:"name"`      // header/cookie/arg key; empty = any
	Operator  Operator `yaml:"operator"`  // default rx
	Patterns  []string `yaml:"patterns"`  // OR within the condition
	Transform []string `yaml:"transform"` // applied left-to-right before matching
	Negate    bool     `yaml:"negate"`    // invert the match result

	// compiled
	regexps []*regexp.Regexp
	cidrs   []*net.IPNet
	phrases []string  // lowercased, for pm
	nums    []float64 // for numeric operators
}

// Rule is one WAF rule.
type Rule struct {
	ID       string      `yaml:"id"`
	Msg      string      `yaml:"msg"`
	Severity Severity    `yaml:"severity"`
	Action   Action      `yaml:"action"`
	Status   int         `yaml:"status"` // for block; default 403
	Match    []Condition `yaml:"match"`
	Track    *Track      `yaml:"track"`
	Tags     []string    `yaml:"tags"`
}

// File is one rule group (one YAML file).
type File struct {
	Group       string `yaml:"group"`
	Description string `yaml:"description"`
	Enabled     *bool  `yaml:"enabled"` // nil = enabled
	Rules       []Rule `yaml:"rules"`
}

// blockStatus returns the deny status, defaulting to 403.
func (r *Rule) blockStatus() int {
	if r.Status != 0 {
		return r.Status
	}
	return 403
}

// needsBody reports whether any condition inspects the request body.
func (r *Rule) needsBody() bool {
	for _, c := range r.Match {
		if c.Field == FieldBody {
			return true
		}
	}
	return false
}

// compile validates the rule and precompiles its regexes/CIDRs/numbers.
func (r *Rule) compile() error {
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("rule id is required")
	}
	if !knownActions[r.Action] {
		return fmt.Errorf("rule %s: unknown action %q", r.ID, r.Action)
	}
	if len(r.Match) == 0 {
		return fmt.Errorf("rule %s: at least one match condition is required", r.ID)
	}
	if r.Action == ActionBan && r.Track == nil {
		return fmt.Errorf("rule %s: action ban requires a track section", r.ID)
	}
	if r.Track != nil {
		if r.Track.Threshold < 1 {
			return fmt.Errorf("rule %s: track.threshold must be >= 1", r.ID)
		}
		if r.Track.Window.Std() <= 0 || r.Track.BanTime.Std() <= 0 {
			return fmt.Errorf("rule %s: track.window and track.ban_time must be positive", r.ID)
		}
	}
	for i := range r.Match {
		if err := r.Match[i].compile(); err != nil {
			return fmt.Errorf("rule %s: match[%d]: %w", r.ID, i, err)
		}
	}
	return nil
}

func (c *Condition) compile() error {
	if !knownFields[c.Field] {
		return fmt.Errorf("unknown field %q", c.Field)
	}
	if c.Operator == "" {
		c.Operator = OpRx
	}
	if !knownOps[c.Operator] {
		return fmt.Errorf("unknown operator %q", c.Operator)
	}
	if len(c.Patterns) == 0 {
		return fmt.Errorf("field %q: patterns is required", c.Field)
	}
	for _, t := range c.Transform {
		if _, ok := transforms[t]; !ok && t != "length" {
			return fmt.Errorf("unknown transform %q", t)
		}
	}
	switch c.Operator {
	case OpRx:
		for _, p := range c.Patterns {
			re, err := regexp.Compile(p)
			if err != nil {
				return fmt.Errorf("invalid regex %q: %w", p, err)
			}
			c.regexps = append(c.regexps, re)
		}
	case OpPm:
		for _, p := range c.Patterns {
			c.phrases = append(c.phrases, strings.ToLower(p))
		}
	case OpIP:
		for _, p := range c.Patterns {
			if _, n, err := net.ParseCIDR(p); err == nil {
				c.cidrs = append(c.cidrs, n)
				continue
			}
			if ip := net.ParseIP(p); ip != nil {
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				c.cidrs = append(c.cidrs, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
				continue
			}
			return fmt.Errorf("invalid ip/cidr %q", p)
		}
	case OpGt, OpGe, OpLt, OpLe:
		for _, p := range c.Patterns {
			n, err := strconv.ParseFloat(strings.TrimSpace(p), 64)
			if err != nil {
				return fmt.Errorf("operator %s needs numeric patterns, got %q", c.Operator, p)
			}
			c.nums = append(c.nums, n)
		}
	}
	return nil
}
