package waf

import (
	"encoding/base64"
	"html"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// evalCtx carries the extracted request (and, later, response status)
// through the evaluation of a rule set.
type evalCtx struct {
	r        *http.Request
	clientIP string
	body     string
	args     url.Values // query + parsed form, computed lazily
	argsDone bool
}

// NewContext builds an evaluation context for one request. body is the
// buffered request body (empty when not inspected). The proxy calls
// this, then Engine.Evaluate.
func NewContext(r *http.Request, clientIP, body string) *evalCtx {
	return &evalCtx{r: r, clientIP: clientIP, body: body}
}

// values returns the strings a condition should test for the given
// field/name.
func (ctx *evalCtx) values(field Field, name string) []string {
	switch field {
	case FieldMethod:
		return []string{ctx.r.Method}
	case FieldPath:
		return []string{ctx.r.URL.Path}
	case FieldQuery:
		return []string{ctx.r.URL.RawQuery}
	case FieldURI:
		return []string{ctx.r.URL.RequestURI()}
	case FieldBody:
		return []string{ctx.body}
	case FieldIP:
		return []string{ctx.clientIP}
	case FieldHeader:
		if name != "" {
			return ctx.r.Header.Values(name)
		}
		var out []string
		for _, vs := range ctx.r.Header {
			out = append(out, vs...)
		}
		return out
	case FieldCookie:
		var out []string
		for _, ck := range ctx.r.Cookies() {
			if name == "" || strings.EqualFold(ck.Name, name) {
				out = append(out, ck.Value)
			}
		}
		return out
	case FieldArg:
		ctx.ensureArgs()
		if name != "" {
			return ctx.args[name]
		}
		var out []string
		for _, vs := range ctx.args {
			out = append(out, vs...)
		}
		return out
	}
	return nil
}

func (ctx *evalCtx) ensureArgs() {
	if ctx.argsDone {
		return
	}
	ctx.argsDone = true
	ctx.args = url.Values{}
	for k, vs := range ctx.r.URL.Query() {
		ctx.args[k] = append(ctx.args[k], vs...)
	}
	// Parse a urlencoded body from the buffered copy (ParseForm would
	// consume the live body; we already captured it).
	ct := ctx.r.Header.Get("Content-Type")
	if ctx.body != "" && strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		if form, err := url.ParseQuery(ctx.body); err == nil {
			for k, vs := range form {
				ctx.args[k] = append(ctx.args[k], vs...)
			}
		}
	}
}

// eval reports whether every condition of the rule matches.
func (r *Rule) eval(ctx *evalCtx) bool {
	for i := range r.Match {
		if !r.Match[i].matches(ctx) {
			return false
		}
	}
	return true
}

// matches applies transforms and the operator to the field's values;
// the result is inverted when Negate is set.
func (c *Condition) matches(ctx *evalCtx) bool {
	hit := false
	for _, v := range ctx.values(c.Field, c.Name) {
		if c.matchOne(applyTransforms(v, c.Transform)) {
			hit = true
			break
		}
	}
	return hit != c.Negate
}

func (c *Condition) matchOne(v string) bool {
	switch c.Operator {
	case OpRx:
		return anyRegex(c.regexps, v)
	case OpPm:
		lv := strings.ToLower(v)
		for _, p := range c.phrases {
			if strings.Contains(lv, p) {
				return true
			}
		}
	case OpContains:
		for _, p := range c.Patterns {
			if strings.Contains(v, p) {
				return true
			}
		}
	case OpEq:
		for _, p := range c.Patterns {
			if v == p {
				return true
			}
		}
	case OpPrefix:
		for _, p := range c.Patterns {
			if strings.HasPrefix(v, p) {
				return true
			}
		}
	case OpSuffix:
		for _, p := range c.Patterns {
			if strings.HasSuffix(v, p) {
				return true
			}
		}
	case OpIP:
		ip := parseIP(v)
		if ip == nil {
			return false
		}
		for _, n := range c.cidrs {
			if n.Contains(ip) {
				return true
			}
		}
	case OpGt, OpGe, OpLt, OpLe:
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil {
			return false
		}
		for _, n := range c.nums {
			switch c.Operator {
			case OpGt:
				if f > n {
					return true
				}
			case OpGe:
				if f >= n {
					return true
				}
			case OpLt:
				if f < n {
					return true
				}
			case OpLe:
				if f <= n {
					return true
				}
			}
		}
	}
	return false
}

func anyRegex(res []*regexp.Regexp, v string) bool {
	for _, re := range res {
		if re.MatchString(v) {
			return true
		}
	}
	return false
}

func parseIP(v string) net.IP { return net.ParseIP(strings.TrimSpace(v)) }

// transforms maps a transform name to its function. "length" is
// special-cased in applyTransforms (it replaces the value with its
// numeric length).
var transforms = map[string]func(string) string{
	"lowercase":          strings.ToLower,
	"uppercase":          strings.ToUpper,
	"trim":               strings.TrimSpace,
	"urldecode":          urlDecode,
	"htmldecode":         html.UnescapeString,
	"removenulls":        func(s string) string { return strings.ReplaceAll(s, "\x00", "") },
	"compresswhitespace": func(s string) string { return wsRe.ReplaceAllString(s, " ") },
	"removewhitespace":   func(s string) string { return wsRe.ReplaceAllString(s, "") },
	"normalizepath":      func(s string) string { return path.Clean(s) },
	"base64decode":       base64Decode,
}

var wsRe = regexp.MustCompile(`\s+`)

func applyTransforms(v string, names []string) string {
	for _, n := range names {
		if n == "length" {
			v = strconv.Itoa(len(v))
			continue
		}
		if fn := transforms[n]; fn != nil {
			v = fn(v)
		}
	}
	return v
}

func urlDecode(s string) string {
	if d, err := url.QueryUnescape(s); err == nil {
		return d
	}
	return s
}

func base64Decode(s string) string {
	if d, err := base64.StdEncoding.DecodeString(s); err == nil {
		return string(d)
	}
	return s
}
