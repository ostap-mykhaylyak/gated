package waf

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"

	"github.com/ostap-mykhaylyak/gated/internal/metrics"
)

// Policy is the per-vhost resolution of the WAF settings, computed at
// vhost load time from the global config plus the vhost overrides.
type Policy struct {
	Enabled bool
	Detect  bool            // true = log matches but never block (tuning)
	Exclude map[string]bool // rule IDs to skip for this vhost
}

func (p Policy) excluded(id string) bool { return p.Exclude[id] }

// compiledSet is the immutable, ready-to-run rule set, split by role
// so the hot path iterates only what it must.
type compiledSet struct {
	allow    []*Rule // whitelist, checked first
	request  []*Rule // enforced at request time
	status   []*Rule // counted at response time (track.on_status)
	needBody bool
	count    int
}

// Engine evaluates requests against the loaded rules. Rules are
// hot-reloaded from a directory (one group per YAML file).
type Engine struct {
	dir   string
	log   *slog.Logger
	m     *metrics.Metrics
	state *stateStore

	set atomic.Pointer[compiledSet]
	mu  sync.Mutex // serializes LoadAll
}

// New returns an Engine reading rules from dir.
func New(dir string, log *slog.Logger, m *metrics.Metrics) *Engine {
	e := &Engine{dir: dir, log: log, m: m, state: newStateStore()}
	e.set.Store(&compiledSet{})
	return e
}

// NeedsBody reports whether any loaded rule inspects the request body,
// so the proxy only buffers bodies when it pays off.
func (e *Engine) NeedsBody() bool { return e.set.Load().needBody }

// Count returns the number of loaded (enabled) rules.
func (e *Engine) Count() int { return e.set.Load().count }

// ActiveBans returns the number of currently banned client IPs.
func (e *Engine) ActiveBans() int { return e.state.activeBans() }

// LoadAll (re)reads every *.yaml file in the directory and swaps the
// compiled set atomically. Invalid rules are skipped with a warning
// (never fatal); a file that fails to parse is skipped whole.
func (e *Engine) LoadAll() {
	e.mu.Lock()
	defer e.mu.Unlock()

	files, err := filepath.Glob(filepath.Join(e.dir, "*.yaml"))
	if err != nil {
		e.log.Error("waf scan failed", "dir", e.dir, "error", err)
		return
	}
	more, _ := filepath.Glob(filepath.Join(e.dir, "*.yml"))
	files = append(files, more...)
	sort.Strings(files)

	cs := &compiledSet{}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			e.log.Error("waf file unreadable", "file", filepath.Base(path), "error", err)
			continue
		}
		var f File
		if err := yaml.Unmarshal(data, &f); err != nil {
			e.log.Error("waf file parse failed", "file", filepath.Base(path), "error", err)
			continue
		}
		if f.Enabled != nil && !*f.Enabled {
			continue
		}
		for i := range f.Rules {
			ru := &f.Rules[i]
			if err := ru.compile(); err != nil {
				e.log.Warn("waf rule skipped", "file", filepath.Base(path), "error", err)
				continue
			}
			cs.add(ru)
		}
	}
	e.set.Store(cs)
	e.log.Info("waf rules loaded", "rules", cs.count, "files", len(files))
}

func (cs *compiledSet) add(ru *Rule) {
	cs.count++
	if ru.needsBody() {
		cs.needBody = true
	}
	switch {
	case ru.Action == ActionAllow:
		cs.allow = append(cs.allow, ru)
	case ru.Track != nil && len(ru.Track.OnStatus) > 0:
		cs.status = append(cs.status, ru)
	default:
		cs.request = append(cs.request, ru)
	}
}

// Decision is the outcome of evaluating a request.
type Decision struct {
	Block    bool
	Status   int
	RuleID   string
	Msg      string
	Severity Severity
}

// Evaluate runs the request-phase rules for one request. It returns the
// decision and the list of response-tracked rules whose request
// conditions matched (to be handed to ObserveResponse in a defer).
func (e *Engine) Evaluate(ctx *evalCtx, policy Policy) (Decision, []*Rule) {
	if !policy.Enabled {
		return Decision{}, nil
	}
	cs := e.set.Load()
	e.m.WAFInspect()

	// Banned client: block up front, cheapest possible path.
	if e.state.banned(ctx.clientIP) {
		e.m.WAFBlock()
		e.log.Info("waf block", "reason", "banned", "ip", ctx.clientIP,
			"method", ctx.r.Method, "path", ctx.r.URL.Path)
		return Decision{Block: true, Status: 403, RuleID: "@ban", Msg: "client temporarily banned"}, nil
	}

	// Whitelist wins over everything else.
	for _, ru := range cs.allow {
		if policy.excluded(ru.ID) {
			continue
		}
		if ru.eval(ctx) {
			return Decision{}, nil
		}
	}

	// Enforced rules.
	for _, ru := range cs.request {
		if policy.excluded(ru.ID) || !ru.eval(ctx) {
			continue
		}
		bannedNow := false
		if ru.Track != nil {
			bannedNow = e.state.hit(ru.ID, ctx.clientIP, ru.Track)
			if bannedNow {
				e.m.WAFBan()
				e.log.Warn("waf ban", "rule", ru.ID, "ip", ctx.clientIP, "msg", ru.Msg)
			}
		}
		block := ru.Action == ActionBlock || (ru.Action == ActionBan && bannedNow)
		e.log.Info("waf match", "rule", ru.ID, "action", ru.Action, "ip", ctx.clientIP,
			"method", ctx.r.Method, "path", ctx.r.URL.Path, "msg", ru.Msg,
			"severity", ru.Severity, "enforced", block && !policy.Detect)
		if block && !policy.Detect {
			e.m.WAFBlock()
			return Decision{Block: true, Status: ru.blockStatus(), RuleID: ru.ID, Msg: ru.Msg, Severity: ru.Severity}, nil
		}
	}

	// Collect response-tracked rules whose request part matched.
	var pending []*Rule
	for _, ru := range cs.status {
		if policy.excluded(ru.ID) {
			continue
		}
		if ru.eval(ctx) {
			pending = append(pending, ru)
		}
	}
	return Decision{}, pending
}

// ObserveResponse feeds the response status to the response-tracked
// rules that matched at request time (fail2ban failure counting).
func (e *Engine) ObserveResponse(pending []*Rule, clientIP string, status int) {
	for _, ru := range pending {
		if !statusIn(ru.Track.OnStatus, status) {
			continue
		}
		if e.state.hit(ru.ID, clientIP, ru.Track) {
			e.m.WAFBan()
			e.log.Warn("waf ban", "rule", ru.ID, "ip", clientIP, "status", status, "msg", ru.Msg)
		}
	}
}

// Watch reloads the rule directory on any *.yaml/*.yml change,
// coalescing bursts into one reload.
func (e *Engine) Watch(stop <-chan struct{}) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("waf watch: %w", err)
	}
	if err := w.Add(e.dir); err != nil {
		w.Close()
		return fmt.Errorf("waf watch: %w", err)
	}
	go func() {
		defer w.Close()
		var pending <-chan time.Time
		for {
			select {
			case <-stop:
				return
			case ev, ok := <-w.Events:
				if !ok {
					return
				}
				name := strings.ToLower(ev.Name)
				if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
					continue
				}
				pending = time.After(200 * time.Millisecond)
			case err, ok := <-w.Errors:
				if !ok {
					return
				}
				e.log.Error("waf watch error", "error", err)
			case <-pending:
				pending = nil
				e.LoadAll()
			}
		}
	}()
	return nil
}

// Close stops the background state GC.
func (e *Engine) Close() { e.state.close() }

func statusIn(set []int, s int) bool {
	for _, v := range set {
		if v == s {
			return true
		}
	}
	return false
}
