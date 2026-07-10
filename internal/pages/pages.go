// Package pages renders the styled error and challenge pages (block,
// not-found, backend-down, rate-limited, browser challenge). Built-in
// templates are embedded; an operator can override them by dropping
// message.html / challenge.html into the pages directory.
package pages

import (
	"bytes"
	"embed"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
)

//go:embed templates/*.html
var builtin embed.FS

// Pages holds the parsed templates.
type Pages struct {
	tmpl *template.Template
}

// MessageData feeds the generic message page (block / 4xx / 5xx).
type MessageData struct {
	Code      int
	Title     string
	Message   string
	Host      string
	RequestID string
}

// ChallengeData feeds the interstitial challenge page.
type ChallengeData struct {
	Token      string
	C          string
	Difficulty int
	Endpoint   string
	Host       string
	RequestID  string
}

// New parses the built-in templates, then overrides any of them with a
// same-named file found in dir (dir may be "" or missing).
func New(dir string) (*Pages, error) {
	t, err := template.ParseFS(builtin, "templates/*.html")
	if err != nil {
		return nil, err
	}
	if dir != "" {
		for _, name := range []string{"message.html", "challenge.html"} {
			path := filepath.Join(dir, name)
			data, err := os.ReadFile(path)
			if err != nil {
				continue // no override for this page
			}
			if _, err := t.New(name).Parse(string(data)); err != nil {
				return nil, err
			}
		}
	}
	return &Pages{tmpl: t}, nil
}

// Message renders the generic page with the given status code.
func (p *Pages) Message(w http.ResponseWriter, d MessageData) {
	p.render(w, "message.html", d.Code, d)
}

// Challenge renders the interstitial page (HTTP 403).
func (p *Pages) Challenge(w http.ResponseWriter, d ChallengeData) {
	p.render(w, "challenge.html", http.StatusForbidden, d)
}

func (p *Pages) render(w http.ResponseWriter, name string, code int, data any) {
	var buf bytes.Buffer
	if err := p.tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		http.Error(w, http.StatusText(code), code)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	buf.WriteTo(w)
}
