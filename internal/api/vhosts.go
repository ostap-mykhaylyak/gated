package api

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ostap-mykhaylyak/gated/internal/vhost"
)

// keepVersions is how many archived versions are retained per vhost.
const keepVersions = 20

// vhost names: file base names without extension, no dot-prefixed
// names (reserved, e.g. .history), no path tricks.
var nameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

// version timestamps: sortable, nanosecond precision.
const versionFormat = "20060102T150405.000000000Z"

var versionRe = regexp.MustCompile(`^\d{8}T\d{6}\.\d{9}Z$`)

func (s *Server) vhostFile(name string) (string, bool) {
	if !nameRe.MatchString(name) || strings.Contains(name, "..") {
		return "", false
	}
	return filepath.Join(s.dir, name+".yaml"), true
}

// listVhosts returns the vhosts the daemon is SERVING (including
// last-good versions of currently broken files).
func (s *Server) listVhosts(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.vhosts.Snapshot())
}

// getVhost returns the raw YAML file: the file is the resource.
func (s *Server) getVhost(w http.ResponseWriter, r *http.Request) {
	path, ok := s.vhostFile(r.PathValue("name"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid vhost name")
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such vhost")
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Write(data)
}

// putVhost replaces (or creates) a vhost file: validate BEFORE
// persisting, snapshot the previous version, write atomically, reload.
func (s *Server) putVhost(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	path, ok := s.vhostFile(name)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid vhost name")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	// Never persist a config the daemon could not load back.
	if err := vhost.Validate(body, s.cfg.Get()); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	created := true
	if _, err := os.Stat(path); err == nil {
		created = false
		if err := s.archive(name, path); err != nil {
			writeErr(w, http.StatusInternalServerError, "archive previous version: "+err.Error())
			return
		}
	}
	if err := atomicWrite(path, body); err != nil {
		writeErr(w, http.StatusInternalServerError, "write vhost: "+err.Error())
		return
	}
	s.vhosts.LoadAll(s.cfg.Get())

	code := http.StatusOK
	if created {
		code = http.StatusCreated
	}
	writeJSON(w, code, map[string]string{"status": "ok", "vhost": name})
}

// deleteVhost archives and removes the file; the vhost stops serving.
func (s *Server) deleteVhost(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	path, ok := s.vhostFile(name)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid vhost name")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := os.Stat(path); err != nil {
		writeErr(w, http.StatusNotFound, "no such vhost")
		return
	}
	if err := s.archive(name, path); err != nil {
		writeErr(w, http.StatusInternalServerError, "archive: "+err.Error())
		return
	}
	if err := os.Remove(path); err != nil {
		writeErr(w, http.StatusInternalServerError, "remove: "+err.Error())
		return
	}
	s.vhosts.LoadAll(s.cfg.Get())
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "vhost": name})
}

// versionInfo is one archived version; only metadata is exposed, never
// the raw content (archives may embed secrets).
type versionInfo struct {
	Version  string    `json:"version"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
}

func (s *Server) vhostHistory(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, ok := s.vhostFile(name); !ok {
		writeErr(w, http.StatusBadRequest, "invalid vhost name")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"vhost":    name,
		"versions": s.versions(name),
	})
}

// rollbackVhost restores an archived version: without a body the most
// recent one, with {"version":"..."} a specific one. The rollback is
// itself versioned (the current file is archived first) and validated:
// an archived version that no longer passes validation is refused.
func (s *Server) rollbackVhost(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	path, ok := s.vhostFile(name)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid vhost name")
		return
	}
	var req struct {
		Version string `json:"version"`
	}
	if body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16)); err == nil && len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	}

	versions := s.versions(name)
	if len(versions) == 0 {
		writeErr(w, http.StatusNotFound, "no history for this vhost")
		return
	}
	target := versions[0] // newest first
	if req.Version != "" {
		found := false
		for _, v := range versions {
			if v.Version == req.Version {
				target, found = v, true
				break
			}
		}
		if !found {
			writeErr(w, http.StatusNotFound, "no such version")
			return
		}
	}

	data, err := os.ReadFile(filepath.Join(s.histDir, name+"."+target.Version+".yaml"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "read archived version: "+err.Error())
		return
	}
	if err := vhost.Validate(data, s.cfg.Get()); err != nil {
		writeErr(w, http.StatusConflict, "archived version no longer valid: "+err.Error())
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := os.Stat(path); err == nil {
		if err := s.archive(name, path); err != nil {
			writeErr(w, http.StatusInternalServerError, "archive current version: "+err.Error())
			return
		}
	}
	if err := atomicWrite(path, data); err != nil {
		writeErr(w, http.StatusInternalServerError, "write vhost: "+err.Error())
		return
	}
	s.vhosts.LoadAll(s.cfg.Get())
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok", "vhost": name, "restored": target.Version,
	})
}

// archive snapshots the current file into .history before a write, and
// prunes the oldest versions beyond keepVersions (FIFO).
func (s *Server) archive(name, path string) error {
	if err := os.MkdirAll(s.histDir, 0o750); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	ts := time.Now().UTC().Format(versionFormat)
	if err := os.WriteFile(filepath.Join(s.histDir, name+"."+ts+".yaml"), data, 0o640); err != nil {
		return err
	}

	versions := s.versions(name) // newest first
	for _, v := range versions[min(len(versions), keepVersions):] {
		os.Remove(filepath.Join(s.histDir, name+"."+v.Version+".yaml"))
	}
	return nil
}

// versions lists the archived versions of name, newest first. The
// timestamp shape is checked strictly so that vhost names that are a
// prefix of another (example.com vs example.com.staging) never mix.
func (s *Server) versions(name string) []versionInfo {
	matches, _ := filepath.Glob(filepath.Join(s.histDir, name+".*.yaml"))
	out := make([]versionInfo, 0, len(matches))
	for _, m := range matches {
		base := filepath.Base(m)
		ver := strings.TrimSuffix(strings.TrimPrefix(base, name+"."), ".yaml")
		if !versionRe.MatchString(ver) {
			continue
		}
		fi, err := os.Stat(m)
		if err != nil {
			continue
		}
		out = append(out, versionInfo{Version: ver, Size: fi.Size(), Modified: fi.ModTime().UTC()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version > out[j].Version })
	return out
}

// atomicWrite writes via temp file + rename in the same directory: the
// vhost file is never observed half-written.
func atomicWrite(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
