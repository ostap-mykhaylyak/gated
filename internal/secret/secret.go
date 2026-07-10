// Package secret loads or creates the long-lived HMAC keys used to
// sign challenge clearances and session cookies. A configured value
// always wins; otherwise a random key is generated once and persisted
// under the writable state directory (0600), so signed cookies survive
// restarts and stay valid across a service reload.
package secret

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// LoadOrCreate returns the configured key if non-empty; otherwise it
// reads path, or creates a fresh random key there on first use.
func LoadOrCreate(configured, path string) (string, error) {
	if configured != "" {
		return configured, nil
	}
	if b, err := os.ReadFile(path); err == nil && len(b) >= 32 {
		return string(b), nil
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	key := hex.EncodeToString(buf)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return "", fmt.Errorf("create secret dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(key), 0o600); err != nil {
		return "", fmt.Errorf("write secret: %w", err)
	}
	return key, nil
}
