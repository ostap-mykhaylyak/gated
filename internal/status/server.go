package status

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

// Server is the local read-only Unix socket the daemon exposes for
// --status. It never crosses the network: no public bind, covered by
// the systemd hardening.
type Server struct {
	ln   net.Listener
	path string
}

// Serve starts listening on the Unix socket at path, serving one JSON
// snapshot per connection. A stale socket left by a previous crash is
// removed first.
func Serve(path string, collect func() *Snapshot) (*Server, error) {
	if err := os.MkdirAll(socketDir(path), 0o750); err != nil {
		return nil, fmt.Errorf("status socket: %w", err)
	}
	// Remove a stale socket from a previous crash.
	if _, err := os.Stat(path); err == nil {
		os.Remove(path)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("status socket: %w", err)
	}
	os.Chmod(path, 0o660)

	s := &Server{ln: ln, path: path}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed on shutdown
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetWriteDeadline(time.Now().Add(2 * time.Second))
				json.NewEncoder(c).Encode(collect())
			}(conn)
		}
	}()
	return s, nil
}

// Close stops the listener and removes the socket file.
func (s *Server) Close() error {
	err := s.ln.Close()
	os.Remove(s.path)
	return err
}
