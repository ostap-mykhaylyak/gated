# Security Policy

gated is designed to sit on the public edge of a server: security
reports are taken seriously.

## Reporting a vulnerability

Please do NOT open a public issue. Report privately to
**ostap.mykhaylyak@gmail.com** with a description, reproduction steps
and the affected version (`gated --version`). You will get an
acknowledgment as soon as possible.

## Scope notes

- The management API is disabled by default and requires a bearer
  token when enabled; report any way to bypass that.
- The status Unix socket is local-only by design.
- The daemon is expected to run under the shipped systemd hardening.
