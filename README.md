# gated

Reverse proxy and load balancer written in Go. Single static binary,
no runtime dependencies, managed by systemd. Designed to be the entry
point of the server, in front of any service.

> **Status: pre-release.** Feature-complete for v1; hardening and
> field testing in progress.

## Features

- Reverse proxy + load balancing (round_robin, least_conn, ip_hash,
  uri_hash, random; per-backend `backup`; sticky sessions; passive +
  active health checks). Backend health state survives config reloads.
  Backends (in each vhost file) take a full `url` — any IP/host, any
  port, `http://` or `https://`; per-vhost `backend_tls` sets the SNI /
  cert name and can accept self-signed backend certs. `backend_protocol`
  picks the upstream wire protocol: `auto` (HTTP/2 over TLS via ALPN,
  h1 fallback — fast for remote backends), `http1`, or `http3` (QUIC).
- **No redirect loops** for TLS-terminated CMSes: gated forwards
  `X-Forwarded-Proto/Ssl/Port` and upgrades a backend's `http://`
  self-redirects to `https://`, so a WordPress/CMS set to HTTPS behind
  an HTTP backend connection does not bounce forever.
- TLS/HTTPS, HTTP/2, HTTP/3 (QUIC, advertised via Alt-Svc), Early
  Hints (103)
- WebSocket and other `Connection: Upgrade` protocols (streamed
  bidirectionally, compression bypassed); Server-Sent Events stream
  unbuffered
- Compression: zstd, brotli, gzip (negotiated, per-vhost overridable)
- Real IP resolution with trusted proxies (`X-Forwarded-For` walked
  right-to-left)
- Certificates reused from the conventional Let's Encrypt layout
  (`/etc/letsencrypt/live/<host>/`), hot-swapped on renewal; ACME
  HTTP-01 challenges passed through to the local nginx
- One YAML file per virtual host (`/etc/gated/vhosts/*.yaml`),
  hot-reloaded with a last-good rule (a broken file never takes a
  vhost down); unknown `Host` gets a plain 404
- **WAF** with YAML rules (`/etc/gated/waf/*.yaml`), hot-reloaded:
  request inspection (method/path/query/headers/cookies/args/body/IP),
  ModSecurity-style operators and transforms, allow/block/log actions,
  and fail2ban-style stateful IP bans (`block` vs `detect` mode, global
  and per-vhost). Convert Coraza/ModSecurity, Nuclei and fail2ban rules
  with [docs/waf-conversion-prompt.md](docs/waf-conversion-prompt.md).
- **GeoIP** (MaxMind `.mmdb` from the conventional `/usr/share/GeoIP/`,
  hot-swapped on refresh): the WAF `country`/`continent`/`asn` fields
  let you block or ban by geography, e.g. deny traffic from a country.
- **IP / ASN access lists** (folder-based, hot-reloaded): drop `.ips`
  files (single IP or CIDR) and `.asn` files (one ASN per line) into
  `/etc/gated/allow` (whitelist) and `/etc/gated/deny` (blacklist). A
  whitelisted client bypasses the WAF entirely; a blacklisted one is
  blocked (whitelist always wins). ASN lists need the GeoIP ASN db.
- **Browser challenge** (`challenge` action, Cloudflare-style): serves a
  "Checking your browser" interstitial that must run JS (and optionally
  solve a SHA-256 proof of work) to earn a signed, IP-bound clearance
  cookie — e.g. challenge a whole country instead of hard-blocking it.
  Signing keys are persisted (auto-generated), so clearances survive
  restarts.
- **Prior-visit / session gate** (`session` field): gated sets a signed
  visit cookie on HTML page loads; a rule can require it on sensitive
  endpoints, so e.g. WooCommerce `add-to-cart` can't be called directly
  without a prior visit — stops direct database-flood patterns.
- **Styled pages** for blocked requests, browser challenge, 404,
  backend-down (502/503), each with a Ray ID for log correlation;
  built-in templates overridable from `/etc/gated/pages/`.
- Optional management REST API (vhosts as REST resources, versioned
  writes with rollback)

## Management API (optional)

Disabled by default. Enable with `api.enabled: true` + `api.token` in
the config (and add `/etc/gated/vhosts` to `ReadWritePaths=` in the
unit). Bearer-token auth on everything except `GET /healthz`.

| Endpoint | Effect |
|---|---|
| `GET /healthz` | 200 if OK/WARN, 503 if CRITICAL (no token, for probes) |
| `GET /status` | full status snapshot (same document as `--status-json`) |
| `GET /metrics` | live metrics snapshot |
| `GET /config` | current global config, secrets redacted |
| `POST /reload` | reload global config + vhosts (same path as SIGHUP) |
| `GET /vhosts` | vhosts being served, with per-backend runtime state |
| `GET /vhosts/{name}` | the raw YAML file |
| `PUT /vhosts/{name}` | validate → snapshot → atomic write → reload |
| `DELETE /vhosts/{name}` | archive and remove |
| `GET /vhosts/{name}/history` | archived versions (metadata only) |
| `POST /vhosts/{name}/rollback` | restore latest or `{"version":"..."}` |

Every write archives the previous version under `vhosts/.history/`
(20 kept, FIFO). The global `config.yaml` is never writable via API.

## Build

```sh
make            # static Linux binary in bin/gated
make test       # go test ./... -race
```

The version is injected at build time from `git describe`.

## Install

Either turnkey from the binary itself (as root):

```sh
./gated --init
systemctl daemon-reload
systemctl enable --now gated
gated --status
```

or from the repo with `make install`.

## CLI

| Flag | Mode | Effect |
|---|---|---|
| *(none)* | daemon | start the service (what systemd runs) |
| `--init` | lifecycle | provision layout, install binary/unit/logrotate, exit |
| `--purge` | lifecycle | remove ALL config, data and logs (asks confirmation; `--yes` to skip) |
| `--status` | client | query the running daemon via its Unix socket |
| `--status-json` | client | machine-readable status (stable field names) |
| `--watch 2s` | client | live status view, like `top` |
| `--version` | misc | print version, exit |

`--status` exit codes follow the Nagios convention: 0 OK, 1 WARNING,
2 CRITICAL, 3 UNKNOWN.

## Layout

```
/sbin/gated                 binary
/etc/gated/config.yaml      global config (never rewritten)
/etc/gated/vhosts/*.yaml    one file per virtual host
/etc/gated/waf/*.yaml       WAF rule groups
/etc/gated/allow/*.{ips,asn} IP/ASN whitelist
/etc/gated/deny/*.{ips,asn}  IP/ASN blacklist
/var/log/gated/             JSON logs (rotation via logrotate + SIGHUP)
/run/gated/gated.sock       local status socket
```

Observability is reading the log files: `gated.log` (service),
`access.log`, `backend.log`, `api.log`, `waf.log` — all JSON, one line
per event.

## License

MIT — see [LICENSE](LICENSE).
