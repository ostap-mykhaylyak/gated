# Contributing

## Ground rules

- Standard library first: the only allowed third-party dependencies
  are `gopkg.in/yaml.v3`, `github.com/fsnotify/fsnotify` and the
  feature-mandated ones (quic-go for HTTP/3, brotli/zstd encoders).
  Everything else needs a very good reason.
- The binary must stay static: `CGO_ENABLED=0`.
- No config/logging/CLI frameworks.

## Before opening a PR

```sh
make fmt    # gofmt -s
make vet
make test   # race detector on
```

CI enforces `go mod tidy`, gofmt, vet and tests on every push.

## Conventions

- Config: every field has a production default; invalid list entries
  are skipped with a warning, never fatal.
- Logs: JSON via log/slog, one stream per concern, rotation delegated
  to logrotate (SIGHUP reopens files).
- Stable public surfaces: `--status-json` field names and REST API
  paths must not change between versions.
