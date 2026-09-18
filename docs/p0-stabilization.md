# P0 stabilization

This branch combines the subscription/standalone hardening work with Xray lifecycle fixes.

Release gate for this change:

- `go vet ./...`
- `go test -race -count=1 ./...`
- `make build-all`
- `golangci-lint`

The lifecycle regression tests cover candidate config rejection, manual stop without auto-restart, crash recovery, and cancellation of a pending restart.
