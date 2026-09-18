# Architecture

## Implemented server paths

HydraFlow currently has two subscription servers:

- `install.sh` configures proxy processes and starts `hydraflow-sub`, built from
  the self-contained `tools/sub-server.go`. It uses `sub-config.json`.
- `hydraflow serve` uses `config`, `smartsub`, `xray` and `integrations`. It uses
  `hydraflow.yaml` and can manage Xray directly or read users/nodes from a panel.

These implementations have different configuration models and are not
interchangeable. The CLI export command and `smartsub` share client renderers;
the installer's server still has its own rendering and ISP lookup code.

## CLI request flow

1. A provider supplies enabled nodes and their user identities.
2. The subscription endpoint validates a user-scoped token.
3. `smartsub.NodesForUser` filters nodes by that exact identity.
4. ISP lookup selects a static protocol priority list.
5. Nodes are ordered using server-side availability and ISP priority. Telemetry
   filters protocols reported blocked, with a fallback if all are blocked.
6. The server renders V2Ray links, Mihomo YAML or sing-box JSON. Compatible clients
   perform their own connection tests and selection after importing a config.

The current algorithm does not implement the previously documented weighted
50/30/20 client score or a built-in TUN/proxy client. Server-side TCP/TLS checks
are not evidence that a protocol is reachable from a censored client network.
In particular they are not valid end-to-end Hysteria2/QUIC checks.

## Components

- `discovery`: probe, fingerprint, blocking map and reporting building blocks.
- `bypass`: fragmentation, padding, DNS, SNI and other connection techniques.
- `smartsub`: user filtering, priorities, telemetry, HTTP endpoints and rendering.
- `integrations`: provider adapters for supported management panels.
- `xray`: server configuration builder and subprocess management.
- `config`: configuration defaults and persistent secrets.

The presence of a discovery or bypass component does not imply it participates
in every subscription request. Full client-side autonomous adaptation and
cross-deployment aggregation are not wired together by `serve`.

## Access and privacy

CLI subscription tokens are HMAC-SHA256 credentials scoped to a user identity.
The admin secret is required only for administrative access and local token
issuance. See [the upgrade guide](upgrade-subscriptions.md) before upgrading.

ISP lookup calls an external service with the client IP, and caches it in memory.
The CLI engine currently uses HTTP for ip-api.com; the separate installer server
uses HTTPS. Therefore the old blanket claim that no IP addresses are transmitted
was incorrect. Log hashing does not anonymize external lookups. Telemetry and
ISP recommendations should not be treated as an independently verified map of
censorship conditions.
