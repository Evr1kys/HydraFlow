# Subscription and standalone reliability update

## Scope

These changes affect `hydraflow serve` and the CLI. The one-command installer
still runs the separate `hydraflow-sub` implementation in `tools/sub-server.go`.
Do not replace an installer deployment's services or configuration with the CLI
configuration without planning that migration. The two services are not yet unified.

## Existing CLI deployments: replace subscription links

Previously, `/sub/{admin_token}/{email}` exposed the same secret used by the
administrative status endpoint. Those links are now rejected. User credentials
are derived using HMAC-SHA256 and bound to the exact user identity.

1. Back up `hydraflow.yaml` and `users.json`.
2. Replace the existing `admin_token` with a new random secret if it has already
   been distributed in subscription links. Generate one with `openssl rand -hex 32`.
3. Start the updated binary using the same configuration file.
4. Run `hydraflow user sub user@example.com --config /path/to/hydraflow.yaml`
   and distribute the new link to that user.

A user's token cannot request another user's subscription or administrative
statistics. Changing `admin_token` revokes every derived token. Disabling or
removing a user removes their nodes after the provider/user-file refresh.
A deleted and recreated identity receives the same derived token unless the
admin secret is rotated. Individual token rotation is not implemented.

In panel modes, `user sub` issues a token for the exact identity returned by the
provider. The server returns 404 until that identity has enabled nodes. Other
user-management commands remain standalone-only.

## Stable configuration and Reality keys

The CLI persists a missing admin secret before printing links. Config writes use
an atomic rename and mode 0600. Failure to save is an error, rather than continuing
with a temporary secret that changes at the next invocation.

Standalone startup generates an X25519 private key and Reality short ID once,
then persists them as `standalone.reality_private_key` and
`standalone.reality_short_id`. Existing values are validated and reused on
restart and user reload. Protect and back up this file.

Set `server_address` to the public IP or hostname if the server is behind NAT
or if the listening address is loopback. It is a host only, without scheme or
port. Example:

```yaml
mode: standalone
listen: "127.0.0.1:10086"
server_address: "vpn.example.com"
standalone:
  xray_binary: /usr/local/bin/xray
  xray_config: /etc/hydraflow/xray-config.json
  users_file: /etc/hydraflow/users.json
```

Install Xray and its geo assets before starting standalone mode. HydraFlow now
runs `xray run -test` on a private candidate config before replacing the live
file. Startup fails if Xray/configuration validation fails. User reload retries
failed updates; published nodes are updated only after a successful reload.
The bundled systemd unit now invokes `hydraflow serve`. Restart the service for
configuration changes; SIGHUP reload is not supported.

Subscription links printed by the CLI use HTTP. Expose the subscription listener
through a correctly configured HTTPS reverse proxy and use its public HTTPS URL
in clients. Reality traffic and HTTPS subscription traffic need separate listening
ports or addresses. Do not expose administrative credentials to clients.

## Client formats

`?format=v2ray`, `?format=clash` and `?format=singbox` now return actual base64
links, Mihomo/Clash Meta YAML and sing-box JSON respectively. Without this
parameter, the server selects a format from the client's User-Agent.
The CLI export command and `serve` share the same renderer.

Supported nodes: VLESS TCP/Reality, VLESS WebSocket, VLESS gRPC, Shadowsocks and
Hysteria2. XHTTP is included only in V2Ray links. Nodes not supported by a format
are omitted; if none remain, the response is HTTP 422. Unsupported transports
are never silently converted into TCP. Node names are made unique.

The sing-box output uses a local mixed proxy on 127.0.0.1:7890, a selector and
URL-test group. It does not configure a system-wide TUN interface. Protocol
parameters follow the official [sing-box VLESS documentation](https://sing-box.sagernet.org/configuration/outbound/vless/)
and [Mihomo VLESS documentation](https://wiki.metacubex.one/en/config/proxies/vless/).

## Validation and limits

Run `make test`, `make vet`, and `make build-all`. Optional runtime schema checks:

```bash
HYDRAFLOW_TEST_XRAY=/absolute/path/to/xray \
HYDRAFLOW_TEST_SINGBOX=/absolute/path/to/sing-box \
go test ./cmd/hydraflow -run TestStandalone -count=1 -v
```

Place Xray geo assets next to that test binary. These checks validate generated
configuration syntax; they do not establish whether a protocol bypasses a
particular ISP's blocking. Real VPS installation, client import and connections
from affected networks still require deployment testing.
