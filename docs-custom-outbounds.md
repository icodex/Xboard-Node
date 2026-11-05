# Custom Outbounds

Custom outbounds are managed from the panel and stored in **Xray-native form**.
The node renders each entry in the native layout of the kernel it is running:
Xray entries are passed through (with flat shorthand assembled into
`vnext`/`servers`/`peers`), and sing-box runs a translated flat outbound.

## Quick Example

VLESS + REALITY, written in the Xray form the panel stores:

```json
{
  "custom_outbounds": [
    {
      "tag": "proxy",
      "protocol": "vless",
      "settings": {
        "address": "example.com",
        "port": 443,
        "id": "211ed558-90f0-4f32-ba5b-d11c1007e2bf",
        "flow": "xtls-rprx-vision",
        "encryption": "none"
      },
      "streamSettings": {
        "network": "raw",
        "security": "reality",
        "realitySettings": {
          "serverName": "www.apple.com",
          "fingerprint": "chrome",
          "publicKey": "<reality public key>",
          "shortId": "a3e60d54"
        }
      },
      "mux": {"enabled": false, "concurrency": -1}
    }
  ]
}
```

The same entry may be written in fully nested Xray form
(`settings.vnext[0].users[0]`). Existing sing-box-native settings
(`server`, `server_port`, `uuid`, `tls`, `transport`) are also accepted.

## Supported Protocols

| Protocol | Xray | Sing-box |
|----------|------|----------|
| vmess | ✅ | ✅ |
| vless | ✅ | ✅ |
| trojan | ✅ | ✅ |
| shadowsocks | ✅ | ✅ |
| socks | ✅ | ✅ |
| http | ✅ | ✅ |
| wireguard | ✅ | ✅ |
| tuic | ❌ | ✅ |
| hysteria2 | ❌ | ✅ |
| anytls | ❌ | ✅ |
| naive | ❌ | ✅ |
| mieru | ❌ | ✅ |

sing-box-only protocols use sing-box-native `settings` and are passed through.

## Core Fields

| Field | Required | Description |
|-------|----------|-------------|
| `tag` | ✅ | Outbound tag, referenced in routes |
| `protocol` | ✅ | Protocol type |
| `settings` | ✅ | Protocol-specific configuration |
| `streamSettings` | ❌ | Xray transport/TLS/REALITY layer |
| `mux` | ❌ | Xray multiplex |
| `proxy_tag` | ❌ | Chain to another outbound (references its tag) |

## Kernel Rendering

| Xray field | sing-box output |
|---|---|
| `address` / `port` | `server` / `server_port` |
| `id` | `uuid` |
| `flow` | `flow` |
| `password` / `method` / `username` | same |
| `security: tls` + `tlsSettings` | `tls` (+ `utls` when a fingerprint is set) |
| `security: reality` + `realitySettings` | `tls.reality` (`public_key`, `short_id`) + `utls` |
| `network: raw/tcp` | no `transport` |
| `network: ws` | `transport.type: ws` |
| `network: grpc` | `transport.type: grpc` |
| `network: httpupgrade` | `transport.type: httpupgrade` |
| `network: http/h2` | `transport.type: http` |
| `sockopt.dialerProxy` | `detour` |
| `mux.concurrency` | `multiplex.max_connections` (protocol defaults to `smux`) |
| `proxy_tag` | `detour` (sing-box) / `proxySettings.tag` (xray) |

## Limitations

- A custom outbound describes **one server**. Xray load-balancing arrays with
  more than one `vnext` or `servers` entry are rejected for sing-box with an
  actionable error.
- `xhttp` / `splithttp` are not supported by the sing-box kernel; use the xray
  kernel for those transports.
- `h2` / `http` / `quic` transports were removed from the pinned xray-core fork;
  use the sing-box kernel for those.
- REALITY as a *client* from the sing-box kernel has a known handshake
  incompatibility against xray-kernel REALITY servers; see
  `docs-known-issue-singbox-reality-client.md`.

## Validation

Shape errors are rejected while normalizing the panel config, before the kernel
starts. Examples:

```
custom_outbounds[0] (proxy): reality requires publicKey
custom_outbounds[0] (proxy): streamSettings.network "xhttp" is not supported by the sing-box kernel; use kernel xray
custom_outbounds[0] (proxy): settings has 2 servers; sing-box outbounds support exactly one
```

## Troubleshooting

### `dial tcp <ip>:<port>: i/o timeout` under `outbound/<proto>[tag]`

The kernel reached the custom outbound `<tag>` chosen by routing and tried to
open a TCP connection to the upstream server; the SYN got no answer. This is
**not** a rendering problem — rendering is pinned by
`go test ./internal/outbound/`, which asserts server, port, uuid, flow, TLS,
uTLS and REALITY fields for the exact panel payload.

Locate it in three steps:

1. **From the node itself**, test plain TCP to the same endpoint:

   ```
   docker exec <node-container> nc -vz <server> <port>
   ```

   A timeout here means the node's network cannot reach the server.
2. **Compare DNS**: `getent hosts <server>` inside the container vs. from your
   own machine. A different IP means DNS poisoning/hijack — fix the node's
   resolver or use the IP in the panel outbound.
3. **Check the upstream**: server firewall/allowlist (the node's public IP may
   not be permitted), provider-level egress blocking of that port, or the
   server simply being down.

At startup the node probes every TCP-based custom outbound endpoint
(5 s timeout, background, non-fatal) and warns:

```
WARN custom outbound endpoint unreachable tag=proxy protocol=vless
     endpoint=example.com:443 error=dial tcp ...: i/o timeout
     hint=traffic routed to this outbound will fail; check the upstream server...
```

With `log.level: debug` each rendered outbound also logs a credential-free
summary (`protocol`, `server`, `server_port`, `transport`, `security`, `flow`,
`detour`, `multiplex`).

## Best Practices

- **Prefer** `custom_outbounds`: panel-managed, rendered per kernel.
- **Use** `kernel.custom_outbound` / `kernel.custom_config` only for local
  static overrides that are already native to the target kernel.
