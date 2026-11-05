# Panel Params × Kernel Support Matrix

Every panel "Advanced Protocol Configuration" field and where it lands. The
node's contract is `internal/panel/types.go`; this page records what happens
to each field beyond it.

## Legend

| Mark | Meaning |
|------|---------|
| ✅ | Rendered for the running kernel |
| ⚠️ | Warn-dropped: node logs one warning per apply, config still starts |
| 🔇 | Silent drop: no log (documented here instead) |
| 📱 | Client-side only: consumed by the panel's subscription output, never effective server-side |
| ❌ | Rejected at node config validation (node keeps its previous config) |

## Multiplex (vmess / vless / trojan)

| Key | sing-box | xray |
|-----|----------|------|
| `multiplex.enabled` | ✅ inbound `multiplex.enabled` | ⚠️ no server-side mux config; **mux clients still work** (mux.cool is transparent server-side) |
| `multiplex.padding` | ✅ | ⚠️ same |
| `multiplex.brutal.enabled` + `up_mbps`/`down_mbps` | ✅ | ⚠️ same |
| `multiplex.protocol` / `max_connections` / `min_streams` / `max_streams` | 📱 client subscription params only (sing-box inbound mux is enabled/padding/brutal); node warns | 📱 |

Breakage note: **sing-box kernel + multiplex off + mux-enabled client** = the
inbound rejects mux streams. With xray the same client works. Enable the
toggle when sing-box nodes serve mux users.

## Common inbound policy

| Key | sing-box | xray |
|-----|----------|------|
| `sniff.enable` / `rewriteDomain` | ✅ sniff / sniff_override_destination | ✅ sniffing.enabled / destOverride |
| `sniff.timeout` | ✅ sniff_timeout | ⚠️ no timeout knob |
| `sniff.tcpPorts` / `udpPorts` | ⚠️ no port filter | ⚠️ no port filter |
| `udp_idle_timeout` | ✅ udp_timeout | ⚠️ no per-inbound knob |
| `accept_proxy_protocol` | ⚠️ not supported (source IPs become the frontend's) | ✅ sockopt.acceptProxyProtocol |

## QUIC tuning (hysteria / tuic)

| Key | sing-box | xray |
|-----|----------|------|
| `quic.disablePathMTUDiscovery` | ✅ | ⚠️ (policy-fields warn) |
| `quic.*` windows / `maxIdleTimeout` / `maxIncomingStreams` / `disableStatelessReset` | ⚠️ not exposed by the kernel | ⚠️ |

## TUIC

| Key | sing-box | xray |
|-----|----------|------|
| `congestion_control` | ✅ | — (tuic is sing-box-only) |
| `udp_relay_mode` (`native` / `quic`) | 📱 client subscription param (`TUICOutboundOptions`); sing-box has **no inbound udp_relay_mode**; panel validates the enum so junk values can't corrupt client configs, node config never receives it | — |
| top-level `alpn` | 🔇 dead key: not sent by the panel, no consumer; server ALPN is fixed h3 (`tls_settings.alpn` is the honored path, h3 fallback) | — |

## Hysteria policy fields

| Key | sing-box (hysteria2) | xray (hysteria2 only) |
|-----|----------------------|------------------------|
| `ignore_client_bandwidth` | ✅ | ⚠️ |
| `congestion.bbrProfile` | ✅ | ⚠️ |
| `congestion.type` ≠ bbr | ⚠️ always BBR | ⚠️ |
| `masquerade.*` | ✅ (404/file/proxy/string) | ⚠️ |
| `resolver.*` / `disable_udp` / `disable_loss_compensation` | ⚠️ | ⚠️ |
| `obfs` (v1 password / v2 salamander) | ✅ | ⚠️ xray hysteria has no obfs |
| `hop_interval` | 📱 client subscription only | — |

## Shadowsocks

| Key | Note |
|-----|------|
| `plugin` / `plugin_opts` | ❌ rejected at node validation; panel prohibits non-empty saves. No kernel implements SIP003 server-side |
| `obfs` / `obfs_settings.*` | panel prohibits non-empty saves (2026-11-06): no kernel implements ss simple-obfs server-side; node would serve plaintext while obfs clients fail — the original silent-breakage case |
| `server_key` (SS2022) | ✅ derived by the panel, consumed by both kernels |

## VMess / VLESS TLS

| Key | sing-box | xray |
|-----|----------|------|
| `tls=2` Reality (vless/trojan) | ✅ | ✅ |
| vmess + Reality (tls=2) | ⚠️ plaintext inbound + warn (kernel auto-select picks xray) | ✅ |
| `tls_settings.alpn` | ✅ verbatim (naive defaults h2, hysteria/tuic default h3) | ✅ |
| `tls_settings.ech.*` | ✅ key / key_path | ✅ echServerKeys |
| vless `decryption` (encryption) | ⚠️ none/unsupported + warn | ✅ |
| `utls.*` | 📱 client subscription only | 📱 |

## Client-only keys (no server effect, by design)

`utls.enabled`/`fingerprint`, hysteria `hop_interval`, multiplex
`protocol`/`max_connections`/`min_streams`/`max_streams`. The panel's
subscription output (Clash/SingBox/etc.) consumes these; the node contract has
no field for them.

## Dead keys (panel accepts, nothing consumes)

- vmess `protocol_settings.rules` — v2board legacy, not sent, no consumer
- tuic top-level `alpn` — see TUIC table

These stay validated-but-unsent to avoid 400s from UIs that still submit them.
