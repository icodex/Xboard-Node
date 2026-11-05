# Custom Routes

## Quick Example

```json
{
  "custom_route_rules": [
    {
      "name": "direct-example",
      "match": {"domain_suffixes": ["example.com"]},
      "action": {"type": "direct"}
    },
    {
      "name": "block-ads",
      "match": {"domains": ["ads.example.com"]},
      "action": {"type": "block"}
    },
    {
      "name": "route-warp",
      "match": {"ip_cidrs": ["1.1.1.0/24"], "ports": ["80", "443"]},
      "action": {"type": "route", "target": "warp-out"}
    }
  ]
}
```

## Match Conditions

| Condition | Description | Example |
|-----------|-------------|---------|
| `domains` | Exact domain match | `["api.example.com"]` |
| `domain_suffixes` | Suffix match (apex + subdomains) | `["example.com"]` |
| `ip_cidrs` | IP CIDR ranges | `["10.0.0.0/8"]` |
| `ports` | Port (single or range) | `["443", "8000-9000"]` |
| `networks` | Protocol | `["tcp"]` or `["udp"]` |
| `source_cidrs` | Source IP CIDR | `["192.168.1.0/24"]` |
| `source_ports` | Source port | `["1024-65535"]` |

## Action Types

| Action | Description |
|--------|-------------|
| `{"type": "direct"}` | Direct connection, bypass proxy |
| `{"type": "block"}` | Block connection |
| `{"type": "route", "target": "tag"}` | Route to specified outbound (by tag) |

## Application Order

1. Structured `custom_route_rules` (highest priority)
2. Raw `custom_routes` (translated for sing-box)
3. Built-in blocklist rules
4. Panel routes

## Raw `custom_routes` (three shapes)

The panel `custom_routes` array (the "Custom Routes (JSON)" field) accepts
three entry shapes, detected per entry:

1. **Structured `match`/`action`** — the same shape as a `custom_route_rules`
   entry. Compiled per kernel, identical output to the structured field.
   This is the recommended raw form.
2. **Xray-native** — keys such as `type`/`outboundTag`/`domain`/`ip`/`port`.
   The xray kernel consumes them verbatim; the sing-box kernel translates them
   at config-build time.
3. **sing-box-native** — keys such as `outbound`/`ip_cidr`/`rule_set`. Kept
   verbatim on the sing-box kernel; dropped with a log on the xray kernel.

```json
[
  {"match": {"networks": ["tcp", "udp"]}, "action": {"type": "route", "target": "proxy"}}
]
```

### Failure handling

Raw rules never take a node down. Each entry is classified independently and
any bad entry (unknown keys, unknown `outboundTag`, invalid ports, geo codes
the kernel removed, unparsable shape) is **dropped with one error log**; the
node starts with the remaining rules. A startup crash loop on legacy panel
data is worse than a dropped rule. The panel rejects unrecognized shapes at
save time so mistakes surface while editing.

Xray-form translation details:

Supported keys (one input rule → one output rule; within a key OR, across
keys AND):

| Xray key | sing-box rendering | Notes |
|----------|--------------------|-------|
| `type` | — | Must be `"field"` (or absent) |
| `outboundTag` | `outbound` | Must reference an existing outbound tag; checked for both kernels |
| `domain` | `domain_suffix` / `domain` / `domain_regex` | plain and `domain:v` → `domain_suffix` (case-insensitive, apex + subdomains); `full:x` → `domain`; `regexp:x` → `domain_regex` (must compile) |
| `ip` | `ip_cidr` / `ip_is_private` | CIDR or bare IP; `geoip:private` → `ip_is_private: true` |
| `port` | `port` + `port_range` | `"443"`, `"443,8000-9000"`, array, or bare number; ranges `a-b` / `a:b` |
| `network` | `network` | `"tcp,udp"` string or array; tcp/udp only |
| `source` | `source_ip_cidr` | CIDR or bare IP, no geo codes |
| `sourcePort` | `source_port` + `source_port_range` | same formats as `port` |

Rejected keys and values (validation error, key named):

- Unknown keys: `balancerTag`, `inboundTag`, `protocol`, `attributes`, `user`, `sourceGeoIP`, `sourceGeosite`, and anything else outside the table above
- `geosite:` / `ext:` / `geoip:` values (other than `geoip:private`): the sing-box kernel removed geo databases; use the xray kernel, or a `kernel.custom_route` rule-set entry
- `geoip:!cn`-style negation (sing-box `invert` is whole-rule only)
- Domain attributes (`example.com@attr`)
- A rule with no match condition

Entries outside all three shapes are dropped (see Failure handling above).

## `kernel.custom_route` (local config)

The `custom_route` entries in the node's own config.yml are **kernel-native
and pass through verbatim** — no translation, no validation. Author them in
the form the *running kernel* expects (sing-box rules when kernel is singbox,
Xray rules when xray).

## Kernel Compatibility

| Feature | Xray | Sing-box |
|---------|------|----------|
| Structured `custom_route_rules` | ✅ | ✅ |
| Raw `custom_routes`, structured shape | ✅ | ✅ |
| Raw `custom_routes`, Xray-native shape | ✅ verbatim | ✅ translated (see supported keys above) |
| Raw `custom_routes`, sing-box-native shape | ❌ dropped + log | ✅ verbatim |

## Best Practices

- **Prefer** `custom_route_rules`: cross-kernel compatible, panel-managed
- **Use** `custom_routes`: for one-off rules; the structured shape is the
  portable choice, Xray-native is fine when sing-box translation covers your keys
- **Use** `kernel.custom_route` only: for kernel-native escape hatches on a single node
