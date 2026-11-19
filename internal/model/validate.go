package model

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/outbound"
)

func ValidateNodeSpec(n *NodeSpec, kcfg config.KernelConfig) error {
	if n == nil {
		return nil
	}

	effectiveKernelType := strings.TrimSpace(kcfg.Type)
	if effectiveKernelType == "" {
		effectiveKernelType = strings.TrimSpace(n.KernelType)
	}
	kernelType, err := normalizeKernelType(effectiveKernelType)
	if err != nil {
		return fmt.Errorf("normalize kernel type: %w", err)
	}
	if kernelType == "auto" {
		// Validate against the concrete kernel auto-selection would pick.
		kernelType = ResolveKernelForNode(n, kcfg)
	}

	if c := strings.ToLower(strings.TrimSpace(n.Cipher)); strings.HasPrefix(c, "2022-blake3-chacha") {
		return fmt.Errorf("cipher %q cannot serve multiple users: SIP022 identity headers (EIH) are AES-only; use a 2022-blake3-aes-*-gcm cipher", n.Cipher)
	}

	// The xray fork's infra/conf cipherFromString only knows the methods below
	// (plus the shadowsocks_2022 ones); anything else resolves to
	// CipherType_UNKNOWN and the kernel dies at config parse. Reject up front
	// so the panel gets an actionable error instead of a retry loop.
	if kernelType == "xray" && n.Protocol == "shadowsocks" {
		cipher := strings.ToLower(strings.TrimSpace(n.Cipher))
		if !xrayShadowsocksCiphers[cipher] {
			return fmt.Errorf("cipher %q is not supported by xray kernel: use aes-128-gcm/aes-256-gcm/chacha20-ietf-poly1305/xchacha20-ietf-poly1305/2022-blake3-aes-*-gcm, or switch kernel to singbox/auto", n.Cipher)
		}
	}

	// Neither kernel implements SIP003 plugins; serving such a node would run
	// a plaintext-capable inbound while clients try to dial with the plugin
	// from the subscription link and fail without any server-side hint.
	if n.Protocol == "shadowsocks" && strings.TrimSpace(n.Plugin) != "" {
		return fmt.Errorf("shadowsocks plugin %q is not supported: neither kernel implements SIP003 plugins; disable the plugin on the panel", n.Plugin)
	}

	if err := validateHysteriaPolicy(n); err != nil {
		return err
	}

	additionalOutboundSources, err := collectAdditionalOutboundTagSources(kcfg.CustomConfig, kcfg.CustomOutbound)
	if err != nil {
		return fmt.Errorf("collect additional outbound tags: %w", err)
	}
	if err := validateOutboundTagCollisions(n.CustomOutbounds, additionalOutboundSources); err != nil {
		return fmt.Errorf("validate outbound tags: %w", err)
	}
	additionalTags := additionalTagNames(additionalOutboundSources)
	availableTags := buildAvailableOutboundTags(n.CustomOutbounds, additionalTags)
	if err := ValidateCustomOutboundsForKernel(n.CustomOutbounds, kernelType, additionalTags); err != nil {
		return fmt.Errorf("validate custom outbounds: %w", err)
	}
	if err := ValidateCustomRouteRules(n.CustomRouteRules, kernelType, availableTags); err != nil {
		return fmt.Errorf("validate custom route rules: %w", err)
	}
	if err := validatePanelRoutes(n.Routes, kernelType, availableTags); err != nil {
		return fmt.Errorf("validate routes: %w", err)
	}
	// Raw custom_routes never fail the node: bad entries are dropped with an
	// error log (legacy panel data must not start a crash loop).
	SanitizeRawCustomRoutes(n, kernelType, availableTags)
	if err := validateTransportKernel(n.Network, kernelType); err != nil {
		return err
	}
	return nil
}

// xrayShadowsocksCiphers lists the Shadowsocks methods the pinned xray-core
// fork can serve: infra/conf/shadowsocks.go cipherFromString (AEAD) plus
// proxy/shadowsocks_2022 methods. 2022-blake3-chacha is excluded upstream for
// multi-user (see the SIP022 check in ValidateNodeSpec).
var xrayShadowsocksCiphers = map[string]bool{
	"aes-128-gcm":             true,
	"aes-256-gcm":             true,
	"chacha20-ietf-poly1305":  true,
	"xchacha20-ietf-poly1305": true,
	"2022-blake3-aes-128-gcm": true,
	"2022-blake3-aes-256-gcm": true,
}

// Transport capability comes from outbound's tables: a second copy here had
// already drifted (it was missing kcp/mkcp/quic for sing-box), so auto mode
// picked a kernel that could not parse the transport.
func validateTransportKernel(network, kernelType string) error {
	net := strings.ToLower(strings.TrimSpace(network))
	switch {
	case outbound.NetworkUnsupportedByBoth(net):
		return fmt.Errorf("transport %q is not supported by either kernel", net)
	case kernelType == "singbox" && outbound.SingboxUnsupportedNetwork(net):
		return fmt.Errorf("transport %q is not supported by sing-box kernel; use xray kernel instead", net)
	case kernelType == "xray" && outbound.XrayUnsupportedNetwork(net):
		return fmt.Errorf("transport %q is not supported by xray kernel (removed upstream); use sing-box kernel instead", net)
	}
	return nil
}

// ResolveKernelForTransport returns the kernel type required by the given
// transport. If the configured kernel cannot handle the transport, it returns
// the kernel that can. Otherwise it returns configuredKernel unchanged.
// This is used in machine mode to auto-switch kernel per node.
func ResolveKernelForTransport(network, configuredKernel string) string {
	net := strings.ToLower(strings.TrimSpace(network))
	if outbound.NetworkUnsupportedByBoth(net) {
		// No kernel can serve it; validation reports the precise reason.
		return configuredKernel
	}
	if configuredKernel == "singbox" && outbound.SingboxUnsupportedNetwork(net) {
		return "xray"
	}
	if configuredKernel == "xray" && outbound.XrayUnsupportedNetwork(net) {
		return "singbox"
	}
	return configuredKernel
}

// singboxOnlyProtocols lists protocols only the sing-box kernel serves.
// Verified against the 31-node dual-kernel sweep (docs-params-support.md).
var singboxOnlyProtocols = map[string]bool{
	"tuic":     true,
	"anytls":   true,
	"naive":    true,
	"socks":    true,
	"http":     true,
	"mieru":    true,
	"hysteria": true, // v1; xray only takes hysteria2
}

// ResolveKernelForNode picks the kernel for a node spec.
//
// With an explicit configured kernel it only flips when the transport is
// unsupported (machine-mode auto-switch semantics); other conflicts surface
// as validation errors. With kernel.type "auto" (or empty) it resolves fully:
// explicit panel kernel_type first, then sing-box-only protocols, then
// transport requirements, then vmess+Reality (sing-box would silently run
// plaintext), then the sing-box default.
func ResolveKernelForNode(n *NodeSpec, kcfg config.KernelConfig) string {
	configured := strings.ToLower(strings.TrimSpace(kcfg.Type))
	if configured != "auto" && configured != "" {
		if n == nil {
			return configured
		}
		return ResolveKernelForTransport(n.Network, configured)
	}
	if n == nil {
		return "singbox"
	}
	if k := strings.ToLower(strings.TrimSpace(n.KernelType)); k != "" && k != "auto" {
		if norm, err := normalizeKernelType(k); err == nil {
			return norm
		}
	}
	protocol := strings.ToLower(strings.TrimSpace(n.Protocol))
	if singboxOnlyProtocols[protocol] {
		return "singbox"
	}
	net := strings.ToLower(strings.TrimSpace(n.Network))
	if !outbound.NetworkUnsupportedByBoth(net) {
		if outbound.SingboxUnsupportedNetwork(net) {
			return "xray"
		}
		if outbound.XrayUnsupportedNetwork(net) {
			return "singbox"
		}
	}
	if protocol == "vmess" && n.TLS == 2 {
		return "xray"
	}
	return "singbox"
}

func normalizeKernelType(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "singbox", "sing-box":
		return "singbox", nil
	case "xray":
		return "xray", nil
	case "auto":
		return "auto", nil
	default:
		return "", fmt.Errorf("unsupported kernel type %q", value)
	}
}

// buildAvailableOutboundTags returns the outbound tags that will be rendered
// into the kernel config. Tags keep their original case: both kernels match
// tag references exactly, so a case-insensitive set would pass references the
// kernel can never resolve.
func buildAvailableOutboundTags(structured []OutboundConfig, rawTags []string) map[string]struct{} {
	available := map[string]struct{}{
		"direct": {},
		"block":  {},
	}
	for _, outbound := range structured {
		tag := strings.TrimSpace(outbound.Tag)
		if tag != "" {
			available[tag] = struct{}{}
		}
	}
	for _, tag := range rawTags {
		tag = strings.TrimSpace(tag)
		if tag != "" {
			available[tag] = struct{}{}
		}
	}
	return available
}

// validatePanelRoutes checks the legacy panel routes list before the kernel
// builders copy its values verbatim. Both builders classify a matcher by
// "contains a slash" and write action_value as an outbound tag, so an
// unparsable CIDR, an unsupported database reference or an unknown tag makes
// the kernel reject the entire config (and the service then restarts it in a
// loop).
func validatePanelRoutes(routes []RouteRule, kernelType string, availableTags map[string]struct{}) error {
	for i, rule := range routes {
		for _, raw := range rule.Match {
			item := strings.TrimSpace(raw)
			if item == "" {
				continue
			}
			lowered := strings.ToLower(item)
			switch {
			case strings.HasPrefix(lowered, "geoip:"):
				if kernelType == "singbox" {
					return fmt.Errorf("routes[%d].match %q: the sing-box kernel has no geoip database; use plain CIDRs or the xray kernel", i, raw)
				}
			case strings.HasPrefix(lowered, "geosite:"):
				if kernelType == "singbox" {
					return fmt.Errorf("routes[%d].match %q: the sing-box kernel has no geosite database; use plain domains or the xray kernel", i, raw)
				}
			case strings.Contains(item, "/"):
				if _, err := netip.ParsePrefix(item); err != nil {
					return fmt.Errorf("routes[%d].match %q: not a valid CIDR", i, raw)
				}
			}
		}

		// The builders default an empty action to block; keep that contract.
		action := strings.ToLower(strings.TrimSpace(rule.Action))
		target := strings.TrimSpace(rule.ActionValue)
		switch action {
		case "", "block", "direct":
			continue
		case "proxy":
		case "dns":
			if kernelType == "xray" {
				// xray compiles this action to block and ignores action_value.
				continue
			}
			if target == "" {
				// The sing-box builder writes outbound "dns-out", which the
				// node never defines; the kernel then rejects the config.
				return fmt.Errorf("routes[%d].action %q requires action_value on the sing-box kernel", i, rule.Action)
			}
		default:
			return fmt.Errorf("routes[%d].action %q is not supported (use block, direct, proxy or dns)", i, rule.Action)
		}
		if target == "" {
			// target-less proxy falls back to block in both builders.
			continue
		}
		if availableTags != nil {
			if _, ok := availableTags[target]; !ok {
				return fmt.Errorf("routes[%d].action_value references unknown outbound %q", i, rule.ActionValue)
			}
		}
	}
	return nil
}

// hysteriaBBRProfiles matches both the sing-box fork enum and hysteria core
// ParseProfile: standard, conservative, aggressive.
var hysteriaBBRProfiles = map[string]bool{
	"standard":     true,
	"conservative": true,
	"aggressive":   true,
}

// validateHysteriaPolicy checks the panel-policy fields every backend would
// otherwise only reject at config-parse time.
func validateHysteriaPolicy(n *NodeSpec) error {
	if n.Protocol != "hysteria" {
		return nil
	}
	if n.HysteriaCongestion != nil {
		if p := strings.TrimSpace(n.HysteriaCongestion.BBRProfile); p != "" && !hysteriaBBRProfiles[strings.ToLower(p)] {
			return fmt.Errorf("hysteria congestion.bbr_profile %q is invalid: use standard, conservative or aggressive", p)
		}
		if t := strings.ToLower(strings.TrimSpace(n.HysteriaCongestion.Type)); t != "" && t != "bbr" && t != "reno" {
			return fmt.Errorf("hysteria congestion.type %q is invalid: use bbr or reno", n.HysteriaCongestion.Type)
		}
	}
	if n.UDPIdleTimeout != 0 && (n.UDPIdleTimeout < 1 || n.UDPIdleTimeout > 600) {
		return fmt.Errorf("hysteria udp_idle_timeout %d out of range: use 1-600 seconds", n.UDPIdleTimeout)
	}
	return nil
}
