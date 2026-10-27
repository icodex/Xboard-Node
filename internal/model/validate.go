package model

import (
	"fmt"
	"strings"

	"github.com/cedar2025/xboard-node/internal/config"
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

	// Neither kernel implements SIP003 plugins; serving such a node would run
	// a plaintext-capable inbound while clients try to dial with the plugin
	// from the subscription link and fail without any server-side hint.
	if n.Protocol == "shadowsocks" && strings.TrimSpace(n.Plugin) != "" {
		return fmt.Errorf("shadowsocks plugin %q is not supported: neither kernel implements SIP003 plugins; disable the plugin on the panel", n.Plugin)
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
	if err := validateTransportKernel(n.Network, kernelType); err != nil {
		return err
	}
	return nil
}

// singboxUnsupportedTransports lists transport types that sing-box does not support.
var singboxUnsupportedTransports = map[string]bool{
	"xhttp":     true,
	"splithttp": true,
}

// xrayUnsupportedTransports lists transport types the pinned xray-core fork
// removed (infra/conf/transport_internet.go: h2/http and quic return
// PrintRemovedFeatureError and fail config parsing).
var xrayUnsupportedTransports = map[string]bool{
	"h2":   true,
	"http": true,
	"quic": true,
}

func validateTransportKernel(network, kernelType string) error {
	net := strings.ToLower(strings.TrimSpace(network))
	if kernelType == "singbox" && singboxUnsupportedTransports[net] {
		return fmt.Errorf("transport %q is not supported by sing-box kernel; use xray kernel instead", net)
	}
	if kernelType == "xray" && xrayUnsupportedTransports[net] {
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
	if configuredKernel == "singbox" && singboxUnsupportedTransports[net] {
		return "xray"
	}
	if configuredKernel == "xray" && xrayUnsupportedTransports[net] {
		return "singbox"
	}
	return configuredKernel
}

// singboxOnlyProtocols lists protocols only the sing-box kernel serves.
// Verified against the 31-node dual-kernel sweep (docs-protocol-support.md).
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
	if singboxUnsupportedTransports[net] {
		return "xray"
	}
	if xrayUnsupportedTransports[net] {
		return "singbox"
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

func buildAvailableOutboundTags(structured []OutboundConfig, rawTags []string) map[string]struct{} {
	available := map[string]struct{}{
		"direct": {},
		"block":  {},
	}
	for _, outbound := range structured {
		tag := strings.ToLower(strings.TrimSpace(outbound.Tag))
		if tag != "" {
			available[tag] = struct{}{}
		}
	}
	for _, tag := range rawTags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag != "" {
			available[tag] = struct{}{}
		}
	}
	return available
}
