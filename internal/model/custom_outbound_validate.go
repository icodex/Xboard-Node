package model

import (
	"fmt"
	"strconv"
	"strings"

	ob "github.com/cedar2025/xboard-node/internal/outbound"
)

// dialerProxyRef is one sockopt.dialerProxy reference collected during the
// first pass, checked once every outbound tag is known (forward references are
// legal, self references are not).
type dialerProxyRef struct {
	index int
	tag   string
	ref   string
}

func ValidateCustomOutboundsForKernel(outbounds []OutboundConfig, kernelType string, additionalTags []string) error {
	if len(outbounds) == 0 {
		return nil
	}

	kernelType = strings.ToLower(strings.TrimSpace(kernelType))
	allowedProtocols := map[string]struct{}{}
	if kernelType != "" {
		support, ok := OutboundSupportMatrix()[kernelType]
		if !ok {
			return fmt.Errorf("unsupported kernel type %q", kernelType)
		}
		for _, protocol := range support.Protocols {
			allowedProtocols[strings.ToLower(protocol)] = struct{}{}
		}
	}

	seen := make(map[string]struct{}, len(outbounds))
	availableTags := make(map[string]struct{}, len(outbounds)+len(additionalTags)+2)
	availableTags["direct"] = struct{}{}
	availableTags["block"] = struct{}{}
	var dialerRefs []dialerProxyRef
	for _, tag := range additionalTags {
		tag = strings.TrimSpace(tag)
		if tag != "" {
			availableTags[tag] = struct{}{}
		}
	}

	for i, outbound := range outbounds {
		tag := strings.TrimSpace(outbound.Tag)
		protocol := strings.ToLower(strings.TrimSpace(outbound.Protocol))
		if tag == "" {
			return fmt.Errorf("custom_outbounds[%d].tag is required", i)
		}
		if IsReservedOutboundTag(tag) {
			return fmt.Errorf("custom_outbounds[%d].tag %q is reserved for the built-in %s outbound", i, outbound.Tag, strings.ToLower(tag))
		}
		if protocol == "" {
			return fmt.Errorf("custom_outbounds[%d].protocol is required", i)
		}
		if kernelType != "" {
			if _, ok := allowedProtocols[protocol]; !ok {
				return fmt.Errorf("custom_outbounds[%d].protocol %q is not supported by kernel %q", i, outbound.Protocol, kernelType)
			}
		}
		if err := validateOutboundSettings(i, outbound.Settings); err != nil {
			return err
		}
		canonical, err := ob.Parse(outbound.Protocol, outbound.Settings, outbound.StreamSettings, outbound.Mux, outbound.ProxyTag)
		if err != nil {
			return fmt.Errorf("custom_outbounds[%d] (%s): %w", i, tag, err)
		}
		if err := ob.ValidateForKernel(canonical, kernelType); err != nil {
			return fmt.Errorf("custom_outbounds[%d] (%s): %w", i, tag, err)
		}
		key := strings.ToLower(tag)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("custom_outbounds[%d].tag duplicates %q", i, tag)
		}
		seen[key] = struct{}{}
		availableTags[tag] = struct{}{}
		if canonical.Stream != nil {
			if ref := strings.TrimSpace(canonical.Stream.DialerProxy); ref != "" {
				dialerRefs = append(dialerRefs, dialerProxyRef{index: i, tag: tag, ref: ref})
			}
		}
	}

	for i, outbound := range outbounds {
		if outbound.ProxyTag == "" {
			continue
		}
		proxyTag := strings.TrimSpace(outbound.ProxyTag)
		if proxyTag == "" {
			return fmt.Errorf("custom_outbounds[%d].proxy_tag must not be blank", i)
		}
		if proxyTag == strings.TrimSpace(outbound.Tag) {
			return fmt.Errorf("custom_outbounds[%d].proxy_tag must not reference itself", i)
		}
		// Tags are rendered with their original case and both kernels match
		// references exactly, so compare without folding case.
		if _, exists := availableTags[proxyTag]; !exists {
			return fmt.Errorf("custom_outbounds[%d].proxy_tag references unknown outbound %q", i, outbound.ProxyTag)
		}
	}

	// sockopt.dialerProxy is the other tag reference the builders write
	// verbatim (sing-box "detour", xray "sockopt.dialerProxy"). An unknown or
	// self reference makes kernel config parsing fail.
	for _, ref := range dialerRefs {
		if ref.ref == ref.tag {
			return fmt.Errorf("custom_outbounds[%d] (%s): sockopt.dialerProxy must not reference itself", ref.index, ref.tag)
		}
		if _, exists := availableTags[ref.ref]; !exists {
			return fmt.Errorf("custom_outbounds[%d] (%s): sockopt.dialerProxy references unknown outbound %q", ref.index, ref.tag, ref.ref)
		}
	}

	return nil
}

func validateOutboundSettings(index int, settings map[string]any) error {
	if len(settings) == 0 {
		return fmt.Errorf("custom_outbounds[%d].settings is required", index)
	}
	for _, reservedKey := range []string{"tag", "protocol", "proxy_tag", "proxyTag"} {
		if _, exists := settings[reservedKey]; exists {
			return fmt.Errorf("custom_outbounds[%d].settings.%s is reserved", index, reservedKey)
		}
	}
	for _, field := range []string{"server", "uuid", "password", "method", "cipher", "private_key", "secret_key", "privateKey", "secretKey"} {
		if value, ok := settings[field]; ok {
			if strings.TrimSpace(fmt.Sprintf("%v", value)) == "" {
				return fmt.Errorf("custom_outbounds[%d].settings.%s must not be blank", index, field)
			}
		}
	}
	if value, ok := settings["server_port"]; ok {
		if _, err := asPort(value); err != nil {
			return fmt.Errorf("custom_outbounds[%d].settings.server_port %w", index, err)
		}
	}
	if value, ok := settings["serverPort"]; ok {
		if _, err := asPort(value); err != nil {
			return fmt.Errorf("custom_outbounds[%d].settings.serverPort %w", index, err)
		}
	}
	return nil
}

func asPort(value any) (int, error) {
	switch v := value.(type) {
	case int:
		if v < 1 || v > 65535 {
			return 0, fmt.Errorf("must be between 1 and 65535")
		}
		return v, nil
	case int32:
		return asPort(int(v))
	case int64:
		return asPort(int(v))
	case float64:
		if v != float64(int(v)) {
			return 0, fmt.Errorf("must be an integer")
		}
		return asPort(int(v))
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return 0, fmt.Errorf("must be an integer")
		}
		return asPort(parsed)
	default:
		return 0, fmt.Errorf("must be an integer")
	}
}
