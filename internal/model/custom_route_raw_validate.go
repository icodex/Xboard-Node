package model

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cedar2025/xboard-node/internal/nlog"
	xr "github.com/cedar2025/xboard-node/internal/route"
)

// SanitizeRawCustomRoutes validates panel raw custom_routes and rewrites
// n.CustomRoutes to the keepers. Raw rules must never take the node down:
// any bad entry is dropped with one error log instead of failing
// normalization (a startup crash loop on legacy panel data is worse than a
// dropped rule).
//
// Three forms are recognized per entry (see route.DetectForm):
//   - structured match/action (the custom_route_rules entry shape): validated
//     here and compiled per kernel by the builders;
//   - Xray-native: shape-whitelisted and tag-checked for both kernels;
//   - sing-box-native: kept verbatim on the singbox kernel, dropped elsewhere.
func SanitizeRawCustomRoutes(n *NodeSpec, kernelType string, availableTags map[string]struct{}) {
	if n == nil || len(n.CustomRoutes) == 0 {
		return
	}

	kept, keptIdx, issues := xr.SanitizeRules(n.CustomRoutes, kernelType, availableTags, "custom_routes")
	for _, issue := range issues {
		nlog.Core().Error("dropping invalid raw custom route", "issue", issue)
	}

	// Structured entries pass through SanitizeRules verbatim; the match/action
	// shape is validated here against the same contract as
	// custom_route_rules. keptIdx keeps error messages pointing at the
	// original panel list position.
	final := make([]map[string]any, 0, len(kept))
	for i, rule := range kept {
		if !xr.IsStructuredRule(rule) {
			final = append(final, rule)
			continue
		}
		prefix := fmt.Sprintf("custom_routes[%d]", keptIdx[i])
		keep, issue := validateStructuredRawRule(rule, prefix, availableTags)
		if issue != "" {
			nlog.Core().Error("dropping invalid raw custom route", "issue", issue)
			continue
		}
		if !keep {
			continue // disabled rule: dropped silently
		}
		final = append(final, rule)
	}
	n.CustomRoutes = final
}

// validateStructuredRawRule applies the ValidateCustomRouteRules contract to
// one structured raw entry. Returns an issue string when the rule must be
// dropped; "" when it is kept.
func validateStructuredRawRule(rule map[string]any, prefix string, availableTags map[string]struct{}) (keep bool, issue string) {
	parsed, err := parseStructuredRawRule(rule)
	if err != nil {
		return false, fmt.Sprintf("%s: %v", prefix, err)
	}
	if parsed.Disabled {
		return false, ""
	}
	if !hasRouteMatch(parsed.Match) {
		return false, fmt.Sprintf("%s: match is required (at least one of domains, domain_suffixes, ip_cidrs, ports, networks, source_cidrs, source_ports)", prefix)
	}
	if err := validatePortSpecs(parsed.Match.Ports, prefix+".match.ports"); err != nil {
		return false, err.Error()
	}
	if err := validatePortSpecs(parsed.Match.SourcePorts, prefix+".match.source_ports"); err != nil {
		return false, err.Error()
	}
	if err := validateNetworks(parsed.Match.Networks, prefix+".match.networks"); err != nil {
		return false, err.Error()
	}
	actionType := strings.ToLower(strings.TrimSpace(parsed.Action.Type))
	switch actionType {
	case "route":
		target := strings.TrimSpace(parsed.Action.Target)
		if target == "" {
			return false, fmt.Sprintf("%s: action.target is required when action.type is route", prefix)
		}
		if availableTags != nil {
			if _, ok := availableTags[strings.ToLower(target)]; !ok {
				return false, fmt.Sprintf("%s: action.target references unknown outbound %q", prefix, parsed.Action.Target)
			}
		}
	case "direct", "block":
		if strings.TrimSpace(parsed.Action.Target) != "" {
			return false, fmt.Sprintf("%s: action.target is only allowed when action.type is route", prefix)
		}
	default:
		return false, fmt.Sprintf("%s: action.type %q is not supported (use direct, block or route)", prefix, parsed.Action.Type)
	}
	return true, ""
}

func parseStructuredRawRule(rule map[string]any) (CustomRouteRule, error) {
	var parsed CustomRouteRule
	data, err := json.Marshal(rule)
	if err != nil {
		return parsed, err
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return parsed, err
	}
	return parsed, nil
}
