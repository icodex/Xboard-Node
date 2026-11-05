package route

import "fmt"

// RenderSingbox renders a parsed rule into one sing-box legacy route rule.
// Pure: it builds fresh maps and never mutates the parsed rule or its slices.
// The legacy top-level "outbound" key is the route-action shorthand the
// embedded sing-box fork still parses (option.RuleAction.UnmarshalJSON maps a
// bare outbound to action=route).
func RenderSingbox(r *Rule) map[string]any {
	entry := map[string]any{"outbound": r.OutboundTag}
	if len(r.DomainSuffixes) > 0 {
		entry["domain_suffix"] = copyStrings(r.DomainSuffixes)
	}
	if len(r.Domains) > 0 {
		entry["domain"] = copyStrings(r.Domains)
	}
	if len(r.DomainRegexps) > 0 {
		entry["domain_regex"] = copyStrings(r.DomainRegexps)
	}
	if len(r.IPCIDRs) > 0 {
		entry["ip_cidr"] = copyStrings(r.IPCIDRs)
	}
	if r.IPIsPrivate {
		entry["ip_is_private"] = true
	}
	if len(r.Ports) > 0 {
		entry["port"] = copyInts(r.Ports)
	}
	if len(r.PortRanges) > 0 {
		entry["port_range"] = copyStrings(r.PortRanges)
	}
	if len(r.Networks) > 0 {
		entry["network"] = copyStrings(r.Networks)
	}
	if len(r.SourceIPCIDRs) > 0 {
		entry["source_ip_cidr"] = copyStrings(r.SourceIPCIDRs)
	}
	if len(r.SourcePorts) > 0 {
		entry["source_port"] = copyInts(r.SourcePorts)
	}
	if len(r.SourcePortRanges) > 0 {
		entry["source_port_range"] = copyStrings(r.SourcePortRanges)
	}
	return entry
}

// RenderSingboxRules parses and renders a raw rule list for the sing-box
// kernel, prefixing errors with the list index.
func RenderSingboxRules(rules []map[string]any) ([]map[string]any, error) {
	parsed, err := ParseRules(rules)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(parsed))
	for i, rule := range parsed {
		if rule.IsEmpty() {
			return nil, fmt.Errorf("rule %d: has no match condition", i)
		}
		out = append(out, RenderSingbox(rule))
	}
	return out, nil
}

func copyStrings(src []string) []string {
	out := make([]string, len(src))
	copy(out, src)
	return out
}

func copyInts(src []int) []int {
	out := make([]int, len(src))
	copy(out, src)
	return out
}
