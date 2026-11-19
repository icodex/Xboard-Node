package model

type CustomRouteRule struct {
	Name     string      `json:"name"`
	Disabled bool        `json:"disabled"`
	Match    RouteMatch  `json:"match"`
	Action   RouteAction `json:"action"`
}

// RouteMatch carries the panel's snake_case shape: raw structured
// custom_routes entries are decoded with encoding/json, which folds case but
// not underscores, so these tags are load-bearing.
type RouteMatch struct {
	Domains        []string `json:"domains,omitempty"`
	DomainSuffixes []string `json:"domain_suffixes,omitempty"`
	IPCIDRs        []string `json:"ip_cidrs,omitempty"`
	Ports          []string `json:"ports,omitempty"`
	Networks       []string `json:"networks,omitempty"`
	SourceCIDRs    []string `json:"source_cidrs,omitempty"`
	SourcePorts    []string `json:"source_ports,omitempty"`
}

type RouteAction struct {
	Type   string `json:"type"`
	Target string `json:"target,omitempty"`
}

func cloneCustomRouteRules(src []CustomRouteRule) []CustomRouteRule {
	if len(src) == 0 {
		return nil
	}
	out := make([]CustomRouteRule, 0, len(src))
	for _, rule := range src {
		out = append(out, CustomRouteRule{
			Name:     rule.Name,
			Disabled: rule.Disabled,
			Match:    cloneRouteMatch(rule.Match),
			Action:   cloneRouteAction(rule.Action),
		})
	}
	return out
}

func cloneRouteMatch(src RouteMatch) RouteMatch {
	return RouteMatch{
		Domains:        cloneStringSlice(src.Domains),
		DomainSuffixes: cloneStringSlice(src.DomainSuffixes),
		IPCIDRs:        cloneStringSlice(src.IPCIDRs),
		Ports:          cloneStringSlice(src.Ports),
		Networks:       cloneStringSlice(src.Networks),
		SourceCIDRs:    cloneStringSlice(src.SourceCIDRs),
		SourcePorts:    cloneStringSlice(src.SourcePorts),
	}
}

func cloneRouteAction(src RouteAction) RouteAction {
	return RouteAction{
		Type:   src.Type,
		Target: src.Target,
	}
}
