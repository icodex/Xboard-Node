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
