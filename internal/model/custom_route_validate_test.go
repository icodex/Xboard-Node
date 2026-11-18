package model

import (
	"strings"
	"testing"
)

func TestValidateCustomRouteRules(t *testing.T) {
	available := map[string]struct{}{"direct": {}, "block": {}, "warp": {}, "proxy": {}}
	tests := []struct {
		name    string
		rules   []CustomRouteRule
		kernel  string
		wantErr string
	}{
		{
			name: "valid route target",
			rules: []CustomRouteRule{{
				Match:  RouteMatch{DomainSuffixes: []string{"example.com"}, Ports: []string{"443"}, Networks: []string{"tcp"}},
				Action: RouteAction{Type: "route", Target: "warp"},
			}},
			kernel: "singbox",
		},
		{
			name:    "missing match",
			rules:   []CustomRouteRule{{Action: RouteAction{Type: "direct"}}},
			kernel:  "singbox",
			wantErr: "custom_route_rules[0].match is required",
		},
		{
			name:    "unknown target",
			rules:   []CustomRouteRule{{Match: RouteMatch{DomainSuffixes: []string{"example.com"}}, Action: RouteAction{Type: "route", Target: "missing"}}},
			kernel:  "singbox",
			wantErr: `custom_route_rules[0].action.target references unknown outbound "missing"`,
		},
		{
			name:    "route target required",
			rules:   []CustomRouteRule{{Match: RouteMatch{DomainSuffixes: []string{"example.com"}}, Action: RouteAction{Type: "route"}}},
			kernel:  "singbox",
			wantErr: "custom_route_rules[0].action.target is required when action.type is route",
		},
		{
			name:    "direct target forbidden",
			rules:   []CustomRouteRule{{Match: RouteMatch{DomainSuffixes: []string{"example.com"}}, Action: RouteAction{Type: "direct", Target: "warp"}}},
			kernel:  "singbox",
			wantErr: "custom_route_rules[0].action.target is only allowed when action.type is route",
		},
		{
			name:    "unsupported action",
			rules:   []CustomRouteRule{{Match: RouteMatch{DomainSuffixes: []string{"example.com"}}, Action: RouteAction{Type: "dns"}}},
			kernel:  "singbox",
			wantErr: `custom_route_rules[0].action.type "dns" is not supported by kernel "singbox"`,
		},
		{
			name:    "invalid port range",
			rules:   []CustomRouteRule{{Match: RouteMatch{Ports: []string{"2000-1000"}}, Action: RouteAction{Type: "direct"}}},
			kernel:  "singbox",
			wantErr: `custom_route_rules[0].match.ports contains invalid port range "2000-1000"`,
		},
		{
			name:    "invalid network",
			rules:   []CustomRouteRule{{Match: RouteMatch{Networks: []string{"icmp"}}, Action: RouteAction{Type: "direct"}}},
			kernel:  "singbox",
			wantErr: `custom_route_rules[0].match.networks contains unsupported network "icmp"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateCustomRouteRules(tc.rules, tc.kernel, available)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if tc.wantErr != "" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

// Geo database references: xray loads geoip/geosite, sing-box has neither.
// A value under the wrong matcher also has to fail (xray would silently never
// match) instead of reaching the kernel and failing config parsing.
func TestValidateCustomRouteRules_GeoValues(t *testing.T) {
	rule := func(m RouteMatch) []CustomRouteRule {
		return []CustomRouteRule{{Match: m, Action: RouteAction{Type: "direct"}}}
	}
	tests := []struct {
		name    string
		kernel  string
		match   RouteMatch
		wantErr bool
	}{
		{"xray geoip in ip_cidrs", "xray", RouteMatch{IPCIDRs: []string{"geoip:cn"}}, false},
		{"xray geosite in domain_suffixes", "xray", RouteMatch{DomainSuffixes: []string{"geosite:cn"}}, false},
		{"xray geosite in ip_cidrs", "xray", RouteMatch{IPCIDRs: []string{"geosite:cn"}}, true},
		{"xray geoip in domains", "xray", RouteMatch{Domains: []string{"geoip:cn"}}, true},
		{"singbox geoip", "singbox", RouteMatch{IPCIDRs: []string{"geoip:cn"}}, true},
		{"singbox geosite", "singbox", RouteMatch{DomainSuffixes: []string{"geosite:cn"}}, true},
		{"singbox literal", "singbox", RouteMatch{IPCIDRs: []string{"10.0.0.0/8"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCustomRouteRules(rule(tt.match), tt.kernel, nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateCustomRouteRules error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Prefixes that only one kernel understands must not slip through validation.
func TestValidateCustomRouteRules_MatcherPrefixes(t *testing.T) {
	rule := func(m RouteMatch) []CustomRouteRule {
		return []CustomRouteRule{{Match: m, Action: RouteAction{Type: "direct"}}}
	}
	tests := []struct {
		name    string
		kernel  string
		match   RouteMatch
		wantErr bool
	}{
		{"xray full in domains", "xray", RouteMatch{Domains: []string{"full:a.example"}}, false},
		{"xray full in suffix", "xray", RouteMatch{DomainSuffixes: []string{"full:a.example"}}, false},
		{"xray full in ip_cidrs", "xray", RouteMatch{IPCIDRs: []string{"full:a.example"}}, true},
		{"singbox full in domains", "singbox", RouteMatch{Domains: []string{"full:a.example"}}, true},
		{"singbox domain in suffix", "singbox", RouteMatch{DomainSuffixes: []string{"domain:a.example"}}, true},
		{"singbox plain suffix", "singbox", RouteMatch{DomainSuffixes: []string{"a.example"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCustomRouteRules(rule(tt.match), tt.kernel, nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
