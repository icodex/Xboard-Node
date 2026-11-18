package kernel

import (
	"testing"

	"github.com/cedar2025/xboard-node/internal/model"
)

func TestNeedsGeoForNode(t *testing.T) {
	tests := []struct {
		name     string
		spec     *model.NodeSpec
		wantIP   bool
		wantSite bool
	}{
		{
			name:   "panel route geoip",
			spec:   &model.NodeSpec{Routes: []model.RouteRule{{Match: []string{"geoip:cn"}}}},
			wantIP: true,
		},
		{
			name:     "panel route geosite",
			spec:     &model.NodeSpec{Routes: []model.RouteRule{{Match: []string{"geosite:cn"}}}},
			wantSite: true,
		},
		{
			name: "structured custom rule geoip",
			spec: &model.NodeSpec{CustomRouteRules: []model.CustomRouteRule{{
				Match: model.RouteMatch{IPCIDRs: []string{"geoip:cn"}},
			}}},
			wantIP: true,
		},
		{
			name: "structured custom rule geosite",
			spec: &model.NodeSpec{CustomRouteRules: []model.CustomRouteRule{{
				Match: model.RouteMatch{DomainSuffixes: []string{"geosite:cn"}},
			}}},
			wantSite: true,
		},
		{
			name:   "raw xray rule geoip",
			spec:   &model.NodeSpec{CustomRoutes: []map[string]any{{"ip": []any{"geoip:cn"}}}},
			wantIP: true,
		},
		{
			name:     "raw xray rule geosite",
			spec:     &model.NodeSpec{CustomRoutes: []map[string]any{{"domain": []any{"geosite:cn"}}}},
			wantSite: true,
		},
		{
			name: "literal matchers only",
			spec: &model.NodeSpec{
				Routes:           []model.RouteRule{{Match: []string{"1.2.3.0/24"}}},
				CustomRouteRules: []model.CustomRouteRule{{Match: model.RouteMatch{IPCIDRs: []string{"10.0.0.0/8"}}}},
				CustomRoutes:     []map[string]any{{"ip": []any{"192.168.0.0/16"}}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NeedsGeoIPForNode(tt.spec); got != tt.wantIP {
				t.Errorf("NeedsGeoIPForNode = %v, want %v", got, tt.wantIP)
			}
			if got := NeedsGeoSiteForNode(tt.spec); got != tt.wantSite {
				t.Errorf("NeedsGeoSiteForNode = %v, want %v", got, tt.wantSite)
			}
		})
	}
}
