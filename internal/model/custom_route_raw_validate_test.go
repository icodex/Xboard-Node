package model

import (
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/panel"
)

func rawRoutesSpec(routes []map[string]any) *panel.NodeConfig {
	return &panel.NodeConfig{
		Protocol:     "shadowsocks",
		ServerPort:   8388,
		CustomRoutes: routes,
	}
}

func sanitizedRouteCount(t *testing.T, routes []map[string]any, kernel string) int {
	t.Helper()
	spec, err := NodeSpecFromPanelValidated(rawRoutesSpec(routes), config.KernelConfig{Type: kernel})
	if err != nil {
		t.Fatalf("raw routes must never fail the node (kernel %s): %v", kernel, err)
	}
	return len(spec.CustomRoutes)
}

// The user's production payload — a structured match/action entry pasted into
// the raw custom_routes field — must validate and survive sanitization on
// both kernels.
func TestSanitizeRawCustomRoutes_StructuredPayloadSurvives(t *testing.T) {
	routes := []map[string]any{
		{"match": map[string]any{"networks": []any{"tcp", "udp"}}, "action": map[string]any{"type": "route", "target": "direct"}},
	}
	for _, kernel := range []string{"singbox", "xray"} {
		if got := sanitizedRouteCount(t, routes, kernel); got != 1 {
			t.Fatalf("kernel %s: structured payload must survive, kept %d", kernel, got)
		}
	}
}

func TestSanitizeRawCustomRoutes_KeepsAndDrops(t *testing.T) {
	tests := []struct {
		name     string
		routes   []map[string]any
		kernel   string
		wantKept int
	}{
		{
			name:     "bug xray payload kept",
			routes:   []map[string]any{{"type": "field", "network": "udp,tcp", "outboundTag": "direct"}},
			kernel:   "singbox",
			wantKept: 1,
		},
		{
			name:     "unknown key dropped, not fatal",
			routes:   []map[string]any{{"type": "field", "balancerTag": "b", "outboundTag": "direct", "network": "tcp"}},
			kernel:   "singbox",
			wantKept: 0,
		},
		{
			name:     "unknown outbound tag dropped",
			routes:   []map[string]any{{"type": "field", "network": "tcp", "outboundTag": "ghost"}},
			kernel:   "singbox",
			wantKept: 0,
		},
		{
			name:     "geosite dropped on singbox",
			routes:   []map[string]any{{"type": "field", "domain": []string{"geosite:cn"}, "outboundTag": "direct"}},
			kernel:   "singbox",
			wantKept: 0,
		},
		{
			name:     "no match condition dropped",
			routes:   []map[string]any{{"outboundTag": "direct"}},
			kernel:   "singbox",
			wantKept: 0,
		},
		{
			name:     "legacy singbox-native rule kept on singbox, dropped on xray",
			routes:   []map[string]any{{"outbound": "direct", "ip_cidr": []string{"10.0.0.0/8"}}},
			kernel:   "singbox",
			wantKept: 1,
		},
		{
			name:     "legacy singbox-native rule dropped on xray",
			routes:   []map[string]any{{"outbound": "direct", "ip_cidr": []string{"10.0.0.0/8"}}},
			kernel:   "xray",
			wantKept: 0,
		},
		{
			name:     "xray kernel still checks tag refs",
			routes:   []map[string]any{{"type": "field", "network": "tcp", "outboundTag": "ghost"}},
			kernel:   "xray",
			wantKept: 0,
		},
		{
			name:     "xray kernel accepts Xray-only keys verbatim",
			routes:   []map[string]any{{"type": "field", "protocol": []string{"bittorrent"}, "outboundTag": "direct"}},
			kernel:   "xray",
			wantKept: 1,
		},
		{
			name:     "structured no-matcher dropped",
			routes:   []map[string]any{{"action": map[string]any{"type": "direct"}}},
			kernel:   "singbox",
			wantKept: 0,
		},
		{
			name:     "structured unknown target dropped",
			routes:   []map[string]any{{"match": map[string]any{"networks": []any{"tcp"}}, "action": map[string]any{"type": "route", "target": "ghost"}}},
			kernel:   "singbox",
			wantKept: 0,
		},
		{
			name:     "structured disabled dropped",
			routes:   []map[string]any{{"disabled": true, "match": map[string]any{"networks": []any{"tcp"}}, "action": map[string]any{"type": "direct"}}},
			kernel:   "singbox",
			wantKept: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizedRouteCount(t, tc.routes, tc.kernel); got != tc.wantKept {
				t.Fatalf("kernel %s: kept %d, want %d", tc.kernel, got, tc.wantKept)
			}
		})
	}
}
