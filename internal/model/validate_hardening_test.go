package model

import (
	"strings"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/panel"
)

func TestValidateNodeSpecRejectsUnservableValues(t *testing.T) {
	base := func() *NodeSpec {
		return &NodeSpec{Protocol: "vless", ServerPort: 443}
	}
	tests := []struct {
		name    string
		spec    *NodeSpec
		kernel  string
		wantErr string
	}{
		{"port zero", &NodeSpec{Protocol: "vless"}, "singbox", "server_port must be between"},
		{"port too high", &NodeSpec{Protocol: "vless", ServerPort: 70000}, "singbox", "server_port must be between"},
		{"listen ip invalid", func() *NodeSpec { s := base(); s.ListenIP = "not-an-ip"; return s }(), "singbox", "listen_ip"},
		{"tls enum", func() *NodeSpec { s := base(); s.TLS = 3; return s }(), "singbox", "tls must be 0"},
		{"singbox cipher", &NodeSpec{Protocol: "shadowsocks", ServerPort: 1, Cipher: "aes-256-cfb"}, "singbox", "not supported by sing-box"},
		{"empty singbox cipher", &NodeSpec{Protocol: "shadowsocks", ServerPort: 1}, "singbox", "not supported by sing-box"},
		{"xray hysteria v1", &NodeSpec{Protocol: "hysteria", ServerPort: 1, Version: 1}, "xray", "only supports hysteria v2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateNodeSpec(tc.spec, config.KernelConfig{Type: tc.kernel})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want substring %q", err, tc.wantErr)
			}
		})
	}

	if err := ValidateNodeSpec(base(), config.KernelConfig{Type: "singbox"}); err != nil {
		t.Fatalf("baseline vless must validate: %v", err)
	}
}

func panelNodeConfig(protocol string) panel.NodeConfig {
	return panel.NodeConfig{Protocol: protocol, ServerPort: 8443}
}

func TestNodeSpecFromPanelNormalizesHysteria2(t *testing.T) {
	nc := panelNodeConfig("hysteria2")
	spec := NodeSpecFromPanel(&nc)
	if spec.Protocol != "hysteria" || spec.Version != 2 {
		t.Fatalf("protocol/version = %q/%d, want hysteria/2", spec.Protocol, spec.Version)
	}
}
