package model

import (
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/panel"
)

func panelPathSpec(t *testing.T, configDir string, nc *panel.NodeConfig) *NodeSpec {
	t.Helper()
	nc.Protocol = "shadowsocks"
	nc.Cipher = "aes-256-gcm"
	nc.ServerPort = 8388
	spec, err := NodeSpecFromPanelValidated(nc, config.KernelConfig{Type: "singbox", ConfigDir: configDir})
	if err != nil {
		t.Fatalf("panel spec: %v", err)
	}
	return spec
}

func TestSanitizePanelMasqueradeFileDir(t *testing.T) {
	const root = "/etc/xboard-node"
	tests := []struct {
		name string
		dir  string
		keep bool
	}{
		{"subdirectory kept", root + "/masq", true},
		{"config dir itself dropped", root, false},
		{"outside root dropped", "/etc", false},
		{"traversal dropped", root + "/../secrets", false},
		{"sibling prefix dropped", root + "-evil", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := panelPathSpec(t, root, &panel.NodeConfig{
				Masquerade: &panel.MasqueradeConfig{
					Type: "file",
					File: &panel.MasqueradeFileConfig{Dir: tc.dir},
				},
			})
			if got := spec.Masquerade != nil; got != tc.keep {
				t.Fatalf("masquerade kept = %v, want %v (dir %q)", got, tc.keep, tc.dir)
			}
		})
	}
}

func TestSanitizePanelMasqueradeProxyURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		keep bool
	}{
		{"public https kept", "https://example.com/mask", true},
		{"metadata literal dropped", "http://169.254.169.254/latest/meta-data/", false},
		{"loopback literal dropped", "http://127.0.0.1/", false},
		{"ipv6 loopback dropped", "http://[::1]/", false},
		{"private literal dropped", "http://10.0.0.5/", false},
		{"localhost dropped", "http://localhost:8080/", false},
		{"non-http scheme dropped", "ftp://example.com/", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := panelPathSpec(t, "/etc/xboard-node", &panel.NodeConfig{
				Masquerade: &panel.MasqueradeConfig{
					Type:  "proxy",
					Proxy: &panel.MasqueradeProxyConfig{URL: tc.url},
				},
			})
			if got := spec.Masquerade != nil; got != tc.keep {
				t.Fatalf("masquerade kept = %v, want %v (url %q)", got, tc.keep, tc.url)
			}
		})
	}
}

func TestSanitizePanelECHKeyPath(t *testing.T) {
	const root = "/etc/xboard-node"

	t.Run("inside root kept", func(t *testing.T) {
		spec := panelPathSpec(t, root, &panel.NodeConfig{
			TLSSettings: map[string]interface{}{
				"ech": map[string]any{"enabled": true, "key_path": root + "/ech.key"},
			},
		})
		ech, ok := spec.TLSSettings["ech"].(map[string]any)
		if !ok || ech["key_path"] != root+"/ech.key" {
			t.Fatalf("ech settings lost: %v", spec.TLSSettings)
		}
	})

	t.Run("outside root drops ech", func(t *testing.T) {
		spec := panelPathSpec(t, root, &panel.NodeConfig{
			TLSSettings: map[string]interface{}{
				"ech": map[string]any{"enabled": true, "key_path": "/etc/shadow"},
			},
		})
		if _, ok := spec.TLSSettings["ech"]; ok {
			t.Fatalf("out-of-root ECH must be disabled: %v", spec.TLSSettings)
		}
	})

	t.Run("outside root keeps inline key", func(t *testing.T) {
		spec := panelPathSpec(t, root, &panel.NodeConfig{
			TLSSettings: map[string]interface{}{
				"ech": map[string]any{"enabled": true, "key": "-----BEGIN ECH KEYS-----", "key_path": "/etc/shadow"},
			},
		})
		ech, ok := spec.TLSSettings["ech"].(map[string]any)
		if !ok {
			t.Fatalf("ech settings lost: %v", spec.TLSSettings)
		}
		if _, ok := ech["key_path"]; ok {
			t.Fatalf("key_path must be removed: %v", ech)
		}
		if ech["key"] != "-----BEGIN ECH KEYS-----" {
			t.Fatalf("inline key must survive: %v", ech)
		}
	})
}
