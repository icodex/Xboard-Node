package outbound

import (
	"reflect"
	"strings"
	"testing"
)

// The payload from the reported bug: a VLESS + REALITY outbound pasted into the
// panel in Xray-native form.
func reportedPayload() (map[string]any, map[string]any, map[string]any) {
	settings := map[string]any{
		"id":         "211ed558-90f0-4f32-ba5b-d11c1007e2bf",
		"flow":       "xtls-rprx-vision",
		"port":       float64(443),
		"email":      "t@t.tt",
		"address":    "example.com",
		"encryption": "none",
	}
	streamSettings := map[string]any{
		"network":  "raw",
		"security": "reality",
		"realitySettings": map[string]any{
			"show":          false,
			"shortId":       "a3e60d54",
			"spiderX":       nil,
			"publicKey":     "0YPI8dNTtdXKU6IjepNQJxydugtijnvZTQiuU9FmcEs",
			"serverName":    "www.apple.com",
			"fingerprint":   "chrome",
			"mldsa65Verify": nil,
		},
	}
	mux := map[string]any{"enabled": false, "concurrency": float64(-1)}
	return settings, streamSettings, mux
}

func TestRenderSingbox_ReportedXrayPayload(t *testing.T) {
	settings, streamSettings, mux := reportedPayload()
	c, err := Parse("vless", settings, streamSettings, mux, "")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := ValidateForKernel(c, "singbox"); err != nil {
		t.Fatalf("validate: %v", err)
	}
	m, err := c.RenderSingbox("proxy")
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	if _, exists := m["address"]; exists {
		t.Fatal("sing-box outbound must not contain Xray's address field")
	}
	if m["type"] != "vless" || m["tag"] != "proxy" {
		t.Fatalf("type/tag: got %v/%v", m["type"], m["tag"])
	}
	if m["server"] != "example.com" {
		t.Errorf("server: got %v", m["server"])
	}
	if m["server_port"] != 443 {
		t.Errorf("server_port: got %v", m["server_port"])
	}
	if m["uuid"] != "211ed558-90f0-4f32-ba5b-d11c1007e2bf" {
		t.Errorf("uuid: got %v", m["uuid"])
	}
	if m["flow"] != "xtls-rprx-vision" {
		t.Errorf("flow: got %v", m["flow"])
	}

	tls, ok := m["tls"].(map[string]any)
	if !ok {
		t.Fatalf("tls missing: %v", m["tls"])
	}
	if tls["enabled"] != true || tls["server_name"] != "www.apple.com" {
		t.Errorf("tls: got %v", tls)
	}
	utls, _ := tls["utls"].(map[string]any)
	if utls == nil || utls["fingerprint"] != "chrome" {
		t.Errorf("utls: got %v", tls["utls"])
	}
	reality, _ := tls["reality"].(map[string]any)
	if reality == nil {
		t.Fatalf("reality missing: %v", tls)
	}
	if reality["public_key"] != "0YPI8dNTtdXKU6IjepNQJxydugtijnvZTQiuU9FmcEs" {
		t.Errorf("reality public_key: got %v", reality["public_key"])
	}
	if reality["short_id"] != "a3e60d54" {
		t.Errorf("reality short_id: got %v", reality["short_id"])
	}
	if _, exists := m["multiplex"]; exists {
		t.Error("disabled mux must not produce a multiplex block")
	}
}

func TestRenderXray_ReportedXrayPayloadPreserved(t *testing.T) {
	settings, streamSettings, mux := reportedPayload()
	c, err := Parse("vless", settings, streamSettings, mux, "")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := ValidateForKernel(c, "xray"); err != nil {
		t.Fatalf("validate: %v", err)
	}
	m, err := c.RenderXray("proxy")
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	if m["protocol"] != "vless" || m["tag"] != "proxy" {
		t.Fatalf("protocol/tag: got %v/%v", m["protocol"], m["tag"])
	}
	if !reflect.DeepEqual(m["streamSettings"], streamSettings) {
		t.Errorf("streamSettings changed: got %v", m["streamSettings"])
	}
	if !reflect.DeepEqual(m["mux"], mux) {
		t.Errorf("mux changed: got %v", m["mux"])
	}
}

func TestParseNestedXrayVnext(t *testing.T) {
	settings := map[string]any{
		"vnext": []any{
			map[string]any{
				"address": "1.2.3.4",
				"port":    float64(443),
				"users": []any{
					map[string]any{"id": "uuid-1", "alterId": float64(0), "security": "auto"},
				},
			},
		},
	}
	c, err := Parse("vmess", settings, nil, nil, "")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := ValidateForKernel(c, "singbox"); err != nil {
		t.Fatalf("validate: %v", err)
	}
	m, err := c.RenderSingbox("vmess-out")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if m["server"] != "1.2.3.4" || m["server_port"] != 443 || m["uuid"] != "uuid-1" {
		t.Errorf("unexpected sing-box outbound: %v", m)
	}
	if m["security"] != "auto" {
		t.Errorf("security: got %v", m["security"])
	}
}

func TestRenderXray_NativeSingboxSettings(t *testing.T) {
	settings := map[string]any{
		"server":      "example.com",
		"server_port": float64(8443),
		"uuid":        "uuid-2",
		"flow":        "xtls-rprx-vision",
		"tls": map[string]any{
			"enabled":     true,
			"server_name": "cdn.example.com",
			"insecure":    true,
			"utls":        map[string]any{"enabled": true, "fingerprint": "chrome"},
			"reality": map[string]any{
				"enabled":    true,
				"public_key": "pub",
				"short_id":   "abcd",
			},
		},
		"transport": map[string]any{
			"type": "ws",
			"path": "/ws",
			"headers": map[string]any{
				"Host": "cdn.example.com",
			},
		},
	}
	c, err := Parse("vless", settings, nil, nil, "")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := ValidateForKernel(c, "xray"); err != nil {
		t.Fatalf("validate: %v", err)
	}
	m, err := c.RenderXray("out")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	xsettings := m["settings"].(map[string]any)
	vnext := xsettings["vnext"].([]any)
	entry := vnext[0].(map[string]any)
	if entry["address"] != "example.com" || entry["port"] != 8443 {
		t.Errorf("vnext: got %v", entry)
	}
	stream := m["streamSettings"].(map[string]any)
	if stream["network"] != "ws" || stream["security"] != "reality" {
		t.Errorf("stream: got %v", stream)
	}
	reality := stream["realitySettings"].(map[string]any)
	if reality["publicKey"] != "pub" || reality["shortId"] != "abcd" || reality["serverName"] != "cdn.example.com" {
		t.Errorf("reality: got %v", reality)
	}
	ws := stream["wsSettings"].(map[string]any)
	if ws["path"] != "/ws" {
		t.Errorf("ws: got %v", ws)
	}
}

func TestValidateForKernelRejects(t *testing.T) {
	tests := []struct {
		name    string
		parse   func() (*Canonical, error)
		kernel  string
		wantErr string
	}{
		{
			name: "multiple servers",
			parse: func() (*Canonical, error) {
				return Parse("trojan", map[string]any{
					"servers": []any{
						map[string]any{"address": "1.1.1.1", "port": float64(443), "password": "p"},
						map[string]any{"address": "2.2.2.2", "port": float64(443), "password": "p"},
					},
				}, nil, nil, "")
			},
			kernel:  "singbox",
			wantErr: "support exactly one",
		},
		{
			name: "reality without public key",
			parse: func() (*Canonical, error) {
				return Parse("vless", map[string]any{
					"address": "1.1.1.1", "port": float64(443), "id": "u",
				}, map[string]any{
					"network":         "raw",
					"security":        "reality",
					"realitySettings": map[string]any{"serverName": "x.com"},
				}, nil, "")
			},
			kernel:  "singbox",
			wantErr: "reality requires publicKey",
		},
		{
			name: "xhttp unsupported by sing-box",
			parse: func() (*Canonical, error) {
				return Parse("vless", map[string]any{
					"address": "1.1.1.1", "port": float64(443), "id": "u",
				}, map[string]any{
					"network":  "xhttp",
					"security": "tls",
				}, nil, "")
			},
			kernel:  "singbox",
			wantErr: "xhttp",
		},
		{
			name: "vision without tls",
			parse: func() (*Canonical, error) {
				return Parse("vless", map[string]any{
					"address": "1.1.1.1", "port": float64(443), "id": "u", "flow": "xtls-rprx-vision",
				}, map[string]any{"network": "raw", "security": "none"}, nil, "")
			},
			kernel:  "singbox",
			wantErr: "requires tls or reality",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := tc.parse()
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			err = ValidateForKernel(c, tc.kernel)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestProxyTagRendersAsDetourAndProxySettings(t *testing.T) {
	c, err := Parse("socks", map[string]any{
		"address": "1.2.3.4", "port": float64(1080),
	}, nil, nil, "warp")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	singbox, err := c.RenderSingbox("proxy")
	if err != nil {
		t.Fatalf("render singbox: %v", err)
	}
	if singbox["detour"] != "warp" {
		t.Errorf("detour: got %v", singbox["detour"])
	}
	if _, exists := singbox["proxy_tag"]; exists {
		t.Error("sing-box uses detour, not proxy_tag")
	}
	xray, err := c.RenderXray("proxy")
	if err != nil {
		t.Fatalf("render xray: %v", err)
	}
	proxySettings, _ := xray["proxySettings"].(map[string]any)
	if proxySettings == nil || proxySettings["tag"] != "warp" {
		t.Errorf("proxySettings: got %v", xray["proxySettings"])
	}
}

func TestWireguardXrayToSingbox(t *testing.T) {
	c, err := Parse("wireguard", map[string]any{
		"secretKey": "priv",
		"address":   []any{"10.0.0.2/32"},
		"peers": []any{
			map[string]any{
				"publicKey": "peerpub",
				"endpoint":  "162.159.192.1:2408",
				"keepAlive": float64(25),
			},
		},
	}, nil, nil, "")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := ValidateForKernel(c, "singbox"); err != nil {
		t.Fatalf("validate: %v", err)
	}
	m, err := c.RenderSingbox("warp")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if m["type"] != "wireguard" || m["server"] != "162.159.192.1" || m["server_port"] != 2408 {
		t.Errorf("wireguard singbox: %v", m)
	}
	if m["private_key"] != "priv" || m["peer_public_key"] != "peerpub" {
		t.Errorf("wireguard keys: %v", m)
	}
}
