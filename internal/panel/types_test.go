package panel

import (
	"encoding/json"
	"testing"
)

func TestStringOrArray_UnmarshalString(t *testing.T) {
	input := `"hello world"`
	var s StringOrArray
	if err := json.Unmarshal([]byte(input), &s); err != nil {
		t.Fatalf("unmarshal string: %v", err)
	}
	if string(s) != "hello world" {
		t.Errorf("got %q, want %q", s, "hello world")
	}
}

func TestStringOrArray_UnmarshalArray(t *testing.T) {
	input := `["stop=8","0=30-30","1=100-400"]`
	var s StringOrArray
	if err := json.Unmarshal([]byte(input), &s); err != nil {
		t.Fatalf("unmarshal array: %v", err)
	}
	want := "stop=8\n0=30-30\n1=100-400"
	if string(s) != want {
		t.Errorf("got %q, want %q", s, want)
	}
}

func TestStringOrArray_UnmarshalEmptyArray(t *testing.T) {
	input := `[]`
	var s StringOrArray
	if err := json.Unmarshal([]byte(input), &s); err != nil {
		t.Fatalf("unmarshal empty array: %v", err)
	}
	if string(s) != "" {
		t.Errorf("got %q, want empty", s)
	}
}

func TestStringOrArray_UnmarshalNull(t *testing.T) {
	input := `null`
	var s StringOrArray
	if err := json.Unmarshal([]byte(input), &s); err != nil {
		t.Fatalf("unmarshal null: %v", err)
	}
	if string(s) != "" {
		t.Errorf("got %q, want empty", s)
	}
}

func TestNodeConfig_UnmarshalWithPaddingSchemeArray(t *testing.T) {
	input := `{
		"protocol": "anytls",
		"server_port": 443,
		"padding_scheme": ["stop=8", "0=30-30", "1=100-400"]
	}`
	var nc NodeConfig
	if err := json.Unmarshal([]byte(input), &nc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if nc.Protocol != "anytls" {
		t.Errorf("protocol: got %q, want %q", nc.Protocol, "anytls")
	}
	want := "stop=8\n0=30-30\n1=100-400"
	if string(nc.PaddingScheme) != want {
		t.Errorf("padding_scheme: got %q, want %q", nc.PaddingScheme, want)
	}
}

func TestNodeConfig_UnmarshalWithPaddingSchemeString(t *testing.T) {
	input := `{
		"protocol": "anytls",
		"server_port": 443,
		"padding_scheme": "stop=8\n0=30-30"
	}`
	var nc NodeConfig
	if err := json.Unmarshal([]byte(input), &nc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := "stop=8\n0=30-30"
	if string(nc.PaddingScheme) != want {
		t.Errorf("padding_scheme: got %q, want %q", nc.PaddingScheme, want)
	}
}

func TestNodeConfig_UnmarshalFullPanelResponse(t *testing.T) {
	input := `{
		"protocol": "shadowsocks",
		"listen_ip": "0.0.0.0",
		"server_port": 111,
		"cipher": "aes-128-gcm",
		"network": null,
		"networkSettings": null,
		"server_name": "",
		"base_config": {
			"push_interval": 60,
			"pull_interval": 60
		}
	}`
	var nc NodeConfig
	if err := json.Unmarshal([]byte(input), &nc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if nc.Protocol != "shadowsocks" {
		t.Errorf("protocol: got %q", nc.Protocol)
	}
	if nc.ServerPort != 111 {
		t.Errorf("server_port: got %d", nc.ServerPort)
	}
	if nc.Cipher != "aes-128-gcm" {
		t.Errorf("cipher: got %q", nc.Cipher)
	}
	if nc.BaseConfig.PushInterval != 60 {
		t.Errorf("push_interval: got %d", nc.BaseConfig.PushInterval)
	}
}

func TestUsersResponse_Unmarshal(t *testing.T) {
	input := `{
		"users": [
			{"id": 1, "uuid": "abc-123", "speed_limit": 3, "device_limit": 2},
			{"id": 2, "uuid": "def-456", "speed_limit": 0, "device_limit": 0}
		]
	}`
	var resp UsersResponse
	if err := json.Unmarshal([]byte(input), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Users) != 2 {
		t.Fatalf("users count: got %d, want 2", len(resp.Users))
	}
	if resp.Users[0].SpeedLimit != 3 {
		t.Errorf("user[0].speed_limit: got %d", resp.Users[0].SpeedLimit)
	}
	if resp.Users[1].DeviceLimit != 0 {
		t.Errorf("user[1].device_limit: got %d", resp.Users[1].DeviceLimit)
	}
}

// PHP encodes empty maps as [] on the wire. Every map-typed NodeConfig field
// must survive the weak decode as an empty map instead of failing (the
// hysteria fork shipped a startup-blocking variant of this bug; lock it here).
func TestNodeConfig_PHPEmptyArrayTolerance(t *testing.T) {
	raw := map[string]interface{}{}
	if err := json.Unmarshal([]byte(`{
		"protocol": "vmess",
		"server_port": 10004,
		"listen_ip": "0.0.0.0",
		"network": "tcp",
		"networkSettings": [],
		"tls_settings": [],
		"custom_outbounds": [
			{"tag": "empty-direct", "protocol": "direct", "settings": []},
			{"tag": "with-settings", "protocol": "socks", "settings": {"server": "1.2.3.4", "server_port": 1080}}
		],
		"custom_routes": [],
		"custom_route_rules": []
	}`), &raw); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}

	var cfg NodeConfig
	if err := decodeWeakRaw(raw, &cfg); err != nil {
		t.Fatalf("weak decode must tolerate PHP empty arrays: %v", err)
	}
	if cfg.NetworkSettings == nil {
		t.Error("networkSettings [] should decode to an empty map, got nil")
	}
	if cfg.TLSSettings == nil {
		t.Error("tls_settings [] should decode to an empty map, got nil")
	}
	if len(cfg.CustomRoutes) != 0 {
		t.Errorf("custom_routes [] should decode to empty slice, got %v", cfg.CustomRoutes)
	}
	if len(cfg.CustomOutbounds) != 2 {
		t.Fatalf("custom_outbounds: got %d entries, want 2", len(cfg.CustomOutbounds))
	}
	if cfg.CustomOutbounds[0].Settings == nil {
		t.Error("outbound settings [] should decode to an empty map, got nil")
	}
	if cfg.CustomOutbounds[1].Settings["server"] != "1.2.3.4" {
		t.Errorf("populated settings must survive: %v", cfg.CustomOutbounds[1].Settings)
	}
}
