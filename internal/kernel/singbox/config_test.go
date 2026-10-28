package singbox

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/panel"
)

var testUsersPanel = []panel.User{
	{ID: 1, UUID: "aaaaaaaa-1111-2222-3333-444444444444", SpeedLimit: 0, DeviceLimit: 0},
	{ID: 2, UUID: "bbbbbbbb-5555-6666-7777-888888888888", SpeedLimit: 3, DeviceLimit: 2},
}

// --- Shadowsocks ---

var testUsers = model.UserSpecsFromPanel(testUsersPanel)

func testNodeSpec(nc *panel.NodeConfig) *model.NodeSpec { return model.NodeSpecFromPanel(nc) }

func testRouteRules(r []panel.RouteRule) []model.RouteRule {
	if r == nil {
		return nil
	}
	return model.NodeSpecFromPanel(&panel.NodeConfig{Routes: r}).Routes
}

func TestBuildInbound_Shadowsocks(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "shadowsocks",
		ServerPort: 111,
		Cipher:     "aes-128-gcm",
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	assertMapValue(t, inbound, "type", "shadowsocks")
	assertMapValue(t, inbound, "method", "aes-128-gcm")
	assertMapValue(t, inbound, "listen_port", 111)

	users := inbound["users"].([]M)
	if len(users) != 2 {
		t.Fatalf("users: got %d, want 2", len(users))
	}
	assertMapValue(t, users[0], "name", "aaaaaaaa-1111-2222-3333-444444444444")
	assertMapValue(t, users[0], "password", "aaaaaaaa-1111-2222-3333-444444444444")
}

func TestBuildInbound_Shadowsocks2022(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "shadowsocks",
		ServerPort: 222,
		Cipher:     "2022-blake3-aes-128-gcm",
		ServerKey:  "base64serverkey==",
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	assertMapValue(t, inbound, "method", "2022-blake3-aes-128-gcm")
	assertMapValue(t, inbound, "password", "base64serverkey==")
}

// --- VMess ---

func TestBuildInbound_VMess(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "vmess",
		ServerPort: 443,
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	assertMapValue(t, inbound, "type", "vmess")
	assertMapValue(t, inbound, "tag", "vmess-in")

	users := inbound["users"].([]M)
	assertMapValue(t, users[0], "uuid", "aaaaaaaa-1111-2222-3333-444444444444")
	assertMapValue(t, users[0], "alterId", 0)
}

func TestBuildInbound_VMess_WithTLS(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "vmess",
		ServerPort: 443,
		TLS:        1,
		ServerName: "example.com",
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	tls := inbound["tls"].(M)
	assertMapValue(t, tls, "enabled", true)
	assertMapValue(t, tls, "server_name", "example.com")
	assertMapValue(t, tls, "certificate", []string{"CERT"})
	assertMapValue(t, tls, "key", []string{"KEY"})
}

// Panel tls=1 with cert_mode none (no paths): inbound must be plain — TLS terminated at nginx/CDN.
func TestBuildInbound_VMess_TLS_PanelOn_NoCertFiles(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "vmess",
		ServerPort: 8888,
		Network:    "ws",
		TLS:        1,
		ServerName: "example.com",
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	if _, exists := inbound["tls"]; exists {
		t.Fatal("expected no tls block when cert/key paths are empty (nginx offload)")
	}
}

func TestBuildInbound_VMess_NoTLS(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "vmess",
		ServerPort: 80,
		TLS:        0,
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	if _, exists := inbound["tls"]; exists {
		t.Error("should not have TLS when tls=0")
	}
}

func TestBuildInbound_VMess_WithWebSocket(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "vmess",
		ServerPort: 80,
		Network:    "ws",
		NetworkSettings: map[string]interface{}{
			"path": "/ws",
			"headers": map[string]interface{}{
				"Host": "example.com",
			},
		},
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	transport := inbound["transport"].(M)
	assertMapValue(t, transport, "type", "ws")
	assertMapValue(t, transport, "path", "/ws")
}

func TestBuildInbound_VMess_WithGRPC(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "vmess",
		ServerPort: 443,
		Network:    "grpc",
		NetworkSettings: map[string]interface{}{
			"serviceName": "mygrpc",
		},
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	transport := inbound["transport"].(M)
	assertMapValue(t, transport, "type", "grpc")
	assertMapValue(t, transport, "service_name", "mygrpc")
}

func TestBuildInbound_VMess_WithGRPCSnakeCaseServiceName(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "vmess",
		ServerPort: 443,
		Network:    "grpc",
		NetworkSettings: map[string]interface{}{
			"service_name": "mygrpc-snake",
		},
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	transport := inbound["transport"].(M)
	assertMapValue(t, transport, "type", "grpc")
	assertMapValue(t, transport, "service_name", "mygrpc-snake")
}

func TestBuildInbound_VMess_WithH2(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "vmess",
		ServerPort: 443,
		Network:    "h2",
		NetworkSettings: map[string]interface{}{
			"path": "/h2path",
			"host": "example.com",
		},
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	transport := inbound["transport"].(M)
	assertMapValue(t, transport, "type", "http")
	assertMapValue(t, transport, "path", "/h2path")
}

func TestBuildInbound_VMess_WithHTTPUpgrade(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "vmess",
		ServerPort: 443,
		Network:    "httpupgrade",
		NetworkSettings: map[string]interface{}{
			"path": "/upgrade",
			"host": "example.com",
		},
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	transport := inbound["transport"].(M)
	assertMapValue(t, transport, "type", "httpupgrade")
	assertMapValue(t, transport, "path", "/upgrade")
	assertMapValue(t, transport, "host", "example.com")
}

// --- VLESS ---

func TestBuildInbound_VLESS(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "vless",
		ServerPort: 443,
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	assertMapValue(t, inbound, "type", "vless")

	users := inbound["users"].([]M)
	assertMapValue(t, users[0], "uuid", "aaaaaaaa-1111-2222-3333-444444444444")
}

func TestBuildInbound_VLESS_WithFlow(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "vless",
		ServerPort: 443,
		Flow:       "xtls-rprx-vision",
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	users := inbound["users"].([]M)
	assertMapValue(t, users[0], "flow", "xtls-rprx-vision")
}

func TestBuildInbound_VLESS_Reality(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "vless",
		ServerPort: 443,
		TLS:        2,
		TLSSettings: map[string]interface{}{
			"private_key": "test-private-key",
			"short_id":    "abc123",
			"dest":        "www.example.com:443",
			"server_name": "www.example.com",
		},
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	tls := inbound["tls"].(M)
	assertMapValue(t, tls, "enabled", true)

	reality := tls["reality"].(M)
	assertMapValue(t, reality, "enabled", true)
	assertMapValue(t, reality, "private_key", "test-private-key")

	handshake := reality["handshake"].(M)
	assertMapValue(t, handshake, "server", "www.example.com")
	assertMapValue(t, handshake, "server_port", 443)
}

func TestBuildInbound_VLESS_Reality_ShortIDArray(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "vless",
		ServerPort: 443,
		TLS:        2,
		TLSSettings: map[string]interface{}{
			"private_key": "pk",
			"short_id":    []interface{}{"id1", "id2"},
			"dest":        "example.com",
		},
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	reality := inbound["tls"].(M)["reality"].(M)
	ids := reality["short_id"].([]string)
	if len(ids) != 2 {
		t.Errorf("short_id: got %d entries, want 2", len(ids))
	}
}

// --- Trojan ---

func TestBuildInbound_Trojan_Reality(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "trojan",
		ServerPort: 443,
		TLS:        2,
		TLSSettings: map[string]interface{}{
			"private_key": "test-private-key",
			"dest":        "gateway.example.com:8443",
			"server_name": "cdn.example.com",
		},
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	tls := inbound["tls"].(M)
	assertMapValue(t, tls, "enabled", true)
	assertMapValue(t, tls, "server_name", "cdn.example.com")

	reality := tls["reality"].(M)
	assertMapValue(t, reality, "enabled", true)
	assertMapValue(t, reality, "private_key", "test-private-key")

	handshake := reality["handshake"].(M)
	assertMapValue(t, handshake, "server", "gateway.example.com")
	assertMapValue(t, handshake, "server_port", 8443)
}

func TestBuildInbound_Trojan_NoTLS(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "trojan",
		ServerPort: 80,
		TLS:        0,
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	// Without certificate paths there is no TLS layer; sing-box trojan needs certs or Reality.
	if _, exists := inbound["tls"]; exists {
		t.Fatal("expected no tls when cert paths are empty and tls=0")
	}
}

func TestBuildInbound_Trojan_WithTLS(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "trojan",
		ServerPort: 443,
		TLS:        1,
		ServerName: "example.com",
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	tls := inbound["tls"].(M)
	assertMapValue(t, tls, "enabled", true)
}

// --- Hysteria ---

func TestBuildInbound_Hysteria2(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "hysteria",
		ServerPort: 444,
		Version:    2,
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	assertMapValue(t, inbound, "type", "hysteria2")

	users := inbound["users"].([]M)
	assertMapValue(t, users[0], "password", "aaaaaaaa-1111-2222-3333-444444444444")

	tls := inbound["tls"].(M)
	assertMapValue(t, tls, "enabled", true)
}

func TestBuildInbound_Hysteria2_WithObfs(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:     "hysteria",
		ServerPort:   444,
		Version:      2,
		Obfs:         "salamander",
		ObfsPassword: "secret",
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	obfs := inbound["obfs"].(M)
	assertMapValue(t, obfs, "type", "salamander")
	assertMapValue(t, obfs, "password", "secret")
}

func TestBuildInbound_Hysteria1(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "hysteria",
		ServerPort: 444,
		Version:    0,
		UpMbps:     100,
		DownMbps:   200,
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	assertMapValue(t, inbound, "type", "hysteria")
	assertMapValue(t, inbound, "up_mbps", 100)
	assertMapValue(t, inbound, "down_mbps", 200)

	users := inbound["users"].([]M)
	assertMapValue(t, users[0], "auth_str", "aaaaaaaa-1111-2222-3333-444444444444")
}

// --- TUIC ---

func TestBuildInbound_TUIC(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:          "tuic",
		ServerPort:        555,
		CongestionControl: "bbr",
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	assertMapValue(t, inbound, "type", "tuic")
	assertMapValue(t, inbound, "congestion_control", "bbr")

	users := inbound["users"].([]M)
	assertMapValue(t, users[0], "uuid", "aaaaaaaa-1111-2222-3333-444444444444")
	assertMapValue(t, users[0], "password", "aaaaaaaa-1111-2222-3333-444444444444")
}

// --- AnyTLS ---

func TestBuildInbound_AnyTLS(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:      "anytls",
		ServerPort:    443,
		PaddingScheme: "stop=8\n0=30-30",
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	assertMapValue(t, inbound, "type", "anytls")
	assertMapValue(t, inbound, "padding_scheme", "stop=8\n0=30-30")

	users := inbound["users"].([]M)
	assertMapValue(t, users[0], "password", "aaaaaaaa-1111-2222-3333-444444444444")
}

func TestBuildInbound_AnyTLS_NoPaddingScheme(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "anytls",
		ServerPort: 443,
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	if _, exists := inbound["padding_scheme"]; exists {
		t.Error("should not have padding_scheme when empty")
	}
}

// --- Naive ---

func TestBuildInbound_Naive(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "naive",
		ServerPort: 443,
		TLS:        1,
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	assertMapValue(t, inbound, "type", "naive")

	users := inbound["users"].([]M)
	assertMapValue(t, users[0], "username", "1")
	assertMapValue(t, users[0], "password", "aaaaaaaa-1111-2222-3333-444444444444")

	tls := inbound["tls"].(M)
	assertMapValue(t, tls, "enabled", true)
}

// --- Socks ---

func TestBuildInbound_Socks(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "socks",
		ServerPort: 1080,
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	assertMapValue(t, inbound, "type", "socks")

	users := inbound["users"].([]M)
	assertMapValue(t, users[0], "username", "aaaaaaaa-1111-2222-3333-444444444444")
	assertMapValue(t, users[0], "password", "aaaaaaaa-1111-2222-3333-444444444444")

	if _, exists := inbound["tls"]; exists {
		t.Error("socks should not have TLS")
	}
}

// --- HTTP ---

func TestBuildInbound_HTTP(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "http",
		ServerPort: 8080,
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	assertMapValue(t, inbound, "type", "http")

	users := inbound["users"].([]M)
	assertMapValue(t, users[0], "username", "aaaaaaaa-1111-2222-3333-444444444444")
}

func TestBuildInbound_HTTP_WithTLS(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "http",
		ServerPort: 443,
		TLS:        1,
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	tls := inbound["tls"].(M)
	assertMapValue(t, tls, "enabled", true)
}

// --- Unknown protocol ---

func TestBuildInbound_Unknown(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "unknown-proto",
		ServerPort: 999,
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	if inbound != nil {
		t.Errorf("unknown protocol should return nil, got %v", inbound)
	}
}

// --- Start missing-inbound guard ---

func TestStart_RejectsMissingInbound(t *testing.T) {
	s := New(config.KernelConfig{LogLevel: "warn"})
	nc := &panel.NodeConfig{Protocol: "unknown-proto", ServerPort: 999}
	err := s.Start(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	if err == nil {
		t.Fatal("expected error for protocol without inbound, got nil")
	}
	if s.box != nil {
		t.Error("kernel must not create an instance when no inbound can be built")
	}
}

// --- buildConfig ---

func TestBuildConfig(t *testing.T) {
	kcfg := config.KernelConfig{LogLevel: "info"}
	nc := &panel.NodeConfig{
		Protocol:   "shadowsocks",
		ServerPort: 111,
		Cipher:     "aes-128-gcm",
	}
	cfg := buildConfig(kcfg, testNodeSpec(nc), testUsers, kernel.TLSCert{})

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if len(data) == 0 {
		t.Error("empty JSON output")
	}

	// The factory level is pinned at "panic" (its own stderr path stays inert);
	// kernel logs flow through nlogBridge instead.
	logCfg := cfg["log"].(M)
	assertMapValue(t, logCfg, "level", "panic")

	outbounds := cfg["outbounds"].([]M)
	if len(outbounds) != 2 {
		t.Errorf("outbounds: got %d, want 2", len(outbounds))
	}
	assertMapValue(t, outbounds[0], "type", "direct")
	assertMapValue(t, outbounds[1], "type", "block")

	inbounds := cfg["inbounds"].([]M)
	if len(inbounds) != 1 {
		t.Fatalf("inbounds: got %d, want 1", len(inbounds))
	}
	assertMapValue(t, inbounds[0], "type", "shadowsocks")
}

func TestBuildConfig_OutboundPriority(t *testing.T) {
	kcfg := config.KernelConfig{
		LogLevel: "info",
		CustomOutbound: []map[string]any{
			{"tag": "block", "type": "dns"}, // Local static override
		},
	}
	nc := &panel.NodeConfig{
		Protocol:   "shadowsocks",
		ServerPort: 111,
		Cipher:     "aes-128-gcm",
		CustomOutbounds: []panel.OutboundConfig{
			{Tag: "direct", Protocol: "socks", Settings: map[string]any{"address": "1.2.3.4"}}, // Panel override
		},
	}

	cfg := buildConfig(kcfg, testNodeSpec(nc), testUsers, kernel.TLSCert{})
	outbounds := cfg["outbounds"].([]M)

	// We have 2 overrides in input, so we should have exactly 2 outbounds total
	// (no auto-generated defaults for these tags)
	if len(outbounds) != 2 {
		t.Errorf("outbounds: got %d, want 2", len(outbounds))
	}

	foundDirect := false
	foundBlock := false

	for _, o := range outbounds {
		tag := o["tag"].(string)
		if tag == "direct" {
			foundDirect = true
			if o["type"] != "socks" {
				t.Errorf("expected 'direct' outbound to be type 'socks' (panel priority), got %v", o["type"])
			}
		}
		if tag == "block" {
			foundBlock = true
			if o["type"] != "dns" {
				t.Errorf("expected 'block' outbound to be type 'dns' (static config priority), got %v", o["type"])
			}
		}
	}

	if !foundDirect || !foundBlock {
		t.Errorf("missing outbounds: direct=%v, block=%v", foundDirect, foundBlock)
	}
}

func TestBuildConfig_AllProtocols_ValidJSON(t *testing.T) {
	protocols := []struct {
		name string
		nc   *panel.NodeConfig
	}{
		{"shadowsocks", &panel.NodeConfig{Protocol: "shadowsocks", ServerPort: 111, Cipher: "aes-128-gcm"}},
		{"vmess", &panel.NodeConfig{Protocol: "vmess", ServerPort: 443}},
		{"vless", &panel.NodeConfig{Protocol: "vless", ServerPort: 443}},
		{"trojan", &panel.NodeConfig{Protocol: "trojan", ServerPort: 443}},
		{"hysteria2", &panel.NodeConfig{Protocol: "hysteria", ServerPort: 444, Version: 2}},
		{"hysteria1", &panel.NodeConfig{Protocol: "hysteria", ServerPort: 444, Version: 1}},
		{"tuic", &panel.NodeConfig{Protocol: "tuic", ServerPort: 555}},
		{"anytls", &panel.NodeConfig{Protocol: "anytls", ServerPort: 443}},
		{"naive", &panel.NodeConfig{Protocol: "naive", ServerPort: 443}},
		{"socks", &panel.NodeConfig{Protocol: "socks", ServerPort: 1080}},
		{"http", &panel.NodeConfig{Protocol: "http", ServerPort: 8080}},
	}

	for _, tc := range protocols {
		t.Run(tc.name, func(t *testing.T) {
			cfg := buildConfig(config.KernelConfig{LogLevel: "warn"}, testNodeSpec(tc.nc), testUsers, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
			data, err := json.Marshal(cfg)
			if err != nil {
				t.Fatalf("marshal %s: %v", tc.name, err)
			}
			var parsed map[string]interface{}
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Fatalf("round-trip %s: %v", tc.name, err)
			}
		})
	}
}

// --- Routes ---

func TestBuildRoutes_Default(t *testing.T) {
	route := buildRoutes(nil, nil, nil)
	assertMapValue(t, route, "final", "direct")

	rules := route["rules"].([]M)
	if len(rules) < 2 {
		t.Fatalf("expected at least 2 default rules, got %d", len(rules))
	}
	assertMapValue(t, rules[0], "outbound", "block")
	assertMapValue(t, rules[1], "outbound", "block")
}

func TestBuildRoutes_WithCustomRules(t *testing.T) {
	rules := []panel.RouteRule{
		{ID: 1, Match: []string{"blocked.com"}, Action: "block"},
		{ID: 2, Match: []string{"10.0.0.0/8"}, Action: "block"},
		{ID: 3, Match: []string{"allowed.com"}, Action: "direct"},
	}
	route := buildRoutes(testRouteRules(rules), nil, nil)
	allRules := route["rules"].([]M)

	if len(allRules) != 5 {
		t.Fatalf("rules count: got %d, want 5", len(allRules))
	}

	assertMapValue(t, allRules[2], "outbound", "block")
	if _, ok := allRules[2]["domain_suffix"]; !ok {
		t.Error("domain rule should use domain_suffix")
	}

	assertMapValue(t, allRules[3], "outbound", "block")
	if _, ok := allRules[3]["ip_cidr"]; !ok {
		t.Error("IP rule should use ip_cidr")
	}
}

func TestBuildRoutes_MultiMatch(t *testing.T) {
	// A single route with mixed domain + CIDR matches should produce separate rules
	// Wildcard *.evil.com should become evil.com for domain_suffix
	rules := []panel.RouteRule{
		{ID: 1, Match: []string{"*.evil.com", "bad.org", "192.168.1.0/24"}, Action: "block"},
		{ID: 2, Match: []string{"*.bypass.com"}, Action: "direct"},
	}
	route := buildRoutes(testRouteRules(rules), nil, nil)
	allRules := route["rules"].([]M)

	// 2 default private-IP rules + 1 domain rule + 1 CIDR rule + 1 domain rule = 5
	if len(allRules) != 5 {
		t.Fatalf("rules count: got %d, want 5", len(allRules))
	}

	// Rule #2 (index 2): domains from first route (wildcards stripped)
	domains := allRules[2]["domain_suffix"].([]string)
	if len(domains) != 2 || domains[0] != "evil.com" || domains[1] != "bad.org" {
		t.Errorf("domain_suffix: got %v, want [evil.com bad.org]", domains)
	}
	assertMapValue(t, allRules[2], "outbound", "block")

	// Rule #3 (index 3): CIDRs from first route
	cidrs := allRules[3]["ip_cidr"].([]string)
	if len(cidrs) != 1 || cidrs[0] != "192.168.1.0/24" {
		t.Errorf("ip_cidr: got %v, want [192.168.1.0/24]", cidrs)
	}
	assertMapValue(t, allRules[3], "outbound", "block")

	// Rule #4 (index 4): direct rule (wildcard stripped)
	directDomains := allRules[4]["domain_suffix"].([]string)
	if len(directDomains) != 1 || directDomains[0] != "bypass.com" {
		t.Errorf("direct domain_suffix: got %v, want [bypass.com]", directDomains)
	}
	assertMapValue(t, allRules[4], "outbound", "direct")
}

func TestBuildRoutes_WithCustomRouteRules(t *testing.T) {
	customRules := []model.CustomRouteRule{
		{
			Name: "direct-mixed",
			Match: model.RouteMatch{
				Domains:        []string{"full.example.com"},
				DomainSuffixes: []string{"example.org"},
				IPCIDRs:        []string{"1.1.1.0/24"},
				Ports:          []string{"53", "1000-1002"},
				Networks:       []string{"tcp"},
				SourceCIDRs:    []string{"10.10.0.0/16"},
				SourcePorts:    []string{"2000-2001"},
			},
			Action: model.RouteAction{Type: "direct"},
		},
	}
	route := buildRoutes(nil, customRules, nil)
	allRules := route["rules"].([]M)
	if len(allRules) != 9 {
		t.Fatalf("rules count: got %d, want 9", len(allRules))
	}
	if allRules[0]["domain"].([]string)[0] != "full.example.com" {
		t.Fatalf("unexpected exact domain rule: %v", allRules[0])
	}
	if allRules[1]["domain_suffix"].([]string)[0] != "example.org" {
		t.Fatalf("unexpected domain suffix rule: %v", allRules[1])
	}
	if allRules[2]["ip_cidr"].([]string)[0] != "1.1.1.0/24" {
		t.Fatalf("unexpected ip cidr rule: %v", allRules[2])
	}
	if allRules[3]["port"].([]int)[0] != 53 {
		t.Fatalf("unexpected port rule: %v", allRules[3])
	}
	if allRules[4]["network"].([]string)[0] != "tcp" {
		t.Fatalf("unexpected network rule: %v", allRules[4])
	}
	if allRules[5]["source_ip_cidr"].([]string)[0] != "10.10.0.0/16" {
		t.Fatalf("unexpected source cidr rule: %v", allRules[5])
	}
	if allRules[6]["source_port_range"].([]string)[0] != "2000:2001" {
		t.Fatalf("unexpected source port rule: %v", allRules[6])
	}
}

func TestBuildRoutes_StructuredCustomRulesRemainFirst(t *testing.T) {
	raw := []map[string]any{{"domain": []string{"raw.example.com"}, "outbound": "raw-tag"}}
	custom := []model.CustomRouteRule{{
		Match:  model.RouteMatch{DomainSuffixes: []string{"structured.example"}},
		Action: model.RouteAction{Type: "direct"},
	}}
	route := buildRoutes(nil, custom, raw)
	allRules := route["rules"].([]M)
	if allRules[0]["outbound"] != "direct" {
		t.Fatalf("expected structured route first, got %v", allRules[0]["outbound"])
	}
	if allRules[1]["outbound"] != "raw-tag" {
		t.Fatalf("expected raw custom route second, got %v", allRules[1]["outbound"])
	}
}

// --- TLS Config ---

func TestBuildTLSConfig_WithCert(t *testing.T) {
	nc := &panel.NodeConfig{ServerName: "example.com"}
	tls := buildTLSConfig(testNodeSpec(nc), kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	assertMapValue(t, tls, "enabled", true)
	assertMapValue(t, tls, "server_name", "example.com")
	assertMapValue(t, tls, "certificate", []string{"CERT"})
	assertMapValue(t, tls, "key", []string{"KEY"})
}

func TestBuildTLSConfig_NoCert(t *testing.T) {
	nc := &panel.NodeConfig{ServerName: "example.com"}
	tls := buildTLSConfig(testNodeSpec(nc), kernel.TLSCert{})
	if tls != nil {
		t.Fatalf("expected nil tls config when cert paths are empty, got %+v", tls)
	}
}

func TestBuildTLSConfig_FallbackToHost(t *testing.T) {
	nc := &panel.NodeConfig{Host: "fallback.com"}
	tls := buildTLSConfig(testNodeSpec(nc), kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	assertMapValue(t, tls, "server_name", "fallback.com")
}

func TestBuildTLSConfig_TLSSettingsOverride(t *testing.T) {
	nc := &panel.NodeConfig{
		ServerName: "original.com",
		TLSSettings: map[string]interface{}{
			"server_name": "override.com",
		},
	}
	tls := buildTLSConfig(testNodeSpec(nc), kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	assertMapValue(t, tls, "server_name", "override.com")
}

// --- Transport ---

func TestApplyTransport_TCP(t *testing.T) {
	base := M{}
	nc := &panel.NodeConfig{Network: "tcp"}
	applyTransport(base, testNodeSpec(nc))
	if _, exists := base["transport"]; exists {
		t.Error("tcp should not add transport")
	}
}

func TestApplyTransport_Empty(t *testing.T) {
	base := M{}
	nc := &panel.NodeConfig{Network: ""}
	applyTransport(base, testNodeSpec(nc))
	if _, exists := base["transport"]; exists {
		t.Error("empty network should not add transport")
	}
}

func TestApplyTransport_WS_MaxEarlyData(t *testing.T) {
	base := M{}
	nc := &panel.NodeConfig{
		Network: "ws",
		NetworkSettings: map[string]interface{}{
			"path":                   "/ws",
			"max_early_data":         2048,
			"early_data_header_name": "Sec-WebSocket-Protocol",
		},
	}
	applyTransport(base, testNodeSpec(nc))
	transport := base["transport"].(M)
	assertMapValue(t, transport, "max_early_data", 2048)
	assertMapValue(t, transport, "early_data_header_name", "Sec-WebSocket-Protocol")
}

// --- helpers ---

func assertMapValue(t *testing.T, m M, key string, expected interface{}) {
	t.Helper()
	val, ok := m[key]
	if !ok {
		t.Errorf("key %q not found in map", key)
		return
	}
	switch e := expected.(type) {
	case int:
		switch v := val.(type) {
		case int:
			if v != e {
				t.Errorf("%s: got %d, want %d", key, v, e)
			}
		case float64:
			if int(v) != e {
				t.Errorf("%s: got %v, want %d", key, v, e)
			}
		default:
			t.Errorf("%s: got %v (type %T), want %d", key, val, val, e)
		}
	default:
		if !reflect.DeepEqual(val, expected) {
			t.Errorf("%s: got %v, want %v", key, val, expected)
		}
	}
}

func TestExtractECHInbound(t *testing.T) {
	tests := []struct {
		name      string
		tls       map[string]interface{}
		expectNil bool
		expectKey []string
	}{
		{"no ech", map[string]interface{}{}, true, nil},
		{"disabled", map[string]interface{}{"ech": map[string]interface{}{"enabled": false}}, true, nil},
		{"enabled with key", map[string]interface{}{"ech": map[string]interface{}{
			"enabled": true,
			"key":     "-----BEGIN ECH KEYS-----\nABCD\n-----END ECH KEYS-----\n",
		}}, false, []string{"-----BEGIN ECH KEYS-----\nABCD\n-----END ECH KEYS-----\n"}},
		{"enabled with key_path", map[string]interface{}{"ech": map[string]interface{}{
			"enabled":  true,
			"key_path": "/etc/ech/keys.pem",
		}}, false, nil},
		{"enabled no key", map[string]interface{}{"ech": map[string]interface{}{"enabled": true}}, false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractECHInbound(tt.tls)
			if tt.expectNil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
				return
			}
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			if result["enabled"] != true {
				t.Errorf("expected enabled=true, got %v", result["enabled"])
			}
			if tt.expectKey != nil {
				if !reflect.DeepEqual(result["key"], tt.expectKey) {
					t.Errorf("key: got %v, want %v", result["key"], tt.expectKey)
				}
			}
		})
	}
}

func TestBuildRealityConfig_ServerNameFallback(t *testing.T) {
	// Panel sends reality_settings with dest only (server_name null):
	// the SNI whitelist must not be left empty or every client is rejected
	spec := &model.NodeSpec{TLS: 2, TLSSettings: map[string]interface{}{
		"private_key": "test-private-key-value",
		"dest":        "fallback.example.com:8443",
		"server_name": nil,
	}}

	tls := buildRealityConfig(spec)
	if sn := tls["server_name"]; sn != "fallback.example.com" {
		t.Errorf("server_name fallback: got %v, want fallback.example.com", sn)
	}

	handshake, ok := tls["reality"].(M)["handshake"].(M)
	if !ok {
		t.Fatal("handshake missing")
	}
	if handshake["server"] != "fallback.example.com" || handshake["server_port"] != 8443 {
		t.Errorf("handshake: got %v:%v, want fallback.example.com:8443", handshake["server"], handshake["server_port"])
	}
}

func TestApplyTransport_WS_HostOverridesHeader(t *testing.T) {
	nc := &model.NodeSpec{
		Network: "ws",
		NetworkSettings: map[string]interface{}{
			"path":    "/ws",
			"host":    "cdn.example.com",
			"headers": map[string]interface{}{"User-Agent": "test", "Host": "stale.example.com"},
		},
	}
	base := M{}
	applyTransport(base, nc)

	headers, ok := base["transport"].(M)["headers"].(map[string]any)
	if !ok {
		t.Fatalf("headers missing: %v", base["transport"])
	}
	if headers["Host"] != "cdn.example.com" {
		t.Errorf("Host: got %v, want cdn.example.com", headers["Host"])
	}
	if headers["User-Agent"] != "test" {
		t.Errorf("panel header lost: %v", headers)
	}
}

func TestBuildInbound_Shadowsocks2022ChachaRejected(t *testing.T) {
	// sing-shadowsocks server iPSK is aes-only: chacha20-poly1305 multi-user
	// inbound creation fails with "invalid argument", so the builder returns
	// nil and the kernel refuses to start.
	nc := &panel.NodeConfig{
		Protocol:   "shadowsocks",
		ServerPort: 8389,
		Cipher:     "2022-blake3-chacha20-poly1305",
		ServerKey:  "base64serverkey==",
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	if inbound != nil {
		t.Fatalf("chacha20-poly1305 multi-user inbound must be rejected, got %+v", inbound)
	}
}

func TestBuildInbound_ProxyProtocolWarnsOnly(t *testing.T) {
	// sing-box has no inbound proxy_protocol support: the field must be
	// dropped (applyProxyProtocol warns) without leaking any option into the
	// generated config.
	nc := &panel.NodeConfig{
		Protocol:            "vmess",
		ServerPort:          10086,
		AcceptProxyProtocol: true,
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	if inbound == nil {
		t.Fatal("inbound must still be built")
	}
	if _, ok := inbound["proxy_protocol"]; ok {
		t.Error("proxy_protocol must not appear in sing-box inbound config")
	}
}

func TestBuildInbound_ListenIP(t *testing.T) {
	tests := []struct {
		name     string
		listenIP string
		want     string
	}{
		{name: "empty stays dual-stack", listenIP: "", want: "::"},
		{name: "v4 wildcard stays dual-stack", listenIP: "0.0.0.0", want: "::"},
		{name: "v6 wildcard stays dual-stack", listenIP: "::", want: "::"},
		{name: "concrete address honored", listenIP: "127.0.0.1", want: "127.0.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nc := &panel.NodeConfig{
				Protocol:   "socks",
				ServerPort: 10019,
				ListenIP:   tt.listenIP,
			}
			inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
			if inbound["listen"] != tt.want {
				t.Errorf("listen = %v, want %v", inbound["listen"], tt.want)
			}
		})
	}
}
