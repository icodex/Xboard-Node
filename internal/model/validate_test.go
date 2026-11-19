package model

import (
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/panel"
)

func TestValidateTransportKernel(t *testing.T) {
	tests := []struct {
		name      string
		network   string
		kernel    string
		wantError bool
	}{
		{"xhttp on singbox rejected", "xhttp", "singbox", true},
		{"splithttp on singbox rejected", "splithttp", "singbox", true},
		{"h2 on xray rejected (removed upstream)", "h2", "xray", true},
		{"http on xray rejected", "http", "xray", true},
		{"quic on xray rejected", "quic", "xray", true},
		{"quic on singbox rejected (neither kernel)", "quic", "singbox", true},
		{"kcp on singbox rejected", "kcp", "singbox", true},
		{"kcp on xray ok", "kcp", "xray", false},
		{"xhttp on xray ok", "xhttp", "xray", false},
		{"ws on singbox ok", "ws", "singbox", false},
		{"ws on xray ok", "ws", "xray", false},
		{"h2 on singbox ok", "h2", "singbox", false},
		{"empty network ok", "", "xray", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTransportKernel(tt.network, tt.kernel)
			if (err != nil) != tt.wantError {
				t.Errorf("validateTransportKernel(%q, %q) error = %v, wantError %v", tt.network, tt.kernel, err, tt.wantError)
			}
		})
	}
}

func TestResolveKernelForTransport(t *testing.T) {
	tests := []struct {
		name    string
		network string
		config  string
		want    string
	}{
		{"xhttp switches singbox to xray", "xhttp", "singbox", "xray"},
		{"h2 switches xray to singbox", "h2", "xray", "singbox"},
		{"http switches xray to singbox", "http", "xray", "singbox"},
		{"quic is unsupported by both, kernel unchanged", "quic", "xray", "xray"},
		{"ws keeps singbox", "ws", "singbox", "singbox"},
		{"ws keeps xray", "ws", "xray", "xray"},
		{"xhttp keeps xray", "xhttp", "xray", "xray"},
		{"h2 keeps singbox", "h2", "singbox", "singbox"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ResolveKernelForTransport(tt.network, tt.config); got != tt.want {
				t.Errorf("ResolveKernelForTransport(%q, %q) = %q, want %q", tt.network, tt.config, got, tt.want)
			}
		})
	}
}

func TestResolveKernelForNode_Auto(t *testing.T) {
	tests := []struct {
		name string
		spec *NodeSpec
		want string
	}{
		{"nil spec defaults", nil, "singbox"},
		{"vless ws defaults", &NodeSpec{Protocol: "vless", Network: "ws"}, "singbox"},
		{"vless xhttp to xray", &NodeSpec{Protocol: "vless", Network: "xhttp"}, "xray"},
		{"vless splithttp to xray", &NodeSpec{Protocol: "vless", Network: "splithttp"}, "xray"},
		{"vmess h2 to singbox", &NodeSpec{Protocol: "vmess", Network: "h2"}, "singbox"},
		{"vmess reality to xray", &NodeSpec{Protocol: "vmess", TLS: 2}, "xray"},
		{"vmess plain stays", &NodeSpec{Protocol: "vmess"}, "singbox"},
		{"vless reality stays default", &NodeSpec{Protocol: "vless", TLS: 2}, "singbox"},
		{"tuic singbox-only", &NodeSpec{Protocol: "tuic"}, "singbox"},
		{"anytls singbox-only", &NodeSpec{Protocol: "anytls"}, "singbox"},
		{"naive singbox-only", &NodeSpec{Protocol: "naive"}, "singbox"},
		{"socks singbox-only", &NodeSpec{Protocol: "socks"}, "singbox"},
		{"http singbox-only", &NodeSpec{Protocol: "http"}, "singbox"},
		{"mieru singbox-only", &NodeSpec{Protocol: "mieru"}, "singbox"},
		{"hysteria v1 singbox-only", &NodeSpec{Protocol: "hysteria"}, "singbox"},
		{"hysteria2 default", &NodeSpec{Protocol: "hysteria2"}, "singbox"},
		{"panel kernel_type wins over rules", &NodeSpec{Protocol: "tuic", KernelType: "xray"}, "xray"},
		{"panel kernel_type xray wins", &NodeSpec{Protocol: "vless", KernelType: "xray"}, "xray"},
		{"panel kernel_type sing-box alias", &NodeSpec{Protocol: "vless", KernelType: "sing-box"}, "singbox"},
		{"panel kernel_type auto ignored", &NodeSpec{Protocol: "vless", KernelType: "auto"}, "singbox"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveKernelForNode(tt.spec, config.KernelConfig{Type: "auto"})
			if got != tt.want {
				t.Errorf("ResolveKernelForNode(auto) = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveKernelForNode_ExplicitKernel(t *testing.T) {
	// Explicit kernel.type: only transport mismatches flip (machine-mode
	// semantics); protocol/Reality conflicts surface as validation errors.
	if got := ResolveKernelForNode(&NodeSpec{Protocol: "tuic"}, config.KernelConfig{Type: "xray"}); got != "xray" {
		t.Errorf("explicit xray + tuic = %q, want xray (validation rejects later)", got)
	}
	if got := ResolveKernelForNode(&NodeSpec{Protocol: "vmess", TLS: 2}, config.KernelConfig{Type: "singbox"}); got != "singbox" {
		t.Errorf("explicit singbox + vmess reality = %q, want singbox (validation path)", got)
	}
	if got := ResolveKernelForNode(&NodeSpec{Protocol: "vless", Network: "xhttp"}, config.KernelConfig{Type: "singbox"}); got != "xray" {
		t.Errorf("explicit singbox + xhttp = %q, want xray", got)
	}
}

func TestValidateNodeSpec_SS2022ChachaRejected(t *testing.T) {
	for _, cipher := range []string{"2022-blake3-chacha20-poly1305", "2022-blake3-chacha12-poly1305", "2022-Blake3-Chacha8-Poly1305"} {
		err := ValidateNodeSpec(&NodeSpec{Protocol: "shadowsocks", ServerPort: 1, Cipher: cipher}, config.KernelConfig{Type: "singbox"})
		if err == nil {
			t.Errorf("cipher %q: expected rejection, got nil", cipher)
			continue
		}
		if !contains(err.Error(), "AES-only") {
			t.Errorf("cipher %q: error should explain AES-only EIH, got %q", cipher, err.Error())
		}
	}
	for _, cipher := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "aes-256-gcm"} {
		if err := ValidateNodeSpec(&NodeSpec{Protocol: "shadowsocks", ServerPort: 1, Cipher: cipher}, config.KernelConfig{Type: "singbox"}); err != nil {
			t.Errorf("cipher %q: unexpected error %v", cipher, err)
		}
	}
}

func TestValidateNodeSpec_XrayShadowsocksCipher(t *testing.T) {
	// The 146 SS-aes-192-gcm-xray node: panel dispatched kernel_type=xray with
	// a cipher the pinned xray fork cannot parse; the node must refuse it
	// before starting the kernel.
	spec := &NodeSpec{Protocol: "shadowsocks", ServerPort: 1, Cipher: "aes-192-gcm"}

	err := ValidateNodeSpec(spec, config.KernelConfig{Type: "xray"})
	if err == nil {
		t.Fatal("xray + aes-192-gcm: expected rejection, got nil")
	}
	if !contains(err.Error(), "not supported by xray") {
		t.Errorf("error should name the xray kernel, got %q", err.Error())
	}

	// sing-box and auto (which resolves Shadowsocks to sing-box) still accept it.
	if err := ValidateNodeSpec(spec, config.KernelConfig{Type: "singbox"}); err != nil {
		t.Errorf("singbox + aes-192-gcm: unexpected error %v", err)
	}
	if err := ValidateNodeSpec(spec, config.KernelConfig{Type: "auto"}); err != nil {
		t.Errorf("auto + aes-192-gcm: unexpected error %v", err)
	}

	// auto resolves to xray when the panel pins kernel_type=xray.
	if err := ValidateNodeSpec(&NodeSpec{Protocol: "shadowsocks", ServerPort: 1, Cipher: "aes-192-gcm", KernelType: "xray"}, config.KernelConfig{Type: "auto"}); err == nil || !contains(err.Error(), "not supported by xray") {
		t.Errorf("auto + panel kernel_type=xray: want rejection, got %v", err)
	}

	if err := ValidateNodeSpec(&NodeSpec{Protocol: "shadowsocks", ServerPort: 1, Cipher: "aes-256-gcm"}, config.KernelConfig{Type: "xray"}); err != nil {
		t.Errorf("xray + aes-256-gcm: unexpected error %v", err)
	}

	for _, cipher := range []string{"", "   "} {
		err := ValidateNodeSpec(&NodeSpec{Protocol: "shadowsocks", ServerPort: 1, Cipher: cipher}, config.KernelConfig{Type: "xray"})
		if err == nil || !contains(err.Error(), "not supported by xray") {
			t.Errorf("xray + cipher %q: want rejection, got %v", cipher, err)
		}
	}
}

func TestValidateNodeSpec_SSPluginRejected(t *testing.T) {
	err := ValidateNodeSpec(&NodeSpec{Protocol: "shadowsocks", ServerPort: 1, Cipher: "aes-256-gcm", Plugin: "simple-obfs", PluginOpt: "obfs=http"}, config.KernelConfig{Type: "singbox"})
	if err == nil {
		t.Fatal("expected rejection, got nil")
	}
	if !contains(err.Error(), "SIP003") {
		t.Errorf("error should mention SIP003 plugins, got %q", err.Error())
	}
	if err := ValidateNodeSpec(&NodeSpec{Protocol: "shadowsocks", ServerPort: 1, Cipher: "aes-256-gcm"}, config.KernelConfig{Type: "singbox"}); err != nil {
		t.Errorf("no plugin: unexpected error %v", err)
	}
}

func TestValidateNodeSpec_HysteriaPolicy(t *testing.T) {
	base := &NodeSpec{Protocol: "hysteria", Version: 2, ServerPort: 8443}

	for _, profile := range []string{"standard", "conservative", "aggressive", ""} {
		spec := *base
		spec.HysteriaCongestion = &panel.CongestionConfig{Type: "bbr", BBRProfile: profile}
		if err := ValidateNodeSpec(&spec, config.KernelConfig{Type: "singbox"}); err != nil {
			t.Errorf("bbr_profile %q: unexpected error %v", profile, err)
		}
	}
	for _, profile := range []string{"high", "low", "turbo"} {
		spec := *base
		spec.HysteriaCongestion = &panel.CongestionConfig{BBRProfile: profile}
		err := ValidateNodeSpec(&spec, config.KernelConfig{Type: "singbox"})
		if err == nil || !contains(err.Error(), "bbr_profile") {
			t.Errorf("bbr_profile %q: want bbr_profile rejection, got %v", profile, err)
		}
	}
	spec := *base
	spec.HysteriaCongestion = &panel.CongestionConfig{Type: "cubic"}
	if err := ValidateNodeSpec(&spec, config.KernelConfig{Type: "singbox"}); err == nil || !contains(err.Error(), "congestion.type") {
		t.Errorf("congestion.type cubic: want rejection, got %v", err)
	}

	for _, timeout := range []int{1, 60, 600} {
		spec := *base
		spec.UDPIdleTimeout = timeout
		if err := ValidateNodeSpec(&spec, config.KernelConfig{Type: "singbox"}); err != nil {
			t.Errorf("udp_idle_timeout %d: unexpected error %v", timeout, err)
		}
	}
	for _, timeout := range []int{-1, 601} {
		spec := *base
		spec.UDPIdleTimeout = timeout
		err := ValidateNodeSpec(&spec, config.KernelConfig{Type: "singbox"})
		if err == nil || !contains(err.Error(), "udp_idle_timeout") {
			t.Errorf("udp_idle_timeout %d: want rejection, got %v", timeout, err)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestValidatePanelRoutes(t *testing.T) {
	tags := map[string]struct{}{"direct": {}, "block": {}, "proxy-out": {}}
	tests := []struct {
		name      string
		kernel    string
		routes    []RouteRule
		wantError bool
	}{
		{"valid cidr", "singbox", []RouteRule{{Match: []string{"10.0.0.0/8"}, Action: "proxy", ActionValue: "proxy-out"}}, false},
		{"bad cidr", "singbox", []RouteRule{{Match: []string{"10.0.0.0/33"}, Action: "block"}}, true},
		{"domain with slash", "xray", []RouteRule{{Match: []string{"example.com/path"}, Action: "block"}}, true},
		{"geoip on singbox", "singbox", []RouteRule{{Match: []string{"geoip:cn"}, Action: "block"}}, true},
		{"geoip on xray", "xray", []RouteRule{{Match: []string{"geoip:cn"}, Action: "block"}}, false},
		{"unknown target", "singbox", []RouteRule{{Match: []string{"example.com"}, Action: "proxy", ActionValue: "missing"}}, true},
		{"case-mismatched target", "singbox", []RouteRule{{Match: []string{"example.com"}, Action: "proxy", ActionValue: "Proxy-Out"}}, true},
		{"proxy without target falls back to block", "xray", []RouteRule{{Match: []string{"example.com"}, Action: "proxy"}}, false},
		{"dns on xray compiles to block", "xray", []RouteRule{{Match: []string{"example.com"}, Action: "dns", ActionValue: "dns-out"}}, false},
		{"dns on singbox without target", "singbox", []RouteRule{{Match: []string{"example.com"}, Action: "dns"}}, true},
		{"unknown action", "singbox", []RouteRule{{Match: []string{"example.com"}, Action: "allow"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePanelRoutes(tt.routes, tt.kernel, tags)
			if (err != nil) != tt.wantError {
				t.Errorf("validatePanelRoutes() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidateMatcherValues_CIDRAndRegexp(t *testing.T) {
	tests := []struct {
		name  string
		match RouteMatch
		ok    bool
	}{
		{"bare ip", RouteMatch{IPCIDRs: []string{"8.8.8.8"}}, true},
		{"ipv6 cidr", RouteMatch{IPCIDRs: []string{"2001:db8::/32"}}, true},
		{"bad cidr", RouteMatch{IPCIDRs: []string{"10.0.0.0/8/1"}}, false},
		{"bad source ip", RouteMatch{SourceCIDRs: []string{"not-an-ip"}}, false},
		{"xray valid regexp", RouteMatch{Domains: []string{`regexp:^ad\.`}}, true},
		{"xray bad regexp", RouteMatch{Domains: []string{`regexp:[`}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMatcherValues("xray", tt.match, "rule.match")
			if (err == nil) != tt.ok {
				t.Errorf("validateMatcherValues() error = %v, want ok %v", err, tt.ok)
			}
		})
	}
}
