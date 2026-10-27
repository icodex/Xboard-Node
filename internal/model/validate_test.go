package model

import "testing"

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
		{"quic switches xray to singbox", "quic", "xray", "singbox"},
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
