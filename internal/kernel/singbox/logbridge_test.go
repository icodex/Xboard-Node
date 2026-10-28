package singbox

import (
	"testing"

	singLog "github.com/sagernet/sing-box/log"
)

func TestNewNlogBridge_ParsesLevel(t *testing.T) {
	tests := []struct {
		input string
		want  singLog.Level
	}{
		{"trace", singLog.LevelTrace},
		{"debug", singLog.LevelDebug},
		{"info", singLog.LevelInfo},
		{"warn", singLog.LevelWarn},
		{"warning", singLog.LevelWarn},
		{"error", singLog.LevelError},
		{"fatal", singLog.LevelFatal},
		// Unknown values fall back to warn.
		{"verbose", singLog.LevelWarn},
		{"", singLog.LevelWarn},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			b := newNlogBridge(tt.input)
			if b.level() != tt.want {
				t.Errorf("newNlogBridge(%q).level() = %d, want %d", tt.input, b.level(), tt.want)
			}
		})
	}
}

func TestNormalizeBridgeMessage(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "relative time prefix",
			input: "ERROR[  12] inbound/vless-in: process connection from 1.2.3.4: dial tcp: i/o timeout",
			want:  "inbound/vless-in: process connection from 1.2.3.4: dial tcp: i/o timeout",
		},
		{
			name:  "ANSI colored level",
			input: "\x1b[31mERROR\x1b[0m[  12] router: lookup failed",
			want:  "router: lookup failed",
		},
		{
			name:  "no prefix",
			input: "some plain message",
			want:  "some plain message",
		},
		{
			name:  "whitespace only after strip",
			input: "  \x1b[31m  \x1b[0m ",
			want:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeBridgeMessage(tt.input); got != tt.want {
				t.Errorf("normalizeBridgeMessage(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestDowngradeInboundError(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want bool
	}{
		{
			name: "inbound tag",
			msg:  "inbound/vless-in: process connection from 1.2.3.4: authentication failed",
			want: true,
		},
		{
			name: "connection noise from other tag",
			msg:  "connection: process connection closed: connection reset by peer",
			want: true,
		},
		{
			name: "real dns error",
			msg:  "dns/transport: lookup example.com: empty result",
			want: false,
		},
		{
			name: "router error",
			msg:  "router: no outbound available",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := downgradeInboundError(tt.msg); got != tt.want {
				t.Errorf("downgradeInboundError(%q) = %v, want %v", tt.msg, got, tt.want)
			}
		})
	}
}

func TestNlogBridge_MinFilter(t *testing.T) {
	// warn-level bridge drops info entries (level number above min) but
	// passes warn and everything more severe.
	b := newNlogBridge("warn")
	if b.level() != singLog.LevelWarn {
		t.Fatalf("bridge level = %d, want %d", b.level(), singLog.LevelWarn)
	}
	// SetLevel hot-updates the filter.
	b.SetLevel("error")
	if b.level() != singLog.LevelError {
		t.Fatalf("bridge level after SetLevel = %d, want %d", b.level(), singLog.LevelError)
	}
	for _, level := range []singLog.Level{singLog.LevelError, singLog.LevelFatal} {
		if level > b.level() {
			t.Errorf("level %d must pass error filter", level)
		}
	}
	for _, level := range []singLog.Level{singLog.LevelWarn, singLog.LevelInfo, singLog.LevelDebug, singLog.LevelTrace} {
		if level <= b.level() {
			t.Errorf("level %d must be dropped by error filter", level)
		}
	}
}
