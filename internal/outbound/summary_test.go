package outbound

import (
	"reflect"
	"strings"
	"testing"
)

func TestSummary_ReportedPayload(t *testing.T) {
	settings, streamSettings, mux := reportedPayload()
	c, err := Parse("vless", settings, streamSettings, mux, "")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	summary := c.Summary()

	want := map[string]any{
		"protocol":    "vless",
		"server":      "example.com",
		"server_port": 443,
		"flow":        "xtls-rprx-vision",
		"transport":   "raw",
		"security":    "reality",
		"server_name": "www.apple.com",
		"fingerprint": "chrome",
	}
	if !reflect.DeepEqual(summary, want) {
		t.Fatalf("summary mismatch:\ngot  %v\nwant %v", summary, want)
	}

	// Never leak credentials.
	for _, key := range []string{"id", "uuid", "password", "public_key", "private_key"} {
		if _, exists := summary[key]; exists {
			t.Fatalf("summary leaks %q: %v", key, summary)
		}
	}
	for key := range summary {
		if strings.Contains(strings.ToLower(key), "key") {
			t.Fatalf("summary key %q looks like a credential", key)
		}
	}
}

func TestSummary_DefaultsAndChain(t *testing.T) {
	settings := map[string]any{"address": "a.example.com", "port": float64(80), "id": "u"}
	c, err := Parse("vless", settings, nil, nil, "warp")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	summary := c.Summary()
	if summary["transport"] != "tcp" {
		t.Errorf("transport default: got %v", summary["transport"])
	}
	if summary["security"] != "none" {
		t.Errorf("security default: got %v", summary["security"])
	}
	if summary["detour"] != "warp" {
		t.Errorf("detour: got %v", summary["detour"])
	}
}

func TestSummary_Nil(t *testing.T) {
	var c *Canonical
	if c.Summary() != nil {
		t.Fatal("nil canonical must summarize to nil")
	}
}
