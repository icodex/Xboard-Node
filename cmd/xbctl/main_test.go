package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
)

// Rewriting a config must not drop inline tokens (legacy files use them).
func TestWriteRootConfigPreservesInlineToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	root := &config.RootConfig{Instances: []config.Config{{
		InstanceID: "panel-node-1-abc",
		Panel:      config.PanelConfig{URL: "https://panel.example", Token: "secret"},
		Kernel:     config.KernelConfig{Type: "xray"},
	}}}
	if err := writeRootConfig(path, root); err != nil {
		t.Fatalf("writeRootConfig: %v", err)
	}

	got, err := loadWritableRootConfig(path)
	if err != nil {
		t.Fatalf("loadWritableRootConfig: %v", err)
	}
	if len(got.Instances) != 1 {
		t.Fatalf("instances = %d, want 1", len(got.Instances))
	}
	if got.Instances[0].Panel.Token != "secret" {
		t.Fatalf("panel token = %q, want secret", got.Instances[0].Panel.Token)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %o, want 600", info.Mode().Perm())
	}
}

// Content-mode certs are valid without cert_mode (implicit resolution), and
// rewriting must not drop them.
func TestWriteRootConfigPreservesImplicitContentCert(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	root := &config.RootConfig{Instances: []config.Config{{
		InstanceID: "panel-node-1-abc",
		Panel:      config.PanelConfig{URL: "https://panel.example", TokenEnv: "KEY"},
		Kernel:     config.KernelConfig{Type: "xray"},
		Cert:       config.CertConfig{CertContent: "CERT", KeyContent: "KEY"},
	}}}
	if err := writeRootConfig(path, root); err != nil {
		t.Fatalf("writeRootConfig: %v", err)
	}

	got, err := loadWritableRootConfig(path)
	if err != nil {
		t.Fatalf("loadWritableRootConfig: %v", err)
	}
	cert := got.Instances[0].Cert
	if cert.CertContent != "CERT" || cert.KeyContent != "KEY" {
		t.Fatalf("cert = %+v, want content preserved", cert)
	}
}

// A token with no credentials destination goes into the 0600 config instead of
// being silently ignored while the config references an unset env var.
func TestConfigInitWritesInlineTokenWithoutCredentials(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "config.yml")
	if err := runConfigInit([]string{
		"--mode", "node",
		"--panel-url", "https://panel.example",
		"--node-id", "7",
		"--token", "secret",
		"--output", out,
		"--install-root", dir,
	}); err != nil {
		t.Fatalf("runConfigInit: %v", err)
	}

	got, err := loadWritableRootConfig(out)
	if err != nil {
		t.Fatalf("loadWritableRootConfig: %v", err)
	}
	if len(got.Instances) != 1 {
		t.Fatalf("instances = %d, want 1", len(got.Instances))
	}
	inst := got.Instances[0]
	if inst.Panel.Token != "secret" {
		t.Fatalf("panel token = %q, want secret", inst.Panel.Token)
	}
	if inst.Panel.TokenEnv != "" {
		t.Fatalf("token_env = %q, want empty when the token is inline", inst.Panel.TokenEnv)
	}
}

func instancesRoot() *config.RootConfig {
	return &config.RootConfig{Instances: []config.Config{
		{InstanceID: "node-a", Panel: config.PanelConfig{URL: "https://panel.example", NodeID: 1}},
		{InstanceID: "node-b", Panel: config.PanelConfig{URL: "https://panel.example", NodeID: 2}},
		{InstanceID: "machine-a", Panel: config.PanelConfig{URL: "https://panel.example"}, Machine: &config.MachineConfig{MachineID: 9}},
	}}
}

// The pure planner decides what survives a bind removal; the caller only
// writes files and toggles systemd.
func TestPlanBindingRemoval(t *testing.T) {
	legacy := &config.RootConfig{Config: config.Config{
		Panel: config.PanelConfig{URL: "https://panel.example", NodeID: 1},
	}}
	tests := []struct {
		name       string
		root       *config.RootConfig
		panelURL   string
		nodeID     int
		machineID  int
		instanceID string
		wantKept   int
		wantRemove int
		wantLegacy bool
		wantErr    bool
	}{
		{"legacy single config", legacy, "https://panel.example", 1, 0, "", 0, 1, true, false},
		{"remove one of many", instancesRoot(), "https://panel.example", 1, 0, "", 2, 1, false, false},
		{"remove machine", instancesRoot(), "https://panel.example", 0, 9, "", 2, 1, false, false},
		{"remove by instance id", instancesRoot(), "", 0, 0, "node-b", 2, 1, false, false},
		{"not found", instancesRoot(), "https://panel.example", 99, 0, "", 0, 0, false, true},
		{"empty config", &config.RootConfig{}, "", 0, 0, "", 0, 0, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan, err := planBindingRemoval(tt.root, tt.panelURL, tt.nodeID, tt.machineID, tt.instanceID)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(plan.kept) != tt.wantKept {
				t.Fatalf("kept = %d, want %d", len(plan.kept), tt.wantKept)
			}
			if len(plan.removed) != tt.wantRemove {
				t.Fatalf("removed = %d, want %d", len(plan.removed), tt.wantRemove)
			}
			if plan.wasLegacy != tt.wantLegacy {
				t.Fatalf("wasLegacy = %v, want %v", plan.wasLegacy, tt.wantLegacy)
			}
		})
	}
}

// A key still referenced by a remaining binding must survive the prune.
func TestPruneCredentialKeysKeepsSharedKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.env")
	if err := os.WriteFile(path, []byte("SHARED=1\nONLY_REMOVED=2\nOTHER=3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	removed := []config.Config{
		{Panel: config.PanelConfig{TokenEnv: "SHARED"}},
		{Panel: config.PanelConfig{TokenEnv: "ONLY_REMOVED"}},
	}
	remaining := []config.Config{{Panel: config.PanelConfig{TokenEnv: "SHARED"}}}

	if err := pruneCredentialKeys(path, removed, remaining); err != nil {
		t.Fatalf("pruneCredentialKeys: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "SHARED=1") {
		t.Fatalf("shared key was removed: %s", text)
	}
	if strings.Contains(text, "ONLY_REMOVED") {
		t.Fatalf("removed-only key was kept: %s", text)
	}
	if !strings.Contains(text, "OTHER=3") {
		t.Fatalf("unrelated key was dropped: %s", text)
	}
}
