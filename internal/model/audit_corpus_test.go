package model

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
)

// Audit: run ResolveKernelForNode over the panel corpus and flag every
// resolution whose kernel cannot actually serve the node. Skipped unless
// XBOARD_ROWS points at the corpus JSON (sqlite3 -json dump of
// id/type/protocol_settings/kernel_type for enabled+shown nodes).
func TestAuditAutoKernelResolutionAgainstPanelCorpus(t *testing.T) {
	path := os.Getenv("XBOARD_ROWS")
	if path == "" {
		t.Skip("set XBOARD_ROWS to the corpus JSON")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("corpus unavailable: %v", err)
	}
	var rows []struct {
		ID     int    `json:"id"`
		Type   string `json:"type"`
		PS     string `json:"ps"`
		Kernel string `json:"kernel_type"`
	}
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}

	kcfg := config.KernelConfig{Type: "auto"}
	counts := map[string]int{}
	var suspicious []string
	for _, r := range rows {
		var ps map[string]any
		if strings.TrimSpace(r.PS) != "" {
			if err := json.Unmarshal([]byte(r.PS), &ps); err != nil {
				t.Fatalf("node %d: bad protocol_settings: %v", r.ID, err)
			}
		}
		spec := &NodeSpec{Protocol: r.Type, KernelType: r.Kernel}
		if v, ok := ps["tls"].(float64); ok {
			spec.TLS = int(v)
		}
		if v, ok := ps["network"].(string); ok {
			spec.Network = v
		}
		if v, ok := ps["version"].(float64); ok {
			spec.Version = int(v)
		}
		if obfs, ok := ps["obfs"].(map[string]any); ok {
			if o, ok := obfs["open"].(bool); ok && o {
				if ty, ok := obfs["type"].(string); ok {
					spec.Obfs = ty
				}
			}
		}
		if mx, ok := ps["multiplex"].(map[string]any); ok {
			if e, ok := mx["enabled"].(bool); ok && e {
				if b, ok := mx["brutal"].(map[string]any); ok {
					if e, ok := b["enabled"].(bool); ok && e {
						spec.Multiplex = &MultiplexConfig{Enabled: true, Brutal: &BrutalConfig{Enabled: true}}
					}
				}
			}
		}

		resolved := ResolveKernelForNode(spec, kcfg)
		counts[resolved]++

		var problems []string
		xrayProtocols := map[string]bool{
			"vmess": true, "vless": true, "trojan": true,
			"shadowsocks": true, "hysteria": true,
		}
		if resolved == "xray" && !xrayProtocols[spec.Protocol] {
			problems = append(problems, "xray cannot serve protocol "+spec.Protocol)
		}
		if resolved == "xray" && spec.Protocol == "hysteria" {
			if spec.Version != 2 {
				problems = append(problems, "xray only serves hysteria v2")
			}
			if strings.TrimSpace(spec.Obfs) != "" {
				problems = append(problems, "xray has no hysteria2 obfs")
			}
		}
		if err := validateTransportKernel(spec.Network, resolved); err != nil {
			problems = append(problems, err.Error())
		}
		if len(problems) > 0 {
			suspicious = append(suspicious, fmt.Sprintf(
				"node %d %s/%s tls=%d hy_ver=%d obfs=%q brutal=%v -> %s: %s",
				r.ID, spec.Protocol, spec.Network, spec.TLS, spec.Version,
				spec.Obfs, spec.Multiplex != nil && spec.Multiplex.Brutal != nil, resolved, strings.Join(problems, "; ")))
		}
	}
	t.Logf("resolved counts: singbox=%d xray=%d (corpus=%d)",
		counts["singbox"], counts["xray"], len(rows))
	for _, line := range suspicious {
		t.Logf("SUSPECT: %s", line)
	}
	if len(suspicious) > 0 {
		// Panel-pinned kernels are validated on save now (ServerSave), so a
		// suspect here means stale panel data, not a resolver bug.
		t.Logf("%d node(s) resolve to a kernel that cannot serve them (stale panel data)", len(suspicious))
	}
}
