package xray

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/panel"
)

// Without a dns block the kernel hands every domain target to the OS resolver
// (AsIs), and a stalled system resolver hangs all direct traffic while IP
// targets keep working. The generated config must carry its own resolvers.
func TestBuildConfigEmitsDNSAndExplicitResolveStrategy(t *testing.T) {
	prev := systemDNSLookup
	systemDNSLookup = func() []string { return []string{"127.0.0.53", "8.8.4.4"} }
	t.Cleanup(func() { systemDNSLookup = prev })

	nc := &panel.NodeConfig{Protocol: "vmess", ServerPort: 10004, TLS: 0}
	cfg, err := buildConfig(testKernelCfg, testNodeSpec(nc), testUsers, kernel.TLSCert{})
	if err != nil {
		t.Fatalf("build config: %v", err)
	}

	dns, ok := cfg["dns"].(M)
	if !ok {
		t.Fatalf("config has no dns block: %v", cfg["dns"])
	}
	servers, _ := dns["servers"].([]string)
	if len(servers) != 2 || servers[0] != "127.0.0.53" || servers[1] != "8.8.4.4" {
		t.Fatalf("dns.servers = %v, want the resolv.conf servers", dns["servers"])
	}
	if dns["queryStrategy"] != "UseIPv4" {
		t.Fatalf("dns.queryStrategy = %v, want UseIPv4", dns["queryStrategy"])
	}

	var direct M
	for _, o := range cfg["outbounds"].([]M) {
		if o["tag"] == "direct" {
			direct = o
		}
	}
	if direct == nil {
		t.Fatal("built-in direct outbound missing")
	}
	ss, _ := direct["streamSettings"].(M)
	sockopt, _ := ss["sockopt"].(M)
	if sockopt["domainStrategy"] != "UseIPv4" {
		t.Fatalf("direct sockopt.domainStrategy = %v, want UseIPv4", sockopt["domainStrategy"])
	}
}

// DNS queries follow routing rules, so the private-address block would blackhole
// loopback/LAN resolvers (127.0.0.53, docker's 127.0.0.11, LAN routers) unless a
// narrow allow rule precedes it.
func TestBuildRoutingAllowsConfiguredResolversBeforePrivateBlock(t *testing.T) {
	routing := buildRouting(nil, nil, nil, "127.0.0.53", "192.168.1.1", "not-an-ip")
	rules, _ := routing["rules"].([]M)
	if len(rules) < 2 {
		t.Fatalf("routing rules = %v, want the allow rule plus the private block", rules)
	}

	allow := rules[0]
	if allow["outboundTag"] != "direct" || allow["port"] != "53" {
		t.Fatalf("first rule = %v, want a port-53 direct allow rule", allow)
	}
	ips, _ := allow["ip"].([]string)
	if len(ips) != 2 || ips[0] != "127.0.0.53" || ips[1] != "192.168.1.1" {
		t.Fatalf("allow rule ip = %v, want the resolver IPs only", allow["ip"])
	}

	block := rules[1]
	if block["outboundTag"] != "block" {
		t.Fatalf("second rule = %v, want the private-address block", block)
	}
}

func TestParseNameserversSkipsJunkAndDuplicates(t *testing.T) {
	body := `
# comment
; other comment
nameserver 1.1.1.1
nameserver   1.1.1.1
nameserver fe80::1%en0
nameserver not-an-ip
nameserver 0.0.0.0
search example.com
options edns0
nameserver 8.8.8.8
nameserver 9.9.9.9
nameserver 1.0.0.1
`
	servers := parseNameservers(body)
	want := []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1"}
	if len(servers) != len(want) {
		t.Fatalf("servers = %v, want %v", servers, want)
	}
	for i := range want {
		if servers[i] != want[i] {
			t.Fatalf("servers = %v, want %v", servers, want)
		}
	}
}

func TestPickDNSServers(t *testing.T) {
	none := func() []string { return nil }
	some := func() []string { return []string{"192.168.1.1"} }

	// macOS: scutil wins over resolv.conf, because resolv.conf mirrors the
	// Supplemental fake-IP resolver some proxy apps install.
	got := pickDNSServers("darwin", "nameserver 198.18.0.2\n", some)
	if len(got) != 1 || got[0] != "192.168.1.1" {
		t.Fatalf("darwin pick = %v, want the scutil resolver", got)
	}

	// macOS with no usable scutil entry falls back to resolv.conf.
	got = pickDNSServers("darwin", "nameserver 127.0.0.53\n", none)
	if len(got) != 1 || got[0] != "127.0.0.53" {
		t.Fatalf("darwin fallback pick = %v, want the resolv.conf server", got)
	}

	// Linux never consults scutil.
	got = pickDNSServers("linux", "nameserver 8.8.4.4\n", some)
	if len(got) != 1 || got[0] != "8.8.4.4" {
		t.Fatalf("linux pick = %v, want the resolv.conf server", got)
	}

	// Empty everywhere: public fallback so the kernel always has a resolver.
	got = pickDNSServers("linux", "", none)
	if len(got) != 2 || got[0] != "1.1.1.1" || got[1] != "8.8.8.8" {
		t.Fatalf("fallback pick = %v, want the public resolvers", got)
	}
}

// An operator custom_config dns block must still replace the auto-generated
// one: deployments with split-horizon/DoH resolvers depend on it.
func TestCustomConfigDNSReplacesGeneratedBlock(t *testing.T) {
	custom := `{"dns":{"servers":["https+local://dns.google/dns-query"],"queryStrategy":"UseIP"}}`
	path := filepath.Join(t.TempDir(), "custom.json")
	if err := os.WriteFile(path, []byte(custom), 0o600); err != nil {
		t.Fatal(err)
	}

	prev := systemDNSLookup
	systemDNSLookup = func() []string { return []string{"1.1.1.1"} }
	t.Cleanup(func() { systemDNSLookup = prev })

	kcfg := testKernelCfg
	kcfg.CustomConfig = path
	nc := &panel.NodeConfig{Protocol: "vmess", ServerPort: 10004}
	cfg, err := buildConfig(kcfg, testNodeSpec(nc), testUsers, kernel.TLSCert{})
	if err != nil {
		t.Fatalf("build config: %v", err)
	}

	dns, _ := cfg["dns"].(map[string]any)
	if dns["queryStrategy"] != "UseIP" {
		t.Fatalf("custom dns not applied: %v", dns)
	}
	servers, _ := dns["servers"].([]any)
	if len(servers) != 1 || servers[0] != "https+local://dns.google/dns-query" {
		t.Fatalf("custom dns servers not applied: %v", dns["servers"])
	}
}
