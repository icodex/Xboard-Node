package route

import (
	"reflect"
	"strings"
	"testing"
)

func mustParse(t *testing.T, rule map[string]any) *Rule {
	t.Helper()
	parsed, err := ParseRule(rule)
	if err != nil {
		t.Fatalf("ParseRule(%v): %v", rule, err)
	}
	return parsed
}

// TestParseRule_ReportedNetworkRule pins the original bug payload:
// {"type":"field","network":"udp,tcp","outboundTag":"proxy"} used to reach the
// sing-box kernel verbatim and die with "unknown rule type: field".
func TestParseRule_ReportedNetworkRule(t *testing.T) {
	parsed := mustParse(t, map[string]any{
		"type":        "field",
		"network":     "udp,tcp",
		"outboundTag": "proxy",
	})
	if parsed.OutboundTag != "proxy" {
		t.Fatalf("OutboundTag: got %q, want proxy", parsed.OutboundTag)
	}
	if !reflect.DeepEqual(parsed.Networks, []string{"udp", "tcp"}) {
		t.Fatalf("Networks: got %v, want [udp tcp]", parsed.Networks)
	}
	if !reflect.DeepEqual(RenderSingbox(parsed), map[string]any{
		"outbound": "proxy",
		"network":  []string{"udp", "tcp"},
	}) {
		t.Fatalf("render: got %v", RenderSingbox(parsed))
	}
}

func TestParseRule_DomainPrefixes(t *testing.T) {
	parsed := mustParse(t, map[string]any{
		"outboundTag": "proxy",
		"domain": []any{
			"Example.COM",
			"domain:Sub.Example.ORG",
			"full:Exact.Example.NET",
			"regexp:^proxy\\.example\\.(com|net)$",
		},
	})
	if !reflect.DeepEqual(parsed.DomainSuffixes, []string{"example.com", "sub.example.org"}) {
		t.Fatalf("DomainSuffixes: got %v", parsed.DomainSuffixes)
	}
	if !reflect.DeepEqual(parsed.Domains, []string{"exact.example.net"}) {
		t.Fatalf("Domains: got %v", parsed.Domains)
	}
	if len(parsed.DomainRegexps) != 1 {
		t.Fatalf("DomainRegexps: got %v", parsed.DomainRegexps)
	}
}

func TestParseRule_IpGeoipPrivate(t *testing.T) {
	parsed := mustParse(t, map[string]any{
		"outboundTag": "direct",
		"ip":          []any{"10.0.0.0/8", "2001:db8::/32", "1.2.3.4", "geoip:private"},
	})
	if !reflect.DeepEqual(parsed.IPCIDRs, []string{"10.0.0.0/8", "2001:db8::/32", "1.2.3.4/32"}) {
		t.Fatalf("IPCIDRs: got %v", parsed.IPCIDRs)
	}
	if !parsed.IPIsPrivate {
		t.Fatal("IPIsPrivate: got false, want true")
	}
}

func TestParseRule_PortForms(t *testing.T) {
	tests := []struct {
		name    string
		input   any
		ports   []int
		ranges  []string
		wantErr string
	}{
		{name: "comma string", input: "443,8000-9000", ports: []int{443}, ranges: []string{"8000:9000"}},
		{name: "colon range", input: "100:200", ranges: []string{"100:200"}},
		{name: "array mixed", input: []any{"443", float64(8080)}, ports: []int{443, 8080}},
		{name: "bare number", input: float64(53), ports: []int{53}},
		{name: "spaces", input: "443, 8000 - 9000", ports: []int{443}, ranges: []string{"8000:9000"}},
		{name: "reversed", input: "9000-8000", wantErr: "reversed"},
		{name: "zero", input: "0", wantErr: "between 1 and 65535"},
		{name: "too big", input: "65536", wantErr: "between 1 and 65535"},
		{name: "junk", input: "https", wantErr: "must be an integer"},
		{name: "empty token", input: "443,", wantErr: "empty port"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := ParseRule(map[string]any{"outboundTag": "proxy", "port": tc.input})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRule: %v", err)
			}
			if !reflect.DeepEqual(parsed.Ports, tc.ports) {
				t.Fatalf("Ports: got %v, want %v", parsed.Ports, tc.ports)
			}
			if !reflect.DeepEqual(parsed.PortRanges, tc.ranges) {
				t.Fatalf("PortRanges: got %v, want %v", parsed.PortRanges, tc.ranges)
			}
		})
	}
}

func TestParseRule_NetworkForms(t *testing.T) {
	parsed := mustParse(t, map[string]any{"outboundTag": "proxy", "network": []any{"TCP", "udp"}})
	if !reflect.DeepEqual(parsed.Networks, []string{"tcp", "udp"}) {
		t.Fatalf("Networks: got %v", parsed.Networks)
	}
	if _, err := ParseRule(map[string]any{"outboundTag": "proxy", "network": "icmp"}); err == nil {
		t.Fatal("expected error for icmp network")
	}
}

func TestParseRule_SourceFields(t *testing.T) {
	parsed := mustParse(t, map[string]any{
		"outboundTag": "proxy",
		"source":      "192.168.1.0/24",
		"sourcePort":  "1000-1002",
	})
	if !reflect.DeepEqual(parsed.SourceIPCIDRs, []string{"192.168.1.0/24"}) {
		t.Fatalf("SourceIPCIDRs: got %v", parsed.SourceIPCIDRs)
	}
	if !reflect.DeepEqual(parsed.SourcePortRanges, []string{"1000:1002"}) {
		t.Fatalf("SourcePortRanges: got %v", parsed.SourcePortRanges)
	}
	if _, err := ParseRule(map[string]any{"outboundTag": "proxy", "source": "geoip:private"}); err == nil {
		t.Fatal("expected error for geoip in source")
	}
}

func TestParseRule_Rejects(t *testing.T) {
	tests := []struct {
		name    string
		rule    map[string]any
		wantErr string
	}{
		{
			name:    "unknown keys sorted",
			rule:    map[string]any{"outboundTag": "proxy", "inboundTag": "in", "protocol": "http", "attributes": "x"},
			wantErr: "has unsupported keys [attributes inboundTag protocol]",
		},
		{name: "type not field", rule: map[string]any{"type": "logical", "outboundTag": "proxy", "network": "tcp"}, wantErr: `unsupported type "logical"`},
		{name: "missing outboundTag", rule: map[string]any{"network": "tcp"}, wantErr: "outboundTag is required"},
		{name: "blank outboundTag", rule: map[string]any{"outboundTag": "  ", "network": "tcp"}, wantErr: "outboundTag is required"},
		{name: "empty matchers", rule: map[string]any{"outboundTag": "proxy"}, wantErr: "no match condition"},
		{name: "geosite", rule: map[string]any{"outboundTag": "proxy", "domain": "geosite:cn"}, wantErr: "geosite"},
		{name: "geoip", rule: map[string]any{"outboundTag": "proxy", "ip": "geoip:cn"}, wantErr: "geoip"},
		{name: "geoip negation", rule: map[string]any{"outboundTag": "proxy", "ip": "geoip:!cn"}, wantErr: "negation"},
		{name: "bad regexp", rule: map[string]any{"outboundTag": "proxy", "domain": "regexp:([a"}, wantErr: "not a valid regexp"},
		{name: "empty domain", rule: map[string]any{"outboundTag": "proxy", "domain": "full:"}, wantErr: "empty"},
		{name: "attribute", rule: map[string]any{"outboundTag": "proxy", "domain": "example.com@ads"}, wantErr: "attributes"},
		{name: "singbox native", rule: map[string]any{"outbound": "proxy", "ip_cidr": []string{"10.0.0.0/8"}}, wantErr: "Xray-native form"},
		{name: "non-string domain", rule: map[string]any{"outboundTag": "proxy", "domain": []any{float64(1)}}, wantErr: "strings"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseRule(tc.rule)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestRenderSingbox_FullRule(t *testing.T) {
	parsed := mustParse(t, map[string]any{
		"type":        "field",
		"outboundTag": "Proxy",
		"domain":      []any{"Example.com", "full:Exact.Example.net", "regexp:^a\\.com$"},
		"ip":          []any{"10.0.0.0/8", "geoip:private"},
		"port":        "443,8000-9000",
		"network":     "TCP,udp",
		"source":      "192.168.0.0/16",
		"sourcePort":  "1000-1002",
	})
	want := map[string]any{
		"outbound":          "Proxy",
		"domain_suffix":     []string{"example.com"},
		"domain":            []string{"exact.example.net"},
		"domain_regex":      []string{"^a\\.com$"},
		"ip_cidr":           []string{"10.0.0.0/8"},
		"ip_is_private":     true,
		"port":              []int{443},
		"port_range":        []string{"8000:9000"},
		"network":           []string{"tcp", "udp"},
		"source_ip_cidr":    []string{"192.168.0.0/16"},
		"source_port_range": []string{"1000:1002"},
	}
	got := RenderSingbox(parsed)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("render mismatch:\ngot  %v\nwant %v", got, want)
	}
}

func TestRenderSingbox_DoesNotMutateInput(t *testing.T) {
	parsed := mustParse(t, map[string]any{"outboundTag": "proxy", "network": "tcp"})
	before := append([]string(nil), parsed.Networks...)
	_ = RenderSingbox(parsed)
	parsed.Networks[0] = "mutated"
	if !reflect.DeepEqual(before, []string{"tcp"}) {
		t.Fatal("render aliased the parsed rule's slices")
	}
}

func TestDetectForm(t *testing.T) {
	tests := []struct {
		name string
		rule map[string]any
		want RuleForm
	}{
		{name: "xray", rule: map[string]any{"type": "field", "network": "tcp", "outboundTag": "proxy"}, want: FormXray},
		{name: "xray outboundTag only", rule: map[string]any{"outboundTag": "proxy", "ip": "10.0.0.0/8"}, want: FormXray},
		{name: "structured", rule: map[string]any{"match": map[string]any{"networks": []any{"tcp"}}, "action": map[string]any{"type": "route", "target": "proxy"}}, want: FormStructured},
		{name: "structured named", rule: map[string]any{"name": "n", "disabled": false, "match": map[string]any{}, "action": map[string]any{"type": "direct"}}, want: FormStructured},
		{name: "singbox", rule: map[string]any{"outbound": "proxy", "ip_cidr": []string{"10.0.0.0/8"}}, want: FormSingbox},
		{name: "singbox action", rule: map[string]any{"action": "reject", "network": []string{"udp"}}, want: FormSingbox},
		{name: "unknown", rule: map[string]any{"foo": "bar", "match": "x", "action": "y"}, want: FormUnknown},
		{name: "empty", rule: map[string]any{}, want: FormUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := DetectForm(tc.rule); got != tc.want {
				t.Fatalf("DetectForm: got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSanitizeRules_XrayForm(t *testing.T) {
	tags := map[string]struct{}{"proxy": {}}
	good := map[string]any{"type": "field", "network": "tcp", "outboundTag": "PROXY"}
	badTag := map[string]any{"type": "field", "network": "tcp", "outboundTag": "nope"}
	badKey := map[string]any{"type": "field", "balancerTag": "b", "outboundTag": "proxy"}

	kept, _, issues := SanitizeRules([]map[string]any{good, badTag, badKey}, "singbox", tags, "custom_routes")
	if len(kept) != 1 || !reflect.DeepEqual(kept[0], good) {
		t.Fatalf("kept: want [good], got %v", kept)
	}
	if len(issues) != 2 {
		t.Fatalf("issues: want 2, got %v", issues)
	}
	joined := strings.Join(issues, "\n")
	if !strings.Contains(joined, `unknown outbound "nope"`) || !strings.Contains(joined, "balancerTag") {
		t.Fatalf("issue text mismatch: %v", issues)
	}

	// tag check runs for both kernels
	for _, kernel := range []string{"xray", "singbox"} {
		_, _, issues = SanitizeRules([]map[string]any{badTag}, kernel, tags, "custom_routes")
		if len(issues) != 1 {
			t.Fatalf("kernel %s: unknown tag must drop the rule, got issues %v", kernel, issues)
		}
		kept, _, _ = SanitizeRules([]map[string]any{good}, kernel, tags, "custom_routes")
		if len(kept) != 1 {
			t.Fatalf("kernel %s: good rule must be kept", kernel)
		}
	}
}

func TestSanitizeRules_SingboxForm(t *testing.T) {
	legacy := map[string]any{"outbound": "proxy", "ip_cidr": []string{"10.0.0.0/8"}}

	kept, _, issues := SanitizeRules([]map[string]any{legacy}, "singbox", nil, "custom_routes")
	if len(kept) != 1 || len(issues) != 0 {
		t.Fatalf("legacy rule must survive the singbox kernel, kept %v issues %v", kept, issues)
	}

	kept, _, issues = SanitizeRules([]map[string]any{legacy}, "xray", nil, "custom_routes")
	if len(kept) != 0 || len(issues) != 1 || !strings.Contains(issues[0], "cannot run on the xray kernel") {
		t.Fatalf("legacy rule must drop on xray, kept %v issues %v", kept, issues)
	}

	// unknown outbound tag still checked when tags are available
	bad := map[string]any{"outbound": "ghost", "ip_cidr": []string{"10.0.0.0/8"}}
	_, _, issues = SanitizeRules([]map[string]any{bad}, "singbox", map[string]struct{}{"proxy": {}}, "custom_routes")
	if len(issues) != 1 || !strings.Contains(issues[0], "ghost") {
		t.Fatalf("unknown singbox outbound must be dropped, issues %v", issues)
	}
}

func TestSanitizeRules_StructuredAndUnknown(t *testing.T) {
	structured := map[string]any{"match": map[string]any{"networks": []any{"tcp", "udp"}}, "action": map[string]any{"type": "route", "target": "proxy"}}
	unknown := map[string]any{"foo": "bar"}

	kept, _, issues := SanitizeRules([]map[string]any{structured, unknown}, "singbox", nil, "custom_routes")
	if len(kept) != 1 || !reflect.DeepEqual(kept[0], structured) {
		t.Fatalf("structured rule must be kept verbatim, kept %v", kept)
	}
	if len(issues) != 1 || !strings.Contains(issues[0], "unrecognized rule shape") || !strings.Contains(issues[0], "[foo]") {
		t.Fatalf("unknown rule must be dropped with keys listed, issues %v", issues)
	}
}
