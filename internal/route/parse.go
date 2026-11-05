// Package route parses panel-authored raw route rules. Panel custom_routes
// are authored in Xray-native form (type/outboundTag/matcher keys); the xray
// kernel consumes them verbatim and the sing-box kernel renders them through
// this package. See docs-custom-routes.md.
package route

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Rule is the typed result of parsing one Xray-form raw route rule.
type Rule struct {
	OutboundTag      string
	DomainSuffixes   []string // Xray plain / "domain:" values (apex + subdomains)
	Domains          []string // Xray "full:" values (exact match)
	DomainRegexps    []string // Xray "regexp:" values (as authored)
	IPCIDRs          []string
	IPIsPrivate      bool // Xray "geoip:private"
	Ports            []int
	PortRanges       []string // "a:b"
	Networks         []string
	SourceIPCIDRs    []string
	SourcePorts      []int
	SourcePortRanges []string // "a:b"
}

// IsEmpty reports whether the rule has no match condition at all.
func (r *Rule) IsEmpty() bool {
	if r == nil {
		return true
	}
	return len(r.DomainSuffixes) == 0 && len(r.Domains) == 0 && len(r.DomainRegexps) == 0 &&
		len(r.IPCIDRs) == 0 && !r.IPIsPrivate &&
		len(r.Ports) == 0 && len(r.PortRanges) == 0 &&
		len(r.Networks) == 0 &&
		len(r.SourceIPCIDRs) == 0 &&
		len(r.SourcePorts) == 0 && len(r.SourcePortRanges) == 0
}

// knownRuleKeys is the Xray routing-rule whitelist. Anything else is rejected
// with the key named so misconfigurations fail at validation instead of at
// kernel start (or worse, silently change meaning).
var knownRuleKeys = map[string]struct{}{
	"type":        {},
	"outboundTag": {},
	"domain":      {},
	"ip":          {},
	"port":        {},
	"network":     {},
	"source":      {},
	"sourcePort":  {},
}

// ParseRule validates one Xray-form raw route rule into a typed Rule.
// Errors are rule-relative; callers prefix them with field and index.
func ParseRule(rule map[string]any) (*Rule, error) {
	var unknown []string
	for key := range rule {
		if _, ok := knownRuleKeys[key]; !ok {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, fmt.Errorf("has unsupported keys [%s]: raw custom_routes must be authored in Xray-native form; see docs-custom-routes.md", strings.Join(unknown, " "))
	}

	out := &Rule{}

	if raw, ok := rule["type"]; ok {
		typeValue, err := ruleString(raw, "type")
		if err != nil {
			return nil, err
		}
		if lowered := strings.ToLower(strings.TrimSpace(typeValue)); lowered != "" && lowered != "field" {
			return nil, fmt.Errorf("has unsupported type %q: only \"field\" rules are supported", typeValue)
		}
	}

	tag, err := requiredString(rule, "outboundTag")
	if err != nil {
		return nil, err
	}
	out.OutboundTag = tag

	if raw, ok := rule["domain"]; ok {
		values, err := xrayStringList(raw, "domain")
		if err != nil {
			return nil, err
		}
		if err := decodeDomainValues(out, values); err != nil {
			return nil, err
		}
	}

	if raw, ok := rule["ip"]; ok {
		values, err := xrayStringList(raw, "ip")
		if err != nil {
			return nil, err
		}
		if err := decodeIPValues(&out.IPCIDRs, &out.IPIsPrivate, values, "ip"); err != nil {
			return nil, err
		}
	}

	if raw, ok := rule["source"]; ok {
		values, err := xrayStringList(raw, "source")
		if err != nil {
			return nil, err
		}
		var unused bool
		if err := decodeIPValues(&out.SourceIPCIDRs, &unused, values, "source"); err != nil {
			return nil, err
		}
	}

	if raw, ok := rule["port"]; ok {
		if out.Ports, out.PortRanges, err = xrayPortSpecs(raw, "port"); err != nil {
			return nil, err
		}
	}
	if raw, ok := rule["sourcePort"]; ok {
		if out.SourcePorts, out.SourcePortRanges, err = xrayPortSpecs(raw, "sourcePort"); err != nil {
			return nil, err
		}
	}

	if raw, ok := rule["network"]; ok {
		values, err := xrayStringList(raw, "network")
		if err != nil {
			return nil, err
		}
		for _, value := range values {
			// Xray joins network values into one comma-separated string.
			for _, part := range strings.Split(value, ",") {
				if err := appendNetwork(out, part); err != nil {
					return nil, err
				}
			}
		}
	}

	if out.IsEmpty() {
		return nil, fmt.Errorf("has no match condition: at least one of domain, ip, source, port, network or sourcePort is required")
	}
	return out, nil
}

// ParseRules parses a raw rule list, prefixing errors with the list index.
func ParseRules(rules []map[string]any) ([]*Rule, error) {
	out := make([]*Rule, 0, len(rules))
	for i, rule := range rules {
		parsed, err := ParseRule(rule)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
		out = append(out, parsed)
	}
	return out, nil
}

// RuleForm classifies a raw custom_routes entry.
type RuleForm int

const (
	FormUnknown RuleForm = iota
	FormStructured
	FormXray
	FormSingbox
)

var structuredRuleKeys = map[string]struct{}{
	"name":     {},
	"disabled": {},
	"match":    {},
	"action":   {},
}

var singboxRuleKeys = map[string]struct{}{
	"outbound":          {},
	"action":            {},
	"network":           {},
	"ip_cidr":           {},
	"ip_is_private":     {},
	"domain":            {},
	"domain_suffix":     {},
	"domain_keyword":    {},
	"domain_regex":      {},
	"port":              {},
	"port_range":        {},
	"source_ip_cidr":    {},
	"source_port":       {},
	"source_port_range": {},
	"inbound":           {},
	"protocol":          {},
	"clash_mode":        {},
	"invert":            {},
	"rule_set":          {},
}

// IsStructuredRule reports whether the entry uses the structured
// match/action shape (the custom_route_rules entry format).
func IsStructuredRule(rule map[string]any) bool {
	return DetectForm(rule) == FormStructured
}

// DetectForm classifies one raw custom_routes entry. Unknown shapes are
// reported as FormUnknown so callers can drop them with a log instead of
// crashing a kernel.
func DetectForm(rule map[string]any) RuleForm {
	if _, hasAction := rule["action"]; hasAction {
		structured := true
		for key := range rule {
			if _, ok := structuredRuleKeys[key]; !ok {
				structured = false
				break
			}
		}
		if structured {
			return FormStructured
		}
	}
	if _, ok := rule["outboundTag"]; ok {
		return FormXray
	}
	if _, ok := rule["type"]; ok {
		return FormXray
	}
	ok := true
	hasRoute := false
	for key := range rule {
		if _, known := singboxRuleKeys[key]; !known {
			ok = false
			break
		}
		if key == "outbound" || key == "action" {
			hasRoute = true
		}
	}
	if ok && hasRoute {
		return FormSingbox
	}
	return FormUnknown
}

func appendNetwork(out *Rule, value string) error {
	lowered := strings.ToLower(strings.TrimSpace(value))
	if lowered == "" {
		return fmt.Errorf("network contains an empty value")
	}
	if lowered != "tcp" && lowered != "udp" {
		return fmt.Errorf("network contains unsupported value %q: use tcp or udp", value)
	}
	out.Networks = append(out.Networks, lowered)
	return nil
}

func decodeDomainValues(out *Rule, values []string) error {
	for _, value := range values {
		switch {
		case strings.HasPrefix(value, "geosite:"):
			return fmt.Errorf("domain %q is not supported: the sing-box kernel removed geosite databases; use the xray kernel, or a kernel.custom_route rule_set entry", value)
		case strings.HasPrefix(value, "ext:"):
			return fmt.Errorf("domain %q is not supported: external geosite files are a sing-box kernel limitation; use the xray kernel, or a kernel.custom_route rule_set entry", value)
		case strings.HasPrefix(value, "regexp:"):
			pattern := strings.TrimSpace(strings.TrimPrefix(value, "regexp:"))
			if pattern == "" {
				return fmt.Errorf("domain %q has an empty regexp", value)
			}
			if _, err := regexp.Compile(pattern); err != nil {
				return fmt.Errorf("domain %q is not a valid regexp: %v", value, err)
			}
			out.DomainRegexps = append(out.DomainRegexps, pattern)
		case strings.HasPrefix(value, "full:"):
			host := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(value, "full:")))
			if host == "" {
				return fmt.Errorf("domain %q is empty", value)
			}
			out.Domains = append(out.Domains, host)
		case strings.HasPrefix(value, "domain:"):
			host := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(value, "domain:")))
			if host == "" {
				return fmt.Errorf("domain %q is empty", value)
			}
			if strings.Contains(host, "@") {
				return fmt.Errorf("domain %q uses attributes, which are not supported", value)
			}
			out.DomainSuffixes = append(out.DomainSuffixes, host)
		default:
			host := strings.ToLower(strings.TrimSpace(value))
			if host == "" {
				return fmt.Errorf("domain list contains an empty value")
			}
			if strings.Contains(host, "@") {
				return fmt.Errorf("domain %q uses attributes, which are not supported", value)
			}
			out.DomainSuffixes = append(out.DomainSuffixes, host)
		}
	}
	return nil
}

func decodeIPValues(cidrs *[]string, isPrivate *bool, values []string, field string) error {
	for _, value := range values {
		lowered := strings.ToLower(value)
		if strings.Contains(lowered, "!") {
			return fmt.Errorf("%s %q uses negation, which is not supported (sing-box invert is whole-rule only)", field, value)
		}
		switch {
		case strings.HasPrefix(lowered, "geoip:"):
			code := strings.TrimPrefix(lowered, "geoip:")
			if code == "private" {
				*isPrivate = true
				continue
			}
			return fmt.Errorf("%s %q is not supported: the sing-box kernel removed geoip databases; use the xray kernel, or a kernel.custom_route rule_set entry", field, value)
		case strings.HasPrefix(lowered, "ext:"):
			return fmt.Errorf("%s %q is not supported: external geoip files are a sing-box kernel limitation; use the xray kernel, or a kernel.custom_route rule_set entry", field, value)
		}
		if _, _, err := net.ParseCIDR(value); err == nil {
			*cidrs = append(*cidrs, value)
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(value))
		if ip == nil {
			return fmt.Errorf("%s %q is not a valid CIDR or IP address", field, value)
		}
		addr, _ := netip.ParseAddr(strings.TrimSpace(value))
		bits := 32
		if addr.Is6() {
			bits = 128
		}
		*cidrs = append(*cidrs, netip.PrefixFrom(addr, bits).String())
	}
	return nil
}

// xrayStringList accepts a scalar string, a []any of strings, or a []string
// and returns trimmed non-empty values.
func xrayStringList(raw any, field string) ([]string, error) {
	var items []any
	switch value := raw.(type) {
	case string:
		items = []any{value}
	case []any:
		items = value
	case []string:
		items = make([]any, len(value))
		for i, item := range value {
			items[i] = item
		}
	default:
		return nil, fmt.Errorf("%s must be a string or an array of strings", field)
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s must contain only strings, got %T", field, item)
		}
		text = strings.TrimSpace(text)
		if text == "" {
			return nil, fmt.Errorf("%s contains an empty value", field)
		}
		out = append(out, text)
	}
	return out, nil
}

// xrayPortSpecs accepts a scalar ("443"), a comma list ("443,8000-9000"), an
// array of strings/numbers, or a bare number, and returns single ports plus
// "a:b" ranges. Invalid tokens error instead of being dropped.
func xrayPortSpecs(raw any, field string) ([]int, []string, error) {
	var tokens []string
	switch value := raw.(type) {
	case string:
		tokens = strings.Split(value, ",")
	case []any:
		for _, item := range value {
			switch entry := item.(type) {
			case string:
				tokens = append(tokens, strings.Split(entry, ",")...)
			case float64, int, int64:
				tokens = append(tokens, fmt.Sprintf("%v", entry))
			default:
				return nil, nil, fmt.Errorf("%s must contain only ports or ranges, got %T", field, item)
			}
		}
	case float64, int, int64:
		tokens = []string{fmt.Sprintf("%v", value)}
	default:
		return nil, nil, fmt.Errorf("%s must be a string, a number, or an array", field)
	}

	var ports []int
	var ranges []string
	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if token == "" {
			return nil, nil, fmt.Errorf("%s contains an empty port", field)
		}
		if strings.Contains(token, "-") || strings.Contains(token, ":") {
			normalized := strings.ReplaceAll(token, ":", "-")
			bounds := strings.Split(normalized, "-")
			if len(bounds) != 2 {
				return nil, nil, fmt.Errorf("%s contains invalid port range %q", field, token)
			}
			start, err := asPort(bounds[0])
			if err != nil {
				return nil, nil, fmt.Errorf("%s contains invalid port range %q: %w", field, token, err)
			}
			end, err := asPort(bounds[1])
			if err != nil {
				return nil, nil, fmt.Errorf("%s contains invalid port range %q: %w", field, token, err)
			}
			if end < start {
				return nil, nil, fmt.Errorf("%s contains reversed port range %q", field, token)
			}
			ranges = append(ranges, fmt.Sprintf("%d:%d", start, end))
			continue
		}
		port, err := asPort(token)
		if err != nil {
			return nil, nil, fmt.Errorf("%s contains invalid port %q: %w", field, token, err)
		}
		ports = append(ports, port)
	}
	return ports, ranges, nil
}

func asPort(value string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("must be an integer")
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("must be between 1 and 65535")
	}
	return port, nil
}

func ruleString(raw any, field string) (string, error) {
	text, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string, got %T", field, raw)
	}
	return text, nil
}

func requiredString(rule map[string]any, key string) (string, error) {
	raw, ok := rule[key]
	if !ok {
		return "", fmt.Errorf("%s is required", key)
	}
	text, err := ruleString(raw, key)
	if err != nil {
		return "", err
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return "", fmt.Errorf("%s is required", key)
	}
	return text, nil
}
