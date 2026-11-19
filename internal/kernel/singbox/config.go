package singbox

import (
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/nlog"
	ob "github.com/cedar2025/xboard-node/internal/outbound"
	"github.com/cedar2025/xboard-node/internal/panel"
	xr "github.com/cedar2025/xboard-node/internal/route"
	"github.com/go-viper/mapstructure/v2"
)

// M is a shorthand for building JSON-like maps
type M = map[string]interface{}

func buildConfig(kcfg config.KernelConfig, nc *model.NodeSpec, users []model.UserSpec, tc kernel.TLSCert) (M, error) {
	var outbounds []M
	tags := make(map[string]bool)

	// Panel-defined custom outbounds are authored in Xray-native form and
	// translated to the sing-box flat layout here.
	for _, co := range nc.CustomOutbounds {
		if model.IsReservedOutboundTag(co.Tag) {
			// Validation rejects this earlier; drop it here too so a direct
			// build (standalone/tests) can never shadow an outbound the
			// private-network rules and the final route depend on.
			nlog.Core().Warn("panel custom outbound uses a reserved tag, dropping", "tag", co.Tag)
			continue
		}
		converted, err := outboundConfigToSingbox(co)
		if err != nil {
			return nil, fmt.Errorf("custom outbound %q: %w", co.Tag, err)
		}
		outbounds = append(outbounds, converted)
		tags[co.Tag] = true
		kernel.LogRenderedOutbound(co)
	}

	// Static outbounds from local config file. Tags are matched exactly:
	// the kernel resolves references case-sensitively, so folding case here
	// would let "Direct" suppress the built-in "direct" while "final" still
	// points at "direct".
	for _, co := range kcfg.CustomOutbound {
		tag, _ := co["tag"].(string)
		if tag != "" {
			tags[tag] = true
		}
		outbounds = append(outbounds, M(co))
	}

	// Add default outbounds only if not already defined
	if !tags["direct"] {
		outbounds = append([]M{{"type": "direct", "tag": "direct"}}, outbounds...)
	}
	if !tags["block"] {
		outbounds = append(outbounds, M{"type": "block", "tag": "block"})
	}

	// The sing-box log factory is pinned at "panic" so its own stderr path
	// stays inert; every entry is forwarded to the nlogBridge PlatformWriter
	// instead (see Start), where level mapping, downgrade and output follow
	// the unified config.yml log settings.
	cfg := M{
		"log": M{
			"level": "panic",
		},
		"outbounds": outbounds,
	}

	inbound := buildInbound(nc, users, tc)
	if inbound != nil {
		cfg["inbounds"] = []M{inbound}
	}

	// Merge panel routes and static config routes
	route, err := buildRoutes(nc.Routes, nc.CustomRouteRules, nc.CustomRoutes, kcfg.CustomRoute)
	if err != nil {
		return nil, err
	}
	cfg["route"] = route

	// cache_file is ALWAYS pinned to a per-instance path: the nlogBridge is
	// passed as PlatformLogWriter, which makes sing-box create a cache-file
	// service even without any experimental config — with a cwd-relative
	// cache.db that every sing-box instance in the process would share and
	// lock-conflict on (second instance dies with "initialize cache-file:
	// timeout"). Geoip/geosite .srs caching (the original trigger) rides the
	// same store.
	cfg["experimental"] = M{
		"cache_file": M{
			"enabled": true,
			"path":    filepath.Join(kcfg.ConfigDir, "cache.db"),
		},
	}

	mergeCustomSingbox(cfg, kcfg)
	return cfg, nil
}

// outboundConfigToSingbox converts a panel outbound (Xray-native form) into a
// sing-box outbound object. sing-box uses a flat layout where all
// protocol-specific fields sit at the top level alongside "type" and "tag".
func outboundConfigToSingbox(oc model.OutboundConfig) (M, error) {
	canonical, err := ob.Parse(oc.Protocol, oc.Settings, oc.StreamSettings, oc.Mux, oc.ProxyTag)
	if err != nil {
		return nil, err
	}
	return canonical.RenderSingbox(oc.Tag)
}

func buildRoutes(panelRoutes []model.RouteRule, customRules []model.CustomRouteRule, panelRaw []map[string]any, staticRaw []map[string]any) (M, error) {
	var rules []M

	// Structured custom routes now take the highest priority for panel-managed overrides.
	for _, rule := range customRules {
		if rule.Disabled {
			continue
		}
		rules = append(rules, compileCustomRouteRule(rule)...)
	}

	// Raw custom routes remain the escape hatch, but no longer outrank
	// structured rules. Three shapes arrive here (SanitizeRawCustomRoutes has
	// already dropped the broken ones): structured match/action entries
	// compile like custom_route_rules, Xray-native rules translate, and
	// sing-box-native rules pass through verbatim. Translation failures skip
	// the rule with a log — a bad raw rule must never fail the kernel build.
	for _, cr := range panelRaw {
		switch {
		case xr.IsStructuredRule(cr):
			parsed, err := kernel.DecodeCustomRouteRule(cr)
			if err != nil {
				nlog.Core().Error("skipping unparseable structured custom route", "error", err)
				continue
			}
			if parsed.Disabled {
				continue
			}
			rules = append(rules, compileCustomRouteRule(parsed)...)
		default:
			parsed, err := xr.ParseRule(cr)
			if err != nil {
				// sing-box-native rules carry keys ParseRule rejects; they are
				// singbox kernel-native and pass through verbatim.
				rules = append(rules, M(cr))
				continue
			}
			rules = append(rules, M(xr.RenderSingbox(parsed)))
		}
	}

	// kernel.custom_route from the local config file is kernel-native by
	// contract (like kernel.custom_outbound) and passes through verbatim.
	for _, cr := range staticRaw {
		rules = append(rules, M(cr))
	}

	// Standard blocks for private IPv4 and IPv6 ranges to prevent SSRF.
	rules = append(rules,
		M{
			"outbound": "block",
			"ip_cidr": []string{
				"10.0.0.0/8",
				"100.64.0.0/10",
				"127.0.0.0/8",
				"169.254.0.0/16",
				"172.16.0.0/12",
				"192.0.0.0/24",
				"192.168.0.0/16",
				"198.18.0.0/15",
			},
		},
		M{
			"outbound": "block",
			"ip_cidr": []string{
				"fc00::/7",
				"fe80::/10",
				"::1/128",
			},
		},
	)

	for _, pr := range panelRoutes {
		rules = append(rules, compilePanelRouteRule(pr)...)
	}

	return M{
		"final": "direct",
		"rules": rules,
	}, nil
}

func compilePanelRouteRule(pr model.RouteRule) []M {
	if len(pr.Match) == 0 {
		return nil
	}

	var domains, cidrs []string
	for _, item := range pr.Match {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		item = strings.TrimPrefix(item, "*.")
		if strings.Contains(item, "/") {
			cidrs = append(cidrs, item)
			continue
		}
		domains = append(domains, item)
	}

	outbound := "block"
	switch pr.Action {
	case "direct":
		outbound = "direct"
	case "dns":
		if pr.ActionValue != "" {
			outbound = pr.ActionValue
		} else {
			outbound = "dns-out"
		}
	case "proxy":
		if pr.ActionValue != "" {
			outbound = pr.ActionValue
		}
	}

	var compiled []M
	if len(domains) > 0 {
		compiled = append(compiled, M{
			"domain_suffix": copyStrings(domains),
			"outbound":      outbound,
		})
	}
	if len(cidrs) > 0 {
		compiled = append(compiled, M{
			"ip_cidr":  copyStrings(cidrs),
			"outbound": outbound,
		})
	}
	return compiled
}

// compileCustomRouteRule renders one structured match/action rule as a single
// kernel rule. sing-box ORs values inside a matcher key and ANDs the keys, so
// a rule with both ip_cidr and port only matches traffic that satisfies both.
// Emitting one rule per key (the previous behavior) turned every multi-key
// match into an OR: {"ports":["443"],"domains":["ads.example.com"]} blocked
// all HTTPS traffic.
func compileCustomRouteRule(rule model.CustomRouteRule) []M {
	if rule.Disabled {
		return nil
	}
	compiled, ok := compileRouteMatch(rule.Match, singboxOutboundForAction(rule.Action))
	if !ok {
		return nil
	}
	return []M{compiled}
}

func compileRouteMatch(match model.RouteMatch, outbound string) (M, bool) {
	entry := M{"outbound": outbound}

	if len(match.Domains) > 0 {
		entry["domain"] = copyStrings(match.Domains)
	}
	if len(match.DomainSuffixes) > 0 {
		entry["domain_suffix"] = copyStrings(match.DomainSuffixes)
	}
	if len(match.IPCIDRs) > 0 {
		entry["ip_cidr"] = copyStrings(match.IPCIDRs)
	}
	if len(match.Ports) > 0 {
		ports, portRanges := splitPorts(match.Ports)
		if len(ports) > 0 {
			entry["port"] = ports
		}
		if len(portRanges) > 0 {
			entry["port_range"] = portRanges
		}
	}
	if len(match.Networks) > 0 {
		entry["network"] = copyStrings(match.Networks)
	}
	if len(match.SourceCIDRs) > 0 {
		entry["source_ip_cidr"] = copyStrings(match.SourceCIDRs)
	}
	if len(match.SourcePorts) > 0 {
		ports, portRanges := splitPorts(match.SourcePorts)
		if len(ports) > 0 {
			entry["source_port"] = ports
		}
		if len(portRanges) > 0 {
			entry["source_port_range"] = portRanges
		}
	}

	if len(entry) == 1 {
		return nil, false
	}
	return entry, true
}

func singboxOutboundForAction(action model.RouteAction) string {
	switch action.Type {
	case "direct":
		return "direct"
	case "route":
		if action.Target != "" {
			return action.Target
		}
		return "block"
	default:
		return "block"
	}
}

func splitPorts(values []string) ([]int, []string) {
	var ports []int
	var ranges []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if strings.ContainsAny(value, ":-") {
			ranges = append(ranges, strings.ReplaceAll(value, "-", ":"))
			continue
		}
		if port, err := strconv.Atoi(value); err == nil {
			ports = append(ports, port)
		}
	}
	return ports, ranges
}

func copyStrings(src []string) []string {
	if len(src) == 0 {
		return nil
	}
	out := make([]string, len(src))
	copy(out, src)
	return out
}

func mergeCustomSingbox(cfg M, kcfg config.KernelConfig) {
	custom, err := kernel.LoadCustomConfig(kcfg.CustomConfig)
	if err != nil {
		nlog.Core().Error("failed to load custom sing-box config", "error", err)
		return
	}
	if custom == nil {
		return
	}

	// dns — custom replaces
	if v, ok := custom["dns"]; ok {
		cfg["dns"] = v
	}

	// experimental — custom replaces
	if v, ok := custom["experimental"]; ok {
		cfg["experimental"] = v
	}

	// outbounds — append custom entries
	if v, ok := custom["outbounds"]; ok {
		if existing, ok := cfg["outbounds"].([]M); ok {
			cfg["outbounds"] = kernel.MergeAppendList(existing, v)
		}
	}

	// endpoints (sing-box 1.11+ wireguard etc.) — append
	if v, ok := custom["endpoints"]; ok {
		if existing, ok := cfg["endpoints"].([]M); ok {
			cfg["endpoints"] = kernel.MergeAppendList(existing, v)
		} else {
			if items := kernel.MergeAppendList(nil, v); len(items) > 0 {
				cfg["endpoints"] = items
			}
		}
	}

	// route — merge sub-fields
	if customRoute, ok := custom["route"]; ok {
		if customRouteMap, ok := customRoute.(map[string]any); ok {
			mergeCustomSingboxRoute(cfg, customRouteMap)
		}
	}
}

func mergeCustomSingboxRoute(cfg M, customRoute map[string]any) {
	route, ok := cfg["route"].(M)
	if !ok {
		route = M{}
		cfg["route"] = route
	}

	// rules — custom rules prepended (so they match before panel rules)
	if v, ok := customRoute["rules"]; ok {
		if existing, ok := route["rules"].([]M); ok {
			route["rules"] = kernel.MergePrependList(existing, v)
		}
	}

	// rule_set — custom rule_sets appended
	if v, ok := customRoute["rule_set"]; ok {
		if existing, ok := route["rule_set"].([]M); ok {
			route["rule_set"] = kernel.MergeAppendList(existing, v)
		} else {
			route["rule_set"] = kernel.MergeAppendList(nil, v)
		}
	}

	// final, auto_detect_interface, default_interface, etc. — custom overrides
	for k, v := range customRoute {
		if k == "rules" || k == "rule_set" {
			continue
		}
		route[k] = v
	}
}

func buildInbound(nc *model.NodeSpec, users []model.UserSpec, tc kernel.TLSCert) M {
	// Dual-stack wildcard by default; honor the panel's listen_ip only when
	// it names a concrete address (the panel sends 0.0.0.0 today, which must
	// NOT downgrade the listener to v4-only).
	listen := "::"
	switch nc.ListenIP {
	case "", "0.0.0.0", "::":
	default:
		listen = nc.ListenIP
	}
	base := M{
		"tag":         nc.Protocol + "-in",
		"listen":      listen,
		"listen_port": nc.ServerPort,
	}

	var inbound M
	switch nc.Protocol {
	case "shadowsocks":
		inbound = buildShadowsocks(base, nc, users)
	case "vmess":
		inbound = buildVMess(base, nc, users, tc)
	case "vless":
		inbound = buildVLESS(base, nc, users, tc)
	case "trojan":
		inbound = buildTrojan(base, nc, users, tc)
	case "hysteria":
		inbound = buildHysteria(base, nc, users, tc)
	case "tuic":
		inbound = buildTUIC(base, nc, users, tc)
	case "anytls":
		inbound = buildAnyTLS(base, nc, users, tc)
	case "naive":
		inbound = buildNaive(base, nc, users, tc)
	case "socks":
		inbound = buildSocks(base, users, nc)
	case "http":
		inbound = buildHTTP(base, nc, users, tc)
	case "mieru":
		inbound = buildMieru(base, nc, users)
	default:
		return nil
	}
	if inbound == nil {
		return nil
	}
	applyGenericPolicy(inbound, nc)
	return inbound
}

// applyGenericPolicy maps the panel's protocol-agnostic policy payload onto
// sing-box ListenOptions, which every inbound embeds: sniff trio + udp_timeout
// for all protocols, and the QUIC subset for the QUIC-based protocols.
func applyGenericPolicy(base M, nc *model.NodeSpec) {
	if nc.Sniff != nil {
		if nc.Sniff.Enable {
			base["sniff"] = true
		}
		if nc.Sniff.RewriteDomain {
			base["sniff_override_destination"] = true
		}
		if nc.Sniff.Timeout > 0 {
			// badoption.Duration unmarshals bare JSON numbers as seconds
			base["sniff_timeout"] = nc.Sniff.Timeout
		}
		if nc.Sniff.TCPPorts != "" || nc.Sniff.UDPPorts != "" {
			nlog.Core().Warn("sing-box inbound sniffing has no port filter (tcpPorts/udpPorts), sniffing applies to all traffic", "protocol", nc.Protocol)
		}
	}

	if nc.UDPIdleTimeout > 0 {
		// UDPTimeoutCompat unmarshals bare JSON numbers as seconds
		base["udp_timeout"] = nc.UDPIdleTimeout
	}

	if nc.Quic != nil && (nc.Protocol == "hysteria" || nc.Protocol == "tuic") {
		if nc.Quic.DisablePathMTUDiscovery {
			base["disable_path_mtu_discovery"] = true
		}
		if nc.Quic.InitStreamReceiveWindow != 0 || nc.Quic.MaxStreamReceiveWindow != 0 ||
			nc.Quic.InitConnReceiveWindow != 0 || nc.Quic.MaxConnReceiveWindow != 0 ||
			nc.Quic.MaxIdleTimeout != 0 || nc.Quic.MaxIncomingStreams != 0 || nc.Quic.DisableStatelessReset {
			nlog.Core().Warn("sing-box does not expose QUIC window/timeout/stream tuning from the panel, ignoring (only disablePathMTUDiscovery applies)", "protocol", nc.Protocol)
		}
	}
}

func buildMieru(base M, nc *model.NodeSpec, users []model.UserSpec) M {
	base["type"] = "mieru"
	if nc.Transport != "" {
		base["transport"] = nc.Transport
	}
	if nc.TrafficPattern != "" {
		base["traffic_pattern"] = nc.TrafficPattern
	}

	userList := make([]M, 0, len(users))
	for _, u := range users {
		userList = append(userList, M{
			"name":     u.UUID,
			"password": u.UUID,
		})
	}
	base["users"] = userList
	return base
}

// ss2022Password renders a Shadowsocks 2022 user key the way sing-box expects:
// base64 of the first Size bytes of the panel UUID string.
func ss2022Password(size int, uuid string) string {
	key := make([]byte, size)
	copy(key, uuid)
	return base64.StdEncoding.EncodeToString(key)
}

func buildShadowsocks(base M, nc *model.NodeSpec, users []model.UserSpec) M {
	base["type"] = "shadowsocks"
	base["method"] = nc.Cipher

	ss2022, isSS2022 := kernel.SS2022Methods[nc.Cipher]

	// sing-shadowsocks server-side iPSK (the users[] form built below) only
	// implements the blake3-aes methods; the chacha20 variant fails inbound
	// creation with "invalid argument". Return nil so the kernel refuses to
	// start with the existing no-inbound guard.
	if isSS2022 && nc.Cipher == "2022-blake3-chacha20-poly1305" {
		nlog.Core().Error("ss2022 chacha20-poly1305 does not support multi-user on sing-box (server iPSK is aes-only); use 2022-blake3-aes-256-gcm instead")
		return nil
	}

	if isSS2022 {
		base["password"] = nc.ServerKey
	}

	userList := make([]M, len(users))
	for i := range users {
		u := &users[i]
		ssPassword := u.UUID
		if isSS2022 {
			ssPassword = ss2022Password(ss2022.Size, u.UUID)
		}
		userList[i] = M{
			"name":     u.UUID,
			"password": ssPassword,
		}
	}
	base["users"] = userList

	if nc.Plugin != "" {
		nlog.Core().Warn("sing-box shadowsocks inbound does not support plugin, ignoring", "plugin", nc.Plugin)
	}

	return base
}

func buildVMess(base M, nc *model.NodeSpec, users []model.UserSpec, tc kernel.TLSCert) M {
	base["type"] = "vmess"

	userList := make([]M, 0, len(users))
	for _, u := range users {
		userList = append(userList, M{
			"name":    u.UUID,
			"uuid":    u.UUID,
			"alterId": 0,
		})
	}
	base["users"] = userList

	applyTransport(base, nc)
	applyProxyProtocol(base, nc)
	applyMultiplex(base, nc)

	if nc.TLS == 2 {
		// sing-box vmess inbound has no REALITY support; silently dropping it
		// produces a plaintext inbound on a node the panel thinks is secured
		nlog.Core().Warn("sing-box vmess does not support Reality (tls=2), inbound will run without TLS; use xray kernel for vmess+Reality")
	} else if nc.TLS == 1 {
		if tls := buildTLSConfig(nc, tc); tls != nil {
			base["tls"] = tls
		}
	}

	return base
}

func buildVLESS(base M, nc *model.NodeSpec, users []model.UserSpec, tc kernel.TLSCert) M {
	if nc.Decryption != "" && nc.Decryption != "none" {
		nlog.Core().Warn("sing-box does not support VLESS encryption (decryption), use xray kernel for this feature")
	}

	base["type"] = "vless"

	userList := make([]M, 0, len(users))
	for _, u := range users {
		user := M{
			"name": u.UUID,
			"uuid": u.UUID,
		}
		if nc.Flow != "" {
			user["flow"] = nc.Flow
		}
		userList = append(userList, user)
	}
	base["users"] = userList

	applyTransport(base, nc)
	applyProxyProtocol(base, nc)
	applyMultiplex(base, nc)

	if nc.TLS == 1 {
		if tls := buildTLSConfig(nc, tc); tls != nil {
			base["tls"] = tls
		}
	} else if nc.TLS == 2 {
		base["tls"] = buildRealityConfig(nc)
	}

	return base
}

func buildTrojan(base M, nc *model.NodeSpec, users []model.UserSpec, tc kernel.TLSCert) M {
	base["type"] = "trojan"

	userList := make([]M, len(users))
	for i := range users {
		u := &users[i]
		userList[i] = M{
			"name":     u.UUID,
			"password": u.UUID,
		}
	}
	base["users"] = userList

	applyTransport(base, nc)
	applyProxyProtocol(base, nc)
	applyMultiplex(base, nc)

	if nc.TLS == 1 {
		if tls := buildTLSConfig(nc, tc); tls != nil {
			base["tls"] = tls
		}
	} else if nc.TLS == 2 {
		base["tls"] = buildRealityConfig(nc)
	}

	// If still no TLS/Reality but cert paths exist, enable TLS (panel may omit tls=1).
	if _, ok := base["tls"]; !ok {
		if tls := buildTLSConfig(nc, tc); tls != nil {
			base["tls"] = tls
		}
	}

	if base["tls"] == nil {
		nlog.Core().Warn("trojan inbound has no TLS (no certificate paths and no Reality); sing-box may refuse to start until cert_mode provides cert/key or Reality is configured")
	}

	return base
}

func buildHysteria(base M, nc *model.NodeSpec, users []model.UserSpec, tc kernel.TLSCert) M {
	if nc.Version == 2 {
		base["type"] = "hysteria2"

		userList := make([]M, 0, len(users))
		for _, u := range users {
			userList = append(userList, M{
				"name":     u.UUID,
				"password": u.UUID,
			})
		}
		base["users"] = userList

		if nc.Obfs != "" {
			base["obfs"] = M{
				"type":     nc.Obfs,
				"password": nc.ObfsPassword,
			}
		}
		applyProxyProtocol(base, nc)
		applyHysteriaPolicy(base, nc)
	} else {
		base["type"] = "hysteria"

		userList := make([]M, 0, len(users))
		for _, u := range users {
			userList = append(userList, M{
				"name":     u.UUID,
				"auth_str": u.UUID,
			})
		}
		base["users"] = userList
		base["up_mbps"] = nc.UpMbps
		base["down_mbps"] = nc.DownMbps

		if nc.UpMbps <= 0 || nc.DownMbps <= 0 {
			nlog.Core().Warn("sing-box hysteria v1 requires positive up_mbps/down_mbps from the panel; inbound may fail to start")
		}

		if nc.Obfs != "" {
			base["obfs"] = nc.Obfs
		}
	}

	tls := buildTLSConfig(nc, tc)
	if tls == nil {
		nlog.Core().Warn("hysteria requires TLS certificate files on disk; configure cert_mode (self, file, http, dns, or content). Sing-box will not start this inbound without tls.")
		return base
	}
	// Hysteria/Hysteria2 uses QUIC and requires ALPN; default to h3 if not set.
	if _, ok := tls["alpn"]; !ok {
		tls["alpn"] = []string{"h3"}
	}
	base["tls"] = tls
	return base
}

// applyHysteriaPolicy maps the panel's hysteria policy payload onto the
// sing-box hysteria2 inbound. Everything sing-box cannot express is surfaced
// as a dropped-field warning, mirroring vmess+Reality / proxy protocol.
func applyHysteriaPolicy(base M, nc *model.NodeSpec) {
	if nc.IgnoreClientBandwidth {
		base["ignore_client_bandwidth"] = true
	}

	if nc.HysteriaCongestion != nil {
		if p := strings.TrimSpace(nc.HysteriaCongestion.BBRProfile); p != "" {
			base["bbr_profile"] = strings.ToLower(p)
		}
		if t := strings.ToLower(strings.TrimSpace(nc.HysteriaCongestion.Type)); t != "" && t != "bbr" {
			// sing-box's hysteria2 congestion is BBR(+Brutal) only; the panel's
			// congestion.type switch has no per-inbound equivalent here.
			nlog.Core().Warn("sing-box hysteria2 does not support congestion.type switching (always BBR), ignoring", "type", nc.HysteriaCongestion.Type)
		}
	}

	if nc.Masquerade != nil {
		if m := buildMasquerade(nc.Masquerade); m != nil {
			base["masquerade"] = m
		}
	}

	if len(nc.Resolver) > 0 {
		nlog.Core().Warn("sing-box does not support per-node resolver from the panel (dns is a global config), ignoring")
	}
	if nc.DisableLossCompensation {
		nlog.Core().Warn("sing-box does not support disable_loss_compensation on hysteria2, ignoring")
	}
	if nc.DisableUDP {
		nlog.Core().Warn("sing-box does not support disable_udp on a single inbound, ignoring; use a route rule if needed")
	}
}

// buildMasquerade translates the panel masquerade object into the sing-box
// hysteria2 masquerade option. Type "404" means default behavior: no
// masquerade key at all.
func buildMasquerade(mc *panel.MasqueradeConfig) M {
	switch strings.ToLower(strings.TrimSpace(mc.Type)) {
	case "", "404":
		return nil
	case "file":
		if mc.File == nil || strings.TrimSpace(mc.File.Dir) == "" {
			nlog.Core().Warn("masquerade type file requires file.dir, dropping masquerade")
			return nil
		}
		return M{"type": "file", "file": M{"directory": mc.File.Dir}}
	case "proxy":
		if mc.Proxy == nil || strings.TrimSpace(mc.Proxy.URL) == "" {
			nlog.Core().Warn("masquerade type proxy requires proxy.url, dropping masquerade")
			return nil
		}
		return M{"type": "proxy", "proxy": M{"url": mc.Proxy.URL, "rewrite_host": mc.Proxy.RewriteHost}}
	case "string":
		if mc.StringConfig == nil || strings.TrimSpace(mc.StringConfig.Content) == "" {
			nlog.Core().Warn("masquerade type string requires string.content, dropping masquerade")
			return nil
		}
		s := M{"content": mc.StringConfig.Content}
		if mc.StringConfig.StatusCode != 0 {
			s["status_code"] = mc.StringConfig.StatusCode
		}
		return M{"type": "string", "string": s}
	default:
		nlog.Core().Warn("masquerade type not supported by sing-box kernel, dropping", "type", mc.Type)
		return nil
	}
}

func buildTUIC(base M, nc *model.NodeSpec, users []model.UserSpec, tc kernel.TLSCert) M {
	base["type"] = "tuic"

	userList := make([]M, 0, len(users))
	for _, u := range users {
		userList = append(userList, M{
			"name":     u.UUID,
			"uuid":     u.UUID,
			"password": u.UUID,
		})
	}
	base["users"] = userList

	if nc.CongestionControl != "" {
		base["congestion_control"] = nc.CongestionControl
	}

	tls := buildTLSConfig(nc, tc)
	if tls == nil {
		nlog.Core().Warn("tuic requires TLS certificate files on disk; configure cert_mode (self, file, http, dns, or content). Sing-box will not start this inbound without tls.")
		return base
	}
	// TUIC requires ALPN for QUIC negotiation; default to h3 if not set by panel.
	if _, ok := tls["alpn"]; !ok {
		tls["alpn"] = []string{"h3"}
	}
	base["tls"] = tls
	return base
}

func buildAnyTLS(base M, nc *model.NodeSpec, users []model.UserSpec, tc kernel.TLSCert) M {
	base["type"] = "anytls"

	userList := make([]M, 0, len(users))
	for _, u := range users {
		userList = append(userList, M{
			"name":     u.UUID,
			"password": u.UUID,
		})
	}
	base["users"] = userList

	if nc.PaddingScheme != "" {
		base["padding_scheme"] = nc.PaddingScheme
	}

	if tls := buildTLSConfig(nc, tc); tls != nil {
		base["tls"] = tls
	} else {
		nlog.Core().Warn("anytls requires TLS certificate files on disk; configure cert_mode (self, file, http, dns, or content). Sing-box will not start this inbound without tls.")
	}
	return base
}

func buildNaive(base M, nc *model.NodeSpec, users []model.UserSpec, tc kernel.TLSCert) M {
	base["type"] = "naive"

	userList := make([]M, 0, len(users))
	for _, u := range users {
		userList = append(userList, M{
			"username": strconv.Itoa(u.ID),
			"password": u.UUID,
		})
	}
	base["users"] = userList

	if nc.TLS == 1 {
		if tls := buildTLSConfig(nc, tc); tls != nil {
			// Naive is an HTTP/2 proxy protocol: without an h2 ALPN the TLS
			// handshake negotiates http/1.1 and the inbound rejects CONNECT.
			// Mirror the hysteria/tuic h3 default when the panel omits or
			// empties alpn.
			base["tls"] = tls
			if !alpnHasValue(tls["alpn"]) {
				tls["alpn"] = []string{"h2"}
			}
		}
	}
	return base
}

func buildSocks(base M, users []model.UserSpec, nc *model.NodeSpec) M {
	base["type"] = "socks"

	// sing-box socks inbound has no TLS option: the panel's tls=1 is silently
	// dropped and the inbound serves plaintext. Surface it like the other
	// dropped panel fields (xray refuses socks outright).
	if nc.TLS == 1 {
		nlog.Core().Warn("sing-box socks inbound does not support TLS; panel tls=1 is ignored and the inbound serves plaintext")
	}

	userList := make([]M, 0, len(users))
	for _, u := range users {
		userList = append(userList, M{
			"username": u.UUID,
			"password": u.UUID,
		})
	}
	base["users"] = userList
	return base
}

func buildHTTP(base M, nc *model.NodeSpec, users []model.UserSpec, tc kernel.TLSCert) M {
	base["type"] = "http"

	userList := make([]M, 0, len(users))
	for _, u := range users {
		userList = append(userList, M{
			"username": u.UUID,
			"password": u.UUID,
		})
	}
	base["users"] = userList

	applyProxyProtocol(base, nc)
	if nc.TLS == 1 {
		if tls := buildTLSConfig(nc, tc); tls != nil {
			base["tls"] = tls
		}
	}
	return base
}

func applyTransport(base M, nc *model.NodeSpec) {
	if nc.Network == "" || nc.Network == "tcp" {
		return
	}

	transport := M{"type": nc.Network}

	// sing-box matches the request path strictly ("" != "/"), so an empty
	// panel path must become "/" or every ws/httpupgrade/h2 handshake 404s.
	ensurePath := func(m M) {
		if v, ok := m["path"]; !ok || v == "" {
			m["path"] = "/"
		}
	}

	if nc.NetworkSettings != nil {
		switch nc.Network {
		case "ws":
			if v, ok := nc.NetworkSettings["path"]; ok {
				transport["path"] = v
			}
			if v, ok := nc.NetworkSettings["headers"]; ok {
				if hm, ok := v.(map[string]any); ok {
					headers := make(M, len(hm)+1)
					for hk, hv := range hm {
						headers[hk] = hv
					}
					transport["headers"] = headers
				} else {
					transport["headers"] = v
				}
			}
			if v, ok := nc.NetworkSettings["host"]; ok {
				// Host header wins over a same-named panel header, matching the xray builder
				if headers, ok := transport["headers"].(map[string]any); ok {
					headers["Host"] = v
				} else {
					transport["headers"] = M{"Host": v}
				}
			}
			if v, ok := nc.NetworkSettings["max_early_data"]; ok {
				transport["max_early_data"] = v
			}
			if v, ok := nc.NetworkSettings["early_data_header_name"]; ok {
				transport["early_data_header_name"] = v
			}
		case "grpc":
			if v, ok := nc.NetworkSettings["serviceName"]; ok {
				transport["service_name"] = v
			} else if v, ok := nc.NetworkSettings["service_name"]; ok {
				transport["service_name"] = v
			}
		case "httpupgrade":
			if v, ok := nc.NetworkSettings["path"]; ok {
				transport["path"] = v
			}
			if v, ok := nc.NetworkSettings["host"]; ok {
				transport["host"] = v
			}
		case "h2", "http":
			transport["type"] = "http"
			if v, ok := nc.NetworkSettings["path"]; ok {
				transport["path"] = v
			}
			if v, ok := nc.NetworkSettings["host"]; ok {
				transport["host"] = v
			}
		}
	}

	// sing-box matches the request path strictly ("" != "/") regardless of
	// whether the panel sent networkSettings at all.
	switch transport["type"] {
	case "ws", "httpupgrade", "http":
		ensurePath(transport)
	}

	base["transport"] = transport
}

// buildTLSConfig returns sing-box inbound TLS options when certificate material
// is available. Returns nil if no TLS material is provided.
func buildTLSConfig(nc *model.NodeSpec, tc kernel.TLSCert) M {
	if !tc.HasCert() {
		return nil
	}

	t := M{"enabled": true}

	serverName := nc.ServerName
	if serverName == "" && nc.Host != "" {
		serverName = nc.Host
	}
	if serverName != "" {
		t["server_name"] = serverName
	}

	if nc.TLSSettings != nil {
		if sn, ok := nc.TLSSettings["server_name"]; ok && sn != "" {
			t["server_name"] = sn
		}
		// A panel that sends "alpn": null must not shadow the protocol default
		// (naive needs h2, QUIC protocols need h3): treat null as absent.
		if alpn, ok := nc.TLSSettings["alpn"]; ok && alpn != nil {
			t["alpn"] = alpn
		}
		// ECH server-side: only key/key_path needed for inbound
		if ech := extractECHInbound(nc.TLSSettings); ech != nil {
			t["ech"] = ech
		}
	}

	t["certificate"] = []string{string(tc.CertPEM)}
	t["key"] = []string{string(tc.KeyPEM)}

	return t
}

func buildRealityConfig(nc *model.NodeSpec) M {
	tls := M{"enabled": true}
	if nc.TLSSettings == nil {
		return tls
	}

	reality := M{"enabled": true}
	var settings struct {
		PrivateKey string `mapstructure:"private_key"`
		ShortID    any    `mapstructure:"short_id"`
		Dest       string `mapstructure:"dest"`
		ServerName string `mapstructure:"server_name"`
		ServerPort int    `mapstructure:"server_port"`
	}

	decoderConfig := &mapstructure.DecoderConfig{
		Metadata:         nil,
		Result:           &settings,
		WeaklyTypedInput: true,
	}
	decoder, _ := mapstructure.NewDecoder(decoderConfig)
	_ = decoder.Decode(nc.TLSSettings)

	if settings.PrivateKey != "" {
		reality["private_key"] = settings.PrivateKey
	}

	switch v := settings.ShortID.(type) {
	case string:
		reality["short_id"] = []string{v}
	case []any:
		ids := make([]string, 0, len(v))
		for _, item := range v {
			ids = append(ids, fmt.Sprintf("%v", item))
		}
		reality["short_id"] = ids
	case []string:
		reality["short_id"] = v
	}

	dest := settings.Dest
	if dest == "" {
		dest = settings.ServerName
	}

	if dest != "" {
		handshake := M{"server": dest, "server_port": 443}
		if parts := strings.SplitN(dest, ":", 2); len(parts) == 2 {
			handshake["server"] = parts[0]
			if p, err := strconv.Atoi(parts[1]); err == nil {
				handshake["server_port"] = p
			}
		} else if settings.ServerPort > 0 {
			handshake["server_port"] = settings.ServerPort
		}
		reality["handshake"] = handshake
		// The handshake target doubles as the REALITY fallback server: every
		// rejected handshake dials it, so log it — an unreachable target shows
		// up client-side as "REALITY: processed invalid connection".
		nlog.Core().Info("reality handshake target",
			"server", handshake["server"], "server_port", handshake["server_port"])
	}

	if settings.ServerName != "" {
		tls["server_name"] = settings.ServerName
	} else if handshake, ok := reality["handshake"].(M); ok {
		// sing-box forks build the SNI whitelist from tls.server_name alone;
		// leaving it empty makes every client SNI mismatch. Fall back to the
		// handshake host (the SNI clients send matches it by construction).
		tls["server_name"] = handshake["server"]
	}

	tls["reality"] = reality
	return tls
}

func applyMultiplex(base M, nc *model.NodeSpec) {
	if nc.Multiplex == nil || !nc.Multiplex.Enabled {
		return
	}

	// sing-box inbound multiplex is enabled/padding/brutal only; protocol and
	// the connection/stream knobs exist on the outbound side alone.
	if nc.Multiplex.Protocol != "" || nc.Multiplex.MaxConnections != 0 || nc.Multiplex.MinStreams != 0 || nc.Multiplex.MaxStreams != 0 {
		nlog.Core().Warn("sing-box inbound multiplex ignores protocol/max_connections/min_streams/max_streams (outbound-only options)", "protocol", nc.Protocol)
	}

	mux := M{
		"enabled": true,
	}
	if nc.Multiplex.Padding {
		mux["padding"] = true
	}

	if nc.Multiplex.Brutal != nil && nc.Multiplex.Brutal.Enabled {
		brutal := M{
			"enabled": true,
		}
		if nc.Multiplex.Brutal.UpMbps > 0 {
			brutal["up_mbps"] = nc.Multiplex.Brutal.UpMbps
		}
		if nc.Multiplex.Brutal.DownMbps > 0 {
			brutal["down_mbps"] = nc.Multiplex.Brutal.DownMbps
		}
		mux["brutal"] = brutal
	}

	base["multiplex"] = mux
}

func applyProxyProtocol(base M, nc *model.NodeSpec) {
	// sing-box has no inbound proxy_protocol option: behind a PROXY-protocol
	// frontend every source IP would be the frontend's (device limits and
	// alive IPs wrong). Surface the dropped panel field like the vmess+Reality
	// case does; the xray kernel honors it.
	if nc.GetProxyProtocol() {
		nlog.Core().Warn("sing-box does not support proxy protocol, ignoring; source IPs will be the frontend's", "protocol", nc.Protocol)
	}
}

// extractECHInbound extracts ECH config for sing-box server (inbound).
// sing-box InboundECHOptions needs: enabled, key (PEM array), key_path.
func extractECHInbound(tlsSettings map[string]interface{}) M {
	echRaw, ok := tlsSettings["ech"]
	if !ok {
		return nil
	}
	echMap, ok := echRaw.(map[string]interface{})
	if !ok {
		return nil
	}
	enabled, _ := echMap["enabled"].(bool)
	if !enabled {
		return nil
	}
	ech := M{"enabled": true}
	hasSource := false
	if key, _ := echMap["key"].(string); key != "" {
		ech["key"] = []string{key} // sing-box expects PEM as-is
		hasSource = true
	}
	if keyPath, _ := echMap["key_path"].(string); keyPath != "" {
		ech["key_path"] = keyPath
		hasSource = true
	}
	if !hasSource {
		nlog.Core().Warn("ECH enabled but no key or key_path provided")
	}
	return ech // let sing-box report a clear error if key is missing
}

// alpnHasValue reports whether a panel-provided ALPN value is usable (a
// non-empty string or list); null and empty lists fall back to the protocol
// default.
func alpnHasValue(v any) bool {
	switch alpn := v.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(alpn) != ""
	case []string:
		return len(alpn) > 0
	case []any:
		return len(alpn) > 0
	default:
		return true
	}
}
