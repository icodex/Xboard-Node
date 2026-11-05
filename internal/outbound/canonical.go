// Package outbound normalizes a panel-provided custom outbound and renders it
// for the concrete kernel. The panel stores outbounds in Xray-native form
// (settings + streamSettings + mux); sing-box uses a different flat layout.
package outbound

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Canonical is a single-server outbound independent of any kernel layout.
type Canonical struct {
	Protocol   string
	Server     string
	ServerPort int
	ServerCnt  int

	UUID     string
	Flow     string
	AlterID  int
	Security string
	Password string
	Username string
	Method   string
	Email    string
	// Encryption is the Xray VLESS user field ("none"); sing-box has no
	// equivalent and drops it.
	Encryption string

	Wireguard *Wireguard
	Stream    *Stream
	Multiplex *Multiplex
	ProxyTag  string

	// nestedXray marks settings already authored as vnext/servers/peers, so the
	// Xray renderer can pass them through without lossy remapping.
	nestedXray bool

	rawSettings map[string]any
	rawStream   map[string]any
	rawMux      map[string]any

	// nativeExtras holds sing-box-native fields not mapped to Canonical
	// (packet_encoding, congestion_control, ...) so they survive rendering.
	nativeExtras map[string]any

	// nativeSingbox marks settings authored in sing-box-native form; the
	// sing-box renderer passes them through so exotic TLS options survive.
	nativeSingbox bool
}

// Wireguard holds the subset shared by the Xray and sing-box wireguard outbounds.
type Wireguard struct {
	PrivateKey    string
	LocalAddress  []string
	PeerPublicKey string
	PreSharedKey  string
	Server        string
	ServerPort    int
	Reserved      []int
	MTU           int
	KeepAlive     int
}

// Stream is the transport/TLS layer in kernel-neutral form.
type Stream struct {
	Network  string // raw/tcp, ws, grpc, httpupgrade, http/h2, xhttp/splithttp, kcp, quic
	Security string // none, tls, reality

	ServerName       string
	Insecure         bool
	ALPN             []string
	Fingerprint      string
	RealityPublicKey string
	RealityShortID   string
	RealitySpiderX   string

	WS          *WSOptions
	GRPC        *GRPCOptions
	HTTP        *HTTPOptions
	HTTPUpgrade *HTTPUpgradeOptions
	DialerProxy string
}

type WSOptions struct {
	Path                string
	Headers             map[string]string
	MaxEarlyData        int
	EarlyDataHeaderName string
}

type GRPCOptions struct {
	ServiceName         string
	PermitWithoutStream bool
}

type HTTPOptions struct {
	Host    []string
	Path    string
	Method  string
	Headers map[string]string
}

type HTTPUpgradeOptions struct {
	Host    string
	Path    string
	Headers map[string]string
}

// Multiplex is the mux layer in kernel-neutral form.
type Multiplex struct {
	Enabled        bool
	Protocol       string
	MaxConnections int
	MinStreams     int
	MaxStreams     int
	Padding        bool
}

// Parse reads a panel outbound (Xray-native, with flat shorthand accepted) into
// the canonical form. It never fails on missing credentials; ValidateForKernel
// owns that. It only reports structs it cannot interpret at all.
func Parse(protocol string, settings, streamSettings, mux map[string]any, proxyTag string) (*Canonical, error) {
	c := &Canonical{
		Protocol:    normalizeProtocol(protocol),
		ProxyTag:    strings.TrimSpace(proxyTag),
		rawSettings: settings,
		rawStream:   streamSettings,
		rawMux:      mux,
	}
	if len(settings) == 0 {
		return c, nil
	}

	if c.Protocol == "wireguard" {
		if err := c.parseWireguard(settings); err != nil {
			return nil, err
		}
		if looksSingboxNative(settings, streamSettings, mux) {
			c.nativeSingbox = true
			c.nativeExtras = nativeExtras(settings)
		}
		c.Stream = parseStream(streamSettings, nil)
		c.Multiplex = parseMultiplex(mux, nil)
		return c, nil
	}
	if vnext := mapSlice(settings["vnext"]); len(vnext) > 0 {
		c.ServerCnt = len(vnext)
		entry := vnext[0]
		c.Server = stringValue(entry, "address", "server")
		c.ServerPort, _ = intValue(entry, "port", "server_port")
		if users := mapSlice(entry["users"]); len(users) > 0 {
			user := users[0]
			c.UUID = stringValue(user, "id", "uuid")
			c.Flow = stringValue(user, "flow")
			c.AlterID, _ = intValue(user, "alterId", "alter_id")
			c.Security = stringValue(user, "security")
			c.Email = stringValue(user, "email")
			c.Encryption = stringValue(user, "encryption")
			if c.Password == "" {
				c.Password = stringValue(user, "password", "pass")
			}
		}
		c.nestedXray = true
	} else if servers := mapSlice(settings["servers"]); len(servers) > 0 {
		c.ServerCnt = len(servers)
		entry := servers[0]
		c.Server = stringValue(entry, "address", "server")
		c.ServerPort, _ = intValue(entry, "port", "server_port")
		c.Password = stringValue(entry, "password")
		c.Method = stringValue(entry, "method")
		if users := mapSlice(entry["users"]); len(users) > 0 {
			user := users[0]
			c.Username = stringValue(user, "user", "username")
			c.Password = firstNonEmpty(c.Password, stringValue(user, "pass", "password"))
			c.Email = stringValue(user, "email")
		}
		c.nestedXray = true
	} else {
		c.Server = stringValue(settings, "address", "server")
		c.ServerPort, _ = intValue(settings, "port", "server_port")
		c.UUID = stringValue(settings, "id", "uuid")
		c.Flow = stringValue(settings, "flow")
		c.AlterID, _ = intValue(settings, "alterId", "alter_id")
		c.Security = stringValue(settings, "security")
		c.Email = stringValue(settings, "email")
		c.Encryption = stringValue(settings, "encryption")
		c.Password = stringValue(settings, "password")
		c.Method = stringValue(settings, "method")
		c.Username = stringValue(settings, "username", "user")
		c.ServerCnt = 1
	}

	if looksSingboxNative(settings, streamSettings, mux) {
		c.nativeSingbox = true
		c.nativeExtras = nativeExtras(settings)
	}

	c.Stream = parseStream(streamSettings, settings)
	c.Multiplex = parseMultiplex(mux, settings)
	return c, nil
}

func normalizeProtocol(protocol string) string {
	p := strings.ToLower(strings.TrimSpace(protocol))
	switch p {
	case "hysteria":
		return "hysteria2"
	}
	return p
}

func (c *Canonical) parseWireguard(settings map[string]any) error {
	wg := &Wireguard{
		PrivateKey:    firstNonEmpty(stringValue(settings, "private_key"), stringValue(settings, "secretKey")),
		LocalAddress:  stringSlice(firstValue(settings, "local_address", "address")),
		PeerPublicKey: stringValue(settings, "peer_public_key"),
		PreSharedKey:  stringValue(settings, "pre_shared_key"),
		MTU:           intValueDefault(settings, 0, "mtu"),
	}
	if v, ok := intValue(settings, "keep_alive"); ok {
		wg.KeepAlive = v
	}
	if peers := mapSlice(settings["peers"]); len(peers) > 0 {
		peer := peers[0]
		wg.PeerPublicKey = firstNonEmpty(wg.PeerPublicKey, stringValue(peer, "publicKey", "public_key"))
		wg.PreSharedKey = firstNonEmpty(wg.PreSharedKey, stringValue(peer, "preSharedKey", "pre_shared_key"))
		wg.KeepAlive = firstNonZero(wg.KeepAlive, intValueDefault(peer, 0, "keepAlive", "keep_alive"))
		if endpoint := stringValue(peer, "endpoint", "server"); endpoint != "" {
			host, port, err := net.SplitHostPort(endpoint)
			if err != nil {
				return fmt.Errorf("wireguard peer endpoint %q must be host:port", endpoint)
			}
			wg.Server = host
			parsed, err := strconv.Atoi(port)
			if err != nil {
				return fmt.Errorf("wireguard peer endpoint %q has an invalid port", endpoint)
			}
			wg.ServerPort = parsed
		} else {
			wg.Server = stringValue(peer, "address", "server")
			wg.ServerPort, _ = intValue(peer, "port", "server_port")
		}
	}
	wg.Server = firstNonEmpty(wg.Server, stringValue(settings, "server"))
	if wg.Server == "" {
		// Xray's wireguard settings use "address" for the local interface and
		// the peer carries the endpoint, so only fall back when no peer existed.
		if peers := mapSlice(settings["peers"]); len(peers) == 0 {
			wg.Server = stringValue(settings, "address")
		}
	}
	wg.ServerPort = firstNonZero(wg.ServerPort, intValueDefault(settings, 0, "server_port", "port"))
	wg.Reserved = intSlice(settings["reserved"])
	c.Wireguard = wg
	c.Server = wg.Server
	c.ServerPort = wg.ServerPort
	c.ServerCnt = 1
	return nil
}

func parseStream(xrayStream, nativeSettings map[string]any) *Stream {
	if len(xrayStream) > 0 {
		return parseXrayStream(xrayStream)
	}
	if len(nativeSettings) > 0 {
		if s := parseNativeStream(nativeSettings); s != nil {
			return s
		}
	}
	return nil
}

func parseXrayStream(raw map[string]any) *Stream {
	s := &Stream{
		Network:  strings.ToLower(stringValue(raw, "network")),
		Security: strings.ToLower(stringValue(raw, "security")),
	}
	if tlsSettings := asMap(raw["tlsSettings"]); tlsSettings != nil {
		s.ServerName = stringValue(tlsSettings, "serverName", "server_name")
		s.Insecure = boolValue(tlsSettings, "allowInsecure", "insecure")
		s.ALPN = stringSlice(tlsSettings["alpn"])
		s.Fingerprint = stringValue(tlsSettings, "fingerprint")
	}
	if reality := asMap(raw["realitySettings"]); reality != nil {
		s.ServerName = firstNonEmpty(stringValue(reality, "serverName", "server_name"), s.ServerName)
		s.Fingerprint = firstNonEmpty(stringValue(reality, "fingerprint"), s.Fingerprint)
		s.RealityPublicKey = stringValue(reality, "publicKey", "public_key")
		s.RealityShortID = firstNonEmpty(stringValue(reality, "shortId", "short_id"), "")
		s.RealitySpiderX = firstNonEmpty(stringValue(reality, "spiderX", "spider_x"), "")
	}
	if sockopt := asMap(raw["sockopt"]); sockopt != nil {
		s.DialerProxy = stringValue(sockopt, "dialerProxy", "dialer_proxy")
	}
	switch s.Network {
	case "ws":
		ws := asMap(raw["wsSettings"])
		if ws != nil {
			s.WS = &WSOptions{
				Path:                stringValue(ws, "path"),
				Headers:             stringMap(ws["headers"]),
				MaxEarlyData:        intValueDefault(ws, 0, "maxEarlyData", "max_early_data"),
				EarlyDataHeaderName: stringValue(ws, "earlyDataHeaderName", "early_data_header_name"),
			}
		}
	case "grpc":
		grpc := asMap(raw["grpcSettings"])
		if grpc != nil {
			s.GRPC = &GRPCOptions{
				ServiceName:         stringValue(grpc, "serviceName", "service_name"),
				PermitWithoutStream: boolValue(grpc, "permitWithoutStream", "permit_without_stream"),
			}
		}
	case "http", "h2":
		httpSettings := asMap(raw["httpSettings"])
		if httpSettings != nil {
			s.HTTP = &HTTPOptions{
				Host:    stringSlice(firstValue(httpSettings, "host", "hosts")),
				Path:    stringValue(httpSettings, "path"),
				Method:  stringValue(httpSettings, "method"),
				Headers: stringMap(httpSettings["headers"]),
			}
		}
	case "httpupgrade":
		hu := asMap(raw["httpupgradeSettings"])
		if hu != nil {
			s.HTTPUpgrade = &HTTPUpgradeOptions{
				Host:    stringValue(hu, "host"),
				Path:    stringValue(hu, "path"),
				Headers: stringMap(hu["headers"]),
			}
		}
	}
	return s
}

func parseNativeStream(settings map[string]any) *Stream {
	tlsMap := asMap(settings["tls"])
	transport := asMap(settings["transport"])
	if tlsMap == nil && transport == nil {
		return nil
	}
	s := &Stream{}
	if tlsMap != nil {
		if boolValue(tlsMap, "enabled") {
			s.Security = "tls"
		}
		s.ServerName = stringValue(tlsMap, "server_name", "serverName")
		s.Insecure = boolValue(tlsMap, "insecure")
		s.ALPN = stringSlice(tlsMap["alpn"])
		if utls := asMap(tlsMap["utls"]); utls != nil {
			s.Fingerprint = stringValue(utls, "fingerprint")
		}
		if reality := asMap(tlsMap["reality"]); reality != nil {
			if boolValue(reality, "enabled") {
				s.Security = "reality"
			}
			s.RealityPublicKey = stringValue(reality, "public_key", "publicKey")
			s.RealityShortID = stringValue(reality, "short_id", "shortId")
		}
	}
	if transport != nil {
		s.Network = strings.ToLower(stringValue(transport, "type"))
		switch s.Network {
		case "ws":
			s.WS = &WSOptions{
				Path:                stringValue(transport, "path"),
				Headers:             stringMap(transport["headers"]),
				MaxEarlyData:        intValueDefault(transport, 0, "max_early_data"),
				EarlyDataHeaderName: stringValue(transport, "early_data_header_name"),
			}
		case "grpc":
			s.GRPC = &GRPCOptions{
				ServiceName:         stringValue(transport, "service_name"),
				PermitWithoutStream: boolValue(transport, "permit_without_stream"),
			}
		case "http":
			s.HTTP = &HTTPOptions{
				Host:    stringSlice(transport["host"]),
				Path:    stringValue(transport, "path"),
				Method:  stringValue(transport, "method"),
				Headers: stringMap(transport["headers"]),
			}
		case "httpupgrade":
			s.HTTPUpgrade = &HTTPUpgradeOptions{
				Host:    stringValue(transport, "host"),
				Path:    stringValue(transport, "path"),
				Headers: stringMap(transport["headers"]),
			}
		}
	}
	return s
}

func parseMultiplex(xrayMux, nativeSettings map[string]any) *Multiplex {
	if len(xrayMux) > 0 {
		return &Multiplex{
			Enabled:        boolValue(xrayMux, "enabled"),
			Protocol:       stringValue(xrayMux, "protocol"),
			MaxConnections: intValueDefault(xrayMux, 0, "concurrency", "max_connections"),
			MinStreams:     intValueDefault(xrayMux, 0, "min_streams"),
			MaxStreams:     intValueDefault(xrayMux, 0, "max_streams"),
			Padding:        boolValue(xrayMux, "padding"),
		}
	}
	if nativeSettings != nil {
		if m := asMap(nativeSettings["multiplex"]); m != nil {
			return &Multiplex{
				Enabled:        boolValue(m, "enabled"),
				Protocol:       stringValue(m, "protocol"),
				MaxConnections: intValueDefault(m, 0, "max_connections"),
				MinStreams:     intValueDefault(m, 0, "min_streams"),
				MaxStreams:     intValueDefault(m, 0, "max_streams"),
				Padding:        boolValue(m, "padding"),
			}
		}
	}
	return nil
}

func looksSingboxNative(settings, streamSettings, mux map[string]any) bool {
	if len(streamSettings) > 0 || len(mux) > 0 {
		return false
	}
	if hasAny(settings, "vnext", "servers", "address", "id", "port", "secretKey", "peers", "streamSettings") {
		return false
	}
	return hasAny(settings, "server", "server_port", "tls", "transport", "multiplex")
}

func nativeExtras(settings map[string]any) map[string]any {
	consumed := map[string]bool{
		"tag": true, "type": true, "protocol": true, "detour": true,
		"server": true, "server_port": true, "address": true, "port": true,
		"uuid": true, "id": true, "flow": true, "alter_id": true, "alterId": true,
		"password": true, "method": true, "username": true, "user": true, "pass": true,
		"security": true, "email": true,
		"tls": true, "transport": true, "multiplex": true,
	}
	extras := make(map[string]any, len(settings))
	for k, v := range settings {
		if !consumed[k] {
			extras[k] = v
		}
	}
	return extras
}

// --- helpers ----------------------------------------------------------------

func asMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return nil
}

func mapSlice(v any) []map[string]any {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func stringValue(m map[string]any, keys ...string) string {
	for _, key := range keys {
		if m == nil {
			return ""
		}
		v, ok := m[key]
		if !ok || v == nil {
			continue
		}
		switch value := v.(type) {
		case string:
			if strings.TrimSpace(value) != "" {
				return value
			}
		default:
			s := strings.TrimSpace(fmt.Sprintf("%v", value))
			if s != "" && s != "<nil>" {
				return s
			}
		}
	}
	return ""
}

func intValue(m map[string]any, keys ...string) (int, bool) {
	for _, key := range keys {
		v, ok := m[key]
		if !ok || v == nil {
			continue
		}
		switch value := v.(type) {
		case int:
			return value, true
		case int32:
			return int(value), true
		case int64:
			return int(value), true
		case float64:
			return int(value), true
		case float32:
			return int(value), true
		case string:
			n, err := strconv.Atoi(strings.TrimSpace(value))
			if err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

func intValueDefault(m map[string]any, fallback int, keys ...string) int {
	if v, ok := intValue(m, keys...); ok {
		return v
	}
	return fallback
}

func boolValue(m map[string]any, keys ...string) bool {
	for _, key := range keys {
		v, ok := m[key]
		if !ok || v == nil {
			continue
		}
		switch value := v.(type) {
		case bool:
			return value
		case string:
			parsed, err := strconv.ParseBool(strings.TrimSpace(value))
			if err == nil {
				return parsed
			}
		}
	}
	return false
}

func stringSlice(v any) []string {
	switch value := v.(type) {
	case []string:
		return value
	case []any:
		out := make([]string, 0, len(value))
		for _, item := range value {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if strings.TrimSpace(value) == "" {
			return nil
		}
		return strings.Split(value, ",")
	}
	return nil
}

func intSlice(v any) []int {
	switch value := v.(type) {
	case []int:
		return value
	case []any:
		out := make([]int, 0, len(value))
		for _, item := range value {
			switch n := item.(type) {
			case int:
				out = append(out, n)
			case float64:
				out = append(out, int(n))
			case string:
				if parsed, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
					out = append(out, parsed)
				}
			}
		}
		return out
	}
	return nil
}

func stringMap(v any) map[string]string {
	raw := asMap(v)
	if raw == nil {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, item := range raw {
		if s, ok := item.(string); ok {
			out[k] = s
		}
	}
	return out
}

func firstValue(m map[string]any, keys ...string) any {
	for _, key := range keys {
		if v, ok := m[key]; ok {
			return v
		}
	}
	return nil
}

func hasAny(m map[string]any, keys ...string) bool {
	for _, key := range keys {
		if _, ok := m[key]; ok {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func firstNonZero(values ...int) int {
	for _, v := range values {
		if v != 0 {
			return v
		}
	}
	return 0
}
