package outbound

import "fmt"

// RenderSingbox converts the canonical outbound into the flat sing-box
// outbound layout.
func (c *Canonical) RenderSingbox(tag string) (map[string]any, error) {
	if c.nativeSingbox {
		m := cloneAnyMap(c.rawSettings)
		delete(m, "type")
		delete(m, "tag")
		delete(m, "protocol")
		m["type"] = c.Protocol
		m["tag"] = tag
		if c.ProxyTag != "" {
			m["detour"] = c.ProxyTag
		}
		return m, nil
	}
	if c.Protocol == "wireguard" {
		return c.renderWireguardSingbox(tag)
	}

	m := map[string]any{
		"type": c.Protocol,
		"tag":  tag,
	}
	for k, v := range c.nativeExtras {
		m[k] = v
	}

	switch c.Protocol {
	case "vless":
		if c.Server == "" || c.ServerPort == 0 || c.UUID == "" {
			return nil, fmt.Errorf("vless requires address, port and id")
		}
		m["server"] = c.Server
		m["server_port"] = c.ServerPort
		m["uuid"] = c.UUID
		if c.Flow != "" {
			m["flow"] = c.Flow
		}
	case "vmess":
		if c.Server == "" || c.ServerPort == 0 || c.UUID == "" {
			return nil, fmt.Errorf("vmess requires address, port and id")
		}
		m["server"] = c.Server
		m["server_port"] = c.ServerPort
		m["uuid"] = c.UUID
		security := c.Security
		if security == "" {
			security = "auto"
		}
		m["security"] = security
		if c.AlterID > 0 {
			m["alter_id"] = c.AlterID
		}
	case "trojan":
		if c.Server == "" || c.ServerPort == 0 || c.Password == "" {
			return nil, fmt.Errorf("trojan requires address, port and password")
		}
		m["server"] = c.Server
		m["server_port"] = c.ServerPort
		m["password"] = c.Password
	case "shadowsocks":
		if c.Server == "" || c.ServerPort == 0 || c.Method == "" || c.Password == "" {
			return nil, fmt.Errorf("shadowsocks requires address, port, method and password")
		}
		m["server"] = c.Server
		m["server_port"] = c.ServerPort
		m["method"] = c.Method
		m["password"] = c.Password
	case "socks", "http":
		if c.Server == "" || c.ServerPort == 0 {
			return nil, fmt.Errorf("%s requires address and port", c.Protocol)
		}
		m["server"] = c.Server
		m["server_port"] = c.ServerPort
		if c.Protocol == "socks" {
			m["version"] = "5"
		}
		if c.Username != "" {
			m["username"] = c.Username
		}
		if c.Password != "" {
			m["password"] = c.Password
		}
	default:
		// sing-box-only protocols (tuic, hysteria2, anytls, naive, mieru):
		// native settings pass through.
		if c.Server == "" || c.ServerPort == 0 {
			return nil, fmt.Errorf("%s requires server and server_port", c.Protocol)
		}
		m["server"] = c.Server
		m["server_port"] = c.ServerPort
	}

	if tls := c.singboxTLS(); tls != nil {
		m["tls"] = tls
	}
	if transport := c.singboxTransport(); transport != nil {
		m["transport"] = transport
	}
	if c.Stream != nil && c.Stream.DialerProxy != "" {
		m["detour"] = c.Stream.DialerProxy
	}
	if c.Multiplex != nil && c.Multiplex.Enabled {
		multiplex := map[string]any{"enabled": true}
		protocol := c.Multiplex.Protocol
		if protocol == "" {
			protocol = "smux"
		}
		multiplex["protocol"] = protocol
		if c.Multiplex.MaxConnections > 0 {
			multiplex["max_connections"] = c.Multiplex.MaxConnections
		}
		if c.Multiplex.MinStreams > 0 {
			multiplex["min_streams"] = c.Multiplex.MinStreams
		}
		if c.Multiplex.MaxStreams > 0 {
			multiplex["max_streams"] = c.Multiplex.MaxStreams
		}
		if c.Multiplex.Padding {
			multiplex["padding"] = true
		}
		m["multiplex"] = multiplex
	}
	if c.ProxyTag != "" {
		m["detour"] = c.ProxyTag
	}
	return m, nil
}

func (c *Canonical) renderWireguardSingbox(tag string) (map[string]any, error) {
	wg := c.Wireguard
	if wg == nil {
		return nil, fmt.Errorf("wireguard settings are missing")
	}
	m := map[string]any{
		"type": "wireguard",
		"tag":  tag,
	}
	if wg.Server != "" {
		m["server"] = wg.Server
	}
	if wg.ServerPort != 0 {
		m["server_port"] = wg.ServerPort
	}
	if len(wg.LocalAddress) > 0 {
		m["local_address"] = wg.LocalAddress
	}
	if wg.PrivateKey != "" {
		m["private_key"] = wg.PrivateKey
	}
	if wg.PeerPublicKey != "" {
		m["peer_public_key"] = wg.PeerPublicKey
	}
	if wg.PreSharedKey != "" {
		m["pre_shared_key"] = wg.PreSharedKey
	}
	if len(wg.Reserved) > 0 {
		m["reserved"] = wg.Reserved
	}
	if wg.MTU != 0 {
		m["mtu"] = wg.MTU
	}
	if c.ProxyTag != "" {
		m["detour"] = c.ProxyTag
	}
	return m, nil
}

func (c *Canonical) singboxTLS() map[string]any {
	if c.Stream == nil || c.Stream.Security == "" || c.Stream.Security == "none" {
		return nil
	}
	tls := map[string]any{"enabled": true}
	if c.Stream.ServerName != "" {
		tls["server_name"] = c.Stream.ServerName
	}
	if c.Stream.Insecure {
		tls["insecure"] = true
	}
	if len(c.Stream.ALPN) > 0 {
		tls["alpn"] = c.Stream.ALPN
	}
	fingerprint := c.Stream.Fingerprint
	if fingerprint == "" && c.Stream.Security == "reality" {
		// Xray defaults REALITY to the chrome uTLS fingerprint; sing-box
		// requires uTLS for REALITY.
		fingerprint = "chrome"
	}
	if fingerprint != "" {
		tls["utls"] = map[string]any{
			"enabled":     true,
			"fingerprint": fingerprint,
		}
	}
	if c.Stream.Security == "reality" {
		reality := map[string]any{"enabled": true}
		if c.Stream.RealityPublicKey != "" {
			reality["public_key"] = c.Stream.RealityPublicKey
		}
		if c.Stream.RealityShortID != "" {
			reality["short_id"] = c.Stream.RealityShortID
		}
		tls["reality"] = reality
	}
	return tls
}

func (c *Canonical) singboxTransport() map[string]any {
	if c.Stream == nil {
		return nil
	}
	switch c.Stream.Network {
	case "", "tcp", "raw":
		return nil
	case "ws":
		transport := map[string]any{"type": "ws"}
		if c.Stream.WS != nil {
			if c.Stream.WS.Path != "" {
				transport["path"] = c.Stream.WS.Path
			}
			if len(c.Stream.WS.Headers) > 0 {
				transport["headers"] = c.Stream.WS.Headers
			}
			if c.Stream.WS.MaxEarlyData > 0 {
				transport["max_early_data"] = c.Stream.WS.MaxEarlyData
			}
			if c.Stream.WS.EarlyDataHeaderName != "" {
				transport["early_data_header_name"] = c.Stream.WS.EarlyDataHeaderName
			}
		}
		return transport
	case "grpc":
		transport := map[string]any{"type": "grpc"}
		if c.Stream.GRPC != nil {
			if c.Stream.GRPC.ServiceName != "" {
				transport["service_name"] = c.Stream.GRPC.ServiceName
			}
			if c.Stream.GRPC.PermitWithoutStream {
				transport["permit_without_stream"] = true
			}
		}
		return transport
	case "httpupgrade":
		transport := map[string]any{"type": "httpupgrade"}
		if c.Stream.HTTPUpgrade != nil {
			if c.Stream.HTTPUpgrade.Host != "" {
				transport["host"] = c.Stream.HTTPUpgrade.Host
			}
			if c.Stream.HTTPUpgrade.Path != "" {
				transport["path"] = c.Stream.HTTPUpgrade.Path
			}
			if len(c.Stream.HTTPUpgrade.Headers) > 0 {
				transport["headers"] = c.Stream.HTTPUpgrade.Headers
			}
		}
		return transport
	case "http", "h2":
		transport := map[string]any{"type": "http"}
		if c.Stream.HTTP != nil {
			if len(c.Stream.HTTP.Host) > 0 {
				transport["host"] = c.Stream.HTTP.Host
			}
			if c.Stream.HTTP.Path != "" {
				transport["path"] = c.Stream.HTTP.Path
			}
			if c.Stream.HTTP.Method != "" {
				transport["method"] = c.Stream.HTTP.Method
			}
			if len(c.Stream.HTTP.Headers) > 0 {
				transport["headers"] = c.Stream.HTTP.Headers
			}
		}
		return transport
	}
	return nil
}
