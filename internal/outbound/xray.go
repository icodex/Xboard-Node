package outbound

import (
	"fmt"
	"net"
	"strconv"
)

// RenderXray converts the canonical outbound into the nested Xray outbound
// layout. Inputs already authored in native Xray form are passed through so no
// native field is lost.
func (c *Canonical) RenderXray(tag string) (map[string]any, error) {
	m := map[string]any{
		"protocol": c.Protocol,
		"tag":      tag,
	}

	if c.Protocol == "wireguard" {
		settings, err := c.xrayWireguardSettings()
		if err != nil {
			return nil, err
		}
		m["settings"] = settings
	} else if c.nestedXray {
		m["settings"] = cloneAnyMap(c.rawSettings)
	} else {
		settings, err := c.xraySettings()
		if err != nil {
			return nil, err
		}
		if len(settings) > 0 {
			m["settings"] = settings
		}
	}

	if len(c.rawStream) > 0 {
		m["streamSettings"] = cloneAnyMap(c.rawStream)
	} else if stream := c.xrayStream(); stream != nil {
		m["streamSettings"] = stream
	}
	if len(c.rawMux) > 0 {
		m["mux"] = cloneAnyMap(c.rawMux)
	} else if mux := c.xrayMux(); mux != nil {
		m["mux"] = mux
	}
	if c.ProxyTag != "" {
		m["proxySettings"] = map[string]any{"tag": c.ProxyTag}
	}
	return m, nil
}

func (c *Canonical) xraySettings() (map[string]any, error) {
	switch c.Protocol {
	case "vless", "vmess":
		if c.Server == "" || c.ServerPort == 0 || c.UUID == "" {
			return nil, fmt.Errorf("%s requires address, port and id", c.Protocol)
		}
		user := map[string]any{
			"id": c.UUID,
		}
		if c.Protocol == "vless" {
			if c.Flow != "" {
				user["flow"] = c.Flow
			}
			if c.Encryption != "" {
				user["encryption"] = c.Encryption
			}
		} else {
			user["alterId"] = c.AlterID
			security := c.Security
			if security == "" {
				security = "auto"
			}
			user["security"] = security
		}
		if c.Email != "" {
			user["email"] = c.Email
		}
		return map[string]any{
			"vnext": []any{
				map[string]any{
					"address": c.Server,
					"port":    c.ServerPort,
					"users":   []any{user},
				},
			},
		}, nil
	case "trojan":
		if c.Server == "" || c.ServerPort == 0 || c.Password == "" {
			return nil, fmt.Errorf("trojan requires address, port and password")
		}
		return map[string]any{
			"servers": []any{
				map[string]any{
					"address":  c.Server,
					"port":     c.ServerPort,
					"password": c.Password,
					"email":    c.Email,
				},
			},
		}, nil
	case "shadowsocks":
		if c.Server == "" || c.ServerPort == 0 || c.Method == "" || c.Password == "" {
			return nil, fmt.Errorf("shadowsocks requires address, port, method and password")
		}
		return map[string]any{
			"servers": []any{
				map[string]any{
					"address":  c.Server,
					"port":     c.ServerPort,
					"method":   c.Method,
					"password": c.Password,
				},
			},
		}, nil
	case "socks", "http":
		if c.Server == "" || c.ServerPort == 0 {
			return nil, fmt.Errorf("%s requires address and port", c.Protocol)
		}
		server := map[string]any{
			"address": c.Server,
			"port":    c.ServerPort,
		}
		if c.Username != "" || c.Password != "" {
			server["users"] = []any{
				map[string]any{
					"user": c.Username,
					"pass": c.Password,
				},
			}
		}
		return map[string]any{"servers": []any{server}}, nil
	default:
		return nil, fmt.Errorf("protocol %q is not supported by the xray kernel", c.Protocol)
	}
}

func (c *Canonical) xrayWireguardSettings() (map[string]any, error) {
	wg := c.Wireguard
	if wg == nil {
		return nil, fmt.Errorf("wireguard settings are missing")
	}
	if wg.PrivateKey == "" || wg.PeerPublicKey == "" {
		return nil, fmt.Errorf("wireguard requires private_key and peer_public_key")
	}
	if wg.Server == "" || wg.ServerPort == 0 {
		return nil, fmt.Errorf("wireguard requires a peer endpoint")
	}
	peer := map[string]any{
		"publicKey": wg.PeerPublicKey,
		"endpoint":  net.JoinHostPort(wg.Server, strconv.Itoa(wg.ServerPort)),
		"allowedIPs": []string{
			"0.0.0.0/0",
			"::/0",
		},
	}
	if wg.PreSharedKey != "" {
		peer["preSharedKey"] = wg.PreSharedKey
	}
	if wg.KeepAlive > 0 {
		peer["keepAlive"] = wg.KeepAlive
	}
	settings := map[string]any{
		"secretKey": wg.PrivateKey,
		"peers":     []any{peer},
	}
	if len(wg.LocalAddress) > 0 {
		settings["address"] = wg.LocalAddress
	}
	if wg.MTU > 0 {
		settings["mtu"] = wg.MTU
	}
	return settings, nil
}

func (c *Canonical) xrayStream() map[string]any {
	if c.Stream == nil {
		return nil
	}
	stream := c.Stream
	network := stream.Network
	if network == "" {
		network = "tcp"
	}
	security := stream.Security
	if security == "" {
		security = "none"
	}
	out := map[string]any{
		"network":  network,
		"security": security,
	}
	switch security {
	case "tls":
		tlsSettings := map[string]any{}
		if stream.ServerName != "" {
			tlsSettings["serverName"] = stream.ServerName
		}
		if stream.Insecure {
			tlsSettings["allowInsecure"] = true
		}
		if len(stream.ALPN) > 0 {
			tlsSettings["alpn"] = stream.ALPN
		}
		if stream.Fingerprint != "" {
			tlsSettings["fingerprint"] = stream.Fingerprint
		}
		out["tlsSettings"] = tlsSettings
	case "reality":
		reality := map[string]any{
			"show":        false,
			"publicKey":   stream.RealityPublicKey,
			"fingerprint": stream.Fingerprint,
		}
		if stream.ServerName != "" {
			reality["serverName"] = stream.ServerName
		}
		if stream.RealityShortID != "" {
			reality["shortId"] = stream.RealityShortID
		}
		if stream.RealitySpiderX != "" {
			reality["spiderX"] = stream.RealitySpiderX
		}
		out["realitySettings"] = reality
	}
	switch network {
	case "ws":
		ws := map[string]any{}
		if stream.WS != nil {
			if stream.WS.Path != "" {
				ws["path"] = stream.WS.Path
			}
			if len(stream.WS.Headers) > 0 {
				ws["headers"] = stream.WS.Headers
			}
			if stream.WS.MaxEarlyData > 0 {
				ws["maxEarlyData"] = stream.WS.MaxEarlyData
			}
			if stream.WS.EarlyDataHeaderName != "" {
				ws["earlyDataHeaderName"] = stream.WS.EarlyDataHeaderName
			}
		}
		out["wsSettings"] = ws
	case "grpc":
		grpc := map[string]any{}
		if stream.GRPC != nil {
			if stream.GRPC.ServiceName != "" {
				grpc["serviceName"] = stream.GRPC.ServiceName
			}
			if stream.GRPC.PermitWithoutStream {
				grpc["permitWithoutStream"] = true
			}
		}
		out["grpcSettings"] = grpc
	case "http", "h2":
		httpSettings := map[string]any{}
		if stream.HTTP != nil {
			switch len(stream.HTTP.Host) {
			case 0:
			case 1:
				httpSettings["host"] = stream.HTTP.Host[0]
			default:
				httpSettings["host"] = stream.HTTP.Host
			}
			if stream.HTTP.Path != "" {
				httpSettings["path"] = stream.HTTP.Path
			}
			if stream.HTTP.Method != "" {
				httpSettings["method"] = stream.HTTP.Method
			}
			if len(stream.HTTP.Headers) > 0 {
				httpSettings["headers"] = stream.HTTP.Headers
			}
		}
		out["httpSettings"] = httpSettings
	case "httpupgrade":
		hu := map[string]any{}
		if stream.HTTPUpgrade != nil {
			if stream.HTTPUpgrade.Host != "" {
				hu["host"] = stream.HTTPUpgrade.Host
			}
			if stream.HTTPUpgrade.Path != "" {
				hu["path"] = stream.HTTPUpgrade.Path
			}
			if len(stream.HTTPUpgrade.Headers) > 0 {
				hu["headers"] = stream.HTTPUpgrade.Headers
			}
		}
		out["httpupgradeSettings"] = hu
	}
	if stream.DialerProxy != "" {
		out["sockopt"] = map[string]any{"dialerProxy": stream.DialerProxy}
	}
	return out
}

func (c *Canonical) xrayMux() map[string]any {
	if c.Multiplex == nil || !c.Multiplex.Enabled {
		return nil
	}
	mux := map[string]any{"enabled": true}
	if c.Multiplex.MaxConnections > 0 {
		mux["concurrency"] = c.Multiplex.MaxConnections
	}
	if c.Multiplex.Protocol != "" {
		mux["protocol"] = c.Multiplex.Protocol
	}
	return mux
}

func cloneAnyMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
