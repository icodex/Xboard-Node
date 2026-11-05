package outbound

import (
	"fmt"
	"strings"
)

var singboxUnsupportedNetworks = map[string]bool{
	"xhttp":     true,
	"splithttp": true,
	"kcp":       true,
	"mkcp":      true,
	"quic":      true,
}

// The pinned xray-core fork removed h2/http and quic transports
// (infra/conf/transport_internet.go returns PrintRemovedFeatureError).
var xrayUnsupportedNetworks = map[string]bool{
	"h2":   true,
	"http": true,
	"quic": true,
}

var singboxOnlyProtocols = map[string]bool{
	"tuic":      true,
	"hysteria2": true,
	"anytls":    true,
	"naive":     true,
	"mieru":     true,
}

// ValidateForKernel reports whether the outbound can be rendered for the given
// kernel. It runs during panel config validation, before any kernel start, so
// shape errors never turn into a kernel crash/reload loop.
func ValidateForKernel(c *Canonical, kernelType string) error {
	if c == nil {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(kernelType)) {
	case "singbox":
		return validateSingbox(c)
	case "xray":
		return validateXray(c)
	}
	return nil
}

func validateSingbox(c *Canonical) error {
	if c.ServerCnt > 1 {
		return fmt.Errorf("settings has %d servers; sing-box outbounds support exactly one", c.ServerCnt)
	}
	if c.Protocol == "wireguard" {
		wg := c.Wireguard
		if wg == nil {
			return fmt.Errorf("wireguard settings are missing")
		}
		if wg.PrivateKey == "" {
			return fmt.Errorf("wireguard requires private_key")
		}
		if wg.PeerPublicKey == "" {
			return fmt.Errorf("wireguard requires peer_public_key")
		}
		if wg.Server == "" || wg.ServerPort == 0 {
			return fmt.Errorf("wireguard requires a peer endpoint")
		}
		return validateStream(c, "singbox")
	}
	if err := validateEndpoint(c.Server, c.ServerPort, c.Protocol); err != nil {
		return err
	}
	switch c.Protocol {
	case "vless", "vmess":
		if c.UUID == "" {
			return fmt.Errorf("%s requires id", c.Protocol)
		}
	case "trojan":
		if c.Password == "" {
			return fmt.Errorf("trojan requires password")
		}
	case "shadowsocks":
		if c.Method == "" || c.Password == "" {
			return fmt.Errorf("shadowsocks requires method and password")
		}
	case "socks", "http":
		// address and port already checked above
	default:
		if !singboxOnlyProtocols[c.Protocol] {
			return fmt.Errorf("protocol %q is not supported by the sing-box kernel", c.Protocol)
		}
	}
	return validateStream(c, "singbox")
}

func validateXray(c *Canonical) error {
	if !c.nestedXray {
		if c.Protocol == "wireguard" {
			wg := c.Wireguard
			if wg == nil || wg.PrivateKey == "" || wg.PeerPublicKey == "" {
				return fmt.Errorf("wireguard requires private_key and peer_public_key")
			}
			if wg.Server == "" || wg.ServerPort == 0 {
				return fmt.Errorf("wireguard requires a peer endpoint")
			}
		} else {
			if err := validateEndpoint(c.Server, c.ServerPort, c.Protocol); err != nil {
				return err
			}
			switch c.Protocol {
			case "vless", "vmess":
				if c.UUID == "" {
					return fmt.Errorf("%s requires id", c.Protocol)
				}
			case "trojan":
				if c.Password == "" {
					return fmt.Errorf("trojan requires password")
				}
			case "shadowsocks":
				if c.Method == "" || c.Password == "" {
					return fmt.Errorf("shadowsocks requires method and password")
				}
			case "socks", "http":
				// address and port already checked above
			default:
				return fmt.Errorf("protocol %q is not supported by the xray kernel", c.Protocol)
			}
		}
	} else if singboxOnlyProtocols[c.Protocol] {
		return fmt.Errorf("protocol %q is not supported by the xray kernel", c.Protocol)
	}
	return validateStream(c, "xray")
}

func validateEndpoint(server string, port int, label string) error {
	if strings.TrimSpace(server) == "" {
		return fmt.Errorf("%s requires address", label)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("%s requires port between 1 and 65535", label)
	}
	return nil
}

func validateStream(c *Canonical, kernel string) error {
	if c.Stream == nil {
		return nil
	}
	stream := c.Stream
	network := strings.ToLower(strings.TrimSpace(stream.Network))
	security := strings.ToLower(strings.TrimSpace(stream.Security))

	switch kernel {
	case "singbox":
		if singboxUnsupportedNetworks[network] {
			return fmt.Errorf("streamSettings.network %q is not supported by the sing-box kernel; use kernel xray", network)
		}
		switch security {
		case "", "none", "tls":
		case "reality":
			if stream.RealityPublicKey == "" {
				return fmt.Errorf("reality requires publicKey")
			}
			if stream.ServerName == "" {
				return fmt.Errorf("reality requires serverName")
			}
		default:
			return fmt.Errorf("streamSettings.security %q is not supported by the sing-box kernel", security)
		}
		if c.Protocol == "vless" && strings.Contains(strings.ToLower(c.Flow), "vision") &&
			security != "tls" && security != "reality" {
			return fmt.Errorf("vless flow %q requires tls or reality", c.Flow)
		}
	case "xray":
		if xrayUnsupportedNetworks[network] {
			return fmt.Errorf("streamSettings.network %q is not supported by the xray kernel (removed upstream); use sing-box kernel", network)
		}
		if security == "reality" && !c.nestedXray && stream.RealityPublicKey == "" {
			return fmt.Errorf("reality requires publicKey")
		}
	}
	return nil
}
