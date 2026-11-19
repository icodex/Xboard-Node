package model

func OutboundSupportMatrix() map[string]KernelOutboundSupport {
	return map[string]KernelOutboundSupport{
		"xray": {
			Protocols: []string{
				"vmess",
				"vless",
				"trojan",
				"shadowsocks",
				"socks",
				"http",
				"wireguard",
			},
		},
		"singbox": {
			Protocols: []string{
				"vmess",
				"vless",
				"trojan",
				"shadowsocks",
				"socks",
				"http",
				"wireguard",
				"tuic",
				"hysteria2",
				"anytls",
				"naive",
				"mieru",
			},
		},
	}
}

type KernelOutboundSupport struct {
	Protocols []string
}
