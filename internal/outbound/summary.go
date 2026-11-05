package outbound

// Summary returns the log-safe shape of a rendered outbound: endpoint, TLS and
// transport choices, chain and mux — never credentials. Used at debug level so
// a misrendered outbound is visible without dumping keys.
func (c *Canonical) Summary() map[string]any {
	if c == nil {
		return nil
	}
	summary := map[string]any{
		"protocol": c.Protocol,
	}
	if c.Server != "" {
		summary["server"] = c.Server
	}
	if c.ServerPort != 0 {
		summary["server_port"] = c.ServerPort
	}
	if c.Flow != "" {
		summary["flow"] = c.Flow
	}
	transport := "tcp"
	security := "none"
	if c.Stream != nil {
		if c.Stream.Network != "" {
			transport = c.Stream.Network
		}
		if c.Stream.Security != "" {
			security = c.Stream.Security
		}
		if c.Stream.ServerName != "" {
			summary["server_name"] = c.Stream.ServerName
		}
		if c.Stream.Fingerprint != "" {
			summary["fingerprint"] = c.Stream.Fingerprint
		}
		if c.Stream.DialerProxy != "" {
			summary["dialer_proxy"] = c.Stream.DialerProxy
		}
	}
	summary["transport"] = transport
	summary["security"] = security
	if c.Multiplex != nil && c.Multiplex.Enabled {
		mux := map[string]any{"enabled": true}
		if c.Multiplex.Protocol != "" {
			mux["protocol"] = c.Multiplex.Protocol
		}
		summary["multiplex"] = mux
	}
	if c.ProxyTag != "" {
		summary["detour"] = c.ProxyTag
	}
	return summary
}
