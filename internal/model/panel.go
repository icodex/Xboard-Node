package model

import (
	"strings"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/nlog"
	"github.com/cedar2025/xboard-node/internal/panel"
)

// sanitizePanelDNSEnv drops endpoint overrides from a panel-supplied dns_env.
// Keys such as NAMECHEAP_API_ENDPOINT or OVH_ENDPOINT are full URLs, so a
// panel could aim the node's DNS-01 requests (and the provider credentials
// they carry) at any host, including an internal address. Only credential
// values are legitimate panel input; endpoints stay an operator decision.
func sanitizePanelDNSEnv(env map[string]string) map[string]string {
	if len(env) == 0 {
		return env
	}
	out := make(map[string]string, len(env))
	for key, value := range env {
		upper := strings.ToUpper(strings.TrimSpace(key))
		if strings.HasSuffix(upper, "_ENDPOINT") || strings.HasSuffix(upper, "_URL") {
			nlog.Core().Warn("ignoring panel dns_env endpoint override", "key", key)
			continue
		}
		out[key] = value
	}
	return out
}

func NodeSpecFromPanel(nc *panel.NodeConfig) *NodeSpec {
	if nc == nil {
		return nil
	}

	var certCfg *config.CertConfig
	if nc.CertConfig != nil {
		certCfg = &config.CertConfig{
			CertMode:    nc.CertConfig.CertMode,
			Domain:      nc.CertConfig.Domain,
			Email:       nc.CertConfig.Email,
			DNSProvider: nc.CertConfig.DNSProvider,
			DNSEnv:      sanitizePanelDNSEnv(nc.CertConfig.DNSEnv),
			HTTPPort:    nc.CertConfig.HTTPPort,
			CertFile:    nc.CertConfig.CertFile,
			KeyFile:     nc.CertConfig.KeyFile,
			CertContent: nc.CertConfig.CertContent,
			KeyContent:  nc.CertConfig.KeyContent,
		}
	}

	var multiplex *MultiplexConfig
	if nc.Multiplex != nil {
		multiplex = &MultiplexConfig{
			Enabled:        nc.Multiplex.Enabled,
			Protocol:       nc.Multiplex.Protocol,
			MaxConnections: nc.Multiplex.MaxConnections,
			MinStreams:     nc.Multiplex.MinStreams,
			MaxStreams:     nc.Multiplex.MaxStreams,
			Padding:        nc.Multiplex.Padding,
		}
		if nc.Multiplex.Brutal != nil {
			multiplex.Brutal = &BrutalConfig{
				Enabled:  nc.Multiplex.Brutal.Enabled,
				UpMbps:   nc.Multiplex.Brutal.UpMbps,
				DownMbps: nc.Multiplex.Brutal.DownMbps,
			}
		}
	}

	routes := make([]RouteRule, 0, len(nc.Routes))
	for _, route := range nc.Routes {
		routes = append(routes, RouteRule{
			ID:          route.ID,
			Match:       cloneStringSlice(route.Match),
			Action:      route.Action,
			ActionValue: route.ActionValue,
		})
	}

	outbounds := make([]OutboundConfig, 0, len(nc.CustomOutbounds))
	for _, outbound := range nc.CustomOutbounds {
		outbounds = append(outbounds, OutboundConfig{
			Tag:            outbound.Tag,
			Protocol:       outbound.Protocol,
			Settings:       cloneAnyMap(outbound.Settings),
			StreamSettings: cloneAnyMap(outbound.StreamSettings),
			Mux:            cloneAnyMap(outbound.Mux),
			ProxyTag:       outbound.ProxyTag,
		})
	}

	customRouteRules := make([]CustomRouteRule, 0, len(nc.CustomRouteRules))
	for _, rule := range nc.CustomRouteRules {
		customRouteRules = append(customRouteRules, CustomRouteRule{
			Name:     rule.Name,
			Disabled: rule.Disabled,
			Match: RouteMatch{
				Domains:        cloneStringSlice(rule.Match.Domains),
				DomainSuffixes: cloneStringSlice(rule.Match.DomainSuffixes),
				IPCIDRs:        cloneStringSlice(rule.Match.IPCIDRs),
				Ports:          cloneStringSlice(rule.Match.Ports),
				Networks:       cloneStringSlice(rule.Match.Networks),
				SourceCIDRs:    cloneStringSlice(rule.Match.SourceCIDRs),
				SourcePorts:    cloneStringSlice(rule.Match.SourcePorts),
			},
			Action: RouteAction{
				Type:   rule.Action.Type,
				Target: rule.Action.Target,
			},
		})
	}

	return &NodeSpec{
		Protocol:                nc.Protocol,
		ListenIP:                nc.ListenIP,
		ServerPort:              nc.ServerPort,
		Network:                 nc.Network,
		NetworkSettings:         cloneAnyMap(nc.NetworkSettings),
		Routes:                  routes,
		KernelType:              nc.KernelType,
		KernelLogLevel:          nc.KernelLogLevel,
		CustomOutbounds:         outbounds,
		CustomRoutes:            cloneMapSlice(nc.CustomRoutes),
		CustomRouteRules:        customRouteRules,
		CertConfig:              certCfg,
		AutoTLS:                 nc.AutoTLS,
		Domain:                  nc.Domain,
		Cipher:                  nc.Cipher,
		Plugin:                  nc.Plugin,
		PluginOpt:               nc.PluginOpt,
		ServerKey:               nc.ServerKey,
		TLS:                     nc.TLS,
		Flow:                    nc.Flow,
		Decryption:              nc.Decryption,
		TLSSettings:             cloneAnyMap(nc.TLSSettings),
		Host:                    nc.Host,
		ServerName:              nc.ServerName,
		Version:                 nc.Version,
		UpMbps:                  nc.UpMbps,
		DownMbps:                nc.DownMbps,
		Obfs:                    nc.Obfs,
		ObfsPassword:            nc.ObfsPassword,
		Sniff:                   nc.Sniff,
		Masquerade:              nc.Masquerade,
		Quic:                    nc.Quic,
		HysteriaCongestion:      nc.HysteriaCongestion,
		Resolver:                cloneAnyMap(nc.Resolver),
		DisableUDP:              nc.DisableUDP,
		UDPIdleTimeout:          nc.UDPIdleTimeout,
		IgnoreClientBandwidth:   nc.IgnoreClientBandwidth,
		DisableLossCompensation: nc.DisableLossCompensation,
		CongestionControl:       nc.CongestionControl,
		PaddingScheme:           string(nc.PaddingScheme),
		Transport:               nc.Transport,
		TrafficPattern:          nc.TrafficPattern,
		Multiplex:               multiplex,
		AcceptProxyProtocol:     nc.AcceptProxyProtocol,
	}
}

func NodeSpecFromPanelValidated(nc *panel.NodeConfig, kcfg config.KernelConfig) (*NodeSpec, error) {
	spec := NodeSpecFromPanel(nc)
	if err := ValidateNodeSpec(spec, kcfg); err != nil {
		return nil, err
	}
	return spec, nil
}

func UserSpecsFromPanel(users []panel.User) []UserSpec {
	if users == nil {
		return nil
	}
	out := make([]UserSpec, 0, len(users))
	for _, user := range users {
		out = append(out, UserSpec{ID: user.ID, UUID: user.UUID, SpeedLimit: user.SpeedLimit, DeviceLimit: user.DeviceLimit})
	}
	return out
}
