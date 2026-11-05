package kernel

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/nlog"
	ob "github.com/cedar2025/xboard-node/internal/outbound"
)

// LogRenderedOutbound emits the credential-free shape of a custom outbound at
// debug level so a misrendered endpoint/transport/TLS is visible without
// dumping keys.
func LogRenderedOutbound(co model.OutboundConfig) {
	canonical, err := ob.Parse(co.Protocol, co.Settings, co.StreamSettings, co.Mux, co.ProxyTag)
	if err != nil || canonical == nil {
		return
	}
	nlog.Core().Debug("custom outbound rendered", "tag", co.Tag, "summary", canonical.Summary())
}

// udpOutboundProtocols never speak plain TCP: probing them would report a
// false failure on a perfectly healthy QUIC/WireGuard endpoint.
var udpOutboundProtocols = map[string]bool{
	"wireguard": true,
	"hysteria":  true,
	"hysteria2": true,
	"tuic":      true,
	"mieru":     true,
}

// OutboundProbeResult reports one custom outbound whose TCP endpoint did not
// answer.
type OutboundProbeResult struct {
	Tag      string
	Protocol string
	Endpoint string
	Err      error
}

// ProbeCustomOutbounds dials every TCP-based custom outbound endpoint
// concurrently and returns the ones that did not answer. It never blocks
// kernel start and never returns an error: an unreachable upstream is a
// configuration/network problem to surface, not a reason to refuse to run.
func ProbeCustomOutbounds(outbounds []model.OutboundConfig, timeout time.Duration) []OutboundProbeResult {
	if len(outbounds) == 0 {
		return nil
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	type target struct {
		tag, protocol, endpoint string
	}
	var targets []target
	for _, co := range outbounds {
		protocol := co.Protocol
		canonical, err := ob.Parse(protocol, co.Settings, co.StreamSettings, co.Mux, co.ProxyTag)
		if err != nil || canonical == nil {
			continue
		}
		protocol = canonical.Protocol
		if udpOutboundProtocols[protocol] {
			continue
		}
		if canonical.Server == "" || canonical.ServerPort == 0 {
			continue
		}
		targets = append(targets, target{
			tag:      co.Tag,
			protocol: protocol,
			endpoint: net.JoinHostPort(canonical.Server, strconv.Itoa(canonical.ServerPort)),
		})
	}
	if len(targets) == 0 {
		return nil
	}

	results := make([]OutboundProbeResult, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t target) {
			defer wg.Done()
			results[i] = OutboundProbeResult{Tag: t.tag, Protocol: t.protocol, Endpoint: t.endpoint}
			conn, err := net.DialTimeout("tcp", t.endpoint, timeout)
			if err != nil {
				results[i].Err = fmt.Errorf("%w", err)
				return
			}
			_ = conn.Close()
		}(i, t)
	}
	wg.Wait()

	failed := make([]OutboundProbeResult, 0, len(results))
	for _, r := range results {
		if r.Err != nil {
			failed = append(failed, r)
		}
	}
	return failed
}
