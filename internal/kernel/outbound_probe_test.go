package kernel

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/model"
)

func vlessOutbound(tag, address string, port int) model.OutboundConfig {
	return model.OutboundConfig{
		Tag:      tag,
		Protocol: "vless",
		Settings: map[string]any{
			"address": address,
			"port":    float64(port),
			"id":      "211ed558-90f0-4f32-ba5b-d11c1007e2bf",
		},
	}
}

func TestProbeCustomOutbounds_ReachableAndUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	// A closed port on the same host: bound, then released.
	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen closed: %v", err)
	}
	closedHost, closedPortStr, _ := net.SplitHostPort(closedLn.Addr().String())
	closedPort, _ := strconv.Atoi(closedPortStr)
	closedLn.Close()

	outbounds := []model.OutboundConfig{
		vlessOutbound("alive", host, port),
		vlessOutbound("dead", closedHost, closedPort),
	}

	failed := ProbeCustomOutbounds(outbounds, 2*time.Second)
	if len(failed) != 1 {
		t.Fatalf("want exactly the dead outbound, got %v", failed)
	}
	if failed[0].Tag != "dead" || failed[0].Protocol != "vless" {
		t.Fatalf("unexpected result: %+v", failed[0])
	}
	if failed[0].Err == nil {
		t.Fatal("expected a dial error")
	}
	if failed[0].Endpoint != net.JoinHostPort(closedHost, closedPortStr) {
		t.Fatalf("endpoint: got %q", failed[0].Endpoint)
	}
}

func TestProbeCustomOutbounds_SkipsUDPAndIncomplete(t *testing.T) {
	outbounds := []model.OutboundConfig{
		{
			Tag:      "quic",
			Protocol: "tuic",
			Settings: map[string]any{"address": "127.0.0.1", "port": float64(1), "uuid": "u", "password": "p"},
		},
		{
			Tag:      "wg",
			Protocol: "wireguard",
			Settings: map[string]any{"private_key": "a", "peer_public_key": "b", "address": "127.0.0.1", "server": "127.0.0.1", "server_port": float64(1)},
		},
		{
			// no endpoint at all
			Tag:      "empty",
			Protocol: "vless",
			Settings: map[string]any{"id": "u"},
		},
	}
	if failed := ProbeCustomOutbounds(outbounds, time.Second); len(failed) != 0 {
		t.Fatalf("UDP/incomplete outbounds must be skipped, got %v", failed)
	}

	if failed := ProbeCustomOutbounds(nil, time.Second); failed != nil {
		t.Fatalf("nil outbounds: got %v", failed)
	}
}
