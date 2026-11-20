package service

import (
	"net"
	"strconv"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/monitor"
)

// A rejected config must reach the panel instead of only the node log: the node
// otherwise shows as "offline" with no reason.
func TestConfigErrorSurfacesInMetrics(t *testing.T) {
	s := newTestService(&fakeKernel{})
	s.cfg = &config.Config{Panel: config.PanelConfig{NodeID: 7}}
	s.source = &fakeSource{}

	msg := "xray kernel does not implement Hysteria2 obfs \"salamander\""
	s.setConfigError(msg)
	if got := s.configError(); got != msg {
		t.Fatalf("configError() = %q, want %q", got, msg)
	}
	if got := s.buildMetrics(monitor.Status{})["config_error"]; got != msg {
		t.Fatalf("metrics[config_error] = %v, want %q", got, msg)
	}

	// A successful start clears it: the node is serving again.
	s.setConfigError("")
	if got, ok := s.buildMetrics(monitor.Status{})["config_error"]; ok {
		t.Fatalf("stale config_error reported after recovery: %v", got)
	}
}

func TestProbeListenPortDetectsForeignListener(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	spec := &model.NodeSpec{Protocol: "vmess", ListenIP: "127.0.0.1", ServerPort: port}

	if err := probeListenPort(spec); err == nil {
		t.Fatal("port held by another listener must be reported as unavailable")
	}

	ln.Close()
	// The kernel binds wildcard addresses: probing the specific IP again must
	// succeed once the listener is gone.
	if err := probeListenPort(spec); err != nil {
		t.Fatalf("freed port must probe as available, got %v", err)
	}
}

func TestProbeListenPortUsesUDPForQUICProtocols(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	port := conn.LocalAddr().(*net.UDPAddr).Port

	hy := &model.NodeSpec{Protocol: "hysteria", ListenIP: "127.0.0.1", ServerPort: port}
	if err := probeListenPort(hy); err == nil {
		t.Fatal("UDP port held by another listener must be reported as unavailable")
	}

	// The same port number on TCP is free: a TCP probe would have said "ok",
	// proving the probe follows the protocol's transport.
	vmess := &model.NodeSpec{Protocol: "vmess", ListenIP: "127.0.0.1", ServerPort: port}
	if err := probeListenPort(vmess); err != nil {
		t.Fatalf("tcp probe on a udp-only conflict must pass, got %v", err)
	}
}

func TestProbeListenPortAcceptsFreePort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	spec := &model.NodeSpec{Protocol: "trojan", ListenIP: "127.0.0.1", ServerPort: port}
	if err := probeListenPort(spec); err != nil {
		t.Fatalf("free port %s must probe as available, got %v", strconv.Itoa(port), err)
	}
}
