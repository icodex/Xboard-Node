package service

import (
	"context"
	"testing"

	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/tracker"
)

type deviceSink struct {
	delivered bool
	calls     int
}

func (s *deviceSink) Report(controlplane.ReportPayload) error { return nil }
func (s *deviceSink) ReportDevices(controlplane.PushClient, map[int][]string) bool {
	s.calls++
	return s.delivered
}
func (s *deviceSink) SupportsReporting() bool     { return true }
func (s *deviceSink) SupportsDeviceReports() bool { return true }

type connectedPush struct{}

func (connectedPush) Run(context.Context)                    {}
func (connectedPush) IsConnected() bool                      { return true }
func (connectedPush) SendDeviceReport(map[int][]string) bool { return true }

// FlushAliveIPs consumes the snapshot cursor. If the enqueue is dropped (full
// write channel, link down between the IsConnected check and the send), the
// service must mark the snapshot stale so the next tick resends it.
func TestSendDeviceBatchRetriesAfterUndeliveredEnqueue(t *testing.T) {
	svc := newTestService(&fakeKernel{running: true})
	svc.tracker = tracker.New()
	svc.tracker.Process(nil, map[int]map[string]bool{1: {"1.2.3.4": true}}, 1)
	svc.wsClient = connectedPush{}
	sink := &deviceSink{}
	svc.sink = sink

	svc.sendDeviceBatch() // delivery fails
	if sink.calls != 1 {
		t.Fatalf("sink calls = %d, want 1", sink.calls)
	}

	sink.delivered = true
	svc.sendDeviceBatch() // stale marker forces a resend
	if sink.calls != 2 {
		t.Fatalf("failed delivery must force a resend, sink calls = %d", sink.calls)
	}

	svc.sendDeviceBatch() // unchanged snapshot: no report
	if sink.calls != 2 {
		t.Fatalf("unchanged snapshot must not resend, sink calls = %d", sink.calls)
	}
}
