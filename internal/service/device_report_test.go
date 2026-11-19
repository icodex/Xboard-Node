package service

import (
	"context"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
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

// Shutdown must cancel the cert worker scope and join workers before the
// manager is stopped, otherwise a late worker could re-arm ACME.
func TestShutdownWorkersCancelsAndJoinsCertWorker(t *testing.T) {
	svc := newTestService(&fakeKernel{running: true})
	svc.shutdownWait = 2 * time.Second

	certCtx, cancel := context.WithCancel(context.Background())
	svc.certCtx, svc.certCancel = certCtx, cancel

	wsCtx, wsCancel := context.WithCancel(context.Background())
	svc.wsCancel = wsCancel

	done := make(chan struct{})
	svc.certWorkers.Add(1)
	go func() {
		<-certCtx.Done()
		svc.certWorkers.Add(-1)
		close(done)
	}()

	svc.shutdownWorkers()

	select {
	case <-done:
	default:
		t.Fatal("shutdown must cancel the cert worker scope")
	}
	if got := svc.certWorkers.Load(); got != 0 {
		t.Fatalf("cert workers still running after shutdown: %d", got)
	}
	select {
	case <-wsCtx.Done():
	default:
		t.Fatal("shutdown must cancel the WS client scope")
	}
}

// A worker that ignores cancellation must not hold shutdown past the bound.
func TestShutdownWorkersIsBounded(t *testing.T) {
	svc := newTestService(&fakeKernel{running: true})
	svc.shutdownWait = 20 * time.Millisecond
	svc.pushWait = 50 * time.Millisecond
	svc.pushInFlight.Add(1)
	defer svc.pushInFlight.Add(-1)

	start := time.Now()
	svc.shutdownWorkers()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("shutdown waited too long: %v", elapsed)
	}
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Fatalf("shutdown did not wait for the in-flight worker: %v", elapsed)
	}
}

type blockingSink struct {
	entered chan struct{}
	release chan struct{}
}

func (s *blockingSink) Report(controlplane.ReportPayload) error {
	if s.entered != nil {
		s.entered <- struct{}{}
	}
	if s.release != nil {
		<-s.release
	}
	return nil
}
func (s *blockingSink) ReportDevices(controlplane.PushClient, map[int][]string) bool {
	return false
}
func (s *blockingSink) SupportsReporting() bool     { return true }
func (s *blockingSink) SupportsDeviceReports() bool { return false }

// Async reports must be counted and joined: a failed one restores traffic into
// the tracker that the final snapshot then flushes.
func TestPushReportAsyncIsCountedAndJoined(t *testing.T) {
	svc := newTestService(&fakeKernel{running: true})
	svc.cfg = &config.Config{}
	svc.source = &fakeSource{}
	svc.tracker = tracker.New()
	svc.tracker.Process(nil, map[int]map[string]bool{1: {"1.2.3.4": true}}, 1)

	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	svc.sink = &blockingSink{entered: entered, release: release}
	svc.pushWait = time.Second

	svc.pushReportAsync()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("async report did not start")
	}
	if got := svc.pushInFlight.Load(); got != 1 {
		t.Fatalf("pushInFlight = %d, want 1", got)
	}

	done := make(chan struct{})
	go func() {
		svc.waitInFlightPushes()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("wait returned while a report was still in flight")
	case <-time.After(50 * time.Millisecond):
	}

	close(release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("wait did not return after the report finished")
	}
	if got := svc.pushInFlight.Load(); got != 0 {
		t.Fatalf("pushInFlight = %d after completion", got)
	}
}

// The final report must not exceed the shutdown budget.
func TestFinalReportIsBounded(t *testing.T) {
	svc := newTestService(&fakeKernel{running: true})
	svc.cfg = &config.Config{}
	svc.source = &fakeSource{}
	svc.tracker = tracker.New()
	release := make(chan struct{})
	svc.sink = &blockingSink{release: release}
	svc.finalReportWait = 50 * time.Millisecond
	defer close(release)

	start := time.Now()
	svc.pushReportSyncBounded()
	elapsed := time.Since(start)
	if elapsed > time.Second {
		t.Fatalf("final report waited too long: %v", elapsed)
	}
	if elapsed < 40*time.Millisecond {
		t.Fatalf("final report did not wait for the sink: %v", elapsed)
	}
}
