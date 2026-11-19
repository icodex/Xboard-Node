package service

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/model"
)

// fakeSource is a minimal control plane Source for reconciliation tests.
type fakeSource struct {
	polls  atomic.Int32
	pollFn func(context.Context) (controlplane.Snapshot, error)
}

func (f *fakeSource) Initial(context.Context, func() map[string]interface{}, chan<- controlplane.Event, chan<- controlplane.StatusChange) (controlplane.Bootstrap, error) {
	return controlplane.Bootstrap{}, nil
}

func (f *fakeSource) Poll(ctx context.Context) (controlplane.Snapshot, error) {
	f.polls.Add(1)
	return f.pollFn(ctx)
}

func (f *fakeSource) Discover(context.Context, func() map[string]interface{}, chan<- controlplane.Event, chan<- controlplane.StatusChange) (controlplane.PushClient, error) {
	return nil, nil
}

func (f *fakeSource) Metrics() controlplane.APIMetrics { return controlplane.APIMetrics{} }
func (f *fakeSource) SupportsPolling() bool            { return true }
func (f *fakeSource) SupportsDiscovery() bool          { return false }

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func takePullResult(t *testing.T, svc *Service) pullResult {
	t.Helper()
	select {
	case result := <-svc.pullResults:
		return result
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for a poll result")
		return pullResult{}
	}
}

// A failed resync poll used to consume the pending flag forever: the CAS in
// requestWSResync never fired again and the WS-connected path skipped polling.
func TestResyncSurvivesFailedPoll(t *testing.T) {
	svc := newTestService(&fakeKernel{running: true})
	svc.pullResults = make(chan pullResult, 1)

	var fail atomic.Bool
	fail.Store(true)
	src := &fakeSource{pollFn: func(context.Context) (controlplane.Snapshot, error) {
		if fail.Load() {
			return controlplane.Snapshot{}, errors.New("panel down")
		}
		return controlplane.Snapshot{Users: []model.UserSpec{{ID: 1, UUID: "u1"}}}, nil
	}}
	svc.source = src

	svc.requestWSResync(context.Background(), "test")
	waitUntil(t, "the first poll", func() bool { return src.polls.Load() == 1 })
	waitUntil(t, "the first poll to finish", func() bool { return !svc.pullActive.Load() })
	if !svc.wsResyncPending.Load() {
		t.Fatal("a failed poll must keep the resync pending")
	}

	// A later request must advance the generation instead of being dropped by
	// the old CAS guard.
	gen := svc.resyncGen.Load()
	svc.requestWSResync(context.Background(), "retry")
	if got := svc.resyncGen.Load(); got != gen+1 {
		t.Fatalf("resync generation did not advance: %d -> %d", gen, got)
	}
	waitUntil(t, "the backoff-skipped retry", func() bool { return !svc.pullActive.Load() })

	// The pull ticker retries once the panel is healthy (skip counter cleared
	// here because the test does not run the ticker loop).
	fail.Store(false)
	svc.pullBackoff.onSuccess()
	svc.pullViaAPIAsync(context.Background())
	svc.applyPullResult(context.Background(), takePullResult(t, svc))

	if svc.wsResyncPending.Load() {
		t.Fatal("a poll that satisfies the request must clear the pending flag")
	}
}

// A snapshot fetched before a WS push must not be applied afterwards: it would
// re-enable users the panel just removed.
func TestStalePollDoesNotRollBackPushedUsers(t *testing.T) {
	svc := newTestService(&fakeKernel{running: true})
	svc.pullResults = make(chan pullResult, 1)

	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	src := &fakeSource{pollFn: func(context.Context) (controlplane.Snapshot, error) {
		entered <- struct{}{}
		<-release
		return controlplane.Snapshot{Users: []model.UserSpec{{ID: 1, UUID: "u1"}}}, nil
	}}
	svc.source = src

	svc.pullViaAPIAsync(context.Background())
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("poll did not start")
	}

	// Newer state arrives over the WS while the snapshot is in flight.
	svc.handleWSEvent(context.Background(), controlplane.Event{
		Type:  controlplane.EventSyncUsers,
		Users: []model.UserSpec{{ID: 1, UUID: "u1"}, {ID: 2, UUID: "u2"}},
	})
	close(release)

	svc.applyPullResult(context.Background(), takePullResult(t, svc))

	if got := len(svc.lastUsers); got != 2 {
		t.Fatalf("stale poll rolled the user set back to %d users: %v", got, svc.lastUsers)
	}
	if !svc.wsResyncPending.Load() {
		t.Fatal("a stale result must leave the resync pending for a retry")
	}

	// The retry snapshot reflects the current set and clears the flag.
	svc.source = &fakeSource{pollFn: func(context.Context) (controlplane.Snapshot, error) {
		return controlplane.Snapshot{Users: []model.UserSpec{{ID: 1, UUID: "u1"}, {ID: 2, UUID: "u2"}}}, nil
	}}
	svc.pullBackoff.onSuccess()
	svc.requestWSResync(context.Background(), "retry")
	svc.applyPullResult(context.Background(), takePullResult(t, svc))

	if svc.wsResyncPending.Load() {
		t.Fatal("the retry snapshot must clear the pending flag")
	}
	if got := len(svc.lastUsers); got != 2 {
		t.Fatalf("retry lost users: %v", svc.lastUsers)
	}
}

func TestIntervalDurationClamps(t *testing.T) {
	tests := []struct {
		in   int
		want time.Duration
	}{
		{0, time.Second},
		{-5, time.Second},
		{10, 10 * time.Second},
		{1 << 40, 24 * time.Hour},
	}
	for _, tc := range tests {
		if got := intervalDuration(tc.in); got != tc.want {
			t.Fatalf("intervalDuration(%d) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
