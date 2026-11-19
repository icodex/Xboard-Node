package service

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/kernel"
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

// ensureKernelResolved must not return before the old kernel finished Stop:
// a background Stop raced the new kernel's bind and could leave it on a port
// that was still held. Both kernels now close listeners synchronously and
// drain async, so the call is safe on the main loop.
func TestAutoSwitchStopsOldKernelBeforeReturning(t *testing.T) {
	stopStarted := make(chan struct{})
	release := make(chan struct{})
	k := &fakeKernel{
		running: true,
		onStop: func() {
			close(stopStarted)
			<-release
		},
	}
	svc := newTestService(k)
	svc.cfg = &config.Config{Kernel: config.KernelConfig{Type: "auto"}}

	done := make(chan error, 1)
	go func() {
		_, err := svc.ensureKernelResolved(&model.NodeSpec{Protocol: "vless", ServerPort: 1}, "xray")
		done <- err
	}()

	select {
	case <-stopStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("old kernel was not stopped")
	}
	select {
	case <-done:
		t.Fatal("ensureKernelResolved returned while the old kernel's Stop was still running")
	default:
	}

	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ensureKernelResolved: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ensureKernelResolved did not finish")
	}
}

// A REST snapshot with an invalid node config must not be applied, while its
// user list still converges: otherwise a bad config would block user updates
// until the panel fixes the config.
func TestApplyPullResultRejectsInvalidConfigButAppliesUsers(t *testing.T) {
	svc := newTestService(&fakeKernel{running: true})
	svc.cfg = &config.Config{Kernel: config.KernelConfig{Type: "singbox"}}

	users := []model.UserSpec{{ID: 1, UUID: "u1"}}
	hash := computeUserHash(users)
	invalid := &model.NodeSpec{Protocol: "not-a-protocol", ServerPort: 1}

	svc.applyPullResult(context.Background(), pullResult{
		config:     invalid,
		configHash: "bad-config",
		users:      users,
		userHash:   hash,
	})

	if svc.lastConfig != nil || svc.lastConfigHash != "" {
		t.Fatalf("invalid config was applied: %+v hash=%q", svc.lastConfig, svc.lastConfigHash)
	}
	if len(svc.lastUsers) != 1 || svc.lastUserHash != hash {
		t.Fatalf("users not applied: %v hash=%q want %q", svc.lastUsers, svc.lastUserHash, hash)
	}
}

// A single invalid user must not reach the kernel (it rejects the whole
// config); the valid remainder still applies.
func TestHandleWSEventDropsInvalidUsers(t *testing.T) {
	svc := newTestService(&fakeKernel{running: true})
	svc.handleWSEvent(context.Background(), controlplane.Event{
		Type: controlplane.EventSyncUsers,
		Users: []model.UserSpec{
			{ID: 1, UUID: ""},
			{ID: 2, UUID: "u2"},
			{ID: 0, UUID: "u0"},
		},
	})
	if len(svc.lastUsers) != 1 || svc.lastUsers[0].ID != 2 {
		t.Fatalf("lastUsers = %v, want only user 2", svc.lastUsers)
	}
}

// The poll path drops a config identical to the applied one before it reaches
// the main loop.
func TestPullSkipsUnchangedConfig(t *testing.T) {
	svc := newTestService(&fakeKernel{running: true})
	svc.pullResults = make(chan pullResult, 1)

	spec := &model.NodeSpec{Protocol: "vless", ServerPort: 443}
	svc.lastConfigHash = computeConfigHash(spec)
	users := []model.UserSpec{{ID: 1, UUID: "u1"}}
	svc.source = &fakeSource{pollFn: func(context.Context) (controlplane.Snapshot, error) {
		return controlplane.Snapshot{Config: spec, Users: users}, nil
	}}

	svc.pullViaAPIAsync(context.Background())
	result := takePullResult(t, svc)

	if result.config != nil {
		t.Fatal("unchanged config must be dropped by the poll")
	}
	if len(result.users) != 1 || result.userHash == "" {
		t.Fatalf("users/hash missing: %v %q", result.users, result.userHash)
	}
}

// tls=1 promises TLS to clients; without certificate material the inbound must
// not silently run plaintext. The local allow_plaintext_tls flag is the explicit
// opt-out for upstream TLS termination.
func TestValidateTLSRequirementsFailsClosed(t *testing.T) {
	spec := &model.NodeSpec{Protocol: "vless", TLS: 1, ServerPort: 443}
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox"}}
	if err := validateNodeRuntime(cfg, []string{"vless"}, spec, kernel.TLSCert{}); err == nil {
		t.Fatal("vless tls=1 without a certificate must be rejected")
	}

	cfg.Kernel.AllowPlaintextTLS = true
	if err := validateNodeRuntime(cfg, []string{"vless"}, spec, kernel.TLSCert{}); err != nil {
		t.Fatalf("explicit plaintext opt-out must be honored: %v", err)
	}

	// QUIC protocols cannot be terminated upstream: still rejected.
	hy := &model.NodeSpec{Protocol: "hysteria", Version: 2, ServerPort: 443}
	if err := validateNodeRuntime(cfg, []string{"hysteria"}, hy, kernel.TLSCert{}); err == nil {
		t.Fatal("hysteria must still require a certificate")
	}
}

func TestApplyChangesRestartsOnReloadError(t *testing.T) {
	k := &fakeKernel{running: true, reloadErr: errors.New("bad routes")}
	svc := newTestService(k)
	svc.lastConfig = &model.NodeSpec{Protocol: "vless", ServerPort: 1}
	svc.lastUsers = []model.UserSpec{{ID: 1, UUID: "u1"}}

	svc.applyChanges(context.Background(), true, false)

	if k.startCalls == 0 {
		t.Fatal("a reload error must restart the kernel instead of keeping old routes")
	}
}

// A single user delta must update the derived indexes without a full rebuild.
func TestApplyUserDeltaUpdatesIndexesIncrementally(t *testing.T) {
	svc := newTestService(&fakeKernel{running: true})
	svc.lastUsers = []model.UserSpec{{ID: 1, UUID: "u1", DeviceLimit: 2}}
	svc.limiter.UpdateUsers(svc.lastUsers)
	svc.speedTracker.UpdateBuckets()

	svc.applyUserDelta(context.Background(), "add", []model.UserSpec{{ID: 2, UUID: "u2", DeviceLimit: 4}})
	if len(svc.lastUsers) != 2 {
		t.Fatalf("lastUsers = %v", svc.lastUsers)
	}
	if limit, ok := svc.limiter.GetDeviceLimitByUUID("u2"); !ok || limit != 4 {
		t.Fatalf("new user limit = %d/%v", limit, ok)
	}
	if svc.lastUserHash != computeUserHash(svc.lastUsers) {
		t.Fatal("hash not refreshed for the delta")
	}

	svc.applyUserDelta(context.Background(), "remove", []model.UserSpec{{ID: 1, UUID: "u1"}})
	if len(svc.lastUsers) != 1 || svc.lastUsers[0].ID != 2 {
		t.Fatalf("after remove: %v", svc.lastUsers)
	}
	if _, ok := svc.limiter.GetDeviceLimitByUUID("u1"); ok {
		t.Fatal("removed user still resolves a limit")
	}
}

// Callers that already computed the hash must not pay for it again.
func TestPrepareUserStateUsesKnownHash(t *testing.T) {
	svc := newTestService(&fakeKernel{running: true})
	_, prevHash := svc.prepareUserState([]model.UserSpec{{ID: 1, UUID: "u1"}}, "known-hash")
	if prevHash != "" {
		t.Fatalf("prevHash = %q, want empty on first call", prevHash)
	}
	if svc.lastUserHash != "known-hash" {
		t.Fatalf("hash = %q, want known-hash", svc.lastUserHash)
	}
}

// A stuck certificate reconfiguration must not block unrelated config changes
// forever: after the bound the config applies with the current certificate.
func TestApplyChangesBoundedByStuckCertWorker(t *testing.T) {
	k := &fakeKernel{running: true}
	svc := newTestService(k)
	svc.lastConfig = &model.NodeSpec{Protocol: "vless", ServerPort: 1}
	svc.lastUsers = []model.UserSpec{{ID: 1, UUID: "u1"}}
	svc.certWorkers.Add(1)
	defer svc.certWorkers.Add(-1)

	svc.applyChanges(context.Background(), true, false)
	if k.reloadCalls != 0 {
		t.Fatal("a fresh cert reconfiguration must defer the config change")
	}
	if !svc.configDeferred.Load() {
		t.Fatal("configDeferred not set")
	}

	svc.certDeferSince = time.Now().Add(-3 * time.Minute)
	svc.applyChanges(context.Background(), true, false)
	if k.reloadCalls == 0 {
		t.Fatal("a stuck cert worker must not block config changes past the bound")
	}
}
