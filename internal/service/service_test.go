package service

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/cert"
	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/limiter"
	"github.com/cedar2025/xboard-node/internal/model"
	"golang.org/x/time/rate"
)

type fakeKernel struct {
	running bool

	startErr  error
	updateErr error
	addErr    error

	startCalls  int
	updateCalls int
	addCalls    int
	removeCalls int
	reloadCalls int

	onUpdateUsers func([]model.UserSpec)
	onAddUsers    func([]model.UserSpec)
	onRemoveUsers func([]model.UserSpec)

	speedLimitFunc  func(string) *rate.Limiter
	deviceLimitFunc func(string) (int, bool)
}

func (f *fakeKernel) Name() string        { return "fake" }
func (f *fakeKernel) Protocols() []string { return []string{"vless"} }
func (f *fakeKernel) Start(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	_, _, _ = nodeConfig, users, tls
	f.startCalls++
	if f.startErr != nil {
		return f.startErr
	}
	f.running = true
	return nil
}
func (f *fakeKernel) Stop()           { f.running = false }
func (f *fakeKernel) IsRunning() bool { return f.running }
func (f *fakeKernel) Reload(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	_, _, _ = nodeConfig, users, tls
	f.reloadCalls++
	return nil
}
func (f *fakeKernel) AddUsers(users []model.UserSpec) (int, error) {
	f.addCalls++
	if f.onAddUsers != nil {
		f.onAddUsers(users)
	}
	if f.addErr != nil {
		return 0, f.addErr
	}
	return len(users), nil
}
func (f *fakeKernel) RemoveUsers(users []model.UserSpec) (int, error) {
	f.removeCalls++
	if f.onRemoveUsers != nil {
		f.onRemoveUsers(users)
	}
	return len(users), nil
}
func (f *fakeKernel) UpdateUsers(users []model.UserSpec) (int, int, error) {
	f.updateCalls++
	if f.onUpdateUsers != nil {
		f.onUpdateUsers(users)
	}
	if f.updateErr != nil {
		return 0, 0, f.updateErr
	}
	return len(users), 0, nil
}
func (f *fakeKernel) GetUserTraffic(ctx context.Context) (map[int][2]int64, map[int]map[string]bool, int, error) {
	_ = ctx
	return nil, nil, 0, nil
}
func (f *fakeKernel) CloseConnection(ctx context.Context, connID string) error {
	_, _ = ctx, connID
	return nil
}
func (f *fakeKernel) CloseUserConnections(ctx context.Context, uuid string) error {
	_, _ = ctx, uuid
	return nil
}
func (f *fakeKernel) SetSpeedLimitFunc(fn func(uuid string) *rate.Limiter) { f.speedLimitFunc = fn }
func (f *fakeKernel) SetDeviceLimitFunc(fn func(uuid string) (int, bool))  { f.deviceLimitFunc = fn }
func (f *fakeKernel) UpdateGlobalDevices(users map[int][]string)           { _ = users }
func (f *fakeKernel) ClearGlobalDevices()                                  {}

func newTestService(k *fakeKernel) *Service {
	sharedLimiter := limiter.New()
	s := &Service{
		kernel:       k,
		limiter:      sharedLimiter,
		speedTracker: limiter.NewSpeedTracker(sharedLimiter),
		cert:         cert.NewManager(config.CertConfig{}),
		certUpdates:  make(chan certUpdate, 1),
	}
	k.SetSpeedLimitFunc(s.speedTracker.GetLimiter)
	k.SetDeviceLimitFunc(s.limiter.GetDeviceLimitByUUID)
	return s
}

func TestApplyUserUpdatePreparesLimiterBeforeKernelUpdate(t *testing.T) {
	k := &fakeKernel{running: true}
	s := newTestService(k)
	s.lastConfig = &model.NodeSpec{Protocol: "vless"}
	oldUsers := []model.UserSpec{{ID: 1, UUID: "uuid-old", SpeedLimit: 4}}
	s.updateUserState(oldUsers)

	newUsers := []model.UserSpec{{ID: 2, UUID: "uuid-new", SpeedLimit: 8}}
	k.onUpdateUsers = func(users []model.UserSpec) {
		if len(users) != 1 || users[0].UUID != "uuid-new" {
			t.Fatalf("unexpected users passed to UpdateUsers: %#v", users)
		}
		if got := k.speedLimitFunc("uuid-new"); got == nil {
			t.Fatal("expected new user's limiter to be visible before kernel UpdateUsers")
		}
	}

	s.applyUserUpdate(context.Background(), newUsers, computeUserHash(newUsers))

	if got := k.updateCalls; got != 1 {
		t.Fatalf("UpdateUsers call count = %d, want 1", got)
	}
	if len(s.lastUsers) != 1 || s.lastUsers[0].UUID != "uuid-new" {
		t.Fatalf("lastUsers = %#v, want new users", s.lastUsers)
	}
	if s.speedTracker.GetLimiter("uuid-new") == nil {
		t.Fatal("expected limiter for new user after successful update")
	}
}

func TestApplyUserUpdateRestoresStateWhenKernelAndRestartFail(t *testing.T) {
	k := &fakeKernel{
		running:   true,
		updateErr: errors.New("update failed"),
		startErr:  errors.New("restart failed"),
	}
	s := newTestService(k)
	s.lastConfig = &model.NodeSpec{Protocol: "vless"}
	oldUsers := []model.UserSpec{{ID: 1, UUID: "uuid-old", SpeedLimit: 4}}
	s.updateUserState(oldUsers)
	oldHash := s.lastUserHash

	newUsers := []model.UserSpec{{ID: 2, UUID: "uuid-new", SpeedLimit: 8}}
	s.applyUserUpdate(context.Background(), newUsers, computeUserHash(newUsers))

	if got := k.startCalls; got != 1 {
		t.Fatalf("Start call count = %d, want 1", got)
	}
	if len(s.lastUsers) != 1 || s.lastUsers[0].UUID != "uuid-old" {
		t.Fatalf("lastUsers = %#v, want restored old users", s.lastUsers)
	}
	if s.lastUserHash != oldHash {
		t.Fatalf("lastUserHash = %q, want %q", s.lastUserHash, oldHash)
	}
	if s.speedTracker.GetLimiter("uuid-old") == nil {
		t.Fatal("expected old limiter to be restored after rollback")
	}
	if s.speedTracker.GetLimiter("uuid-new") != nil {
		t.Fatal("expected new limiter to be removed after rollback")
	}
}

func TestApplyUserDeltaAddPreparesLimiterBeforeKernelUpdate(t *testing.T) {
	k := &fakeKernel{running: true}
	s := newTestService(k)
	s.lastConfig = &model.NodeSpec{Protocol: "vless"}
	oldUsers := []model.UserSpec{{ID: 1, UUID: "uuid-old", SpeedLimit: 4}}
	s.updateUserState(oldUsers)

	delta := []model.UserSpec{{ID: 2, UUID: "uuid-new", SpeedLimit: 8}}
	k.onAddUsers = func(users []model.UserSpec) {
		if len(users) != 1 || users[0].UUID != "uuid-new" {
			t.Fatalf("unexpected users passed to AddUsers: %#v", users)
		}
		if got := k.speedLimitFunc("uuid-new"); got == nil {
			t.Fatal("expected delta user's limiter to be visible before kernel AddUsers")
		}
	}

	s.applyUserDelta(context.Background(), "add", delta)

	if got := k.addCalls; got != 1 {
		t.Fatalf("AddUsers call count = %d, want 1", got)
	}
	if s.speedTracker.GetLimiter("uuid-new") == nil {
		t.Fatal("expected limiter for delta-added user after successful update")
	}
}

func TestValidateNodeRuntimeRejectsUnsupportedDNSProvider(t *testing.T) {
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox"}}
	err := validateNodeRuntime(cfg, []string{"http"}, &model.NodeSpec{
		Protocol: "http",
		CertConfig: &config.CertConfig{
			CertMode:    "dns",
			DNSProvider: "3123123",
			Domain:      "example.com",
		},
	}, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() == "" {
		t.Fatal("expected non-empty error")
	}
	if got := err.Error(); !strings.HasPrefix(got, `unsupported cert_config.dns_provider "3123123" (supported: `) {
		t.Fatalf("unexpected error: %v", got)
	}
}

func TestValidateNodeRuntimeAllowsSelfManagedTLSBeforeFilesExist(t *testing.T) {
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox"}}
	err := validateNodeRuntime(cfg, []string{"anytls", "hysteria"}, &model.NodeSpec{
		Protocol: "anytls",
		CertConfig: &config.CertConfig{
			CertMode: "self",
			Domain:   "example.com",
		},
	}, kernel.TLSCert{})
	if err != nil {
		t.Fatalf("expected self-managed TLS config to pass validation, got %v", err)
	}
}

func TestValidateNodeRuntimeAllowsSingboxRealityWithRequiredFields(t *testing.T) {
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox"}}
	err := validateNodeRuntime(cfg, []string{"vless"}, &model.NodeSpec{
		Protocol: "vless",
		TLS:      2,
		TLSSettings: map[string]any{
			"private_key": "test-key",
			"server_name": "example.com",
		},
	}, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	if err != nil {
		t.Fatalf("expected sing-box reality validation to pass, got %v", err)
	}
}

func TestValidateNodeRuntimeRejectsRealityWithoutTLSSettings(t *testing.T) {
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox"}}
	err := validateNodeRuntime(cfg, []string{"vless"}, &model.NodeSpec{
		Protocol: "vless",
		TLS:      2,
	}, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := err.Error(); got != "reality tls requires tls_settings" {
		t.Fatalf("unexpected error: %v", got)
	}
}

func TestValidateNodeRuntimeRejectsRealityWithoutPrivateKey(t *testing.T) {
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox"}}
	err := validateNodeRuntime(cfg, []string{"vless"}, &model.NodeSpec{
		Protocol: "vless",
		TLS:      2,
		TLSSettings: map[string]any{
			"server_name": "example.com",
		},
	}, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := err.Error(); got != "reality tls requires tls_settings.private_key" {
		t.Fatalf("unexpected error: %v", got)
	}
}

func TestValidateNodeRuntimeRejectsRealityWithoutServerNameOrDest(t *testing.T) {
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox"}}
	err := validateNodeRuntime(cfg, []string{"vless"}, &model.NodeSpec{
		Protocol: "vless",
		TLS:      2,
		TLSSettings: map[string]any{
			"private_key": "test-key",
		},
	}, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := err.Error(); got != "reality tls requires tls_settings.server_name or tls_settings.dest" {
		t.Fatalf("unexpected error: %v", got)
	}
}

// A pinned singbox kernel must reject vmess+Reality instead of silently
// running a plaintext inbound.
func TestValidateNodeRuntimeRejectsVmessRealityOnSingbox(t *testing.T) {
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox"}}
	err := validateNodeRuntime(cfg, []string{"vmess"}, &model.NodeSpec{
		Protocol: "vmess",
		TLS:      2,
		TLSSettings: map[string]any{
			"private_key": "test-key",
			"server_name": "example.com",
		},
	}, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	if err == nil {
		t.Fatal("expected vmess+Reality on singbox to be rejected, got nil")
	}
	if !strings.Contains(err.Error(), "plaintext") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// A rejected config update must not swap (and thereby stop) the running
// kernel in auto mode: validation runs before the swap, against the resolved
// kernel's protocol list.
func TestHandleWSEventRejectedConfigKeepsRunningKernel(t *testing.T) {
	k := &fakeKernel{running: true}
	s := newTestService(k)
	s.cfg = &config.Config{Kernel: config.KernelConfig{Type: "auto"}}

	// vless+Reality without tls_settings fails validation; auto would resolve
	// this spec to singbox (not the fake), so the check uses the singbox list.
	bad := &model.NodeSpec{Protocol: "vless", TLS: 2}
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: bad})

	if s.kernel != k {
		t.Fatalf("kernel was swapped on a rejected config: %T", s.kernel)
	}
	if !k.running {
		t.Fatal("running kernel was stopped by a rejected config")
	}

	// A valid config for a different kernel type does swap.
	good := &model.NodeSpec{
		Protocol:   "tuic",
		CertConfig: &config.CertConfig{CertMode: "self", Domain: "example.com"},
	}
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: good})
	if s.kernel == k {
		t.Fatal("valid config for resolved singbox did not swap kernel")
	}
	if s.kernel.Name() != "sing-box" {
		t.Fatalf("kernel after valid swap = %q, want sing-box", s.kernel.Name())
	}
}

// A failed kernel start must not be cached as applied: otherwise the panel's
// identical syncs (same hashes, REST 304) are deduped and the node stays down
// until the config changes or the process restarts.
func TestApplyUserUpdateClearsHashesAndRetriesAfterStartFailure(t *testing.T) {
	k := &fakeKernel{startErr: errors.New("bind: address already in use")}
	s := newTestService(k)
	s.lastConfig = &model.NodeSpec{Protocol: "vless"}

	users := []model.UserSpec{{ID: 1, UUID: "uuid-1"}}
	s.applyUserUpdate(context.Background(), users, computeUserHash(users))

	if k.startCalls != 1 {
		t.Fatalf("Start calls = %d, want 1", k.startCalls)
	}
	if s.lastConfigHash != "" || s.lastUserHash != "" {
		t.Fatalf("hashes after failed start: config=%q users=%q, want both empty",
			s.lastConfigHash, s.lastUserHash)
	}
	if s.kernel.IsRunning() {
		t.Fatal("kernel must not be running after a failed start")
	}

	k.startErr = nil
	if !s.ensureRunning() {
		t.Fatal("expected the retry to start the kernel")
	}
	if k.startCalls != 2 {
		t.Fatalf("Start calls after retry = %d, want 2", k.startCalls)
	}
	if !s.kernel.IsRunning() {
		t.Fatal("kernel should be running after a successful retry")
	}
}

// The periodic retry backs off instead of rebuilding a broken kernel every tick.
func TestRetryKernelBacksOff(t *testing.T) {
	k := &fakeKernel{startErr: errors.New("still broken")}
	s := newTestService(k)
	s.lastConfig = &model.NodeSpec{Protocol: "vless"}
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "uuid-1"}})

	s.retryKernel() // first attempt, fails, backoff = 1
	if k.startCalls != 1 {
		t.Fatalf("Start calls = %d, want 1", k.startCalls)
	}
	s.retryKernel() // skipped by backoff
	if k.startCalls != 1 {
		t.Fatalf("Start calls after backoff tick = %d, want 1", k.startCalls)
	}
	s.retryKernel() // backoff consumed, retries
	if k.startCalls != 2 {
		t.Fatalf("Start calls after backoff expiry = %d, want 2", k.startCalls)
	}
}

// The runtime certificate path runs off the main loop; the result must arrive
// on certUpdates and the material must be installed. Self mode needs no
// network, so this exercises the actual worker.
func TestCertReconfigureRunsOffLoop(t *testing.T) {
	k := &fakeKernel{running: true}
	s := newTestService(k)
	s.cfg = &config.Config{}
	s.cfg.Cert.CertDir = t.TempDir()

	s.applyNodeCert(context.Background(), &config.CertConfig{CertMode: "self", Domain: "example.test"}, false)

	select {
	case upd := <-s.certUpdates:
		if !upd.ok {
			t.Fatal("expected the certificate update to be marked successful")
		}
		if upd.cfg.CertMode != "self" {
			t.Fatalf("cert mode = %q, want self", upd.cfg.CertMode)
		}
		if !upd.changed {
			t.Fatal("expected new material to be reported as changed")
		}
		if !s.cert.HasCert() {
			t.Fatal("expected certificate material to be installed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the cert update")
	}
}

// hysteria v1 and v2 share the protocol field; the log prefix must use Version.
func TestNodeDisplayProtocol(t *testing.T) {
	tests := []struct {
		nc   *model.NodeSpec
		want string
	}{
		{&model.NodeSpec{Protocol: "hysteria", Version: 1}, "hysteria"},
		{&model.NodeSpec{Protocol: "hysteria", Version: 2}, "hysteria2"},
		{&model.NodeSpec{Protocol: "vless"}, "vless"},
	}
	for _, tt := range tests {
		if got := nodeDisplayProtocol(tt.nc); got != tt.want {
			t.Errorf("nodeDisplayProtocol(%+v) = %q, want %q", tt.nc, got, tt.want)
		}
	}
}

// While a certificate reconfiguration is running, kernel loads are deferred so
// the config change lands together with the new material (one reload, not two).
func TestApplyChangesDefersWhileCertInFlight(t *testing.T) {
	k := &fakeKernel{running: true}
	s := newTestService(k)
	s.lastConfig = &model.NodeSpec{Protocol: "vless"}
	s.lastUsers = []model.UserSpec{{ID: 1, UUID: "uuid-1"}}

	s.certWorkers.Add(1)
	s.applyChanges(context.Background(), true, false)
	if k.reloadCalls != 0 {
		t.Fatalf("Reload calls = %d, want 0 while cert is in flight", k.reloadCalls)
	}
	if !s.configDeferred.Load() {
		t.Fatal("config change should be marked deferred")
	}

	// The cert update handler clears the flag and replays the change.
	s.certWorkers.Add(-1)
	deferred := s.configDeferred.Swap(false)
	if !deferred {
		t.Fatal("deferred flag should be set")
	}
	s.applyChanges(context.Background(), true, false)
	if k.reloadCalls != 1 {
		t.Fatalf("Reload calls after cert completed = %d, want 1", k.reloadCalls)
	}
}

// A failing reconfiguration must not report success or leave the worker
// counter stuck. Cancelling the context must end the retry backoff promptly.
func TestCertReconfigureFailureCancelsCleanly(t *testing.T) {
	k := &fakeKernel{running: true}
	s := newTestService(k)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.startCertReconfigure(ctx, config.CertConfig{
		CertMode: "file",
		CertFile: filepath.Join(t.TempDir(), "missing.pem"),
		KeyFile:  filepath.Join(t.TempDir(), "missing.key"),
	})

	// The worker fails fast (missing file) and enters its backoff loop.
	deadline := time.Now().Add(2 * time.Second)
	for s.certWorkers.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := s.certWorkers.Load(); got != 1 {
		t.Fatalf("certWorkers = %d, want 1 while the worker runs", got)
	}

	cancel()
	deadline = time.Now().Add(2 * time.Second)
	for s.certWorkers.Load() > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := s.certWorkers.Load(); got != 0 {
		t.Fatalf("certWorkers = %d, want 0 after cancellation", got)
	}
	select {
	case upd := <-s.certUpdates:
		t.Fatalf("unexpected certificate update after failure: %+v", upd)
	default:
	}
}

// A config that keeps failing is retried a bounded number of times, then
// reported as a failure so the main loop can apply any deferred kernel change.
func TestCertReconfigureGivesUpAfterRetries(t *testing.T) {
	k := &fakeKernel{running: true}
	s := newTestService(k)
	s.certRetryAttempts = 2
	s.certRetryBase = time.Millisecond

	var attempts atomic.Int32
	s.certReconfigure = func(context.Context, config.CertConfig) (bool, error) {
		attempts.Add(1)
		return false, errors.New("reconfigure failed")
	}

	s.startCertReconfigure(context.Background(), config.CertConfig{CertMode: "file"})

	select {
	case upd := <-s.certUpdates:
		if upd.ok {
			t.Fatal("give-up must not be reported as success")
		}
		if upd.changed {
			t.Fatal("a failed reconfiguration must not report changed material")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the give-up update")
	}

	if got := attempts.Load(); got != 2 {
		t.Fatalf("reconfigure attempts = %d, want 2", got)
	}
	deadline := time.Now().Add(2 * time.Second)
	for s.certWorkers.Load() > 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := s.certWorkers.Load(); got != 0 {
		t.Fatalf("certWorkers = %d, want 0 after give-up", got)
	}
	s.certMu.Lock()
	busy := s.certBusy
	s.certMu.Unlock()
	if busy {
		t.Fatal("certBusy must be false after give-up")
	}
}
