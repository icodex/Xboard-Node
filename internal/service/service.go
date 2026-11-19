package service

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cedar2025/xboard-node/internal/cert"
	"github.com/cedar2025/xboard-node/internal/cert/dnsproviders"
	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/kernel/singbox"
	"github.com/cedar2025/xboard-node/internal/kernel/xray"
	"github.com/cedar2025/xboard-node/internal/limiter"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/monitor"
	"github.com/cedar2025/xboard-node/internal/nlog"
	"github.com/cedar2025/xboard-node/internal/tracker"
)

type Service struct {
	cfg          *config.Config
	source       controlplane.Source
	sink         controlplane.Sink
	kernel       kernel.Kernel
	tracker      *tracker.Tracker
	limiter      *limiter.Limiter
	speedTracker *limiter.SpeedTracker
	cert         *cert.Manager

	// kernelMu guards kernel construction/swap when kernel.type resolves to
	// auto: ensureKernelFor may replace s.kernel mid-run on config changes.
	kernelMu sync.Mutex

	lastConfig *model.NodeSpec
	lastUsers  []model.UserSpec

	// nodeLog is the logger with node context for this service instance.
	nodeLog *nlog.NodeLog

	pushInterval int // seconds
	pullInterval int // seconds

	lastUserHash   string     // hash of user list for change detection
	lastConfigHash string     // hash of full config for change detection
	pullBackoff    apiBackoff // backoff for panel pull failures
	pushBackoff    apiBackoff // backoff for panel push failures
	startBackoff   apiBackoff // backoff for periodic kernel start retries

	// pushActive prevents overlapping push/pull goroutines.
	pushActive atomic.Bool
	pullActive atomic.Bool
	// probeHash dedupes custom-outbound reachability probes: only a changed
	// outbound set is re-dialed on reload.
	probeHash atomic.Value
	// pullResults delivers async pullViaAPI results back to the main goroutine.
	pullResults chan pullResult

	wsClient        controlplane.PushClient        // Push client (nil if push is not enabled)
	wsEvents        chan controlplane.Event        // receives data events from push transport
	wsStatusCh      chan controlplane.StatusChange // receives push connectivity notifications
	wsCancel        context.CancelFunc             // cancels the WS client goroutine
	wsDisconnectAt  time.Time                      // when WS last disconnected (zero if connected)
	wsResyncPending atomic.Bool

	// stateSeq counts applied config/user state changes from any source. A
	// poll captures it before fetching; a result whose captured value no
	// longer matches is stale and must not overwrite newer pushed state.
	// Every path that writes lastUsers or lastConfig must bump it; otherwise
	// stale polls regress to overwriting that state.
	stateSeq atomic.Uint64
	// resyncGen counts reconciliation requests. A poll captures it at start
	// and may clear wsResyncPending only when it satisfies every request made
	// so far; otherwise the pull ticker retries.
	resyncGen atomic.Uint64

	machineMailbox   *controlplane.NodeMailbox
	machineMailboxCh <-chan struct{}

	// metricsMu: lastUsers, lastConfig, wsClient, wsDisconnectAt (buildMetrics vs main loop).
	metricsMu sync.RWMutex

	// Certificate reconfiguration runs off the main loop: ACME issuance
	// (HTTP-01/DNS-01) can take minutes and must not stall reports, tracking
	// or config handling. certUpdates delivers the result back to the loop.
	certUpdates chan certUpdate
	certMu      sync.Mutex
	certBusy    bool
	certPending *config.CertConfig

	// certWorkers counts running certificate reconfigurations. Kernel loads
	// are deferred while it is non-zero, so a config+cert push causes one
	// reload (with the new cert) instead of two. A counter rather than a bool:
	// a second worker can start before the first one's update reaches the main
	// loop, and a bool was cleared too early in that window.
	certWorkers    atomic.Int32
	configDeferred atomic.Bool
	// certDeferSince bounds how long config changes may wait for a cert
	// reconfiguration; past it the config applies with the current cert and
	// the cert update triggers another reload.
	certDeferSince time.Time

	// Certificate retry tuning. Zero values fall back to the production
	// defaults, so tests can exercise the give-up path without waiting 30s.
	certRetryAttempts int
	certRetryBase     time.Duration

	// certReconfigure performs one reconfiguration attempt. Nil uses the cert
	// manager; tests override it to count attempts without touching files.
	certReconfigure func(opCtx context.Context, cfg config.CertConfig) (bool, error)

	// certCtx scopes certificate reconfiguration workers. Shutdown cancels it
	// and waits (bounded) before cert.Stop, so a worker cannot re-arm ACME
	// after the manager was stopped.
	certCtx    context.Context
	certCancel context.CancelFunc

	// pushInFlight counts async report goroutines. The shutdown branch waits
	// for them (bounded) before the final snapshot, so a failed report has
	// already restored its traffic into the tracker by then.
	pushInFlight atomic.Int32

	// Shutdown budgets; tests lower them.
	shutdownWait    time.Duration // join cert workers
	pushWait        time.Duration // drain in-flight async reports
	finalReportWait time.Duration // bound the final synchronous report
}

// certUpdate carries an applied certificate configuration back to the main
// loop (which owns s.cfg).
type certUpdate struct {
	cfg     config.CertConfig
	changed bool
	ok      bool
}

// pullResult carries the outcome of an async pullViaAPI back to the main goroutine.
type pullResult struct {
	config     *model.NodeSpec
	users      []model.UserSpec
	configHash string
	userHash   string
	// seq is stateSeq when the poll started; a mismatch means newer pushed
	// state was applied while the snapshot was in flight.
	seq uint64
	// gen is resyncGen when the poll started; it gates clearing the pending
	// reconciliation flag.
	gen uint64
}

// intervalDuration converts a seconds setting to a ticker-safe Duration.
// time.NewTicker panics on <= 0, and multiplying a huge value overflows into
// a negative Duration, so clamp both ends. Config validation rejects negative
// local values; this also covers panel-provided and hot-reloaded ones.
func intervalDuration(seconds int) time.Duration {
	if seconds < 1 {
		seconds = 1
	}
	const maxSeconds = 24 * 60 * 60
	if seconds > maxSeconds {
		seconds = maxSeconds
	}
	return time.Duration(seconds) * time.Second
}

// apiBackoff implements simple exponential backoff for API failures.
type apiBackoff struct {
	mu            sync.Mutex
	skipRemaining int
}

func (b *apiBackoff) shouldSkip() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.skipRemaining > 0 {
		b.skipRemaining--
		return true
	}
	return false
}

func (b *apiBackoff) onSuccess() {
	b.mu.Lock()
	b.skipRemaining = 0
	b.mu.Unlock()
}

func (b *apiBackoff) onFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.skipRemaining <= 0 {
		b.skipRemaining = 1
	} else if b.skipRemaining < 8 {
		b.skipRemaining *= 2
	}
}

func New(cfg *config.Config) *Service {
	var cp controlplane.ControlPlane
	if cfg.IsStandalone() {
		cp = controlplane.NewLocalControlPlane(cfg)
	} else {
		cp = controlplane.NewPanelControlPlane(cfg.Panel, cfg.WS, cfg.Kernel)
	}
	return newService(cfg, cp)
}

// NewWithControlPlane creates a Service with an externally-provided
// ControlPlane. Used by the machine orchestrator to inject a
// MachinePanelControlPlane with WS mux routing.
func NewWithControlPlane(cfg *config.Config, cp controlplane.ControlPlane) *Service {
	return newService(cfg, cp)
}

func newService(cfg *config.Config, cp controlplane.ControlPlane) *Service {
	certMgr := cert.NewManager(cfg.Cert)

	l := limiter.New()
	st := limiter.NewSpeedTracker(l)

	s := &Service{
		cfg:          cfg,
		source:       cp,
		sink:         cp,
		tracker:      tracker.New(),
		limiter:      l,
		speedTracker: st,
		cert:         certMgr,
		wsEvents:     make(chan controlplane.Event, 16),
		wsStatusCh:   make(chan controlplane.StatusChange, 4),
		pullResults:  make(chan pullResult, 1),
		certUpdates:  make(chan certUpdate, 1),
	}
	// kernel.type auto defers kernel construction until the first node spec
	// arrives; concrete types build immediately (behaviour unchanged).
	s.kernel = s.buildKernel(cfg.Kernel.Type)
	if s.kernel == nil {
		s.kernel = singbox.New(cfg.Kernel) // placeholder until first spec resolves
	}
	return s
}

// buildKernel constructs a kernel for a concrete type. Returns nil for
// "auto"/empty — the caller must resolve via ensureKernelFor first.
func (s *Service) buildKernel(kernelType string) kernel.Kernel {
	switch strings.ToLower(strings.TrimSpace(kernelType)) {
	case "singbox", "sing-box", "":
		return singbox.New(s.cfg.Kernel)
	case "xray":
		return xray.New(s.cfg.Kernel)
	default:
		return nil
	}
}

// ensureKernelFor returns a kernel compatible with the given spec, building
// (or rebuilding, on hot config change) it when the resolved type differs.
// Callers must hold no other service locks; kernel ops stay on the main loop.
func (s *Service) ensureKernelFor(spec *model.NodeSpec) (kernel.Kernel, error) {
	return s.ensureKernelResolved(spec, model.ResolveKernelForNode(spec, s.cfg.Kernel))
}

// ensureKernelResolved is ensureKernelFor with the resolution done by the
// caller, so a config event resolves the kernel type exactly once.
func (s *Service) ensureKernelResolved(spec *model.NodeSpec, resolved string) (kernel.Kernel, error) {
	s.kernelMu.Lock()
	defer s.kernelMu.Unlock()

	current := s.kernel
	if current != nil {
		if name := strings.ToLower(strings.TrimSpace(s.cfg.Kernel.Type)); name != "auto" && name != "" {
			// Concrete kernel.type: never swap.
			return current, nil
		}
		// Auto: compare against what the running kernel implements.
		if matchesResolvedKernel(current, resolved) {
			return current, nil
		}
		nlog.Core().Info("kernel auto-switch on config change",
			"protocol", spec.Protocol, "network", spec.Network, "kernel", resolved)
	}

	k := s.buildKernel(resolved)
	if k == nil {
		return nil, fmt.Errorf("unsupported kernel type %q resolved for protocol %q", resolved, spec.Protocol)
	}
	k.SetSpeedLimitFunc(s.speedTracker.GetLimiter)
	k.SetDeviceLimitFunc(s.limiter.GetDeviceLimitByUUID)
	s.kernel = k
	// Stop the old kernel synchronously: both kernels close their listeners
	// before Stop returns and drain in the background, so the new instance can
	// bind the same ports without racing an unscheduled goroutine.
	if current != nil {
		current.Stop()
	}
	return k, nil
}

// currentKernel returns the kernel the service is using right now. Kernel
// auto-switch replaces s.kernel on the main loop, so goroutines that only
// report status (WS ping, report push) must read it under kernelMu instead of
// racing the swap.
func (s *Service) currentKernel() kernel.Kernel {
	s.kernelMu.Lock()
	k := s.kernel
	s.kernelMu.Unlock()
	return k
}

// kernelRunning reports whether the current kernel accepts connections.
func (s *Service) kernelRunning() bool {
	k := s.currentKernel()
	return k != nil && k.IsRunning()
}

// shutdownWorkers cancels certificate reconfiguration and the WS client, then
// joins cert workers and in-flight reports with independent bounds before
// cert.Stop runs. The bounds matter: ACME issuance can ignore cancellation for
// a while, and the daemon only allows a short shutdown budget. The manager
// refuses reconfiguration once stopped, so a straggler cannot re-arm
// maintenance.
func (s *Service) shutdownWorkers() {
	if s.certCancel != nil {
		s.certCancel()
	}
	// The WS client goroutine derives from the run context; cancel it too so a
	// service rebuilt after a setup error does not leave it parked on ctx.
	if s.wsCancel != nil {
		s.wsCancel()
	}
	waitCount(s.certWorkers.Load, s.shutdownWait, 3*time.Second)
	waitCount(s.pushInFlight.Load, s.pushWait, 3*time.Second)
}

// waitInFlightPushes lets async reports finish (and restore traffic on
// failure) before the final synchronous snapshot is taken.
func (s *Service) waitInFlightPushes() {
	waitCount(s.pushInFlight.Load, s.pushWait, 3*time.Second)
}

func waitCount(remaining func() int32, limit, fallback time.Duration) {
	if limit <= 0 {
		limit = fallback
	}
	deadline := time.Now().Add(limit)
	for remaining() > 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
}

// stopCurrentKernel stops whatever kernel is running now. Run's deferred stop
// has to resolve the kernel at exit: with kernel.type auto the kernel object
// can be replaced after Run starts, and binding the original receiver would
// leave the live kernel running (still listening, still serving stale users).
func (s *Service) stopCurrentKernel() {
	if k := s.currentKernel(); k != nil {
		k.Stop()
	}
}

// matchesResolvedKernel reports whether k is the kernel auto mode resolved to.
func matchesResolvedKernel(k kernel.Kernel, resolved string) bool {
	switch resolved {
	case "singbox":
		return strings.HasPrefix(k.Name(), "sing-box")
	case "xray":
		return k.Name() == "xray"
	}
	return false
}

func (s *Service) Run(ctx context.Context) error {
	// Start cert manager (handles auto-TLS or manual cert verification)
	if err := s.cert.Start(ctx); err != nil {
		return fmt.Errorf("cert manager: %w", err)
	}
	defer s.cert.Stop()

	// Workers (certificate reconfiguration, async reports) must not outlive
	// this Run: cancel their scope and join them before cert.Stop.
	certCtx, certCancel := context.WithCancel(ctx)
	s.certCtx, s.certCancel = certCtx, certCancel
	defer s.shutdownWorkers()

	// Handshake: get WS config + initial data in one call
	if err := s.initialSetup(ctx); err != nil {
		return fmt.Errorf("initial setup: %w", err)
	}
	defer s.stopCurrentKernel()

	// Set up tickers. intervalDuration clamps, because config validation
	// rejects negatives but panel-provided and hot-reloaded values still flow
	// here, and NewTicker panics on <= 0.
	pushSeconds := s.pushInterval
	if pushSeconds < 5 {
		pushSeconds = 5
	}
	trackTicker := time.NewTicker(intervalDuration(s.cfg.Node.TrackInterval))
	reportTicker := time.NewTicker(intervalDuration(pushSeconds))
	pullTicker := time.NewTicker(intervalDuration(s.pullInterval))
	deviceReportTicker := time.NewTicker(intervalDuration(s.cfg.Node.DeviceReportInterval))

	// WS discovery: when in REST-only mode, periodically re-handshake to check
	// if WS has been enabled. When WS is disconnected for too long, re-check
	// if it's still available.
	wsDiscoveryTicker := time.NewTicker(intervalDuration(s.cfg.WS.DiscoveryInterval))

	defer trackTicker.Stop()
	defer reportTicker.Stop()
	defer pullTicker.Stop()
	defer deviceReportTicker.Stop()
	defer wsDiscoveryTicker.Stop()

	s.startWSClient(ctx)

	for {
		select {
		case <-ctx.Done():
			// Let in-flight reports finish first: a failed one restores its
			// traffic into the tracker, and the final snapshot must include it.
			s.waitInFlightPushes()
			s.pushReportSyncBounded()
			return nil

		case <-trackTicker.C:
			s.retryKernel()
			s.trackAndEnforce(ctx)

		case <-reportTicker.C:
			// certmagic renews on its own goroutine and only stores the new
			// PEM. The kernel reads TLS material in Start/Reload, so the
			// reload must be triggered here: REST polling (the other place
			// that used to consume the flag) is skipped while the WS is
			// connected, which left long-lived nodes serving an expired cert.
			if s.cert.CertRenewed() && s.lastConfig != nil && len(s.lastUsers) > 0 {
				nlog.Core().Info("certificate renewed, reloading kernel")
				s.applyChanges(ctx, true, false)
			}
			s.pushReportAsync()

		case <-deviceReportTicker.C:
			s.reportDevices()

		case upd := <-s.certUpdates:
			// The worker finished an off-loop certificate reconfiguration.
			// Its counter is decremented by the worker itself.
			deferred := s.configDeferred.Swap(false)
			if upd.ok {
				s.cfg.Cert = upd.cfg
			} else {
				// The hash was already advanced when this config arrived, so the
				// identical panel sync would be deduplicated and the failed
				// certificate configuration would never be retried. Clearing it
				// makes the next sync.cfg/config poll re-apply the cert config.
				s.lastConfigHash = ""
			}
			if upd.changed || deferred {
				s.applyChanges(ctx, true, false)
			}

		case <-pullTicker.C:
			// When WebSocket is connected, skip REST polling entirely:
			// config/user updates arrive via WS push. A pending
			// reconciliation overrides that — a dropped event or a failed
			// resync poll must still converge while the WS stays up.
			if s.wsClient != nil && s.wsClient.IsConnected() && !s.wsResyncPending.Load() {
				continue
			}
			nlog.Core().Debug("polling from API", "resync_pending", s.wsResyncPending.Load())
			s.pullViaAPIAsync(ctx)

		case result := <-s.pullResults:
			s.applyPullResult(ctx, result)

		case <-wsDiscoveryTicker.C:
			s.wsDiscovery(ctx)

		case status := <-s.wsStatusCh:
			s.handleWSStatus(ctx, status)

		case <-s.machineMailboxCh:
			s.drainMachineMailbox(ctx)

		case event := <-s.wsEvents:
			s.handleWSEvent(ctx, event)
		}
	}
}

func (s *Service) initialSetup(ctx context.Context) error {
	// Register speed limit lookup with kernel unconditionally (before push/poll branch).
	s.kernel.SetSpeedLimitFunc(s.speedTracker.GetLimiter)
	s.kernel.SetDeviceLimitFunc(s.limiter.GetDeviceLimitByUUID)

	bootstrap, err := s.source.Initial(ctx, s.wsMetrics, s.wsEvents, s.wsStatusCh)
	if err != nil {
		return err
	}

	if s.cfg.Node.PushInterval == 0 && bootstrap.PushInterval > 0 {
		s.pushInterval = bootstrap.PushInterval
	} else {
		s.pushInterval = s.cfg.Node.PushInterval
	}
	if s.pushInterval == 0 {
		s.pushInterval = 60
	}

	if s.cfg.Node.PullInterval == 0 && bootstrap.PullInterval > 0 {
		s.pullInterval = bootstrap.PullInterval
	} else {
		s.pullInterval = s.cfg.Node.PullInterval
	}
	if s.pullInterval == 0 {
		s.pullInterval = 60
	}

	if bootstrap.Push != nil {
		s.wsClient = bootstrap.Push
	}
	s.machineMailbox = bootstrap.Mailbox
	if s.machineMailbox != nil {
		s.machineMailboxCh = s.machineMailbox.NotifyCh()
	}
	if bootstrap.Config == nil {
		if bootstrap.Push != nil {
			// In machine mode a shared WS client may be available before the first
			// per-node snapshot arrives. In that case we wait for subsequent WS/REST
			// updates instead of failing startup.
			return nil
		}
		return fmt.Errorf("initial config is nil")
	}
	if err := validateNodeRuntime(s.cfg, s.kernelProtocolsFor(bootstrap.Config), bootstrap.Config, s.cert.TLSCert()); err != nil {
		return err
	}
	if err := s.resolveAutoKernel(bootstrap.Config); err != nil {
		return err
	}

	s.metricsMu.Lock()
	s.lastConfig = bootstrap.Config
	s.metricsMu.Unlock()
	s.lastConfigHash = computeConfigHash(bootstrap.Config)
	s.updateUserState(bootstrap.Users)

	nlog.Core().Info("initial snapshot ready",
		"protocol", bootstrap.Config.Protocol,
		"port", bootstrap.Config.ServerPort,
		"users", len(bootstrap.Users),
	)

	if len(bootstrap.Users) == 0 {
		nlog.Core().Warn("no users, kernel will not start until users are available")
		s.markMailboxReadyAndDrain(ctx)
		return nil
	}

	s.applyRemoteOverrides(ctx, bootstrap.Config, true)
	if !s.startKernel(bootstrap.Config, bootstrap.Users) {
		return fmt.Errorf("start kernel")
	}
	s.markMailboxReadyAndDrain(ctx)
	return nil
}

// applyRemoteOverrides updates service-level settings (log level, cert config)
// from the panel's NodeConfig. syncCert must be true only during startup,
// before the main loop runs; otherwise ACME issuance happens off-loop.
// Returns true if cert paths changed synchronously (kernel restart needed).
func (s *Service) applyRemoteOverrides(ctx context.Context, nc *model.NodeSpec, syncCert bool) bool {
	if nc == nil {
		return false
	}

	// Dynamic Log Level (Kernel)
	if nc.KernelLogLevel != "" && nc.KernelLogLevel != s.cfg.Kernel.LogLevel {
		nlog.Core().Info("kernel log level override", "old", s.cfg.Kernel.LogLevel, "new", nc.KernelLogLevel)
		s.cfg.Kernel.LogLevel = nc.KernelLogLevel
	}

	// Certificate configuration from panel (panel-first: takes precedence over local config)
	if nc.CertConfig != nil {
		return s.applyNodeCert(ctx, nc.CertConfig, syncCert)
	}

	// Legacy fields (deprecated: prefer cert_config)
	if nc.AutoTLS != s.cfg.Cert.AutoTLS {
		nlog.Core().Info("cert: auto_tls policy changed (deprecated field)", "new", nc.AutoTLS)
		s.cfg.Cert.AutoTLS = nc.AutoTLS
	}
	if nc.Domain != "" && nc.Domain != s.cfg.Cert.Domain {
		s.cfg.Cert.Domain = nc.Domain
	}

	return false
}

// applyNodeCert reconfigures the certificate manager. syncCert is true during
// startup (before the main loop), where blocking is harmless and the kernel
// must start with the panel certificate. At runtime the work is handed to a
// background worker so ACME issuance cannot freeze the service loop.
func (s *Service) applyNodeCert(ctx context.Context, newCfg *config.CertConfig, syncCert bool) bool {
	if newCfg == nil {
		return false
	}
	cfgCopy := *newCfg
	cfgCopy.CertDir = s.nodeCertDir(cfgCopy.Domain)

	if !syncCert {
		s.startCertReconfigure(ctx, cfgCopy)
		return false
	}

	changed, err := s.cert.Reconfigure(ctx, cfgCopy)
	if err != nil {
		nlog.Core().Error("failed to apply runtime cert config", "mode", cfgCopy.CertMode, "error", err)
		return false
	}
	s.cfg.Cert = cfgCopy
	if changed {
		msg := fmt.Sprintf("cert: material updated, has_cert=%v", s.cert.HasCert())
		if s.nodeLog != nil {
			s.nodeLog.Info(msg)
		} else {
			nlog.Core().Info(msg)
		}
	}
	return changed
}

// nodeCertDir picks where a panel-pushed certificate is stored. A domain that
// differs from the one in the local config is per-node state: writing it into
// the shared configured directory makes the last node win, and a restart can
// then load a certificate issued for a different domain.
func (s *Service) nodeCertDir(domain string) string {
	if domain == "" || domain == s.cfg.Cert.Domain || s.cfg.Kernel.ConfigDir == "" {
		return s.cfg.Cert.CertDir
	}
	return filepath.Join(s.cfg.Kernel.ConfigDir, "certs")
}

// startCertReconfigure serializes certificate reconfiguration in a background
// goroutine. A config arriving while one run is in flight replaces the pending
// one (latest wins); the running ACME attempt is not interrupted.
func (s *Service) startCertReconfigure(ctx context.Context, cfg config.CertConfig) {
	if s.certCtx != nil {
		// Run owns the worker scope; a retry loop must stop with it.
		ctx = s.certCtx
	}
	s.certMu.Lock()
	if s.certBusy {
		s.certPending = &cfg
		s.certMu.Unlock()
		nlog.Core().Info("cert: reconfigure already running, queued latest config")
		return
	}
	s.certBusy = true
	s.certWorkers.Add(1)
	s.certMu.Unlock()
	go s.runCertReconfigure(ctx, cfg)
}

// Defaults for runtime certificate retries. A later panel push still
// triggers a fresh attempt after the limit is reached.
const (
	certRetryMax       = 5
	certRetryBaseDelay = time.Second
)

func (s *Service) runCertReconfigure(ctx context.Context, cfg config.CertConfig) {
	defer s.certWorkers.Add(-1)

	maxAttempts := s.certRetryAttempts
	if maxAttempts <= 0 {
		maxAttempts = certRetryMax
	}
	base := s.certRetryBase
	if base <= 0 {
		base = certRetryBaseDelay
	}
	reconfigure := s.certReconfigure
	if reconfigure == nil {
		reconfigure = s.cert.Reconfigure
	}

	attempt := 0
	changedAny := false
	okAny := false
	applied := cfg

	for {
		if ctx.Err() != nil {
			// Shutdown cancelled the worker scope: do not run another round
			// (and its backoff wait) for a pending config.
			s.certMu.Lock()
			s.certBusy = false
			s.certMu.Unlock()
			return
		}
		rctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		changed, err := reconfigure(rctx, cfg)
		cancel()
		if err == nil {
			attempt = 0
			okAny = true
			changedAny = changedAny || changed
			applied = cfg
		} else {
			attempt++
			nlog.Core().Error("failed to apply runtime cert config",
				"mode", cfg.CertMode, "attempt", attempt, "error", err)
		}

		s.certMu.Lock()
		next := s.certPending
		s.certPending = nil
		if next != nil {
			// A newer panel config always wins over retrying the failed one.
			cfg = *next
			attempt = 0
			s.certMu.Unlock()
			continue
		}
		if err != nil && attempt < maxAttempts {
			s.certMu.Unlock()
			// Exponential backoff: base*2^attempt (2s, 4s, 8s, 16s by default).
			timer := time.NewTimer(base * time.Duration(1<<attempt))
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				s.certMu.Lock()
				s.certBusy = false
				s.certMu.Unlock()
				return
			}
			continue
		}
		s.certBusy = false
		s.certMu.Unlock()

		// Report once, after every queued config is handled, so the main loop
		// reloads a single time with the final certificate material.
		select {
		case s.certUpdates <- certUpdate{cfg: applied, changed: changedAny, ok: okAny}:
		case <-ctx.Done():
		}
		return
	}
}

// startWSClient starts the push client goroutine if a client is configured.
func (s *Service) startWSClient(ctx context.Context) {
	if s.wsClient == nil {
		return
	}
	wsCtx, wsCancel := context.WithCancel(ctx)
	s.wsCancel = wsCancel
	go s.wsClient.Run(wsCtx)
}

func (s *Service) markMailboxReadyAndDrain(ctx context.Context) {
	if s.machineMailbox == nil {
		return
	}
	// Seed mailbox with bootstrap state so delta events can be applied
	// incrementally instead of always triggering REST reconciliation.
	s.metricsMu.RLock()
	users := s.lastUsers
	config := s.lastConfig
	s.metricsMu.RUnlock()
	s.machineMailbox.SeedBaseline(users, config)
	s.machineMailbox.MarkReady()
	s.drainMachineMailbox(ctx)
}

func (s *Service) drainMachineMailbox(ctx context.Context) {
	if s.machineMailbox == nil {
		return
	}
	state := s.machineMailbox.DrainIfReady()
	if state.HasConfig {
		s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncConfig, Config: state.Config})
	}
	if state.HasUsers {
		s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncUsers, Users: state.Users})
	}
	if state.HasDevices {
		s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncDevices, DeviceUsers: state.DeviceUsers})
	}
	if state.NeedsReconcile {
		s.requestWSResync(ctx, "machine_mailbox_reconcile")
	}
}

// userProtocolRequiresUUID reports whether the current node config validates
// user UUIDs as UUIDs.
func (s *Service) userProtocolRequiresUUID() bool {
	if s.lastConfig == nil {
		return false
	}
	return model.ProtocolRequiresUUID(s.lastConfig.Protocol)
}

func (s *Service) requestWSResync(ctx context.Context, reason string) {
	// Every request advances the generation: a poll that was already in
	// flight when this request arrived does not cover it, so it must not
	// clear the pending flag on completion.
	s.resyncGen.Add(1)
	if !s.wsResyncPending.Swap(true) {
		if s.nodeLog != nil {
			s.nodeLog.Warn("ws state may be stale, scheduling REST reconciliation", "reason", reason)
		} else {
			nlog.Core().Warn("ws state may be stale, scheduling REST reconciliation", "reason", reason)
		}
	}
	s.pullViaAPIAsync(ctx)
}

func (s *Service) wsMetrics() map[string]interface{} {
	status := monitor.Collect()
	m := s.buildMetrics(status)
	m["kernel_status"] = s.kernelRunning()
	return m
}

// handleWSStatus reacts to WS connectivity changes.

// - On disconnect: record timestamp, immediately REST poll.
// - On reconnect: clear disconnect timestamp, REST poll to catch missed events.
func (s *Service) handleWSStatus(ctx context.Context, status controlplane.StatusChange) {
	if status.NeedsResync {
		s.requestWSResync(ctx, "drop_detected")
	}
	if status.Connected {
		s.metricsMu.Lock()
		s.wsDisconnectAt = time.Time{}
		s.metricsMu.Unlock()
		// Use nodeLog if available, otherwise core
		if s.nodeLog != nil {
			s.nodeLog.Info("ws connected")
		} else {
			nlog.Core().Info("ws connected")
		}
		// After reconnect, proactively pull once to ensure we haven't missed
		// any updates during the disconnection window.
		s.pullViaAPIAsync(ctx)
	} else {
		s.metricsMu.Lock()
		if s.wsDisconnectAt.IsZero() {
			s.wsDisconnectAt = time.Now()
		}
		s.metricsMu.Unlock()
		if s.nodeLog != nil {
			s.nodeLog.Info("ws disconnected")
		} else {
			nlog.Core().Info("ws disconnected")
		}
		// Clear global device state on disconnect
		s.kernel.ClearGlobalDevices()
		s.pullViaAPIAsync(ctx)
	}
}

// wsDiscovery periodically checks WS availability:
//
//  1. REST-only mode (wsClient == nil): Re-handshake to check if panel now has
//     WS enabled. If so, create and start a WS client. This handles the case
//     where WS was not enabled at startup but enabled later.
//
//  2. WS disconnected for >10 min: Re-handshake to check if the panel still
//     has WS enabled. If it was disabled, stop the WS client and switch to
//     REST-only. An existing client is never replaced here: it reconnects
//     itself with its original URL, so a changed ws_url only takes effect on
//     service restart or config reload.
func (s *Service) wsDiscovery(ctx context.Context) {
	if !s.source.SupportsDiscovery() {
		return
	}

	needsCheck := false
	if s.wsClient == nil {
		needsCheck = true
		nlog.Core().Debug("push discovery: no push client, checking if control plane enabled push")
	} else if !s.wsDisconnectAt.IsZero() && time.Since(s.wsDisconnectAt) > 10*time.Minute {
		needsCheck = true
		nlog.Core().Debug("push discovery: push disconnected for >10min, re-checking")
	}
	if !needsCheck {
		return
	}

	pushClient, err := s.source.Discover(ctx, s.wsMetrics, s.wsEvents, s.wsStatusCh)
	if err != nil {
		nlog.Core().Debug("push discovery failed", "error", err)
		return
	}
	if s.source.SupportsPolling() {
		s.pullViaAPIAsync(ctx)
	}

	if pushClient != nil {
		if s.wsClient == nil {
			nlog.Core().Info("push discovery: control plane enabled push, creating client")
			s.metricsMu.Lock()
			s.wsClient = pushClient
			s.wsDisconnectAt = time.Time{}
			s.metricsMu.Unlock()
			s.startWSClient(ctx)
		}
	} else if s.wsClient != nil {
		nlog.Core().Info("push discovery: control plane disabled push, switching to polling")
		if s.wsCancel != nil {
			s.wsCancel()
		}
		s.metricsMu.Lock()
		s.wsClient = nil
		s.wsDisconnectAt = time.Time{}
		s.metricsMu.Unlock()
		s.wsCancel = nil
	}
}

// handleWSEvent processes data events received via WebSocket
func (s *Service) handleWSEvent(ctx context.Context, event controlplane.Event) {
	switch event.Type {
	case controlplane.EventSyncConfig:
		if event.Config == nil {
			return
		}
		newConfigHash := computeConfigHash(event.Config)
		if newConfigHash == s.lastConfigHash {
			return
		}
		if err := validateNodeRuntime(s.cfg, s.kernelProtocolsFor(event.Config), event.Config, s.cert.TLSCert()); err != nil {
			nlog.Core().Warn("ws config validation failed, ignoring update", "error", err)
			return
		}
		// Validation passed — safe to swap the kernel for this spec now.
		if err := s.resolveAutoKernel(event.Config); err != nil {
			nlog.Core().Warn("kernel auto-selection failed, ignoring update", "error", err)
			return
		}
		s.stateSeq.Add(1)
		// Initialize nodeLog on first config
		if s.nodeLog == nil {
			s.nodeLog = nlog.ForNode(nodeDisplayProtocol(event.Config), event.Config.ServerPort)
		}
		s.nodeLog.Info(fmt.Sprintf("config updated, %d users", len(s.lastUsers)))
		s.metricsMu.Lock()
		s.lastConfig = event.Config
		s.metricsMu.Unlock()
		s.lastConfigHash = newConfigHash
		s.applyRemoteOverrides(ctx, event.Config, false)
		s.applyChanges(ctx, true, false)

	case controlplane.EventSyncUsers:
		if event.Users == nil {
			return
		}
		event.Users = model.SanitizeUserSpecs(event.Users, s.userProtocolRequiresUUID())
		newHash := computeUserHash(event.Users)
		if newHash == s.lastUserHash {
			return
		}
		s.stateSeq.Add(1)
		if s.nodeLog != nil {
			s.nodeLog.Info(fmt.Sprintf("users updated, %d users", len(event.Users)))
		}
		// Pure-WS bootstrap: when the handshake returns no REST snapshot (WS
		// enabled), REST pulls are skipped while the WS is connected. The
		// update must seed lastUsers itself or the kernel never starts.
		s.applyUserUpdate(ctx, event.Users, newHash)

	case controlplane.EventSyncUserDelta:
		if len(event.DeltaUsers) == 0 {
			return
		}
		requireUUID := s.userProtocolRequiresUUID()
		event.DeltaUsers = model.SanitizeUserDeltas(event.DeltaUsers, event.DeltaAction, requireUUID)
		if len(event.DeltaUsers) == 0 {
			return
		}
		s.stateSeq.Add(1)
		// The panel emits one delta per edited user. Applying each on the main
		// loop costs a full pass over every user (limiter maps, speed buckets,
		// user-map rebuild, hash), and a burst overflows wsEvents, which
		// triggers a full REST resync. Merge the deltas already queued and
		// apply the resulting set once.
		batch := []controlplane.Event{event}
		var following []controlplane.Event
	drain:
		for len(batch) < maxQueuedDeltas {
			select {
			case next := <-s.wsEvents:
				if next.Type == controlplane.EventSyncUserDelta && len(next.DeltaUsers) > 0 {
					next.DeltaUsers = model.SanitizeUserDeltas(next.DeltaUsers, next.DeltaAction, requireUUID)
					if len(next.DeltaUsers) == 0 {
						continue
					}
					batch = append(batch, next)
					continue
				}
				following = append(following, next)
			default:
				break drain
			}
		}
		if len(batch) == 1 {
			if s.nodeLog != nil {
				s.nodeLog.Info(fmt.Sprintf("users delta: %s, %d users", event.DeltaAction, len(event.DeltaUsers)))
			}
			s.applyUserDelta(ctx, event.DeltaAction, event.DeltaUsers)
		} else {
			if s.nodeLog != nil {
				s.nodeLog.Info(fmt.Sprintf("users deltas merged: %d events", len(batch)))
			}
			s.applyUserDeltaBatch(ctx, batch)
		}
		// Events dequeued behind the batch keep their original order.
		for _, next := range following {
			s.handleWSEvent(ctx, next)
		}

	case controlplane.EventSyncDevices:
		// Sync global device state
		if event.DeviceUsers != nil {
			s.kernel.UpdateGlobalDevices(event.DeviceUsers)
		}

	default:
		nlog.Core().Debug(fmt.Sprintf("unknown ws event: %v", event.Type))
	}
}

// pullViaAPIAsync fetches config/users from the panel API in a background
// goroutine and sends the result to pullResults for the main goroutine to apply.
func (s *Service) pullViaAPIAsync(ctx context.Context) {
	if !s.source.SupportsPolling() {
		return
	}
	if !s.pullActive.CompareAndSwap(false, true) {
		nlog.Core().Debug("pull already in progress, skipping")
		return
	}
	if s.pullBackoff.shouldSkip() {
		nlog.Core().Debug("skipping pull due to backoff")
		s.pullActive.Store(false)
		return
	}

	currentConfigHash := s.lastConfigHash

	go func() {
		defer s.pullActive.Store(false)
		// Captured before the request: state applied while the snapshot is in
		// flight makes this result older than what the main loop holds.
		result := pullResult{seq: s.stateSeq.Load(), gen: s.resyncGen.Load()}

		snapshot, err := s.source.Poll(ctx)
		if err != nil {
			nlog.Core().Error("poll control plane failed", "error", err)
			s.pullBackoff.onFailure()
			// Keep wsResyncPending set: the pull ticker retries even while
			// the WS is connected.
			return
		}
		s.pullBackoff.onSuccess()
		if snapshot.Config != nil {
			result.config = snapshot.Config
			result.configHash = computeConfigHash(snapshot.Config)
			if result.configHash == currentConfigHash {
				result.config = nil
			}
		}
		if snapshot.Users != nil {
			result.users = snapshot.Users
			result.userHash = computeUserHash(snapshot.Users)
		}

		select {
		case s.pullResults <- result:
		case <-ctx.Done():
		}
	}()
}

// applyPullResult processes the result of an async pullViaAPI on the main goroutine.
func (s *Service) applyPullResult(ctx context.Context, result pullResult) {
	// The snapshot predates state that has since been applied: applying it
	// would re-enable removed users or roll config back to the old spec. Keep
	// the resync pending so the pull ticker fetches a fresh snapshot.
	if result.seq != s.stateSeq.Load() {
		nlog.Core().Debug("dropping stale poll result, newer state already applied")
		s.wsResyncPending.Store(true)
		return
	}
	// Any applied poll result becomes the new state baseline.
	s.stateSeq.Add(1)
	// A poll only satisfies the requests issued before it started; requests
	// that arrived while it was in flight keep the flag set for the next tick.
	defer func() {
		if result.gen >= s.resyncGen.Load() {
			s.wsResyncPending.Store(false)
		}
	}()
	configChanged := false

	if result.config != nil {
		if err := validateNodeRuntime(s.cfg, s.kernelProtocolsFor(result.config), result.config, s.cert.TLSCert()); err != nil {
			nlog.Core().Warn("runtime config validation failed", "error", err)
			result.config = nil
		} else if err := s.resolveAutoKernel(result.config); err != nil {
			nlog.Core().Warn("kernel auto-selection failed", "error", err)
			result.config = nil
		} else {
			configChanged = true
			// Initialize or update node logger
			if s.nodeLog == nil {
				s.nodeLog = nlog.ForNode(nodeDisplayProtocol(result.config), result.config.ServerPort)
			}
			s.nodeLog.Info(fmt.Sprintf("config updated, %d users", len(s.lastUsers)))
			s.metricsMu.Lock()
			s.lastConfig = result.config
			s.metricsMu.Unlock()
			s.lastConfigHash = result.configHash
			if s.applyRemoteOverrides(ctx, result.config, false) {
				configChanged = true
			}
		}
	}

	if result.users != nil {
		usersChanged := result.userHash != s.lastUserHash

		if usersChanged && !configChanged {
			s.applyUserUpdate(ctx, result.users, result.userHash)
		} else if usersChanged {
			s.updateUserState(result.users)
		}
	}

	if configChanged {
		s.applyChanges(ctx, true, false)
	}
}

// ─── User state helpers ─────────────────────────────────────────────────────

func (s *Service) updateUserState(users []model.UserSpec) {
	if users == nil {
		users = []model.UserSpec{}
	}
	prev := append([]model.UserSpec(nil), s.lastUsers...)
	_, _ = s.prepareUserState(users, "")
	s.forgetRemovedUsers(prev, users)
}

// forgetRemovedUsers drops tracker baselines for users no longer registered.
func (s *Service) forgetRemovedUsers(prev, next []model.UserSpec) {
	if len(prev) == 0 {
		return
	}
	keep := make(map[int]struct{}, len(next))
	for _, u := range next {
		keep[u.ID] = struct{}{}
	}
	ids := make([]int, 0, len(prev))
	for _, u := range prev {
		if _, ok := keep[u.ID]; !ok {
			ids = append(ids, u.ID)
		}
	}
	s.tracker.ForgetUsers(ids)
}

func (s *Service) prepareUserState(users []model.UserSpec, knownHash string) (prevUsers []model.UserSpec, prevHash string) {
	if users == nil {
		users = []model.UserSpec{}
	}

	s.metricsMu.RLock()
	prevUsers = append([]model.UserSpec(nil), s.lastUsers...)
	s.metricsMu.RUnlock()
	prevHash = s.lastUserHash

	s.limiter.UpdateUsers(users)
	s.speedTracker.UpdateBuckets()

	s.metricsMu.Lock()
	s.lastUsers = append([]model.UserSpec(nil), users...)
	s.metricsMu.Unlock()
	if knownHash != "" {
		s.lastUserHash = knownHash
	} else {
		s.lastUserHash = computeUserHash(users)
	}
	return prevUsers, prevHash
}

// prepareUserDeltaState updates the derived indexes for exactly the users a
// panel delta touched, instead of rebuilding both limiter maps and every speed
// bucket for the whole table on the main loop.
func (s *Service) prepareUserDeltaState(users, changed []model.UserSpec, action string) (prevUsers []model.UserSpec, prevHash string) {
	s.metricsMu.RLock()
	prevUsers = append([]model.UserSpec(nil), s.lastUsers...)
	s.metricsMu.RUnlock()
	prevHash = s.lastUserHash

	if action == "remove" {
		ids := make([]int, 0, len(changed))
		for _, u := range changed {
			if u.ID > 0 {
				ids = append(ids, u.ID)
			}
		}
		s.limiter.UpdateUsersDelta(nil, ids)
		s.speedTracker.UpdateBucketsDelta(nil, ids)
	} else {
		s.limiter.UpdateUsersDelta(changed, nil)
		s.speedTracker.UpdateBucketsDelta(changed, nil)
	}

	s.metricsMu.Lock()
	s.lastUsers = append([]model.UserSpec(nil), users...)
	s.metricsMu.Unlock()
	s.lastUserHash = computeUserHash(users)
	return prevUsers, prevHash
}

func (s *Service) restoreUserState(users []model.UserSpec, hash string) {
	if users == nil {
		users = []model.UserSpec{}
	}
	s.limiter.UpdateUsers(users)
	s.speedTracker.UpdateBuckets()
	s.metricsMu.Lock()
	s.lastUsers = append([]model.UserSpec(nil), users...)
	s.metricsMu.Unlock()
	s.lastUserHash = hash
}

// nodeDisplayProtocol is the protocol name used in log prefixes. Hysteria v1
// and v2 share the protocol field and are told apart by Version.
func nodeDisplayProtocol(nc *model.NodeSpec) string {
	if nc == nil {
		return ""
	}
	if nc.Protocol == "hysteria" && nc.Version == 2 {
		return "hysteria2"
	}
	return nc.Protocol
}

// startKernel starts (or restarts) the kernel with the given config/users and
// records the successfully applied state. Returns false on error.
func (s *Service) startKernel(nc *model.NodeSpec, users []model.UserSpec) bool {
	if err := s.kernel.Start(nc, users, s.cert.TLSCert()); err != nil {
		nlog.Core().Error("failed to start kernel", "error", err)
		// A transient failure (EADDRINUSE during a reload, cert not readable
		// yet) must not be cached as "applied": the next identical sync would
		// otherwise be deduped by the hash checks and the node would stay down
		// until the config changed or the process restarted.
		s.lastConfigHash = ""
		s.lastUserHash = ""
		return false
	}

	// A successful start (including one triggered by an explicit panel event)
	// clears the periodic-retry backoff, so a later failure starts retrying
	// immediately instead of inheriting an old skip count.
	s.startBackoff.onSuccess()

	// Initialize node logger on first successful start
	if s.nodeLog == nil {
		s.nodeLog = nlog.ForNode(nodeDisplayProtocol(nc), nc.ServerPort)
	}
	s.probeOutboundsAsync(nc)
	s.speedTracker.SetLogCallback(func(msg string) {
		fullMsg := fmt.Sprintf("speedtracker: %s active_limiters=%d", msg, s.speedTracker.LimitedUserCount())
		s.nodeLog.Info(fullMsg)
	})
	s.nodeLog.Info(fmt.Sprintf("started, %d users", len(users)))
	return true
}

// ensureRunning starts the kernel if it is not running and there are users +
// config available. Returns true if the kernel is running afterwards.
// Used by explicit panel events, which are infrequent enough to retry at once.
func (s *Service) ensureRunning() bool {
	if s.kernel.IsRunning() {
		return true
	}
	if len(s.lastUsers) > 0 && s.lastConfig != nil {
		return s.startKernel(s.lastConfig, s.lastUsers)
	}
	return false
}

// retryKernel is the periodic fallback for a kernel that failed to start and
// then received no new panel sync (WS connected, identical hashes, REST ETag
// 304). Backoff keeps a permanently broken config from rebuilding every tick.
func (s *Service) retryKernel() {
	if s.kernel.IsRunning() || len(s.lastUsers) == 0 || s.lastConfig == nil {
		return
	}
	if s.startBackoff.shouldSkip() {
		return
	}
	if s.startKernel(s.lastConfig, s.lastUsers) {
		s.startBackoff.onSuccess()
		return
	}
	s.startBackoff.onFailure()
}

// ─── User update entry points ───────────────────────────────────────────────

// applyUserUpdate replaces the full user set and hot-swaps the kernel.
// Called from WS sync.users and REST polling.
func (s *Service) applyUserUpdate(ctx context.Context, users []model.UserSpec, newHash string) {
	if !s.kernel.IsRunning() {
		// No kernel yet (config-only bootstrap, or the panel had no users when
		// the node started). Persist the desired state and start from it:
		// returning early would drop the users forever, because the panel's
		// ETag no longer changes and later polls return 304.
		s.updateUserState(users)
		if newHash != "" {
			s.lastUserHash = newHash
		}
		s.ensureRunning()
		return
	}

	prevUsers, prevHash := s.prepareUserState(users, newHash)
	added, removed, err := s.kernel.UpdateUsers(users)
	if err != nil {
		nlog.Core().Warn(fmt.Sprintf("UpdateUsers failed, restarting kernel: %v", err))
		if !s.startKernel(s.lastConfig, users) {
			s.restoreUserState(prevUsers, prevHash)
			return
		}
		s.forgetRemovedUsers(prevUsers, users)
		return
	}
	s.forgetRemovedUsers(prevUsers, users)
	if s.nodeLog != nil && (added > 0 || removed > 0) {
		s.nodeLog.Info(fmt.Sprintf("users updated: +%d -%d", added, removed))
	}
}

// applyUserDelta applies an incremental user change (add or remove) directly
// via the kernel's atomic user API. Kernel updates run before updateUserState.
func (s *Service) applyUserDelta(ctx context.Context, action string, deltaUsers []model.UserSpec) {
	switch action {
	case "add":
		// Defensive check for empty or nil deltaUsers
		if deltaUsers == nil || len(deltaUsers) == 0 {
			return
		}
		merged := mergeUsers(s.lastUsers, deltaUsers)

		if !s.kernel.IsRunning() {
			s.updateUserState(merged)
			s.ensureRunning()
			return
		}

		// Index the current users once: the previous nested scan was
		// O(users × deltas) on the main loop (5M comparisons for a 10k-user
		// panel and a 500-user batch).
		prevByID := make(map[int]model.UserSpec, len(s.lastUsers))
		for _, old := range s.lastUsers {
			prevByID[old.ID] = old
		}
		rotationFailed := false
		for _, delta := range deltaUsers {
			if old, ok := prevByID[delta.ID]; ok && old.UUID != delta.UUID {
				if _, err := s.kernel.RemoveUsers([]model.UserSpec{old}); err != nil {
					// Ignoring this left the old credential active in the kernel
					// while the service moved on to the new UUID.
					nlog.Core().Warn("RemoveUsers failed for rotated user, applying full update",
						"user", old.ID, "error", err)
					rotationFailed = true
				}
			}
		}
		if rotationFailed {
			s.applyUserUpdate(ctx, merged, "")
			return
		}

		prevUsers, prevHash := s.prepareUserDeltaState(merged, deltaUsers, "add")
		added, err := s.kernel.AddUsers(deltaUsers)
		if err != nil {
			nlog.Core().Warn(fmt.Sprintf("AddUsers failed: %v, falling back to UpdateUsers", err))
			if _, _, err := s.kernel.UpdateUsers(merged); err != nil {
				nlog.Core().Error(fmt.Sprintf("UpdateUsers fallback failed: %v", err))
				s.restoreUserState(prevUsers, prevHash)
				return
			}
		}
		if s.nodeLog != nil && added > 0 {
			s.nodeLog.Info(fmt.Sprintf("users added: +%d", added))
		}

	case "remove":
		// Defensive check for empty or nil deltaUsers
		if deltaUsers == nil || len(deltaUsers) == 0 {
			return
		}
		filtered := subtractUsers(s.lastUsers, deltaUsers)

		if !s.kernel.IsRunning() {
			s.updateUserState(filtered)
			return
		}

		prevUsers, prevHash := s.prepareUserDeltaState(filtered, deltaUsers, "remove")
		removed, err := s.kernel.RemoveUsers(deltaUsers)
		if err != nil {
			nlog.Core().Warn(fmt.Sprintf("RemoveUsers failed: %v, falling back to UpdateUsers", err))
			if _, _, err := s.kernel.UpdateUsers(filtered); err != nil {
				nlog.Core().Error(fmt.Sprintf("UpdateUsers fallback failed: %v", err))
				s.restoreUserState(prevUsers, prevHash)
				return
			}
		}
		ids := make([]int, 0, len(deltaUsers))
		for _, u := range deltaUsers {
			if u.ID > 0 {
				ids = append(ids, u.ID)
			}
		}
		s.tracker.ForgetUsers(ids)
		if s.nodeLog != nil && removed > 0 {
			s.nodeLog.Info(fmt.Sprintf("users removed: -%d", removed))
		}

	default:
		nlog.Core().Warn(fmt.Sprintf("unknown user delta action: %s", action))
	}
}

// maxQueuedDeltas bounds how many queued user-delta events one batch merge
// consumes, so a permanently busy queue cannot starve the other channels.
const maxQueuedDeltas = 64

// applyUserDeltaBatch replays a run of queued add/remove deltas onto the
// current user set and applies the result once. Per-user add/remove ordering
// is preserved: a later action for the same user wins.
func (s *Service) applyUserDeltaBatch(ctx context.Context, events []controlplane.Event) {
	byID := make(map[int]model.UserSpec, len(s.lastUsers))
	for _, u := range s.lastUsers {
		byID[u.ID] = u
	}
	for _, event := range events {
		switch event.DeltaAction {
		case "add":
			for _, u := range event.DeltaUsers {
				byID[u.ID] = u
			}
		case "remove":
			for _, u := range event.DeltaUsers {
				delete(byID, u.ID)
			}
		default:
			nlog.Core().Warn("unknown user delta action in batch", "action", event.DeltaAction)
		}
	}
	merged := make([]model.UserSpec, 0, len(byID))
	for _, u := range byID {
		merged = append(merged, u)
	}
	s.applyUserUpdate(ctx, merged, "")
}

// mergeUsers overlays deltaUsers onto base (keyed by ID). New users are
// appended, existing users have their properties overwritten.
func mergeUsers(base, delta []model.UserSpec) []model.UserSpec {
	// Handle nil slices
	if base == nil {
		base = []model.UserSpec{}
	}
	if delta == nil {
		return base
	}

	m := make(map[int]model.UserSpec, len(base))
	for _, u := range base {
		m[u.ID] = u
	}
	for _, u := range delta {
		m[u.ID] = u
	}
	out := make([]model.UserSpec, 0, len(m))
	for _, u := range m {
		out = append(out, u)
	}
	return out
}

// subtractUsers returns base with all users in delta removed.
func subtractUsers(base, delta []model.UserSpec) []model.UserSpec {
	if base == nil {
		return nil
	}
	if delta == nil || len(delta) == 0 {
		return base
	}
	removeSet := make(map[int]struct{}, len(delta))
	for _, u := range delta {
		removeSet[u.ID] = struct{}{}
	}
	out := make([]model.UserSpec, 0, len(base))
	for _, u := range base {
		if _, ok := removeSet[u.ID]; !ok {
			out = append(out, u)
		}
	}
	return out
}

// applyChanges applies config changes to the kernel. User-only changes are
// handled by applyUserUpdate/applyUserDelta directly via the atomic user API.
func (s *Service) applyChanges(ctx context.Context, configChanged, usersChanged bool) {
	if !configChanged {
		return
	}

	if s.certWorkers.Load() > 0 {
		// A certificate reconfiguration is running; normally wait for the new
		// material so the kernel loads once (the certUpdates handler replays
		// this). A stuck ACME attempt must not block unrelated config changes
		// indefinitely: after certDeferMax the config applies with the current
		// certificate and the certificate update reloads again.
		if s.certDeferSince.IsZero() {
			s.certDeferSince = time.Now()
		}
		const certDeferMax = 2 * time.Minute
		if time.Since(s.certDeferSince) < certDeferMax {
			s.configDeferred.Store(true)
			nlog.Core().Debug("config change deferred until certificate reconfiguration completes")
			return
		}
		nlog.Core().Warn("certificate reconfiguration is taking too long; applying the config with the current certificate")
	}
	s.certDeferSince = time.Time{}

	if s.lastConfig == nil || len(s.lastUsers) == 0 {
		if len(s.lastUsers) == 0 {
			s.kernel.Stop()
		}
		return
	}

	// If config changed, delegate to kernel.Reload. The kernel implementation
	// decides whether to hot-swap users, reconstruct inbounds, or restart itself.
	if configChanged && s.kernel.IsRunning() {
		if err := s.kernel.Reload(s.lastConfig, s.lastUsers, s.cert.TLSCert()); err != nil {
			nlog.Core().Warn(fmt.Sprintf("reload failed, restarting: %v", err))
			s.startKernel(s.lastConfig, s.lastUsers)
		} else {
			if s.nodeLog != nil {
				s.nodeLog.Info(fmt.Sprintf("config updated, %d users", len(s.lastUsers)))
			}
			s.probeOutboundsAsync(s.lastConfig)
		}
	} else if !s.kernel.IsRunning() {
		s.startKernel(s.lastConfig, s.lastUsers)
	}
}

// probeOutboundsAsync dials the TCP-based custom outbound endpoints in the
// background and warns about unreachable ones. Routing rules that send traffic
// into a dead outbound otherwise surface only as per-connection timeouts.
// Deduped on the outbound set so repeated sync.config pushes do not re-dial.
func (s *Service) probeOutboundsAsync(nc *model.NodeSpec) {
	if nc == nil || len(nc.CustomOutbounds) == 0 {
		return
	}
	hash := kernel.ComputeHash(&model.NodeSpec{CustomOutbounds: nc.CustomOutbounds}, nil)
	if prev, _ := s.probeHash.Load().(string); prev == hash {
		return
	}
	s.probeHash.Store(hash)

	outbounds := nc.CustomOutbounds
	go func() {
		for _, result := range kernel.ProbeCustomOutbounds(outbounds, 5*time.Second) {
			nlog.Core().Warn("custom outbound endpoint unreachable",
				"tag", result.Tag,
				"protocol", result.Protocol,
				"endpoint", result.Endpoint,
				"error", result.Err,
				"hint", "traffic routed to this outbound will fail; check the upstream server, its firewall/allowlist, and DNS")
		}
	}()
}

func (s *Service) trackAndEnforce(ctx context.Context) {
	if !s.kernel.IsRunning() {
		return
	}

	traffic, aliveIPs, connCount, err := s.kernel.GetUserTraffic(ctx)
	if err != nil {
		nlog.Core().Debug("get user traffic failed", "error", err)
		return
	}

	s.tracker.Process(traffic, aliveIPs, connCount)

	// Only log stats if there's actual traffic or connections
	if connCount > 0 || len(traffic) > 0 {
		if s.nodeLog != nil {
			s.nodeLog.Debug(fmt.Sprintf("tracker: %d conns, %d users online", connCount, len(traffic)))
		} else {
			nlog.TrackerStats(connCount, len(traffic))
		}
	}
}

// pushReportAsync sends the report in a background goroutine so the select
// loop is never blocked by slow HTTP. Only one push runs at a time.
func (s *Service) pushReportAsync() {
	if !s.sink.SupportsReporting() {
		return
	}
	if !s.pushActive.CompareAndSwap(false, true) {
		nlog.Core().Debug("push already in progress, skipping")
		return
	}
	if s.pushBackoff.shouldSkip() {
		nlog.Core().Debug("skipping report due to backoff")
		s.pushActive.Store(false)
		return
	}

	traffic := s.tracker.FlushTraffic()
	aliveIPs := s.tracker.FlushAliveIPs(tracker.ConsumerReport)
	online := s.tracker.CurrentOnline()

	s.pushInFlight.Add(1)
	go func() {
		defer s.pushInFlight.Add(-1)
		defer s.pushActive.Store(false)
		// System stats (procfs/statfs) must not block the main loop that
		// handles WS events and kernel user updates.
		status := monitor.Collect()
		metrics := s.buildMetrics(status)
		metrics["kernel_status"] = s.kernelRunning()
		if err := s.sink.Report(controlplane.ReportPayload{Traffic: traffic, Alive: aliveIPs, Online: online, CPU: status.CPU, Mem: [2]uint64{status.MemTotal, status.MemUsed}, Swap: [2]uint64{status.SwapTotal, status.SwapUsed}, Disk: [2]uint64{status.DiskTotal, status.DiskUsed}, Metrics: metrics}); err != nil {
			nlog.Core().Warn("failed to push report", "error", err)
			if len(traffic) > 0 {
				s.tracker.RestoreTraffic(traffic)
			}
			if len(aliveIPs) > 0 {
				// Alive IPs are a full snapshot, not a delta: drop the change
				// cache so the next flush resends everything.
				s.tracker.MarkAliveIPsStale()
			}
			s.pushBackoff.onFailure()
			return
		}
		s.pushBackoff.onSuccess()
		nlog.ReportPushed(len(traffic), len(online))
	}()
}

// pushReportSyncBounded runs the final report with the shutdown budget. The
// payload maps are flushed and owned by the goroutine, so a late completion
// cannot race a tracker mutation; the daemon's hard kill bounds the rest.
func (s *Service) pushReportSyncBounded() {
	limit := s.finalReportWait
	if limit <= 0 {
		limit = 4 * time.Second
	}
	done := make(chan struct{})
	go func() {
		s.pushReportSync()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(limit):
		nlog.Core().Warn("final report did not finish within the shutdown budget", "limit", limit)
	}
}

// pushReportSync is used only during shutdown to ensure final data is sent.
func (s *Service) pushReportSync() {
	if !s.sink.SupportsReporting() {
		return
	}
	traffic := s.tracker.FlushTraffic()
	aliveIPs := s.tracker.FlushAliveIPs(tracker.ConsumerReport)
	online := s.tracker.CurrentOnline()
	status := monitor.Collect()
	metrics := s.buildMetrics(status)
	metrics["kernel_status"] = s.kernelRunning()

	if err := s.sink.Report(controlplane.ReportPayload{Traffic: traffic, Alive: aliveIPs, Online: online, CPU: status.CPU, Mem: [2]uint64{status.MemTotal, status.MemUsed}, Swap: [2]uint64{status.SwapTotal, status.SwapUsed}, Disk: [2]uint64{status.DiskTotal, status.DiskUsed}, Metrics: metrics}); err != nil {
		nlog.Core().Warn("failed to push final report", "error", err)
	}
}

// buildMetrics aggregates node-level metrics to be reported to the panel.
// This includes active connections, per-core CPU, GC stats, API call stats,
// WebSocket status, and limiter hit counts.
func (s *Service) buildMetrics(status monitor.Status) map[string]interface{} {
	s.metricsMu.RLock()
	lastUsers := s.lastUsers
	wsClient := s.wsClient
	s.metricsMu.RUnlock()

	m := make(map[string]interface{})
	online := s.tracker.CurrentOnline()

	m["uptime"] = status.Uptime
	m["goroutines"] = status.Goroutines

	// Active connections (last measured during tracker.Process()).
	m["active_connections"] = s.tracker.ActiveConnections()
	m["active_users"] = len(online)
	m["total_users"] = len(lastUsers)

	// Speed
	m["inbound_speed"] = s.tracker.InboundSpeed()
	m["outbound_speed"] = s.tracker.OutboundSpeed()

	// Per-core CPU usage (if available).
	if len(status.CPUPerCore) > 0 {
		m["cpu_per_core"] = status.CPUPerCore
	}

	m["load"] = map[string]interface{}{
		"load1":  status.Load1,
		"load5":  status.Load5,
		"load15": status.Load15,
	}

	// Speed Limiter metrics
	m["speed_limiter"] = map[string]interface{}{
		"has_limits":    s.speedTracker.HasLimits(),
		"limited_users": s.speedTracker.LimitedUserCount(),
	}

	// GC metrics.
	m["gc"] = map[string]interface{}{
		"num_gc":        status.NumGC,
		"last_pause_ms": status.LastPauseMS,
	}

	// API metrics.
	api := s.source.Metrics()
	m["api"] = map[string]interface{}{
		"success": api.Success,
		"failure": api.Failure,
	}

	// WebSocket status.
	wsEnabled := wsClient != nil
	wsConnected := wsEnabled && wsClient.IsConnected()
	m["ws"] = map[string]interface{}{
		"enabled":   wsEnabled,
		"connected": wsConnected,
	}

	return m
}

// computeConfigHash returns a deterministic hash of the node config.
// It uses JSON marshaling to ensure all fields are captured, ensuring that
// any configuration change correctly triggers a kernel reload.
func computeConfigHash(cfg *model.NodeSpec) string {
	if cfg == nil {
		return ""
	}
	h := sha256.New()
	// We marshal the entire config to be safe. Node config updates are low-frequency,
	// so the robustness of capturing all fields outweighs the micro-performance of manual hashing.
	data, _ := json.Marshal(cfg)
	h.Write(data)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// computeUserHash returns a deterministic hash of the user list for change detection.
// Uses direct byte encoding instead of binary.Write to avoid reflection overhead.
func computeUserHash(users []model.UserSpec) string {
	sorted := make([]model.UserSpec, len(users))
	copy(sorted, users)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	h := sha256.New()
	var idBuf [8]byte
	uuidBuf := make([]byte, 0, 64)
	for _, u := range sorted {
		binary.LittleEndian.PutUint64(idBuf[:], uint64(u.ID))
		h.Write(idBuf[:])
		// Reuse the scratch buffer: io.WriteString allocates per user.
		uuidBuf = append(uuidBuf[:0], u.UUID...)
		h.Write(uuidBuf)
		binary.LittleEndian.PutUint64(idBuf[:], uint64(u.SpeedLimit))
		h.Write(idBuf[:])
		binary.LittleEndian.PutUint64(idBuf[:], uint64(u.DeviceLimit))
		h.Write(idBuf[:])
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// ─── Device management ──────────────────────────────────────────────────

// sendDeviceBatch reports local device snapshot to panel via WS.
func (s *Service) sendDeviceBatch() {
	if s.wsClient == nil || !s.wsClient.IsConnected() {
		return
	}

	devices := s.tracker.FlushAliveIPs(tracker.ConsumerDevices)
	// FlushAliveIPs returns nil if no changes since last flush
	if devices == nil {
		nlog.Core().Debug("device snapshot unchanged, skipping")
		return
	}
	if !s.sink.ReportDevices(s.wsClient, devices) {
		// FlushAliveIPs already advanced the tracker cursor; without this the
		// snapshot would be lost when the write channel was full or the link
		// dropped between the IsConnected check and the enqueue.
		s.tracker.MarkAliveIPsStale()
		nlog.Core().Debug("device snapshot not delivered, will retry", "users", len(devices))
		return
	}
	nlog.Core().Debug("device snapshot sent", "users", len(devices))
}

// reportDevices periodically reports device snapshot to panel.
func (s *Service) reportDevices() {
	s.sendDeviceBatch()
}

// kernelProtocolsFor returns the protocol list validation should check
// against: the running kernel's, unless auto mode would switch kernels for
// this spec — then the resolved type's list. Lets validation reject a config
// before the kernel swap happens, so a rejected update leaves the old kernel
// untouched and running.
func (s *Service) kernelProtocolsFor(spec *model.NodeSpec) []string {
	name := strings.ToLower(strings.TrimSpace(s.cfg.Kernel.Type))
	if name == "auto" && spec != nil {
		resolved := model.ResolveKernelForNode(spec, s.cfg.Kernel)
		if !matchesResolvedKernel(s.kernel, resolved) {
			if k := s.buildKernel(resolved); k != nil {
				return k.Protocols()
			}
		}
	}
	return s.kernel.Protocols()
}

// ─── Runtime validation ─────────────────────────────────────────────────

// resolveAutoKernel aligns s.kernel with the spec when kernel.type is auto.
// It is a no-op for concrete kernel types. Call only AFTER validateNodeRuntime
// passed for this spec (via kernelProtocolsFor), so a rejected update never
// stops the running kernel. Runs on the main loop only.
func (s *Service) resolveAutoKernel(spec *model.NodeSpec) error {
	name := strings.ToLower(strings.TrimSpace(s.cfg.Kernel.Type))
	if name != "auto" || spec == nil {
		return nil
	}
	resolved := model.ResolveKernelForNode(spec, s.cfg.Kernel)
	if _, err := s.ensureKernelResolved(spec, resolved); err != nil {
		return err
	}
	nlog.Core().Info("kernel auto-selected",
		"protocol", spec.Protocol, "network", spec.Network, "kernel", resolved)
	return nil
}

func validateNodeRuntime(cfg *config.Config, kcfgSupported []string, spec *model.NodeSpec, tls kernel.TLSCert) error {
	if spec == nil {
		return fmt.Errorf("node spec is nil")
	}
	kernelType := cfgKernelType(cfg)
	if !containsString(kcfgSupported, spec.Protocol) {
		return fmt.Errorf("protocol %q is not supported by kernel %q", spec.Protocol, cfg.Kernel.Type)
	}
	// sing-box cannot do vmess+Reality; a pinned singbox kernel would start a
	// plaintext inbound (Reality clients rejected, plaintext accepted). Auto
	// mode resolves this to xray, so only explicit singbox lands here.
	if kernelType == "singbox" && spec.Protocol == "vmess" && spec.TLS == 2 {
		return fmt.Errorf("vmess with Reality would silently run plaintext on sing-box; use kernel xray or auto")
	}
	if err := validateTLSRequirements(spec, tls, kernelType, cfg.Kernel.AllowPlaintextTLS); err != nil {
		return err
	}
	if err := validateRuntimeCertConfig(spec); err != nil {
		return err
	}
	return nil
}

func validateTLSRequirements(spec *model.NodeSpec, tls kernel.TLSCert, kernelType string, allowPlaintext bool) error {
	needsCert := false
	switch spec.Protocol {
	case "hysteria", "hysteria2", "tuic", "anytls":
		needsCert = true
	case "trojan":
		if spec.TLS != 2 {
			needsCert = true
		}
	case "vmess", "vless":
		// tls=1 promises TLS to the panel and clients; without material the
		// sing-box builders would run a plaintext inbound.
		if spec.TLS == 1 {
			needsCert = true
		}
	}
	if allowPlaintext && spec.TLS == 1 {
		switch spec.Protocol {
		case "vmess", "vless", "trojan":
			needsCert = false
		}
	}
	if needsCert && !hasUsableTLSConfig(spec, tls) {
		return fmt.Errorf("protocol %q requires TLS certificate files", spec.Protocol)
	}
	if spec.TLS == 2 {
		if err := validateRealityRequirements(spec, kernelType); err != nil {
			return err
		}
	}
	return nil
}

func hasUsableTLSConfig(spec *model.NodeSpec, tls kernel.TLSCert) bool {
	if tls.HasCert() {
		return true
	}
	if spec == nil || spec.CertConfig == nil {
		return false
	}
	mode := strings.ToLower(strings.TrimSpace(spec.CertConfig.CertMode))
	switch mode {
	case "self":
		return true
	case "content":
		return strings.TrimSpace(spec.CertConfig.CertContent) != "" && strings.TrimSpace(spec.CertConfig.KeyContent) != ""
	case "file":
		return (strings.TrimSpace(spec.CertConfig.CertFile) != "" && strings.TrimSpace(spec.CertConfig.KeyFile) != "") ||
			strings.TrimSpace(spec.CertConfig.CertDir) != ""
	case "http":
		return strings.TrimSpace(spec.CertConfig.Domain) != ""
	case "dns":
		return strings.TrimSpace(spec.CertConfig.Domain) != "" && strings.TrimSpace(spec.CertConfig.DNSProvider) != ""
	default:
		return false
	}
}

func validateRuntimeCertConfig(spec *model.NodeSpec) error {
	if spec == nil || spec.CertConfig == nil {
		return nil
	}
	mode := strings.ToLower(strings.TrimSpace(spec.CertConfig.CertMode))
	if mode != "dns" {
		return nil
	}
	provider := strings.TrimSpace(spec.CertConfig.DNSProvider)
	if provider == "" {
		return fmt.Errorf("dns cert mode requires cert_config.dns_provider")
	}
	if _, ok := dnsproviders.Get(provider); !ok {
		return fmt.Errorf("unsupported cert_config.dns_provider %q (supported: %s)", provider, strings.Join(dnsproviders.CanonicalNames(), ", "))
	}
	return nil
}

func validateRealityRequirements(spec *model.NodeSpec, _ string) error {
	if spec.TLSSettings == nil {
		return fmt.Errorf("reality tls requires tls_settings")
	}
	privateKey := strings.TrimSpace(stringValue(spec.TLSSettings["private_key"]))
	serverName := strings.TrimSpace(stringValue(spec.TLSSettings["server_name"]))
	dest := strings.TrimSpace(stringValue(spec.TLSSettings["dest"]))
	if privateKey == "" {
		return fmt.Errorf("reality tls requires tls_settings.private_key")
	}
	if serverName == "" && dest == "" {
		return fmt.Errorf("reality tls requires tls_settings.server_name or tls_settings.dest")
	}
	return nil
}

func cfgKernelType(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(cfg.Kernel.Type))
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func stringValue(v any) string {
	switch value := v.(type) {
	case string:
		return value
	default:
		return ""
	}
}
