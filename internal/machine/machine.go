// Package machine implements the machine-mode orchestrator that dynamically
// discovers nodes from the panel's machine API and manages their lifecycles.
package machine

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/monitor"
	"github.com/cedar2025/xboard-node/internal/nlog"
	"github.com/cedar2025/xboard-node/internal/panel"
	"github.com/cedar2025/xboard-node/internal/service"
)

// nodeHandle tracks a running node service.
type nodeHandle struct {
	cancel  context.CancelFunc
	done    chan struct{}
	mailbox *controlplane.NodeMailbox
}

// Orchestrator manages all nodes bound to a panel machine. It:
//   - discovers nodes via GET /machine/nodes
//   - starts / stops Service instances as nodes are added / removed
//   - maintains a shared WS connection that demuxes events by node_id
//   - reports machine-level load via POST /machine/status
type Orchestrator struct {
	cfg    *config.Config
	client *panel.Client // machine-level client (no node_id)

	mu    sync.Mutex
	nodes map[int]*nodeHandle // node_id → handle
	// stopping tracks nodes detached by rediscover whose service goroutine has
	// not exited yet. A restarted node with the same ID waits on it before the
	// kernel binds ports again; stopAll drains whatever remains.
	stopping map[int]<-chan struct{}
	// nodeKernels holds each node's resolved kernel config so shared-WS events
	// are translated with the kernel that node actually runs (auto-switch).
	nodeKernels map[int]config.KernelConfig

	// Per-node mailbox keyed by node_id. Shared WS events are aggregated here
	// and each node service drains the latest state when ready.
	eventsMu  sync.RWMutex
	mailboxes map[int]*controlplane.NodeMailbox
	statuses  map[int]chan<- controlplane.StatusChange

	// Shared WS client (nil when WS is disabled).
	ws       *panel.WSClient
	wsCancel context.CancelFunc

	// runCtx is stored from Run() so that onWSEvent can trigger rediscover
	// for sync.nodes events without blocking the main loop.
	runCtx context.Context

	// rediscovering single-flights rediscover runs (ticker + sync.nodes).
	rediscovering atomic.Bool

	pullInterval time.Duration
	pushInterval time.Duration
}

// New creates a machine orchestrator from the given config.
func New(cfg *config.Config) *Orchestrator {
	panelCfg := config.PanelConfig{
		URL:       cfg.Panel.URL,
		Token:     cfg.Machine.Token,
		MachineID: cfg.Machine.MachineID,
	}
	return &Orchestrator{
		cfg:       cfg,
		client:    panel.NewClient(panelCfg),
		nodes:     make(map[int]*nodeHandle),
		mailboxes: make(map[int]*controlplane.NodeMailbox),
		statuses:  make(map[int]chan<- controlplane.StatusChange),
	}
}

// Run is the main loop. It blocks until ctx is cancelled.
func (o *Orchestrator) Run(ctx context.Context) error {
	o.runCtx = ctx
	nodesResp, err := o.client.GetMachineNodes()
	if err != nil {
		return fmt.Errorf("initial node discovery: %w", err)
	}

	o.applyIntervals(nodesResp.BaseConfig)
	nlog.Core().Info(fmt.Sprintf("machine %d: discovered %d nodes",
		o.cfg.Machine.MachineID, len(nodesResp.Nodes)))

	// Start machine-level WS as early as possible so sync.nodes can reach an
	// empty machine before the first node is attached.
	o.tryStartWS(ctx)

	// Start initial nodes.
	for _, n := range nodesResp.Nodes {
		o.startNode(ctx, n)
	}

	discoveryTicker := time.NewTicker(o.pullInterval)
	statusTicker := time.NewTicker(o.pushInterval)
	defer discoveryTicker.Stop()
	defer statusTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			o.stopAll()
			return nil

		case <-discoveryTicker.C:
			o.rediscover(ctx)
			// Re-check WS enablement: the panel may turn WS on after boot.
			if o.currentWS() == nil {
				o.tryStartWS(ctx)
			}

		case <-statusTicker.C:
			o.reportMachineStatus()
		}
	}
}

// ─── Node lifecycle ──────────────────────────────────────────────────────

func (o *Orchestrator) startNode(ctx context.Context, mn panel.MachineNode) {
	o.mu.Lock()
	if _, exists := o.nodes[mn.ID]; exists {
		o.mu.Unlock()
		return
	}
	// A node removed by an earlier rediscover may still be shutting down; its
	// kernel keeps the ports until Run returns.
	prevStop := o.stopping[mn.ID]

	nodeCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	mb := controlplane.NewNodeMailbox()
	o.nodes[mn.ID] = &nodeHandle{cancel: cancel, done: done, mailbox: mb}
	o.mu.Unlock()

	o.eventsMu.Lock()
	o.mailboxes[mn.ID] = mb
	o.eventsMu.Unlock()

	nlog.Core().Info(fmt.Sprintf("machine: starting node %d (%s/%s)",
		mn.ID, mn.Type, mn.Name))

	go func() {
		defer close(done)
		defer o.unregisterNode(mn.ID)
		// A node whose Service.Run returned never restarts: the handle stayed in
		// o.nodes, so rediscover's startNode saw it as already running and
		// returned. Removing it here lets the next discovery tick bring the node
		// back instead of leaving it offline until the process restarts.
		defer func() {
			o.mu.Lock()
			if cur, ok := o.nodes[mn.ID]; ok && cur.done == done {
				delete(o.nodes, mn.ID)
			}
			o.mu.Unlock()
		}()

		nodeCfg := o.cfg.ExpandMachineNode(mn.ID, mn.Type)

		perNodeClient := o.client.ForNode(mn.ID)

		// Pre-fetch node config to resolve kernel requirements (transport,
		// protocol, Reality) and auto-switch when the configured kernel
		// cannot serve this node (kernel.type auto or explicit mismatch).
		if cfgSnapshot, err := perNodeClient.GetConfig(); err == nil && cfgSnapshot != nil {
			resolved := model.ResolveKernelForTransport(cfgSnapshot.Network, nodeCfg.Kernel.Type)
			if spec := model.NodeSpecFromPanel(cfgSnapshot); spec != nil {
				resolved = model.ResolveKernelForNode(spec, nodeCfg.Kernel)
			}
			if resolved != nodeCfg.Kernel.Type {
				nlog.Core().Info(fmt.Sprintf("machine: auto-switching kernel for node %d (%s→%s, transport=%s protocol=%s)",
					mn.ID, nodeCfg.Kernel.Type, resolved, cfgSnapshot.Network, cfgSnapshot.Protocol))
				nodeCfg.Kernel.Type = resolved
			}
		}
		o.mu.Lock()
		if o.nodeKernels == nil {
			o.nodeKernels = make(map[int]config.KernelConfig)
		}
		o.nodeKernels[mn.ID] = nodeCfg.Kernel
		o.mu.Unlock()

		// Reset cached ETag so the subsequent GetConfig in Initial() gets a full response.
		perNodeClient.ResetConfigETag()

		// Always provide the adapter: it resolves the shared WS per call, so a
		// node started before the machine handshake still gets a mailbox and
		// can report devices once WS comes up.
		push := &machineNodePush{
			nodeID: mn.ID,
			ws:     o.currentWS,
		}

		// The registerFn is called by MachinePanelControlPlane.Initial() to expose
		// the node mailbox + status channel to the Service.
		nodeID := mn.ID
		registerFn := func(st chan<- controlplane.StatusChange) *controlplane.NodeMailbox {
			o.registerNode(nodeID, st)
			return mb
		}

		if prevStop != nil {
			nlog.Core().Info("machine: waiting for the previous node instance to exit", "node_id", mn.ID)
		}
		if !awaitStop(nodeCtx, prevStop) {
			return
		}
		// awaitStop's select is random when both the previous stop closed and
		// this node was cancelled concurrently: do not start a service that was
		// already detached (it would bind ports and run initialSetup briefly).
		if nodeCtx.Err() != nil {
			return
		}

		cp := controlplane.NewMachinePanelControlPlane(perNodeClient, nodeCfg.Kernel, push, registerFn)
		svc := service.NewWithControlPlane(nodeCfg, cp)
		if err := svc.Run(nodeCtx); err != nil && nodeCtx.Err() == nil {
			nlog.Core().Error("machine node exited with error",
				"node_id", mn.ID, "error", err)
		}
	}()
}

// detachNode unregisters a node and cancels its service without waiting for
// its goroutine to exit. The exit can take seconds (final report, cert worker
// join), which used to stall the whole discovery/status loop.
func (o *Orchestrator) detachNode(nodeID int) *nodeHandle {
	o.mu.Lock()
	h, ok := o.nodes[nodeID]
	if !ok {
		o.mu.Unlock()
		return nil
	}
	delete(o.nodes, nodeID)
	delete(o.nodeKernels, nodeID)
	if o.stopping == nil {
		o.stopping = make(map[int]<-chan struct{})
	}
	o.stopping[nodeID] = h.done
	o.mu.Unlock()

	o.eventsMu.Lock()
	delete(o.mailboxes, nodeID)
	o.eventsMu.Unlock()

	nlog.Core().Info(fmt.Sprintf("machine: stopping node %d", nodeID))
	h.cancel()

	// Reap the entry once the service is gone so the map only holds live
	// shutdowns. A startNode that already read the channel still observes the
	// close.
	go func() {
		<-h.done
		o.mu.Lock()
		if ch, ok := o.stopping[nodeID]; ok && ch == h.done {
			delete(o.stopping, nodeID)
		}
		o.mu.Unlock()
	}()

	return h
}

// awaitStop blocks until a previously detached node has exited, or the new
// node's context is cancelled.
func awaitStop(ctx context.Context, ch <-chan struct{}) bool {
	if ch == nil {
		return true
	}
	select {
	case <-ch:
		return true
	case <-ctx.Done():
		return false
	}
}

func (o *Orchestrator) stopAll() {
	o.mu.Lock()
	handles := make(map[int]*nodeHandle, len(o.nodes))
	for id, h := range o.nodes {
		handles[id] = h
	}
	o.mu.Unlock()

	for id, h := range handles {
		nlog.Core().Info(fmt.Sprintf("machine: stopping node %d", id))
		h.cancel()
	}
	for _, h := range handles {
		<-h.done
	}

	// unregisterNode only clears mailboxes/statuses; drop the stale handles
	// too so a completed stopAll leaves no zombie entries behind.
	o.mu.Lock()
	for id := range handles {
		delete(o.nodes, id)
	}
	// Nodes detached by an earlier rediscover are no longer in o.nodes but
	// their services may still be exiting.
	var stopping []<-chan struct{}
	for _, ch := range o.stopping {
		stopping = append(stopping, ch)
	}
	o.stopping = nil
	o.mu.Unlock()

	for _, ch := range stopping {
		<-ch
	}

	if o.wsCancel != nil {
		o.wsCancel()
	}
}

// maxMachineNodes bounds one discovery response; each entry becomes a service.
const maxMachineNodes = 1024

// ─── Node discovery ──────────────────────────────────────────────────────

func (o *Orchestrator) rediscover(ctx context.Context) {
	// Single-flight: sync.nodes events can spawn rediscover runs on top of
	// the ticker; an overlapping run is skipped, the next tick catches up.
	if !o.rediscovering.CompareAndSwap(false, true) {
		return
	}
	defer o.rediscovering.Store(false)

	nodesResp, err := o.client.GetMachineNodes()
	if err != nil {
		nlog.Core().Warn("machine node discovery failed", "error", err)
		return
	}

	if len(nodesResp.Nodes) > maxMachineNodes {
		// A corrupt or hostile node list would otherwise be applied wholesale:
		// one kernel, listener and goroutine per entry.
		nlog.Core().Error("machine node list exceeds the cap, keeping the current set",
			"nodes", len(nodesResp.Nodes), "cap", maxMachineNodes)
		return
	}

	wanted := make(map[int]panel.MachineNode, len(nodesResp.Nodes))
	for _, n := range nodesResp.Nodes {
		wanted[n.ID] = n
	}

	o.mu.Lock()
	var toRemove []int
	for id := range o.nodes {
		if _, ok := wanted[id]; !ok {
			toRemove = append(toRemove, id)
		}
	}
	o.mu.Unlock()

	for _, id := range toRemove {
		o.detachNode(id)
	}

	for _, n := range nodesResp.Nodes {
		o.startNode(ctx, n) // no-op if already running
	}
}

// ─── Machine status reporting ────────────────────────────────────────────

func (o *Orchestrator) reportMachineStatus() {
	s := monitor.Collect()
	if err := o.client.ReportMachineStatus(
		s.CPU,
		[2]uint64{s.MemTotal, s.MemUsed},
		[2]uint64{s.SwapTotal, s.SwapUsed},
		[2]uint64{s.DiskTotal, s.DiskUsed},
		s.NetInSpeed, s.NetOutSpeed,
	); err != nil {
		nlog.Core().Warn("machine status report failed", "error", err)
	}
}

// ─── WS mux ─────────────────────────────────────────────────────────────

// currentWS returns the shared WS client, nil until the machine handshake
// enables it. The nil check happens here: returning a typed nil *panel.WSClient
// as wsSender would produce a non-nil interface and panic on IsConnected.
func (o *Orchestrator) currentWS() wsSender {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.ws == nil {
		return nil
	}
	return o.ws
}

func (o *Orchestrator) tryStartWS(ctx context.Context) {
	hs, err := o.client.Handshake()
	if err != nil {
		// Debug: re-checked on every discovery tick, so failures would spam.
		nlog.Core().Debug("machine ws handshake failed, REST only", "error", err)
		return
	}
	if !hs.WebSocket.Enabled || hs.WebSocket.WSURL == "" {
		nlog.Core().Debug("machine: ws disabled by panel, REST only")
		return
	}
	if err := panel.ValidateWSURL(hs.WebSocket.WSURL, o.cfg.Panel.URL); err != nil {
		nlog.Core().Warn("machine: panel websocket url rejected, REST only", "error", err)
		return
	}

	wsCfg := panel.WSClientConfig{
		StatusInterval:   time.Duration(o.cfg.WS.StatusInterval) * time.Second,
		HandshakeTimeout: time.Duration(o.cfg.WS.HandshakeTimeout) * time.Second,
		BackoffInitial:   time.Duration(o.cfg.WS.BackoffInitial) * time.Second,
		BackoffMax:       time.Duration(o.cfg.WS.BackoffMax) * time.Second,
		MachineID:        o.cfg.Machine.MachineID,
	}

	o.mu.Lock()
	o.ws = panel.NewWSClient(
		hs.WebSocket.WSURL,
		o.cfg.Machine.Token,
		0, // no single node_id
		wsCfg,
		o.onWSEvent,
		o.onWSStatus,
		nil, // per-node status is sent via machineNodePush
	)
	o.mu.Unlock()

	wsCtx, wsCancel := context.WithCancel(ctx)
	o.wsCancel = wsCancel
	go o.ws.Run(wsCtx)

	nlog.Core().Info("machine: ws mux started")
}

// onWSEvent routes a WS event to the correct node's channel.
// sync.nodes is a machine-level event that triggers immediate rediscovery.
func (o *Orchestrator) onWSEvent(event panel.WSEvent) {
	// sync.nodes is a machine-level event, not per-node
	if event.Type == panel.WSEventSyncNodes {
		nlog.Core().Info("machine received sync.nodes, triggering immediate rediscovery")
		go o.rediscover(o.runCtx)
		return
	}

	nodeID := event.NodeID
	if nodeID == 0 {
		nlog.Core().Debug("machine ws event missing node_id, dropping", "type", event.Type)
		return
	}

	translated, err := controlplane.TranslateWSEvent(event, o.kernelForNode(nodeID))
	if err != nil {
		nlog.Core().Warn("machine ws event translation failed",
			"type", event.Type, "node_id", nodeID, "error", err)
		return
	}

	o.eventsMu.RLock()
	mailbox, ok := o.mailboxes[nodeID]
	o.eventsMu.RUnlock()
	if !ok {
		nlog.Core().Debug("machine ws event for unknown node", "node_id", nodeID, "type", event.Type)
		return
	}
	mailbox.Apply(translated)
}

// onWSStatus broadcasts WS connectivity changes to all registered nodes.
func (o *Orchestrator) onWSStatus(status panel.WSStatusChange) {
	change := controlplane.StatusChange{Connected: status.Connected}
	o.eventsMu.RLock()
	defer o.eventsMu.RUnlock()
	for _, ch := range o.statuses {
		select {
		case ch <- change:
		default:
		}
	}
}

func (o *Orchestrator) registerNode(nodeID int, st chan<- controlplane.StatusChange) {
	o.eventsMu.Lock()
	o.statuses[nodeID] = st
	o.eventsMu.Unlock()
}

func (o *Orchestrator) unregisterNode(nodeID int) {
	o.eventsMu.Lock()
	delete(o.mailboxes, nodeID)
	delete(o.statuses, nodeID)
	o.eventsMu.Unlock()

	o.mu.Lock()
	delete(o.nodeKernels, nodeID)
	o.mu.Unlock()
}

// kernelForNode returns the resolved kernel config for a node, falling back to
// the machine-level config before the node has started.
func (o *Orchestrator) kernelForNode(nodeID int) config.KernelConfig {
	o.mu.Lock()
	defer o.mu.Unlock()
	if kcfg, ok := o.nodeKernels[nodeID]; ok {
		return kcfg
	}
	return o.cfg.Kernel
}

func (o *Orchestrator) applyIntervals(bc panel.MachineBaseConfig) {
	o.pullInterval = time.Duration(bc.PullInterval) * time.Second
	if o.pullInterval < 30*time.Second {
		o.pullInterval = 60 * time.Second
	}
	o.pushInterval = time.Duration(bc.PushInterval) * time.Second
	if o.pushInterval < 10*time.Second {
		o.pushInterval = 60 * time.Second
	}
}

// ─── Virtual PushClient ─────────────────────────────────────────────────

// wsSender is the subset of the shared WS client this adapter needs.
type wsSender interface {
	IsConnected() bool
	SendRaw(event string, data json.RawMessage) bool
}

var _ wsSender = (*panel.WSClient)(nil)

// machineNodePush implements controlplane.PushClient for a single node
// backed by the shared machine WS connection. Events are routed by the
// WS mux directly to the Service's channels; this adapter only provides
// connectivity status and send capabilities.
//
// It resolves the WS client per call: the machine handshake may succeed after
// a node was already started, and a snapshot taken at startNode time would
// leave that node unable to report devices (or receive routed events) until
// it was restarted.
type machineNodePush struct {
	nodeID int
	ws     func() wsSender
}

func (p *machineNodePush) sender() wsSender {
	if p.ws == nil {
		return nil
	}
	return p.ws()
}

func (p *machineNodePush) Run(ctx context.Context) {
	// The shared WS mux pushes events into our channels; we just wait.
	<-ctx.Done()
}

func (p *machineNodePush) IsConnected() bool {
	s := p.sender()
	return s != nil && s.IsConnected()
}

func (p *machineNodePush) SendDeviceReport(devices map[int][]string) bool {
	s := p.sender()
	if s == nil || !s.IsConnected() {
		return false
	}
	payload := map[string]interface{}{
		"node_id": p.nodeID,
	}
	// Flatten into the standard format with node_id wrapper.
	strDevices := make(map[string][]string, len(devices))
	for uid, ips := range devices {
		strDevices[fmt.Sprintf("%d", uid)] = ips
	}
	payload["devices"] = strDevices
	data, _ := json.Marshal(payload)
	return s.SendRaw(panel.WSEventReportDevices, data)
}

// stopNode cancels one node and waits for its goroutine. Retained for callers
// that stop a single node synchronously (rediscovery uses detachNode instead).
func (o *Orchestrator) stopNode(nodeID int) {
	o.mu.Lock()
	h, ok := o.nodes[nodeID]
	if !ok {
		o.mu.Unlock()
		return
	}
	delete(o.nodes, nodeID)
	o.mu.Unlock()

	o.eventsMu.Lock()
	delete(o.mailboxes, nodeID)
	o.eventsMu.Unlock()

	nlog.Core().Info(fmt.Sprintf("machine: stopping node %d", nodeID))
	h.cancel()
	<-h.done
}
