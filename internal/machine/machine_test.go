package machine

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/panel"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// panelStub fakes the v2 machine/server endpoints the orchestrator and its
// node services call. Response shapes mirror the panel source
// (Xboard app/Http/Controllers/V2/Server/{ServerController,MachineController}.php
// and app/Services/ServerService.php buildNodeConfig).
type panelStub struct {
	srv *httptest.Server

	mu         sync.Mutex
	nodes      []panel.MachineNode
	nodeHits   map[int]*atomic.Int64 // node_id → GET /server/user count
	nodesHits  atomic.Int64          // POST /machine/nodes count
	handshakes atomic.Int64
}

func newPanelStub(t *testing.T, nodes []panel.MachineNode) *panelStub {
	t.Helper()
	p := &panelStub{
		nodes:    nodes,
		nodeHits: make(map[int]*atomic.Int64),
	}
	for _, n := range nodes {
		p.nodeHits[n.ID] = &atomic.Int64{}
	}

	mux := http.NewServeMux()

	// POST /api/v2/server/machine/nodes
	mux.HandleFunc("/api/v2/server/machine/nodes", func(w http.ResponseWriter, r *http.Request) {
		p.nodesHits.Add(1)
		p.mu.Lock()
		nodes := p.nodes
		p.mu.Unlock()
		writeJSON(w, map[string]any{
			"nodes": nodes,
			"base_config": map[string]any{
				"push_interval": 60,
				"pull_interval": 60,
			},
		})
	})

	// POST /api/v2/server/handshake — WS disabled, no settings key (the panel
	// handshake only carries websocket).
	mux.HandleFunc("/api/v2/server/handshake", func(w http.ResponseWriter, r *http.Request) {
		p.handshakes.Add(1)
		writeJSON(w, map[string]any{"websocket": map[string]any{"enabled": false}})
	})

	// GET /api/v2/server/config — minimal socks node (per-node via node_id).
	mux.HandleFunc("/api/v2/server/config", func(w http.ResponseWriter, r *http.Request) {
		nodeID, _ := strconv.Atoi(r.URL.Query().Get("node_id"))
		writeJSON(w, map[string]any{
			"protocol":        "socks",
			"listen_ip":       "0.0.0.0",
			"server_port":     20000 + nodeID,
			"network":         nil,
			"networkSettings": nil,
			"base_config": map[string]any{
				"push_interval": 60,
				"pull_interval": 60,
			},
		})
	})

	// GET /api/v2/server/user — empty user list keeps the kernel unstarted.
	mux.HandleFunc("/api/v2/server/user", func(w http.ResponseWriter, r *http.Request) {
		nodeID, _ := strconv.Atoi(r.URL.Query().Get("node_id"))
		if hits, ok := p.nodeHits[nodeID]; ok {
			hits.Add(1)
		}
		writeJSON(w, map[string]any{"users": []any{}})
	})

	// Report endpoints: accept and ack.
	mux.HandleFunc("/api/v2/server/report", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"data": true})
	})
	mux.HandleFunc("/api/v2/server/machine/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"data": true})
	})

	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *panelStub) setNodes(nodes []panel.MachineNode) {
	p.mu.Lock()
	p.nodes = nodes
	for _, n := range nodes {
		if _, ok := p.nodeHits[n.ID]; !ok {
			p.nodeHits[n.ID] = &atomic.Int64{}
		}
	}
	p.mu.Unlock()
}

func (p *panelStub) waitUserFetch(t *testing.T, nodeID int, want int64) {
	t.Helper()
	hits := p.nodeHits[nodeID]
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if hits.Load() >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("node %d: user endpoint fetched %d times, want >= %d", nodeID, hits.Load(), want)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// newTestOrchestrator builds an Orchestrator pointed at the stub panel.
func newTestOrchestrator(t *testing.T, p *panelStub) *Orchestrator {
	t.Helper()
	cfg := &config.Config{
		Panel:   config.PanelConfig{URL: p.srv.URL},
		Machine: &config.MachineConfig{MachineID: 77, Token: "machine-token"},
		Kernel:  config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir()},
		Node:    config.NodeConfig{TrackInterval: 10, DeviceReportInterval: 30},
		WS:      config.WSConfig{DiscoveryInterval: 300},
	}
	return New(cfg)
}

func node(id int) panel.MachineNode {
	return panel.MachineNode{ID: id, Type: "socks", Name: fmt.Sprintf("n%d", id)}
}

func handleExists(t *testing.T, o *Orchestrator, id int) bool {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	_, ok := o.nodes[id]
	return ok
}

// Rediscover must start nodes the panel added, keep running ones, and fully
// stop (handle unregistered, service exited) the ones it removed.
func TestOrchestratorRediscoverAddKeepRemove(t *testing.T) {
	p := newPanelStub(t, []panel.MachineNode{node(1)})
	o := newTestOrchestrator(t, p)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	o.runCtx = ctx

	o.startNode(ctx, node(1))
	p.waitUserFetch(t, 1, 1)
	if !handleExists(t, o, 1) {
		t.Fatal("node 1 should be registered after startNode")
	}

	// Keep 1, add 2.
	p.setNodes([]panel.MachineNode{node(1), node(2)})
	o.rediscover(ctx)
	p.waitUserFetch(t, 2, 1)
	if !handleExists(t, o, 1) || !handleExists(t, o, 2) {
		t.Fatal("nodes 1 and 2 should both be running")
	}

	// Remove 1, keep 2. rediscover stops the node synchronously: after it
	// returns the handle must be gone and the service goroutine exited.
	p.setNodes([]panel.MachineNode{node(2)})
	o.rediscover(ctx)
	if handleExists(t, o, 1) {
		t.Fatal("node 1 handle should be unregistered after removal")
	}
	if !handleExists(t, o, 2) {
		t.Fatal("node 2 should survive the rediscovery")
	}
	o.eventsMu.RLock()
	_, mailboxLeft := o.mailboxes[1]
	o.eventsMu.RUnlock()
	if mailboxLeft {
		t.Fatal("node 1 mailbox should be unregistered after removal")
	}
}

// Shared-mux WS events must land in the addressed node's mailbox, be dropped
// without a node_id or for unknown nodes, and sync.nodes must trigger
// rediscovery.
func TestOrchestratorWSEventRouting(t *testing.T) {
	p := newPanelStub(t, nil)
	o := newTestOrchestrator(t, p)
	ctx, contextCancel := context.WithCancel(context.Background())
	defer contextCancel()
	o.runCtx = ctx

	mb1 := controlplane.NewNodeMailbox()
	mb2 := controlplane.NewNodeMailbox()
	o.eventsMu.Lock()
	o.mailboxes[1] = mb1
	o.mailboxes[2] = mb2
	o.eventsMu.Unlock()
	mb1.MarkReady()
	mb2.MarkReady()

	o.onWSEvent(panel.WSEvent{
		Type:   panel.WSEventSyncUsers,
		NodeID: 1,
		Users:  []panel.User{{ID: 5, UUID: "uuid-5"}},
	})
	st := mb1.DrainIfReady()
	if !st.HasUsers || len(st.Users) != 1 || st.Users[0].ID != 5 {
		t.Fatalf("node 1 mailbox: got %+v, want one user 5", st)
	}
	if st2 := mb2.DrainIfReady(); st2.HasUsers {
		t.Fatal("node 2 mailbox must not receive node 1's event")
	}

	// Missing node_id: dropped entirely.
	o.onWSEvent(panel.WSEvent{
		Type:  panel.WSEventSyncUsers,
		Users: []panel.User{{ID: 6, UUID: "uuid-6"}},
	})
	if st := mb1.DrainIfReady(); st.HasUsers {
		t.Fatal("event without node_id must be dropped")
	}

	// Unknown node: dropped.
	o.onWSEvent(panel.WSEvent{
		Type:   panel.WSEventSyncUsers,
		NodeID: 99,
		Users:  []panel.User{{ID: 7, UUID: "uuid-7"}},
	})
	if st := mb1.DrainIfReady(); st.HasUsers {
		t.Fatal("event for unknown node must be dropped")
	}

	// sync.nodes: machine-level event, triggers rediscovery.
	before := p.nodesHits.Load()
	p.setNodes([]panel.MachineNode{node(3)})
	o.onWSEvent(panel.WSEvent{Type: panel.WSEventSyncNodes})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if p.nodesHits.Load() > before {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if p.nodesHits.Load() <= before {
		t.Fatal("sync.nodes event did not trigger rediscovery")
	}
}

// Cancelling while nodes are still starting must converge: stopAll waits for
// every service goroutine to exit and leaves no handles behind.
func TestOrchestratorStopAllDuringStart(t *testing.T) {
	p := newPanelStub(t, []panel.MachineNode{node(1), node(2)})
	o := newTestOrchestrator(t, p)
	ctx, cancel := context.WithCancel(context.Background())
	o.runCtx = ctx

	o.startNode(ctx, node(1))
	o.startNode(ctx, node(2))

	// Cancel mid-startup, then stopAll: it must return with all handles gone.
	cancel()
	o.stopAll()

	if len(o.nodes) != 0 {
		t.Fatalf("handles left after stopAll: %v", o.nodes)
	}
	o.eventsMu.RLock()
	left := len(o.mailboxes)
	o.eventsMu.RUnlock()
	if left != 0 {
		t.Fatalf("mailboxes left after stopAll: %d", left)
	}

	// Note: no goroutine-count assertion here — httptest keep-alive
	// connections keep server-side goroutines alive past stopAll, which drowns
	// the signal. Convergence is proven by the handle/mailbox assertions and
	// stopAll's <-h.done waits.
}
