package panel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// fakeWSServer simulates a minimal Workerman-style WS server for testing.
// It authenticates via token/node_id query params, sends auth.success, then
// delivers the provided events and handles pongs until the client disconnects.
func fakeWSServer(t *testing.T, events []wsMessage) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate query params
		q := r.URL.Query()
		if q.Get("token") == "" || q.Get("node_id") == "" {
			http.Error(w, "missing auth params", http.StatusUnauthorized)
			return
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Logf("upgrade error: %v", err)
			return
		}
		defer conn.Close()

		// Send auth.success
		if err := conn.WriteJSON(wsMessage{Event: "auth.success"}); err != nil {
			return
		}

		// Send test events
		for _, evt := range events {
			time.Sleep(50 * time.Millisecond)
			if err := conn.WriteJSON(evt); err != nil {
				return
			}
		}

		// Handle pongs/messages until connection closes
		for {
			var msg wsMessage
			if err := conn.ReadJSON(&msg); err != nil {
				return
			}
			if msg.Event == "pong" {
				// Client pong — acknowledged
			}
		}
	}))
}

func TestWSClient_ConnectAndReceiveDataEvents(t *testing.T) {
	configPayload := syncConfigPayload{
		Config:    NodeConfig{Protocol: "vless", ServerPort: 443},
		Timestamp: 1234,
	}
	usersPayload := syncUsersPayload{
		Users:     []User{{ID: 1, UUID: "abc", SpeedLimit: 100, DeviceLimit: 3}},
		Timestamp: 1235,
	}

	configData, _ := json.Marshal(configPayload)
	usersData, _ := json.Marshal(usersPayload)

	events := []wsMessage{
		{Event: WSEventSyncConfig, Data: configData},
		{Event: WSEventSyncUsers, Data: usersData},
	}
	server := fakeWSServer(t, events)
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")

	var mu sync.Mutex
	var received []WSEvent

	ws := NewWSClient("ws://"+host, "test-token", 1, WSClientConfig{}, func(event WSEvent) {
		mu.Lock()
		received = append(received, event)
		mu.Unlock()
	}, nil, func() map[string]interface{} { return nil })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go ws.Run(ctx)

	// Wait for events
	deadline := time.After(1500 * time.Millisecond)
	for {
		mu.Lock()
		n := len(received)
		mu.Unlock()
		if n >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for events, got %d", n)
		case <-time.After(50 * time.Millisecond):
		}
	}

	mu.Lock()
	defer mu.Unlock()

	if len(received) != 2 {
		t.Fatalf("expected 2 events, got %d", len(received))
	}

	// Verify config event
	if received[0].Type != WSEventSyncConfig {
		t.Errorf("event[0].Type = %q, want %q", received[0].Type, WSEventSyncConfig)
	}
	if received[0].Config == nil {
		t.Fatal("event[0].Config is nil")
	}
	if received[0].Config.Protocol != "vless" {
		t.Errorf("config.Protocol = %q, want %q", received[0].Config.Protocol, "vless")
	}
	if received[0].Config.ServerPort != 443 {
		t.Errorf("config.ServerPort = %d, want 443", received[0].Config.ServerPort)
	}

	// Verify users event
	if received[1].Type != WSEventSyncUsers {
		t.Errorf("event[1].Type = %q, want %q", received[1].Type, WSEventSyncUsers)
	}
	if len(received[1].Users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(received[1].Users))
	}
	if received[1].Users[0].UUID != "abc" {
		t.Errorf("user.UUID = %q, want %q", received[1].Users[0].UUID, "abc")
	}

	if !ws.IsConnected() {
		t.Error("expected IsConnected() = true while server is running")
	}
}

func TestWSClient_ReconnectOnDisconnect(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	var mu sync.Mutex
	connectCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}

		mu.Lock()
		connectCount++
		count := connectCount
		mu.Unlock()

		// Send auth.success
		conn.WriteJSON(wsMessage{Event: "auth.success"})

		// Close immediately on first connection to trigger reconnect
		if count == 1 {
			conn.Close()
			return
		}

		// Keep second connection alive
		for {
			var msg wsMessage
			if err := conn.ReadJSON(&msg); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")
	ws := NewWSClient("ws://"+host, "reconnect-token", 1, WSClientConfig{}, func(WSEvent) {}, nil, func() map[string]interface{} { return nil })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go ws.Run(ctx)

	// Wait for reconnection
	deadline := time.After(4 * time.Second)
	for {
		mu.Lock()
		n := connectCount
		mu.Unlock()
		if n >= 2 {
			break
		}
		select {
		case <-deadline:
			mu.Lock()
			t.Fatalf("expected at least 2 connections, got %d", connectCount)
			mu.Unlock()
		case <-time.After(100 * time.Millisecond):
		}
	}

	if !ws.IsConnected() {
		t.Error("expected IsConnected() = true after reconnect")
	}
}

func TestWSClient_FallbackWhenNoServer(t *testing.T) {
	ws := NewWSClient("ws://127.0.0.1:19999", "fallback-token", 1, WSClientConfig{}, func(WSEvent) {}, nil, func() map[string]interface{} { return nil })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	go ws.Run(ctx)

	time.Sleep(500 * time.Millisecond)
	if ws.IsConnected() {
		t.Error("expected IsConnected() = false when no server")
	}
}

func TestWSClient_UserDeltaEvent(t *testing.T) {
	deltaPayload := syncUserDeltaPayload{
		Action:    "add",
		Users:     []User{{ID: 42, UUID: "delta-uuid"}},
		Timestamp: 1236,
	}
	deltaData, _ := json.Marshal(deltaPayload)

	events := []wsMessage{
		{Event: WSEventSyncUserDelta, Data: deltaData},
	}
	server := fakeWSServer(t, events)
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")

	var mu sync.Mutex
	var received []WSEvent

	ws := NewWSClient("ws://"+host, "delta-token", 1, WSClientConfig{}, func(event WSEvent) {
		mu.Lock()
		received = append(received, event)
		mu.Unlock()
	}, nil, func() map[string]interface{} { return nil })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go ws.Run(ctx)

	deadline := time.After(1500 * time.Millisecond)
	for {
		mu.Lock()
		n := len(received)
		mu.Unlock()
		if n >= 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for delta event")
		case <-time.After(50 * time.Millisecond):
		}
	}

	mu.Lock()
	defer mu.Unlock()

	if received[0].Type != WSEventSyncUserDelta {
		t.Errorf("event.Type = %q, want %q", received[0].Type, WSEventSyncUserDelta)
	}
	if received[0].DeltaAction != "add" {
		t.Errorf("event.DeltaAction = %q, want %q", received[0].DeltaAction, "add")
	}
	if len(received[0].DeltaUsers) != 1 || received[0].DeltaUsers[0].ID != 42 {
		t.Errorf("unexpected DeltaUsers: %+v", received[0].DeltaUsers)
	}
}

// Send* must be race-free against connect() swapping the write channel.
func TestWSClient_ConcurrentSendDuringReconnect(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	// Server closes every connection right after auth: constant reconnect
	// churn with a tiny backoff maximises the swap/send overlap window.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		if err := conn.WriteJSON(wsMessage{Event: "auth.success"}); err != nil {
			return
		}
		conn.Close()
	}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")
	ws := NewWSClient("ws://"+host, "race-token", 1,
		WSClientConfig{BackoffInitial: 10 * time.Millisecond, BackoffMax: 50 * time.Millisecond},
		func(WSEvent) {}, nil, func() map[string]interface{} { return nil })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go ws.Run(ctx)

	for ctx.Err() == nil {
		ws.SendDeviceReport(map[int][]string{1: {"1.1.1.1"}})
	}
}

// A peer that never answers the close frame must not block Run after ctx
// cancel: the read goroutine has no deadline, so connect() closes the conn
// from a watcher goroutine to unblock it.
func TestWSClient_ShutdownUnblocksWhenPeerSilent(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		if err := conn.WriteJSON(wsMessage{Event: "auth.success"}); err != nil {
			return
		}
		// Go silent: never read, never answer the client's close frame.
		time.Sleep(5 * time.Second)
	}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")
	ws := NewWSClient("ws://"+host, "silent-token", 1, WSClientConfig{}, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		ws.Run(ctx)
		close(done)
	}()

	time.Sleep(300 * time.Millisecond) // let it connect and authenticate
	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return within 3s after ctx cancel (blocked on silent peer)")
	}
}

// The client must ask for the global device snapshot right after connecting:
// the panel only pushes sync.devices to the node that just reported, so a
// fresh connection would otherwise hold no global state at all.
func TestWSClient_RequestsDeviceStateOnConnect(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	received := make(chan string, 8)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		if err := conn.WriteJSON(wsMessage{Event: "auth.success"}); err != nil {
			return
		}
		for {
			var msg wsMessage
			if err := conn.ReadJSON(&msg); err != nil {
				return
			}
			select {
			case received <- msg.Event:
			default:
			}
		}
	}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")
	ws := NewWSClient("ws://"+host, "devreq-token", 1, WSClientConfig{}, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ws.Run(ctx)

	deadline := time.After(3 * time.Second)
	for {
		select {
		case ev := <-received:
			if ev == "request.devices" {
				return
			}
		case <-deadline:
			t.Fatal("client never sent request.devices after connect")
		}
	}
}
