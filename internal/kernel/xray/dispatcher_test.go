package xray

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport"
)

func newTestDispatcher() *LimitDispatcher {
	return &LimitDispatcher{
		limitedIPs: make(map[string]map[string]int),
	}
}

type nopReader struct{}

func (nopReader) ReadMultiBuffer() (buf.MultiBuffer, error) { return nil, nil }

func TestLimitDispatcher_DeviceLimitCheck(t *testing.T) {
	ld := newTestDispatcher()

	users := []model.UserSpec{
		{ID: 1, UUID: "uuid-1", DeviceLimit: 2, SpeedLimit: 0},
		{ID: 2, UUID: "uuid-2", DeviceLimit: 0, SpeedLimit: 10},
	}

	emailToUID := make(map[string]int)
	deviceLimits := make(map[string]int)
	for _, u := range users {
		email := userEmail(u.ID)
		emailToUID[email] = u.ID
		if u.DeviceLimit > 0 {
			deviceLimits[email] = u.DeviceLimit
		}
	}
	ld.UpdateLimits(emailToUID, deviceLimits)

	email1 := userEmail(1)

	// First IP should be allowed
	if ld.checkDeviceLimit(email1, "1.1.1.1") {
		t.Error("first IP should be allowed")
	}

	// Second IP should be allowed (limit=2)
	if ld.checkDeviceLimit(email1, "2.2.2.2") {
		t.Error("second IP should be allowed")
	}

	// Third unique IP should be rejected
	if !ld.checkDeviceLimit(email1, "3.3.3.3") {
		t.Error("third IP should be rejected (limit=2)")
	}

	// Same IP as first should be allowed (already connected)
	if ld.checkDeviceLimit(email1, "1.1.1.1") {
		t.Error("same IP should always be allowed")
	}

	// User 2 has no device limit — should always be allowed
	email2 := userEmail(2)
	for i := 0; i < 10; i++ {
		ip := "10.0.0." + string(rune('0'+i))
		if ld.checkDeviceLimit(email2, ip) {
			t.Errorf("user with no device limit should always be allowed (ip=%s)", ip)
		}
	}
}

func TestLimitDispatcher_DelConn(t *testing.T) {
	ld := newTestDispatcher()

	email := userEmail(1)
	deviceLimits := map[string]int{email: 2}
	ld.UpdateLimits(map[string]int{email: 1}, deviceLimits)

	// Add 2 IPs
	ld.checkDeviceLimit(email, "1.1.1.1")
	ld.checkDeviceLimit(email, "2.2.2.2")

	// Third should be rejected
	if !ld.checkDeviceLimit(email, "3.3.3.3") {
		t.Error("third IP should be rejected")
	}

	// Remove first IP
	ld.delConn(email, "1.1.1.1")

	// Now third IP should be allowed
	if ld.checkDeviceLimit(email, "3.3.3.3") {
		t.Error("after deleting one IP, new IP should be allowed")
	}
}

func TestLimitDispatcher_GetConnectionState(t *testing.T) {
	ld := newTestDispatcher()

	email1 := userEmail(1)
	email2 := userEmail(2)
	ld.UpdateLimits(map[string]int{email1: 1, email2: 2}, nil)

	ic1 := &ipCounter{}
	r1 := &atomic.Int64{}
	r1.Store(1)
	ic1.ips.Store("1.1.1.1", r1)
	r2 := &atomic.Int64{}
	r2.Store(1)
	ic1.ips.Store("2.2.2.2", r2)
	ld.unlimitedIPs.Store(email1, ic1)

	ic2 := &ipCounter{}
	r3 := &atomic.Int64{}
	r3.Store(1)
	ic2.ips.Store("3.3.3.3", r3)
	ld.unlimitedIPs.Store(email2, ic2)

	ld.connCount.Store(5)

	aliveIPs, connCount := ld.GetConnectionState()

	if connCount != 5 {
		t.Errorf("expected connCount=5, got %d", connCount)
	}
	if len(aliveIPs[1]) != 2 {
		t.Errorf("user 1 IPs: got %d, want 2", len(aliveIPs[1]))
	}
	if len(aliveIPs[2]) != 1 {
		t.Errorf("user 2 IPs: got %d, want 1", len(aliveIPs[2]))
	}
}

func TestLimitDispatcher_ResetConns(t *testing.T) {
	ld := newTestDispatcher()

	ld.mu.Lock()
	ld.limitedIPs["user@1"] = map[string]int{"1.1.1.1": 1}
	ld.mu.Unlock()
	ld.connCount.Store(3)

	ld.ResetConns()

	ld.mu.RLock()
	ipCount := len(ld.limitedIPs)
	ld.mu.RUnlock()
	if ipCount != 0 {
		t.Error("limitedIPs should be empty after reset")
	}

	if ld.connCount.Load() != 0 {
		t.Error("connCount should be 0 after reset")
	}
}

func TestLimitDispatcher_UnlimitedUserFastPath(t *testing.T) {
	ld := newTestDispatcher()

	email := userEmail(1)
	// No device limit set for this user
	ld.UpdateLimits(map[string]int{email: 1}, nil)

	// Should use fast path (sync.Map), no lock needed
	for i := 0; i < 100; i++ {
		ip := "10.0.0." + string(rune('0'+i%10))
		if ld.checkDeviceLimit(email, ip) {
			t.Errorf("unlimited user should always be allowed (ip=%s)", ip)
		}
	}

	// Verify IPs are tracked in unlimitedIPs
	v, ok := ld.unlimitedIPs.Load(email)
	if !ok {
		t.Error("unlimited user should have entry in unlimitedIPs")
	}
	ic := v.(*ipCounter)
	ips := ic.aliveIPs()
	if len(ips) == 0 {
		t.Error("should have tracked some IPs")
	}
}

func TestLimitDispatcher_TrackLinkPreservesReader(t *testing.T) {
	ld := newTestDispatcher()
	email := userEmail(1)
	ld.UpdateLimits(map[string]int{email: 1}, map[string]int{email: 1})

	origReader := nopReader{}
	origWriter := &closeTrackingWriter{Writer: buf.Discard, onClose: func() {}}
	link := &transport.Link{Reader: origReader, Writer: origWriter}

	ld.trackLink(link, email, "1.1.1.1")

	if link.Reader != origReader {
		t.Fatal("trackLink must not replace link.Reader")
	}
	if link.Writer == origWriter {
		t.Fatal("trackLink should wrap link.Writer for lifecycle callbacks")
	}
}

func TestLimitDispatcher_CloseTrackingWriterReleasesConn(t *testing.T) {
	ld := newTestDispatcher()
	email := userEmail(1)
	ld.UpdateLimits(map[string]int{email: 1}, map[string]int{email: 1})
	if ld.checkDeviceLimit(email, "1.1.1.1") {
		t.Fatal("first connection should be allowed")
	}

	link := &transport.Link{Reader: nopReader{}, Writer: buf.Discard}
	ld.trackLink(link, email, "1.1.1.1")

	if got := ld.connCount.Load(); got != 1 {
		t.Fatalf("expected connCount=1 after tracking, got %d", got)
	}
	cw, ok := link.Writer.(*closeTrackingWriter)
	if !ok {
		t.Fatal("expected closeTrackingWriter wrapper")
	}
	if err := cw.Close(); err != nil {
		t.Fatalf("closeTrackingWriter.Close() error = %v", err)
	}
	if got := ld.connCount.Load(); got != 0 {
		t.Fatalf("expected connCount=0 after close, got %d", got)
	}
	if ld.checkDeviceLimit(email, "2.2.2.2") {
		t.Fatal("device slot should be released after writer close")
	}
}

// A user whose device limit is granted at runtime keeps stale entries in
// unlimitedIPs from earlier connections; delConn must still release the
// limitedIPs refcount so no ghost IP occupies a device slot forever.
func TestLimitDispatcher_DelConnAfterRuntimeLimitGrant(t *testing.T) {
	ld := newTestDispatcher()
	email := userEmail(1)

	// Unlimited era: connection tracked in unlimitedIPs.
	ld.UpdateLimits(map[string]int{email: 1}, nil)
	if ld.checkDeviceLimit(email, "1.1.1.1") {
		t.Fatal("unlimited user should be allowed")
	}

	// Admin grants device limit 1 at runtime.
	ld.UpdateLimits(map[string]int{email: 1}, map[string]int{email: 1})

	// New connection goes through the limited path.
	if ld.checkDeviceLimit(email, "2.2.2.2") {
		t.Fatal("first limited connection should be allowed")
	}

	// Close the limited-era connection: slot must be released even though
	// a stale unlimitedIPs entry exists for this email.
	ld.delConn(email, "2.2.2.2")

	aliveIPs, _ := ld.GetConnectionState()
	ips := aliveIPs[1]
	if len(ips) != 1 || !ips["1.1.1.1"] {
		t.Fatalf("alive IPs = %v, want only the pre-grant connection 1.1.1.1", ips)
	}
	if ld.checkDeviceLimit(email, "3.3.3.3") {
		t.Fatal("closing a limited connection must free the slot for a new IP")
	}
}

// The old checkDeviceLimit read ips[sourceIP]>0 under RLock, then incremented
// under Lock: a concurrent delConn could delete the entry in between, and the
// increment resurrected a refcount from nothing — a ghost device slot that
// no close can release. Under the write-lock re-check, admit/close cycles on
// the same IP must net out to zero.
func TestLimitDispatcher_AdmitCloseNoGhostResurrection(t *testing.T) {
	ld := newTestDispatcher()
	email := userEmail(1)
	ld.UpdateLimits(map[string]int{email: 1}, map[string]int{email: 1})

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				if !ld.checkDeviceLimit(email, "1.1.1.1") {
					ld.delConn(email, "1.1.1.1")
				}
			}
		}()
	}
	wg.Wait()

	// Every admitted connection was closed: no refcount may survive.
	ld.mu.RLock()
	_, ghost := ld.limitedIPs[email]
	ld.mu.RUnlock()
	if ghost {
		t.Fatal("ghost refcount survived admit/close cycles")
	}
}

// GetConnectionState copies limited-IP maps while holding RLock; concurrent
// delConn must not race (fatal under -race without the copy).
func TestLimitDispatcher_GetConnectionState_ConcurrentWithClose(t *testing.T) {
	ld := newTestDispatcher()
	email := userEmail(1)
	ld.UpdateLimits(map[string]int{email: 1}, map[string]int{email: 1000})

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			ip := fmt.Sprintf("10.0.%d.%d", (i>>8)&0xff, i&0xff)
			if !ld.checkDeviceLimit(email, ip) {
				ld.delConn(email, ip)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			ld.GetConnectionState()
		}
	}()

	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// Global device state from the panel must take part in admission: an IP
// already known globally is an existing device (allowed, locally tracked),
// merged sets count toward the limit, and rejection follows the same
// lexicographic soft preference as the local-only path.
func TestLimitDispatcher_GlobalDeviceMerge(t *testing.T) {
	ld := newTestDispatcher()
	email := userEmail(1)
	ld.UpdateLimits(map[string]int{email: 1}, map[string]int{email: 2})

	// Panel snapshot: another node already serves 8.8.8.8 for this user.
	ld.SetGlobalDevicesByUID(map[int][]string{1: {"8.8.8.8"}})

	if ld.checkDeviceLimit(email, "8.8.8.8") {
		t.Fatal("IP known globally must be allowed and locally tracked")
	}
	if ld.checkDeviceLimit(email, "1.1.1.1") {
		t.Fatal("second distinct IP should fill the remaining slot")
	}
	// Merged set {8.8.8.8, 1.1.1.1} is at limit; a candidate sorting after
	// both must be rejected (lexicographic order, "9..." > "8...").
	if !ld.checkDeviceLimit(email, "9.9.9.9") {
		t.Fatal("candidate above all merged IPs must be rejected at limit")
	}

	// Alive reporting stays local: the global echo must not double-report.
	ld.delConn(email, "1.1.1.1")
	aliveIPs, _ := ld.GetConnectionState()
	ips := aliveIPs[1]
	if len(ips) != 1 || !ips["8.8.8.8"] {
		t.Fatalf("alive IPs = %v, want only locally tracked 8.8.8.8", ips)
	}
}

// A stale global snapshot must be ignored entirely (local-only semantics),
// mirroring sing-box's 60s staleness fallback.
func TestLimitDispatcher_GlobalStaleFallsBackToLocal(t *testing.T) {
	ld := newTestDispatcher()
	email := userEmail(1)
	ld.UpdateLimits(map[string]int{email: 1}, map[string]int{email: 1})
	ld.SetGlobalDevicesByUID(map[int][]string{1: {"8.8.8.8"}})

	// Fresh snapshot: merged {8.8.8.8} is at limit, candidate sorting after
	// it loses.
	if !ld.checkDeviceLimit(email, "9.9.9.9") {
		t.Fatal("fresh global state must count toward the limit")
	}
	ld.delConn(email, "9.9.9.9")

	// Expire the snapshot: local-only admission admits again.
	ld.globalMu.Lock()
	ld.globalUpdatedAt = time.Now().Add(-2 * globalDeviceWindow)
	ld.globalMu.Unlock()
	if ld.checkDeviceLimit(email, "9.9.9.9") {
		t.Fatal("stale global state must be ignored (local has a free slot)")
	}
}

// The panel snapshot is keyed by panel user ID; the dispatcher must translate
// through emailToUID and drop UIDs it does not know.
func TestLimitDispatcher_GlobalByUIDTranslation(t *testing.T) {
	ld := newTestDispatcher()
	email := userEmail(7)
	ld.UpdateLimits(map[string]int{email: 7}, nil)

	ld.SetGlobalDevicesByUID(map[int][]string{
		7:  {"1.2.3.4"},
		99: {"5.6.7.8"},
	})

	ld.globalMu.RLock()
	got := ld.globalDevices[email]
	_, hasUnknown := ld.globalDevices[userEmail(99)]
	emptyForOthers := len(ld.globalDevices) == 1
	ld.globalMu.RUnlock()

	if len(got) != 1 || !got["1.2.3.4"] {
		t.Fatalf("global devices for uid 7 = %v, want {1.2.3.4}", got)
	}
	if hasUnknown || !emptyForOthers {
		t.Fatal("UIDs without an email mapping must be dropped")
	}

	ld.ClearGlobalDevices()
	ld.globalMu.RLock()
	cleared := len(ld.globalDevices) == 0 && ld.globalUpdatedAt.IsZero()
	ld.globalMu.RUnlock()
	if !cleared {
		t.Fatal("ClearGlobalDevices must empty the snapshot")
	}
}
