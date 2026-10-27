package xray

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
	appstats "github.com/xtls/xray-core/app/stats"
	xrayCore "github.com/xtls/xray-core/core"
	featurebandwidth "github.com/xtls/xray-core/features/bandwidth"
	xraystats "github.com/xtls/xray-core/features/stats"
	"golang.org/x/time/rate"
)

func newStatsManager(t *testing.T) xraystats.Manager {
	t.Helper()
	mgr, err := appstats.NewManager(context.Background(), &appstats.Config{})
	if err != nil {
		t.Fatalf("stats.NewManager() error = %v", err)
	}
	return mgr
}

func mustRegisterCounter(t *testing.T, mgr xraystats.Manager, name string) xraystats.Counter {
	t.Helper()
	counter, err := mgr.RegisterCounter(name)
	if err != nil {
		t.Fatalf("RegisterCounter(%q) error = %v", name, err)
	}
	return counter
}

func counterName(userID int, direction string) string {
	return fmt.Sprintf("user>>>%s>>>traffic>>>%s", userEmail(userID), direction)
}

func newStatsBackedXray(t *testing.T, users []model.UserSpec, ld *LimitDispatcher) (*Xray, xraystats.Manager) {
	t.Helper()
	mgr := newStatsManager(t)
	inst := new(xrayCore.Instance)
	if err := inst.AddFeature(mgr); err != nil {
		t.Fatalf("Instance.AddFeature(stats) error = %v", err)
	}
	x := New(config.KernelConfig{Type: "xray"})
	x.instance = inst
	x.limitDispatcher = ld
	x.users = users
	x.cumTraffic = make(map[int][2]int64)
	x.running.Store(true)
	return x, mgr
}

func TestXrayGetUserTrafficUsesBuiltInStatsAndDispatcherState(t *testing.T) {
	users := []model.UserSpec{
		{ID: 1, UUID: "uuid-1"},
		{ID: 2, UUID: "uuid-2"},
	}

	ld := newTestDispatcher()
	email1 := userEmail(1)
	email2 := userEmail(2)
	ld.UpdateLimits(map[string]int{email1: 1, email2: 2}, nil)
	ld.mu.Lock()
	ld.limitedIPs[email1] = map[string]int{"1.1.1.1": 1}
	ld.mu.Unlock()
	ref := &atomic.Int64{}
	ref.Store(1)
	ic := &ipCounter{}
	ic.ips.Store("2.2.2.2", ref)
	ld.unlimitedIPs.Store(email2, ic)
	ld.connCount.Store(7)

	x, mgr := newStatsBackedXray(t, users, ld)
	up1 := mustRegisterCounter(t, mgr, counterName(1, "uplink"))
	down1 := mustRegisterCounter(t, mgr, counterName(1, "downlink"))
	up2 := mustRegisterCounter(t, mgr, counterName(2, "uplink"))
	down2 := mustRegisterCounter(t, mgr, counterName(2, "downlink"))
	up1.Add(100)
	down1.Add(200)
	up2.Add(50)
	down2.Add(80)

	traffic, aliveIPs, connCount, err := x.GetUserTraffic(context.Background())
	if err != nil {
		t.Fatalf("GetUserTraffic() error = %v", err)
	}
	if connCount != 7 {
		t.Fatalf("connCount = %d, want 7", connCount)
	}
	if got := traffic[1]; got != [2]int64{100, 200} {
		t.Fatalf("traffic[1] = %v, want [100 200]", got)
	}
	if got := traffic[2]; got != [2]int64{50, 80} {
		t.Fatalf("traffic[2] = %v, want [50 80]", got)
	}
	if !aliveIPs[1]["1.1.1.1"] {
		t.Fatal("expected limited-user IP to be reported")
	}
	if !aliveIPs[2]["2.2.2.2"] {
		t.Fatal("expected unlimited-user IP to be reported")
	}

	up1.Add(30)
	down1.Add(40)
	traffic, _, _, err = x.GetUserTraffic(context.Background())
	if err != nil {
		t.Fatalf("second GetUserTraffic() error = %v", err)
	}
	if got := traffic[1]; got != [2]int64{130, 240} {
		t.Fatalf("traffic[1] after second poll = %v, want [130 240]", got)
	}
	if got := traffic[2]; got != [2]int64{50, 80} {
		t.Fatalf("traffic[2] after second poll = %v, want [50 80]", got)
	}
}

// A removed user's residual counter bytes must be reported exactly once.
func TestXrayRemovedUserResidualReportedOnce(t *testing.T) {
	users := []model.UserSpec{{ID: 5, UUID: "uuid-5"}, {ID: 6, UUID: "uuid-6"}}
	x, mgr := newStatsBackedXray(t, users, nil)
	up := mustRegisterCounter(t, mgr, counterName(5, "uplink"))
	down := mustRegisterCounter(t, mgr, counterName(5, "downlink"))
	up.Add(10)
	down.Add(20)

	x.mu.Lock()
	x.drainRemovedStats(users[:1])
	x.users = users[1:]
	x.mu.Unlock()

	traffic, _, _, err := x.GetUserTraffic(context.Background())
	if err != nil {
		t.Fatalf("GetUserTraffic() error = %v", err)
	}
	if got := traffic[5]; got != [2]int64{10, 20} {
		t.Fatalf("residual traffic[5] = %v, want [10 20]", got)
	}

	traffic, _, _, err = x.GetUserTraffic(context.Background())
	if err != nil {
		t.Fatalf("second GetUserTraffic() error = %v", err)
	}
	if _, still := traffic[5]; still {
		t.Fatalf("residual must be reported once, got %v", traffic[5])
	}
}

func TestXrayUpdateDispatcherLimitsPropagatesDeviceMetadata(t *testing.T) {
	x := New(config.KernelConfig{Type: "xray"})
	ld := newTestDispatcher()
	x.limitDispatcher = ld

	users := []model.UserSpec{
		{ID: 7, UUID: "uuid-7", DeviceLimit: 2, SpeedLimit: 12},
		{ID: 9, UUID: "uuid-9", DeviceLimit: 0, SpeedLimit: 0},
	}

	x.updateDispatcherLimits(users)

	if got := ld.deviceLimits[userEmail(7)]; got != 2 {
		t.Fatalf("deviceLimits[email] = %d, want 2", got)
	}
	if got := ld.deviceLimits["uuid-7"]; got != 2 {
		t.Fatalf("deviceLimits[uuid] = %d, want 2", got)
	}
	if _, ok := ld.deviceLimits[userEmail(9)]; ok {
		t.Fatal("unexpected device limit entry for unlimited user")
	}
}

func TestXraySetSpeedLimitFuncUsesPatchedCorePath(t *testing.T) {
	x := New(config.KernelConfig{Type: "xray"})
	called := false

	x.SetSpeedLimitFunc(func(string) *rate.Limiter {
		called = true
		return rate.NewLimiter(rate.Limit(1), 1)
	})

	if called {
		t.Fatal("patched xray path should not consult external speed-limit callbacks")
	}

	mu, err := toMemoryUser("vless", &model.NodeSpec{Protocol: "vless"}, model.UserSpec{ID: 1, UUID: "11111111-1111-1111-1111-111111111111", SpeedLimit: 8})
	if err != nil {
		t.Fatalf("toMemoryUser() error = %v", err)
	}
	if mu.Level != 0 {
		t.Fatalf("MemoryUser.Level = %d, want 0", mu.Level)
	}
}

func TestXrayUpdateBandwidthLimitsWritesPatchedCoreFeature(t *testing.T) {
	inst := new(xrayCore.Instance)
	bm := featurebandwidth.New()
	if err := inst.AddFeature(bm); err != nil {
		t.Fatalf("Instance.AddFeature(bandwidth) error = %v", err)
	}
	x := New(config.KernelConfig{Type: "xray"})
	x.instance = inst
	x.updateBandwidthLimits([]model.UserSpec{{ID: 1, UUID: "uuid-1", SpeedLimit: 8}})
	lim := bm.GetUserLimiter(userEmail(1))
	if lim == nil {
		t.Fatal("expected patched bandwidth feature to receive user limiter")
	}
}

func TestXrayUpdateBandwidthLimitsUsesSpeedLimitFunc(t *testing.T) {
	inst := new(xrayCore.Instance)
	bm := featurebandwidth.New()
	if err := inst.AddFeature(bm); err != nil {
		t.Fatalf("Instance.AddFeature(bandwidth) error = %v", err)
	}
	x := New(config.KernelConfig{Type: "xray"})
	x.instance = inst
	x.users = []model.UserSpec{{ID: 1, UUID: "uuid-1", SpeedLimit: 8}}
	shared := rate.NewLimiter(7, 7)
	x.SetSpeedLimitFunc(func(uuid string) *rate.Limiter {
		if uuid != "uuid-1" {
			t.Fatalf("unexpected uuid: %s", uuid)
		}
		return shared
	})
	lim := bm.GetUserLimiter(userEmail(1))
	if lim != shared {
		t.Fatal("expected patched bandwidth feature to consume shared limiter from callback")
	}
}

func TestXrayUpdateBandwidthLimitsFallsBackToUserSpeed(t *testing.T) {
	inst := new(xrayCore.Instance)
	bm := featurebandwidth.New()
	if err := inst.AddFeature(bm); err != nil {
		t.Fatalf("Instance.AddFeature(bandwidth) error = %v", err)
	}
	x := New(config.KernelConfig{Type: "xray"})
	x.instance = inst
	x.users = []model.UserSpec{{ID: 2, UUID: "uuid-2", SpeedLimit: 16}}
	x.updateBandwidthLimits(nil)
	if bm.GetUserLimiter(userEmail(2)) == nil {
		t.Fatal("expected fallback limiter derived from user speed")
	}
}

func TestXrayUpdateUsersLimitOnlyRefreshesDispatcherAndBandwidth(t *testing.T) {
	x := New(config.KernelConfig{Type: "xray"})
	ld := newTestDispatcher()
	inst := new(xrayCore.Instance)
	bm := featurebandwidth.New()
	if err := inst.AddFeature(bm); err != nil {
		t.Fatalf("Instance.AddFeature(bandwidth) error = %v", err)
	}
	x.instance = inst
	x.limitDispatcher = ld
	x.users = []model.UserSpec{{ID: 1, UUID: "uuid-1", DeviceLimit: 1, SpeedLimit: 8}}

	added, removed, err := x.UpdateUsers([]model.UserSpec{{ID: 1, UUID: "uuid-1", DeviceLimit: 3, SpeedLimit: 16}})
	if err != nil {
		t.Fatalf("UpdateUsers() error = %v", err)
	}
	if added != 0 || removed != 0 {
		t.Fatalf("UpdateUsers() counts = (%d, %d), want (0, 0)", added, removed)
	}
	if got := ld.deviceLimits[userEmail(1)]; got != 3 {
		t.Fatalf("device limit after refresh = %d, want 3", got)
	}
	if bm.GetUserLimiter(userEmail(1)) == nil {
		t.Fatal("expected bandwidth limiter to be refreshed for unchanged user set")
	}
}

func TestXrayRemoveUsersStopsKernelWhenLastUserRemoved(t *testing.T) {
	x := New(config.KernelConfig{Type: "xray"})
	x.instance = new(xrayCore.Instance)
	ld := newTestDispatcher()
	x.limitDispatcher = ld
	x.users = []model.UserSpec{{ID: 1, UUID: "uuid-1"}}
	x.running.Store(true)

	removed, err := x.RemoveUsers([]model.UserSpec{{ID: 1, UUID: "uuid-1"}})
	if err != nil {
		t.Fatalf("RemoveUsers() error = %v", err)
	}
	if removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}
	if x.IsRunning() {
		t.Fatal("expected xray to stop when last user is removed")
	}
}
