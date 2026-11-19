package controlplane

import (
	"runtime"
	"testing"

	"github.com/cedar2025/xboard-node/internal/model"
)

func TestNodeMailboxLatestStateAndNotifyCollapse(t *testing.T) {
	mb := NewNodeMailbox()
	cfg1 := &model.NodeSpec{Protocol: "vmess", ServerPort: 10010}
	cfg2 := &model.NodeSpec{Protocol: "vless", ServerPort: 10020}

	mb.Apply(Event{Type: EventSyncConfig, Config: cfg1})
	mb.Apply(Event{Type: EventSyncConfig, Config: cfg2})

	select {
	case <-mb.NotifyCh():
	default:
		t.Fatal("expected collapsed notify signal")
	}

	mb.MarkReady()
	state := mb.DrainIfReady()
	if !state.HasConfig || state.Config == nil {
		t.Fatal("expected config state")
	}
	if state.Config.Protocol != "vless" || state.Config.ServerPort != 10020 {
		t.Fatalf("unexpected config: %+v", state.Config)
	}
}

func TestNodeMailboxFullUsersOverwriteAndDeltaBeforeBaseline(t *testing.T) {
	mb := NewNodeMailbox()
	mb.Apply(Event{
		Type:        EventSyncUserDelta,
		DeltaAction: "add",
		DeltaUsers:  []model.UserSpec{{ID: 1, UUID: "u1"}},
	})
	mb.MarkReady()
	state := mb.DrainIfReady()
	if !state.NeedsReconcile {
		t.Fatal("expected reconcile when delta arrives before baseline")
	}

	mb.Apply(Event{Type: EventSyncUsers, Users: []model.UserSpec{{ID: 1, UUID: "u1"}}})
	mb.Apply(Event{Type: EventSyncUsers, Users: []model.UserSpec{{ID: 2, UUID: "u2"}}})
	state = mb.DrainIfReady()
	if !state.HasUsers {
		t.Fatal("expected users snapshot")
	}
	if len(state.Users) != 1 || state.Users[0].ID != 2 {
		t.Fatalf("unexpected users: %+v", state.Users)
	}
}

func TestNodeMailboxDevicesLatestWins(t *testing.T) {
	mb := NewNodeMailbox()
	mb.Apply(Event{Type: EventSyncDevices, DeviceUsers: map[int][]string{1: {"1.1.1.1"}}})
	mb.Apply(Event{Type: EventSyncDevices, DeviceUsers: map[int][]string{1: {"2.2.2.2"}}})
	mb.MarkReady()
	state := mb.DrainIfReady()
	if !state.HasDevices {
		t.Fatal("expected devices state")
	}
	if got := state.DeviceUsers[1][0]; got != "2.2.2.2" {
		t.Fatalf("unexpected device state: %v", state.DeviceUsers)
	}
}

func TestNodeMailboxDeviceDeltaMergesInsteadOfReplacing(t *testing.T) {
	mb := NewNodeMailbox()
	// full snapshot first: users 1 and 2 have devices
	mb.Apply(Event{Type: EventSyncDevices, DeviceUsers: map[int][]string{
		1: {"1.1.1.1"},
		2: {"2.2.2.2"},
	}})
	mb.MarkReady()
	mb.DrainIfReady()

	// delta touches user 1 only; user 2 must survive
	mb.Apply(Event{Type: EventSyncDevicesDelta, DeviceUsers: map[int][]string{1: {"9.9.9.9"}}})
	state := mb.DrainIfReady()
	if !state.HasDevices {
		t.Fatal("expected devices state")
	}
	if got := state.DeviceUsers[1][0]; got != "9.9.9.9" {
		t.Fatalf("delta did not update user 1: %v", state.DeviceUsers)
	}
	if got := state.DeviceUsers[2][0]; got != "2.2.2.2" {
		t.Fatalf("delta dropped unrelated user 2: %v", state.DeviceUsers)
	}
}

func TestNodeMailboxDeviceDeltaRemovesUsers(t *testing.T) {
	mb := NewNodeMailbox()
	mb.Apply(Event{Type: EventSyncDevices, DeviceUsers: map[int][]string{
		1: {"1.1.1.1"},
		2: {"2.2.2.2"},
	}})
	mb.MarkReady()
	mb.DrainIfReady()

	mb.Apply(Event{Type: EventSyncDevicesDelta, DeviceUsersRemoved: []int{1}})
	state := mb.DrainIfReady()
	if _, ok := state.DeviceUsers[1]; ok {
		t.Fatalf("user 1 should be gone: %v", state.DeviceUsers)
	}
	if got := state.DeviceUsers[2][0]; got != "2.2.2.2" {
		t.Fatalf("user 2 should survive: %v", state.DeviceUsers)
	}
}

func TestNodeMailboxDeviceDeltaWithoutSnapshotRequestsReconcile(t *testing.T) {
	mb := NewNodeMailbox()
	mb.MarkReady()

	mb.Apply(Event{Type: EventSyncDevicesDelta, DeviceUsers: map[int][]string{1: {"1.1.1.1"}}})

	state := mb.DrainIfReady()
	if !state.NeedsReconcile {
		t.Fatal("a delta before any full snapshot must trigger a reconcile")
	}
	if state.HasDevices {
		t.Fatalf("partial device state must not be applied: %v", state.DeviceUsers)
	}
}

func TestNodeMailboxReconcileNotifies(t *testing.T) {
	mb := NewNodeMailbox()
	mb.MarkReady()

	// Drain the MarkReady notification
	select {
	case <-mb.NotifyCh():
	default:
	}

	// Delta without baseline should trigger reconcile AND notify
	mb.Apply(Event{
		Type:        EventSyncUserDelta,
		DeltaAction: "add",
		DeltaUsers:  []model.UserSpec{{ID: 1, UUID: "u1"}},
	})

	select {
	case <-mb.NotifyCh():
	default:
		t.Fatal("expected notify on reconcile path")
	}

	state := mb.DrainIfReady()
	if !state.NeedsReconcile {
		t.Fatal("expected NeedsReconcile")
	}
}

func TestNodeMailboxSeedBaselineEnablesDelta(t *testing.T) {
	mb := NewNodeMailbox()
	mb.SeedBaseline([]model.UserSpec{{ID: 1, UUID: "u1"}, {ID: 2, UUID: "u2"}}, nil)
	mb.MarkReady()

	// Drain MarkReady notify
	select {
	case <-mb.NotifyCh():
	default:
	}

	// Delta should now apply incrementally, not trigger reconcile
	mb.Apply(Event{
		Type:        EventSyncUserDelta,
		DeltaAction: "add",
		DeltaUsers:  []model.UserSpec{{ID: 3, UUID: "u3"}},
	})

	select {
	case <-mb.NotifyCh():
	default:
		t.Fatal("expected notify after delta")
	}

	state := mb.DrainIfReady()
	if state.NeedsReconcile {
		t.Fatal("should not need reconcile after seeded baseline")
	}
	if !state.HasUsers {
		t.Fatal("expected users")
	}
	if len(state.Users) != 3 {
		t.Fatalf("expected 3 users, got %d: %+v", len(state.Users), state.Users)
	}
}

func TestNodeMailboxDeltaFailedApplyNotifies(t *testing.T) {
	mb := NewNodeMailbox()
	mb.SeedBaseline([]model.UserSpec{{ID: 1, UUID: "u1"}}, nil)
	mb.MarkReady()

	// Drain MarkReady notify
	select {
	case <-mb.NotifyCh():
	default:
	}

	// Invalid action should trigger reconcile and still notify
	mb.Apply(Event{
		Type:        EventSyncUserDelta,
		DeltaAction: "invalid_action",
		DeltaUsers:  []model.UserSpec{{ID: 2, UUID: "u2"}},
	})

	select {
	case <-mb.NotifyCh():
	default:
		t.Fatal("expected notify on failed delta apply")
	}

	state := mb.DrainIfReady()
	if !state.NeedsReconcile {
		t.Fatal("expected NeedsReconcile for invalid delta action")
	}
}

// One delta per edited user arrives on the shared WS read goroutine. Copying
// the whole table per event made a 10k-user bulk edit quadratic; the mailbox
// now updates an index in place and compacts once per drain.
func TestNodeMailboxUserDeltaDoesNotCopyWholeTable(t *testing.T) {
	const n = 20000
	users := make([]model.UserSpec, n)
	for i := range users {
		users[i] = model.UserSpec{ID: i + 1, UUID: "uuid"}
	}
	mb := NewNodeMailbox()
	mb.SeedBaseline(users, nil)
	mb.MarkReady()
	mb.DrainIfReady()

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < 200; i++ {
		mb.Apply(Event{Type: EventSyncUserDelta, DeltaAction: "add", DeltaUsers: []model.UserSpec{{ID: 1, UUID: "updated"}}})
	}
	runtime.ReadMemStats(&after)

	allocated := after.TotalAlloc - before.TotalAlloc
	if limit := uint64(8 << 20); allocated > limit {
		t.Fatalf("200 single-user updates allocated %d bytes; the table is still copied per event (limit %d)", allocated, limit)
	}
}

func TestNodeMailboxUserDeltaOrderBeforeDrain(t *testing.T) {
	mb := NewNodeMailbox()
	mb.SeedBaseline([]model.UserSpec{{ID: 1, UUID: "a"}, {ID: 2, UUID: "b"}}, nil)
	mb.MarkReady()

	mb.Apply(Event{Type: EventSyncUserDelta, DeltaAction: "remove", DeltaUsers: []model.UserSpec{{ID: 2}}})
	mb.Apply(Event{Type: EventSyncUserDelta, DeltaAction: "add", DeltaUsers: []model.UserSpec{{ID: 2, UUID: "b2"}}})
	mb.Apply(Event{Type: EventSyncUserDelta, DeltaAction: "add", DeltaUsers: []model.UserSpec{{ID: 3, UUID: "c"}}})

	state := mb.DrainIfReady()
	if !state.HasUsers {
		t.Fatal("delta changes were not drained")
	}
	want := map[int]string{1: "a", 2: "b2", 3: "c"}
	if len(state.Users) != len(want) {
		t.Fatalf("users = %v, want %v", state.Users, want)
	}
	for _, user := range state.Users {
		if want[user.ID] != user.UUID {
			t.Fatalf("user %d = %q, want %q", user.ID, user.UUID, want[user.ID])
		}
	}

	if st := mb.DrainIfReady(); st.HasUsers {
		t.Fatal("a drain without changes must not produce a users snapshot")
	}

	mb.Apply(Event{Type: EventSyncUserDelta, DeltaAction: "remove", DeltaUsers: []model.UserSpec{{ID: 1}}})
	state = mb.DrainIfReady()
	if len(state.Users) != 2 {
		t.Fatalf("remove was not compacted: %v", state.Users)
	}
}

// Removing the last user must produce a non-nil empty slice: handleWSEvent
// treats a nil users payload as "no update" and would keep the removed user
// alive forever (old implementation returned nil here).
func TestNodeMailboxRemovingAllUsersKeepsNonNilEmptySlice(t *testing.T) {
	mb := NewNodeMailbox()
	mb.SeedBaseline([]model.UserSpec{{ID: 1, UUID: "a"}, {ID: 2, UUID: "b"}}, nil)
	mb.MarkReady()

	mb.Apply(Event{Type: EventSyncUserDelta, DeltaAction: "remove", DeltaUsers: []model.UserSpec{{ID: 1}, {ID: 2}}})
	state := mb.DrainIfReady()

	if !state.HasUsers {
		t.Fatal("removing all users must still drain a users update")
	}
	if state.Users == nil {
		t.Fatal("empty result must be non-nil so the service does not early-return")
	}
	if len(state.Users) != 0 {
		t.Fatalf("users = %v, want empty", state.Users)
	}
}

// After compaction the index must be rebuilt, otherwise a later add reuses a
// stale position and the user lands in the wrong slot or duplicates.
func TestNodeMailboxAddAfterDrainUsesRebuiltIndex(t *testing.T) {
	mb := NewNodeMailbox()
	mb.SeedBaseline([]model.UserSpec{{ID: 1, UUID: "a"}, {ID: 2, UUID: "b"}}, nil)
	mb.MarkReady()

	mb.Apply(Event{Type: EventSyncUserDelta, DeltaAction: "remove", DeltaUsers: []model.UserSpec{{ID: 1}}})
	if st := mb.DrainIfReady(); len(st.Users) != 1 {
		t.Fatalf("after remove: %v", st.Users)
	}

	mb.Apply(Event{Type: EventSyncUserDelta, DeltaAction: "add", DeltaUsers: []model.UserSpec{{ID: 3, UUID: "c"}, {ID: 1, UUID: "a2"}}})
	state := mb.DrainIfReady()
	want := map[int]string{2: "b", 3: "c", 1: "a2"}
	if len(state.Users) != len(want) {
		t.Fatalf("users = %v, want %v", state.Users, want)
	}
	for _, user := range state.Users {
		if want[user.ID] != user.UUID {
			t.Fatalf("user %d = %q, want %q", user.ID, user.UUID, want[user.ID])
		}
	}
}
