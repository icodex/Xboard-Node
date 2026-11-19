package limiter

import (
	"testing"

	"github.com/cedar2025/xboard-node/internal/model"
)

func TestNew(t *testing.T) {
	l := New()
	if l == nil {
		t.Fatal("New returned nil")
	}
}

func TestUpdateUsers(t *testing.T) {
	l := New()
	l.UpdateUsers([]model.UserSpec{
		{ID: 1, UUID: "u1"},
		{ID: 3, UUID: "u3"},
	})

	// User specs are replaced wholesale.
	l.mu.RLock()
	_, hasOld := l.users[1]
	_, hasNew := l.users[3]
	l.mu.RUnlock()
	if !hasOld || !hasNew {
		t.Fatalf("expected users {1,3} after update, got %v", l.users)
	}
}

func TestGetDeviceLimitByUUID(t *testing.T) {
	l := New()
	l.UpdateUsers([]model.UserSpec{
		{ID: 1, UUID: "u1", DeviceLimit: 3},
		{ID: 2, UUID: "u2", DeviceLimit: 0},
	})

	// User with device limit
	limit, ok := l.GetDeviceLimitByUUID("u1")
	if !ok || limit != 3 {
		t.Errorf("expected (3, true), got (%d, %v)", limit, ok)
	}

	// User without device limit
	_, ok = l.GetDeviceLimitByUUID("u2")
	if ok {
		t.Error("expected (_, false) for user with no device limit")
	}

	// Unknown UUID
	_, ok = l.GetDeviceLimitByUUID("unknown")
	if ok {
		t.Error("expected (_, false) for unknown UUID")
	}
}

func TestUpdateUsersDelta(t *testing.T) {
	l := New()
	l.UpdateUsers([]model.UserSpec{
		{ID: 1, UUID: "a", DeviceLimit: 2},
		{ID: 2, UUID: "b", DeviceLimit: 1},
	})

	l.UpdateUsersDelta([]model.UserSpec{
		{ID: 2, UUID: "b", DeviceLimit: 3},
		{ID: 3, UUID: "c", DeviceLimit: 0},
	}, nil)

	if got, ok := l.GetDeviceLimitByUUID("b"); !ok || got != 3 {
		t.Fatalf("b limit = %d/%v, want 3", got, ok)
	}
	if got, ok := l.GetDeviceLimitByUUID("a"); !ok || got != 2 {
		t.Fatalf("a limit lost: %d/%v", got, ok)
	}

	l.UpdateUsersDelta(nil, []int{1})
	if _, ok := l.GetDeviceLimitByUUID("a"); ok {
		t.Fatal("removed user's UUID must not resolve")
	}
}
