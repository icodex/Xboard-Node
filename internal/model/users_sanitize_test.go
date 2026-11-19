package model

import "testing"

const (
	uuidA = "11111111-1111-1111-1111-111111111111"
	uuidB = "22222222-2222-2222-2222-222222222222"
	uuidC = "33333333-3333-3333-3333-333333333333"
)

func TestSanitizeUserSpecs(t *testing.T) {
	in := []UserSpec{
		{ID: 0, UUID: uuidA},
		{ID: 1, UUID: ""},
		{ID: 2, UUID: "not-a-uuid"},
		{ID: 3, UUID: uuidA},
		{ID: 3, UUID: uuidB}, // duplicate ID
		{ID: 4, UUID: uuidA}, // duplicate UUID
		{ID: 5, UUID: uuidC},
	}

	generic := SanitizeUserSpecs(in, false)
	assertIDs(t, generic, 2, 3, 5)

	strict := SanitizeUserSpecs(in, true) // vmess/vless: malformed UUID dropped
	assertIDs(t, strict, 3, 5)

	empty := SanitizeUserSpecs([]UserSpec{{ID: 0}}, false)
	if empty == nil || len(empty) != 0 {
		t.Fatalf("all-invalid input must yield non-nil empty slice, got %#v", empty)
	}
	if SanitizeUserSpecs(nil, false) != nil {
		t.Fatal("nil input must stay nil (no update)")
	}

	if !ProtocolRequiresUUID("vless") || !ProtocolRequiresUUID("VMess") || ProtocolRequiresUUID("trojan") {
		t.Fatal("uuid protocol detection is wrong")
	}
}

func TestSanitizeUserDeltas(t *testing.T) {
	removed := SanitizeUserDeltas([]UserSpec{{ID: 1}, {ID: 0}, {ID: 2, UUID: ""}}, "remove", true)
	assertIDs(t, removed, 1, 2)

	added := SanitizeUserDeltas([]UserSpec{{ID: 1, UUID: ""}, {ID: 2, UUID: uuidA}}, "add", true)
	assertIDs(t, added, 2)
}

func assertIDs(t *testing.T, users []UserSpec, want ...int) {
	t.Helper()
	if len(users) != len(want) {
		t.Fatalf("users = %v, want IDs %v", users, want)
	}
	for i, id := range want {
		if users[i].ID != id {
			t.Fatalf("users = %v, want IDs %v", users, want)
		}
	}
}

func TestSpeedLimitBytesPerSecOverflowGuard(t *testing.T) {
	if got := SpeedLimitBytesPerSec(0); got != 0 {
		t.Fatalf("unlimited = %d, want 0", got)
	}
	if got := SpeedLimitBytesPerSec(10); got != 1_250_000 {
		t.Fatalf("10 Mbps = %d, want 1250000", got)
	}
	if got := SpeedLimitBytesPerSec(int(^uint(0) >> 1)); got != 1_000_000_000_000 {
		t.Fatalf("overflow guard = %d, want 1e12", got)
	}
}
