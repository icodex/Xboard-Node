package model

import (
	"strings"

	"github.com/google/uuid"

	"github.com/cedar2025/xboard-node/internal/nlog"
)

// ProtocolRequiresUUID reports whether the kernel validates the user UUID as a
// UUID (vmess/vless do; trojan/socks read it as a password, any string works).
func ProtocolRequiresUUID(protocol string) bool {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "vmess", "vless":
		return true
	}
	return false
}

// SanitizeUserSpecs drops entries no kernel can serve — missing/zero ID, empty
// UUID, malformed UUID for uuid protocols — and de-duplicates by ID and UUID.
// A single bad user otherwise makes the kernel reject the whole config and
// keeps the node in a start-retry loop.
//
// A non-nil input yields a non-nil result even when everything was dropped:
// the service treats nil as "no update", which would keep removed users alive.
func SanitizeUserSpecs(users []UserSpec, requireUUID bool) []UserSpec {
	if users == nil {
		return nil
	}
	out := make([]UserSpec, 0, len(users))
	seenID := make(map[int]struct{}, len(users))
	seenUUID := make(map[string]struct{}, len(users))
	dropped := 0
	for _, user := range users {
		if user.ID <= 0 || strings.TrimSpace(user.UUID) == "" {
			dropped++
			continue
		}
		if requireUUID {
			if _, err := uuid.Parse(strings.TrimSpace(user.UUID)); err != nil {
				dropped++
				continue
			}
		}
		key := strings.ToLower(strings.TrimSpace(user.UUID))
		if _, ok := seenID[user.ID]; ok {
			dropped++
			continue
		}
		if _, ok := seenUUID[key]; ok {
			dropped++
			continue
		}
		seenID[user.ID] = struct{}{}
		seenUUID[key] = struct{}{}
		out = append(out, user)
	}
	if dropped > 0 {
		nlog.Core().Warn("dropped invalid panel users", "count", dropped)
	}
	return out
}

// SanitizeUserDeltas keeps remove payloads (ID-only is legal) and applies the
// full rules to add payloads.
func SanitizeUserDeltas(users []UserSpec, action string, requireUUID bool) []UserSpec {
	if users == nil {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(action), "remove") {
		out := make([]UserSpec, 0, len(users))
		for _, user := range users {
			if user.ID > 0 {
				out = append(out, user)
			}
		}
		return out
	}
	return SanitizeUserSpecs(users, requireUUID)
}

// SpeedLimitBytesPerSec converts Mbps to bytes/s with an overflow guard. The
// naive int(mbps)*1_000_000/8 overflows for absurd panel values and yields a
// negative rate, which blocks the user's connections forever.
func SpeedLimitBytesPerSec(mbps int) int64 {
	if mbps <= 0 {
		return 0
	}
	const maxMbps = 8_000_000 // 8 Tbps; far above any NIC, keeps the product in int64
	if mbps > maxMbps {
		mbps = maxMbps
	}
	return int64(mbps) * 1_000_000 / 8
}
