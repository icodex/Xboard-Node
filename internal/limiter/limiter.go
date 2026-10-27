package limiter

import (
	"sync"

	"github.com/cedar2025/xboard-node/internal/model"
)

// Limiter provides per-user limit lookups for kernel gate-keeping.
type Limiter struct {
	mu    sync.RWMutex
	users map[int]model.UserSpec // current user specs (speed limits, device limits)

	// uuidDeviceLimit provides O(1) UUID→device-limit lookup for the
	// kernel gate-keeping hot path (called per new connection).
	uuidDeviceLimit map[string]int
}

func New() *Limiter {
	return &Limiter{
		users:           make(map[int]model.UserSpec),
		uuidDeviceLimit: make(map[string]int),
	}
}

// UpdateUsers refreshes the user limit configuration.
func (l *Limiter) UpdateUsers(users []model.UserSpec) {
	l.mu.Lock()
	defer l.mu.Unlock()

	newUsers := make(map[int]model.UserSpec, len(users))
	for _, u := range users {
		newUsers[u.ID] = u
	}

	l.users = newUsers

	// Rebuild UUID→device-limit index for O(1) lookups.
	idx := make(map[string]int, len(newUsers))
	for _, u := range newUsers {
		if u.DeviceLimit > 0 {
			idx[u.UUID] = u.DeviceLimit
		}
	}
	l.uuidDeviceLimit = idx
}

// GetDeviceLimitByUUID returns the device limit for a user identified by UUID.
// Returns (limit, true) if a device limit is set, (0, false) otherwise.
// This is designed to be passed as a function reference to kernel.SetDeviceLimitFunc.
func (l *Limiter) GetDeviceLimitByUUID(uuid string) (int, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	limit, ok := l.uuidDeviceLimit[uuid]
	return limit, ok
}
