package limiter

import (
	"sync"
	"sync/atomic"

	"github.com/cedar2025/xboard-node/internal/model"
	"golang.org/x/time/rate"
)

// SpeedTrackerLogCallback is called when bucket updates occur.
type SpeedTrackerLogCallback func(msg string)

// SpeedTracker manages per-user token-bucket rate limiters.
// It does NOT wrap connections itself — instead, ConnTracker consults it
// via GetLimiter to embed rate limiting in the same tracked connection
// wrapper that does byte counting.
type SpeedTracker struct {
	limiter *Limiter
	mu      sync.RWMutex
	buckets map[int]*rate.Limiter // userID → shared rate limiter
	uuidMap map[string]int        // UUID → userID
	idUUID  map[int]string        // userID → UUID (removal needs the reverse)

	// Fast-path: when no users have a speed limit, GetLimiter returns nil
	// immediately without any map lookup.
	hasLimits atomic.Bool

	// Optional callback for logging
	logFunc SpeedTrackerLogCallback
}

// NewSpeedTracker creates a bucket manager for per-user bandwidth throttling.
func NewSpeedTracker(l *Limiter) *SpeedTracker {
	return &SpeedTracker{
		limiter: l,
		buckets: make(map[int]*rate.Limiter),
		uuidMap: make(map[string]int),
		idUUID:  make(map[int]string),
	}
}

// SetLogCallback sets the logging callback.
func (t *SpeedTracker) SetLogCallback(f SpeedTrackerLogCallback) {
	t.logFunc = f
}

// UpdateBuckets updates the UUID→userID mapping and syncs existing limiters.
func (t *SpeedTracker) UpdateBuckets() {
	currentUsers := make([]model.UserSpec, 0, 32)
	t.limiter.mu.RLock()
	for _, u := range t.limiter.users {
		currentUsers = append(currentUsers, u)
	}
	t.limiter.mu.RUnlock()

	func() {
		t.mu.Lock()
		defer t.mu.Unlock()

		newUUIDMap := make(map[string]int, len(currentUsers))
		newIDUUID := make(map[int]string, len(currentUsers))
		activeIDs := make(map[int]struct{}, len(currentUsers))

		for _, user := range currentUsers {
			activeIDs[user.ID] = struct{}{}
			if user.UUID != "" {
				newUUIDMap[user.UUID] = user.ID
				newIDUUID[user.ID] = user.UUID
			}

			// Update existing limiter if speed changed
			if lim, ok := t.buckets[user.ID]; ok {
				if user.SpeedLimit > 0 {
					bytesPerSec := int(model.SpeedLimitBytesPerSec(user.SpeedLimit))
					burst := bytesPerSec
					if burst < 64*1024 {
						burst = 64 * 1024
					}
					lim.SetLimit(rate.Limit(bytesPerSec))
					lim.SetBurst(burst)
				} else {
					delete(t.buckets, user.ID)
				}
			}
		}

		// Clean up buckets for removed users
		for id := range t.buckets {
			if _, ok := activeIDs[id]; !ok {
				delete(t.buckets, id)
			}
		}

		t.uuidMap = newUUIDMap
		t.idUUID = newIDUUID
		t.hasLimits.Store(len(t.buckets) > 0)
	}()

	if t.logFunc != nil {
		t.logFunc("buckets updated")
	}
}

// UpdateBucketsDelta applies one panel delta without rebuilding the UUID maps
// or scanning every active user. Buckets themselves are created lazily by
// GetLimiter on the first connection.
func (t *SpeedTracker) UpdateBucketsDelta(upserts []model.UserSpec, removedIDs []int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, id := range removedIDs {
		delete(t.buckets, id)
		if uuid, ok := t.idUUID[id]; ok {
			delete(t.uuidMap, uuid)
			delete(t.idUUID, id)
		}
	}
	for _, user := range upserts {
		if old, ok := t.idUUID[user.ID]; ok && user.UUID != "" && old != user.UUID {
			delete(t.uuidMap, old)
		}
		if user.UUID != "" {
			t.uuidMap[user.UUID] = user.ID
			t.idUUID[user.ID] = user.UUID
		}
		lim, ok := t.buckets[user.ID]
		if !ok {
			continue
		}
		if user.SpeedLimit <= 0 {
			delete(t.buckets, user.ID)
			continue
		}
		bytesPerSec := int(model.SpeedLimitBytesPerSec(user.SpeedLimit))
		burst := bytesPerSec
		if burst < 64*1024 {
			burst = 64 * 1024
		}
		lim.SetLimit(rate.Limit(bytesPerSec))
		lim.SetBurst(burst)
	}
	t.hasLimits.Store(len(t.buckets) > 0)
	if t.logFunc != nil {
		t.logFunc("buckets updated")
	}
}

// GetLimiter returns the rate limiter for the given user UUID, or nil if
// no limit applies. Creates limiter on-demand if not exists.
// Thread-safe.
func (t *SpeedTracker) GetLimiter(user string) *rate.Limiter {
	t.mu.RLock()
	uid, exists := t.uuidMap[user]
	if !exists {
		t.mu.RUnlock()
		return nil
	}
	if lim, ok := t.buckets[uid]; ok {
		t.mu.RUnlock()
		return lim
	}
	t.mu.RUnlock()

	// Get user info from limiter
	t.limiter.mu.RLock()
	u, userExists := t.limiter.users[uid]
	t.limiter.mu.RUnlock()

	if !userExists || u.SpeedLimit <= 0 {
		return nil
	}

	// Create limiter on-demand
	bytesPerSec := int(model.SpeedLimitBytesPerSec(u.SpeedLimit))
	burst := bytesPerSec
	if burst < 64*1024 {
		burst = 64 * 1024
	}

	lim := rate.NewLimiter(rate.Limit(bytesPerSec), burst)

	t.mu.Lock()
	// Double-check after acquiring write lock
	if existing, ok := t.buckets[uid]; ok {
		t.mu.Unlock()
		return existing
	}
	t.buckets[uid] = lim
	t.hasLimits.Store(true)
	t.mu.Unlock()

	return lim
}

// HasLimits returns true if any user currently has a speed limit configured.
func (t *SpeedTracker) HasLimits() bool {
	return t.hasLimits.Load()
}

// LimitedUserCount returns the number of users with active speed limits.
func (t *SpeedTracker) LimitedUserCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.buckets)
}
