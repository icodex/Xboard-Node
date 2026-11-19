package xray

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"time"
	_ "unsafe"

	xrayDispatcher "github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"

	"github.com/cedar2025/xboard-node/internal/nlog"
)

// globalDeviceWindow is how long the panel-pushed global device state stays
// trusted. Past it, admission falls back to local-only, mirroring sing-box's
// ConnTracker.checkDeviceGate.
const globalDeviceWindow = 60 * time.Second

// Access xray's internal config creator registry so we can replace the
// default dispatcher factory with ours. This runs AFTER xray's init()
// functions because our package imports xray (dependency order guarantee).
//
//go:linkname typeCreatorRegistry github.com/xtls/xray-core/common.typeCreatorRegistry
var typeCreatorRegistry map[reflect.Type]common.ConfigCreator

var origDispatcherFactory common.ConfigCreator

// globalLimitDispatcher is set when the factory creates a LimitDispatcher.
// The Xray kernel reads it to configure limits and get connections.
var globalLimitDispatcher atomic.Pointer[LimitDispatcher]

func init() {
	configType := reflect.TypeOf((*xrayDispatcher.Config)(nil))
	origDispatcherFactory = typeCreatorRegistry[configType]
	typeCreatorRegistry[configType] = limitDispatcherFactory
}

func limitDispatcherFactory(ctx context.Context, config interface{}) (interface{}, error) {
	orig, err := origDispatcherFactory(ctx, config)
	if err != nil {
		return nil, err
	}
	inner, ok := orig.(routing.Dispatcher)
	if !ok {
		return orig, nil
	}
	ld := &LimitDispatcher{
		inner:         orig,
		innerDisp:     inner,
		limitedIPs:    make(map[string]map[string]int),
		globalDevices: make(map[string]map[string]bool),
	}
	globalLimitDispatcher.Store(ld)
	nlog.Core().Debug("xray: limit dispatcher installed")
	return ld, nil
}

// LimitDispatcher wraps xray's DefaultDispatcher to enforce per-user
// admission checks before a request is dispatched into xray-core.
//
// It intentionally does NOT mutate transport.Link.Reader/Writer. Xray's
// mux/XUDP close path requires the original concrete *pipe.Reader to remain
// intact, so the dispatcher is limited to gate-keeping and safe connection
// lifecycle bookkeeping.
type LimitDispatcher struct {
	inner     interface{}        // original DefaultDispatcher (Feature + Dispatcher)
	innerDisp routing.Dispatcher // same object, typed as Dispatcher

	// limitedUsers: users with device limit > 0, protected by mu.
	// Needs deterministic IP ordering for kick decisions.
	mu           sync.RWMutex
	limitedIPs   map[string]map[string]int // email → sourceIP → refcount
	deviceLimits map[string]int            // email → max devices
	emailToUID   map[string]int            // email → panel user ID

	// unlimitedIPs: users without device limit — sync.Map for lock-free access.
	// Each entry is *ipCounter{ips sync.Map}.
	unlimitedIPs sync.Map // email → *ipCounter

	// Global device state pushed by the panel (sync.devices), keyed by email.
	// Never written by connection bookkeeping — admission merges it with local
	// state; alive-IP reports stay local-only (the panel aggregates globally).
	globalMu        sync.RWMutex
	globalDevices   map[string]map[string]bool
	globalUpdatedAt time.Time

	connCount atomic.Int64 // total active connections tracked by dispatcher
}

// ipCounter tracks IPs for unlimited users without any lock.
const maxUnlimitedIPsPerUser = 4096

type ipCounter struct {
	ips sync.Map // sourceIP → *atomic.Int64 (refcount)
	// ipCount mirrors len(ips) without a Range; caps spoofed-address growth.
	ipCount atomic.Int64
	// live counts connections currently holding this counter. The entry is
	// removed when it drops to zero; without it the map grew with every user
	// that ever connected and GetConnectionState scanned them all each tick.
	live atomic.Int64
}

// aliveIPs returns a snapshot of distinct IPs.
func (ic *ipCounter) aliveIPs() map[string]bool {
	result := make(map[string]bool)
	ic.ips.Range(func(key, _ interface{}) bool {
		if rv, ok := ic.ips.Load(key); ok && rv.(*atomic.Int64).Load() > 0 {
			result[key.(string)] = true
		}
		return true
	})
	return result
}

// ─── routing.Dispatcher ──────────────────────────────────────────────────────

func (d *LimitDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	email, sourceIP, err := d.identifyAndCheck(ctx, dest)
	if err != nil {
		return nil, err
	}

	link, err := d.innerDisp.Dispatch(ctx, dest)
	if err != nil {
		if email != "" {
			d.delConn(email, sourceIP)
		}
		return nil, err
	}

	if email != "" {
		d.trackLink(link, email, sourceIP)
	}
	return link, nil
}

func (d *LimitDispatcher) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	email, sourceIP, err := d.identifyAndCheck(ctx, dest)
	if err != nil {
		return err
	}

	if err := d.innerDisp.DispatchLink(ctx, dest, link); err != nil {
		// Mirror Dispatch: an admission that never got a link must not keep
		// its device slot or connection count (permanently occupied IP).
		if email != "" {
			d.delConn(email, sourceIP)
		}
		return err
	}
	// Register only after a successful dispatch, matching Dispatch. Wrapping
	// before the call would make the close callback release the slot a second
	// time when the failed link is later closed.
	if email != "" {
		d.trackLink(link, email, sourceIP)
	}
	return nil
}

// identifyAndCheck extracts user identity from the session context and enforces
// device limits. Returns a non-nil error only when the connection should be
// rejected.
func (d *LimitDispatcher) identifyAndCheck(ctx context.Context, dest net.Destination) (email, sourceIP string, err error) {
	si := session.InboundFromContext(ctx)
	if si == nil || si.User == nil || len(si.User.Email) == 0 {
		return "", "", nil
	}
	email = si.User.Email
	sourceIP = si.Source.Address.IP().String()

	if d.checkDeviceLimit(email, sourceIP) {
		nlog.Core().Debug("xray: device limit exceeded", "email", email, "ip", sourceIP)
		return "", "", errors.New("device limit exceeded for " + email)
	}
	return email, sourceIP, nil
}

// trackLink records connection lifecycle without mutating xray-core owned
// transport primitives. This keeps mux/XUDP compatible while still allowing
// the dispatcher to release device-limit state when the link closes.
// UDP (XUDP) sessions release their slot the same way: xray closes the link
// writer when the session ends.
func (d *LimitDispatcher) trackLink(link *transport.Link, email, sourceIP string) {
	d.connCount.Add(1)

	onClose := func() {
		d.delConn(email, sourceIP)
		d.connCount.Add(-1)
	}

	link.Writer = &closeTrackingWriter{
		Writer:  link.Writer,
		onClose: onClose,
	}
}

// ─── features.Feature (delegated) ───────────────────────────────────────────

func (d *LimitDispatcher) Type() interface{} { return routing.DispatcherType() }

func (d *LimitDispatcher) Start() error {
	if s, ok := d.inner.(interface{ Start() error }); ok {
		return s.Start()
	}
	return nil
}

func (d *LimitDispatcher) Close() error {
	if c, ok := d.inner.(interface{ Close() error }); ok {
		return c.Close()
	}
	return nil
}

// ─── Limit management (called by Xray kernel) ──────────────────────────────

func (d *LimitDispatcher) UpdateLimits(emailToUID map[string]int, deviceLimits map[string]int) {
	d.mu.Lock()
	d.emailToUID = emailToUID
	d.deviceLimits = deviceLimits
	d.mu.Unlock()

	// Counters normally disappear on their last release; sweep ones whose
	// last connection raced with that delete so a long-lived node cannot
	// accumulate one entry per user that ever connected.
	d.unlimitedIPs.Range(func(key, value interface{}) bool {
		if ic, ok := value.(*ipCounter); ok && ic.live.Load() == 0 {
			d.unlimitedIPs.CompareAndDelete(key, value)
		}
		return true
	})
}

func (d *LimitDispatcher) ResetConns() {
	d.mu.Lock()
	d.limitedIPs = make(map[string]map[string]int)
	d.mu.Unlock()

	// Clear unlimited IPs
	d.unlimitedIPs.Range(func(key, _ interface{}) bool {
		d.unlimitedIPs.Delete(key)
		return true
	})

	d.connCount.Store(0)
}

// GetConnectionState returns dispatcher-tracked alive IPs and connection count.
// Traffic bytes are intentionally left to xray's built-in stats pipeline.
func (d *LimitDispatcher) GetConnectionState() (aliveIPs map[int]map[string]bool, connCount int) {
	// Copy the limited-IP nested maps while still holding RLock: delConn
	// mutates those entries under the write lock, and iterating them after
	// releasing RLock is a fatal concurrent map iteration and map write.
	d.mu.RLock()
	emailToUID := d.emailToUID
	aliveIPs = make(map[int]map[string]bool, len(d.limitedIPs))

	for email, ipsMap := range d.limitedIPs {
		uid := emailToUID[email]
		if uid == 0 {
			continue
		}
		ipSet := make(map[string]bool, len(ipsMap))
		for ip := range ipsMap {
			ipSet[ip] = true
		}
		if len(ipSet) > 0 {
			aliveIPs[uid] = ipSet
		}
	}
	d.mu.RUnlock()

	// Collect IPs from unlimited users (lock-free).
	d.unlimitedIPs.Range(func(key, value interface{}) bool {
		email := key.(string)
		uid := emailToUID[email]
		if uid == 0 {
			return true
		}
		ic := value.(*ipCounter)
		if ips := ic.aliveIPs(); len(ips) > 0 {
			// Merge with limited IPs if any
			if existing, ok := aliveIPs[uid]; ok {
				for ip := range ips {
					existing[ip] = true
				}
			} else {
				aliveIPs[uid] = ips
			}
		}
		return true
	})

	connCount = int(d.connCount.Load())
	return
}

// ─── Internal helpers ───────────────────────────────────────────────────────

// checkDeviceLimit enforces per-user device limits.
// Fast path: unlimited users use lock-free sync.Map.
// Slow path: limited users use RWMutex with deterministic IP ordering.
// Counts every network type: gating on TCP let UDP-only traffic bypass the
// limit and stay invisible in alive-IP reports.
func (d *LimitDispatcher) checkDeviceLimit(email, sourceIP string) bool {
	d.mu.RLock()
	limit, hasLimit := d.deviceLimits[email]
	d.mu.RUnlock()

	// Fast path: no device limit — use lock-free sync.Map.
	if !hasLimit || limit <= 0 {
		for {
			v, _ := d.unlimitedIPs.LoadOrStore(email, &ipCounter{})
			ic := v.(*ipCounter)
			ic.live.Add(1)
			// A concurrent release may have removed the entry between
			// LoadOrStore and the increment; only count against the counter
			// the map still owns, otherwise retry with a fresh one.
			if cur, ok := d.unlimitedIPs.Load(email); !ok || cur != v {
				ic.live.Add(-1)
				continue
			}

			// Increment IP refcount atomically. Beyond the cap the connection
			// is admitted but not tracked, so the map stays bounded.
			rv, loaded := ic.ips.LoadOrStore(sourceIP, &atomic.Int64{})
			if !loaded {
				if ic.ipCount.Add(1) > maxUnlimitedIPsPerUser {
					ic.ipCount.Add(-1)
					ic.ips.Delete(sourceIP)
					return false
				}
			}
			rv.(*atomic.Int64).Add(1)
			return false
		}
	}

	// Snapshot the global device state BEFORE taking d.mu (lock order:
	// globalMu first, never nested the other way). Stale or empty state
	// mirrors sing-box's checkDeviceGate and degrades to local-only.
	d.globalMu.RLock()
	globalFresh := !d.globalUpdatedAt.IsZero() && time.Since(d.globalUpdatedAt) <= globalDeviceWindow
	var globalIPs map[string]bool
	if globalFresh {
		globalIPs = d.globalDevices[email]
	}
	d.globalMu.RUnlock()

	// Slow path: user has device limit. All bookkeeping happens under the
	// write lock with a re-check, so concurrent admissions can never push the
	// count past the limit (an RLock fast path would let two goroutines pass
	// the len<limit check before either acquires the write lock).
	d.mu.Lock()
	defer d.mu.Unlock()

	ips := d.limitedIPs[email]
	if ips == nil {
		ips = make(map[string]int)
		d.limitedIPs[email] = ips
	}

	if ips[sourceIP] > 0 {
		ips[sourceIP]++
		return false
	}
	if len(ips) >= maxUnlimitedIPsPerUser {
		// A huge panel device limit must still not let this map grow without
		// bound under spoofed source addresses.
		return true
	}

	// Known globally (this or another node already serves this IP): allow and
	// start local bookkeeping so alive-IP reports include the connection.
	if globalIPs[sourceIP] {
		ips[sourceIP]++
		return false
	}

	// Local allowance is full: a brand-new IP must be rejected. Without this,
	// the lexicographic rule admitted a lower-sorting newcomer on top of the
	// existing IPs (limit 2 with 9.9.9.9 + 8.8.8.8 connected accepted 1.1.1.1
	// as a third device).
	if len(ips) >= limit {
		return true
	}

	// Merge local and global IP sets; the node's own report echoes back, so
	// overlaps deduplicate naturally. Global IPs never enter the refcounts.
	allIPs := make(map[string]struct{}, len(ips)+len(globalIPs)+1)
	for ip := range ips {
		allIPs[ip] = struct{}{}
	}
	for ip := range globalIPs {
		allIPs[ip] = struct{}{}
	}

	if len(allIPs) < limit {
		ips[sourceIP]++
		return false
	}

	// Over limit — deterministic: allow lowest IPs lexicographically.
	ipList := make([]string, 0, len(allIPs)+1)
	for ip := range allIPs {
		ipList = append(ipList, ip)
	}
	ipList = append(ipList, sourceIP)
	sort.Strings(ipList)

	for i := 0; i < limit && i < len(ipList); i++ {
		if ipList[i] == sourceIP {
			ips[sourceIP]++
			return false
		}
	}
	return true
}

// SetGlobalDevicesByUID stores the panel-pushed global device snapshot
// (sync.devices, keyed by panel user ID) translated to the dispatcher's
// email keys. Connection bookkeeping never touches this store.
func (d *LimitDispatcher) SetGlobalDevicesByUID(users map[int][]string) {
	if users == nil {
		users = map[int][]string{}
	}

	// Translate under d.mu.RLock (read-only), then publish under globalMu —
	// never nested the other way around.
	d.mu.RLock()
	byEmail := make(map[string]map[string]bool, len(users))
	for email, uid := range d.emailToUID {
		ips, ok := users[uid]
		if !ok {
			continue
		}
		set := make(map[string]bool, len(ips))
		for _, ip := range ips {
			set[ip] = true
		}
		byEmail[email] = set
	}
	d.mu.RUnlock()

	d.globalMu.Lock()
	d.globalDevices = byEmail
	d.globalUpdatedAt = time.Now()
	d.globalMu.Unlock()
}

// ClearGlobalDevices drops the panel-pushed global device snapshot.
func (d *LimitDispatcher) ClearGlobalDevices() {
	d.globalMu.Lock()
	d.globalDevices = make(map[string]map[string]bool)
	d.globalUpdatedAt = time.Time{}
	d.globalMu.Unlock()
}

// delConn decrements the IP refcount when a connection closes.
//
// The refcount lives in the store the user's state pointed at when the
// connection was ADMITTED, but the user's device limit can change at runtime
// (sync.user.delta). Route by current state first, then fall back to the
// other store: decrementing only the current-state store leaks the other one
// and permanently occupies a device slot with a ghost IP.
func (d *LimitDispatcher) delConn(email, sourceIP string) {
	d.mu.RLock()
	_, limited := d.deviceLimits[email]
	d.mu.RUnlock()

	if !limited {
		if d.decUnlimited(email, sourceIP) {
			return
		}
		// Fall through: the connection may predate the limit grant.
		d.decLimited(email, sourceIP)
		return
	}
	if !d.decLimited(email, sourceIP) {
		// Fall through: the connection may predate the limit release.
		d.decUnlimited(email, sourceIP)
	}
}

// decLimited decrements the limited-user refcount, reporting whether the
// entry existed.
func (d *LimitDispatcher) decLimited(email, sourceIP string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	ips, ok := d.limitedIPs[email]
	if !ok || ips[sourceIP] <= 0 {
		return false
	}
	ips[sourceIP]--
	if ips[sourceIP] <= 0 {
		delete(ips, sourceIP)
	}
	if len(ips) == 0 {
		delete(d.limitedIPs, email)
	}
	return true
}

// decUnlimited decrements the unlimited-user refcount, reporting whether the
// entry existed. The email entry is dropped once its last connection closes.
// When a user's device limit changed while connections were open, the caller
// may route a connection here that was admitted through the limited store; the
// IP lookup then misses and the caller falls back to decLimited.
func (d *LimitDispatcher) decUnlimited(email, sourceIP string) bool {
	v, ok := d.unlimitedIPs.Load(email)
	if !ok {
		return false
	}
	ic := v.(*ipCounter)
	rv, ok := ic.ips.Load(sourceIP)
	if !ok {
		return false
	}
	counter := rv.(*atomic.Int64)
	if counter.Add(-1) <= 0 {
		ic.ips.Delete(sourceIP)
		ic.ipCount.Add(-1)
	}
	if ic.live.Add(-1) <= 0 {
		d.unlimitedIPs.CompareAndDelete(email, ic)
	}
	return true
}

type closeTrackingWriter struct {
	buf.Writer
	onClose func()
	closed  atomic.Bool
}

func (w *closeTrackingWriter) Close() error {
	if w.closed.CompareAndSwap(false, true) {
		w.onClose()
	}
	return common.Close(w.Writer)
}

func (w *closeTrackingWriter) Interrupt() {
	if w.closed.CompareAndSwap(false, true) {
		w.onClose()
	}
	common.Interrupt(w.Writer)
}
