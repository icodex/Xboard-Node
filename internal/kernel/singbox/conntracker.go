package singbox

import (
	"context"
	"io"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	singM "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/time/rate"

	"github.com/cedar2025/xboard-node/internal/nlog"
)

// ─── Per-user statistics ────────────────────────────────────────────────────

// userStats holds per-user traffic counters and alive IP tracking.
// Traffic counters are lock-free atomics (read on every packet).
// IP tracking uses a lightweight mutex (only touched at connect/disconnect).
type userStats struct {
	upload   atomic.Int64
	download atomic.Int64

	mu        sync.RWMutex   // RWMutex for concurrent reads
	ips       map[string]int // sourceIP → refcount (number of active conns from that IP)
	connCount int            // total active connections
}

// maxIPsPerUser bounds the per-user alive-IP set. It only matters for
// unlimited users under address-spoofing load; real device counts are smaller.
const maxIPsPerUser = 4096

// addConn registers a new connection from sourceIP. Connections beyond the IP
// cap still count toward connCount but are not tracked as alive IPs, so one
// user cannot grow this map without bound.
func (u *userStats) addConn(sourceIP string) {
	u.mu.Lock()
	u.connCount++
	if _, tracked := u.ips[sourceIP]; !tracked && len(u.ips) >= maxIPsPerUser {
		u.mu.Unlock()
		return
	}
	u.ips[sourceIP]++
	u.mu.Unlock()
}

// removeConn unregisters a connection from sourceIP.
func (u *userStats) removeConn(sourceIP string) {
	u.mu.Lock()
	u.connCount--
	u.ips[sourceIP]--
	if u.ips[sourceIP] <= 0 {
		delete(u.ips, sourceIP)
	}
	u.mu.Unlock()
}

// aliveIPList returns the set of alive IPs as a boolean map (for reporting).
func (u *userStats) aliveIPList() map[string]bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.ips) == 0 {
		return nil
	}
	result := make(map[string]bool, len(u.ips))
	for ip := range u.ips {
		result[ip] = true
	}
	return result
}

// ─── ConnTracker ────────────────────────────────────────────────────────────

// ConnTracker provides per-user traffic counting, alive IP tracking, device
// limit gate-keeping, and per-user speed limiting for the sing-box kernel.
//
// Architecture: instead of maintaining a per-connection map (O(connections)),
// it maintains per-user atomic counters and IP refcount sets (O(users)).
// This means:
//   - GetUserTraffic is O(users), not O(connections)
//   - No Snapshot/pending buffer needed
//   - No per-connection map lock contention
//   - Bytes are counted directly into per-user atomics via CountFunc callbacks
//
// The per-connection wrapper (trackedConn) is still needed for:
//   - Hooking into sing's ReadCounter/WriteCounter for zero-copy byte counting
//   - Close callback to decrement IP refcounts
//   - Per-connection rate limit token accumulation (amortized WaitN)
type ConnTracker struct {
	usersMu sync.RWMutex
	users   map[int]*userStats // userID → stats
	uuidMap map[string]int     // UUID → userID (for lookup in RoutedConnection)

	// speedLimitFunc resolves a user UUID to a *rate.Limiter.
	speedLimitFunc atomic.Pointer[func(uuid string) *rate.Limiter]

	// deviceLimitFunc resolves a user UUID to their device limit.
	deviceLimitFunc atomic.Pointer[func(uuid string) (int, bool)]

	// Multi-node device state from panel
	globalDevices    map[int]map[string]bool // userID → IP → exists
	globalMu         sync.RWMutex
	globalLastUpdate time.Time
}

// NewConnTracker creates a tracker.
func NewConnTracker(_ int) *ConnTracker {
	return &ConnTracker{
		users:         make(map[int]*userStats),
		uuidMap:       make(map[string]int),
		globalDevices: make(map[int]map[string]bool),
	}
}

// SetSpeedLimitFunc configures the per-user speed limit lookup.
func (t *ConnTracker) SetSpeedLimitFunc(fn func(uuid string) *rate.Limiter) {
	t.speedLimitFunc.Store(&fn)
}

// SetDeviceLimitFunc configures the per-user device limit lookup for gate-keeping.
func (t *ConnTracker) SetDeviceLimitFunc(fn func(uuid string) (int, bool)) {
	t.deviceLimitFunc.Store(&fn)
}

// SetUserMap replaces the UUID→userID mapping and ensures per-user stats
// structs exist for all users. Stats of removed users with no live
// connections are dropped, so the map does not grow unbounded over the
// node's lifetime; removed users still holding connections keep their
// stats until those connections drain.
func (t *ConnTracker) SetUserMap(m map[string]int) {
	t.usersMu.Lock()
	defer t.usersMu.Unlock()
	t.uuidMap = m
	keep := make(map[int]struct{}, len(m))
	for _, uid := range m {
		keep[uid] = struct{}{}
		if _, ok := t.users[uid]; !ok {
			t.users[uid] = &userStats{ips: make(map[string]int)}
		}
	}
	for uid, us := range t.users {
		if _, ok := keep[uid]; ok {
			continue
		}
		us.mu.Lock()
		idle := us.connCount == 0
		us.mu.Unlock()
		if idle {
			delete(t.users, uid)
		}
	}
}

// UpdateGlobalDevices syncs global device state from panel.
func (t *ConnTracker) UpdateGlobalDevices(users map[int][]string) {
	t.globalMu.Lock()
	t.globalDevices = make(map[int]map[string]bool, len(users))
	for uid, ips := range users {
		m := make(map[string]bool, len(ips))
		for _, ip := range ips {
			m[ip] = true
		}
		t.globalDevices[uid] = m
	}
	t.globalLastUpdate = time.Now()
	t.globalMu.Unlock()
	nlog.Core().Debug("global device state updated", "users", len(users))
}

// ClearGlobalDevices resets global device state (on WS disconnect).
func (t *ConnTracker) ClearGlobalDevices() {
	t.globalMu.Lock()
	t.globalDevices = make(map[int]map[string]bool)
	t.globalLastUpdate = time.Time{}
	t.globalMu.Unlock()
	nlog.Core().Debug("global device state cleared")
}

// ─── adapter.ConnectionTracker ──────────────────────────────────────────────

// RoutedConnection wraps a TCP conn to count bytes per-user, track IPs,
// and optionally rate-limit. Gate-keeps device limits at connection time.
func (t *ConnTracker) RoutedConnection(
	ctx context.Context, conn net.Conn,
	metadata adapter.InboundContext,
	_ adapter.Rule, _ adapter.Outbound,
) net.Conn {
	uuid := metadata.User
	sourceIP := metadata.Source.Addr.String()

	t.usersMu.RLock()
	uid := t.uuidMap[uuid]
	us := t.users[uid]
	t.usersMu.RUnlock()

	// Device limit gate-keeping registers the connection under the same lock,
	// so concurrent admissions cannot both pass the count check.
	if !t.admitConnectionFor(us, uid, uuid, sourceIP) {
		// Per-connection: Debug keeps a user who loops on reconnect from
		// writing a log line per attempt.
		nlog.Core().Debug("singbox: device limit gate-keep, rejecting connection",
			"user", uuid, "ip", sourceIP)
		conn.Close()
		return conn
	}

	var lim *rate.Limiter
	if slf := t.speedLimitFunc.Load(); slf != nil {
		lim = (*slf)(uuid)
	}

	return &trackedConn{
		Conn:     conn,
		tracker:  t,
		us:       us,
		userID:   uid,
		sourceIP: sourceIP,
		limiter:  lim,
		ctx:      ctx,
	}
}

// RoutedPacketConnection wraps UDP with per-user counting.
func (t *ConnTracker) RoutedPacketConnection(
	ctx context.Context, conn N.PacketConn,
	metadata adapter.InboundContext,
	_ adapter.Rule, _ adapter.Outbound,
) N.PacketConn {
	uuid := metadata.User
	sourceIP := metadata.Source.Addr.String()

	t.usersMu.RLock()
	uid := t.uuidMap[uuid]
	us := t.users[uid]
	t.usersMu.RUnlock()

	// Device limit gate-keeping registers the connection under the same lock,
	// so concurrent admissions cannot both pass the count check.
	if !t.admitConnectionFor(us, uid, uuid, sourceIP) {
		nlog.Core().Debug("singbox: device limit gate-keep, rejecting UDP connection",
			"user", uuid, "ip", sourceIP)
		conn.Close()
		return conn
	}

	var lim *rate.Limiter
	if slf := t.speedLimitFunc.Load(); slf != nil {
		lim = (*slf)(uuid)
	}

	return &trackedPacketConn{
		PacketConn: conn,
		tracker:    t,
		us:         us,
		userID:     uid,
		sourceIP:   sourceIP,
		limiter:    lim,
		ctx:        ctx,
	}
}

// RoutedFlow implements the adapter.ConnectionTracker hook for L3 flows
// (added in sing-box 1.14.0). Per-user accounting happens at L4 in
// RoutedConnection/RoutedPacketConnection, so flows are not tracked here.
func (t *ConnTracker) RoutedFlow(
	ctx context.Context,
	metadata adapter.InboundContext,
	_ adapter.Rule, _ adapter.Outbound,
) tun.FlowTracker {
	return nil
}

// admitConnectionFor looks up the device limit for uuid and admits the
// connection, registering its source IP in the same critical section.
func (t *ConnTracker) admitConnectionFor(us *userStats, userID int, uuid, sourceIP string) bool {
	if dlf := t.deviceLimitFunc.Load(); dlf != nil {
		if limit, hasLimit := (*dlf)(uuid); hasLimit {
			return t.admitConnection(us, userID, sourceIP, limit)
		}
	}
	if us != nil {
		us.addConn(sourceIP)
	}
	return true
}

// admitConnection reports whether a new connection from sourceIP is allowed
// under the device limit, and registers it when allowed. The check and the
// registration happen under one us.mu write lock: the previous split version
// let two concurrent connections from new IPs both observe localCount < limit
// and pass, exceeding the limit.
//
// Strategy: merge local + global state when fresh; local-only when stale.
// Global state is snapshotted first (globalMu is never taken while holding
// us.mu anywhere, so this order cannot deadlock).
func (t *ConnTracker) admitConnection(us *userStats, userID int, sourceIP string, limit int) bool {
	if us == nil {
		return true
	}
	if limit <= 0 {
		us.addConn(sourceIP)
		return true
	}

	t.globalMu.RLock()
	globalStale := time.Since(t.globalLastUpdate) > 60*time.Second
	globalIPs := t.globalDevices[userID]
	t.globalMu.RUnlock()
	if globalStale {
		globalIPs = nil
	}

	us.mu.Lock()
	defer us.mu.Unlock()

	if us.ips[sourceIP] > 0 {
		us.ips[sourceIP]++
		us.connCount++
		return true
	}

	// Known globally: this or another node already serves the IP.
	if globalIPs[sourceIP] {
		us.ips[sourceIP] = 1
		us.connCount++
		return true
	}

	// This node already carries the user's full allowance. The lexicographic
	// rule below only picks among candidates when a local slot is free;
	// without this check a brand-new lower-sorting IP was admitted on top of
	// the existing ones (limit 2, 9.9.9.9 + 8.8.8.8 connected, 1.1.1.1
	// admitted → 3 devices).
	if len(us.ips) >= limit {
		nlog.Core().Debug("device limit: local capacity reached, rejecting",
			"userID", userID, "ip", sourceIP, "localIPs", len(us.ips), "limit", limit)
		return false
	}

	// Merge local + global; the node's own report echoes back, so overlaps
	// deduplicate naturally. Global IPs never enter the refcounts.
	allIPs := make(map[string]struct{}, len(us.ips)+len(globalIPs)+1)
	for ip := range us.ips {
		allIPs[ip] = struct{}{}
	}
	for ip := range globalIPs {
		allIPs[ip] = struct{}{}
	}

	if len(allIPs) < limit {
		us.ips[sourceIP] = 1
		us.connCount++
		return true
	}

	// Over limit — deterministic: allow the lowest IPs lexicographically.
	ipList := make([]string, 0, len(allIPs)+1)
	for ip := range allIPs {
		ipList = append(ipList, ip)
	}
	ipList = append(ipList, sourceIP)
	sort.Strings(ipList)

	for i := 0; i < limit && i < len(ipList); i++ {
		if ipList[i] == sourceIP {
			us.ips[sourceIP] = 1
			us.connCount++
			return true
		}
	}
	nlog.Core().Debug("device limit: rejecting",
		"userID", userID, "ip", sourceIP, "totalIPs", len(allIPs), "limit", limit)
	return false
}

// ─── Public API ─────────────────────────────────────────────────────────────

// GetUserTraffic returns per-user cumulative traffic and alive IPs.
// This is O(users), not O(connections).
func (t *ConnTracker) GetUserTraffic() (traffic map[int][2]int64, aliveIPs map[int]map[string]bool, connCount int) {
	t.usersMu.RLock()
	traffic = make(map[int][2]int64, len(t.users))
	aliveIPs = make(map[int]map[string]bool, len(t.users))
	for uid, us := range t.users {
		up := us.upload.Load()
		down := us.download.Load()
		if up > 0 || down > 0 {
			traffic[uid] = [2]int64{up, down}
		}

		ips := us.aliveIPList()
		if ips != nil {
			aliveIPs[uid] = ips
		}

		us.mu.Lock()
		connCount += us.connCount
		us.mu.Unlock()
	}
	t.usersMu.RUnlock()
	return
}

// ActiveCount returns the total number of active connections.
func (t *ConnTracker) ActiveCount() int {
	t.usersMu.RLock()
	total := 0
	for _, us := range t.users {
		us.mu.Lock()
		total += us.connCount
		us.mu.Unlock()
	}
	t.usersMu.RUnlock()
	return total
}

// ─── trackedConn (TCP) ──────────────────────────────────────────────────────

type trackedConn struct {
	net.Conn
	tracker  *ConnTracker
	us       *userStats // per-user stats (upload/download atomics + IP tracking)
	userID   int        // user ID for device tracking
	sourceIP string
	limiter  *rate.Limiter
	ctx      context.Context
	timer    *time.Timer
	closed   atomic.Bool
}

// waitLimit blocks until n tokens are available or ctx is done. Requests
// larger than the burst are split into burst-sized chunks: one ReserveN(n)
// with n > burst yields an infinite delay and would stall the connection
// until it is cancelled.
func waitLimit(ctx context.Context, lim *rate.Limiter, n int, timer **time.Timer) error {
	if lim == nil || n <= 0 {
		return nil
	}
	burst := lim.Burst()
	if burst <= 0 {
		return nil
	}
	for n > 0 {
		chunk := n
		if chunk > burst {
			chunk = burst
		}
		if !lim.AllowN(time.Now(), chunk) {
			resv := lim.ReserveN(time.Now(), chunk)
			if delay := resv.Delay(); delay > 0 {
				// Reuse one timer per connection: steady-state rate limiting
				// allocates a timer per packet otherwise.
				if *timer == nil {
					*timer = time.NewTimer(delay)
				} else {
					if !(*timer).Stop() {
						select {
						case <-(*timer).C:
						default:
						}
					}
					(*timer).Reset(delay)
				}
				select {
				case <-(*timer).C:
				case <-ctx.Done():
					(*timer).Stop()
					resv.Cancel()
					return ctx.Err()
				}
			}
		}
		n -= chunk
	}
	return nil
}

func (c *trackedConn) Read(b []byte) (int, error) {
	if c.limiter != nil {
		if burst := c.limiter.Burst(); len(b) > burst {
			b = b[:burst]
		}
	}
	n, err := c.Conn.Read(b)
	if n > 0 {
		if c.us != nil {
			c.us.upload.Add(int64(n)) // 从入站读取 = 用户上传
		}
		if c.limiter != nil {
			if werr := waitLimit(c.ctx, c.limiter, n, &c.timer); werr != nil {
				return n, werr
			}
		}
	}
	return n, err
}

// Write rate-limits and writes the whole buffer. The previous version cut b
// to the bucket burst and returned a short count with a nil error, which
// io.Writer callers treat as a complete write — the tail was silently lost.
func (c *trackedConn) Write(b []byte) (int, error) {
	if c.limiter == nil {
		n, err := c.Conn.Write(b)
		if n > 0 && c.us != nil {
			c.us.download.Add(int64(n)) // 向入站写入 = 用户下载
		}
		return n, err
	}

	written := 0
	for len(b) > 0 {
		chunk := len(b)
		if burst := c.limiter.Burst(); burst > 0 && chunk > burst {
			chunk = burst
		}
		if err := waitLimit(c.ctx, c.limiter, chunk, &c.timer); err != nil {
			return written, err
		}
		n, err := c.Conn.Write(b[:chunk])
		if n > 0 {
			written += n
			b = b[n:]
			if c.us != nil {
				c.us.download.Add(int64(n)) // 向入站写入 = 用户下载
			}
		}
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

func (c *trackedConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		if c.us != nil {
			c.us.removeConn(c.sourceIP)
		}
	}
	return c.Conn.Close()
}

// makeCountFunc builds a CountFunc for zero-copy byte counting via sing's
// ReadCounter/WriteCounter unwrap interfaces.
func (c *trackedConn) makeCountFunc(counter *atomic.Int64) N.CountFunc {
	if c.limiter == nil || c.ctx == nil {
		return func(n int64) { counter.Add(n) }
	}
	return func(n int64) {
		counter.Add(n)
		_ = waitLimit(c.ctx, c.limiter, int(n), &c.timer)
	}
}

func (c *trackedConn) UnwrapReader() (io.Reader, []N.CountFunc) {
	if c.us == nil {
		return c.Conn, nil
	}
	return c.Conn, []N.CountFunc{c.makeCountFunc(&c.us.upload)} // 从入站读取 = 用户上传
}

func (c *trackedConn) UnwrapWriter() (io.Writer, []N.CountFunc) {
	if c.us == nil {
		return c.Conn, nil
	}
	return c.Conn, []N.CountFunc{c.makeCountFunc(&c.us.download)} // 向入站写入 = 用户下载
}

func (c *trackedConn) Upstream() any           { return c.Conn }
func (c *trackedConn) ReaderReplaceable() bool { return true }
func (c *trackedConn) WriterReplaceable() bool { return true }

// ─── trackedPacketConn (UDP / QUIC) ─────────────────────────────────────────

type trackedPacketConn struct {
	N.PacketConn
	tracker  *ConnTracker
	us       *userStats
	userID   int
	sourceIP string
	limiter  *rate.Limiter
	ctx      context.Context
	timer    *time.Timer
	closed   atomic.Bool
}

func (c *trackedPacketConn) ReadPacket(buffer *buf.Buffer) (singM.Socksaddr, error) {
	dest, err := c.PacketConn.ReadPacket(buffer)
	if err == nil {
		n := int64(buffer.Len())
		if c.us != nil {
			c.us.upload.Add(n) // 从入站读取 = 用户上传
		}
		if c.limiter != nil {
			if werr := waitLimit(c.ctx, c.limiter, int(n), &c.timer); werr != nil {
				return dest, werr
			}
		}
	}
	return dest, err
}

func (c *trackedPacketConn) WritePacket(buffer *buf.Buffer, dest singM.Socksaddr) error {
	n := int64(buffer.Len())

	// Apply rate limiting before write
	if c.limiter != nil {
		if err := waitLimit(c.ctx, c.limiter, int(n), &c.timer); err != nil {
			return err
		}
	}

	err := c.PacketConn.WritePacket(buffer, dest)
	if err == nil && c.us != nil {
		c.us.download.Add(n) // 向入站写入 = 用户下载
	}
	return err
}

func (c *trackedPacketConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		if c.us != nil {
			c.us.removeConn(c.sourceIP)
		}
	}
	return c.PacketConn.Close()
}

func (c *trackedPacketConn) makeCountFunc(counter *atomic.Int64) N.CountFunc {
	if c.limiter == nil || c.ctx == nil {
		return func(n int64) { counter.Add(n) }
	}
	return func(n int64) {
		counter.Add(n)
		_ = waitLimit(c.ctx, c.limiter, int(n), &c.timer)
	}
}

func (c *trackedPacketConn) UnwrapPacketReader() (N.PacketReader, []N.CountFunc) {
	if c.us == nil {
		return c.PacketConn, nil
	}
	// Read from the inbound = user upload, matching ReadPacket and the TCP
	// wrapper (UnwrapReader).
	return c.PacketConn, []N.CountFunc{c.makeCountFunc(&c.us.upload)}
}

func (c *trackedPacketConn) UnwrapPacketWriter() (N.PacketWriter, []N.CountFunc) {
	if c.us == nil {
		return c.PacketConn, nil
	}
	// Write to the inbound = user download, matching WritePacket and the TCP
	// wrapper (UnwrapWriter).
	return c.PacketConn, []N.CountFunc{c.makeCountFunc(&c.us.download)}
}

func (c *trackedPacketConn) Upstream() any           { return c.PacketConn }
func (c *trackedPacketConn) ReaderReplaceable() bool { return true }
func (c *trackedPacketConn) WriterReplaceable() bool { return true }
