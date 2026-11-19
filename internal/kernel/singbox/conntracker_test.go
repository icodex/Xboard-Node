package singbox

import (
	"fmt"
	"testing"
)

// sing uses the UnwrapPacket* fast path (ReaderReplaceable() is true), so
// these CountFuncs are the live accounting path for UDP traffic. Reads must
// count as upload and writes as download, matching ReadPacket/WritePacket
// and the TCP wrapper.
func TestConnTracker_PacketUnwrapCountsDirection(t *testing.T) {
	ct := NewConnTracker(0)
	ct.SetUserMap(map[string]int{"uuid-1": 1})

	ct.usersMu.RLock()
	us := ct.users[1]
	ct.usersMu.RUnlock()
	if us == nil {
		t.Fatal("SetUserMap did not create per-user stats")
	}

	pc := &trackedPacketConn{us: us}

	_, readCounts := pc.UnwrapPacketReader()
	_, writeCounts := pc.UnwrapPacketWriter()
	if len(readCounts) != 1 || len(writeCounts) != 1 {
		t.Fatalf("expected one CountFunc per direction, got %d/%d", len(readCounts), len(writeCounts))
	}

	readCounts[0](100) // bytes read from the inbound = upload
	writeCounts[0](50) // bytes written to the inbound = download

	if got := us.upload.Load(); got != 100 {
		t.Errorf("upload = %d, want 100", got)
	}
	if got := us.download.Load(); got != 50 {
		t.Errorf("download = %d, want 50", got)
	}
}

func TestUserStatsIPCapped(t *testing.T) {
	us := &userStats{ips: make(map[string]int)}
	for i := 0; i <= maxIPsPerUser; i++ {
		us.addConn(fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256))
	}

	if got := len(us.ips); got != maxIPsPerUser {
		t.Fatalf("tracked IPs = %d, want cap %d", got, maxIPsPerUser)
	}
	if us.connCount != maxIPsPerUser+1 {
		t.Fatalf("connCount = %d, want %d", us.connCount, maxIPsPerUser+1)
	}
	// A connection beyond the cap still closes cleanly.
	us.removeConn("11.11.11.11")
}
