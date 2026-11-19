package controlplane

import (
	"context"

	"github.com/cedar2025/xboard-node/internal/model"
)

type EventType string

const (
	EventSyncConfig       EventType = "sync.config"
	EventSyncUsers        EventType = "sync.users"
	EventSyncUserDelta    EventType = "sync.user.delta"
	EventSyncDevices      EventType = "sync.devices"
	EventSyncDevicesDelta EventType = "sync.devices.delta"
)

type Event struct {
	Type        EventType
	Config      *model.NodeSpec
	Users       []model.UserSpec
	DeltaAction string
	DeltaUsers  []model.UserSpec
	DeviceUsers map[int][]string
	// DeviceUsersRemoved lists users whose device entry must be dropped.
	// Only used by EventSyncDevicesDelta; EventSyncDevices still replaces
	// the whole snapshot.
	DeviceUsersRemoved []int
}

type StatusChange struct {
	Connected   bool
	NeedsResync bool
}

type APIMetrics struct {
	Success uint64
	Failure uint64
}

type Bootstrap struct {
	PushInterval int
	PullInterval int
	Push         PushClient
	Config       *model.NodeSpec
	Users        []model.UserSpec
	Mailbox      *NodeMailbox
}

type Snapshot struct {
	Config *model.NodeSpec
	Users  []model.UserSpec
}

type ReportPayload struct {
	Traffic map[int][2]int64
	Alive   map[int][]string
	Online  map[int]int
	CPU     float64
	Mem     [2]uint64
	Swap    [2]uint64
	Disk    [2]uint64
	Metrics map[string]interface{}
}

type PushClient interface {
	Run(ctx context.Context)
	IsConnected() bool
	SendDeviceReport(devices map[int][]string)
}

type Source interface {
	Initial(ctx context.Context, metricsFn func() map[string]interface{}, events chan<- Event, statuses chan<- StatusChange) (Bootstrap, error)
	Poll(ctx context.Context) (Snapshot, error)
	Discover(ctx context.Context, metricsFn func() map[string]interface{}, events chan<- Event, statuses chan<- StatusChange) (PushClient, error)
	Metrics() APIMetrics
	SupportsPolling() bool
	SupportsDiscovery() bool
}

type Sink interface {
	Report(payload ReportPayload) error
	ReportDevices(push PushClient, devices map[int][]string)
	SupportsReporting() bool
	SupportsDeviceReports() bool
}

type ControlPlane interface {
	Source
	Sink
}
