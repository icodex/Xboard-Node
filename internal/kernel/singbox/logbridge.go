package singbox

import (
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/cedar2025/xboard-node/internal/nlog"
	singLog "github.com/sagernet/sing-box/log"
)

// nlogBridge routes sing-box internal logs into nlog so kernel logs follow
// the unified config.yml log settings (log.level / log.output).
//
// The generated config pins the sing-box log factory at level "panic", which
// keeps the factory's own stderr path inert. The factory still forwards every
// entry to its PlatformWriter — this bridge — so level filtering, downgrade
// and output all happen here.
type nlogBridge struct {
	min atomic.Uint32
}

var _ singLog.PlatformWriter = (*nlogBridge)(nil)

// newNlogBridge builds a bridge whose minimum level comes from the effective
// kernel log level (canonical: trace/debug/info/warn/error/fatal). Unknown
// values fall back to warn.
func newNlogBridge(kernelLevel string) *nlogBridge {
	b := &nlogBridge{}
	b.SetLevel(kernelLevel)
	return b
}

// SetLevel hot-updates the minimum level (panel kernel_log_level changes are
// applied by Reload without rebuilding the box).
func (b *nlogBridge) SetLevel(kernelLevel string) {
	min, err := singLog.ParseLevel(kernelLevel)
	if err != nil {
		min = singLog.LevelWarn
	}
	b.min.Store(uint32(min))
}

func (b *nlogBridge) level() singLog.Level {
	return singLog.Level(b.min.Load())
}

// inboundTagPrefix marks sing-box inbound subsystem logs. ERROR entries from
// an inbound are per-connection failures (scanner probes, wrong credentials,
// aborted clients) — routine noise, not node faults.
const inboundTagPrefix = "inbound/"

// noiseRe matches per-connection error texts regardless of tag.
var noiseRe = regexp.MustCompile(`process connection|connection reset|handshake failure|authentication failed|invalid request`)

// ansiRe strips ANSI colors: the platform formatter embeds them even when
// colors are otherwise disabled.
var ansiRe = regexp.MustCompile("\x1b\\[[0-9;]*m")

// levelPrefixRe strips the leading level marker the platform formatter
// prepends: "ERROR[  12] " (relative time) or "ERROR " (no timestamp).
// Only level words match, so plain messages starting with an uppercase
// word (e.g. "DNS ...") are left intact.
var levelPrefixRe = regexp.MustCompile(`^(?:TRACE|DEBUG|INFO|WARN|ERROR|FATAL|PANIC)(?:\[[^\]]*\])?\s+`)

// WriteMessage implements singLog.PlatformWriter.
func (b *nlogBridge) WriteMessage(level singLog.Level, message string) {
	if level > b.level() {
		return
	}
	msg := normalizeBridgeMessage(message)
	if msg == "" {
		return
	}

	core := nlog.Core()
	switch {
	case level <= singLog.LevelFatal:
		// nlog has no slot above ERROR; keep the text visible.
		core.Error(msg)
	case level == singLog.LevelError:
		if downgradeInboundError(msg) {
			core.Warn(msg)
		} else {
			core.Error(msg)
		}
	case level == singLog.LevelWarn:
		core.Warn(msg)
	case level == singLog.LevelInfo:
		core.Info(msg)
	default:
		core.Debug(msg)
	}
}

// normalizeBridgeMessage strips ANSI colors and the sing-box level/time
// prefix, leaving "tag: message" text for nlog.
func normalizeBridgeMessage(message string) string {
	clean := strings.TrimSpace(ansiRe.ReplaceAllString(message, ""))
	return levelPrefixRe.ReplaceAllString(clean, "")
}

// downgradeInboundError reports whether an ERROR entry is per-connection
// noise that should surface as WARN.
func downgradeInboundError(msg string) bool {
	return strings.HasPrefix(msg, inboundTagPrefix) || noiseRe.MatchString(msg)
}
