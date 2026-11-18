package nlog

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

// ANSI color codes
const (
	ColorReset  = "\033[0m"
	ColorGray   = "\033[90m" // 时间戳
	ColorWhite  = "\033[37m" // INFO
	ColorYellow = "\033[33m" // WARN
	ColorRed    = "\033[31m" // ERROR
	ColorCyan   = "\033[36m" // 节点前缀
	ColorGreen  = "\033[32m" // 调试信息
	ColorBlue   = "\033[34m" // core 前缀
)

// NodeLog provides structured logging with node context.
// Format: LEVEL [protocol:port] message
type NodeLog struct {
	prefix string // e.g., "shadowsocks:10005" or "trojan:10033"
}

// Global logger state
var (
	mu          sync.RWMutex
	defaultNode string
	nodeLoggers = make(map[string]*NodeLog)

	logMu     sync.RWMutex
	logWriter io.Writer = os.Stdout
	logMin              = slog.LevelInfo
	logColor            = true
)

// Init configures process-wide log output (called from config.InitLogger).
// w must be non-nil. minLevel drops messages below that severity.
// color enables ANSI coloring when true (typically TTY + stdout/stderr).
func Init(w io.Writer, minLevel slog.Level, color bool) {
	if w == nil {
		w = os.Stdout
	}
	logMu.Lock()
	defer logMu.Unlock()
	logWriter = w
	logMin = minLevel
	logColor = color
}

// formatMsg appends alternating key-value pairs like slog: ("k", v, "k2", v2).
func formatMsg(msg string, args []any) string {
	if len(args) == 0 {
		return msg
	}
	var b strings.Builder
	b.WriteString(msg)
	for i := 0; i < len(args); i += 2 {
		if i+1 < len(args) {
			fmt.Fprintf(&b, " %v=%v", args[i], args[i+1])
		} else {
			fmt.Fprintf(&b, " %v", args[i])
		}
	}
	return b.String()
}

// SetDefault sets the default node prefix for core-level logs.
func SetDefault(prefix string) {
	mu.Lock()
	defaultNode = prefix
	mu.Unlock()
}

// ForNode returns a NodeLog for the given protocol and port.
func ForNode(protocol string, port int) *NodeLog {
	key := fmt.Sprintf("%s:%d", normalizeProto(protocol), port)
	mu.RLock()
	if nl, ok := nodeLoggers[key]; ok {
		mu.RUnlock()
		return nl
	}
	mu.RUnlock()

	mu.Lock()
	defer mu.Unlock()
	// Double check
	if nl, ok := nodeLoggers[key]; ok {
		return nl
	}
	nl := &NodeLog{prefix: key}
	nodeLoggers[key] = nl
	return nl
}

// Core returns a NodeLog for core/system messages.
func Core() *NodeLog {
	mu.RLock()
	if nl, ok := nodeLoggers["core"]; ok {
		mu.RUnlock()
		return nl
	}
	mu.RUnlock()

	mu.Lock()
	defer mu.Unlock()
	if nl, ok := nodeLoggers["core"]; ok {
		return nl
	}
	nl := &NodeLog{prefix: "core"}
	nodeLoggers["core"] = nl
	return nl
}

// normalizeProto returns the full protocol name for display.
func normalizeProto(p string) string {
	switch strings.ToLower(p) {
	case "shadowsocks", "ss":
		return "shadowsocks"
	case "vmess":
		return "vmess"
	case "vless":
		return "vless"
	case "trojan":
		return "trojan"
	case "hysteria2":
		return "hysteria2"
	case "hysteria":
		return "hysteria"
	case "tuic":
		return "tuic"
	case "anytls":
		return "anytls"
	case "naive":
		return "naive"
	case "http":
		return "http"
	case "socks":
		return "socks"
	default:
		return p
	}
}

// ─── Logging Methods ────────────────────────────────────────────────────────

func (nl *NodeLog) Debug(msg string, args ...any) {
	logWithColor(slog.LevelDebug, nl.prefix, msg, args...)
}

func (nl *NodeLog) Info(msg string, args ...any) {
	logWithColor(slog.LevelInfo, nl.prefix, msg, args...)
}

func (nl *NodeLog) Warn(msg string, args ...any) {
	logWithColor(slog.LevelWarn, nl.prefix, msg, args...)
}

func (nl *NodeLog) Error(msg string, args ...any) {
	logWithColor(slog.LevelError, nl.prefix, msg, args...)
}

// logWithColor writes one line to the configured writer (see Init).
// Format: HH:MM:SS.mmm LEVEL [prefix] message [key=value ...]
func logWithColor(level slog.Level, prefix, msg string, args ...any) {
	logMu.RLock()
	out := logWriter
	min := logMin
	color := logColor
	logMu.RUnlock()

	if level < min {
		return
	}

	now := time.Now().Format("15:04:05.000")
	fullMsg := formatMsg(msg, args)

	var levelStr string
	switch level {
	case slog.LevelDebug:
		levelStr = "DEBUG"
	case slog.LevelInfo:
		levelStr = "INFO "
	case slog.LevelWarn:
		levelStr = "WARN "
	case slog.LevelError:
		levelStr = "ERROR"
	default:
		levelStr = "?????"
	}

	if !color {
		fmt.Fprintf(out, "%s %s [%s] %s\n", now, strings.TrimSpace(levelStr), prefix, fullMsg)
		return
	}

	var levelColor string
	switch level {
	case slog.LevelDebug:
		levelColor = ColorGreen
	case slog.LevelInfo:
		levelColor = ColorWhite
	case slog.LevelWarn:
		levelColor = ColorYellow
	case slog.LevelError:
		levelColor = ColorRed
	default:
		levelColor = ColorWhite
	}

	prefixColor := ColorCyan
	if prefix == "core" {
		prefixColor = ColorBlue
	}

	fmt.Fprintf(out, "%s%s%s %s%s%s %s[%s]%s %s\n",
		ColorGray, now, ColorReset,
		levelColor, levelStr, ColorReset,
		prefixColor, prefix, ColorReset,
		fullMsg,
	)
}

// ─── Helpers ────────────────────────────────────────────────────────────────

// ReportPushed logs a report push event.
func ReportPushed(users, online int) {
	Core().Info(fmt.Sprintf("report pushed: %d users, %d online", users, online))
}

// TrackerStats logs tracker statistics.
func TrackerStats(conns, users int) {
	Core().Debug(fmt.Sprintf("tracker: %d conns, %d users online", conns, users))
}
