package xray

import (
	"bufio"
	"context"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/cedar2025/xboard-node/internal/nlog"
)

// resolvConfPath is a variable so tests can point it at a fixture.
var resolvConfPath = "/etc/resolv.conf"

// systemDNSServers returns the resolvers the generated xray config should use.
//
// Leaving the kernel without a dns block made every direct dial resolve through
// the OS resolver (sockopt.domainStrategy defaults to AsIs), and a stalled
// system resolver then hangs every domain-target connection while IP targets
// keep working. Feeding the kernel the same resolvers the OS uses, with an
// explicit query strategy, keeps resolution inside the process.
func systemDNSServers() []string {
	return systemDNSLookup()
}

// systemDNSLookup is a variable so tests can pin the resolver set.
var systemDNSLookup = func() []string {
	return pickDNSServers(runtime.GOOS, readFileOrEmpty(resolvConfPath), scutilNameservers)
}

// pickDNSServers chooses the resolvers for the generated dns block. Split out
// from the lookup so every branch is testable without touching the host.
func pickDNSServers(goos string, resolvConf string, scutil func() []string) []string {
	var servers []string
	if goos == "darwin" {
		// /etc/resolv.conf mirrors the primary resolver, including the fake-IP
		// resolver proxy apps install as Supplemental. scutil can tell them
		// apart, so it wins on macOS.
		servers = scutil()
	}
	if len(servers) == 0 {
		servers = parseNameservers(resolvConf)
	}
	if len(servers) == 0 {
		servers = []string{"1.1.1.1", "8.8.8.8"}
	}
	return servers
}

// parseIPv4 returns the address when it is a usable IPv4 resolver. IPv6
// resolvers are dropped on purpose: the generated dns block queries A records
// only (queryStrategy UseIPv4), and a bracketed/zone IPv6 entry is the one shape
// xray's DNS server parser rejects - which would abort the whole kernel start.
func parseIPv4(raw string) net.IP {
	ip := raw
	if i := strings.IndexByte(ip, '%'); i >= 0 {
		ip = ip[:i]
	}
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.IsUnspecified() || parsed.To4() == nil {
		return nil
	}
	return parsed
}

// parseNameservers extracts valid resolver IPs from a resolv.conf body.
func parseNameservers(body string) []string {
	var servers []string
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "nameserver") {
			continue
		}
		ip := fields[1]
		if i := strings.IndexByte(ip, '%'); i >= 0 { // strip IPv6 zone
			ip = ip[:i]
		}
		parsed := parseIPv4(ip)
		if parsed == nil {
			continue
		}
		normalized := parsed.String()
		if seen[normalized] {
			continue
		}
		seen[normalized] = true
		servers = append(servers, normalized)
		if len(servers) == 4 {
			break
		}
	}
	return servers
}

// parseScutilDNS extracts the primary resolvers from `scutil --dns` output.
//
// Only the "DNS configuration" section is considered (the scoped section holds
// per-interface resolvers that are not reachable for general traffic), and
// Supplemental resolvers are skipped: proxy apps install those with private
// fake-IP addresses that only work inside their own TUN.
func parseScutilDNS(output string) []string {
	var servers, pending []string
	seen := make(map[string]bool)
	skipBlock := false
	inScoped := false
	done := false

	// A block's flags line follows its nameserver lines, so the decision to
	// keep a block can only be made once the block ends. The first block that
	// carries usable nameservers is the primary resolver; later blocks are
	// per-domain/per-interface overrides that do not belong in the default
	// resolver list.
	flush := func() {
		if done {
			pending = nil
			return
		}
		if !skipBlock {
			for _, ip := range pending {
				if seen[ip] {
					continue
				}
				seen[ip] = true
				servers = append(servers, ip)
			}
			if len(servers) > 4 {
				servers = servers[:4]
			}
			if len(servers) > 0 {
				done = true
			}
		}
		pending = nil
	}

	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "DNS configuration (for scoped queries)") {
			flush()
			inScoped = true
			continue
		}
		if inScoped {
			continue
		}
		if strings.HasPrefix(line, "resolver #") {
			flush()
			skipBlock = false
			continue
		}
		if strings.HasPrefix(line, "flags") && strings.Contains(line, "Supplemental") {
			skipBlock = true
			continue
		}
		fields := strings.SplitN(line, ":", 2)
		if len(fields) != 2 || !strings.HasPrefix(strings.TrimSpace(fields[0]), "nameserver[") {
			continue
		}
		ip := strings.TrimSpace(fields[1])
		if i := strings.IndexByte(ip, '%'); i >= 0 {
			ip = ip[:i]
		}
		parsed := parseIPv4(ip)
		if parsed == nil {
			continue
		}
		pending = append(pending, parsed.String())
	}
	flush()
	if len(servers) > 4 {
		servers = servers[:4]
	}
	return servers
}

// scutilNameservers reads macOS' resolved nameservers. Best effort: a missing
// binary or timeout falls back to the public resolvers.
func scutilNameservers() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "scutil", "--dns").Output()
	if err != nil {
		nlog.Core().Debug("scutil --dns failed, falling back to public resolvers", "error", err)
		return nil
	}
	return parseScutilDNS(string(out))
}

func readFileOrEmpty(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}
