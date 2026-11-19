package model

import (
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/cedar2025/xboard-node/internal/nlog"
)

// sanitizePanelPaths confines the filesystem paths and proxy URLs a panel can
// hand to the kernel. The panel is semi-trusted (see sanitizePanelDNSEnv): an
// unrestricted hysteria2 masquerade.directory serves any node-readable file on
// the public port, and an unrestricted tls_settings.ech.key_path reads any
// file into the kernel config.
//
// configDir is the node-owned root (kernel.config_dir). Paths must resolve
// inside it; the directory itself is not a valid masquerade root, since it
// holds config.yml and credentials.
func sanitizePanelPaths(n *NodeSpec, configDir string) {
	if n == nil {
		return
	}
	sanitizePanelMasquerade(n, configDir)
	sanitizePanelECHKeyPath(n, configDir)
}

func sanitizePanelMasquerade(n *NodeSpec, configDir string) {
	mc := n.Masquerade
	if mc == nil {
		return
	}
	switch strings.ToLower(strings.TrimSpace(mc.Type)) {
	case "file":
		if mc.File == nil || strings.TrimSpace(mc.File.Dir) == "" {
			return
		}
		if !pathUnderRoot(mc.File.Dir, configDir, false) {
			nlog.Core().Warn("panel masquerade directory is outside the node config dir, dropping masquerade", "dir", mc.File.Dir)
			n.Masquerade = nil
		}
	case "proxy":
		if mc.Proxy == nil || strings.TrimSpace(mc.Proxy.URL) == "" {
			return
		}
		if !safeMasqueradeProxyURL(mc.Proxy.URL) {
			nlog.Core().Warn("panel masquerade proxy URL is not allowed, dropping masquerade", "url", mc.Proxy.URL)
			n.Masquerade = nil
		}
	}
}

// sanitizePanelECHKeyPath drops an out-of-root ECH key file. When the panel
// also supplied an inline key, only key_path is removed; otherwise the whole
// ech block goes away, since sing-box forwards a keyless enabled block to the
// kernel instead of failing closed.
func sanitizePanelECHKeyPath(n *NodeSpec, configDir string) {
	if len(n.TLSSettings) == 0 {
		return
	}
	ech, ok := n.TLSSettings["ech"].(map[string]any)
	if !ok {
		return
	}
	keyPath, _ := ech["key_path"].(string)
	if strings.TrimSpace(keyPath) == "" || pathUnderRoot(keyPath, configDir, true) {
		return
	}

	// Copy before mutating: only the outer TLSSettings map is cloned by
	// NodeSpecFromPanel, so the nested ech map is shared with the panel
	// snapshot.
	cloned := make(map[string]any, len(ech))
	for k, v := range ech {
		cloned[k] = v
	}
	delete(cloned, "key_path")

	if key, _ := cloned["key"].(string); strings.TrimSpace(key) == "" {
		delete(n.TLSSettings, "ech")
		nlog.Core().Warn("panel ECH key_path is outside the node config dir and no inline key was provided, disabling ECH", "key_path", keyPath)
		return
	}
	n.TLSSettings["ech"] = cloned
	nlog.Core().Warn("panel ECH key_path is outside the node config dir, using the inline key", "key_path", keyPath)
}

// pathUnderRoot reports whether path resolves inside root. allowRoot controls
// whether root itself counts as inside. It fails closed for an empty root and
// for the filesystem root: filepath.Abs("") is the process CWD (often "/"
// under systemd), which would otherwise accept every panel path.
func pathUnderRoot(path, root string, allowRoot bool) bool {
	root = strings.TrimSpace(root)
	path = strings.TrimSpace(path)
	if root == "" || path == "" {
		return false
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	if rootAbs == string(filepath.Separator) {
		return false
	}
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(rootAbs, pathAbs)
	if err != nil {
		return false
	}
	if rel == "." {
		return allowRoot
	}
	return !filepath.IsAbs(rel) && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// safeMasqueradeProxyURL rejects proxy targets that let the panel turn the
// node into a metadata/loopback SSRF client. Hostnames are not resolved here:
// a DNS name pointing at a private address still passes, so this is a bound on
// the obvious cases, not a complete SSRF defence.
func safeMasqueradeProxyURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return true
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	return !addr.IsLoopback() &&
		!addr.IsPrivate() &&
		!addr.IsLinkLocalUnicast() &&
		!addr.IsLinkLocalMulticast() &&
		!addr.IsUnspecified() &&
		!addr.IsMulticast()
}
