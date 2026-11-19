package geodata

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cedar2025/xboard-node/internal/nlog"
)

const (
	singboxGeoIPURL   = "https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db"
	singboxGeoSiteURL = "https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db"
	xrayGeoIPURL      = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
	xrayGeoSiteURL    = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"

	// minGeoFileSize rejects truncated downloads. Every published geo database
	// is several MiB; anything smaller is a partial file or an error page.
	minGeoFileSize = 1 << 20
)

// httpClient timeout is deliberately short: the download runs inside kernel
// start, and a hung GitHub connection used to stall startup for 10 minutes per
// file before failing.
var httpClient = &http.Client{Timeout: 60 * time.Second}

func Ensure(dir string, needGeoIP, needGeoSite bool, kernelType string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create geo_data_dir %q: %w", dir, err)
	}

	type entry struct {
		name string
		url  string
	}

	var files []entry
	if kernelType == "singbox" {
		if needGeoIP {
			files = append(files, entry{"geoip.db", singboxGeoIPURL})
		}
		if needGeoSite {
			files = append(files, entry{"geosite.db", singboxGeoSiteURL})
		}
	} else {
		if needGeoIP {
			files = append(files, entry{"geoip.dat", xrayGeoIPURL})
		}
		if needGeoSite {
			files = append(files, entry{"geosite.dat", xrayGeoSiteURL})
		}
	}

	var firstErr error
	for _, f := range files {
		if err := ensureFile(dir, f.name, f.url); err != nil {
			nlog.Core().Warn("geo database auto-download failed", "file", f.name, "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func ensureFile(dir, name, url string) error {
	dst := filepath.Join(dir, name)
	if fi, err := os.Stat(dst); err == nil {
		if fi.Size() > 0 {
			return nil
		}
		// Only a zero-byte placeholder is removed. A smaller-than-expected
		// file may be a user-provided custom database; never delete it.
		nlog.Core().Warn("geo database is empty, re-downloading", "file", name, "dir", dir)
		if err := os.Remove(dst); err != nil {
			return fmt.Errorf("remove empty %s: %w", dst, err)
		}
	}
	nlog.Core().Info("geo database missing, downloading automatically", "file", name, "url", url)
	if err := atomicDownload(dst, url); err != nil {
		return fmt.Errorf("%w; download %s manually into %s", err, name, dir)
	}
	return nil
}

// downloadLocks serialises downloads per destination path inside this process:
// machine mode shares geo_data_dir across node instances that start together.
var downloadLocks sync.Map // dst → *sync.Mutex

func atomicDownload(dst, url string) error {
	lockAny, _ := downloadLocks.LoadOrStore(dst, &sync.Mutex{})
	mu := lockAny.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()

	// Another instance may have completed the download while we waited.
	if fi, err := os.Stat(dst); err == nil && fi.Size() > 0 {
		return nil
	}

	resp, err := httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("http get %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status from %s: %s", url, resp.Status)
	}

	// Unique temp name: a fixed ".tmp" let two processes (shared geo_data_dir
	// across node instances, or two daemons) interleave writes into one file,
	// and the truncated result was never re-downloaded because ensureFile
	// trusts any non-empty file.
	f, err := os.CreateTemp(filepath.Dir(dst), filepath.Base(dst)+".tmp.*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)

	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return fmt.Errorf("write geo database: %w", err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("stat temp file: %w", err)
	}
	if fi.Size() < minGeoFileSize {
		f.Close()
		return fmt.Errorf("downloaded file is too small (%d bytes)", fi.Size())
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		return fmt.Errorf("rename to destination: %w", err)
	}
	nlog.Core().Info("geo database ready", "file", filepath.Base(dst), "size_kb", fi.Size()/1024)
	return nil
}
