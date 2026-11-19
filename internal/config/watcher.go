package config

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cedar2025/xboard-node/internal/nlog"
	"github.com/fsnotify/fsnotify"
)

// Watcher reloads the config file on change (debounced) and calls onChangeRoot.
type Watcher struct {
	path         string
	debounce     time.Duration
	onChangeRoot func(*RootConfig)
	watcher      *fsnotify.Watcher

	stopOnce sync.Once
	stopCh   chan struct{}
	stopped  atomic.Bool
}

// WatchConfigRoot watches path and reloads the root config model.
func WatchConfigRoot(ctx context.Context, path string, onChange func(*RootConfig)) (*Watcher, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	dir := filepath.Dir(absPath)
	if err := fsw.Add(dir); err != nil {
		fsw.Close()
		return nil, err
	}

	w := &Watcher{
		path:         absPath,
		debounce:     1 * time.Second,
		onChangeRoot: onChange,
		watcher:      fsw,
		stopCh:       make(chan struct{}),
	}

	go w.loop(ctx)
	nlog.Core().Info("config watcher started", "path", absPath)
	return w, nil
}

func (w *Watcher) loop(ctx context.Context) {
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
		w.watcher.Close()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.stopCh:
			return

		case ev, ok := <-w.watcher.Events:
			if !ok {
				return
			}
			if filepath.Clean(ev.Name) != w.path {
				continue
			}
			if !ev.Has(fsnotify.Write) && !ev.Has(fsnotify.Create) {
				continue
			}

			if timer == nil {
				timer = time.AfterFunc(w.debounce, w.reload)
			} else {
				timer.Reset(w.debounce)
			}

		case err, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			nlog.Core().Warn("config watcher error", "error", err)
		}
	}
}

func (w *Watcher) reload() {
	if w.stopped.Load() {
		return
	}
	root, err := LoadRoot(w.path)
	if err != nil {
		nlog.Core().Error("config reload failed, keeping current config", "error", err)
		return
	}
	// LoadRoot only checks field-level validity. Startup layout conflicts
	// (duplicate health_port, shared config_dir, duplicate node binding)
	// are caught by ValidateStartupLayout when the services are already
	// stopped, which would make the daemon exit. Reject here instead so the
	// running configuration stays untouched.
	instances, err := root.NormalizeInstances()
	if err != nil {
		nlog.Core().Error("config reload rejected, keeping current config", "error", err)
		return
	}
	if err := ValidateStartupLayout(instances); err != nil {
		nlog.Core().Error("config reload rejected, keeping current config", "error", err)
		return
	}
	nlog.Core().Info("config reloaded successfully")
	w.onChangeRoot(root)
}

func (w *Watcher) Stop() {
	w.stopped.Store(true)
	w.stopOnce.Do(func() { close(w.stopCh) })
}
