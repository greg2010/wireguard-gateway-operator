package link

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// defaultReconcileInterval backs the safety-net ticker when the configured
// interval is non-positive, so time.NewTicker can never panic.
const defaultReconcileInterval = 10 * time.Second

// applyFunc programs the tunnel and nftables from rc. It is injected so the
// reload loop can be tested without shelling out.
type applyFunc func(ctx context.Context, rc RuntimeConfig, privKey, peerPubKey string) error

// watchAndReload applies the RuntimeConfig and re-applies it on change, returning nil
// on ctx cancellation. It watches the config's parent dir because a ConfigMap update
// swaps the atomic ..data symlink a plain file watch would miss.
func watchAndReload(ctx context.Context, cfg Config, privKey, peerPubKey string, reconcile applyFunc, log *zap.SugaredLogger) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create config watcher: %w", err)
	}
	defer watcher.Close()

	dir := filepath.Dir(cfg.ConfigPath)
	if err := watcher.Add(dir); err != nil {
		return fmt.Errorf("watch config dir %s: %w", dir, err)
	}

	interval := cfg.ReconcileInterval
	if interval <= 0 {
		interval = defaultReconcileInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lastApplied string
	apply := func() {
		rc, err := LoadRuntimeConfig(cfg.ConfigPath)
		if err != nil {
			log.Warnw("load runtime config", "path", cfg.ConfigPath, "error", err)
			return
		}
		digest, err := configDigest(rc)
		if err != nil {
			log.Warnw("digest runtime config", "error", err)
			return
		}
		if digest == lastApplied {
			return
		}
		if rc.WireGuard.Peer.Endpoint == "" {
			log.Infow("waiting for gateway endpoint in config", "path", cfg.ConfigPath)
			return
		}
		if err := reconcile(ctx, rc, privKey, peerPubKey); err != nil {
			log.Warnw("apply tunnel config", "endpoint", rc.WireGuard.Peer.Endpoint, "error", err)
			return
		}
		lastApplied = digest
		log.Infow("applied tunnel config", "endpoint", rc.WireGuard.Peer.Endpoint)
	}

	apply()
	for {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if event.Name == dir && (event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename)) {
				log.Warnw("config dir watch lost, re-adding", "dir", dir, "op", event.Op.String())
				if err := watcher.Add(dir); err != nil {
					log.Warnw("re-add config dir watch", "dir", dir, "error", err)
				}
			}
			apply()
		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			log.Warnw("config watcher error", "error", err)
		case <-ticker.C:
			apply()
		}
	}
}

// configDigest is the sha256 hex of rc's JSON, used to detect a config change across
// reloads. json.Marshal of RuntimeConfig is deterministic, so an unchanged config
// always hashes the same.
func configDigest(rc RuntimeConfig) (string, error) {
	data, err := json.Marshal(rc)
	if err != nil {
		return "", fmt.Errorf("marshal runtime config: %w", err)
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum), nil
}
