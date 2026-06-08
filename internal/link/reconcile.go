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
// interval is non-positive, so it can never panic time.NewTicker or busy-loop.
// The fsnotify watch is the primary trigger; the ticker only backstops a missed
// event.
const defaultReconcileInterval = 10 * time.Second

// applyFunc programs the tunnel and nftables from rc, given the WireGuard
// private and peer public keys. It is injected so the reload loop can be tested
// without shelling out; production binds it to a closure that picks Apply or
// Reconcile from wg0Exists.
type applyFunc func(ctx context.Context, rc RuntimeConfig, privKey, peerPubKey string) error

// watchAndReload applies the link's RuntimeConfig and keeps it in sync with the
// on-disk ConfigMap in place: it re-applies whenever the file changes and the
// peer endpoint is set, without ever tearing the tunnel down.
//
// It loads and applies the initial config synchronously before entering the
// watch loop (tolerating an empty Peer.Endpoint: the operator may not have
// observed the gateway address yet, in which case it logs and waits rather than
// applying a peerless tunnel). That initial apply is what picks up the endpoint
// once it is present. It then watches the directory holding the config so the
// ConfigMap's atomic ..data symlink swap is observed: a Kubernetes ConfigMap
// update replaces that symlink rather than rewriting the mounted file, so a file
// watch would miss it; any directory event triggers a re-read. A
// cfg.ReconcileInterval ticker backs the watch purely as a safety-net for a
// missed event.
//
// On each wake it reloads the config and compares its canonical digest against
// the last successfully-applied one; an unchanged config is a no-op, and a
// changed config is applied only when the endpoint is set. last-applied is
// advanced only on a successful apply, so a transient apply failure is retried on
// the next wake. reconcile is injected for testing. It returns nil when ctx is
// cancelled.
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

// configDigest is the sha256 hex of rc's canonical JSON, used to detect a config
// change across reloads. json.Marshal of RuntimeConfig is deterministic: struct
// fields serialize in declaration order and the only slices (AllowedIPs,
// Forwards) carry caller-defined order, so an unchanged config always hashes the
// same.
func configDigest(rc RuntimeConfig) (string, error) {
	data, err := json.Marshal(rc)
	if err != nil {
		return "", fmt.Errorf("marshal runtime config: %w", err)
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum), nil
}
