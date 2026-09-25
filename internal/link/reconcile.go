package link

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// defaultReconcileInterval backs the safety-net ticker when the configured
// interval is non-positive, so time.NewTicker can never panic.
const defaultReconcileInterval = 10 * time.Second

// applyFunc applies the current runtime configuration.
type applyFunc func(ctx context.Context, rc RuntimeConfig, privKey string, forwards []ResolvedForward, unsatisfied []unsatisfiedForward) ([]SlotResult, error)

// watchAndReload re-applies on a config or endpoint change, also digesting the unsatisfied set,
// which no ruleset shows. keptDataPlane seeds appliedForwards; reassert runs before the digests.
func watchAndReload(ctx context.Context, cfg Config, ew *endpointWatcher, identity *GatewayIdentity, keptDataPlane bool, privKey string, reconcile applyFunc, reassert func(context.Context, RuntimeConfig), log *zap.SugaredLogger) error {
	var changes <-chan struct{}
	if ew != nil {
		var cancelChanges func()
		changes, cancelChanges = ew.subscribe()
		defer cancelChanges()
	}

	var lastConfigDigest, lastRulesetDigest string
	// appliedForwards is the set the last apply programmed, seeded from a data plane this cycle
	// took over. Re-applying without one drops its rules; one never applied has none to lose.
	var appliedForwards map[string]bool
	apply := func() {
		rc, err := loadRuntimeConfigMatching(cfg.ConfigPath, identity)
		if err != nil {
			log.Warnw("load runtime config", "path", cfg.ConfigPath, "error", err)
			return
		}
		reassert(ctx, rc)
		cfgDigest, err := configDigest(rc)
		if err != nil {
			log.Warnw("digest runtime config", "error", err)
			return
		}

		// One snapshot per apply, reused for the digest and the apply: a second one could
		// resolve differently and record a ruleset that was never installed.
		var forwards []ResolvedForward
		var unsatisfied []unsatisfiedForward
		var pending []string
		if appliedForwards == nil {
			if keptDataPlane {
				appliedForwards = forwardNames(rc.Forwards, nil)
			} else {
				appliedForwards = map[string]bool{}
			}
		}
		if ew != nil {
			ew.setForwards(rc.Forwards)
			forwards, unsatisfied, pending = ew.snapshot()
			if len(pending) > 0 {
				log.Infow("waiting for endpoint watches to sync", "forwards", pending)
				if slices.ContainsFunc(pending, func(name string) bool { return appliedForwards[name] }) {
					return
				}
			}
		}

		changed := cfgDigest != lastConfigDigest
		var rulesetDig string
		if ew != nil {
			ruleset, err := RenderNftables(rc, forwards, cfg.NodeName)
			if err != nil {
				log.Warnw("render nftables ruleset for digest", "error", err)
				return
			}
			rulesetDig = rulesetDigest(ruleset, unsatisfied)
			changed = changed || rulesetDig != lastRulesetDigest
		}
		if !changed {
			return
		}

		if slices.ContainsFunc(rc.WireGuard.Peers, func(p Peer) bool { return p.Endpoint == "" }) {
			log.Infow("waiting for every peer's endpoint in config", "path", cfg.ConfigPath)
			return
		}
		results, err := reconcile(ctx, rc, privKey, forwards, unsatisfied)
		if err != nil {
			log.Warnw("apply tunnel config", "peers", len(rc.WireGuard.Peers), "error", err)
			return
		}
		if slices.ContainsFunc(results, func(result SlotResult) bool { return !result.Applied }) {
			log.Infow("retrying tunnel config for down slots", "peers", len(rc.WireGuard.Peers))
			return
		}
		lastConfigDigest = cfgDigest
		if ew != nil {
			lastRulesetDigest = rulesetDig
		}
		appliedForwards = forwardNames(rc.Forwards, pending)
		log.Infow("applied tunnel config", "peers", len(rc.WireGuard.Peers))
	}

	return watchConfigDir(ctx, cfg, changes, log, apply)
}

// forwardNames is the set an apply over this snapshot programs: the config's forwards less the
// pending ones, which the snapshot left out of both the ruleset and the unsatisfied set.
func forwardNames(forwards []Forward, pending []string) map[string]bool {
	names := make(map[string]bool, len(forwards))
	for _, f := range forwards {
		if slices.Contains(pending, f.Name) {
			continue
		}
		names[f.Name] = true
	}
	return names
}

// watchLocalForwards tracks Local backends for reconciliation.
func watchLocalForwards(ctx context.Context, cfg Config, ew *endpointWatcher, identity *GatewayIdentity,
	onConfig func(context.Context, RuntimeConfig), log *zap.SugaredLogger) error {
	return watchConfigDir(ctx, cfg, nil, log, func() {
		rc, err := loadRuntimeConfigMatching(cfg.ConfigPath, identity)
		if err != nil {
			log.Warnw("load runtime config for forward set", "path", cfg.ConfigPath, "error", err)
			return
		}
		ew.setForwards(rc.Forwards)
		onConfig(ctx, rc)
	})
}

// loadRuntimeConfigMatching loads the RuntimeConfig at path and rejects one whose mode or identity
// differs from startup's: the watcher, RBAC and data-plane table names are fixed at process start.
func loadRuntimeConfigMatching(path string, startup *GatewayIdentity) (RuntimeConfig, error) {
	rc, err := LoadRuntimeConfig(path)
	if err != nil {
		return rc, err
	}
	if rc.isLocal() != (startup != nil) {
		return rc, fmt.Errorf("runtime config %s: traffic policy %q does not match the process mode (local=%t)", path, rc.TrafficPolicy, startup != nil)
	}
	if startup != nil && *rc.Identity != *startup {
		return rc, fmt.Errorf("runtime config %s: identity %+v differs from the identity this process started with %+v", path, *rc.Identity, *startup)
	}
	return rc, nil
}

// watchConfigDir calls onChange once, then on each event in the config file's parent dir, each
// tick and each extra signal, until ctx is done. The dir, not the file: a ConfigMap swaps ..data.
func watchConfigDir(ctx context.Context, cfg Config, extra <-chan struct{}, log *zap.SugaredLogger, onChange func()) error {
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

	// onChange never runs on a done context: a caller can be cancelled before reaching
	// this loop, and work on a dead context fails every command it runs.
	if ctx.Err() != nil {
		return nil
	}
	onChange()
	for {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-watcher.Events:
			if !ok {
				return errors.New("config watcher events channel closed")
			}
			if event.Name == dir && (event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename)) {
				log.Warnw("config dir watch lost, re-adding", "dir", dir, "op", event.Op.String())
				if err := watcher.Add(dir); err != nil {
					log.Warnw("re-add config dir watch", "dir", dir, "error", err)
				}
			}
			onChange()
		case err, ok := <-watcher.Errors:
			if !ok {
				return errors.New("config watcher errors channel closed")
			}
			log.Warnw("config watcher error", "error", err)
		case <-ticker.C:
			onChange()
		case <-extra:
			onChange()
		}
	}
}

// configDigest is the sha256 hex of rc's JSON. json.Marshal of RuntimeConfig is deterministic, so
// an unchanged config always hashes the same.
func configDigest(rc RuntimeConfig) (string, error) {
	data, err := json.Marshal(rc)
	if err != nil {
		return "", fmt.Errorf("marshal runtime config: %w", err)
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum), nil
}

// rulesetDigest hashes a rendered ruleset together with the forwards it could not program. The
// unsatisfied entries are invisible in the ruleset, yet a change among them must republish a fault.
func rulesetDigest(ruleset string, unsatisfied []unsatisfiedForward) string {
	h := sha256.New()
	h.Write([]byte(ruleset))
	for _, u := range unsatisfied {
		fmt.Fprintf(h, "\x00%s\x00%s", u.name, u.reason)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
