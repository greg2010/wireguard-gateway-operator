// Package link implements the in-cluster gateway-link daemon: it brings up the
// WireGuard tunnel to the gateway VM and DNATs public ports either to Service
// ClusterIPs (Cluster mode) or to ready backend pods on the node holding the Lease
// (Local mode), reloading from a watched ConfigMap. Leader election over a Lease lets
// only the holder program the data plane.
package link

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

const shutdownTimeout = 5 * time.Second

// Run loads the config and key material, then runs leader election and the readiness HTTP server
// until ctx is cancelled. Config and key reads are fatal and precede the in-cluster client, so
// they surface without apiserver access. The health server starts only once the link pod watch has
// synced, so a link that cannot yet see its peers stays unready instead of answering the probe.
func Run(ctx context.Context, cfg Config, log *zap.SugaredLogger) error {
	rc, err := LoadRuntimeConfig(cfg.ConfigPath)
	if err != nil {
		return fmt.Errorf("load runtime config: %w", err)
	}

	privKey, err := readKeyFile(cfg.WGKeyPath)
	if err != nil {
		return fmt.Errorf("read wireguard private key: %w", err)
	}
	peerPubKey, err := readKeyFile(cfg.PeerPubKeyPath)
	if err != nil {
		return fmt.Errorf("read wireguard peer public key: %w", err)
	}

	if rc.isLocal() && cfg.NodeName == "" {
		return fmt.Errorf("local mode requires NODE_NAME")
	}

	restCfg, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("in-cluster config: %w", err)
	}
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("kubernetes client: %w", err)
	}
	lock, err := resourcelock.New(
		resourcelock.LeasesResourceLock,
		cfg.PodNamespace,
		cfg.LeaseName,
		cs.CoreV1(),
		cs.CoordinationV1(),
		resourcelock.ResourceLockConfig{Identity: cfg.PodName},
	)
	if err != nil {
		return fmt.Errorf("create lease lock: %w", err)
	}

	iface := interfaceName(rc)
	// A holder that died without releasing the Lease leaves its interface behind: it is an earlier
	// process's data plane, kept until another holder is observed or this replica re-applies it.
	var inherited bool
	if rc.isLocal() {
		var err error
		// A failed probe is logged, not fatal: a node whose ip(8) is broken cannot
		// fence or apply either, and the first apply publishes that as a fault.
		inherited, err = ifaceExists(ctx, execCommand, iface)
		if err != nil {
			log.Warnw("probe for an existing data plane failed, assuming none", "interface", iface, "error", err)
		}
		if inherited {
			log.Infow("found an existing data plane at start, keeping it until a holder on another node is observed", "interface", iface)
		}
	}
	rd := newReadiness(iface, rc.WireGuard.Peer.PersistentKeepalive, time.Now, wgShowHandshakes)

	var preCheck preCheckFault
	if rc.isLocal() {
		preCheck = preCheckLocal(cfg.NodeName)
		rd.setNodeFault(preCheck.Reason)
		if preCheck.Reason != "" {
			// Without this, a node that cannot program the data plane is
			// indistinguishable from a healthy standby until it holds the Lease.
			log.Warnw("local pre-check fault", "node", cfg.NodeName, "reason", preCheck.Reason, "message", preCheck.Message)
		}
	}

	ew, err := newLocalEndpointWatcher(ctx, cs, cfg, rc, log)
	if err != nil {
		return err
	}

	resolve := newResolver(net.DefaultResolver.LookupIP)

	apply := func(ctx context.Context, rc RuntimeConfig, privKey, peerPubKey string, localForwards []ResolvedForward) error {
		return Apply(ctx, execCommand, rc, privKey, peerPubKey, resolve, localForwards, log)
	}
	reconcile := newLeaderReconcile(cs, cfg, rd, preCheck, apply, log)

	g, gctx := errgroup.WithContext(ctx)
	if ew != nil {
		g.Go(func() error {
			return watchLocalForwards(gctx, cfg, ew, rc.Identity, log)
		})
	}
	deps := electionDeps{
		cfg:        cfg,
		lock:       lock,
		rd:         rd,
		ew:         ew,
		identity:   rc.Identity,
		cs:         cs,
		privKey:    privKey,
		peerPubKey: peerPubKey,
		reconcile:  reconcile,
		timing:     defaultElectionTiming,

		inheritedDataPlane: inherited,
		fence: func(ctx context.Context) error {
			return Teardown(ctx, execCommand, rc)
		},
		log: log,
	}
	g.Go(func() error {
		return deps.runElection(ctx, gctx)
	})
	g.Go(func() error {
		return serveHealth(gctx, rd, cs, cfg, log)
	})
	return g.Wait()
}

// newLocalEndpointWatcher builds the Local EndpointSlice and pod watches, returning nil in Cluster
// mode, whose forwards carry no keys, whose decisions read none, and whose RBAC denies the list.
func newLocalEndpointWatcher(ctx context.Context, cs kubernetes.Interface, cfg Config, rc RuntimeConfig, log *zap.SugaredLogger) (*endpointWatcher, error) {
	if !rc.isLocal() {
		return nil, nil
	}
	// Validation rejects a Local config without a podSelector, so the selector never widens to
	// labels.Everything(), which would count every pod in the namespace as a link pod.
	ew, err := newEndpointWatcher(ctx, cs, cfg.NodeName, rc.Forwards, cfg.PodNamespace, labels.SelectorFromSet(rc.PodSelector), endpointResync, log)
	if err != nil {
		return nil, fmt.Errorf("start endpoint watcher: %w", err)
	}
	return ew, nil
}

// newLeaderReconcile builds the reload loop's apply step. A node the pre-check failed is never
// programmed; a failed Local apply gates readiness; a failed publish forces a re-apply next tick.
func newLeaderReconcile(cs kubernetes.Interface, cfg Config, rd *readiness, preCheck preCheckFault, apply func(ctx context.Context, rc RuntimeConfig, privKey, peerPubKey string, localForwards []ResolvedForward) error, log *zap.SugaredLogger) applyFunc {
	return func(ctx context.Context, rc RuntimeConfig, privKey, peerPubKey string, localForwards []ResolvedForward, unsatisfied []unsatisfiedForward) error {
		if preCheck.Reason != "" {
			if err := publishFault(ctx, cs, cfg.PodNamespace, cfg.LeaseName, cfg.PodName, preCheck.Reason, preCheck.Message, log); err != nil {
				log.Warnw("publish lease fault", "reason", preCheck.Reason, "error", err)
			}
			// Returned as an error so the reload loop records no digest and a
			// config that was never programmed is not suppressed as applied.
			return fmt.Errorf("node pre-check fault %s: %s", preCheck.Reason, preCheck.Message)
		}

		applyErr := apply(ctx, rc, privKey, peerPubKey, localForwards)
		// Only a failed apply gates readiness. A forward with no ready local endpoint is an
		// election input, not a reason to hide this replica from its peers' liveness table.
		if rc.isLocal() {
			if applyErr != nil {
				rd.setFault(FaultApplyFailed)
			} else {
				rd.setFault("")
			}
		}

		reason, message := leaderFault(cfg.NodeName, applyErr, unsatisfied)
		if err := publishFault(ctx, cs, cfg.PodNamespace, cfg.LeaseName, cfg.PodName, reason, message, log); err != nil {
			log.Warnw("publish lease fault", "reason", reason, "error", err)
			if applyErr == nil {
				return fmt.Errorf("publish lease fault %q: %w", reason, err)
			}
		}
		return applyErr
	}
}

// readKeyFile reads a trimmed WireGuard key from path. An empty result is an
// error so a blank or absent mounted Secret fails fast.
func readKeyFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	key := strings.TrimSpace(string(raw))
	if key == "" {
		return "", fmt.Errorf("key file %s is empty", path)
	}
	return key, nil
}

// serveHealth runs the readiness HTTP server until ctx is cancelled, then drains it within
// shutdownTimeout. An unexpected error publishes a fault when this replica holds the Lease.
func serveHealth(ctx context.Context, rd *readiness, cs kubernetes.Interface, cfg Config, log *zap.SugaredLogger) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", rd.handler)
	srv := &http.Server{Addr: cfg.HealthAddr, Handler: mux}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		if rd.isLeader() {
			if pubErr := publishFault(ctx, cs, cfg.PodNamespace, cfg.LeaseName, cfg.PodName, FaultApplyFailed, nodeMessage(cfg.NodeName, fmt.Sprintf("health server: %v", err)), log); pubErr != nil {
				log.Warnw("publish health server fault", "error", pubErr)
			}
		}
		return fmt.Errorf("health server: %w", err)
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown health server: %w", err)
		}
		return nil
	}
}

func wgShowHandshakes(ctx context.Context, iface string) (string, error) {
	out, err := exec.CommandContext(ctx, "wg", "show", iface, "latest-handshakes").Output()
	if err != nil {
		return "", fmt.Errorf("wg show %s latest-handshakes: %w", iface, err)
	}
	return string(out), nil
}
