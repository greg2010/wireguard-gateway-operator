// Package link implements the in-cluster gateway-link daemon: it brings up the
// WireGuard tunnel to the gateway VM and DNATs public ports either to Service
// ClusterIPs (Cluster mode) or to ready backend pods on the node holding the Lease
// (Local mode), reloading from a watched ConfigMap. Leader election over a Lease lets
// only the holder program the data plane.
package link

import (
	"context"
	"encoding/json"
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
)

const shutdownTimeout = 5 * time.Second

// Run starts election and readiness until ctx is cancelled.
func Run(ctx context.Context, cfg Config, log *zap.SugaredLogger) error {
	rc, err := LoadRuntimeConfig(cfg.ConfigPath)
	if err != nil {
		return fmt.Errorf("load runtime config: %w", err)
	}

	privKey, err := readKeyFile(cfg.WGKeyPath)
	if err != nil {
		return fmt.Errorf("read wireguard private key: %w", err)
	}

	if rc.isLocal() && cfg.NodeName == "" {
		return fmt.Errorf("local mode requires NODE_NAME")
	}

	dp := newDataPlane(rc)
	if rc.isLocal() {
		// No slot is admitted yet: this replica has applied none, and the fence admits the
		// health port on exactly the interfaces of the slots its own passes applied.
		if err := InstallFencing(ctx, execCommand, rc, nil); err != nil {
			return fmt.Errorf("install fencing table: %w", err)
		}
		// Deferred first so Go's LIFO order runs it last, after every other cleanup this
		// function defers below and after g.Wait() has returned serveHealth.
		defer func() {
			if err := RemoveFencing(context.Background(), execCommand, rc); err != nil {
				log.Warnw("remove fencing table", "error", err)
			}
		}()
	}

	restCfg, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("in-cluster config: %w", err)
	}
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("kubernetes client: %w", err)
	}
	// Discovery holds every inherited Gateway slot so departed slots are torn down.
	var inherited bool
	if rc.isLocal() {
		names, listErr := linkNames(ctx)
		if listErr != nil {
			log.Warnw("enumerate the node's links, assuming no inherited data plane", "error", listErr)
		}
		for _, slot := range InheritedSlots(names, rc.Identity.ID) {
			inherited = true
			dp.hold(slot)
			log.Infow("found an existing data plane at start, keeping it until this replica's first pass",
				"interface", NewSlotIdentity(rc.Identity.ID, slot).Interface)
		}
	}
	rd := newReadiness(rc.isLocal(), gatewayIDOf(rc), time.Now, wgShowHandshakes, log)
	lock := newTunnelLeaseLock(cfg.PodNamespace, cfg.LeaseName, cs.CoordinationV1(), cfg.PodName, func(ctx context.Context) (bool, string) {
		if !rd.isLeader() {
			return false, "not leader"
		}
		return rd.tunnelStatus(ctx)
	})

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

	apply := func(ctx context.Context, rc RuntimeConfig, privKey string, localForwards []ResolvedForward) ([]SlotResult, error) {
		return dp.applyPass(ctx, execCommand, rc, func(ctx context.Context) ([]SlotResult, error) {
			return Apply(ctx, execCommand, rc, privKey, resolve, localForwards, log)
		}, log)
	}
	reconcile := newLeaderReconcile(cs, cfg, rd, preCheck, apply, log)

	g, gctx := errgroup.WithContext(ctx)
	if ew != nil {
		g.Go(func() error {
			return watchLocalForwards(gctx, cfg, ew, rc.Identity, func(ctx context.Context, accepted RuntimeConfig) {
				if err := dp.standbyPass(ctx, execCommand, accepted, rd.isLeader, log); err != nil {
					log.Warnw("maintain the standby's fence", "error", err)
				}
			}, log)
		})
	}
	deps := electionDeps{
		cfg:       cfg,
		lock:      lock,
		rd:        rd,
		ew:        ew,
		identity:  rc.Identity,
		cs:        cs,
		privKey:   privKey,
		reconcile: reconcile,
		timing:    defaultElectionTiming,

		inheritedDataPlane: inherited,
		fence: func(ctx context.Context) error {
			return dp.stepDown(ctx, execCommand, log)
		},
		onOtherHolder:    dp.observeOtherHolder,
		onStartedLeading: dp.clearOtherHolder,
		log:              log,
	}
	g.Go(func() error {
		return deps.runElection(ctx, gctx)
	})
	g.Go(func() error {
		return serveHealth(gctx, rd, cs, cfg, log)
	})
	return g.Wait()
}

// gatewayIDOf returns rc's Gateway-level link id, or 0 in Cluster mode, whose passes carry no
// slot so the id is never read.
func gatewayIDOf(rc RuntimeConfig) int {
	if rc.Identity != nil {
		return rc.Identity.ID
	}
	return 0
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

// newLeaderReconcile starts reconciliation after leadership acquisition.
func newLeaderReconcile(cs kubernetes.Interface, cfg Config, rd *readiness, preCheck preCheckFault,
	apply func(ctx context.Context, rc RuntimeConfig, privKey string, localForwards []ResolvedForward) ([]SlotResult, error),
	log *zap.SugaredLogger) applyFunc {
	return func(ctx context.Context, rc RuntimeConfig, privKey string, localForwards []ResolvedForward, unsatisfied []unsatisfiedForward) ([]SlotResult, error) {
		if preCheck.Reason != "" {
			if err := publishFault(ctx, cs, cfg.PodNamespace, cfg.LeaseName, cfg.PodName, preCheck.Reason, preCheck.Message, log); err != nil {
				log.Warnw("publish lease fault", "reason", preCheck.Reason, "error", err)
			}
			// Returned as an error so the reload loop records no digest and a
			// config that was never programmed is not suppressed as applied.
			return nil, fmt.Errorf("node pre-check fault %s: %s", preCheck.Reason, preCheck.Message)
		}

		results, applyErr := apply(ctx, rc, privKey, localForwards)

		keepalive := 0
		if len(rc.WireGuard.Peers) > 0 {
			keepalive = rc.WireGuard.Peers[0].PersistentKeepalive
		}
		rd.setPass(results, len(rc.WireGuard.Peers), keepalive, applyErr == nil)
		faultReason := ""
		if applyErr != nil {
			faultReason = FaultApplyFailed
		}
		rd.setFault(faultReason)

		if err := publishSlotState(ctx, cs, cfg.PodNamespace, cfg.LeaseName, cfg.PodName, results, log); err != nil {
			log.Warnw("publish lease slot state", "error", err)
		}

		reason, message := leaderFault(cfg.NodeName, applyErr, unsatisfied)
		if err := publishFault(ctx, cs, cfg.PodNamespace, cfg.LeaseName, cfg.PodName, reason, message, log); err != nil {
			log.Warnw("publish lease fault", "reason", reason, "error", err)
			if applyErr == nil {
				return results, fmt.Errorf("publish lease fault %q: %w", reason, err)
			}
		}
		return results, applyErr
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
	mux.HandleFunc("/forwarded-healthz", rd.forwardedHandler)
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

// linkNames lists the node's link names in one call, the enumeration startup discovery matches
// this Gateway's interface names against instead of probing every slot.
func linkNames(ctx context.Context) ([]string, error) {
	out, err := exec.CommandContext(ctx, "ip", "-j", "link", "show").Output()
	if err != nil {
		return nil, fmt.Errorf("ip -j link show: %w", err)
	}
	var links []struct {
		IfName string `json:"ifname"`
	}
	if err := json.Unmarshal(out, &links); err != nil {
		return nil, fmt.Errorf("decode ip -j link show output: %w", err)
	}
	names := make([]string, 0, len(links))
	for _, l := range links {
		names = append(names, l.IfName)
	}
	return names, nil
}

func wgShowHandshakes(ctx context.Context, iface string) (string, error) {
	out, err := exec.CommandContext(ctx, "wg", "show", iface, "latest-handshakes").Output()
	if err != nil {
		return "", fmt.Errorf("wg show %s latest-handshakes: %w", iface, err)
	}
	return string(out), nil
}
