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
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

const shutdownTimeout = 5 * time.Second

const (
	leaseDuration = 15 * time.Second
	renewDeadline = 10 * time.Second
	retryPeriod   = 2 * time.Second
)

// fenceTimeout is derived from the parent context without its cancellation so
// the fence still runs during shutdown.
const fenceTimeout = 10 * time.Second

// Run loads the config and key material, then runs leader election and the readiness
// HTTP server until ctx is cancelled. Config and key reads are fatal and precede the
// in-cluster client so they surface without apiserver access.
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

	rd := newReadiness(rc.WireGuard.Peer.PersistentKeepalive, time.Now, wgShowHandshakes)

	resolve := newResolver(net.DefaultResolver.LookupIP)

	// Reconcile in place once wg0 exists so an established handshake survives a config
	// change; full Apply otherwise.
	reconcile := func(ctx context.Context, rc RuntimeConfig, privKey, peerPubKey string) error {
		if wg0Exists(ctx, execCommand) {
			return Reconcile(ctx, execCommand, rc, privKey, peerPubKey, resolve)
		}
		return Apply(ctx, execCommand, rc, privKey, peerPubKey, resolve)
	}

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return runElection(gctx, cfg, lock, rd, privKey, peerPubKey, reconcile, log)
	})
	g.Go(func() error {
		return serveHealth(gctx, cfg.HealthAddr, rd)
	})
	return g.Wait()
}

// runElection runs the data plane only while this replica holds the Lease, fencing on
// loss. A fresh elector is built each cycle because a LeaderElector is single use;
// returns nil on ctx cancellation, error only when an elector cannot be constructed.
func runElection(ctx context.Context, cfg Config, lock resourcelock.Interface, rd *readiness, privKey, peerPubKey string, reconcile applyFunc, log *zap.SugaredLogger) error {
	for ctx.Err() == nil {
		ran := make(chan struct{})
		done := make(chan struct{})
		elector, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
			Lock:            lock,
			ReleaseOnCancel: true,
			LeaseDuration:   leaseDuration,
			RenewDeadline:   renewDeadline,
			RetryPeriod:     retryPeriod,
			Callbacks: leaderelection.LeaderCallbacks{
				OnStartedLeading: func(leaderCtx context.Context) {
					close(ran)
					defer close(done)
					rd.setLeader(true)
					defer rd.setLeader(false)

					_ = watchAndReload(leaderCtx, cfg, privKey, peerPubKey, reconcile, log)

					fenceCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), fenceTimeout)
					defer cancel()
					if err := Teardown(fenceCtx, execCommand); err != nil {
						log.Warnw("link fence incomplete", "error", err)
					}
				},
				OnStoppedLeading: func() {},
				OnNewLeader:      func(identity string) { log.Debugw("observed leader", "identity", identity) },
			},
		})
		if err != nil {
			return fmt.Errorf("create leader elector: %w", err)
		}

		elector.Run(ctx)

		// elector.Run also returns when leadership was never acquired, so only
		// wait for the callback to finish fencing when it actually started.
		select {
		case <-ran:
			<-done
		default:
		}
	}
	return nil
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

// serveHealth runs the readiness HTTP server until ctx is cancelled, then
// drains it within shutdownTimeout. An unexpected server error is returned;
// http.ErrServerClosed from the cancel path is not.
func serveHealth(ctx context.Context, addr string, rd *readiness) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", rd.handler)
	srv := &http.Server{Addr: addr, Handler: mux}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
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

// wgShowHandshakes returns the latest-handshakes table for wg0.
func wgShowHandshakes(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "wg", "show", "wg0", "latest-handshakes").Output()
	if err != nil {
		return "", fmt.Errorf("wg show wg0 latest-handshakes: %w", err)
	}
	return string(out), nil
}
