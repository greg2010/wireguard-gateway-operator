package link

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

// shutdownTimeout bounds the graceful drain of the health server on cancel.
const shutdownTimeout = 5 * time.Second

// Run loads the runtime config and key material, then runs two concurrent
// loops until ctx is cancelled: a reconcile loop that tracks the gateway's
// endpoint from XGateway.status.address and (re-)applies the WireGuard and
// nftables configuration whenever the IP appears or changes, and the readiness
// HTTP server. Config load, key reads, and in-cluster client construction are
// fatal and returned before the loops start. The reconcile loop is non-fatal on
// transient read or apply failures: it logs and retries, so the process does not
// exit merely because the address is not yet observed. The wg0 address and the
// port forwards remain ConfigMap-driven and restart-on-config; only the peer
// endpoint is reconciled live. The health server is drained gracefully on cancel.
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
		return fmt.Errorf("load in-cluster config: %w", err)
	}
	dyn, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("build dynamic client: %w", err)
	}

	readIP := func(ctx context.Context) (string, error) {
		return readGatewayIP(ctx, dyn, cfg.GatewayName, cfg.GatewayNamespace)
	}

	rd := newReadiness(rc.WireGuard.Peer.PersistentKeepalive, time.Now, wgShowHandshakes)

	apply := func(ctx context.Context, rc RuntimeConfig, privKey, peerPubKey string) error {
		return Apply(ctx, rc, privKey, peerPubKey, defaultResolve)
	}

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return reconcile(gctx, rc, privKey, peerPubKey, readIP,
			cfg.WGListenPort, cfg.ReconcileInterval, apply, log)
	})
	g.Go(func() error {
		return serveHealth(gctx, cfg.HealthAddr, rd)
	})
	return g.Wait()
}

// readKeyFile reads a WireGuard key from path, trimming surrounding whitespace,
// and rejects an empty result so a blank or absent mounted Secret fails fast
// rather than producing an invalid wg config.
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
