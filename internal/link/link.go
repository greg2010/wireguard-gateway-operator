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
)

// shutdownTimeout bounds the graceful drain of the health server on cancel.
const shutdownTimeout = 5 * time.Second

// Run loads the runtime config and key material, then runs two concurrent loops
// until ctx is cancelled: a reload loop that applies the WireGuard and nftables
// configuration and re-applies it in place whenever the mounted ConfigMap
// changes, and the readiness HTTP server. Config load and key reads are fatal and
// returned before the loops start. The reload loop is non-fatal on transient load
// or apply failures: it logs and retries, so the process does not exit merely
// because the peer endpoint is not yet present in the config. The peer endpoint
// is supplied by the operator in the ConfigMap; the link holds no cluster
// credentials. The health server is drained gracefully on cancel.
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

	rd := newReadiness(rc.WireGuard.Peer.PersistentKeepalive, time.Now, wgShowHandshakes)

	resolve := newResolver(net.DefaultResolver.LookupIP)

	// Reconcile in place once wg0 exists so an established handshake and in-flight
	// connections survive a config change.
	reconcile := func(ctx context.Context, rc RuntimeConfig, privKey, peerPubKey string) error {
		if wg0Exists(ctx, execCommand) {
			return Reconcile(ctx, execCommand, rc, privKey, peerPubKey, resolve)
		}
		return Apply(ctx, execCommand, rc, privKey, peerPubKey, resolve)
	}

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return watchAndReload(gctx, cfg, privKey, peerPubKey, reconcile, log)
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
