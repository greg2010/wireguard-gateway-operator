package link

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"
)

func TestReadKeyFile(t *testing.T) {
	const want = "QWERTYwireguardkeymaterial="

	tcs := []struct {
		name        string
		write       bool
		body        string
		wantKey     string
		wantErrSubs []string
	}{
		{
			name:    "trims_surrounding_whitespace",
			write:   true,
			body:    "  " + want + "\n\t",
			wantKey: want,
		},
		{
			name:        "missing_file_wraps_read_error",
			write:       false,
			wantErrSubs: []string{"read ", "does-not-exist"},
		},
		{
			name:        "empty_file_is_rejected",
			write:       true,
			body:        "",
			wantErrSubs: []string{"is empty"},
		},
		{
			name:        "whitespace_only_file_is_rejected",
			write:       true,
			body:        "   \n\t ",
			wantErrSubs: []string{"is empty"},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var path string
			if tc.write {
				path = filepath.Join(t.TempDir(), "key")
				if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
					t.Fatalf("write key file: %v", err)
				}
			} else {
				path = filepath.Join(t.TempDir(), "does-not-exist")
			}

			got, err := readKeyFile(path)
			if len(tc.wantErrSubs) > 0 {
				if err == nil {
					t.Fatalf("expected error containing %v, got nil (key %q)", tc.wantErrSubs, got)
				}
				for _, sub := range tc.wantErrSubs {
					if !strings.Contains(err.Error(), sub) {
						t.Errorf("error = %q, want substring %q", err.Error(), sub)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("readKeyFile: %v", err)
			}
			if got != tc.wantKey {
				t.Errorf("key = %q, want %q", got, tc.wantKey)
			}
		})
	}
}

// newHealthHandler builds the readiness handler with an injected wgShow and a fixed clock, marked
// leader so the handshake gate is exercised rather than short-circuited.
func newHealthHandler(now time.Time, showOut string, showErr error) http.HandlerFunc {
	rd := newReadiness("wg0", 25, func() time.Time { return now }, func(_ context.Context, _ string) (string, error) {
		return showOut, showErr
	})
	rd.setLeader(true)
	return rd.handler
}

func TestServeHealthHandler(t *testing.T) {
	now := time.Unix(1700001000, 0)

	tcs := []struct {
		name     string
		showOut  string
		showErr  error
		wantCode int
		wantBody string
	}{
		{
			name:     "ready_on_fresh_handshake",
			showOut:  fmt.Sprintf("PK=\t%d", now.Unix()-30),
			wantCode: http.StatusOK,
			wantBody: "ok",
		},
		{
			name:     "not_ready_on_stale_handshake",
			showOut:  fmt.Sprintf("PK=\t%d", now.Unix()-3600),
			wantCode: http.StatusServiceUnavailable,
			wantBody: "no recent handshake",
		},
		{
			name:     "not_ready_on_wg_show_error",
			showErr:  fmt.Errorf("wg0 does not exist"),
			wantCode: http.StatusServiceUnavailable,
			wantBody: "no recent handshake",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			handler := newHealthHandler(now, tc.showOut, tc.showErr)
			req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			rec := httptest.NewRecorder()

			handler(rec, req)

			if rec.Code != tc.wantCode {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantCode)
			}
			if got := rec.Body.String(); got != tc.wantBody {
				t.Errorf("body = %q, want %q", got, tc.wantBody)
			}
		})
	}
}

// TestServeHealthServesAndDrains confirms /healthz answers over the wire, then cancels and asserts
// a graceful nil return.
func TestServeHealthServesAndDrains(t *testing.T) {
	now := time.Unix(1700001000, 0)
	rd := newReadiness("wg0", 25, func() time.Time { return now }, func(_ context.Context, _ string) (string, error) {
		return fmt.Sprintf("PK=\t%d", now.Unix()-30), nil
	})
	rd.setLeader(true)

	addr := freeLoopbackAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveHealth(ctx, rd, nil, Config{HealthAddr: addr}, testLogger(t)) }()

	body := getHealthz(t, addr)
	if body != "ok" {
		t.Errorf("healthz body = %q, want ok", body)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serveHealth returned %v on cancel, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serveHealth did not return after cancel")
	}
}

func TestRunErrorPaths(t *testing.T) {
	validConfig := configJSON("203.0.113.5:51820", "web.default.svc")

	tcs := []struct {
		name string
		// configBody is written to ConfigPath; empty means point ConfigPath at a
		// missing file.
		configBody string
		// writePrivKey writes a private key file and points WGKeyPath at it; when
		// false, WGKeyPath points at a missing file.
		writePrivKey bool
		// writePeerKey writes a peer public key file and points PeerPubKeyPath at
		// it; when false, PeerPubKeyPath points at a missing file.
		writePeerKey bool
		wantErrSub   string
	}{
		{
			name:       "bad_config_path",
			configBody: "",
			wantErrSub: "load runtime config",
		},
		{
			name:         "missing_private_key",
			configBody:   validConfig,
			writePrivKey: false,
			wantErrSub:   "read wireguard private key",
		},
		{
			name:         "missing_peer_public_key",
			configBody:   validConfig,
			writePrivKey: true,
			writePeerKey: false,
			wantErrSub:   "read wireguard peer public key",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := Config{
				ConfigPath:     filepath.Join(dir, "missing-config.json"),
				WGKeyPath:      filepath.Join(dir, "missing-priv"),
				PeerPubKeyPath: filepath.Join(dir, "missing-peer"),
			}
			if tc.configBody != "" {
				cfg.ConfigPath = filepath.Join(dir, "config.json")
				writeConfig(t, cfg.ConfigPath, tc.configBody)
			}
			if tc.writePrivKey {
				cfg.WGKeyPath = filepath.Join(dir, "priv")
				writeConfig(t, cfg.WGKeyPath, "private-key-material=")
			}
			if tc.writePeerKey {
				cfg.PeerPubKeyPath = filepath.Join(dir, "peer")
				writeConfig(t, cfg.PeerPubKeyPath, "peer-pub-key-material=")
			}

			err := Run(context.Background(), cfg, testLogger(t))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErrSub)
			}
			if !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.wantErrSub)
			}
		})
	}
}

// TestRunRejectsLocalWithoutNodeName pins that Run fails fast, before touching the in-cluster
// client, when a Local-mode RuntimeConfig is loaded and cfg.NodeName is empty.
func TestRunRejectsLocalWithoutNodeName(t *testing.T) {
	dir := t.TempDir()
	body := `{"trafficPolicy":"Local","identity":{"id":3,"interface":"wg-gw3","nftTable":"gw3","mark":"0x00030000","markMask":"0xffff0000","routeTable":100003,"healthPort":27003},"podSelector":{"app":"gateway-link"},` +
		`"wireguard":{"address":"10.244.1.7/32","peer":{"endpoint":"203.0.113.5:51820","allowedIPs":["0.0.0.0/0"]}},` +
		`"forwards":[{"name":"web","publicPort":443,"protocol":"tcp","namespace":"default","serviceName":"web"}]}`

	cfg := Config{
		ConfigPath:     filepath.Join(dir, "config.json"),
		WGKeyPath:      filepath.Join(dir, "priv"),
		PeerPubKeyPath: filepath.Join(dir, "peer"),
	}
	writeConfig(t, cfg.ConfigPath, body)
	writeConfig(t, cfg.WGKeyPath, "priv-key-material=")
	writeConfig(t, cfg.PeerPubKeyPath, "peer-key-material=")

	err := Run(context.Background(), cfg, testLogger(t))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "NODE_NAME") {
		t.Errorf("error = %q, want substring %q", err.Error(), "NODE_NAME")
	}
}

// freeLoopbackAddr reserves an ephemeral loopback port and releases it. The brief gap before the
// server under test re-binds is acceptable for a single non-parallel loopback test.
func freeLoopbackAddr(t testing.TB) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback port: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("release loopback port: %v", err)
	}
	return addr
}

// getHealthz polls GET /healthz on addr until the server is listening, returning
// the body of the first successful response or failing on timeout.
func getHealthz(t testing.TB, addr string) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	url := "http://" + addr + "/healthz"
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err != nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		body := make([]byte, 64)
		n, _ := resp.Body.Read(body)
		resp.Body.Close()
		return string(body[:n])
	}
	t.Fatalf("GET %s never succeeded before deadline", url)
	return ""
}

// TestNewLocalEndpointWatcherMode pins the mode split of the watches: Local builds them, Cluster
// builds none and issues no discovery.k8s.io call, which it has no RBAC for.
func TestNewLocalEndpointWatcherMode(t *testing.T) {
	forwards := []Forward{{
		Name:        "web",
		PublicPort:  443,
		Protocol:    "tcp",
		Namespace:   "gw-ns",
		ServiceName: "web",
	}}
	podSelector := map[string]string{"app": "gateway-link"}

	tcs := []struct {
		name              string
		rc                RuntimeConfig
		wantWatcher       bool
		wantSliceRequests bool
		wantPodRequests   bool
	}{
		{
			name: "local_watches_endpointslices_and_pods",
			rc: RuntimeConfig{
				TrafficPolicy: TrafficPolicyLocal,
				Identity:      &Identity{ID: 1, Interface: "wg-gw1"},
				PodSelector:   podSelector,
				Forwards:      forwards,
			},
			wantWatcher:       true,
			wantSliceRequests: true,
			wantPodRequests:   true,
		},
		{
			name: "cluster_watches_nothing",
			rc: RuntimeConfig{
				TrafficPolicy: TrafficPolicyCluster,
				PodSelector:   podSelector,
				Forwards:      forwards,
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewClientset()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			cfg := Config{NodeName: "node-a", PodNamespace: "gw-ns"}
			ew, err := newLocalEndpointWatcher(ctx, cs, cfg, tc.rc, testLogger(t))
			if err != nil {
				t.Fatalf("newLocalEndpointWatcher: %v", err)
			}
			if (ew != nil) != tc.wantWatcher {
				t.Fatalf("watcher non-nil = %v, want %v", ew != nil, tc.wantWatcher)
			}

			requested := func(resource string) bool {
				for _, action := range cs.Actions() {
					if action.GetResource().Resource == resource {
						return true
					}
				}
				return false
			}
			// The EndpointSlice informers start without being waited on, so their
			// first list is reached rather than observed at once.
			if tc.wantSliceRequests {
				eventually(t, func() bool { return requested("endpointslices") }, "endpointslice request from the started informer")
			} else if requested("endpointslices") {
				t.Errorf("endpointslices requested in Cluster mode (actions: %v)", cs.Actions())
			}
			if got := requested("pods"); got != tc.wantPodRequests {
				t.Errorf("pods requests = %v, want %v (actions: %v)", got, tc.wantPodRequests, cs.Actions())
			}
		})
	}
}
