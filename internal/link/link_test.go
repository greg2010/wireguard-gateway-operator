package link

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.uber.org/zap"
	"time"

	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
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

// newHealthHandler builds a leader/applied readiness handler with a fixed clock and injected
// wgShow result. Local selects one applied slot; peers sets the reported peer count.
func newHealthHandler(local bool, peers int, now time.Time, showOut string, showErr error) http.HandlerFunc {
	rd := newReadiness(local, 3, func() time.Time { return now }, func(_ context.Context, _ string) (string, error) {
		return showOut, showErr
	}, zap.NewNop().Sugar())
	rd.setLeader(true)
	var slots []SlotResult
	if local {
		slots = singleSlotApplied
	}
	rd.setPass(slots, peers, 25, true)
	return rd.handler
}

func TestServeHealthHandler(t *testing.T) {
	now := time.Unix(1700001000, 0)

	tcs := []struct {
		name     string
		local    bool
		peers    int
		showOut  string
		showErr  error
		wantCode int
		wantBody string
	}{
		{
			name:     "local_ready_on_fresh_handshake",
			local:    true,
			peers:    1,
			showOut:  fmt.Sprintf("PK=\t%d", now.Unix()-30),
			wantCode: http.StatusOK,
			wantBody: "ok",
		},
		{
			name:     "local_not_ready_on_stale_handshake",
			local:    true,
			peers:    1,
			showOut:  fmt.Sprintf("PK=\t%d", now.Unix()-3600),
			wantCode: http.StatusServiceUnavailable,
			wantBody: "no recent handshake",
		},
		{
			name:     "local_not_ready_on_wg_show_error",
			local:    true,
			peers:    1,
			showErr:  fmt.Errorf("wg0 does not exist"),
			wantCode: http.StatusServiceUnavailable,
			wantBody: "no recent handshake",
		},
		{
			name:     "cluster_ready_on_fresh_handshake",
			peers:    1,
			showOut:  fmt.Sprintf("PK=\t%d", now.Unix()-30),
			wantCode: http.StatusOK,
			wantBody: "ok",
		},
		{
			name:     "cluster_not_ready_on_stale_handshake",
			peers:    1,
			showOut:  fmt.Sprintf("PK=\t%d", now.Unix()-3600),
			wantCode: http.StatusServiceUnavailable,
			wantBody: "no recent handshake",
		},
		{
			name:     "cluster_not_ready_without_a_configured_peer",
			peers:    0,
			showOut:  fmt.Sprintf("PK=\t%d", now.Unix()-30),
			wantCode: http.StatusServiceUnavailable,
			wantBody: "no peers configured",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			handler := newHealthHandler(tc.local, tc.peers, now, tc.showOut, tc.showErr)
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

// TestServeHealthServesAndDrains confirms /healthz answers over the wire, then cancels and
// asserts a graceful nil return.
func TestServeHealthServesAndDrains(t *testing.T) {
	now := time.Unix(1700001000, 0)
	rd := newReadiness(true, 3, func() time.Time { return now }, func(_ context.Context, _ string) (string, error) {
		return fmt.Sprintf("PK=\t%d", now.Unix()-30), nil
	}, testLogger(t))
	rd.setLeader(true)
	rd.setPass(singleSlotApplied, 1, 25, true)

	addr := freeLoopbackAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveHealth(ctx, rd, nil, Config{HealthAddr: addr}, testLogger(t)) }()

	body := getBody(t, addr, "/healthz")
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
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := Config{
				ConfigPath: filepath.Join(dir, "missing-config.json"),
				WGKeyPath:  filepath.Join(dir, "missing-priv"),
			}
			if tc.configBody != "" {
				cfg.ConfigPath = filepath.Join(dir, "config.json")
				writeConfig(t, cfg.ConfigPath, tc.configBody)
			}
			if tc.writePrivKey {
				cfg.WGKeyPath = filepath.Join(dir, "priv")
				writeConfig(t, cfg.WGKeyPath, "private-key-material=")
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
	body := `{"trafficPolicy":"Local","healthPort":27003,"identity":{"id":3,"nftTable":"gw3","healthPort":27003},"podSelector":{"app":"gateway-link"},` +
		`"wireguard":{"address":"10.244.1.7/32","peers":[{"slot":0,"publicKey":"PUB=","endpoint":"203.0.113.5:51820","allowedIPs":["0.0.0.0/0"]}]},` +
		`"forwards":[{"name":"web","publicPort":443,"protocol":"tcp","namespace":"default","serviceName":"web"}]}`

	cfg := Config{
		ConfigPath: filepath.Join(dir, "config.json"),
		WGKeyPath:  filepath.Join(dir, "priv"),
	}
	writeConfig(t, cfg.ConfigPath, body)
	writeConfig(t, cfg.WGKeyPath, "priv-key-material=")

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

// getBody polls GET path on addr until the server is listening, returning
// the body of the first successful response or failing on timeout.
func getBody(t testing.TB, addr, path string) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	url := "http://" + addr + path
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err != nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		body, readErr := io.ReadAll(resp.Body)
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close the %s response body: %v", url, closeErr)
		}
		if readErr != nil {
			t.Fatalf("read the %s response body: %v", url, readErr)
		}
		return string(body)
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
	gwIdent := NewGatewayIdentity(1)

	tcs := []struct {
		name        string
		rc          RuntimeConfig
		wantWatcher bool
		// wantResources is every resource the mode's watches request. Cluster mode builds no
		// watcher, so its whole action list is compared against it instead.
		wantResources []string
	}{
		{
			name: "local_watches_endpointslices_and_pods",
			rc: RuntimeConfig{
				TrafficPolicy: TrafficPolicyLocal,
				Identity:      &gwIdent,
				PodSelector:   podSelector,
				Forwards:      forwards,
			},
			wantWatcher:   true,
			wantResources: []string{"endpointslices", "pods"},
		},
		{
			name: "cluster_watches_nothing",
			rc: RuntimeConfig{
				TrafficPolicy: TrafficPolicyCluster,
				PodSelector:   podSelector,
				Forwards:      forwards,
			},
			wantResources: []string{},
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

			if !tc.wantWatcher {
				if got := actionResources(cs.Actions()); !slices.Equal(got, tc.wantResources) {
					t.Errorf("client actions = %v, want %v", got, tc.wantResources)
				}
				return
			}
			// The informers start without being waited on, so their first list is
			// reached rather than observed at once.
			for _, resource := range tc.wantResources {
				eventually(t, func() bool { return slices.Contains(actionResources(cs.Actions()), resource) },
					resource+" request from the started informer")
			}
		})
	}
}

// actionResources is the resource each client action requested, in order.
func actionResources(actions []k8stesting.Action) []string {
	resources := make([]string, 0, len(actions))
	for _, action := range actions {
		resources = append(resources, action.GetResource().Resource)
	}
	return resources
}
