package crossplane

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/wait"
)

// keyfetchImage is pinned so the boot script proof runs against a known busybox/curl
// build; keyfetch.sh only needs a POSIX sh, curl and coreutils-level file tools.
const keyfetchImage = "alpine:3.20"

// keyfetchFixture is the metadata, token and Secret Manager backend for the real script.
// It binds 0.0.0.0 so the boot-script container can reach it through the Docker bridge.
type keyfetchFixture struct {
	srv *httptest.Server

	mu        sync.Mutex
	smPaths   []string
	smAttempt int
}

// newKeyfetchFixture serves metadata, a fixed OAuth token and Secret Manager responses.
// smHandler receives each Secret Manager request with a 1-indexed attempt counter.
func newKeyfetchFixture(t *testing.T, attrs map[string]string, instanceName string, smHandler func(attempt int) (status int, body string)) *keyfetchFixture {
	t.Helper()

	f := &keyfetchFixture{}
	mux := http.NewServeMux()
	for attr, value := range attrs {
		mux.HandleFunc("/attributes/"+attr, func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, value)
		})
	}
	mux.HandleFunc("/name", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, instanceName)
	})
	mux.HandleFunc("/service-accounts/default/token", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"access_token":"test-access-token","expires_in":3600,"token_type":"Bearer"}`)
	})
	mux.HandleFunc("/v1/projects/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.smAttempt++
		attempt := f.smAttempt
		f.smPaths = append(f.smPaths, r.URL.Path)
		f.mu.Unlock()

		status, body := smHandler(attempt)
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	})

	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listen for keyfetch fixture: %v", err)
	}
	f.srv = httptest.NewUnstartedServer(mux)
	if cerr := f.srv.Listener.Close(); cerr != nil {
		t.Fatalf("close default fixture listener: %v", cerr)
	}
	f.srv.Listener = listener
	f.srv.Start()
	t.Cleanup(f.srv.Close)
	return f
}

// smRequestPaths returns every Secret Manager access path requested so far, in order.
func (f *keyfetchFixture) smRequestPaths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.smPaths)
}

// baseURL is the fixture's address as seen from inside the boot-script container,
// reached through the Docker bridge's host-gateway alias.
func (f *keyfetchFixture) baseURL(t testing.TB) string {
	t.Helper()
	_, port, err := net.SplitHostPort(f.srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split keyfetch fixture address: %v", err)
	}
	return "http://host.docker.internal:" + port
}

// smSuccessBody wraps bundleJSON the way Secret Manager's versions.access response does:
// a base64 payload under "data".
func smSuccessBody(bundleJSON string) string {
	return fmt.Sprintf(`{"name":"projects/p/secrets/s/versions/1","payload":{"data":"%s"}}`, base64.StdEncoding.EncodeToString([]byte(bundleJSON)))
}

// defaultKeyfetchAttrs is the metadata attribute set every case shares except the
// secret-id, which the derivation cases vary.
func defaultKeyfetchAttrs(projectID, secretID string) map[string]string {
	return map[string]string{
		"wg-listen-port":  "51820",
		"wg-mtu":          "1420",
		"wg-link-address": "10.99.0.2",
		"traffic-policy":  "local",
		"project-id":      projectID,
		"secret-id":       secretID,
	}
}

// startKeyfetchContainer provides curl, the systemd-network group and real chart scripts.
// write_netdev needs the group to chown its output.
func startKeyfetchContainer(t *testing.T) testcontainers.Container {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:      keyfetchImage,
			Entrypoint: []string{"sleep", "infinity"},
			Labels:     map[string]string{"gateway.test": "integration"},
			HostConfigModifier: func(hc *container.HostConfig) {
				hc.ExtraHosts = append(hc.ExtraHosts, "host.docker.internal:host-gateway")
			},
			WaitingFor: wait.ForExec([]string{"true"}).WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	if ctr != nil {
		t.Cleanup(func() {
			if terr := ctr.Terminate(context.Background()); terr != nil {
				t.Logf("terminate keyfetch container: %v", terr)
			}
		})
	}
	if err != nil {
		t.Fatalf("start keyfetch container: %v", err)
	}

	setup := [][]string{
		{"apk", "add", "--no-cache", "curl"},
		{"addgroup", "systemd-network"},
		{"mkdir", "-p", "/etc/systemd/network", "/etc/nftables", "/opt/gateway", "/usr/local/bin"},
		{"sh", "-c", "printf '#!/bin/sh\necho \"$0 $*\" >> /tmp/keyfetch-invocations\n' > /usr/local/bin/systemctl && cp /usr/local/bin/systemctl /usr/local/bin/ip && chmod +x /usr/local/bin/systemctl /usr/local/bin/ip"},
	}
	for _, cmd := range setup {
		if code, out := keyfetchExec(ctx, t, ctr, cmd...); code != 0 {
			t.Fatalf("%v failed (exit %d):\n%s", cmd, code, out)
		}
	}

	script := readChartFile(t, "files/gcp/keyfetch.sh")
	if err := ctr.CopyToContainer(ctx, []byte(script), "/opt/gateway/keyfetch.sh", 0o755); err != nil {
		t.Fatalf("copy keyfetch.sh to container: %v", err)
	}
	nft := readChartFile(t, "files/gcp/gateway.nft")
	if err := ctr.CopyToContainer(ctx, []byte(nft), "/etc/nftables/gateway.nft", 0o644); err != nil {
		t.Fatalf("copy gateway.nft to container: %v", err)
	}
	return ctr
}

// keyfetchExec runs cmd in ctr and returns its exit code and combined output.
func keyfetchExec(ctx context.Context, t *testing.T, ctr testcontainers.Container, cmd ...string) (int, string) {
	t.Helper()
	code, reader, err := ctr.Exec(ctx, cmd, tcexec.Multiplexed())
	if err != nil {
		t.Fatalf("exec %v: %v", cmd, err)
	}
	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read output of %v: %v", cmd, err)
	}
	return code, string(out)
}

// keyfetchFile reads path back from ctr, reporting presence separately from content so
// a case can assert a file was never written without treating a read error as one.
func keyfetchFile(ctx context.Context, t *testing.T, ctr testcontainers.Container, path string) (content string, present bool) {
	t.Helper()
	code, out := keyfetchExec(ctx, t, ctr, "cat", path)
	if code != 0 {
		return "", false
	}
	return out, true
}

// runKeyfetchScript uses busybox timeout so an unconverged script returns its poll output.
// The exec context allows time to collect that output.
func runKeyfetchScript(ctx context.Context, t *testing.T, ctr testcontainers.Container, fx *keyfetchFixture, budgetSeconds int) string {
	t.Helper()
	base := fx.baseURL(t)
	cmd := []string{"sh", "-c", fmt.Sprintf(
		"GATEWAY_KEYFETCH_METADATA_BASE=%s GATEWAY_KEYFETCH_SECRETMANAGER_BASE=%s timeout %d sh /opt/gateway/keyfetch.sh 2>&1; echo KEYFETCH_EXIT=$?",
		base, base, budgetSeconds,
	)}
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(budgetSeconds+20)*time.Second)
	defer cancel()
	_, out := keyfetchExec(runCtx, t, ctr, cmd...)
	return out
}

// resetKeyfetchOutputs clears the two files a converged run writes, so cases sharing a
// container start from the same observed absence.
func resetKeyfetchOutputs(ctx context.Context, t *testing.T, ctr testcontainers.Container) {
	t.Helper()
	if code, out := keyfetchExec(ctx, t, ctr, "rm", "-f", "/etc/systemd/network/10-wg0.netdev", "/etc/systemd/network/20-wg0.network", "/tmp/keyfetch-invocations"); code != 0 {
		t.Fatalf("reset keyfetch outputs failed (exit %d):\n%s", code, out)
	}
}

// TestKeyfetchExecutesRealScript exercises the shipped script against metadata and Secret Manager.
// It verifies bootstrap behavior instead of a Go reimplementation.
func TestKeyfetchExecutesRealScript(t *testing.T) {
	if os.Getenv("GATEWAY_INTEGRATION") == "" {
		t.Skip("set GATEWAY_INTEGRATION to run the keyfetch script-execution integration test")
	}
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	ctr := startKeyfetchContainer(t)

	bundleFields := func(privateKey, address, slot, peerPublicKey, peerAllowedIPs string) string {
		var b strings.Builder
		b.WriteByte('{')
		first := true
		add := func(key, value string) {
			if value == "" {
				return
			}
			if !first {
				b.WriteByte(',')
			}
			first = false
			fmt.Fprintf(&b, "%q:%q", key, value)
		}
		add("privateKey", privateKey)
		add("address", address)
		add("slot", slot)
		add("peerPublicKey", peerPublicKey)
		add("peerAllowedIPs", peerAllowedIPs)
		b.WriteByte('}')
		return b.String()
	}

	validBundle := bundleFields("priv-key-abc", "10.99.0.3/29", "1", "peer-pub-xyz", "10.99.0.2/32")
	malformedBundle := bundleFields("priv-key-abc", "", "1", "peer-pub-xyz", "10.99.0.2/32")

	for _, tc := range []struct {
		name          string
		projectID     string
		secretID      string
		instanceName  string
		smHandler     func(attempt int) (int, string)
		budgetSeconds int
		check         func(t *testing.T, out string, fx *keyfetchFixture)
	}{
		{
			name:         "derives_bundle_id_from_own_name",
			projectID:    "wgnet-test-project",
			secretID:     "gw-x-p",
			instanceName: "gw-vm-a1b2",
			smHandler: func(_ int) (int, string) {
				return http.StatusOK, smSuccessBody(validBundle)
			},
			budgetSeconds: 8,
			check: func(t *testing.T, out string, fx *keyfetchFixture) {
				if !strings.Contains(out, "slot=1") {
					t.Errorf("keyfetch output does not report bundle slot:\n%s", out)
				}
				want := "/secrets/gw-x-p-gw-vm-a1b2/versions/latest:access"
				got := fx.smRequestPaths()
				if !slices.ContainsFunc(got, func(p string) bool { return strings.HasSuffix(p, want) }) {
					t.Errorf("Secret Manager requests %v do not contain a path ending %q:\n%s", got, want, out)
				}
			},
		},
		{
			name:         "writes_netdev_from_bundle_fields",
			projectID:    "wgnet-test-project",
			secretID:     "gw-y-q",
			instanceName: "gw-vm-c3d4",
			smHandler: func(_ int) (int, string) {
				return http.StatusOK, smSuccessBody(validBundle)
			},
			budgetSeconds: 8,
			check: func(t *testing.T, out string, _ *keyfetchFixture) {
				netdev, ok := keyfetchFile(ctx, t, ctr, "/etc/systemd/network/10-wg0.netdev")
				if !ok {
					t.Fatalf("10-wg0.netdev was not written:\n%s", out)
				}
				for _, want := range []string{"PrivateKey=priv-key-abc", "[WireGuardPeer]", "PublicKey=peer-pub-xyz", "AllowedIPs=10.99.0.2/32"} {
					if !strings.Contains(netdev, want) {
						t.Errorf("10-wg0.netdev does not contain %q:\n%s", want, netdev)
					}
				}
				network, ok := keyfetchFile(ctx, t, ctr, "/etc/systemd/network/20-wg0.network")
				if !ok {
					t.Fatalf("20-wg0.network was not written:\n%s", out)
				}
				if !strings.Contains(network, "Address=10.99.0.3/29") {
					t.Errorf("20-wg0.network does not contain %q:\n%s", "Address=10.99.0.3/29", network)
				}
			},
		},
		{
			name:         "malformed_bundle_retries_writes_nothing",
			projectID:    "wgnet-test-project",
			secretID:     "gw-z-r",
			instanceName: "gw-vm-e5f6",
			smHandler: func(_ int) (int, string) {
				return http.StatusOK, smSuccessBody(malformedBundle)
			},
			budgetSeconds: 13,
			check: func(t *testing.T, out string, fx *keyfetchFixture) {
				code, listing := keyfetchExec(ctx, t, ctr, "sh", "-c", "ls -1A /etc/systemd/network")
				if code != 0 {
					t.Fatalf("list systemd network directory failed (exit %d):\n%s", code, listing)
				}
				if got, want := strings.Fields(listing), []string{}; !slices.Equal(got, want) {
					t.Errorf("systemd network directory = %v, want %v", got, want)
				}
				wantPaths := []string{
					"/v1/projects/wgnet-test-project/secrets/gw-z-r-gw-vm-e5f6/versions/latest:access",
					"/v1/projects/wgnet-test-project/secrets/gw-z-r-gw-vm-e5f6/versions/latest:access",
					"/v1/projects/wgnet-test-project/secrets/gw-z-r-gw-vm-e5f6/versions/latest:access",
				}
				if got := fx.smRequestPaths(); !slices.Equal(got, wantPaths) {
					t.Errorf("Secret Manager request paths = %v, want %v:\n%s", got, wantPaths, out)
				}
			},
		},
		{
			name:         "tolerates_403_then_200",
			projectID:    "wgnet-test-project",
			secretID:     "gw-a-s",
			instanceName: "gw-vm-g7h8",
			smHandler: func(attempt int) (int, string) {
				if attempt <= 2 {
					return http.StatusForbidden, `{"error":{"code":403,"message":"forbidden"}}`
				}
				return http.StatusOK, smSuccessBody(validBundle)
			},
			budgetSeconds: 20,
			check: func(t *testing.T, out string, _ *keyfetchFixture) {
				netdev, ok := keyfetchFile(ctx, t, ctr, "/etc/systemd/network/10-wg0.netdev")
				if !ok {
					t.Fatalf("10-wg0.netdev was not written after Secret Manager recovered from 403:\n%s", out)
				}
				if !strings.Contains(netdev, "PrivateKey=priv-key-abc") {
					t.Errorf("10-wg0.netdev does not contain %q:\n%s", "PrivateKey=priv-key-abc", netdev)
				}
			},
		},
		{
			name:         "tolerates_404_then_200",
			projectID:    "wgnet-test-project",
			secretID:     "gw-b-t",
			instanceName: "gw-vm-i9j0",
			smHandler: func(attempt int) (int, string) {
				if attempt <= 2 {
					return http.StatusNotFound, `{"error":{"code":404,"message":"not found"}}`
				}
				return http.StatusOK, smSuccessBody(validBundle)
			},
			budgetSeconds: 20,
			check: func(t *testing.T, out string, _ *keyfetchFixture) {
				netdev, ok := keyfetchFile(ctx, t, ctr, "/etc/systemd/network/10-wg0.netdev")
				if !ok {
					t.Fatalf("10-wg0.netdev was not written after Secret Manager recovered from 404:\n%s", out)
				}
				if !strings.Contains(netdev, "PrivateKey=priv-key-abc") {
					t.Errorf("10-wg0.netdev does not contain %q:\n%s", "PrivateKey=priv-key-abc", netdev)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetKeyfetchOutputs(ctx, t, ctr)
			fx := newKeyfetchFixture(t, defaultKeyfetchAttrs(tc.projectID, tc.secretID), tc.instanceName, tc.smHandler)
			out := runKeyfetchScript(ctx, t, ctr, fx, tc.budgetSeconds)
			tc.check(t, out, fx)
			if tc.name != "malformed_bundle_retries_writes_nothing" {
				if !strings.Contains(out, "KEYFETCH_EXIT=0") {
					t.Errorf("keyfetch exit status is not zero:\n%s", out)
				}
				invocations, _ := keyfetchFile(ctx, t, ctr, "/tmp/keyfetch-invocations")
				if got, want := strings.Fields(invocations), []string{"/usr/local/bin/systemctl", "restart", "systemd-networkd", "/usr/local/bin/ip", "link", "show", "wg0"}; !slices.Equal(got, want) {
					t.Errorf("stub invocations = %v, want %v", got, want)
				}
			}
		})
	}
}
