package linkint

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/greg2010/wireguard-gateway-operator/internal/link"
	"github.com/moby/moby/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// A three-netns topology forwards traffic through wg0 to a separate cluster netns
// so the accept rules are exercised, not bypassed by local delivery.

const (
	// dpRetargetPort is the public port the forward exposes on wg0.
	dpRetargetPort = 8453
	// dpTargetPort is the backend port both stand-in Services listen on.
	dpTargetPort = 443
	// dpClusterIPA and dpClusterIPB are the stand-in ClusterIPs the forward is
	// retargeted between; both are reachable in the cluster netns.
	dpClusterIPA = "10.96.0.10"
	dpClusterIPB = "10.96.0.20"
	// dpMarkerA and dpMarkerB are the per-backend response markers, so a probe's
	// reply identifies which backend served it.
	dpMarkerA = "AAAA"
	dpMarkerB = "BBBB"
	// dpProbeTimeout bounds a single in-container probe attempt.
	dpProbeTimeout = 5 * time.Second
)

// TestNftablesRetargetDataPathFollowsClusterIP asserts the data path follows a
// retargeted ClusterIP: a fresh pre-retarget flow reaches A, an established flow
// stays pinned to A, and a fresh post-retarget flow reaches B.
func TestNftablesRetargetDataPathFollowsClusterIP(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	ctr := startDataPathContainer(ctx, t)

	forwardA := link.ResolvedForward{Name: "retarget", PublicPort: dpRetargetPort, Protocol: "tcp", ClusterIP: dpClusterIPA, TargetPort: dpTargetPort}
	forwardB := link.ResolvedForward{Name: "retarget", PublicPort: dpRetargetPort, Protocol: "tcp", ClusterIP: dpClusterIPB, TargetPort: dpTargetPort}

	applyRuleset(ctx, t, ctr, renderRuleset(t, []link.ResolvedForward{forwardA}))

	if got := probeOnce(ctx, t, ctr); got != dpMarkerA {
		t.Fatalf("before retarget: fresh probe = %q, want %q (DNAT to A not working)", got, dpMarkerA)
	}

	held := openHeldConnection(ctx, t, ctr)
	defer held.close(t)
	if got := held.request(ctx, t); got != dpMarkerA {
		t.Fatalf("before retarget: held connection = %q, want %q", got, dpMarkerA)
	}

	applyRuleset(ctx, t, ctr, renderRuleset(t, []link.ResolvedForward{forwardB}))

	reused := held.request(ctx, t)
	if reused == "" {
		t.Errorf("after retarget: reused established connection blackholed (no reply); the leading ct established,related accept should keep it flowing to A")
	} else if reused != dpMarkerA {
		t.Errorf("after retarget: reused established connection = %q, want %q (an established flow is conntrack-pinned to A, not re-DNATed)", reused, dpMarkerA)
	}

	if got := probeOnce(ctx, t, ctr); got != dpMarkerB {
		t.Errorf("after retarget: fresh probe = %q, want %q (a new connection must re-evaluate DNAT to B)", got, dpMarkerB)
	}
}

// startDataPathContainer brings up the three-netns topology with a wg0 veth peer,
// unlike startNftContainer whose dummy wg0 cannot carry forwarded traffic.
func startDataPathContainer(ctx context.Context, t testing.TB) testcontainers.Container {
	t.Helper()

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:      nftImage,
			Entrypoint: []string{"sleep", "infinity"},
			Labels:     map[string]string{"gateway.test": "integration"},
			HostConfigModifier: func(hc *container.HostConfig) {
				hc.CapAdd = append(hc.CapAdd, "NET_ADMIN")
				hc.Privileged = true
			},
			WaitingFor: wait.ForExec([]string{"true"}).WithStartupTimeout(containerStartTimeout),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start data-path container: %v", err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(context.Background()) })

	installDataPathPackages(ctx, t, ctr)
	setupTopology(ctx, t, ctr)
	startBackends(ctx, t, ctr)
	return ctr
}

// installDataPathPackages adds nft, the ip tooling, and python3 (the listeners
// and probes). An apk failure is a real environment failure, not a skip.
func installDataPathPackages(ctx context.Context, t testing.TB, ctr testcontainers.Container) {
	t.Helper()
	code, out := execInContainer(ctx, t, ctr, "apk", "add", "--no-cache", "nftables", "iproute2", "python3")
	if code != 0 {
		t.Fatalf("apk add nftables iproute2 python3 failed (exit %d):\n%s", code, out)
	}
}

// topologyScript builds the client/gateway/cluster netns plumbing: wg0 is the
// gateway end of the client veth, and the stand-in ClusterIPs live behind a second
// veth in the cluster netns so DNAT'd packets are forwarded, not delivered locally.
const topologyScript = `set -e
ip netns add client
ip link add vc-gw type veth peer name wg0
ip link set vc-gw netns client
ip addr add 10.99.0.2/24 dev wg0
ip link set wg0 up
ip netns exec client ip addr add 10.99.0.1/24 dev vc-gw
ip netns exec client ip link set vc-gw up
ip netns exec client ip link set lo up
ip netns exec client ip route add default via 10.99.0.2

ip netns add cluster
ip link add vs-gw type veth peer name vs-cl
ip link set vs-cl netns cluster
ip addr add 10.96.0.1/24 dev vs-gw
ip link set vs-gw up
ip netns exec cluster ip link set vs-cl up
ip netns exec cluster ip link set lo up
ip netns exec cluster ip addr add 10.96.0.2/24 dev vs-cl
ip netns exec cluster ip addr add 10.96.0.10/32 dev vs-cl
ip netns exec cluster ip addr add 10.96.0.20/32 dev vs-cl
ip netns exec cluster ip route add default via 10.96.0.1

ip route add 10.96.0.10/32 dev vs-gw
ip route add 10.96.0.20/32 dev vs-gw
sysctl -w net.ipv4.ip_forward=1
`

// setupTopology runs topologyScript in the container.
func setupTopology(ctx context.Context, t testing.TB, ctr testcontainers.Container) {
	t.Helper()
	code, out := execInContainer(ctx, t, ctr, "sh", "-c", topologyScript)
	if code != 0 {
		t.Fatalf("set up netns topology (exit %d):\n%s", code, out)
	}
}

// backendScript is a line-oriented TCP server bound to one ClusterIP that replies
// with its marker on every read and keeps the connection open, so a single
// connection can carry multiple requests (the reuse the test depends on).
const backendScript = `import socket, sys
ip = sys.argv[1]
marker = sys.argv[2]
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((ip, 443))
srv.listen(16)
while True:
    conn, _ = srv.accept()
    while True:
        data = conn.recv(64)
        if not data:
            break
        conn.sendall((marker + "\n").encode())
    conn.close()
`

// startBackends launches the two marker servers in the cluster netns and waits
// for both to listen, so the first probe does not race bind.
func startBackends(ctx context.Context, t testing.TB, ctr testcontainers.Container) {
	t.Helper()
	if err := ctr.CopyToContainer(ctx, []byte(backendScript), "/tmp/backend.py", 0o644); err != nil {
		t.Fatalf("copy backend script: %v", err)
	}
	for _, b := range []struct{ ip, marker string }{{dpClusterIPA, dpMarkerA}, {dpClusterIPB, dpMarkerB}} {
		cmd := fmt.Sprintf("ip netns exec cluster python3 /tmp/backend.py %s %s &", b.ip, b.marker)
		if code, out := execInContainer(ctx, t, ctr, "sh", "-c", cmd); code != 0 {
			t.Fatalf("start backend %s (exit %d):\n%s", b.ip, code, out)
		}
	}
	waitClusterListening(ctx, t, ctr)
}

// waitClusterListening polls until both ClusterIP:port listeners are up in the
// cluster netns, failing if neither appears before the deadline.
func waitClusterListening(ctx context.Context, t testing.TB, ctr testcontainers.Container) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	want := fmt.Sprintf(":%d", dpTargetPort)
	for time.Now().Before(deadline) {
		code, out := execInContainer(ctx, t, ctr, "ip", "netns", "exec", "cluster", "ss", "-ltn")
		if code == 0 && strings.Count(out, want) >= 2 {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("cluster backends did not start listening on port %d within deadline", dpTargetPort)
}

// probeScript dials a fresh connection from the client netns, sends one request,
// and prints the reply prefixed GOT: (or ERR: on failure). The fresh connection
// forces a prerouting DNAT re-evaluation, like the e2e probe's per-poll dial.
const probeScript = `import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(float(sys.argv[3]))
try:
    s.connect((sys.argv[1], int(sys.argv[2])))
    s.sendall(b"r\n")
    print("GOT:" + s.recv(64).decode(errors="replace").strip())
except Exception as e:
    print("ERR:" + repr(e))
finally:
    s.close()
`

// probeOnce dials a fresh connection through the gateway and returns the backend
// marker, or "" if the probe failed (a blackhole or refusal).
func probeOnce(ctx context.Context, t testing.TB, ctr testcontainers.Container) string {
	t.Helper()
	if err := ctr.CopyToContainer(ctx, []byte(probeScript), "/tmp/probe.py", 0o644); err != nil {
		t.Fatalf("copy probe script: %v", err)
	}
	secs := fmt.Sprintf("%.0f", dpProbeTimeout.Seconds())
	cmd := fmt.Sprintf("ip netns exec client python3 /tmp/probe.py 10.99.0.2 %d %s", dpRetargetPort, secs)
	code, out := execInContainer(ctx, t, ctr, "sh", "-c", cmd)
	if code != 0 {
		t.Fatalf("probe exec failed (exit %d):\n%s", code, out)
	}
	return parseMarker(out)
}

// heldConnection is a client connection kept open across a retarget so the test can
// observe whether conntrack pins the flow to the old target. It is driven through
// the filesystem via a generation counter and per-generation reply files.
type heldConnection struct {
	ctr testcontainers.Container
	gen int
}

// heldScript opens one connection, then on each generation bump sends a request on
// the held socket and writes the reply to /tmp/held_reply.<gen>. Keeping the socket
// open between requests is what makes the flow ESTABLISHED across the retarget.
const heldScript = `import socket, os, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(("10.99.0.2", 8453))
last = 0
while True:
    try:
        with open("/tmp/held_gen") as f:
            gen = int(f.read().strip() or "0")
    except (FileNotFoundError, ValueError):
        gen = 0
    if gen <= last:
        time.sleep(0.05)
        continue
    last = gen
    try:
        s.sendall(b"r\n")
        reply = s.recv(64).decode(errors="replace").strip()
    except Exception as e:
        reply = "ERR:" + repr(e)
    tmp = "/tmp/held_reply.%d.tmp" % gen
    with open(tmp, "w") as f:
        f.write(reply + "\n")
    os.rename(tmp, "/tmp/held_reply.%d" % gen)
`

// openHeldConnection starts the held-connection server in the client netns and
// returns a handle once the connection is established.
func openHeldConnection(ctx context.Context, t testing.TB, ctr testcontainers.Container) *heldConnection {
	t.Helper()
	if code, out := execInContainer(ctx, t, ctr, "sh", "-c", "echo 0 > /tmp/held_gen"); code != 0 {
		t.Fatalf("init generation file (exit %d):\n%s", code, out)
	}
	if err := ctr.CopyToContainer(ctx, []byte(heldScript), "/tmp/held.py", 0o644); err != nil {
		t.Fatalf("copy held script: %v", err)
	}
	if code, out := execInContainer(ctx, t, ctr, "sh", "-c", "ip netns exec client python3 /tmp/held.py &"); code != 0 {
		t.Fatalf("start held connection (exit %d):\n%s", code, out)
	}
	h := &heldConnection{ctr: ctr}
	h.waitConnected(ctx, t)
	return h
}

// waitConnected polls the client netns until the held connection appears as an
// established socket to the public port, so request does not race the connect.
func (h *heldConnection) waitConnected(ctx context.Context, t testing.TB) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	want := fmt.Sprintf(":%d", dpRetargetPort)
	for time.Now().Before(deadline) {
		code, out := execInContainer(ctx, t, h.ctr, "ip", "netns", "exec", "client", "ss", "-tn", "state", "established")
		if code == 0 && strings.Contains(out, want) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("held connection did not establish to port %d within deadline", dpRetargetPort)
}

// request sends one request on the held connection and returns the backend
// marker, or "" if the held flow blackholed (no reply before the wait elapses).
// It bumps the generation file, then polls for the matching reply file.
func (h *heldConnection) request(ctx context.Context, t testing.TB) string {
	t.Helper()
	h.gen++
	if code, out := execInContainer(ctx, t, h.ctr, "sh", "-c", fmt.Sprintf("echo %d > /tmp/held_gen", h.gen)); code != 0 {
		t.Fatalf("bump generation (exit %d):\n%s", code, out)
	}
	replyPath := fmt.Sprintf("/tmp/held_reply.%d", h.gen)
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		code, out := execInContainer(ctx, t, h.ctr, "sh", "-c", fmt.Sprintf("cat %s 2>/dev/null", replyPath))
		if code == 0 {
			reply := strings.TrimSpace(out)
			if reply == "" || strings.HasPrefix(reply, "ERR:") {
				return ""
			}
			return reply
		}
		time.Sleep(150 * time.Millisecond)
	}
	return ""
}

// close terminates the held-connection server.
func (h *heldConnection) close(t testing.TB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()
	_, _ = execInContainer(ctx, t, h.ctr, "sh", "-c", "pkill -f held.py || true")
}

// parseMarker extracts the marker from a probe's GOT:/ERR: output, returning ""
// for an ERR line so callers treat a failed probe as a blackhole.
func parseMarker(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if m, ok := strings.CutPrefix(line, "GOT:"); ok {
			return m
		}
	}
	return ""
}
