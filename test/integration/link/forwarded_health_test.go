package linkint

// A member's broken data plane or sysctl withholds only that member's forwarded probe.

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/greg2010/wireguard-gateway-operator/internal/link"
	"github.com/greg2010/wireguard-gateway-operator/test/harness/netns"
	"github.com/testcontainers/testcontainers-go"
)

const (
	fhLinkID       = 9
	fhHealthPort   = 27009
	fhProbeTimeout = 5 * time.Second
)

// fhEchoScript answers every connection to port with "OK\n" once, the minimal proof a probe
// reached a live local listener.
func fhEchoScript(port int) string {
	return fmt.Sprintf(`import socket
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", %d))
srv.listen(16)
while True:
    conn, _ = srv.accept()
    conn.sendall(b"OK\n")
    conn.close()
`, port)
}

// fhLocalTopologyScript wires client <-> vm <-> node, the same shape localTopologyScript builds,
// minus the backend netns: forwarded-health traffic terminates on the node itself.
func fhLocalTopologyScript(iface string) string {
	return fmt.Sprintf(`set -e
ip netns add client
ip netns add vm
ip link add vc-cl type veth peer name vc-vm
ip link set vc-cl netns client
ip link set vc-vm netns vm
ip netns exec client ip addr add 10.0.1.2/24 dev vc-cl
ip netns exec client ip link set vc-cl up
ip netns exec client ip link set lo up
ip netns exec client ip route add default via 10.0.1.1
ip netns exec vm ip addr add 10.0.1.1/24 dev vc-vm
ip netns exec vm ip link set vc-vm up
ip netns exec vm ip link set lo up

ip link add vt-vm type veth peer name %[1]s
ip link set vt-vm netns vm
ip netns exec vm ip addr add 10.99.0.1/24 dev vt-vm
ip netns exec vm ip link set vt-vm up
ip netns exec vm sysctl -w net.ipv4.ip_forward=1
ip netns exec vm sysctl -w net.ipv4.conf.vt-vm.proxy_arp=1
ip addr add 10.99.0.2/24 dev %[1]s
ip link set %[1]s up

ip netns add sink
ip link add ds-nd type veth peer name ds-sink
ip link set ds-sink netns sink
ip addr add 192.0.2.1/24 dev ds-nd
ip link set ds-nd up
ip netns exec sink ip addr add 192.0.2.2/24 dev ds-sink
ip netns exec sink ip link set ds-sink up
ip netns exec sink ip link set lo up

sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.%[1]s.rp_filter=0
ip route replace default via 192.0.2.2 dev ds-nd
`, iface)
}

// fhVMRuleset DNATs every port but 51820 to the node's tunnel address, matching
// traffic-policy=local's real VM ruleset (local_datapath_test.go's vmRuleset).
const fhVMRuleset = `add table inet gateway
flush table inet gateway
table inet gateway {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		iifname "vc-vm" meta l4proto { tcp, udp } th dport != 51820 dnat ip to 10.99.0.2
	}

	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname "vt-vm" return
	}
}
`

// TestForwardedHealth checks forwarded health through the fence.
func TestForwardedHealth(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	gwIdent := link.NewGatewayIdentity(fhLinkID)
	slotIdent := link.NewSlotIdentity(fhLinkID, 0)
	rc := link.RuntimeConfig{
		TrafficPolicy: link.TrafficPolicyLocal,
		Identity:      &gwIdent,
		HealthPort:    fhHealthPort,
		WireGuard:     link.WireGuard{Peers: []link.Peer{{Slot: 0, PublicKey: "PUB="}}},
	}

	ctr := netns.Start(ctx, t, "python3")
	if code, out := netns.Exec(ctx, t, ctr, "sh", "-c", fhLocalTopologyScript(slotIdent.Interface)); code != 0 {
		t.Fatalf("set up local netns topology (exit %d):\n%s", code, out)
	}
	programLocalRoutes(ctx, t, ctr, slotIdent, nil)
	netns.Apply(ctx, t, ctr, link.FencingRuleset(rc, []int{0}))
	netns.Apply(ctx, t, ctr, renderRuleset(t, rc, nil))
	applyInNetns(ctx, t, ctr, "vm", fhVMRuleset)
	startEcho(ctx, t, ctr, fhHealthPort)

	t.Run("local forwarded probe external source returns through tunnel", func(t *testing.T) {
		before := outputReplyPackets(ctx, t, ctr, gwIdent.NftTable, slotIdent)
		if got := fhProbe(ctx, t, ctr); got != "OK" {
			t.Fatalf("probe through the fenced tunnel = %q, want %q", got, "OK")
		}
		if got := outputReplyPackets(ctx, t, ctr, gwIdent.NftTable, slotIdent) - before; got < 1 {
			t.Errorf("health reply counter delta = %d, want greater than zero", got)
		}
	})

	t.Run("local reply route correct before and after mark restore", func(t *testing.T) {
		if iface := routeGetInterface(ctx, t, ctr, slotIdent, false); iface != "ds-nd" {
			t.Fatalf("unmarked route to the prober uses %q, want decoy %q", iface, "ds-nd")
		}
		if iface := routeGetInterface(ctx, t, ctr, slotIdent, true); iface != slotIdent.Interface {
			t.Fatalf("marked route to the prober uses %q, want slot interface %q", iface, slotIdent.Interface)
		}
		before := outputReplyPackets(ctx, t, ctr, gwIdent.NftTable, slotIdent)
		if got := fhProbe(ctx, t, ctr); got != "OK" {
			t.Fatalf("probe through the fenced tunnel = %q, want %q", got, "OK")
		}
		if got := outputReplyPackets(ctx, t, ctr, gwIdent.NftTable, slotIdent) - before; got < 1 {
			t.Errorf("output reply-rule packet delta = %d, want greater than zero", got)
		}
	})
}

type linkStatistics struct {
	Stats64 struct {
		RX struct {
			Packets uint64 `json:"packets"`
		} `json:"rx"`
		TX struct {
			Packets uint64 `json:"packets"`
		} `json:"tx"`
	} `json:"stats64"`
}

func interfacePacketCount(ctx context.Context, t testing.TB, ctr testcontainers.Container, ns, iface, direction string) uint64 {
	t.Helper()
	args := []string{"ip", "-j", "-s", "link", "show", "dev", iface}
	if ns != "" {
		args = append([]string{"ip", "netns", "exec", ns}, args...)
	}
	code, out := netns.Exec(ctx, t, ctr, args...)
	if code != 0 {
		t.Fatalf("ip link statistics for %s failed (exit %d):\n%s", iface, code, out)
	}
	var stats []linkStatistics
	if err := json.Unmarshal([]byte(out), &stats); err != nil || len(stats) != 1 {
		t.Fatalf("decode link statistics for %s: %v\n%s", iface, err, out)
	}
	if direction == "rx" {
		return stats[0].Stats64.RX.Packets
	}
	return stats[0].Stats64.TX.Packets
}

func routeGetInterface(ctx context.Context, t testing.TB, ctr testcontainers.Container, id link.SlotIdentity, marked bool) string {
	t.Helper()
	args := []string{"ip", "-j", "route", "get", "10.0.1.2", "from", "10.99.0.2"}
	if marked {
		args = append(args, "mark", id.Mark)
	}
	code, out := netns.Exec(ctx, t, ctr, args...)
	if code != 0 {
		t.Fatalf("ip route get failed (exit %d):\n%s", code, out)
	}
	var routes []struct {
		Dev string `json:"dev"`
	}
	if err := json.Unmarshal([]byte(out), &routes); err != nil || len(routes) != 1 || routes[0].Dev == "" {
		t.Fatalf("decode route lookup: %v\n%s", err, out)
	}
	return routes[0].Dev
}

func outputReplyPackets(ctx context.Context, t testing.TB, ctr testcontainers.Container, table string, id link.SlotIdentity) uint64 {
	t.Helper()
	code, out := netns.Exec(ctx, t, ctr, "nft", "list", "chain", "inet", table, "output")
	if code != 0 {
		t.Fatalf("nft list output chain failed (exit %d):\n%s", code, out)
	}
	linePattern := regexp.MustCompile(`(?m)^.*tcp sport ` + strconv.Itoa(fhHealthPort) + `.*` + regexp.QuoteMeta(id.Mark) + `.*counter packets ([0-9]+).*$`)
	match := linePattern.FindStringSubmatch(out)
	if len(match) != 2 {
		t.Fatalf("output chain has no health reply rule for %s:\n%s", id.Interface, out)
	}
	packets, err := strconv.ParseUint(match[1], 10, 64)
	if err != nil {
		t.Fatalf("parse output reply-rule packets %q: %v", match[1], err)
	}
	return packets
}

// startEcho launches an echo listener on port in the container's own (node) netns and waits for
// it to bind before returning, so no probe races the listener.
func startEcho(ctx context.Context, t testing.TB, ctr testcontainers.Container, port int) {
	t.Helper()
	path := fmt.Sprintf("/tmp/echo_%d.py", port)
	if err := ctr.CopyToContainer(ctx, []byte(fhEchoScript(port)), path, 0o644); err != nil {
		t.Fatalf("copy echo script for port %d: %v", port, err)
	}
	if code, out := netns.Exec(ctx, t, ctr, "sh", "-c", "python3 "+path+" &"); code != 0 {
		t.Fatalf("start echo on port %d (exit %d):\n%s", port, code, out)
	}
	want := fmt.Sprintf(":%d", port)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		code, out := netns.Exec(ctx, t, ctr, "ss", "-ltn")
		if code == 0 && strings.Contains(out, want) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("echo listener did not bind %s within deadline", want)
}

// fhProbe dials the VM's public address at the health port from the client netns, returning the
// echoed reply with its trailing newline trimmed, or "" on any failure.
func fhProbe(ctx context.Context, t testing.TB, ctr testcontainers.Container) string {
	t.Helper()
	if err := ctr.CopyToContainer(ctx, []byte(probeScript), "/tmp/fh_probe.py", 0o644); err != nil {
		t.Fatalf("copy probe script: %v", err)
	}
	secs := fmt.Sprintf("%.0f", fhProbeTimeout.Seconds())
	cmd := fmt.Sprintf("ip netns exec client python3 /tmp/fh_probe.py 10.0.1.1 %d %s", fhHealthPort, secs)
	code, out := netns.Exec(ctx, t, ctr, "sh", "-c", cmd)
	if code != 0 {
		t.Fatalf("probe exec failed (exit %d):\n%s", code, out)
	}
	return parseMarker(out)
}

// TestClusterForwardedProbeWithMasquerade checks the Cluster probe with masquerading.
func TestClusterForwardedProbeWithMasquerade(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	ctr := startDataPathContainer(ctx, t)

	rc := twoPeerClusterRC()
	rc.HealthPort = fhHealthPort
	forward := link.ResolvedForward{Name: "svc", PublicPort: dpRetargetPort, Protocol: "tcp", Target: dpClusterIPA, TargetPort: dpTargetPort}
	netns.Apply(ctx, t, ctr, renderRuleset(t, rc, []link.ResolvedForward{forward}))
	startEcho(ctx, t, ctr, fhHealthPort)

	if got := probeOnce(ctx, t, ctr); got != dpMarkerA {
		t.Errorf("forward probe through masquerading ruleset = %q, want %q", got, dpMarkerA)
	}

	if err := ctr.CopyToContainer(ctx, []byte(probeScript), "/tmp/health_probe.py", 0o644); err != nil {
		t.Fatalf("copy health probe script: %v", err)
	}
	secs := fmt.Sprintf("%.0f", fhProbeTimeout.Seconds())
	cmd := fmt.Sprintf("ip netns exec client python3 /tmp/health_probe.py 10.99.0.2 %d %s", fhHealthPort, secs)
	code, out := netns.Exec(ctx, t, ctr, "sh", "-c", cmd)
	if code != 0 {
		t.Fatalf("health probe exec failed (exit %d):\n%s", code, out)
	}
	if got := parseMarker(out); got != "OK" {
		t.Errorf("health probe through the admitted input rule = %q, want %q", got, "OK")
	}
}

// TestMemberScopedFailures keeps member faults scoped to their own probes.
func TestMemberScopedFailures(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	t.Run("broken DNAT on one member fails only that probe", func(t *testing.T) {
		healthy := startDataPathContainer(ctx, t)
		broken := startDataPathContainer(ctx, t)

		rc := twoPeerClusterRC()
		goodForward := link.ResolvedForward{Name: "svc", PublicPort: dpRetargetPort, Protocol: "tcp", Target: dpClusterIPA, TargetPort: dpTargetPort}
		// The broken member's DNAT targets an address nothing backs: the member-local
		// equivalent of a misconfigured forward.
		badForward := link.ResolvedForward{Name: "svc", PublicPort: dpRetargetPort, Protocol: "tcp", Target: "10.96.0.99", TargetPort: dpTargetPort}

		netns.Apply(ctx, t, healthy, renderRuleset(t, rc, []link.ResolvedForward{goodForward}))
		netns.Apply(ctx, t, broken, renderRuleset(t, rc, []link.ResolvedForward{badForward}))

		if got := probeOnce(ctx, t, healthy); got != dpMarkerA {
			t.Errorf("healthy member's probe = %q, want %q", got, dpMarkerA)
		}
		err := probeErrorFrom(ctx, t, broken, tcpProbe, "client", dpGatewayAddr, dpRetargetPort)
		if !isHostUnreachable(err) {
			t.Errorf("broken member's probe = %q, want EHOSTUNREACH: its DNAT targets an address nothing backs", err)
		}
	})

	t.Run("forwarding sysctl cleared fails only that member", func(t *testing.T) {
		gwIdent := link.NewGatewayIdentity(fhLinkID)
		slotIdent := link.NewSlotIdentity(fhLinkID, 0)
		rc := link.RuntimeConfig{
			TrafficPolicy: link.TrafficPolicyLocal,
			Identity:      &gwIdent,
			WireGuard:     link.WireGuard{Peers: []link.Peer{{Slot: 0, PublicKey: "PUB="}}},
		}
		forwards := []link.ResolvedForward{{Name: "tcp-8443", PublicPort: lpPublicPort, Protocol: "tcp", Target: lpPodIP, TargetPort: lpPodPort}}

		healthy := startLocalForwardMember(ctx, t, slotIdent, rc, forwards, true)
		unhealthy := startLocalForwardMember(ctx, t, slotIdent, rc, forwards, false)

		if got := probeFrom(ctx, t, healthy, tcpProbe, "client", lpVMPublicAddr, lpPublicPort); !strings.Contains(got, lpMarker) {
			t.Errorf("member with ip_forward=1 forward probe = %q, want a reply carrying %q", got, lpMarker)
		}
		err := probeErrorFrom(ctx, t, unhealthy, tcpProbe, "client", lpVMPublicAddr, lpPublicPort)
		if !isTimeout(err) {
			t.Errorf("member with ip_forward=0 forward probe = %q, want a timeout: the kernel must refuse to forward between interfaces", err)
		}
	})
}

// isHostUnreachable reports whether a probe failed with EHOSTUNREACH, the outcome a DNAT to an
// address no host answers for produces once the node's ARP for it goes unanswered.
func isHostUnreachable(err string) bool {
	return strings.Contains(err, "OSError(113")
}

// startLocalForwardMember starts a Local forwarding member for health tests.
func startLocalForwardMember(ctx context.Context, t testing.TB, id link.SlotIdentity, rc link.RuntimeConfig, forwards []link.ResolvedForward, forwardingEnabled bool) testcontainers.Container {
	t.Helper()
	ctr := netns.Start(ctx, t, "python3")
	if code, out := netns.Exec(ctx, t, ctr, "sh", "-c", localTopologyScript(id.Interface)); code != 0 {
		t.Fatalf("set up local netns topology (exit %d):\n%s", code, out)
	}
	startPeerBackend(ctx, t, ctr)
	programLocalRoutes(ctx, t, ctr, id, []string{lpPodIP})
	netns.Apply(ctx, t, ctr, renderRuleset(t, rc, forwards))
	applyInNetns(ctx, t, ctr, "vm", vmRuleset)

	forwardingValue := "1"
	if !forwardingEnabled {
		forwardingValue = "0"
	}
	if code, out := netns.Exec(ctx, t, ctr, "sysctl", "-w", "net.ipv4.ip_forward="+forwardingValue); code != 0 {
		t.Fatalf("set net.ipv4.ip_forward=%s failed (exit %d):\n%s", forwardingValue, code, out)
	}
	if code, out := netns.Exec(ctx, t, ctr, "sysctl", "-w", "net.ipv4.conf."+id.Interface+".forwarding="+forwardingValue); code != 0 {
		t.Fatalf("set net.ipv4.conf.%s.forwarding=%s failed (exit %d):\n%s", id.Interface, forwardingValue, code, out)
	}
	return ctr
}
