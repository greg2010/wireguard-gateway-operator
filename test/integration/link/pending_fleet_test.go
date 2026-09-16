package linkint

// A zero-peer configuration has no slot interfaces; the first member config brings its slot up.

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/greg2010/wireguard-gateway-operator/internal/link"
	"github.com/greg2010/wireguard-gateway-operator/test/harness/netns"
	"github.com/testcontainers/testcontainers-go"
)

const (
	// pfLinkID is the link id the pending-fleet fixture derives every name from.
	pfLinkID = 14
	// pfNodeAddr is the node end of the slot's carrier, the address the probe dials.
	pfNodeAddr = "10.91.0.1"
)

// pfTopologyScript attaches a client netns to the node over a veth named after the slot
// interface, the carrier a probe arriving through the tunnel takes.
func pfTopologyScript(iface string) string {
	return fmt.Sprintf(`set -e
ip link set lo up
ip netns add client
ip link add %[1]s type veth peer name c-out
ip link set c-out netns client
ip addr add %[2]s/24 dev %[1]s
ip link set %[1]s up
ip netns exec client ip addr add 10.91.0.2/24 dev c-out
ip netns exec client ip link set c-out up
ip netns exec client ip link set lo up
`, iface, pfNodeAddr)
}

// pfResponderScript answers every request with a 200, so a probe's verdict is the status line a
// real prober reads rather than a bare connection.
func pfResponderScript(port int) string {
	return fmt.Sprintf(`import socket
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", %d))
srv.listen(16)
while True:
    conn, _ = srv.accept()
    conn.recv(1024)
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    conn.close()
`, port)
}

// pfHTTPProbeScript prints the status line of a GET against /forwarded-healthz.
const pfHTTPProbeScript = `import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(float(sys.argv[3]))
try:
    s.connect((sys.argv[1], int(sys.argv[2])))
    s.sendall(b"GET /forwarded-healthz HTTP/1.1\r\nHost: probe\r\n\r\n")
    print("GOT:" + s.recv(256).decode(errors="replace").split("\r\n")[0].strip())
except Exception as e:
    print("ERR:" + repr(e))
finally:
    s.close()
`

var pfHTTPProbe = probeKind{name: "http", script: pfHTTPProbeScript, path: "/tmp/http_probe.py"}

// TestPendingFleetThenFirstMember handles a fleet before and after its first member.
func TestPendingFleetThenFirstMember(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	gwIdent := link.NewGatewayIdentity(pfLinkID)
	slot0 := link.NewSlotIdentity(pfLinkID, 0)
	pending := link.RuntimeConfig{
		TrafficPolicy: link.TrafficPolicyLocal,
		Identity:      &gwIdent,
		HealthPort:    gwIdent.HealthPort,
		WireGuard:     link.WireGuard{Address: "10.99.0.2/32", Peers: []link.Peer{}},
	}
	oneMember := pending
	oneMember.WireGuard.Peers = []link.Peer{{Slot: 0, PublicKey: "PUB0=", Endpoint: "203.0.113.1:51820", AllowedIPs: []string{"0.0.0.0/0"}}}

	fenceTable := tableNameOf(t, link.FencingRuleset(pending, nil))

	ctr := netns.Start(ctx, t, "python3")
	netns.Apply(ctx, t, ctr, renderRuleset(t, pending, nil))
	netns.Apply(ctx, t, ctr, link.FencingRuleset(pending, nil))

	t.Run("zero peer config programs no slot", func(t *testing.T) {
		wantTables := []string{"inet " + fenceTable, "inet " + gwIdent.NftTable}
		if got := gatewayTables(ctx, t, ctr, []string{gwIdent.NftTable, fenceTable}); !slices.Equal(got, wantTables) {
			t.Errorf("gateway tables = %v, want %v", got, wantTables)
		}

		wantDataPlane := map[string][]string{
			"premark":    {"type filter hook prerouting priority mangle; policy accept;"},
			"output":     {"type route hook output priority mangle; policy accept;"},
			"prerouting": {"type nat hook prerouting priority dstnat; policy accept;"},
			"forward":    {"type filter hook forward priority filter; policy accept;"},
			"input":      {"type filter hook input priority filter; policy accept;"},
		}
		if got := tableChains(ctx, t, ctr, gwIdent.NftTable); !reflect.DeepEqual(got, wantDataPlane) {
			t.Errorf("data-plane table %s = %v, want %v", gwIdent.NftTable, got, wantDataPlane)
		}

		wantFence := map[string][]string{"input": {
			"type filter hook input priority filter; policy accept;",
			fmt.Sprintf("tcp dport %d iifname \"lo\" accept", gwIdent.HealthPort),
			fmt.Sprintf("tcp dport %d drop", gwIdent.HealthPort),
		}}
		if got := tableChains(ctx, t, ctr, fenceTable); !reflect.DeepEqual(got, wantFence) {
			t.Errorf("fencing table %s = %v, want %v", fenceTable, got, wantFence)
		}

		if got := gatewayLinkNames(ctx, t, ctr, pfLinkID); !slices.Equal(got, []string{}) {
			t.Errorf("gateway tunnel interfaces = %v, want none: a pending fleet has no member to bring one up for", got)
		}
	})

	t.Run("first member applies on top and answers its probe", func(t *testing.T) {
		if code, out := netns.Exec(ctx, t, ctr, "sh", "-c", pfTopologyScript(slot0.Interface)); code != 0 {
			t.Fatalf("set up the pending-fleet topology (exit %d):\n%s", code, out)
		}
		startForwardedResponder(ctx, t, ctr, gwIdent.HealthPort)
		programLocalRoutes(ctx, t, ctr, slot0, nil)
		netns.Apply(ctx, t, ctr, renderRuleset(t, oneMember, nil))
		netns.Apply(ctx, t, ctr, link.FencingRuleset(oneMember, []int{0}))

		assertGatewayState(ctx, t, ctr, pfLinkID, wantGatewayState(slot0), "after the first member's config")
		if got := gatewayLinkNames(ctx, t, ctr, pfLinkID); !slices.Equal(got, []string{slot0.Interface}) {
			t.Errorf("gateway tunnel interfaces = %v, want %v", got, []string{slot0.Interface})
		}

		wantInput := []string{
			"type filter hook input priority filter; policy accept;",
			fmt.Sprintf("iifname %q tcp dport %d counter accept", slot0.Interface, gwIdent.HealthPort),
			fmt.Sprintf("iifname %q counter drop", slot0.Interface),
		}
		if got := tableChains(ctx, t, ctr, gwIdent.NftTable)["input"]; !slices.Equal(got, wantInput) {
			t.Errorf("data-plane input chain = %v, want %v", got, wantInput)
		}
		wantFence := map[string][]string{"input": {
			"type filter hook input priority filter; policy accept;",
			fmt.Sprintf("tcp dport %d iifname \"lo\" accept", gwIdent.HealthPort),
			fmt.Sprintf("tcp dport %d iifname %q accept", gwIdent.HealthPort, slot0.Interface),
			fmt.Sprintf("tcp dport %d drop", gwIdent.HealthPort),
		}}
		if got := tableChains(ctx, t, ctr, fenceTable); !reflect.DeepEqual(got, wantFence) {
			t.Errorf("fencing table %s = %v, want %v", fenceTable, got, wantFence)
		}

		if got := probeFrom(ctx, t, ctr, pfHTTPProbe, "client", pfNodeAddr, gwIdent.HealthPort); got != "HTTP/1.1 200 OK" {
			t.Errorf("forwarded probe through the first member's slot = %q, want %q", got, "HTTP/1.1 200 OK")
		}
	})
}

// tableNameOf returns the table an nft document creates, read from its `add table` line, so a
// test names the fencing table the product names rather than restating its spelling.
func tableNameOf(t testing.TB, ruleset string) string {
	t.Helper()
	for line := range strings.SplitSeq(ruleset, "\n") {
		if name, ok := strings.CutPrefix(strings.TrimSpace(line), "add table inet "); ok {
			return name
		}
	}
	t.Fatalf("ruleset carries no `add table inet` line:\n%s", ruleset)
	return ""
}

// gatewayTables is the loaded tables named in owned, sorted, each as `<family> <name>`.
func gatewayTables(ctx context.Context, t testing.TB, ctr testcontainers.Container, owned []string) []string {
	t.Helper()
	names := []string{}
	for line := range strings.SplitSeq(netns.List(ctx, t, ctr, "tables"), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "table" && slices.Contains(owned, fields[2]) {
			names = append(names, fields[1]+" "+fields[2])
		}
	}
	slices.Sort(names)
	return names
}

// nftCounter matches the packet and byte counts nft prints for a counter statement, which a
// listing carries and the rendered document does not.
var nftCounter = regexp.MustCompile(` packets \d+ bytes \d+`)

// tableChains is the kernel's view of table: each chain's name mapped to its lines in order, the
// chain's type line first, with counter values dropped so a probe's traffic does not move them.
func tableChains(ctx context.Context, t testing.TB, ctr testcontainers.Container, table string) map[string][]string {
	t.Helper()
	chains := map[string][]string{}
	current := ""
	for line := range strings.SplitSeq(netns.List(ctx, t, ctr, "table", "inet", table), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "chain ") && strings.HasSuffix(trimmed, "{"):
			current = strings.TrimSuffix(strings.TrimPrefix(trimmed, "chain "), " {")
			chains[current] = []string{}
		case trimmed == "}":
			current = ""
		case current != "" && trimmed != "":
			chains[current] = append(chains[current], nftCounter.ReplaceAllString(trimmed, ""))
		}
	}
	if len(chains) == 0 {
		t.Fatalf("table inet %s carries no chain", table)
	}
	return chains
}

// gatewayLinkNames is gatewayID's tunnel interfaces present on the node, from `ip -o link`,
// sorted. A veth's @peer suffix is dropped, so a carrier standing in for a slot's device counts.
func gatewayLinkNames(ctx context.Context, t testing.TB, ctr testcontainers.Container, gatewayID int) []string {
	t.Helper()
	code, out := netns.Exec(ctx, t, ctr, "ip", "-o", "link", "show")
	if code != 0 {
		t.Fatalf("ip -o link show failed (exit %d):\n%s", code, out)
	}
	owned := slotInterfaces(gatewayID)
	names := []string{}
	for line := range strings.SplitSeq(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name, _, _ := strings.Cut(strings.TrimSuffix(fields[1], ":"), "@")
		if slices.Contains(owned, name) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// slotInterfaces is every interface name gatewayID's slots can carry.
func slotInterfaces(gatewayID int) []string {
	names := make([]string, 0, 256)
	for slot := range 256 {
		names = append(names, link.NewSlotIdentity(gatewayID, slot).Interface)
	}
	return names
}

// startForwardedResponder launches the 200-answering listener on port in the node netns and waits
// for its bind, so no probe races it.
func startForwardedResponder(ctx context.Context, t testing.TB, ctr testcontainers.Container, port int) {
	t.Helper()
	path := fmt.Sprintf("/tmp/responder_%d.py", port)
	if err := ctr.CopyToContainer(ctx, []byte(pfResponderScript(port)), path, 0o644); err != nil {
		t.Fatalf("copy responder script for port %d: %v", port, err)
	}
	if code, out := netns.Exec(ctx, t, ctr, "sh", "-c", "python3 "+path+" &"); code != 0 {
		t.Fatalf("start responder on port %d (exit %d):\n%s", port, code, out)
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
	t.Fatalf("responder did not bind %s within deadline", want)
}
