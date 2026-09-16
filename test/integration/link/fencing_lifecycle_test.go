package linkint

// Fencing lifecycle tests cover table installation, removal, and handoff data-plane transfer.

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/greg2010/wireguard-gateway-operator/internal/link"
	"github.com/greg2010/wireguard-gateway-operator/test/harness/netns"
	"github.com/testcontainers/testcontainers-go"
)

// flLinkID is the link id every fencing-lifecycle fixture in this file derives its names from.
const flLinkID = 7

// flTwoSlotRC supplies a two-slot Local configuration for lifecycle tests.
func flTwoSlotRC() (link.RuntimeConfig, link.GatewayIdentity) {
	gwIdent := link.NewGatewayIdentity(flLinkID)
	rc := link.RuntimeConfig{
		TrafficPolicy: link.TrafficPolicyLocal,
		Identity:      &gwIdent,
		WireGuard:     link.WireGuard{Peers: []link.Peer{{Slot: 0, PublicKey: "PUB0="}, {Slot: 2, PublicKey: "PUB2="}}},
	}
	return rc, gwIdent
}

func flFencingTable(gwIdent link.GatewayIdentity) string { return "fence-" + gwIdent.NftTable }

// flAppliedSlots is the applied set of a holder whose pass programmed both of flTwoSlotRC's
// slots; the fence admits the health port on exactly their interfaces.
var flAppliedSlots = []int{0, 2}

// flFenceListing is the fencing table the kernel lists back for a replica admitting exactly
// ifaces at flLinkID's health port.
func flFenceListing(ifaces ...string) string {
	var b strings.Builder
	b.WriteString("table inet fence-gw7 {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n")
	b.WriteString("\t\ttcp dport 27007 iifname \"lo\" accept\n")
	for _, iface := range ifaces {
		fmt.Fprintf(&b, "\t\ttcp dport 27007 iifname %q accept\n", iface)
	}
	b.WriteString("\t\ttcp dport 27007 drop\n\t}\n}\n")
	return b.String()
}

// TestFencingLifecycle verifies fencing installation, admission, and removal.
func TestFencingLifecycle(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	rc, gwIdent := flTwoSlotRC()
	fenceTable := flFencingTable(gwIdent)

	t.Run("standby installs fencing with no slot", func(t *testing.T) {
		ctr := netns.Start(ctx, t)
		// A standby holds no slot, so it installs the fencing table with an empty applied set
		// before it ever programs a data plane.
		netns.Apply(ctx, t, ctr, link.FencingRuleset(rc, nil))

		if !nftTablePresent(ctx, t, ctr, fenceTable) {
			t.Fatalf("inet %s table absent after InstallFencing with no slot applied", fenceTable)
		}
		listing := netns.List(ctx, t, ctr, "table", "inet", fenceTable)
		want := flFenceListing()
		if listing != want {
			t.Errorf("fencing input chain listing = %q, want %q", listing, want)
		}
	})

	t.Run("fencing survives holder flush and recreate", func(t *testing.T) {
		ctr := netns.Start(ctx, t)
		netns.Apply(ctx, t, ctr, link.FencingRuleset(rc, flAppliedSlots))
		if !nftTablePresent(ctx, t, ctr, fenceTable) {
			t.Fatalf("precondition failed: inet %s table absent before the data-plane flush", fenceTable)
		}

		// The holder's own data-plane table, named distinctly, flushed and recreated the way
		// a re-apply does. The fencing table must never be touched by this.
		dataPlaneTable := gwIdent.NftTable
		netns.Apply(ctx, t, ctr, "add table inet "+dataPlaneTable+"\nflush table inet "+dataPlaneTable+"\ntable inet "+dataPlaneTable+" {}\n")
		netns.Apply(ctx, t, ctr, "add table inet "+dataPlaneTable+"\nflush table inet "+dataPlaneTable+"\ntable inet "+dataPlaneTable+" {}\n")

		if !nftTablePresent(ctx, t, ctr, fenceTable) {
			t.Errorf("inet %s table absent after the data-plane table was flushed and recreated twice", fenceTable)
		}
		if !nftTablePresent(ctx, t, ctr, dataPlaneTable) {
			t.Fatalf("precondition broken: inet %s table absent after being applied", dataPlaneTable)
		}
	})

	t.Run("fencing survives stepdown fence", func(t *testing.T) {
		ctr := netns.Start(ctx, t)
		netns.Apply(ctx, t, ctr, link.FencingRuleset(rc, flAppliedSlots))
		// The data-plane table the step-down fence removes, present so TeardownCommands has
		// something to delete.
		netns.Apply(ctx, t, ctr, "add table inet "+gwIdent.NftTable+"\ntable inet "+gwIdent.NftTable+" {}\n")
		assertGatewayNftTables(ctx, t, ctr, gwIdent, []string{fenceTable, gwIdent.NftTable}, "before the step-down fence")
		for _, id := range []link.SlotIdentity{link.NewSlotIdentity(flLinkID, 0), link.NewSlotIdentity(flLinkID, 2)} {
			if code, out := netns.Exec(ctx, t, ctr, "ip", "link", "add", id.Interface, "type", "dummy"); code != 0 {
				t.Fatalf("ip link add %s failed (exit %d):\n%s", id.Interface, code, out)
			}
			if code, out := netns.Exec(ctx, t, ctr, "ip", "link", "set", id.Interface, "up"); code != 0 {
				t.Fatalf("ip link set %s up failed (exit %d):\n%s", id.Interface, code, out)
			}
			programLocalRoutes(ctx, t, ctr, id, nil)
		}

		runTeardownPlan(ctx, t, ctr, rc)

		// The fence outlives the step-down: it is removed only at process exit.
		assertGatewayNftTables(ctx, t, ctr, gwIdent, []string{fenceTable}, "after the step-down fence")
	})

	t.Run("fencing removed after process exit", func(t *testing.T) {
		ctr := netns.Start(ctx, t)
		netns.Apply(ctx, t, ctr, link.FencingRuleset(rc, flAppliedSlots))
		assertGatewayNftTables(ctx, t, ctr, gwIdent, []string{fenceTable}, "before removal at process exit")

		if code, out := netns.Exec(ctx, t, ctr, "nft", "delete", "table", "inet", fenceTable); code != 0 {
			t.Fatalf("nft delete table inet %s failed (exit %d):\n%s", fenceTable, code, out)
		}

		assertGatewayNftTables(ctx, t, ctr, gwIdent, []string{}, "after removal at process exit")
	})
}

// TestHandoffProgramsEveryStaleSlotRetainsNone transfers state without stale slots.
func TestHandoffProgramsEveryStaleSlotRetainsNone(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	rc, gwIdent := flTwoSlotRC()
	slots := []link.SlotIdentity{link.NewSlotIdentity(flLinkID, 0), link.NewSlotIdentity(flLinkID, 2)}

	ctr := netns.Start(ctx, t)

	// The old holder: every slot's interface and route plan programmed, matching what a real
	// Apply pass installs per slot.
	for _, id := range slots {
		if code, out := netns.Exec(ctx, t, ctr, "ip", "link", "add", id.Interface, "type", "dummy"); code != 0 {
			t.Fatalf("ip link add %s failed (exit %d):\n%s", id.Interface, code, out)
		}
		if code, out := netns.Exec(ctx, t, ctr, "ip", "link", "set", id.Interface, "up"); code != 0 {
			t.Fatalf("ip link set %s up failed (exit %d):\n%s", id.Interface, code, out)
		}
		programLocalRoutes(ctx, t, ctr, id, []string{lpPodIP})
	}
	netns.Apply(ctx, t, ctr, renderRuleset(t, rc, nil))

	assertGatewayState(ctx, t, ctr, flLinkID, wantGatewayState(slots...), "while the old holder holds the data plane")
	assertGatewayNftTables(ctx, t, ctr, gwIdent, []string{gwIdent.NftTable}, "while the old holder holds the data plane")

	// The old holder steps down: its fence tears every slot down.
	runTeardownPlan(ctx, t, ctr, rc)

	assertGatewayState(ctx, t, ctr, flLinkID, wantGatewayState(), "after the old holder stepped down")
	assertGatewayNftTables(ctx, t, ctr, gwIdent, []string{}, "after the old holder stepped down")

	// The new holder acquires: every slot is programmed again from a clean node.
	for _, id := range slots {
		if code, out := netns.Exec(ctx, t, ctr, "ip", "link", "add", id.Interface, "type", "dummy"); code != 0 {
			t.Fatalf("new holder: ip link add %s failed (exit %d):\n%s", id.Interface, code, out)
		}
		if code, out := netns.Exec(ctx, t, ctr, "ip", "link", "set", id.Interface, "up"); code != 0 {
			t.Fatalf("new holder: ip link set %s up failed (exit %d):\n%s", id.Interface, code, out)
		}
		programLocalRoutes(ctx, t, ctr, id, []string{lpPodIP})
	}
	netns.Apply(ctx, t, ctr, renderRuleset(t, rc, nil))

	assertGatewayState(ctx, t, ctr, flLinkID, wantGatewayState(slots...), "after the new holder acquired")
	assertGatewayNftTables(ctx, t, ctr, gwIdent, []string{gwIdent.NftTable}, "after the new holder acquired")
}

// assertGatewayNftTables asserts the inet tables gwIdent owns — its data plane and its fence —
// are exactly want.
func assertGatewayNftTables(ctx context.Context, t testing.TB, ctr testcontainers.Container, gwIdent link.GatewayIdentity, want []string, stage string) {
	t.Helper()
	owned := []string{gwIdent.NftTable, flFencingTable(gwIdent)}
	got := []string{}
	for line := range strings.SplitSeq(netns.List(ctx, t, ctr, "tables"), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "table" && fields[1] == "inet" && slices.Contains(owned, fields[2]) {
			got = append(got, fields[2])
		}
	}
	slices.Sort(got)
	sorted := slices.Clone(want)
	slices.Sort(sorted)
	if !slices.Equal(got, sorted) {
		t.Errorf("gateway %d inet tables %s = %v, want %v", gwIdent.ID, stage, got, sorted)
	}
}

const (
	// flOutsideNodeAddr and flOutsideAddr are the node and peer ends of a veth the fence never
	// lists, standing in for any other interface a node carries.
	flOutsideNodeAddr = "198.51.100.1"
	flOutsideAddr     = "198.51.100.2"
	// flSlot1NodeAddr is the node end of slot 1's interface.
	flSlot1NodeAddr = "10.99.1.2"
	// flOpenPort carries a second node listener, outside the port the fence decides.
	flOpenPort = 27107
)

// flFenceTopologyScript attaches two netns to the node: "outside" through a veth the fence never
// lists, and "slot1" through a veth named after slot 1's interface.
func flFenceTopologyScript(slot1Iface string) string {
	return fmt.Sprintf(`set -e
ip link set lo up
ip netns add outside
ip link add fx-nd type veth peer name fx-out
ip link set fx-out netns outside
ip addr add %[1]s/24 dev fx-nd
ip link set fx-nd up
ip netns exec outside ip addr add %[2]s/24 dev fx-out
ip netns exec outside ip link set fx-out up
ip netns exec outside ip link set lo up

ip netns add slot1
ip link add %[3]s type veth peer name s1-out
ip link set s1-out netns slot1
ip addr add %[4]s/24 dev %[3]s
ip link set %[3]s up
ip netns exec slot1 ip addr add 10.99.1.1/24 dev s1-out
ip netns exec slot1 ip link set s1-out up
ip netns exec slot1 ip link set lo up
`, flOutsideNodeAddr, flOutsideAddr, slot1Iface, flSlot1NodeAddr)
}

// TestFenceAdmitsOnlyListedInterfaces allows health traffic only on listed interfaces.
func TestFenceAdmitsOnlyListedInterfaces(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	rc, gwIdent := flTwoSlotRC()
	slot1 := link.NewSlotIdentity(flLinkID, 1)

	ctr := netns.Start(ctx, t, "python3")
	if code, out := netns.Exec(ctx, t, ctr, "sh", "-c", flFenceTopologyScript(slot1.Interface)); code != 0 {
		t.Fatalf("set up the fencing topology (exit %d):\n%s", code, out)
	}
	netns.Apply(ctx, t, ctr, link.FencingRuleset(rc, flAppliedSlots))
	startEcho(ctx, t, ctr, gwIdent.HealthPort)
	startEcho(ctx, t, ctr, flOpenPort)

	t.Run("unlisted interface reaches another port", func(t *testing.T) {
		if got := probeFrom(ctx, t, ctr, tcpProbe, "outside", flOutsideNodeAddr, flOpenPort); got != "OK" {
			t.Fatalf("probe from the unlisted interface to port %d = %q, want %q", flOpenPort, got, "OK")
		}
	})

	t.Run("unlisted interface is fenced off the health port", func(t *testing.T) {
		err := probeErrorFrom(ctx, t, ctr, tcpProbe, "outside", flOutsideNodeAddr, gwIdent.HealthPort)
		if !isTimeout(err) {
			t.Fatalf("probe from the unlisted interface to the health port = %q, want a timeout: the fence drops it", err)
		}
	})

	t.Run("a pass that applies the added slot admits it", func(t *testing.T) {
		reloaded := rc
		reloaded.WireGuard.Peers = append(slices.Clone(rc.WireGuard.Peers), link.Peer{Slot: 1, PublicKey: "PUB1="})
		netns.Apply(ctx, t, ctr, link.FencingRuleset(reloaded, append(slices.Clone(flAppliedSlots), 1)))

		if got := probeFrom(ctx, t, ctr, tcpProbe, "slot1", flSlot1NodeAddr, gwIdent.HealthPort); got != "OK" {
			t.Errorf("probe arriving on slot 1's interface after the reload = %q, want %q", got, "OK")
		}
	})
}

// TestStepDownTeardownFailureRetriedOnTheStandby retries failed teardown from standby.
func TestStepDownTeardownFailureRetriedOnTheStandby(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	rc, gwIdent := flTwoSlotRC()
	fenceTable := flFencingTable(gwIdent)
	slot0, slot2 := link.NewSlotIdentity(flLinkID, 0), link.NewSlotIdentity(flLinkID, 2)

	ctr := netns.Start(ctx, t)
	for _, id := range []link.SlotIdentity{slot0, slot2} {
		addDummySlotInterface(ctx, t, ctr, id)
		programLocalRoutes(ctx, t, ctr, id, nil)
	}
	netns.Apply(ctx, t, ctr, renderRuleset(t, rc, nil))
	netns.Apply(ctx, t, ctr, link.FencingRuleset(rc, flAppliedSlots))
	assertGatewayState(ctx, t, ctr, flLinkID, wantGatewayState(slot0, slot2), "while the holder holds both slots")

	staleDelete := []string{"ip", "link", "del", slot2.Interface}
	for _, step := range link.TeardownCommands(rc) {
		argv := append([]string{step.Name}, step.Args...)
		if slices.Equal(argv, staleDelete) {
			// The kernel refuses the delete to an unprivileged caller: a teardown failure
			// that is not its object being gone, so the slot stays for the next pass.
			code, out := netns.Exec(ctx, t, ctr, "su", "-s", "/bin/sh", "nobody", "-c", strings.Join(argv, " "))
			if code == 0 {
				t.Fatalf("unprivileged %v unexpectedly succeeded:\n%s", argv, out)
			}
			t.Logf("unprivileged %v failed as intended (exit %d):\n%s", argv, code, out)
			continue
		}
		if code, out := netns.Exec(ctx, t, ctr, argv...); code != 0 {
			t.Fatalf("step-down step %v failed (exit %d):\n%s", argv, code, out)
		}
	}
	netns.Apply(ctx, t, ctr, link.FencingRuleset(rc, nil))

	stale := wantGatewayState()
	stale.Interfaces = []string{slot2.Interface}
	assertGatewayState(ctx, t, ctr, flLinkID, stale, "after the step-down whose slot 2 delete was refused")

	// The standby retries held state and treats step-down's absent objects as complete.
	retained := rc
	retained.WireGuard.Peers = []link.Peer{{Slot: 2, PublicKey: "PUB2="}}
	for _, step := range link.TeardownCommands(retained) {
		if step.Name != "ip" {
			continue
		}
		code, out := netns.Exec(ctx, t, ctr, append([]string{step.Name}, step.Args...)...)
		if code != 0 && !strings.Contains(out, "No such file or directory") {
			t.Fatalf("standby teardown step %v failed (exit %d):\n%s", step.Args, code, out)
		}
	}
	netns.Apply(ctx, t, ctr, link.FencingRuleset(rc, nil))

	assertGatewayState(ctx, t, ctr, flLinkID, wantGatewayState(), "after the standby retried the teardown")
	if listing := netns.List(ctx, t, ctr, "table", "inet", fenceTable); listing != flFenceListing() {
		t.Errorf("fence after the standby's config = %q, want %q", listing, flFenceListing())
	}
}
