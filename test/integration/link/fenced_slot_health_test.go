package linkint

// Fencing admits each applied slot independently, so failed and departed slots do not block
// healthy slots.

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

const (
	// fsLinkID is the link id the fenced-slot fixtures derive every name from.
	fsLinkID = 13
	// fsSlotANodeAddr and fsSlotBNodeAddr are the node ends of the two slots' carriers, each
	// probed from its own netns so a verdict belongs to exactly one slot.
	fsSlotANodeAddr = "10.90.0.1"
	fsSlotBNodeAddr = "10.90.2.1"
)

// fsTwoSlotRC is the two-slot Local fixture, slots 0 and 2, with the health port the fence and
// the data-plane ruleset both render.
func fsTwoSlotRC() (link.RuntimeConfig, link.GatewayIdentity) {
	gwIdent := link.NewGatewayIdentity(fsLinkID)
	rc := link.RuntimeConfig{
		TrafficPolicy: link.TrafficPolicyLocal,
		Identity:      &gwIdent,
		HealthPort:    gwIdent.HealthPort,
		WireGuard:     link.WireGuard{Peers: []link.Peer{{Slot: 0, PublicKey: "PUB0="}, {Slot: 2, PublicKey: "PUB2="}}},
	}
	return rc, gwIdent
}

// fsTopologyScript configures the network namespace topology for slot-health tests.
func fsTopologyScript(slotAIface, slotBIface string) string {
	return fmt.Sprintf(`set -e
ip link set lo up
ip netns add clientA
ip link add %[1]s type veth peer name a-out
ip link set a-out netns clientA
ip addr add %[3]s/24 dev %[1]s
ip link set %[1]s up
ip netns exec clientA ip addr add 10.90.0.2/24 dev a-out
ip netns exec clientA ip link set a-out up
ip netns exec clientA ip link set lo up

ip netns add clientB
ip link add %[2]s type bridge
ip link add b-nd type veth peer name b-out
ip link set b-out netns clientB
ip link set b-nd master %[2]s
ip addr add %[4]s/24 dev %[2]s
ip link set b-nd up
ip link set %[2]s up
ip netns exec clientB ip addr add 10.90.2.2/24 dev b-out
ip netns exec clientB ip link set b-out up
ip netns exec clientB ip link set lo up
`, slotAIface, slotBIface, fsSlotANodeAddr, fsSlotBNodeAddr)
}

// TestFencedSlotHealth checks health admission for each slot outcome.
func TestFencedSlotHealth(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	rc, gwIdent := fsTwoSlotRC()
	slotA := link.NewSlotIdentity(fsLinkID, 0)
	slotB := link.NewSlotIdentity(fsLinkID, 2)

	ctr := netns.Start(ctx, t, "python3")
	if code, out := netns.Exec(ctx, t, ctr, "sh", "-c", fsTopologyScript(slotA.Interface, slotB.Interface)); code != 0 {
		t.Fatalf("set up the fenced-slot topology (exit %d):\n%s", code, out)
	}
	startEcho(ctx, t, ctr, gwIdent.HealthPort)
	for _, id := range []link.SlotIdentity{slotA, slotB} {
		programLocalRoutes(ctx, t, ctr, id, nil)
	}
	netns.Apply(ctx, t, ctr, renderRuleset(t, rc, nil))
	netns.Apply(ctx, t, ctr, link.FencingRuleset(rc, []int{0, 2}))

	t.Run("every applied slot answers its own probe", func(t *testing.T) {
		for _, probe := range []struct {
			slot int
			addr string
		}{{slot: 0, addr: fsSlotANodeAddr}, {slot: 2, addr: fsSlotBNodeAddr}} {
			ns := fmt.Sprintf("client%s", map[int]string{0: "A", 2: "B"}[probe.slot])
			if got := probeFrom(ctx, t, ctr, tcpProbe, ns, probe.addr, gwIdent.HealthPort); got != "OK" {
				t.Errorf("probe through slot %d = %q, want %q", probe.slot, got, "OK")
			}
		}
	})

	t.Run("a slot whose apply failed is fenced off the health port", func(t *testing.T) {
		// The pass's own interface step for slot 2, failing on a name a device of another
		// Keep the other device passing packets while its peer's removal is blocked.
		code, out := netns.Exec(ctx, t, ctr, "ip", "link", "add", slotB.Interface, "type", "wireguard")
		if code == 0 {
			t.Fatalf("slot 2's interface step unexpectedly succeeded against the occupied name %s", slotB.Interface)
		}
		t.Logf("slot 2's interface step failed as intended (exit %d):\n%s", code, out)
		netns.Apply(ctx, t, ctr, link.FencingRuleset(rc, []int{0}))

		err := probeErrorFrom(ctx, t, ctr, tcpProbe, "clientB", fsSlotBNodeAddr, gwIdent.HealthPort)
		if !isTimeout(err) {
			t.Errorf("probe through the down slot = %q, want a timeout: the fence drops it", err)
		}
		if got := probeFrom(ctx, t, ctr, tcpProbe, "clientA", fsSlotANodeAddr, gwIdent.HealthPort); got != "OK" {
			t.Errorf("probe through the applied slot = %q, want %q", got, "OK")
		}
	})

	t.Run("the failed slot's next pass readmits it", func(t *testing.T) {
		// The obstruction is gone from the plan: the interface is present, so the pass omits
		// the creation step and its remaining steps succeed.
		if !ifacePresent(ctx, t, ctr, slotB.Interface) {
			t.Fatalf("%s absent; the retrying pass would build a plan that creates it", slotB.Interface)
		}
		programLocalRoutes(ctx, t, ctr, slotB, nil)
		netns.Apply(ctx, t, ctr, link.FencingRuleset(rc, []int{0, 2}))

		if got := probeFrom(ctx, t, ctr, tcpProbe, "clientB", fsSlotBNodeAddr, gwIdent.HealthPort); got != "OK" {
			t.Errorf("probe through the retried slot = %q, want %q", got, "OK")
		}
		if got := probeFrom(ctx, t, ctr, tcpProbe, "clientA", fsSlotANodeAddr, gwIdent.HealthPort); got != "OK" {
			t.Errorf("probe through the applied slot = %q, want %q", got, "OK")
		}
	})
}

// TestDepartedSlotAbsentInterfaceKeepsThePass accepts an already-absent departed interface.
func TestDepartedSlotAbsentInterfaceKeepsThePass(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	twoSlot, gwIdent := fsTwoSlotRC()
	oneSlot := twoSlot
	oneSlot.WireGuard.Peers = []link.Peer{{Slot: 0, PublicKey: "PUB0="}}
	slotA := link.NewSlotIdentity(fsLinkID, 0)
	slotB := link.NewSlotIdentity(fsLinkID, 2)

	ctr := netns.Start(ctx, t, "python3")
	if code, out := netns.Exec(ctx, t, ctr, "sh", "-c", fsTopologyScript(slotA.Interface, slotB.Interface)); code != 0 {
		t.Fatalf("set up the fenced-slot topology (exit %d):\n%s", code, out)
	}
	startEcho(ctx, t, ctr, gwIdent.HealthPort)
	for _, id := range []link.SlotIdentity{slotA, slotB} {
		programLocalRoutes(ctx, t, ctr, id, nil)
	}
	netns.Apply(ctx, t, ctr, renderRuleset(t, twoSlot, nil))
	netns.Apply(ctx, t, ctr, link.FencingRuleset(twoSlot, []int{0, 2}))

	// Slot 2's interface goes out of band, the way a node reboot or another agent takes one:
	// the departed teardown that follows finds its object already gone.
	if code, out := netns.Exec(ctx, t, ctr, "ip", "link", "del", slotB.Interface); code != 0 {
		t.Fatalf("delete %s out of band failed (exit %d):\n%s", slotB.Interface, code, out)
	}

	failures := replayDepartedTeardown(ctx, t, ctr, twoSlot, oneSlot)
	wantAbsent := []string{fmt.Sprintf(`Cannot find device "%s"`, slotB.Interface)}
	if !slices.EqualFunc(failures, wantAbsent, strings.Contains) {
		t.Errorf("departed teardown failures = %v, want exactly one naming %v", failures, wantAbsent)
	}

	programLocalRoutes(ctx, t, ctr, slotA, nil)
	netns.Apply(ctx, t, ctr, renderRuleset(t, oneSlot, nil))
	netns.Apply(ctx, t, ctr, link.FencingRuleset(oneSlot, []int{0}))

	assertGatewayState(ctx, t, ctr, fsLinkID, wantGatewayState(slotA), "after the pass that dropped slot 2")
	if got := probeFrom(ctx, t, ctr, tcpProbe, "clientA", fsSlotANodeAddr, gwIdent.HealthPort); got != "OK" {
		t.Errorf("probe through the slot the config kept = %q, want %q", got, "OK")
	}
}

// replayDepartedTeardown replays teardown commands in the network namespace.
func replayDepartedTeardown(ctx context.Context, t testing.TB, ctr testcontainers.Container, previous, current link.RuntimeConfig) []string {
	t.Helper()
	kept := make(map[int]struct{}, len(current.WireGuard.Peers))
	for _, p := range current.WireGuard.Peers {
		kept[p.Slot] = struct{}{}
	}
	departed := previous
	departed.WireGuard.Peers = nil
	for _, p := range previous.WireGuard.Peers {
		if _, ok := kept[p.Slot]; !ok {
			departed.WireGuard.Peers = append(departed.WireGuard.Peers, p)
		}
	}

	failures := []string{}
	for _, step := range link.TeardownCommands(departed) {
		if step.Name != "ip" {
			continue
		}
		code, out := netns.Exec(ctx, t, ctr, append([]string{step.Name}, step.Args...)...)
		if code != 0 {
			failures = append(failures, strings.TrimSpace(out))
		}
	}
	return failures
}
