package linkint

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/greg2010/wireguard-gateway-operator/internal/link"
	"github.com/greg2010/wireguard-gateway-operator/test/harness/netns"
	"github.com/testcontainers/testcontainers-go"
)

func TestFenceRemovesDataPlane(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	ctr := startNftContainer(ctx, t)

	// The rendered ruleset is the exact document the daemon loads, so the table the
	// fence deletes is created by production code, not a stand-in.
	forwards := []link.ResolvedForward{
		{Name: "tcp-svc", PublicPort: 8443, Protocol: "tcp", Target: "10.96.1.1", TargetPort: 443},
		{Name: "udp-svc", PublicPort: 30000, Protocol: "udp", Target: "10.96.2.2", TargetPort: 9000},
	}
	rc := link.RuntimeConfig{}
	netns.Apply(ctx, t, ctr, renderRuleset(t, rc, forwards))

	// The fence is only meaningful if there is a data plane to tear down.
	if !ifacePresent(ctx, t, ctr, "wg0") {
		t.Fatal("precondition failed: wg0 absent before fence")
	}
	if !nftTablePresent(ctx, t, ctr, "gateway") {
		t.Fatal("precondition failed: inet gateway table absent before fence")
	}

	runTeardownPlan(ctx, t, ctr, rc)

	// A demoted replica that left either object behind would keep carrying traffic
	// after losing leadership, the failure the fence prevents.
	if ifacePresent(ctx, t, ctr, "wg0") {
		t.Error("wg0 still present after fence; the demoted replica's interface was not removed")
	}
	if nftTablePresent(ctx, t, ctr, "gateway") {
		t.Error("inet gateway table still present after fence; the demoted replica's nftables data plane was not removed")
	}
}

// TestLocalFenceRemovesNodeState covers node-global state: an fwmark rule or route table
// left behind outlives the link pod and diverts the node's traffic into an empty table.
func TestLocalFenceRemovesNodeState(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	ident := link.NewIdentity(lpLinkID)
	rc := link.RuntimeConfig{TrafficPolicy: link.TrafficPolicyLocal, Identity: &ident}
	forwards := []link.ResolvedForward{
		{Name: "tcp-8443", PublicPort: lpPublicPort, Protocol: "tcp", Target: lpPodIP, TargetPort: lpPodPort},
	}

	ctr := netns.Start(ctx, t)
	// A dummy stands in for the WireGuard device: the ruleset and the route plan both
	// name it, and nft resolves iifname at load time.
	if code, out := netns.Exec(ctx, t, ctr, "ip", "link", "add", ident.Interface, "type", "dummy"); code != 0 {
		t.Fatalf("ip link add %s failed (exit %d):\n%s", ident.Interface, code, out)
	}
	if code, out := netns.Exec(ctx, t, ctr, "ip", "link", "set", ident.Interface, "up"); code != 0 {
		t.Fatalf("ip link set %s up failed (exit %d):\n%s", ident.Interface, code, out)
	}
	programLocalRoutes(ctx, t, ctr, ident, []string{lpPodIP})
	netns.Apply(ctx, t, ctr, renderRuleset(t, rc, forwards))

	if n := countPlanRules(ctx, t, ctr, ident); n != 1 {
		t.Fatalf("precondition failed: %d ip rules match the plan before the fence, want 1", n)
	}
	if !nftTablePresent(ctx, t, ctr, ident.NftTable) {
		t.Fatalf("precondition failed: inet %s table absent before the fence", ident.NftTable)
	}

	runTeardownPlan(ctx, t, ctr, rc)

	if n := countPlanRules(ctx, t, ctr, ident); n != 0 {
		t.Errorf("%d ip rules still match the plan's fwmark %s/%s and table %d after the fence; the rule is node-global and outlives the pod",
			n, ident.Mark, ident.MarkMask, ident.RouteTable)
	}
	table := strconv.Itoa(ident.RouteTable)
	code, out := netns.Exec(ctx, t, ctr, "ip", "route", "show", "table", table)
	if code != 0 {
		t.Fatalf("ip route show table %s failed (exit %d):\n%s", table, code, out)
	}
	if strings.TrimSpace(out) != "" {
		t.Errorf("route table %s still holds routes after the fence:\n%s", table, out)
	}
	if nftTablePresent(ctx, t, ctr, ident.NftTable) {
		t.Errorf("inet %s table still present after the fence", ident.NftTable)
	}
	if ifacePresent(ctx, t, ctr, ident.Interface) {
		t.Errorf("%s still present after the fence", ident.Interface)
	}
}

// runTeardownPlan runs the product's teardown plan in order. The test programmed every
// object the plan removes, so each step must succeed.
func runTeardownPlan(ctx context.Context, t testing.TB, ctr testcontainers.Container, rc link.RuntimeConfig) {
	t.Helper()
	for _, step := range link.TeardownCommands(rc) {
		code, out := netns.Exec(ctx, t, ctr, append([]string{step.Name}, step.Args...)...)
		if code != 0 {
			t.Fatalf("fence: %s %s failed (exit %d):\n%s", step.Name, strings.Join(step.Args, " "), code, out)
		}
	}
}

func ifacePresent(ctx context.Context, t testing.TB, ctr testcontainers.Container, iface string) bool {
	t.Helper()
	code, _ := netns.Exec(ctx, t, ctr, "ip", "link", "show", iface)
	return code == 0
}

func nftTablePresent(ctx context.Context, t testing.TB, ctr testcontainers.Container, table string) bool {
	t.Helper()
	code, _ := netns.Exec(ctx, t, ctr, "nft", "list", "table", "inet", table)
	return code == 0
}
