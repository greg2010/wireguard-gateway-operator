package linkint

import (
	"context"
	"testing"
	"time"

	"github.com/greg2010/wireguard-gateway-operator/internal/link"
	"github.com/testcontainers/testcontainers-go"
)

// TestFenceRemovesDataPlane applies the real rendered ruleset, then fences and
// asserts both wg0 and the inet gateway table are gone. It reproduces link.Teardown's
// two commands because Teardown takes an unexported runner this package cannot call.
func TestFenceRemovesDataPlane(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	ctr := startNftContainer(ctx, t)

	// The rendered ruleset is the exact document the daemon loads, so the table the
	// fence deletes is created by production code, not a stand-in.
	forwards := []link.ResolvedForward{
		{Name: "tcp-svc", PublicPort: 8443, Protocol: "tcp", ClusterIP: "10.96.1.1", TargetPort: 443},
		{Name: "udp-svc", PublicPort: 30000, Protocol: "udp", ClusterIP: "10.96.2.2", TargetPort: 9000},
	}
	applyRuleset(ctx, t, ctr, renderRuleset(t, forwards))

	// The fence is only meaningful if there is a data plane to tear down.
	if !wg0Present(ctx, t, ctr) {
		t.Fatal("precondition failed: wg0 absent before fence")
	}
	if !gatewayTablePresent(ctx, t, ctr) {
		t.Fatal("precondition failed: inet gateway table absent before fence")
	}

	fence(ctx, t, ctr)

	// A demoted replica that left either object behind would keep carrying traffic
	// after losing leadership, the failure the fence prevents.
	if wg0Present(ctx, t, ctr) {
		t.Error("wg0 still present after fence; the demoted replica's interface was not removed")
	}
	if gatewayTablePresent(ctx, t, ctr) {
		t.Error("inet gateway table still present after fence; the demoted replica's nftables data plane was not removed")
	}
}

// fence runs the two commands link.Teardown issues, in order: delete wg0, then
// delete the inet gateway table. Each must succeed since the test programmed both.
func fence(ctx context.Context, t testing.TB, ctr testcontainers.Container) {
	t.Helper()
	if code, out := execInContainer(ctx, t, ctr, "ip", "link", "del", "wg0"); code != 0 {
		t.Fatalf("fence: ip link del wg0 failed (exit %d):\n%s", code, out)
	}
	if code, out := execInContainer(ctx, t, ctr, "nft", "delete", "table", "inet", "gateway"); code != 0 {
		t.Fatalf("fence: nft delete table inet gateway failed (exit %d):\n%s", code, out)
	}
}

// wg0Present reports whether the wg0 interface exists in the container.
func wg0Present(ctx context.Context, t testing.TB, ctr testcontainers.Container) bool {
	t.Helper()
	code, _ := execInContainer(ctx, t, ctr, "ip", "link", "show", "wg0")
	return code == 0
}

// gatewayTablePresent reports whether the inet gateway nftables table exists in the
// container. The identifier matches RenderNftables and the fence's delete target.
func gatewayTablePresent(ctx context.Context, t testing.TB, ctr testcontainers.Container) bool {
	t.Helper()
	code, _ := execInContainer(ctx, t, ctr, "nft", "list", "table", "inet", "gateway")
	return code == 0
}
