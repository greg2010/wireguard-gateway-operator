// Package linkint exercises the link daemon's rendered nftables ruleset against a
// real nft binary in a container, asserting the document is self-replacing and that
// dropping a forward removes its DNAT rule.
package linkint

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/greg2010/wireguard-gateway-operator/internal/link"
	"github.com/moby/moby/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	// nftImage is pinned so the netns programming runs against a known nftables build.
	nftImage = "alpine:3.20"

	// rulesetPath stands in for `nft -f -` because exec cannot pipe stdin; the
	// transaction nft runs is identical.
	rulesetPath = "/tmp/ruleset.nft"

	containerStartTimeout = 2 * time.Minute
	execTimeout           = 30 * time.Second
)

func TestNftablesApplyIsSelfReplacing(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	ctr := startNftContainer(ctx, t)

	twoForwards := []link.ResolvedForward{
		{Name: "tcp-svc", PublicPort: 8443, Protocol: "tcp", ClusterIP: "10.96.1.1", TargetPort: 443},
		{Name: "udp-svc", PublicPort: 30000, Protocol: "udp", ClusterIP: "10.96.2.2", TargetPort: 9000},
	}

	rulesetTwo := renderRuleset(t, twoForwards)

	applyRuleset(ctx, t, ctr, rulesetTwo)
	firstListing := listTable(ctx, t, ctr)
	firstDNAT := countDNATRules(firstListing)
	if firstDNAT != len(twoForwards) {
		t.Fatalf("after first apply: DNAT rule count = %d, want %d\n%s", firstDNAT, len(twoForwards), firstListing)
	}

	applyRuleset(ctx, t, ctr, rulesetTwo)
	secondListing := listTable(ctx, t, ctr)

	if got := countDNATRules(secondListing); got != firstDNAT {
		t.Errorf("DNAT rule count changed after re-applying the same ruleset: first=%d second=%d (flush did not clear)\n%s",
			firstDNAT, got, secondListing)
	}
	if firstListing != secondListing {
		t.Errorf("table listing differs after re-applying the same ruleset; the document is not self-replacing\nfirst:\n%s\nsecond:\n%s",
			firstListing, secondListing)
	}

	oneForward := []link.ResolvedForward{twoForwards[0]}
	rulesetOne := renderRuleset(t, oneForward)
	applyRuleset(ctx, t, ctr, rulesetOne)
	prunedListing := listTable(ctx, t, ctr)

	removedDNAT := dnatRuleFor(twoForwards[1])
	if strings.Contains(prunedListing, removedDNAT) {
		t.Errorf("DNAT rule for the removed forward is still present after re-apply: %q\n%s", removedDNAT, prunedListing)
	}
	keptDNAT := dnatRuleFor(twoForwards[0])
	if !strings.Contains(prunedListing, keptDNAT) {
		t.Errorf("DNAT rule for the retained forward is missing after re-apply: %q\n%s", keptDNAT, prunedListing)
	}
	if got := countDNATRules(prunedListing); got != len(oneForward) {
		t.Errorf("after pruning to one forward: DNAT rule count = %d, want %d\n%s", got, len(oneForward), prunedListing)
	}
}

// TestNftablesRetargetReplacesClusterIP repoints a forward from ClusterIP_A to
// ClusterIP_B and asserts the ruleset DNATs and accepts B, references A nowhere, and
// programs exactly one forward, so a stale or diverging rule surfaces as a blackhole.
func TestNftablesRetargetReplacesClusterIP(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	ctr := startNftContainer(ctx, t)

	const (
		retargetPort     = 8453
		retargetProtocol = "tcp"
		retargetTarget   = 443
		clusterIPA       = "10.96.0.10"
		clusterIPB       = "10.96.0.20"
	)

	forwardA := link.ResolvedForward{Name: "retarget", PublicPort: retargetPort, Protocol: retargetProtocol, ClusterIP: clusterIPA, TargetPort: retargetTarget}
	forwardB := link.ResolvedForward{Name: "retarget", PublicPort: retargetPort, Protocol: retargetProtocol, ClusterIP: clusterIPB, TargetPort: retargetTarget}

	applyRuleset(ctx, t, ctr, renderRuleset(t, []link.ResolvedForward{forwardA}))
	beforeListing := listTable(ctx, t, ctr)
	if dnat := dnatRuleFor(forwardA); !strings.Contains(beforeListing, dnat) {
		t.Fatalf("before retarget: DNAT to ClusterIP_A missing: %q\n%s", dnat, beforeListing)
	}

	applyRuleset(ctx, t, ctr, renderRuleset(t, []link.ResolvedForward{forwardB}))
	afterListing := listTable(ctx, t, ctr)

	wantDNAT := dnatRuleFor(forwardB)
	if !strings.Contains(afterListing, wantDNAT) {
		t.Errorf("after retarget: DNAT to ClusterIP_B missing: %q\n%s", wantDNAT, afterListing)
	}
	wantAccept := acceptRuleFor(forwardB)
	if !strings.Contains(afterListing, wantAccept) {
		t.Errorf("after retarget: forward accept rule for daddr B missing: %q\n%s", wantAccept, afterListing)
	}

	staleDNAT := dnatRuleFor(forwardA)
	if strings.Contains(afterListing, staleDNAT) {
		t.Errorf("after retarget: stale DNAT to ClusterIP_A survives: %q\n%s", staleDNAT, afterListing)
	}
	staleAccept := acceptRuleFor(forwardA)
	if strings.Contains(afterListing, staleAccept) {
		t.Errorf("after retarget: stale accept rule for daddr A survives: %q\n%s", staleAccept, afterListing)
	}
	if n := strings.Count(afterListing, clusterIPA); n != 0 {
		t.Errorf("after retarget: ClusterIP_A %q still referenced %d time(s) in the ruleset; a retarget must leave no rule pointing at the old target\n%s",
			clusterIPA, n, afterListing)
	}
	if got := countDNATRules(afterListing); got != 1 {
		t.Errorf("after retarget: DNAT rule count = %d, want 1 (the single retargeted forward)\n%s", got, afterListing)
	}
}

// startNftContainer brings up the pinned image, installs nft, and returns the
// running container, terminated when t finishes. NET_ADMIN lets nft program the
// netns; Privileged is a fallback for runtimes that ignore the capability add.
func startNftContainer(ctx context.Context, t testing.TB) testcontainers.Container {
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
		t.Fatalf("start nft container: %v", err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(context.Background()) })

	installPackages(ctx, t, ctr)
	createWG0(ctx, t, ctr)
	return ctr
}

// installPackages installs nft and the ip tooling. An apk failure is a real
// environment failure, not a reason to skip.
func installPackages(ctx context.Context, t testing.TB, ctr testcontainers.Container) {
	t.Helper()
	code, out := execInContainer(ctx, t, ctr, "apk", "add", "--no-cache", "nftables", "iproute2")
	if code != 0 {
		t.Fatalf("apk add nftables iproute2 failed (exit %d):\n%s", code, out)
	}
}

// createWG0 adds a dummy wg0 so the ruleset loads: the rules match `iif "wg0"`,
// which nft resolves to an interface index at load time and rejects when absent. It
// reproduces production's precondition without a real WireGuard tunnel.
func createWG0(ctx context.Context, t testing.TB, ctr testcontainers.Container) {
	t.Helper()
	code, out := execInContainer(ctx, t, ctr, "ip", "link", "add", "wg0", "type", "dummy")
	if code != 0 {
		t.Fatalf("ip link add wg0 failed (exit %d):\n%s", code, out)
	}
}

// renderRuleset renders forwards through the production RenderNftables, the same
// bytes the daemon pipes to `nft -f -`.
func renderRuleset(t testing.TB, forwards []link.ResolvedForward) string {
	t.Helper()
	out, err := link.RenderNftables(forwards)
	if err != nil {
		t.Fatalf("RenderNftables: %v", err)
	}
	return out
}

// applyRuleset copies the rendered document into the container and loads it with
// `nft -f`, the atomic transaction the daemon relies on.
func applyRuleset(ctx context.Context, t testing.TB, ctr testcontainers.Container, ruleset string) {
	t.Helper()
	if err := ctr.CopyToContainer(ctx, []byte(ruleset), rulesetPath, 0o644); err != nil {
		t.Fatalf("copy ruleset to container: %v", err)
	}
	code, out := execInContainer(ctx, t, ctr, "nft", "-f", rulesetPath)
	if code != 0 {
		t.Fatalf("nft -f %s failed (exit %d):\n%s\n--- ruleset ---\n%s", rulesetPath, code, out, ruleset)
	}
}

// listTable returns the kernel's view of the gateway table after an apply.
func listTable(ctx context.Context, t testing.TB, ctr testcontainers.Container) string {
	t.Helper()
	code, out := execInContainer(ctx, t, ctr, "nft", "list", "table", "inet", "gateway")
	if code != 0 {
		t.Fatalf("nft list table inet gateway failed (exit %d):\n%s", code, out)
	}
	return out
}

// execInContainer runs cmd and returns its exit code and combined output.
func execInContainer(ctx context.Context, t testing.TB, ctr testcontainers.Container, cmd ...string) (int, string) {
	t.Helper()
	execCtx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()

	code, reader, err := ctr.Exec(execCtx, cmd, tcexec.Multiplexed())
	if err != nil {
		t.Fatalf("exec %v: %v", cmd, err)
	}
	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read output of %v: %v", cmd, err)
	}
	return code, string(out)
}

// countDNATRules counts the DNAT rule lines in an `nft list table` dump. Each
// forward renders exactly one, so the count equals the forwards programmed.
func countDNATRules(listing string) int {
	return strings.Count(listing, "dnat ip to")
}

// dnatRuleFor returns the prerouting DNAT statement RenderNftables emits for f, as
// it appears in `nft list table` output.
func dnatRuleFor(f link.ResolvedForward) string {
	return fmt.Sprintf("%s dport %d dnat ip to %s:%d", f.Protocol, f.PublicPort, f.ClusterIP, f.TargetPort)
}

// acceptRuleFor returns the forward-chain accept statement RenderNftables emits for
// f. It keys on the post-DNAT destination (ClusterIP and target port), so a retarget
// must move it in lockstep with the DNAT.
func acceptRuleFor(f link.ResolvedForward) string {
	return fmt.Sprintf("iif \"wg0\" ip daddr %s %s dport %d accept", f.ClusterIP, f.Protocol, f.TargetPort)
}
