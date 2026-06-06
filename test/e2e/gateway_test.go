package e2e_test

import (
	"context"
	"testing"
)

// TestGatewayDataPath validates the whole operator system against real GCP: it
// installs the operator into the cluster, creates a Gateway CR that provisions a
// real e2-micro gateway with an ephemeral IP, forwards an in-cluster TCP (HTTP)
// echo and a UDP echo through the gateway, and asserts both are reachable from
// the host on the gateway's public IP. It also asserts a non-forwarded public
// port is NOT reachable (tcp and udp), proving the GCP firewall and DNAT closure
// hold jointly. Teardown (registered by Start) deletes the Gateway, waits for
// Crossplane to drain every GCP resource the run created, then uninstalls.
func TestGatewayDataPath(t *testing.T) {
	t.Parallel()

	suite := getSuite(t)
	ctx := context.Background()

	stack, err := suite.Start(ctx, t)
	if err != nil {
		t.Fatalf("start stack: %v", err)
	}

	if stack.Address == "" {
		t.Fatal("gateway reported no public IP")
	}
	t.Logf("gateway public IP: %s", stack.Address)

	t.Run("tcp", func(t *testing.T) {
		marker, err := probeTCPThroughGateway(ctx, stack)
		if err != nil {
			t.Fatalf("tcp data path: %v", err)
		}
		// agnhost /hostname returns the serving pod name; a non-empty marker
		// proves the request reached the in-cluster echo pod through the tunnel.
		if marker == "" {
			t.Fatal("tcp echo returned an empty marker")
		}
		t.Logf("tcp echo marker (echo pod name): %s", marker)
	})

	t.Run("udp", func(t *testing.T) {
		const payload = "cyno-e2e-udp-probe"
		got, err := probeUDPThroughGateway(ctx, stack, payload)
		if err != nil {
			t.Fatalf("udp data path: %v", err)
		}
		if got != payload {
			t.Fatalf("udp echo = %q, want %q", got, payload)
		}
	})

	// Negative probes: a non-forwarded public port must NOT reach the pod. The
	// GCP firewall opens only the forwarded ports and the WireGuard port, so
	// these assert the firewall and DNAT closure jointly. Start has already
	// asserted stack.NegativePort is disjoint from the forwarded ports and the
	// WireGuard listen port, so a hit here is a real leak, not a misconfigured
	// probe.
	t.Run("tcp-denied", func(t *testing.T) {
		if err := probeTCPDenied(ctx, stack, stack.NegativePort); err != nil {
			t.Fatalf("tcp negative probe: %v", err)
		}
	})

	t.Run("udp-denied", func(t *testing.T) {
		if err := probeUDPDenied(ctx, stack, stack.NegativePort, "cyno-e2e-udp-denied"); err != nil {
			t.Fatalf("udp negative probe: %v", err)
		}
	})
}
