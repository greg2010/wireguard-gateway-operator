package e2e

import "testing"

// Public ports the gateway publishes and the link DNATs to the in-cluster echo
// Services. They drive both the Gateway CR forwards (Port) and the host-side
// probe targets (Stack.TCPPublicPort / Stack.UDPPublicPort).
const (
	tcpPublicPort = 8443
	udpPublicPort = 8444

	// wgListenPort is the gateway VM's WireGuard UDP port. It must match the
	// chart's wireguard.listenPort default, which the e2e overlay leaves
	// untouched. The negative probe asserts its port is disjoint from this so a
	// future chart change cannot silently make the WG port the negative target.
	wgListenPort = 51820

	// negativePort is the non-forwarded public port the negative probes target.
	// The GCP firewall opens only the forwarded ports plus wgListenPort, so this
	// port is dropped at the firewall. Start asserts it is disjoint from the
	// forwarded ports and wgListenPort, so a future forwards change cannot
	// silently turn the negative probe into a false pass.
	negativePort = 9999
)

// forwardedPorts is the set of public ports the Gateway CR forwards; the GCP
// firewall opens exactly these (plus the WG listen port and ICMP). The negative
// probe asserts its port is not among them.
func forwardedPorts() []int {
	return []int{tcpPublicPort, udpPublicPort}
}

// assertNegativePortDisjoint fails the test if negativePort collides with any
// forwarded port or the WireGuard listen port. A collision would silently make
// the negative probe target an open port, turning a real leak into a false pass,
// so this is a setup precondition (a Done-criterion, not just prose).
func assertNegativePortDisjoint(t *testing.T) {
	t.Helper()
	if negativePort == wgListenPort {
		t.Fatalf("negative probe port %d collides with the WireGuard listen port %d", negativePort, wgListenPort)
	}
	for _, p := range forwardedPorts() {
		if negativePort == p {
			t.Fatalf("negative probe port %d collides with forwarded port %d", negativePort, p)
		}
	}
}
