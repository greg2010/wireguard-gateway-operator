package e2e

import "fmt"

// Public ports the gateway publishes and the link DNATs to the in-cluster echo
// Services. They drive both the Gateway CR forwards (Port) and the host-side
// probe targets (Stack.TCPPublicPort / Stack.UDPPublicPort).
const (
	tcpPublicPort = 8443
	udpPublicPort = 8444
	// nodePortPublicPort forwards to a NodePort-backed echo Service, exercising
	// the operator's NodePort service-type acceptance through the data path.
	nodePortPublicPort = 8445
	// crossNSPublicPort forwards to an echo Service in a second, consent-labelled
	// namespace, exercising the cross-namespace forward data path end to end.
	crossNSPublicPort = 8446
	// editedPublicPort is added to spec.forwards live by the forward-edit subtest;
	// it is not forwarded at create time. It is listed in forwardedPorts so the
	// negative probe's disjointness check accounts for it even though it only opens
	// after the edit rolls the link.
	editedPublicPort = 8447

	// The lifecycle subtests each attach one dedicated runtime forward on its own
	// public port and remove it again, so they never touch the create-time forwards
	// other subtests assert on. Each is listed in forwardedPorts so the negative
	// probe's disjointness check accounts for it even though it only opens
	// transiently mid-run.
	//
	// serviceCreatedPort: backend Service created after the forward (denied then works).
	// serviceDeletedPort: backend Service deleted under a live forward (works then stops).
	// consentTogglePort:  cross-namespace forward gated by the consent label.
	// targetPortScenarioPort: forward whose targetPort is corrected from non-listening.
	// backendRolloutPort: forward whose backend Deployment is rolled under it (DNAT survives pod churn).
	// forwardRetargetPort: forward retargeted to a second backend Service (bytes follow the retarget).
	serviceCreatedPort     = 8448
	serviceDeletedPort     = 8449
	consentTogglePort      = 8450
	targetPortScenarioPort = 8451
	backendRolloutPort     = 8452
	forwardRetargetPort    = 8453

	// wgListenPort is the gateway VM's default WireGuard UDP port. It must match
	// the chart's wireguard.listenPort default, which the e2e overlay leaves
	// untouched. The negative probe asserts its port is disjoint from this so a
	// future chart change cannot silently make the WG port the negative target. A
	// stack started with WithWireguardListenPort overrides it per gateway.
	wgListenPort = 51820

	// negativePort is the non-forwarded public port the negative probes target.
	// The GCP firewall opens only the forwarded ports plus wgListenPort, so this
	// port is dropped at the firewall. Start asserts it is disjoint from the
	// forwarded ports and wgListenPort, so a future forwards change cannot
	// silently turn the negative probe into a false pass.
	negativePort = 9999
)

// forwardedPorts is the set of public ports the Gateway CR forwards over the
// run, including the ports the forward-edit and lifecycle subtests open
// transiently. The GCP firewall opens at most these (plus the WG listen port) at
// any moment. The negative probe asserts its port is not among them, so a future
// scenario port reusing the negative port fails the disjointness precondition
// rather than silently turning the negative probe into a false pass.
func forwardedPorts() []int {
	return []int{
		tcpPublicPort, udpPublicPort, nodePortPublicPort, crossNSPublicPort, editedPublicPort,
		serviceCreatedPort, serviceDeletedPort, consentTogglePort, targetPortScenarioPort,
		backendRolloutPort, forwardRetargetPort,
	}
}

// negativePortDisjointError returns a non-nil error if negativePort collides
// with any forwarded port or the gateway's WireGuard listen port. A collision
// would silently make the negative probe target an open port, turning a real
// leak into a false pass, so StartE checks this as a setup precondition (a
// Done-criterion, not just prose) before provisioning. wgPort is the stack's
// effective WireGuard listen port, which a per-gateway override can move off the
// default.
func negativePortDisjointError(wgPort int) error {
	if negativePort == wgPort {
		return fmt.Errorf("negative probe port %d collides with the WireGuard listen port %d", negativePort, wgPort)
	}
	for _, p := range forwardedPorts() {
		if negativePort == p {
			return fmt.Errorf("negative probe port %d collides with forwarded port %d", negativePort, p)
		}
	}
	return nil
}
