package e2e

import "fmt"

// Public ports the gateway publishes and the link DNATs to the in-cluster echo
// Services.
const (
	tcpPublicPort = 8443
	udpPublicPort = 8444
	// nodePortPublicPort forwards to a NodePort-backed echo Service, exercising the
	// operator's NodePort service-type acceptance.
	nodePortPublicPort = 8445
	// crossNSPublicPort forwards to an echo Service in a consent-labelled namespace.
	crossNSPublicPort = 8446
	// editedPublicPort is added live by the forward-edit subtest, not at create
	// time; it is still in forwardedPorts so the disjointness check accounts for it.
	editedPublicPort = 8447

	// The lifecycle subtests each attach one dedicated runtime forward on its own
	// port and remove it again, so they never touch the create-time forwards. Each
	// is in forwardedPorts so the disjointness check covers its transient opening.
	serviceCreatedPort     = 8448
	serviceDeletedPort     = 8449
	consentTogglePort      = 8450
	targetPortScenarioPort = 8451
	backendRolloutPort     = 8452
	forwardRetargetPort    = 8453

	// wgListenPort must match the chart's wireguard.listenPort default, which the
	// e2e overlay leaves untouched. WithWireguardListenPort overrides it per gateway.
	wgListenPort = 51820

	// negativePort is the non-forwarded public port the negative probes target,
	// dropped at the GCP firewall. Start asserts it is disjoint from the forwarded
	// and WG ports so a future change cannot silently make the probe a false pass.
	negativePort = 9999
)

// forwardedPorts is every public port the Gateway CR forwards over the run,
// including the ports the lifecycle subtests open transiently. The negative probe
// asserts its port is not among them.
func forwardedPorts() []int {
	return []int{
		tcpPublicPort, udpPublicPort, nodePortPublicPort, crossNSPublicPort, editedPublicPort,
		serviceCreatedPort, serviceDeletedPort, consentTogglePort, targetPortScenarioPort,
		backendRolloutPort, forwardRetargetPort,
	}
}

// negativePortDisjointError errors if negativePort collides with a forwarded port or
// wgPort (the stack's effective WireGuard port), which would point the negative probe
// at an open port and turn a real leak into a false pass.
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
