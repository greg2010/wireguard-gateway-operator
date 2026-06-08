package e2e_test

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"
	policyv1 "k8s.io/api/policy/v1"

	e2eharness "github.com/greg2010/wireguard-gateway-operator/test/harness/e2e"
	hk8s "github.com/greg2010/wireguard-gateway-operator/test/harness/k8s"
)

// Ready=False reasons the lifecycle subtests assert on, mirroring the operator's
// unexported reason constants.
const (
	crossNamespaceForwardDeniedReason = "CrossNamespaceForwardDenied"
	serviceNotFoundReason             = "ServiceNotFound"
	targetPortNotListeningReason      = "TargetPortNotListening"
)

// consentLabel and consentValue are the cross-namespace ingress consent label,
// mirroring the operator's unexported gate.
const (
	consentLabel = "wgnet.dev/allow-gateway-ingress"
	consentValue = "true"
)

// lifecycleConditionTimeout bounds a lifecycle subtest's wait for the operator to
// re-stamp Ready after a forward/backend/consent change: a re-classification and
// status write, not a GCP round trip.
const lifecycleConditionTimeout = 90 * time.Second

// lifecycleReadyTimeout bounds a lifecycle subtest's wait for the Gateway to return
// Ready after a forward becomes valid, sharing editRollTimeout's budget.
const lifecycleReadyTimeout = editRollTimeout

// deniedConditionTimeout bounds the wait for a validation-failure Gateway to report
// Ready=False, decided on the first reconcile and so short.
const deniedConditionTimeout = 90 * time.Second

// editRollTimeout bounds the wait for the Gateway to return Ready after a live
// forward edit (re-render, in-place nftables re-apply, fresh handshake), with no
// pod replacement.
const editRollTimeout = 3 * time.Minute

// coexistWGListenPortA and coexistWGListenPortB are the distinct WireGuard listen
// ports TestGatewayCoexistence gives its two gateways, so the isolation assertion
// can prove each rule admits only its own WG port.
const (
	coexistWGListenPortA = 51820
	coexistWGListenPortB = 51821
)

// TestGatewayCoexistence validates that two gateways sharing one GCP VPC are isolated
// by per-gateway service-account scoping: each serves only its own forwards, the
// other's port is dropped at its firewall, and one VPC backs both.
func TestGatewayCoexistence(t *testing.T) {
	t.Parallel()

	suite := getSuite(t)
	ctx := context.Background()

	// Distinct WG and exposed ports make the firewall isolation assertion below a
	// real test of per-gateway targetServiceAccounts scoping, not port bookkeeping.
	// Bring-up errors are re-raised on the test goroutine, where t.Fatal is legal.
	var stackA, stackB *e2eharness.Stack
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		s, err := suite.StartE(gctx, t, e2eharness.WithWireguardListenPort(coexistWGListenPortA))
		if err != nil {
			return fmt.Errorf("start stack A: %w", err)
		}
		stackA = s
		return nil
	})
	g.Go(func() error {
		s, err := suite.StartE(gctx, t, e2eharness.WithWireguardListenPort(coexistWGListenPortB))
		if err != nil {
			return fmt.Errorf("start stack B: %w", err)
		}
		stackB = s
		return nil
	})
	if err := g.Wait(); err != nil {
		t.Fatalf("provision coexisting gateways: %v", err)
	}

	if stackA.Address == "" || stackB.Address == "" {
		t.Fatalf("a gateway reported no public IP (A=%q B=%q)", stackA.Address, stackB.Address)
	}
	t.Logf("coexisting gateways: A=%s B=%s", stackA.Address, stackB.Address)

	client := suite.Client()

	// Distinctly named backends so a marker identifies which gateway answered.
	const (
		backendA = "gateway-echo-coexist-a"
		backendB = "gateway-echo-coexist-b"
	)
	if _, err := client.DeployEchoBackend(ctx, stackA.Namespace, backendA); err != nil {
		t.Fatalf("deploy coexistence backend A: %v", err)
	}
	if _, err := client.DeployEchoBackend(ctx, stackB.Namespace, backendB); err != nil {
		t.Fatalf("deploy coexistence backend B: %v", err)
	}

	if err := client.UpdateGateway(ctx, stackA.Namespace, stackA.GatewayName, func(spec map[string]any) error {
		return appendForward(spec, hk8s.GatewayForward{
			Port: stackA.ServiceCreatedPort, Protocol: "TCP", Service: backendA, TargetPort: stackA.TCPBackendPort,
		})
	}); err != nil {
		t.Fatalf("forward coexistence backend A: %v", err)
	}
	if err := client.UpdateGateway(ctx, stackB.Namespace, stackB.GatewayName, func(spec map[string]any) error {
		return appendForward(spec, hk8s.GatewayForward{
			Port: stackB.ServiceDeletedPort, Protocol: "TCP", Service: backendB, TargetPort: stackB.TCPBackendPort,
		})
	}); err != nil {
		t.Fatalf("forward coexistence backend B: %v", err)
	}

	if _, err := client.WaitGatewayReady(ctx, stackA.Namespace, stackA.GatewayName, lifecycleReadyTimeout); err != nil {
		t.Fatalf("gateway A not ready after coexistence forward: %v", err)
	}
	if _, err := client.WaitGatewayReady(ctx, stackB.Namespace, stackB.GatewayName, lifecycleReadyTimeout); err != nil {
		t.Fatalf("gateway B not ready after coexistence forward: %v", err)
	}

	// The just-added forward uses the edit budget: the link's new nftables rule is
	// not trailed by the readiness gate.
	markerA, err := probeTCPThroughGatewayPortUntil(ctx, stackA, stackA.ServiceCreatedPort, editRollTimeout)
	if err != nil {
		t.Fatalf("gateway A data path: %v", err)
	}
	assertBackendMarker(t, markerA, backendA)
	markerB, err := probeTCPThroughGatewayPortUntil(ctx, stackB, stackB.ServiceDeletedPort, editRollTimeout)
	if err != nil {
		t.Fatalf("gateway B data path: %v", err)
	}
	assertBackendMarker(t, markerB, backendB)

	// Neither gateway forwards the other's port, so the SYN is dropped immediately;
	// the port was never opened here, so no propagation wait is needed.
	if err := probeTCPDenied(ctx, stackA, stackB.ServiceDeletedPort); err != nil {
		t.Fatalf("gateway A leaked gateway B's port %d: %v", stackB.ServiceDeletedPort, err)
	}
	if err := probeTCPDenied(ctx, stackB, stackA.ServiceCreatedPort); err != nil {
		t.Fatalf("gateway B leaked gateway A's port %d: %v", stackA.ServiceCreatedPort, err)
	}

	// Assert at the firewall-rule level that each gateway's rules target only its own
	// SA and WG port, more reliable than a silently-dropped UDP data-path probe.
	saA, err := suite.GatewayServiceAccountEmail(ctx, stackA.Namespace, stackA.GatewayName)
	if err != nil {
		t.Fatalf("read gateway A service account email: %v", err)
	}
	saB, err := suite.GatewayServiceAccountEmail(ctx, stackB.Namespace, stackB.GatewayName)
	if err != nil {
		t.Fatalf("read gateway B service account email: %v", err)
	}
	if saA == "" || saB == "" {
		t.Fatalf("a gateway reported no service account email (A=%q B=%q)", saA, saB)
	}
	if saA == saB {
		t.Fatalf("gateways share service account email %q; want distinct per-gateway SAs", saA)
	}
	assertFirewallIsolation(ctx, t, suite, stackA, saA, saB, stackB.WireguardListenPort)
	assertFirewallIsolation(ctx, t, suite, stackB, saB, saA, stackA.WireguardListenPort)

	// The VPC is created once on the first gateway and reused, never duplicated.
	n, err := suite.SharedNetworkCount(ctx)
	if err != nil {
		t.Fatalf("count shared networks: %v", err)
	}
	if n != 1 {
		t.Fatalf("shared network count = %d, want exactly 1 backing both gateways", n)
	}
}

// assertFirewallIsolation fails unless every firewall rule for stack's gateway
// targets only ownSA, and the gateway's own WireGuard port appears in some rule's
// allowed UDP ports while otherWG does not.
func assertFirewallIsolation(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack, ownSA, otherSA string, otherWG int) {
	t.Helper()

	rules, err := suite.GatewayFirewallTargets(ctx, stack.NamePrefix)
	if err != nil {
		t.Fatalf("list firewall rules for gateway %s: %v", stack.NamePrefix, err)
	}
	if len(rules) == 0 {
		t.Fatalf("gateway %s has no firewall rules; want at least one scoped to its SA", stack.NamePrefix)
	}

	ownWGPort := strconv.Itoa(stack.WireguardListenPort)
	otherWGPort := strconv.Itoa(otherWG)
	sawOwnWG := false
	for _, rule := range rules {
		// The caller asserted ownSA != otherSA, so a single ownSA target also proves
		// the rule never opens this gateway's ports on the other's VM.
		if len(rule.TargetServiceAccounts) != 1 || rule.TargetServiceAccounts[0] != ownSA {
			t.Fatalf("firewall rule %q targets %v, want exactly [%s] (and never the other gateway's SA %s)",
				rule.Name, rule.TargetServiceAccounts, ownSA, otherSA)
		}
		for _, allowed := range rule.Allowed {
			if !strings.EqualFold(allowed.Protocol, "udp") {
				continue
			}
			for _, p := range allowed.Ports {
				if p == ownWGPort {
					sawOwnWG = true
				}
				if p == otherWGPort {
					t.Fatalf("firewall rule %q admits the other gateway's WireGuard port %s; WG ports leak across gateways", rule.Name, otherWGPort)
				}
			}
		}
	}
	if !sawOwnWG {
		t.Fatalf("gateway %s firewall rules do not admit its own WireGuard port %s", stack.NamePrefix, ownWGPort)
	}
}

// TestGatewayDataPath validates the data path against real GCP: forwarded TCP/UDP
// echoes (ClusterIP, NodePort, cross-namespace) are reachable on the public IP while
// non-forwarded ports and internet ICMP are not, proving firewall and DNAT closure.
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
		// The marker's prefix proves the request reached the intended echo pod, not
		// merely some pod.
		assertBackendMarker(t, marker, stack.TCPBackendName)
		t.Logf("tcp echo marker (echo pod name): %s", marker)
	})

	t.Run("udp", func(t *testing.T) {
		const payload = "gateway-e2e-udp-probe"
		got, err := probeUDPThroughGateway(ctx, stack, payload)
		if err != nil {
			t.Fatalf("udp data path: %v", err)
		}
		if got != payload {
			t.Fatalf("udp echo = %q, want %q", got, payload)
		}
	})

	t.Run("nodeport", func(t *testing.T) {
		marker, err := probeTCPThroughGatewayPort(ctx, stack, stack.NodePortPublicPort)
		if err != nil {
			t.Fatalf("nodeport data path: %v", err)
		}
		assertBackendMarker(t, marker, stack.NodePortBackendName)
		t.Logf("nodeport echo marker (echo pod name): %s", marker)
	})

	t.Run("cross-namespace", func(t *testing.T) {
		marker, err := probeTCPThroughGatewayPort(ctx, stack, stack.CrossNSPublicPort)
		if err != nil {
			t.Fatalf("cross-namespace data path: %v", err)
		}
		assertBackendMarker(t, marker, stack.CrossNSBackendName)
		t.Logf("cross-namespace echo marker (echo pod name): %s", marker)
	})

	t.Run("icmp-denied", func(t *testing.T) {
		// The firewall does not allow internet-wide ICMP, so a reply is a leak.
		if err := pingDenied(ctx, stack); err != nil {
			t.Fatalf("icmp negative probe: %v", err)
		}
	})

	// Start asserted NegativePort is disjoint from the forwarded and WG ports, so a
	// hit here is a real leak, not a misconfigured probe.
	t.Run("tcp-denied", func(t *testing.T) {
		if err := probeTCPDenied(ctx, stack, stack.NegativePort); err != nil {
			t.Fatalf("tcp negative probe: %v", err)
		}
	})

	t.Run("udp-denied", func(t *testing.T) {
		if err := probeUDPDenied(ctx, stack, stack.NegativePort, "gateway-e2e-udp-denied"); err != nil {
			t.Fatalf("udp negative probe: %v", err)
		}
	})

	// forward-retarget proves the data path tracks a retarget: it points a dedicated
	// forward at one backend then retargets to a second, leaving create-time forwards
	// untouched.
	t.Run("forward-retarget", func(t *testing.T) {
		client := suite.Client()

		// Read inside the cleanup, where t.Failed reflects the final result, to leave
		// a failing data path inspectable.
		preserve := os.Getenv("GATEWAY_E2E_PRESERVE") != ""

		const retargetBackend = "gateway-echo-retarget"
		t.Cleanup(func() {
			if t.Failed() && preserve {
				t.Logf("preserving forward-retarget failure state: forward on port %d and backend %s left in place (GATEWAY_E2E_PRESERVE)", stack.ForwardRetargetPort, retargetBackend)
				return
			}
			cctx := context.Background()
			if err := client.UpdateGateway(cctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
				return removeForward(spec, stack.ForwardRetargetPort)
			}); err != nil {
				t.Logf("cleanup remove forward-retarget forward: %v", err)
			}
			if err := client.DeleteService(cctx, stack.Namespace, retargetBackend); err != nil {
				t.Logf("cleanup delete service %s: %v", retargetBackend, err)
			}
			if err := client.DeleteDeployment(cctx, stack.Namespace, retargetBackend); err != nil {
				t.Logf("cleanup delete deployment %s: %v", retargetBackend, err)
			}
		})

		// Forward the dedicated port to the create-time echo first; the marker proves
		// traffic reaches the original backend before the retarget.
		if _, err := client.DeployEchoBackend(ctx, stack.Namespace, retargetBackend); err != nil {
			t.Fatalf("deploy retarget backend: %v", err)
		}
		// The echo has no readinessProbe, so gate on it serving before the retarget's
		// DNAT goes live, else the probe blackholes for the full window.
		if err := client.WaitDeploymentAvailable(ctx, stack.Namespace, retargetBackend, lifecycleReadyTimeout); err != nil {
			t.Fatalf("retarget backend not available: %v", err)
		}
		if err := client.WaitEndpointsReady(ctx, stack.Namespace, retargetBackend, lifecycleReadyTimeout); err != nil {
			t.Fatalf("retarget backend has no ready endpoints: %v", err)
		}
		if err := client.UpdateGateway(ctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
			return appendForward(spec, hk8s.GatewayForward{
				Port: stack.ForwardRetargetPort, Protocol: "TCP",
				Service: stack.TCPBackendName, TargetPort: stack.TCPBackendPort,
			})
		}); err != nil {
			t.Fatalf("add forward to retarget origin: %v", err)
		}
		if _, err := client.WaitGatewayReady(ctx, stack.Namespace, stack.GatewayName, lifecycleReadyTimeout); err != nil {
			t.Fatalf("gateway not ready after forward-retarget origin added: %v", err)
		}
		origin, err := probeTCPThroughGatewayPort(ctx, stack, stack.ForwardRetargetPort)
		if err != nil {
			t.Fatalf("forward-retarget origin data path: %v", err)
		}
		assertBackendMarker(t, origin, stack.TCPBackendName)

		// The link reloads its ConfigMap in place, so its DNAT can trail Ready and a
		// single probe can catch the old backend; poll until the marker leaves origin.
		if err := client.UpdateGateway(ctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
			return setForwardService(spec, stack.ForwardRetargetPort, retargetBackend, "")
		}); err != nil {
			t.Fatalf("retarget forward to second backend: %v", err)
		}
		if _, err := client.WaitGatewayReady(ctx, stack.Namespace, stack.GatewayName, lifecycleReadyTimeout); err != nil {
			t.Fatalf("gateway not ready after forward retarget: %v", err)
		}
		retargeted, err := probeUntilMarkerChanges(ctx, stack, stack.ForwardRetargetPort, origin, lifecycleReadyTimeout)
		if err != nil {
			t.Fatalf("retarget did not converge to the new backend: %v", err)
		}
		assertBackendMarker(t, retargeted, retargetBackend)
	})
}

// TestGatewayForwardEdit validates that live forward edits take effect over the
// wire: adding a forward rolls the link onto new nftables rules without a pod roll,
// and a forward to a missing Service is denied then admitted once it appears.
func TestGatewayForwardEdit(t *testing.T) {
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

	// forward-edit adds a forward live; the data-path probe on the new port is the
	// signal the link reloaded its ConfigMap in place, with no pod roll.
	t.Run("forward-edit", func(t *testing.T) {
		client := suite.Client()

		addForward := hk8s.GatewayForward{
			Port:       stack.EditedPublicPort,
			Protocol:   "TCP",
			Service:    "gateway-echo-tcp",
			TargetPort: 8080,
		}
		if err := client.UpdateGateway(ctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
			return appendForward(spec, addForward)
		}); err != nil {
			t.Fatalf("add forward to gateway: %v", err)
		}

		// The in-place reload keeps the same pod, so the data-path probe on the new
		// port confirms the reloaded nftables rules took effect.
		if _, err := client.WaitGatewayReady(ctx, stack.Namespace, stack.GatewayName, editRollTimeout); err != nil {
			t.Fatalf("gateway not ready after forward edit: %v", err)
		}

		marker, err := probeTCPThroughGatewayPort(ctx, stack, stack.EditedPublicPort)
		if err != nil {
			t.Fatalf("edited-forward data path: %v", err)
		}
		if marker == "" {
			t.Fatal("edited-forward echo returned an empty marker")
		}
		t.Logf("edited-forward echo marker (echo pod name): %s", marker)
	})

	// The live-classification subtests each attach and remove a dedicated forward,
	// never touching the valid create-time forwards, so an invalid dedicated forward
	// leaves the VM up with Ready=False rather than tearing it down.

	// service-created-after-gateway: a forward to a missing Service is denied
	// (ServiceNotFound); creating the Service admits it and the port becomes reachable.
	t.Run("service-created-after-gateway", func(t *testing.T) {
		client := suite.Client()

		const svcName = "gateway-echo-created"
		t.Cleanup(func() {
			cctx := context.Background()
			if err := client.UpdateGateway(cctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
				return removeForward(spec, stack.ServiceCreatedPort)
			}); err != nil {
				t.Logf("cleanup remove service-created forward: %v", err)
			}
			if err := client.DeleteService(cctx, stack.Namespace, svcName); err != nil {
				t.Logf("cleanup delete service %s: %v", svcName, err)
			}
			if err := client.DeleteDeployment(cctx, stack.Namespace, svcName); err != nil {
				t.Logf("cleanup delete deployment %s: %v", svcName, err)
			}
		})

		// Adding the forward before the backend exists must keep the gateway up (its
		// create-time forwards stay valid) and report Ready=False/ServiceNotFound.
		if err := client.UpdateGateway(ctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
			return appendForward(spec, hk8s.GatewayForward{
				Port: stack.ServiceCreatedPort, Protocol: "TCP", Service: svcName, TargetPort: stack.TCPBackendPort,
			})
		}); err != nil {
			t.Fatalf("add forward to missing service: %v", err)
		}
		if err := client.WaitGatewayCondition(ctx, stack.Namespace, stack.GatewayName,
			"Ready", "False", serviceNotFoundReason, lifecycleConditionTimeout); err != nil {
			t.Fatalf("gateway did not report Ready=False/%s for missing backend: %v", serviceNotFoundReason, err)
		}

		// Creating the Service re-classifies the forward as valid; the new port
		// becomes reachable.
		if _, err := client.DeployEchoBackend(ctx, stack.Namespace, svcName); err != nil {
			t.Fatalf("deploy created-after backend: %v", err)
		}
		if _, err := client.WaitGatewayReady(ctx, stack.Namespace, stack.GatewayName, lifecycleReadyTimeout); err != nil {
			t.Fatalf("gateway not ready after backend created: %v", err)
		}
		marker, err := probeTCPThroughGatewayPort(ctx, stack, stack.ServiceCreatedPort)
		if err != nil {
			t.Fatalf("created-after-forward data path: %v", err)
		}
		assertBackendMarker(t, marker, svcName)
	})
}

// TestGatewayConsentLifecycle validates per-forward classification transitions on a
// live gateway: deleting a backend Service closes only its forward, and toggling the
// consent label denies, admits, then re-denies a cross-namespace forward.
func TestGatewayConsentLifecycle(t *testing.T) {
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

	// service-deleted: deleting a live backend Service drops only its forward, while
	// the create-time forwards keep working and the gateway keeps its VM.
	t.Run("service-deleted", func(t *testing.T) {
		client := suite.Client()

		const svcName = "gateway-echo-deletable"
		t.Cleanup(func() {
			cctx := context.Background()
			if err := client.UpdateGateway(cctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
				return removeForward(spec, stack.ServiceDeletedPort)
			}); err != nil {
				t.Logf("cleanup remove service-deleted forward: %v", err)
			}
			if err := client.DeleteService(cctx, stack.Namespace, svcName); err != nil {
				t.Logf("cleanup delete service %s: %v", svcName, err)
			}
			if err := client.DeleteDeployment(cctx, stack.Namespace, svcName); err != nil {
				t.Logf("cleanup delete deployment %s: %v", svcName, err)
			}
		})

		if _, err := client.DeployEchoBackend(ctx, stack.Namespace, svcName); err != nil {
			t.Fatalf("deploy deletable backend: %v", err)
		}
		if err := client.UpdateGateway(ctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
			return appendForward(spec, hk8s.GatewayForward{
				Port: stack.ServiceDeletedPort, Protocol: "TCP", Service: svcName, TargetPort: stack.TCPBackendPort,
			})
		}); err != nil {
			t.Fatalf("add forward to deletable service: %v", err)
		}
		// The data path through a freshly-opened forward is already proven by the
		// service-created probe, so this asserts the admit transition via Ready only.
		if _, err := client.WaitGatewayReady(ctx, stack.Namespace, stack.GatewayName, lifecycleReadyTimeout); err != nil {
			t.Fatalf("gateway not ready with deletable forward: %v", err)
		}

		// Deleting the backend re-classifies the forward as ServiceNotFound; the
		// operator re-renders without it (closing the port) while keeping its VM.
		if err := client.DeleteService(ctx, stack.Namespace, svcName); err != nil {
			t.Fatalf("delete deletable backend service: %v", err)
		}
		if err := client.WaitGatewayCondition(ctx, stack.Namespace, stack.GatewayName,
			"Ready", "False", serviceNotFoundReason, lifecycleConditionTimeout); err != nil {
			t.Fatalf("gateway did not report Ready=False/%s after backend deleted: %v", serviceNotFoundReason, err)
		}
		if err := waitPortDenied(ctx, stack, stack.ServiceDeletedPort, lifecycleReadyTimeout); err != nil {
			t.Fatalf("deleted-backend port did not stop responding: %v", err)
		}

		// Dropping one forward must not disturb the others.
		survivor, err := probeTCPThroughGateway(ctx, stack)
		if err != nil {
			t.Fatalf("create-time tcp forward broke after unrelated backend delete: %v", err)
		}
		assertBackendMarker(t, survivor, stack.TCPBackendName)
	})

	// consent-label-toggle: a cross-namespace forward into an unlabelled namespace is
	// denied; the operator's Namespace watch observes the consent label toggling and
	// re-classifies it admitted then denied again.
	t.Run("consent-label-toggle", func(t *testing.T) {
		client := suite.Client()

		consentNS := stack.Namespace + "-consent-target"
		const svcName = "gateway-echo-consent"
		t.Cleanup(func() {
			cctx := context.Background()
			if err := client.UpdateGateway(cctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
				return removeForward(spec, stack.ConsentTogglePort)
			}); err != nil {
				t.Logf("cleanup remove consent forward: %v", err)
			}
			if err := client.DeleteNamespace(cctx, consentNS); err != nil {
				t.Logf("cleanup delete consent namespace %s: %v", consentNS, err)
			}
		})

		// The target namespace starts without the consent label.
		if err := client.EnsureNamespace(ctx, consentNS); err != nil {
			t.Fatalf("ensure consent namespace: %v", err)
		}
		if _, err := client.DeployEchoBackend(ctx, consentNS, svcName); err != nil {
			t.Fatalf("deploy consent backend: %v", err)
		}
		if err := client.UpdateGateway(ctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
			return appendForward(spec, hk8s.GatewayForward{
				Port: stack.ConsentTogglePort, Protocol: "TCP", Service: svcName,
				Namespace: consentNS, TargetPort: stack.TCPBackendPort,
			})
		}); err != nil {
			t.Fatalf("add cross-namespace forward: %v", err)
		}

		// Unlabelled: denied.
		if err := client.WaitGatewayCondition(ctx, stack.Namespace, stack.GatewayName,
			"Ready", "False", crossNamespaceForwardDeniedReason, lifecycleConditionTimeout); err != nil {
			t.Fatalf("cross-namespace forward into unlabelled ns not denied: %v", err)
		}

		// Label added: admitted. The probe proves the consented forward carries
		// traffic over the wire, not merely that the condition flipped.
		if err := client.SetNamespaceLabel(ctx, consentNS, consentLabel, consentValue); err != nil {
			t.Fatalf("add consent label: %v", err)
		}
		if _, err := client.WaitGatewayReady(ctx, stack.Namespace, stack.GatewayName, lifecycleReadyTimeout); err != nil {
			t.Fatalf("gateway not ready after consent label added: %v", err)
		}
		marker, err := probeTCPThroughGatewayPort(ctx, stack, stack.ConsentTogglePort)
		if err != nil {
			t.Fatalf("consent-forward data path after label added: %v", err)
		}
		assertBackendMarker(t, marker, svcName)

		// Label removed: re-denied and the port stops.
		if err := client.RemoveNamespaceLabel(ctx, consentNS, consentLabel); err != nil {
			t.Fatalf("remove consent label: %v", err)
		}
		if err := client.WaitGatewayCondition(ctx, stack.Namespace, stack.GatewayName,
			"Ready", "False", crossNamespaceForwardDeniedReason, lifecycleConditionTimeout); err != nil {
			t.Fatalf("cross-namespace forward not re-denied after label removed: %v", err)
		}
		if err := waitPortDenied(ctx, stack, stack.ConsentTogglePort, lifecycleReadyTimeout); err != nil {
			t.Fatalf("consent-forward port did not stop after label removed: %v", err)
		}
	})

	// backend-rollout proves a forward's DNAT targets the Service's stable ClusterIP,
	// not a specific pod: after rolling every backend pod the forward still carries
	// traffic to a fresh one.
	t.Run("backend-rollout", func(t *testing.T) {
		client := suite.Client()

		const svcName = "gateway-echo-rollout"
		t.Cleanup(func() {
			cctx := context.Background()
			if err := client.UpdateGateway(cctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
				return removeForward(spec, stack.BackendRolloutPort)
			}); err != nil {
				t.Logf("cleanup remove backend-rollout forward: %v", err)
			}
			if err := client.DeleteService(cctx, stack.Namespace, svcName); err != nil {
				t.Logf("cleanup delete service %s: %v", svcName, err)
			}
			if err := client.DeleteDeployment(cctx, stack.Namespace, svcName); err != nil {
				t.Logf("cleanup delete deployment %s: %v", svcName, err)
			}
		})

		if _, err := client.DeployEchoBackend(ctx, stack.Namespace, svcName); err != nil {
			t.Fatalf("deploy rollout backend: %v", err)
		}
		if err := client.UpdateGateway(ctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
			return appendForward(spec, hk8s.GatewayForward{
				Port: stack.BackendRolloutPort, Protocol: "TCP", Service: svcName, TargetPort: stack.TCPBackendPort,
			})
		}); err != nil {
			t.Fatalf("add forward to rollout backend: %v", err)
		}
		if _, err := client.WaitGatewayReady(ctx, stack.Namespace, stack.GatewayName, lifecycleReadyTimeout); err != nil {
			t.Fatalf("gateway not ready with rollout forward: %v", err)
		}
		before, err := probeTCPThroughGatewayPort(ctx, stack, stack.BackendRolloutPort)
		if err != nil {
			t.Fatalf("rollout backend data path before roll: %v", err)
		}
		assertBackendMarker(t, before, svcName)

		// At replicas=1 the old pod can linger in endpoints across the roll, so a
		// single post-roll probe can catch the old marker; poll until it changes under
		// the lifecycle budget the roll plus old-endpoint drain can need.
		if err := client.RestartDeployment(ctx, stack.Namespace, svcName); err != nil {
			t.Fatalf("restart rollout backend: %v", err)
		}
		if err := client.WaitDeploymentAvailable(ctx, stack.Namespace, svcName, lifecycleReadyTimeout); err != nil {
			t.Fatalf("rollout backend not available after roll: %v", err)
		}
		// A Deployment can report Available before the fresh pod is a ready endpoint,
		// so gate the convergence probe on one.
		if err := client.WaitEndpointsReady(ctx, stack.Namespace, svcName, lifecycleReadyTimeout); err != nil {
			t.Fatalf("rollout backend has no ready endpoints after roll: %v", err)
		}
		after, err := probeUntilMarkerChanges(ctx, stack, stack.BackendRolloutPort, before, lifecycleReadyTimeout)
		if err != nil {
			t.Fatalf("rollout backend did not converge to a fresh pod: %v", err)
		}
		assertBackendMarker(t, after, svcName)
	})
}

// TestGatewayTargetPortLifecycle validates targetPort classification (a forward to a
// non-published targetPort is denied and unreachable, then admitted once corrected)
// and that a Gateway with only an unlabelled cross-namespace forward provisions no VM.
func TestGatewayTargetPortLifecycle(t *testing.T) {
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

	// targetPort-not-listening: a forward whose targetPort the backend does not
	// publish is denied (TargetPortNotListening); correcting it admits the forward.
	t.Run("targetPort-not-listening", func(t *testing.T) {
		client := suite.Client()

		const wrongTargetPort = 9090
		t.Cleanup(func() {
			if err := client.UpdateGateway(context.Background(), stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
				return removeForward(spec, stack.TargetPortScenarioPort)
			}); err != nil {
				t.Logf("cleanup remove targetPort forward: %v", err)
			}
		})

		if err := client.UpdateGateway(ctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
			return appendForward(spec, hk8s.GatewayForward{
				Port: stack.TargetPortScenarioPort, Protocol: "TCP",
				Service: stack.TCPBackendName, TargetPort: wrongTargetPort,
			})
		}); err != nil {
			t.Fatalf("add forward with wrong targetPort: %v", err)
		}
		if err := client.WaitGatewayCondition(ctx, stack.Namespace, stack.GatewayName,
			"Ready", "False", targetPortNotListeningReason, lifecycleConditionTimeout); err != nil {
			t.Fatalf("forward with non-published targetPort not denied: %v", err)
		}
		// Prove the denied forward is also closed at the firewall, not just reported
		// denied by the condition.
		if err := waitPortDenied(ctx, stack, stack.TargetPortScenarioPort, lifecycleReadyTimeout); err != nil {
			t.Fatalf("wrong-targetPort forward port did not stay closed: %v", err)
		}

		// Correcting the targetPort admits the forward.
		if err := client.UpdateGateway(ctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
			return setForwardTargetPort(spec, stack.TargetPortScenarioPort, stack.TCPBackendPort)
		}); err != nil {
			t.Fatalf("correct targetPort: %v", err)
		}
		// The probe proves the corrected forward carries traffic over the wire.
		if _, err := client.WaitGatewayReady(ctx, stack.Namespace, stack.GatewayName, lifecycleReadyTimeout); err != nil {
			t.Fatalf("gateway not ready after targetPort corrected: %v", err)
		}
		marker, err := probeTCPThroughGatewayPort(ctx, stack, stack.TargetPortScenarioPort)
		if err != nil {
			t.Fatalf("corrected-targetPort data path: %v", err)
		}
		assertBackendMarker(t, marker, stack.TCPBackendName)
	})

	// cross-namespace-denied applies a Gateway whose only forward targets an
	// unlabelled namespace; with zero valid forwards the operator never creates a VM
	// and reports the Ready=False denial reason.
	t.Run("cross-namespace-denied", func(t *testing.T) {
		client := suite.Client()
		env := suite.Env()

		// The namespace exists but lacks the consent label, so the reason is
		// CrossNamespaceForwardDenied, not TargetNamespaceNotFound.
		deniedNS := stack.Namespace + "-denied-target"
		if err := client.EnsureNamespace(ctx, deniedNS); err != nil {
			t.Fatalf("ensure denied-target namespace: %v", err)
		}
		t.Cleanup(func() {
			if err := client.DeleteNamespace(context.Background(), deniedNS); err != nil {
				t.Logf("cleanup denied-target namespace %s: %v", deniedNS, err)
			}
		})

		deniedGateway := stack.GatewayName + "-denied"
		spec := hk8s.GatewaySpec{
			ProjectID:   env.ProjectID,
			Region:      env.Region,
			Zone:        env.Zone,
			MachineType: "e2-micro",
			Forwards: []hk8s.GatewayForward{{
				Port:      stack.TCPPublicPort,
				Protocol:  "TCP",
				Service:   "gateway-echo-tcp",
				Namespace: deniedNS,
			}},
		}
		if err := client.CreateGateway(ctx, stack.Namespace, deniedGateway, spec); err != nil {
			t.Fatalf("create denied gateway: %v", err)
		}
		t.Cleanup(func() {
			cctx := context.Background()
			if err := client.DeleteGateway(cctx, stack.Namespace, deniedGateway); err != nil {
				t.Logf("cleanup denied gateway %s: %v", deniedGateway, err)
				return
			}
			// The denied Gateway never created an XGatewayGCP, so its finalizer clears
			// immediately; wait so the namespace teardown does not race it.
			if err := client.WaitGatewayGone(cctx, stack.Namespace, deniedGateway, deniedConditionTimeout); err != nil {
				t.Logf("cleanup wait denied gateway gone %s: %v", deniedGateway, err)
			}
		})

		if err := client.WaitGatewayCondition(ctx, stack.Namespace, deniedGateway,
			"Ready", "False", crossNamespaceForwardDeniedReason, deniedConditionTimeout); err != nil {
			t.Fatalf("denied gateway did not reach Ready=False reason %s: %v", crossNamespaceForwardDeniedReason, err)
		}
	})

	// link-pod-restart proves the data path survives losing the active link pod: the
	// new holder re-establishes the tunnel and DNAT before traffic flows. It keys on
	// the lease holder moving, the failover signal at any replica count.
	t.Run("link-pod-restart", func(t *testing.T) {
		client := suite.Client()

		// Baseline before the active link pod is deleted.
		before, err := probeTCPThroughGateway(ctx, stack)
		if err != nil {
			t.Fatalf("create-time tcp forward broken before link restart: %v", err)
		}
		assertBackendMarker(t, before, stack.TCPBackendName)

		oldHolder, err := client.GetLeaseHolder(ctx, stack.Namespace, linkLeaseName(stack.GatewayName))
		if err != nil {
			t.Fatalf("read link lease holder before restart: %v", err)
		}
		if oldHolder == "" {
			t.Fatal("link lease has no holder before restart; the active link never acquired leadership")
		}

		// At this shard's single replica the deleted pod is the lease holder, so
		// leadership must move to its replacement.
		deleted, err := client.DeletePodsByLabel(ctx, stack.Namespace, linkSelector(stack.GatewayName))
		if err != nil {
			t.Fatalf("delete link pods: %v", err)
		}
		if deleted < 1 {
			t.Fatalf("link selector in ns %q matched no pods", stack.Namespace)
		}

		newHolder, err := client.WaitLeaseHolderChanges(ctx, stack.Namespace, linkLeaseName(stack.GatewayName), oldHolder, lifecycleReadyTimeout)
		if err != nil {
			t.Fatalf("link lease holder did not move after restart: %v", err)
		}
		t.Logf("link lease holder moved %s -> %s", oldHolder, newHolder)

		// The data-path retry absorbs the new holder's handshake and rule convergence.
		after, err := probeTCPThroughGateway(ctx, stack)
		if err != nil {
			t.Fatalf("create-time tcp forward did not resume after link restart: %v", err)
		}
		assertBackendMarker(t, after, stack.TCPBackendName)
	})

	// Forward classification and validation transitions live in the controller
	// envtest, not duplicated here so each shard stays a single VM.
}

// haFailoverTimeout bounds the wait for the link lease holder to move to a survivor:
// one lease-duration plus the new holder publishing itself, not the tunnel bring-up
// the data-path probe owns.
const haFailoverTimeout = 90 * time.Second

// haReplicas is the link replica count TestGatewayLinkHA provisions: one active plus
// one standby, the minimum exercising leader election, fencing, failover, and a PDB.
const haReplicas = 2

// TestGatewayLinkHA validates the link's active-passive HA at two replicas behind
// leader election: exactly the lease holder runs wg0 and the inet gateway table, and
// the data path survives failover, a rolling update, and a budgeted eviction.
func TestGatewayLinkHA(t *testing.T) {
	t.Parallel()

	suite := getSuite(t)
	ctx := context.Background()

	stack, err := suite.Start(ctx, t, e2eharness.WithLinkReplicas(haReplicas))
	if err != nil {
		t.Fatalf("start stack: %v", err)
	}

	if stack.Address == "" {
		t.Fatal("gateway reported no public IP")
	}
	t.Logf("gateway public IP: %s", stack.Address)

	client := suite.Client()
	leaseName := linkLeaseName(stack.GatewayName)
	selector := linkSelector(stack.GatewayName)

	// Baseline before any HA scenario perturbs the active replica.
	baseline, err := probeTCPThroughGateway(ctx, stack)
	if err != nil {
		t.Fatalf("create-time tcp forward broken at HA baseline: %v", err)
	}
	assertBackendMarker(t, baseline, stack.TCPBackendName)

	// single-active proves exactly one replica owns wg0 and it is the lease holder.
	t.Run("single-active", func(t *testing.T) {
		holder, owners := assertSingleWG0Owner(ctx, t, client, stack.Namespace, selector, leaseName)
		t.Logf("active link replica: %s (lease holder, sole wg0 owner)", holder)
		if len(owners) != 1 || owners[0] != holder {
			t.Fatalf("wg0 owners %v do not match lease holder %q", owners, holder)
		}
	})

	// standby-idle proves every non-holder replica carries no data plane (neither wg0
	// nor the inet gateway table); otherwise it would double-drive the tunnel.
	t.Run("standby-idle", func(t *testing.T) {
		holder, err := client.GetLeaseHolder(ctx, stack.Namespace, leaseName)
		if err != nil {
			t.Fatalf("read lease holder: %v", err)
		}
		if holder == "" {
			t.Fatal("link lease has no holder; no active replica")
		}
		pods, err := client.PodNamesByLabel(ctx, stack.Namespace, selector)
		if err != nil {
			t.Fatalf("list link pods: %v", err)
		}
		standbys := 0
		for _, pod := range pods {
			if pod == holder {
				continue
			}
			standbys++
			if podHasWG0(ctx, t, client, stack.Namespace, pod) {
				t.Errorf("standby %s has wg0; a demoted replica must not carry the interface", pod)
			}
			if podHasGatewayTable(ctx, t, client, stack.Namespace, pod) {
				t.Errorf("standby %s has the inet gateway table; a demoted replica must not carry the nftables data plane", pod)
			}
		}
		if standbys == 0 {
			t.Fatalf("no standby replicas among link pods %v (holder %q); HA test needs >1 replica", pods, holder)
		}
	})

	// failover proves leadership and the data plane move to a survivor when the
	// active replica is lost.
	t.Run("failover", func(t *testing.T) {
		oldHolder, err := client.GetLeaseHolder(ctx, stack.Namespace, leaseName)
		if err != nil {
			t.Fatalf("read lease holder before failover: %v", err)
		}
		if oldHolder == "" {
			t.Fatal("link lease has no holder before failover")
		}

		// Delete only the holder, leaving the standby; leadership must move to it.
		if err := client.DeletePod(ctx, stack.Namespace, oldHolder); err != nil {
			t.Fatalf("delete lease holder %s: %v", oldHolder, err)
		}

		newHolder, err := client.WaitLeaseHolderChanges(ctx, stack.Namespace, leaseName, oldHolder, haFailoverTimeout)
		if err != nil {
			t.Fatalf("lease holder did not move after holder deletion: %v", err)
		}
		t.Logf("failover: lease holder moved %s -> %s", oldHolder, newHolder)

		// wg0 bring-up trails the lease acquire, so allow the failover budget.
		if err := waitPodHasWG0(ctx, t, client, stack.Namespace, newHolder, haFailoverTimeout); err != nil {
			t.Fatalf("new holder %s did not bring up wg0 after failover: %v", newHolder, err)
		}

		// The until-probe absorbs the new holder's handshake and DNAT convergence,
		// which can exceed the steady-state window, hence the edit budget.
		after, err := probeTCPThroughGatewayPortUntil(ctx, stack, stack.TCPPublicPort, editRollTimeout)
		if err != nil {
			t.Fatalf("data path did not resume after failover: %v", err)
		}
		assertBackendMarker(t, after, stack.TCPBackendName)
	})

	// rolling-update proves a link rollout keeps the data path serviceable: with
	// maxUnavailable=0 and leader election the holder stays up until a replacement is
	// Ready, so traffic tolerates at most a brief failover blip.
	t.Run("rolling-update", func(t *testing.T) {
		if err := client.RestartDeployment(ctx, stack.Namespace, leaseName); err != nil {
			t.Fatalf("restart link deployment: %v", err)
		}

		// The until-probe tolerates a brief blip while leadership moves to a rolled
		// pod, but must converge within the edit budget.
		during, err := probeTCPThroughGatewayPortUntil(ctx, stack, stack.TCPPublicPort, editRollTimeout)
		if err != nil {
			t.Fatalf("data path not serviceable across link rolling update: %v", err)
		}
		assertBackendMarker(t, during, stack.TCPBackendName)

		if err := client.WaitDeploymentAvailable(ctx, stack.Namespace, leaseName, lifecycleReadyTimeout); err != nil {
			t.Fatalf("link deployment not available after rolling update: %v", err)
		}

		// The single-active invariant must survive the roll.
		holder, owners := assertSingleWG0Owner(ctx, t, client, stack.Namespace, selector, leaseName)
		if len(owners) != 1 || owners[0] != holder {
			t.Fatalf("after rolling update, wg0 owners %v do not match lease holder %q", owners, holder)
		}
	})

	// pdb-protects proves the link PodDisruptionBudget targets the link pods: the
	// controller reports one disruption allowed, then one eviction succeeds. The
	// status assertion catches the real failure mode, a selector matching no pods.
	t.Run("pdb-protects", func(t *testing.T) {
		if err := client.SetLinkReplicas(ctx, stack.Namespace, stack.GatewayName, haReplicas); err != nil {
			t.Fatalf("rescale link to %d replicas: %v", haReplicas, err)
		}
		if err := client.WaitDeploymentAvailable(ctx, stack.Namespace, leaseName, lifecycleReadyTimeout); err != nil {
			t.Fatalf("link deployment not available before eviction: %v", err)
		}

		// A mismatched selector would leave the status at NoPods with no disruption
		// allowed, which this assertion fails on.
		if err := waitPDBProtects(ctx, t, client, stack.Namespace, leaseName, haReplicas, lifecycleReadyTimeout); err != nil {
			t.Fatalf("link PDB did not reach protected status: %v", err)
		}

		pods, err := client.PodNamesByLabel(ctx, stack.Namespace, selector)
		if err != nil {
			t.Fatalf("list link pods: %v", err)
		}
		if len(pods) < haReplicas {
			t.Fatalf("link has %d pods, want >=%d before eviction test", len(pods), haReplicas)
		}

		// With DisruptionsAllowed==1 one eviction is within budget; a second
		// back-to-back would race the controller's recompute, so the test does not.
		if err := client.EvictPod(ctx, stack.Namespace, pods[0]); err != nil {
			t.Fatalf("within-budget link pod eviction rejected (want allowed under minAvailable=1 with %d replicas): %v", haReplicas, err)
		}
	})
}

// linkSelector is the label selector matching a gateway's link pods, mirroring the
// operator's unexported linkSelectorLabels.
func linkSelector(gatewayName string) string {
	return fmt.Sprintf("app.kubernetes.io/component=link,app.kubernetes.io/instance=%s", gatewayName)
}

// linkLeaseName is the Lease the link runs leader election over: <gateway>-link. It
// mirrors the operator's unexported linkComponentName.
func linkLeaseName(gatewayName string) string {
	return gatewayName + "-link"
}

// assertSingleWG0Owner fails unless exactly one link replica owns wg0 and it is the
// lease holder, returning the holder and the observed owners.
func assertSingleWG0Owner(ctx context.Context, t *testing.T, client *hk8s.Client, ns, selector, leaseName string) (holder string, owners []string) {
	t.Helper()
	holder, err := client.GetLeaseHolder(ctx, ns, leaseName)
	if err != nil {
		t.Fatalf("read lease holder: %v", err)
	}
	if holder == "" {
		t.Fatal("link lease has no holder; no active replica")
	}
	pods, err := client.PodNamesByLabel(ctx, ns, selector)
	if err != nil {
		t.Fatalf("list link pods: %v", err)
	}
	for _, pod := range pods {
		if podHasWG0(ctx, t, client, ns, pod) {
			owners = append(owners, pod)
		}
	}
	if len(owners) != 1 {
		t.Fatalf("wg0 owners = %v among link pods %v, want exactly one (the lease holder %q)", owners, pods, holder)
	}
	return holder, owners
}

// podHasWG0 reports whether the link pod has the wg0 interface, via `ip link show
// wg0`. Only the active replica runs wg0, so this distinguishes the holder from a
// fenced standby.
func podHasWG0(ctx context.Context, t *testing.T, client *hk8s.Client, ns, pod string) bool {
	t.Helper()
	_, _, err := client.ExecInPod(ctx, ns, pod, []string{"ip", "link", "show", "wg0"})
	return err == nil
}

// podHasGatewayTable reports whether the link pod has the inet gateway nftables
// table. Only the active replica programs it, so a standby carrying it is a stale
// data plane.
func podHasGatewayTable(ctx context.Context, t *testing.T, client *hk8s.Client, ns, pod string) bool {
	t.Helper()
	_, _, err := client.ExecInPod(ctx, ns, pod, []string{"nft", "list", "table", "inet", "gateway"})
	return err == nil
}

// waitPodHasWG0 polls until the link pod has wg0 or the timeout elapses. The new
// holder brings wg0 up only after acquiring leadership, so the failover assertion
// gives that a bounded window rather than racing it.
func waitPodHasWG0(ctx context.Context, t *testing.T, client *hk8s.Client, ns, pod string, timeout time.Duration) error {
	t.Helper()
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		if podHasWG0(dctx, t, client, ns, pod) {
			return nil
		}
		select {
		case <-dctx.Done():
			return fmt.Errorf("wg0 not present on %s/%s after %s", ns, pod, timeout)
		case <-ticker.C:
		}
	}
}

// waitPDBProtects polls the named PodDisruptionBudget until the controller computes
// full protection (Expected/CurrentHealthy==replicas, DesiredHealthy==replicas-1,
// DisruptionsAllowed==1), proving the selector matches; a bad selector stalls at NoPods.
func waitPDBProtects(ctx context.Context, t *testing.T, client *hk8s.Client, ns, name string, replicas int32, timeout time.Duration) error {
	t.Helper()
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var last policyv1.PodDisruptionBudgetStatus
	for {
		status, err := client.GetPodDisruptionBudgetStatus(dctx, ns, name)
		if err == nil {
			last = status
			if status.ExpectedPods == replicas && status.CurrentHealthy == replicas &&
				status.DesiredHealthy == replicas-1 && status.DisruptionsAllowed == 1 {
				return nil
			}
		}
		select {
		case <-dctx.Done():
			return fmt.Errorf("pdb %s/%s status not protected after %s: %+v", ns, name, timeout, last)
		case <-ticker.C:
		}
	}
}

// assertBackendMarker fails unless marker (an agnhost /hostname pod name) carries
// backend as a prefix. The pod name is its Deployment's name plus a suffix, so the
// prefix identifies which backend answered; a mismatch is a misrouted forward.
func assertBackendMarker(t *testing.T, marker, backend string) {
	t.Helper()
	if marker == "" {
		t.Fatalf("echo returned an empty marker; want a %q pod name", backend)
	}
	if !strings.HasPrefix(marker, backend) {
		t.Fatalf("echo marker %q is not from backend %q; forward routed to the wrong Service", marker, backend)
	}
}

// appendForward appends f to the spec's forwards slice in the unstructured shape
// the API server stores, mirroring hk8s.CreateGateway. namespace and targetPort are
// included only when set; a zero targetPort would fail the CRD's minimum=1.
func appendForward(spec map[string]any, f hk8s.GatewayForward) error {
	existing, _ := spec["forwards"].([]any)
	entry := map[string]any{
		"port":     int64(f.Port),
		"protocol": f.Protocol,
		"service":  f.Service,
	}
	if f.Namespace != "" {
		entry["namespace"] = f.Namespace
	}
	if f.TargetPort != 0 {
		entry["targetPort"] = int64(f.TargetPort)
	}
	spec["forwards"] = append(existing, entry)
	return nil
}

// removeForward drops the forward on the given public port, the inverse of
// appendForward. It is a no-op when no forward uses the port, so cleanup is
// idempotent.
func removeForward(spec map[string]any, port int) error {
	existing, _ := spec["forwards"].([]any)
	kept := make([]any, 0, len(existing))
	for _, raw := range existing {
		entry, ok := raw.(map[string]any)
		if !ok {
			kept = append(kept, raw)
			continue
		}
		if p, ok := entry["port"].(int64); ok && int(p) == port {
			continue
		}
		kept = append(kept, entry)
	}
	spec["forwards"] = kept
	return nil
}

// setForwardTargetPort sets the targetPort of the forward on the given public port.
// It errors if no forward uses the port, so a misaddressed edit fails loudly.
func setForwardTargetPort(spec map[string]any, port, targetPort int) error {
	existing, _ := spec["forwards"].([]any)
	for _, raw := range existing {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if p, ok := entry["port"].(int64); ok && int(p) == port {
			entry["targetPort"] = int64(targetPort)
			return nil
		}
	}
	return fmt.Errorf("no forward on port %d to set targetPort", port)
}

// setForwardService retargets the forward on the given public port to a different
// Service, erroring if none uses the port. A non-empty namespace sets a
// cross-namespace target; an empty one clears it to default to the Gateway's namespace.
func setForwardService(spec map[string]any, port int, service, namespace string) error {
	existing, _ := spec["forwards"].([]any)
	for _, raw := range existing {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if p, ok := entry["port"].(int64); ok && int(p) == port {
			entry["service"] = service
			if namespace != "" {
				entry["namespace"] = namespace
			} else {
				delete(entry, "namespace")
			}
			return nil
		}
	}
	return fmt.Errorf("no forward on port %d to set service", port)
}
