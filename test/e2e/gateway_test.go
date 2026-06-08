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

	e2eharness "github.com/greg2010/wireguard-gateway-operator/test/harness/e2e"
	hk8s "github.com/greg2010/wireguard-gateway-operator/test/harness/k8s"
)

// Ready=False reasons the operator sets on a forward-classification failure. The
// lifecycle subtests assert on them. They mirror the operator's unexported reason
// constants (internal/controller), duplicated here like the harness's consent
// label because the operator's are unexported.
const (
	crossNamespaceForwardDeniedReason = "CrossNamespaceForwardDenied"
	serviceNotFoundReason             = "ServiceNotFound"
	targetPortNotListeningReason      = "TargetPortNotListening"
)

// consentLabel and consentValue are the cross-namespace ingress consent label the
// consent-label-toggle subtest sets on a target namespace. They mirror the
// operator's gate (internal/controller), duplicated here because the operator's
// constants are unexported.
const (
	consentLabel = "wgnet.dev/allow-gateway-ingress"
	consentValue = "true"
)

// lifecycleConditionTimeout bounds a lifecycle subtest's wait for the operator to
// re-stamp the Gateway Ready condition after a forward, backend, or consent-label
// change. The change is observed on the next reconcile the relevant watch
// enqueues, so this need only cover the operator re-running classification and
// writing status, not a GCP round trip.
const lifecycleConditionTimeout = 90 * time.Second

// lifecycleReadyTimeout bounds a lifecycle subtest's wait for the Gateway to
// return Ready after a forward becomes valid. Like editRollTimeout it covers the
// operator re-rendering the firewall and link config plus the link re-applying
// nftables in place and the readiness gate trailing the live tunnel, so it shares
// that budget.
const lifecycleReadyTimeout = editRollTimeout

// deniedConditionTimeout bounds the wait for a validation-failure Gateway to
// report its Ready=False condition. The denial is decided on the first reconcile
// after the target namespace exists, so this is short; it never provisions.
const deniedConditionTimeout = 90 * time.Second

// editRollTimeout bounds the forward-edit subtest's wait for the Gateway to
// return Ready after a live forward edit. The link reloads its ConfigMap in
// place, so this covers the operator re-rendering the config plus the link
// re-applying nftables and the readiness gate trailing a fresh handshake, not a
// pod replacement.
const editRollTimeout = 3 * time.Minute

// coexistWGListenPortA and coexistWGListenPortB are the distinct WireGuard listen
// ports TestGatewayCoexistence gives its two gateways, so the firewall isolation
// assertion can prove each gateway's rule admits only its own WG port in the
// shared VPC. A keeps the chart default (51820); B uses a disjoint port. Both must
// be disjoint from the negative and forwarded ports (StartE's precondition
// re-checks the effective WG port).
const (
	coexistWGListenPortA = 51820
	coexistWGListenPortB = 51821
)

// TestGatewayCoexistence validates that two independently provisioned gateways
// sharing one GCP VPC serve only their own forwards and are isolated by
// per-gateway service-account scoping. Each gateway's firewall, WireGuard tunnel,
// and DNAT carry traffic to its own backend; a port one gateway forwards is
// dropped at the other's firewall; and at the GCP firewall-rule level each
// gateway's rules target only its own service account and admit only its own
// WireGuard port. It provisions both gateways concurrently (each its own GCP VM,
// namespace, and link) with distinct exposed ports and distinct WireGuard listen
// ports, then asserts the positive data path on each, the negative cross-isolation
// in both directions, the per-gateway firewall-rule scoping, and that exactly one
// shared VPC backs both (create-once, no per-gateway duplicate).
//
// It is the 5th sharded top-level test. Unlike the single-VM shards it brings up
// two stacks, so it provisions them under an errgroup to overlap the two GCP
// round trips rather than serialize them; each stack registers its own teardown
// (Gateway delete + GCP drain + namespace delete) via StartE, which is safe to run
// off the test goroutine because it returns errors instead of calling t.Fatal.
func TestGatewayCoexistence(t *testing.T) {
	t.Parallel()

	suite := getSuite(t)
	ctx := context.Background()

	// Provision both stacks concurrently. StartE never calls t.Fatal (it returns
	// errors and uses only the goroutine-safe t.Cleanup/t.Errorf/t.Logf), so it is
	// safe under errgroup; the bring-up errors are collected here and re-raised on
	// the test goroutine, where t.Fatal is legal.
	// Give the two gateways distinct WireGuard listen ports: A keeps the chart
	// default, B overrides to coexistWGListenPortB. With both gateways in one
	// shared VPC, distinct WG ports plus distinct exposed ports make the firewall
	// isolation assertion below a real test of per-gateway targetServiceAccounts
	// scoping, not just of port-set bookkeeping.
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

	// Each gateway forwards its own distinctly named backend on a distinct public
	// port: A on its ServiceCreatedPort, B on its ServiceDeletedPort. Both ports are
	// in forwardedPorts() and proven disjoint, and the backends carry the gateway's
	// suffix so a marker identifies which gateway's data path answered.
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

	// Positive: each gateway carries traffic to its own backend. The forward was
	// just added, so the link must apply its new nftables rule before the data path
	// answers; the readiness gate above trails the live handshake, not that apply, so
	// these probes use the edit/lifecycle budget rather than the shorter data-path one.
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

	// Cross-isolation: a gateway never forwards the other's port, so a SYN to the
	// other's port is dropped at this gateway's firewall. The port was never opened
	// here, so probeTCPDenied needs no propagation wait.
	if err := probeTCPDenied(ctx, stackA, stackB.ServiceDeletedPort); err != nil {
		t.Fatalf("gateway A leaked gateway B's port %d: %v", stackB.ServiceDeletedPort, err)
	}
	if err := probeTCPDenied(ctx, stackB, stackA.ServiceCreatedPort); err != nil {
		t.Fatalf("gateway B leaked gateway A's port %d: %v", stackA.ServiceCreatedPort, err)
	}

	// Firewall-rule isolation: assert at the GCP firewall-rule level (not just the
	// data path) that each gateway's rules target only its own service account and
	// admit only its own WireGuard port. In a shared VPC this is the invariant that
	// keeps one gateway's rules off the other's VM; it is more reliable than a UDP
	// data-path probe, which the firewall drops silently.
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

	// Exactly one shared VPC backs both gateways: the network is created once on
	// the first gateway and reused, never duplicated per gateway.
	n, err := suite.SharedNetworkCount(ctx)
	if err != nil {
		t.Fatalf("count shared networks: %v", err)
	}
	if n != 1 {
		t.Fatalf("shared network count = %d, want exactly 1 backing both gateways", n)
	}
}

// assertFirewallIsolation fails the test unless every firewall rule scoped to
// stack's gateway targets only ownSA (never otherSA), and the gateway's own
// WireGuard UDP port appears in some rule's allowed UDP ports while the other
// gateway's WG port (otherWG) does not. It proves, at the GCP firewall-rule
// level, that the two coexisting gateways in the shared VPC are isolated by
// targetServiceAccounts for both exposed and WireGuard ports.
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
		// Every rule must be scoped to exactly this gateway's SA. The caller has
		// already asserted ownSA != otherSA, so requiring the single target to be
		// ownSA also proves the rule never carries the other gateway's SA: a rule
		// leaking onto it would open this gateway's ports on the other gateway's VM
		// in the shared VPC.
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

// TestGatewayDataPath validates the operator data path against real GCP: it
// installs the operator, creates a Gateway CR that provisions a real e2-micro
// gateway with an ephemeral IP, forwards in-cluster TCP (HTTP) and UDP echoes
// (ClusterIP, NodePort, and cross-namespace) through the gateway, and asserts
// each is reachable from the host on the gateway's public IP. It also asserts
// non-forwarded public ports and internet ICMP are NOT reachable, proving the
// GCP firewall and DNAT closure hold jointly. Teardown (registered by Start)
// deletes the Gateway, waits for Crossplane to drain every GCP resource the run
// created (asserting no orphans, including the hash-derived ServiceAccount and
// Secret), then uninstalls.
//
// This is one of four sharded top-level tests, each provisioning its own GCP
// gateway in parallel against the shared control plane. The shards split the
// scenarios so wall-clock is bounded by the slowest shard rather than the sum;
// each runs its subtests serially against its own single provisioned VM.
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
		// agnhost /hostname returns the serving pod name, which the backend
		// Deployment prefixes with its own name; asserting the prefix proves the
		// request reached the intended echo pod, not merely some pod.
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
		// The firewall no longer allows internet-wide ICMP, so a ping to the public
		// IP must draw no reply. A reply is a leak.
		if err := pingDenied(ctx, stack); err != nil {
			t.Fatalf("icmp negative probe: %v", err)
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
		if err := probeUDPDenied(ctx, stack, stack.NegativePort, "gateway-e2e-udp-denied"); err != nil {
			t.Fatalf("udp negative probe: %v", err)
		}
	})

	// forward-retarget points one forward at a backend, proves it carries traffic
	// to it, then retargets the same forward to a second backend and proves the
	// bytes follow: the data path tracks the retarget, not just the initial wiring.
	// It runs after the negative probes (which target the disjoint negative port)
	// so its transient open forward never overlaps them. It uses its own dedicated
	// public port and a second backend Service, leaving the create-time forwards the
	// other subtests assert on untouched.
	t.Run("forward-retarget", func(t *testing.T) {
		client := suite.Client()

		// When the subtest fails and GATEWAY_E2E_PRESERVE is set, leave the live
		// cluster in its exact failing state (8453 forward still pointed at the
		// retarget backend, backend B alive) so the data path can be inspected on the
		// preserved cluster. Evaluated inside the cleanup, where t.Failed reflects the
		// subtest's final result.
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

		// Deploy the second backend, then forward the dedicated port to the create-time
		// TCP echo first; the marker proves traffic reaches the original backend before
		// the retarget.
		if _, err := client.DeployEchoBackend(ctx, stack.Namespace, retargetBackend); err != nil {
			t.Fatalf("deploy retarget backend: %v", err)
		}
		// Gate on the retarget backend actually serving before the forward is pointed
		// at it below: DeployEchoBackend returns immediately and the echo Deployment
		// has no readinessProbe, so without this the retarget's DNAT can go live before
		// the backend has a ready endpoint and the probe blackholes for the full window.
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

		// Retarget the same forward to the second backend in the Gateway's own
		// namespace, then prove the marker now identifies that backend: the link
		// re-renders its DNAT and the bytes follow the new Service. The link reloads
		// its ConfigMap in place, so its DNAT can trail the operator's Ready
		// condition and a single probe can still catch the old backend; poll until
		// the marker leaves the origin backend, under lifecycleReadyTimeout, as the
		// convergence gate.
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

// TestGatewayForwardEdit validates that live forward edits on a provisioned
// gateway take effect over the wire: adding a forward in place rolls the link
// onto new nftables rules without a pod roll, and a forward to a not-yet-existing
// backend Service is denied then admitted once the Service appears. It is one of
// four sharded top-level tests, each provisioning its own GCP gateway; teardown
// (registered by Start) drains every GCP resource the shard created.
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

	// forward-edit adds a forward live and asserts the link picks up the new
	// nftables rules by reloading its ConfigMap in place: no pod roll. The link
	// watches the mounted ConfigMap and reconciles wg0 and nftables without tearing
	// the tunnel down, so the data-path probe on the new port is the signal that
	// the reload landed. It runs after the other positive probes so it does not
	// interfere with them.
	t.Run("forward-edit", func(t *testing.T) {
		client := suite.Client()

		// Add a TCP forward on editedPublicPort to the in-namespace TCP echo. The
		// edit changes the link ConfigMap, which the link reloads in place.
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

		// Ready returns once the operator has applied the new config and the link is
		// Available; the in-place reload keeps the same pod, so the data-path probe
		// on the new port confirms the reloaded nftables rules took effect.
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

	// Live-classification subtests each attach one dedicated runtime forward (and,
	// where needed, a dedicated backend Service or namespace) and remove it again,
	// so they never touch the create-time forwards the data-path subtests assert
	// on. Because the gateway is already provisioned via its valid create-time
	// forwards, an invalid dedicated forward leaves the VM up and reports
	// Ready=False with that forward's reason rather than tearing the VM down.

	// service-created-after-gateway: a forward to a not-yet-existing backend Service
	// is denied (ServiceNotFound) on the live gateway; creating the Service admits
	// it and the new port becomes reachable.
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

		// Add the forward before the backend exists: the operator must keep the
		// gateway up (its create-time forwards stay valid) and report
		// Ready=False/ServiceNotFound for the new forward.
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

		// Create the backend Service: the Service watch re-classifies the forward as
		// valid, the gateway returns Ready, and the new port becomes reachable.
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

// TestGatewayConsentLifecycle validates per-forward classification transitions
// driven by backend and consent-label changes on a live provisioned gateway:
// deleting a backend Service closes only its forward, and toggling the
// cross-namespace ingress consent label denies, admits (reachable over the
// wire), then re-denies a cross-namespace forward. It is one of four sharded
// top-level tests, each provisioning its own GCP gateway; teardown (registered
// by Start) drains every GCP resource the shard created.
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

	// service-deleted: a forward to a live backend works, then deleting the backend
	// Service drops only that forward (its port stops responding) while the
	// create-time forwards keep working and the gateway keeps its VM.
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
		// Ready=True is the fast signal that the operator classified the deletable
		// forward as valid and opened it; the data path through a freshly-opened
		// forward is already proven by the retained service-created probe, so this
		// scenario asserts the admit transition via the condition only.
		if _, err := client.WaitGatewayReady(ctx, stack.Namespace, stack.GatewayName, lifecycleReadyTimeout); err != nil {
			t.Fatalf("gateway not ready with deletable forward: %v", err)
		}

		// Delete the backend: the Service watch re-classifies the forward as
		// ServiceNotFound, the operator re-renders without it (closing the port), and
		// the gateway reports Ready=False/ServiceNotFound while keeping its VM.
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

		// A create-time forward must still work: dropping one forward does not
		// disturb the others.
		survivor, err := probeTCPThroughGateway(ctx, stack)
		if err != nil {
			t.Fatalf("create-time tcp forward broke after unrelated backend delete: %v", err)
		}
		assertBackendMarker(t, survivor, stack.TCPBackendName)
	})

	// consent-label-toggle: a cross-namespace forward into a NEW unlabelled
	// namespace is denied, adding the consent label admits it (and the port becomes
	// reachable), and removing the label re-denies it (and the port stops).
	//
	// The operator is cluster-scoped, so its informer cache and the
	// Namespace/Service watches cover all namespaces, including the cross-namespace
	// target. The consent-label change on that namespace is observed by the
	// cluster-wide Namespace watch, which drives the re-classification.
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

		// Create the target namespace WITHOUT the consent label and deploy the
		// backend in it.
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

		// Label added: admitted. Ready=True is the fast admit signal; the probe then
		// proves the freshly-consented cross-namespace forward carries traffic to the
		// consent-namespace backend over the wire, not merely that the condition
		// flipped.
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

	// backend-rollout proves a forward's DNAT targets the backend Service's stable
	// ClusterIP, not a specific pod: after rolling every backend pod the forward
	// still carries traffic, and the marker (agnhost /hostname, the serving pod's
	// name) identifies the same backend but a fresh pod. It uses its own dedicated
	// public port and backend Service, so it never disturbs the create-time forwards
	// or the other lifecycle subtests.
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

		// Roll the backend: every pod is replaced, so the forward must re-resolve to
		// the same ClusterIP and reach a pod with a different name. WaitDeploymentAvailable
		// only lets the rollout progress; at replicas=1 with the default RollingUpdate
		// strategy the old pod keeps the Deployment Available across the roll and can
		// linger in the Service endpoints, so a single post-roll probe can still catch
		// the old marker. Polling until the marker changes, under lifecycleReadyTimeout,
		// is the joint continuity + convergence gate: the roll plus the old-endpoint
		// drain can exceed dataPathDeadline, so it needs the longer budget.
		if err := client.RestartDeployment(ctx, stack.Namespace, svcName); err != nil {
			t.Fatalf("restart rollout backend: %v", err)
		}
		if err := client.WaitDeploymentAvailable(ctx, stack.Namespace, svcName, lifecycleReadyTimeout); err != nil {
			t.Fatalf("rollout backend not available after roll: %v", err)
		}
		// Close the endpoint-population lag the same way the retarget subtest does: a
		// Deployment can report Available before the fresh pod is registered as a ready
		// endpoint, so gate the post-roll convergence probe on a ready endpoint.
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

// TestGatewayTargetPortLifecycle validates targetPort classification on a live
// provisioned gateway (a forward to a non-published targetPort is denied and
// unreachable, then admitted and reachable once corrected) and that a second
// Gateway whose only forward targets an unlabelled namespace is denied without
// ever provisioning a VM. It is one of four sharded top-level tests, each
// provisioning its own GCP gateway; teardown (registered by Start) drains every
// GCP resource the shard created.
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

	// targetPort-not-listening: a forward whose targetPort names a port the backend
	// Service does not publish is denied (TargetPortNotListening); correcting the
	// targetPort to a published port admits it and the port becomes reachable. It
	// reuses the create-time TCP echo Service as the backend, attacking only its own
	// dedicated public port.
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

		// Add a forward to the TCP echo with a targetPort it does not publish.
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
		// The denied forward must also be closed at the firewall: prove the
		// wrong-targetPort port is unreachable over the wire, not just that the
		// condition reports it denied.
		if err := waitPortDenied(ctx, stack, stack.TargetPortScenarioPort, lifecycleReadyTimeout); err != nil {
			t.Fatalf("wrong-targetPort forward port did not stay closed: %v", err)
		}

		// Correct the targetPort to the published one: the operator admits the
		// forward and the port becomes reachable.
		if err := client.UpdateGateway(ctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
			return setForwardTargetPort(spec, stack.TargetPortScenarioPort, stack.TCPBackendPort)
		}); err != nil {
			t.Fatalf("correct targetPort: %v", err)
		}
		// Ready=True is the fast admit signal; the probe then proves the corrected
		// forward carries traffic to the create-time TCP echo backend over the wire.
		if _, err := client.WaitGatewayReady(ctx, stack.Namespace, stack.GatewayName, lifecycleReadyTimeout); err != nil {
			t.Fatalf("gateway not ready after targetPort corrected: %v", err)
		}
		marker, err := probeTCPThroughGatewayPort(ctx, stack, stack.TargetPortScenarioPort)
		if err != nil {
			t.Fatalf("corrected-targetPort data path: %v", err)
		}
		assertBackendMarker(t, marker, stack.TCPBackendName)
	})

	// cross-namespace-denied applies a SECOND Gateway whose only forward targets an
	// unlabelled namespace. With zero valid forwards and nothing provisioned, the
	// operator never creates a GCP VM; the subtest asserts the Ready=False denial
	// reason and cleans up its Gateway and namespace.
	t.Run("cross-namespace-denied", func(t *testing.T) {
		client := suite.Client()
		env := suite.Env()

		// A namespace that exists but lacks the consent label; the denial reason is
		// CrossNamespaceForwardDenied (not TargetNamespaceNotFound).
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
			// The denied Gateway never created an XGatewayGCP (validation stops first),
			// so its finalizer clears immediately; wait so the namespace teardown
			// does not race a finalizer-held object.
			if err := client.WaitGatewayGone(cctx, stack.Namespace, deniedGateway, deniedConditionTimeout); err != nil {
				t.Logf("cleanup wait denied gateway gone %s: %v", deniedGateway, err)
			}
		})

		if err := client.WaitGatewayCondition(ctx, stack.Namespace, deniedGateway,
			"Ready", "False", crossNamespaceForwardDeniedReason, deniedConditionTimeout); err != nil {
			t.Fatalf("denied gateway did not reach Ready=False reason %s: %v", crossNamespaceForwardDeniedReason, err)
		}
	})

	// link-pod-restart proves the data path survives losing the link pod: the link
	// owns wg0 and the nftables DNAT ruleset, both of which live in the pod, so a
	// replacement pod must re-establish the WireGuard tunnel to the persistent VM
	// and re-apply the DNAT before traffic flows again. It snapshots the link pods,
	// deletes them, waits for a Ready replacement with a new name (proving the old
	// pod was actually torn down, since the delete is async), and proves a
	// create-time forward carries traffic again. It adds no forward or backend, so
	// it needs no cleanup; the create-time TCP echo it probes is restored by the new
	// pod.
	t.Run("link-pod-restart", func(t *testing.T) {
		client := suite.Client()

		// Baseline: the create-time TCP forward works before the link pod is evicted.
		before, err := probeTCPThroughGateway(ctx, stack)
		if err != nil {
			t.Fatalf("create-time tcp forward broken before link restart: %v", err)
		}
		assertBackendMarker(t, before, stack.TCPBackendName)

		// Snapshot the current link pods before evicting them. The delete is async and
		// the Deployment can stay Available on the still-Ready old pod, so a name set
		// captured now lets the wait below gate on a genuinely new replacement rather
		// than the lingering original.
		linkSelector := fmt.Sprintf("app.kubernetes.io/component=link,app.kubernetes.io/instance=%s", stack.GatewayName)
		oldPods, err := client.PodNamesByLabel(ctx, stack.Namespace, linkSelector)
		if err != nil {
			t.Fatalf("list link pods before restart: %v", err)
		}

		// Evict the link pods by their component+instance labels; the Deployment's
		// Recreate strategy brings up a single replacement that re-owns wg0 and the
		// nftables ruleset.
		deleted, err := client.DeletePodsByLabel(ctx, stack.Namespace, linkSelector)
		if err != nil {
			t.Fatalf("delete link pods: %v", err)
		}
		if deleted < 1 {
			t.Fatalf("link selector %q in ns %q matched no pods", linkSelector, stack.Namespace)
		}

		// Wait for a Ready replacement whose name is not in the pre-delete set: the
		// Recreate strategy gives the new pod a fresh name, so this proves the old pod
		// was actually torn down and replaced, not that the async delete merely
		// returned while the original stayed up.
		if err := client.WaitForReplacementPod(ctx, stack.Namespace, linkSelector, oldPods, lifecycleReadyTimeout); err != nil {
			t.Fatalf("link pod not replaced after restart: %v", err)
		}

		// Traffic must resume through the replacement pod's freshly established tunnel
		// and DNAT; the data-path retry absorbs the handshake and rule convergence.
		after, err := probeTCPThroughGateway(ctx, stack)
		if err != nil {
			t.Fatalf("create-time tcp forward did not resume after link restart: %v", err)
		}
		assertBackendMarker(t, after, stack.TCPBackendName)
	})

	// Forward classification, retargeting, and validation transitions are covered by
	// TestClassifyForwards and TestForwardValidationTransitions in the controller
	// envtest; they are not duplicated here to keep each shard to a single VM.
}

// assertBackendMarker fails the test unless marker (an agnhost /hostname pod
// name) carries backend as a prefix. The serving pod's name is its Deployment's
// name plus a generated suffix, so the prefix identifies which backend answered;
// a mismatch means the forward routed to the wrong Service.
func assertBackendMarker(t *testing.T, marker, backend string) {
	t.Helper()
	if marker == "" {
		t.Fatalf("echo returned an empty marker; want a %q pod name", backend)
	}
	if !strings.HasPrefix(marker, backend) {
		t.Fatalf("echo marker %q is not from backend %q; forward routed to the wrong Service", marker, backend)
	}
}

// appendForward appends f to the Gateway spec's forwards slice in the
// unstructured shape the API server stores: each scalar is an int64 or string,
// with namespace and targetPort included only when set. It mirrors the encoding
// hk8s.CreateGateway uses so a spec edited here round-trips identically, including
// omitting a zero targetPort (which the CRD's minimum=1 would otherwise reject).
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

// removeForward drops the forward on the given public port from the Gateway spec's
// forwards slice, the inverse of appendForward. It is a no-op when no forward uses
// the port, so a scenario's cleanup is idempotent. Used to detach a lifecycle
// subtest's dedicated forward so the firewall ports stay disjoint for later
// probes.
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

// setForwardTargetPort sets the targetPort of the forward on the given public port,
// for the targetPort lifecycle subtest's correction step. It errors if no forward
// uses the port, so a misaddressed edit fails loudly rather than silently no-op'ing.
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
// backend Service, for the forward-retarget subtest. A non-empty namespace sets
// the cross-namespace target; an empty one deletes the key so the forward defaults
// to the Gateway's own namespace, mirroring appendForward's optional-field
// encoding. It errors if no forward uses the port, so a misaddressed edit fails
// loudly rather than silently no-op'ing.
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
