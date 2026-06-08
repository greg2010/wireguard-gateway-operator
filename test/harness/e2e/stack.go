package e2e

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"go.uber.org/zap"

	hk8s "github.com/greg2010/wireguard-gateway-operator/test/harness/k8s"
	"github.com/greg2010/wireguard-gateway-operator/test/harness/shared"
)

// Stack holds the per-test resources and the observed gateway facts the
// data-path assertions read.
type Stack struct {
	// Namespace is the test's namespace.
	Namespace string
	// NamePrefix is the run-unique prefix on every operator-owned object and GCP
	// resource; the orphan check filters on it. It is also the Gateway CR name.
	NamePrefix string
	// GatewayName is the name of the Gateway CR the suite created; the operator
	// names the XGatewayGCP composite after it.
	GatewayName string
	// Address is the gateway's observed public IP, the host-side probe target.
	Address string
	// TCPPublicPort / UDPPublicPort are the gateway ports the link forwards to
	// the in-namespace ClusterIP echo Services.
	TCPPublicPort int
	UDPPublicPort int
	// NodePortPublicPort is the gateway port forwarding to the NodePort-backed
	// echo Service.
	NodePortPublicPort int
	// CrossNSPublicPort is the gateway port forwarding to the echo Service in the
	// consent-labelled second namespace.
	CrossNSPublicPort int
	// EditedPublicPort is the gateway port the forward-edit subtest adds live; it
	// forwards to the in-namespace TCP echo Service once the edit rolls the link.
	EditedPublicPort int
	// ServiceCreatedPort / ServiceDeletedPort / ConsentTogglePort /
	// TargetPortScenarioPort are the dedicated public ports the lifecycle subtests
	// attach a runtime forward to and remove again, each disjoint from the
	// create-time forwards and the negative port.
	ServiceCreatedPort     int
	ServiceDeletedPort     int
	ConsentTogglePort      int
	TargetPortScenarioPort int
	// BackendRolloutPort is the dedicated public port the backend-rollout subtest
	// forwards to a backend it then restarts, proving the DNAT to the backend's
	// stable ClusterIP survives pod churn.
	BackendRolloutPort int
	// ForwardRetargetPort is the dedicated public port the forward-retarget subtest
	// forwards to one backend then retargets to a second, proving bytes follow the
	// retarget.
	ForwardRetargetPort int
	// NegativePort is a non-forwarded public port the negative probes target; it
	// is dropped at the GCP firewall. Start asserts it is disjoint from the
	// forwarded ports and the WireGuard listen port.
	NegativePort int
	// WireguardListenPort is the gateway VM's WireGuard UDP listen port for this
	// stack, the port the operator opens in this gateway's firewall rule. It is
	// the default (wgListenPort) unless StartWithWireguardListenPort overrode it,
	// which the coexistence test uses to give two gateways distinct WG ports and
	// assert each gateway's firewall admits only its own.
	WireguardListenPort int

	// TCPBackendName / NodePortBackendName / CrossNSBackendName are the echo
	// Deployment names behind the TCP, NodePort, and cross-namespace forwards.
	// agnhost /hostname returns the serving pod's name, which a Deployment prefixes
	// with its own name, so a positive probe can assert it hit the intended backend
	// (catching a misrouted forward) by checking the marker carries the matching
	// prefix.
	TCPBackendName      string
	NodePortBackendName string
	CrossNSBackendName  string
	// TCPBackendPort is the published port of the in-namespace TCP echo Service
	// (TCPBackendName). The targetPort lifecycle subtest forwards to it, first with
	// a wrong targetPort (rejected) then this one (admitted).
	TCPBackendPort int

	// extraNamespaces are namespaces Start created beyond the primary one (the
	// cross-namespace echo namespace); teardown deletes them.
	extraNamespaces []string

	suite *Suite
	log   *zap.Logger
}

// StartOption configures an optional, per-stack override applied before
// provisioning. Existing single-gateway shards pass none and get the defaults;
// the coexistence test uses WithWireguardListenPort to give two gateways distinct
// WG ports.
type StartOption func(*startConfig)

// startConfig holds the resolved per-stack overrides StartE applies. Its
// zero-value reflects the standard single-gateway shard, so a stack created with
// no options behaves exactly as before.
type startConfig struct {
	// wgListenPort overrides the gateway VM's WireGuard listen port. Zero means
	// use the suite-wide wgListenPort default.
	wgListenPort int
}

// WithWireguardListenPort overrides the gateway VM's WireGuard UDP listen port
// for the stack, so coexisting gateways can run distinct WG ports and a caller
// can assert each gateway's firewall admits only its own. The port is set on the
// Gateway CR's spec.wireguard.listenPort and recorded on Stack.WireguardListenPort,
// and is folded into the negative-port disjointness precondition.
func WithWireguardListenPort(port int) StartOption {
	return func(c *startConfig) { c.wgListenPort = port }
}

// Start brings up a full per-test stack and fails the test if it cannot. It is a
// thin wrapper over StartE for the common single-gateway shard, where a failed
// bring-up should abort the test immediately; it keeps the (*Stack, error)
// signature so existing call sites are unchanged. Tests that bring up several
// stacks concurrently call StartE directly so a bring-up error can be collected
// off the test goroutine (where t.Fatal is illegal) and re-raised on it.
func (s *Suite) Start(ctx context.Context, t *testing.T, opts ...StartOption) (*Stack, error) {
	t.Helper()
	stack, err := s.StartE(ctx, t, opts...)
	if err != nil {
		t.Fatalf("start stack: %v", err)
	}
	return stack, nil
}

// StartE brings up a full per-test stack: a namespace, the TCP+UDP echo
// fixtures, and a Gateway CR provisioning a real GCP gateway. The always
// cluster-scoped operator is installed once by Setup, so StartE only creates the
// Gateway CR;
// the shared operator reconciles it into the XGatewayGCP composite, Crossplane
// provisions the gateway VM, and the operator mirrors the public IP up to
// Gateway.status.address. StartE polls that status for the host-side data-path
// probes. Teardown (Gateway delete + GCP drain assertion + namespace delete) is
// registered via t.Cleanup; the operator is suite-owned and is not touched here.
//
// StartE returns every failure as an error and never calls t.Fatal, so it is
// safe to run off the test goroutine (e.g. under errgroup) when a test provisions
// concurrent gateways. registerTeardown, which it still calls, uses only
// t.Cleanup/t.Errorf/t.Logf, all of which are goroutine-safe.
func (s *Suite) StartE(ctx context.Context, t *testing.T, opts ...StartOption) (*Stack, error) {
	t.Helper()

	var cfg startConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	wgPort := wgListenPort
	if cfg.wgListenPort != 0 {
		wgPort = cfg.wgListenPort
	}

	// Fail fast before provisioning if the negative probe port is not disjoint
	// from the forwarded ports or the WireGuard listen port; otherwise a later
	// forwards change could silently make the negative probe a false pass. The
	// effective WG port is passed so a per-stack override is covered too.
	if err := negativePortDisjointError(wgPort); err != nil {
		return nil, err
	}

	// prefix is the run-unique base for the test namespace, the Gateway CR, and
	// every GCP resource the composition creates. It is kept short and label-safe
	// so the operator-derived GCP service-account ID stays within GCP's 30-char
	// limit while remaining a usable name filter for the orphan check. The
	// test-name slug is logged but deliberately kept out of the prefix to preserve
	// that budget.
	prefix := "gw" + shared.ShortID()
	ns := prefix
	log := s.log.With(
		zap.String("ns", ns),
		zap.String("prefix", prefix),
		zap.String("test", shared.Slug(t.Name())),
	)

	if err := s.client.EnsureNamespace(ctx, ns); err != nil {
		return nil, fmt.Errorf("ensure namespace: %w", err)
	}

	echo, err := s.client.DeployEchoFixtures(ctx, ns)
	if err != nil {
		return nil, fmt.Errorf("deploy echo fixtures: %w", err)
	}

	nodePortEcho, err := s.client.DeployNodePortEcho(ctx, ns)
	if err != nil {
		return nil, fmt.Errorf("deploy nodeport echo: %w", err)
	}

	// The cross-namespace echo lives in a second namespace carrying the consent
	// label, so the operator permits the Gateway in ns to forward into it.
	xnsNamespace := prefix + "-xns"
	crossNSEcho, err := s.client.DeployEchoInNamespace(ctx, xnsNamespace, map[string]string{
		crossNamespaceIngressLabel: crossNamespaceIngressValue,
	})
	if err != nil {
		return nil, fmt.Errorf("deploy cross-namespace echo: %w", err)
	}

	stack := &Stack{
		Namespace:              ns,
		NamePrefix:             prefix,
		GatewayName:            prefix,
		TCPPublicPort:          tcpPublicPort,
		UDPPublicPort:          udpPublicPort,
		NodePortPublicPort:     nodePortPublicPort,
		CrossNSPublicPort:      crossNSPublicPort,
		EditedPublicPort:       editedPublicPort,
		ServiceCreatedPort:     serviceCreatedPort,
		ServiceDeletedPort:     serviceDeletedPort,
		ConsentTogglePort:      consentTogglePort,
		TargetPortScenarioPort: targetPortScenarioPort,
		BackendRolloutPort:     backendRolloutPort,
		ForwardRetargetPort:    forwardRetargetPort,
		NegativePort:           negativePort,
		WireguardListenPort:    wgPort,
		TCPBackendName:         echo.TCPService,
		NodePortBackendName:    nodePortEcho.Service,
		CrossNSBackendName:     crossNSEcho.Service,
		TCPBackendPort:         echo.TCPPort,
		extraNamespaces:        []string{xnsNamespace},
		suite:                  s,
		log:                    log,
	}
	s.registerTeardown(t, stack)

	if err := s.client.CreateGateway(ctx, ns, stack.GatewayName, gatewaySpec(s.env, echo, nodePortEcho, crossNSEcho, wgPort)); err != nil {
		return nil, fmt.Errorf("create gateway: %w", err)
	}

	status, err := s.client.WaitGatewayReady(ctx, ns, stack.GatewayName, gatewayReadyTimeout)
	if err != nil {
		return nil, fmt.Errorf("wait gateway ready: %w", err)
	}
	stack.Address = status.Address
	log.Info("gateway ready", zap.String("address", status.Address))

	return stack, nil
}

// crossNamespaceIngressLabel and crossNamespaceIngressValue mirror the operator's
// consent gate (internal/controller). A namespace must carry this label before a
// Gateway in another namespace may forward public traffic into it. They are
// duplicated here, like the orphan check's gcpID, because the operator's are
// unexported.
const (
	crossNamespaceIngressLabel = "wgnet.dev/allow-gateway-ingress"
	crossNamespaceIngressValue = "true"
)

// gatewaySpec builds the Gateway CR spec for the run: the GCP placement from the
// suite env and the create-time forwards. It forwards the TCP and UDP ClusterIP
// echoes, the NodePort echo (same namespace), and the cross-namespace echo (its
// bare Service name plus its namespace, which carries the consent label). The
// forward-edit subtest adds a further forward at runtime; it is not built here.
//
// wgPort is the effective WireGuard listen port. When it equals the suite-wide
// wgListenPort default the field is left unset so the CR relies on the CRD
// default and its shape is unchanged; a non-default port (the coexistence test's
// per-gateway override) is pinned on spec.wireguard.listenPort.
func gatewaySpec(env Env, echo hk8s.EchoFixtures, nodePort, crossNS hk8s.EchoBackend, wgPort int) hk8s.GatewaySpec {
	spec := hk8s.GatewaySpec{
		ProjectID:   env.ProjectID,
		Region:      env.Region,
		Zone:        env.Zone,
		MachineType: "e2-micro",
		Forwards: []hk8s.GatewayForward{
			{
				Port:       tcpPublicPort,
				Protocol:   "TCP",
				Service:    echo.TCPService,
				TargetPort: echo.TCPPort,
			},
			{
				Port:       udpPublicPort,
				Protocol:   "UDP",
				Service:    echo.UDPService,
				TargetPort: echo.UDPPort,
			},
			{
				Port:       nodePortPublicPort,
				Protocol:   "TCP",
				Service:    nodePort.Service,
				TargetPort: nodePort.Port,
			},
			{
				Port:       crossNSPublicPort,
				Protocol:   "TCP",
				Service:    crossNS.Service,
				Namespace:  crossNS.Namespace,
				TargetPort: crossNS.Port,
			},
		},
	}
	if wgPort != wgListenPort {
		spec.WireguardListenPort = wgPort
	}
	return spec
}

// registerTeardown registers, in reverse order, the namespace delete and the
// Gateway-delete-driven GCP drain. The drain is ordered: delete the Gateway (the
// operator's finalizer deletes the XGatewayGCP and Crossplane drains the GCP VM),
// wait until both the Gateway and its XGatewayGCP are gone and the GCP orphan check
// reaches zero, all while the namespace stays alive; only then delete the
// namespace. The operator is suite-owned and shared across Stacks, so it is not
// uninstalled here. On failure with GATEWAY_E2E_PRESERVE set the per-test
// resources are left in place for post-mortem.
func (s *Suite) registerTeardown(t *testing.T, stack *Stack) {
	t.Cleanup(func() {
		if t.Failed() && os.Getenv("GATEWAY_E2E_PRESERVE") != "" {
			s.log.Warn("test failed; preserving per-test resources", zap.String("ns", stack.Namespace))
			return
		}
		// Cleanup runs in t.Cleanup, which still counts against the whole-binary
		// `go test -timeout 10m`, so this context must finish well under that or a
		// slow run is SIGKILLed mid-drain and leaks the GCP VM the orphan check
		// exists to catch. orphanDrainTimeout (4m) is one full drain window for
		// WaitGatewayGone, which blocks on the operator finalizer until the XGatewayGCP
		// and its GCP resources are gone; the +3m absorbs the post-drain orphan
		// check (fast once the drain completed, with headroom for GCP delete
		// propagation) plus the namespace deletes. The sum (7m) leaves
		// the binary room for the setup and test work that ran before teardown. A
		// drain genuinely stuck past this window is a real GCP-side hang the orphan
		// check would surface anyway, not a budget to widen.
		cctx, cancel := context.WithTimeout(context.Background(), orphanDrainTimeout+3*time.Minute)
		defer cancel()

		auth := gcpAuth{projectID: s.env.ProjectID, credsFile: s.env.CredsFile}

		if t.Failed() {
			s.dumpDiagnostics(cctx, t, stack, auth)
		}

		// GATEWAY_E2E_KEEP leaves every resource up (cluster, release, namespaces,
		// and the GCP gateway VM) for live debugging, regardless of pass or fail.
		// The diagnostic dump above still ran, so a failed run keeps both the
		// captured serial console and the live VM. Skipping the drain leaks the GCP
		// resources until the operator drains them by hand, hence the hints.
		if s.env.Keep {
			s.log.Warn("GATEWAY_E2E_KEEP set; skipping teardown, leaving resources up for debugging",
				zap.String("ns", stack.Namespace),
				zap.String("gateway", stack.GatewayName),
				zap.String("gcp_instance_prefix", stack.NamePrefix),
				zap.String("gcp_zone", s.env.Zone),
				zap.String("gcp_project", s.env.ProjectID),
				zap.String("ssh_hint", fmt.Sprintf(
					"gcloud compute ssh %s-* --zone %s --project %s",
					stack.NamePrefix, s.env.Zone, s.env.ProjectID)),
				zap.String("serial_hint", fmt.Sprintf(
					"gcloud compute instances get-serial-port-output %s-* --port 1 --zone %s --project %s",
					stack.NamePrefix, s.env.Zone, s.env.ProjectID)),
				zap.String("drain_hint", fmt.Sprintf(
					"kubectl delete gateway %s -n %s  # then re-run to drain GCP",
					stack.GatewayName, stack.Namespace)))
			return
		}

		// Delete the Gateway first; its finalizer drives the ordered GCP drain.
		// Force-deleting the namespace here would bypass the finalizer and orphan
		// the GCP resources, so the namespace must outlive the drain.
		if err := s.client.DeleteGateway(cctx, stack.Namespace, stack.GatewayName); err != nil {
			s.log.Error("delete gateway", zap.Error(err))
		}
		// Wait for the operator's finalizer to clear (Gateway gone). The finalizer
		// requeues until the XGatewayGCP is absent, and the XGatewayGCP's own finalizer
		// holds until Crossplane drains its GCP resources, so the Gateway
		// disappearing is the in-cluster signal that the drain reached the cloud.
		// The GCP orphan check below is the authoritative zero signal.
		if err := s.client.WaitGatewayGone(cctx, stack.Namespace, stack.GatewayName, orphanDrainTimeout); err != nil {
			s.log.Error("wait gateway gone", zap.Error(err))
		}
		// Once the Gateway is gone the XGatewayGCP is already absent; this is a fast
		// confirmation, not a second drain wait.
		if err := s.client.WaitXGatewayGCPGone(cctx, stack.Namespace, stack.GatewayName, orphanDrainTimeout); err != nil {
			s.log.Error("wait xgatewaygcp gone", zap.Error(err))
		}
		// The GCP drain reaching zero, with the namespace still alive so the
		// provider can write the per-namespace ProviderConfigUsage each composed
		// MR needs to release its GCP resource, is the authoritative drain signal.
		// assertNoOrphans covers every provisioned family, including the
		// hash-derived ServiceAccount and Secret, so a Gateway delete that leaks any
		// of them fails the test here.
		s.log.Info("asserting no orphaned GCP resources after gateway deletion",
			zap.String("prefix", stack.NamePrefix))
		if err := assertNoOrphans(cctx, auth, stack.Namespace, stack.GatewayName, stack.NamePrefix, orphanDrainTimeout, s.log); err != nil {
			t.Errorf("orphaned GCP resources after teardown: %v", err)
		}
		if err := s.client.DeleteNamespace(cctx, stack.Namespace); err != nil {
			s.log.Error("delete namespace", zap.Error(err))
		}
		// The extra namespaces (the cross-namespace echo) hold no GCP-backed
		// resources and no finalizers, so they can be deleted alongside the primary
		// namespace once the drain has completed.
		for _, ns := range stack.extraNamespaces {
			if err := s.client.DeleteNamespace(cctx, ns); err != nil {
				s.log.Error("delete extra namespace", zap.String("ns", ns), zap.Error(err))
			}
		}
	})
}
