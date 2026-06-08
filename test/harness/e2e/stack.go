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
	Namespace string
	// NamePrefix is the run-unique prefix on every operator-owned object and GCP
	// resource the orphan check filters on. It is also the Gateway CR name.
	NamePrefix string
	// GatewayName is the Gateway CR name; the operator names the XGatewayGCP
	// composite after it.
	GatewayName string
	// Address is the gateway's observed public IP, the host-side probe target.
	Address       string
	TCPPublicPort int
	UDPPublicPort int
	// NodePortPublicPort forwards to the NodePort-backed echo Service.
	NodePortPublicPort int
	// CrossNSPublicPort forwards to the echo Service in the consent-labelled
	// second namespace.
	CrossNSPublicPort int
	// EditedPublicPort is the port the forward-edit subtest adds live.
	EditedPublicPort int
	// The lifecycle subtests attach a runtime forward to these dedicated ports and
	// remove it again, each disjoint from the create-time forwards and negativePort.
	ServiceCreatedPort     int
	ServiceDeletedPort     int
	ConsentTogglePort      int
	TargetPortScenarioPort int
	BackendRolloutPort     int
	ForwardRetargetPort    int
	// NegativePort is a non-forwarded port the negative probes target, dropped at
	// the GCP firewall. Start asserts it is disjoint from the forwarded and WG ports.
	NegativePort int
	// WireguardListenPort is this stack's WireGuard UDP listen port, opened in the
	// gateway's firewall rule; WithWireguardListenPort gives coexisting gateways
	// distinct ports.
	WireguardListenPort int
	// LinkReplicas is the link Deployment's effective replica count (override, or 1).
	// Teardown reads it to decide whether the link PDB should exist, applied only at
	// replicas>1.
	LinkReplicas int32

	// TCPBackendName, NodePortBackendName, and CrossNSBackendName are the echo
	// Deployment names behind the create-time forwards. agnhost /hostname returns the
	// serving pod's name, prefixed by its Deployment's, so a probe matches by prefix.
	TCPBackendName      string
	NodePortBackendName string
	CrossNSBackendName  string
	// TCPBackendPort is the published port of the TCP echo Service. The targetPort
	// subtest forwards to it, first with a wrong targetPort then this one.
	TCPBackendPort int

	// extraNamespaces are namespaces Start created beyond the primary one; teardown
	// deletes them.
	extraNamespaces []string

	suite *Suite
	log   *zap.Logger
}

// StartOption configures a per-stack override applied before provisioning.
type StartOption func(*startConfig)

// startConfig holds the resolved per-stack overrides StartE applies; its zero value
// is the standard single-gateway shard.
type startConfig struct {
	// wgListenPort overrides the WireGuard listen port. Zero uses the wgListenPort
	// default.
	wgListenPort int
	// linkReplicas overrides the link replica count. Zero uses the CRD default (1).
	linkReplicas int32
}

// WithWireguardListenPort overrides the stack's WireGuard UDP listen port, so
// coexisting gateways can run distinct WG ports. It is folded into the negative-port
// disjointness precondition.
func WithWireguardListenPort(port int) StartOption {
	return func(c *startConfig) { c.wgListenPort = port }
}

// WithLinkReplicas brings the gateway up with n link replicas behind leader
// election, so the HA test gets a hot standby. n must be >=1 (the CRD's minimum).
func WithLinkReplicas(n int32) StartOption {
	return func(c *startConfig) { c.linkReplicas = n }
}

// Start wraps StartE for the common single-gateway shard, failing the test on error.
// Tests bringing up several stacks concurrently call StartE directly to collect the
// error off the test goroutine, where t.Fatal is illegal.
func (s *Suite) Start(ctx context.Context, t *testing.T, opts ...StartOption) (*Stack, error) {
	t.Helper()
	stack, err := s.StartE(ctx, t, opts...)
	if err != nil {
		t.Fatalf("start stack: %v", err)
	}
	return stack, nil
}

// StartE brings up a full per-test stack (namespace, echo fixtures, a Gateway CR
// provisioning a real GCP gateway) and registers teardown via t.Cleanup. It returns
// every failure as an error rather than t.Fatal, so it is errgroup-safe.
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

	// Fail fast before provisioning so a later forwards change cannot silently turn
	// the negative probe into a false pass.
	if err := negativePortDisjointError(wgPort); err != nil {
		return nil, err
	}

	// prefix bases the namespace, Gateway CR, and GCP resources. Kept short and
	// label-safe so the operator-derived service-account ID fits GCP's 30-char limit;
	// the test-name slug is logged, not folded in, to preserve it.
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
		LinkReplicas:           effectiveLinkReplicas(cfg.linkReplicas),
		TCPBackendName:         echo.TCPService,
		NodePortBackendName:    nodePortEcho.Service,
		CrossNSBackendName:     crossNSEcho.Service,
		TCPBackendPort:         echo.TCPPort,
		extraNamespaces:        []string{xnsNamespace},
		suite:                  s,
		log:                    log,
	}
	s.registerTeardown(t, stack)

	if err := s.client.CreateGateway(ctx, ns, stack.GatewayName, gatewaySpec(s.env, echo, nodePortEcho, crossNSEcho, wgPort, cfg.linkReplicas)); err != nil {
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
// unexported consent gate: a namespace must carry this label before a Gateway in
// another namespace may forward into it.
const (
	crossNamespaceIngressLabel = "wgnet.dev/allow-gateway-ingress"
	crossNamespaceIngressValue = "true"
)

// gatewaySpec builds the Gateway CR spec: GCP placement plus the create-time forwards
// (TCP/UDP ClusterIP, NodePort, cross-namespace echoes). wgPort and linkReplicas are
// pinned only when non-default, else the CR relies on the CRD default.
func gatewaySpec(env Env, echo hk8s.EchoFixtures, nodePort, crossNS hk8s.EchoBackend, wgPort int, linkReplicas int32) hk8s.GatewaySpec {
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
	if linkReplicas > 0 {
		spec.Replicas = linkReplicas
	}
	return spec
}

// effectiveLinkReplicas resolves the configured link replica count to what the
// operator runs with: the override, or 1 when unset. It mirrors the operator's
// unexported effectiveLinkReplicas so teardown can tell whether the link PDB exists.
func effectiveLinkReplicas(configured int32) int32 {
	if configured == 0 {
		return 1
	}
	return configured
}

// registerTeardown registers the ordered GCP drain: delete the Gateway (whose
// finalizer drains the XGatewayGCP and VM), wait for the orphan check to reach zero
// with the namespace alive, then delete the namespace. GATEWAY_E2E_PRESERVE keeps a failure.
func (s *Suite) registerTeardown(t *testing.T, stack *Stack) {
	t.Cleanup(func() {
		if t.Failed() && os.Getenv("GATEWAY_E2E_PRESERVE") != "" {
			s.log.Warn("test failed; preserving per-test resources", zap.String("ns", stack.Namespace))
			return
		}
		// Bounded under the whole-binary `go test -timeout 10m` so a slow drain is not
		// SIGKILLed mid-flight and left leaking the VM: one drain window plus headroom
		// for the post-drain orphan check and namespace deletes.
		cctx, cancel := context.WithTimeout(context.Background(), orphanDrainTimeout+3*time.Minute)
		defer cancel()

		auth := gcpAuth{projectID: s.env.ProjectID, credsFile: s.env.CredsFile}

		if t.Failed() {
			s.dumpDiagnostics(cctx, t, stack, auth)
		}

		// GATEWAY_E2E_KEEP leaves every resource up for debugging regardless of result;
		// the hints cover the by-hand drain that then leaks until run.
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

		// Delete the Gateway first; its finalizer drives the GCP drain. A namespace
		// force-delete would bypass it and orphan the resources, so the namespace must
		// outlive the drain.
		if err := s.client.DeleteGateway(cctx, stack.Namespace, stack.GatewayName); err != nil {
			s.log.Error("delete gateway", zap.Error(err))
		}
		// The Gateway disappearing signals the drain reached the cloud (its finalizer
		// requeues until the XGatewayGCP is gone); the orphan check below is the
		// authoritative zero.
		if err := s.client.WaitGatewayGone(cctx, stack.Namespace, stack.GatewayName, orphanDrainTimeout); err != nil {
			s.log.Error("wait gateway gone", zap.Error(err))
		}
		// A fast confirmation, not a second drain wait.
		if err := s.client.WaitXGatewayGCPGone(cctx, stack.Namespace, stack.GatewayName, orphanDrainTimeout); err != nil {
			s.log.Error("wait xgatewaygcp gone", zap.Error(err))
		}
		// Keep the namespace alive so the provider can write the per-namespace
		// ProviderConfigUsage each MR needs to release its resource. assertNoOrphans
		// covers every family, including the hash-derived SA and Secret.
		s.log.Info("asserting no orphaned GCP resources after gateway deletion",
			zap.String("prefix", stack.NamePrefix))
		if err := assertNoOrphans(cctx, auth, stack.Namespace, stack.GatewayName, stack.NamePrefix, orphanDrainTimeout, s.log); err != nil {
			t.Errorf("orphaned GCP resources after teardown: %v", err)
		}
		// Assert owner-ref GC reaped the Gateway's children while the namespace is
		// alive, before the namespace delete below would mask a child left by a broken
		// owner reference. expectPDB tracks replicas since the PDB exists only at >1.
		s.client.AssertOwnedChildrenGone(cctx, t, stack.Namespace, stack.GatewayName, stack.LinkReplicas > 1, orphanDrainTimeout)
		if err := s.client.DeleteNamespace(cctx, stack.Namespace); err != nil {
			s.log.Error("delete namespace", zap.Error(err))
		}
		// The extra namespaces hold no GCP-backed resources or finalizers, so they
		// can go alongside the primary one.
		for _, ns := range stack.extraNamespaces {
			if err := s.client.DeleteNamespace(cctx, ns); err != nil {
				s.log.Error("delete extra namespace", zap.String("ns", ns), zap.Error(err))
			}
		}
	})
}
