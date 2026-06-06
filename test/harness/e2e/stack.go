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
	// Release is the operator helm release name.
	Release string
	// NamePrefix is the run-unique prefix on every operator-owned object and GCP
	// resource; the orphan check filters on it. It is also the Gateway CR name.
	NamePrefix string
	// GatewayName is the name of the Gateway CR the suite created; the operator
	// names the XGateway composite after it.
	GatewayName string
	// Address is the gateway's observed public IP, the host-side probe target.
	Address string
	// TCPPublicPort / UDPPublicPort are the gateway ports the link forwards to
	// the echo Services.
	TCPPublicPort int
	UDPPublicPort int
	// NegativePort is a non-forwarded public port the negative probes target; it
	// is dropped at the GCP firewall. Start asserts it is disjoint from the
	// forwarded ports and the WireGuard listen port.
	NegativePort int

	suite *Suite
	log   *zap.Logger
}

// Start brings up a full per-test stack: a namespace, the TCP+UDP echo
// fixtures, the operator release, and a Gateway CR provisioning a real GCP
// gateway. The operator chart installs the operator (Deployment + RBAC + CRDs +
// XRD/Composition + static Ignition); --wait blocks until the operator
// Deployment is Available. The suite then creates a Gateway CR; the operator
// reconciles it into the XGateway composite, Crossplane provisions the gateway
// VM, and the operator mirrors the public IP up to Gateway.status.address. Start
// polls that status for the host-side data-path probes. Teardown (Gateway
// delete + GCP drain assertion + uninstall) is registered via t.Cleanup.
func (s *Suite) Start(ctx context.Context, t *testing.T) (*Stack, error) {
	t.Helper()

	// Fail fast before provisioning if the negative probe port is not disjoint
	// from the forwarded ports or the WireGuard listen port; otherwise a later
	// forwards change could silently make the negative probe a false pass.
	assertNegativePortDisjoint(t)

	// prefix is the run-unique base for the operator's chart-rendered objects,
	// the Gateway CR, and every GCP resource the composition creates. It is kept
	// short and label-safe so the operator-derived GCP service-account ID stays
	// within GCP's 30-char limit while remaining a usable name filter for the
	// orphan check. The test-name slug is logged but deliberately kept out of the
	// prefix to preserve that budget.
	prefix := "cyno" + shared.ShortID()
	ns := prefix
	release := prefix
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

	stack := &Stack{
		Namespace:     ns,
		Release:       release,
		NamePrefix:    prefix,
		GatewayName:   prefix,
		TCPPublicPort: tcpPublicPort,
		UDPPublicPort: udpPublicPort,
		NegativePort:  negativePort,
		suite:         s,
		log:           log,
	}
	s.registerTeardown(t, stack)

	if err := s.installOperator(ctx, ns, release, prefix); err != nil {
		return nil, fmt.Errorf("operator install: %w", err)
	}
	// The operator Deployment is named after the chart, which the overlay's
	// nameOverride sets to the run prefix.
	if err := s.client.WaitDeploymentAvailable(ctx, ns, prefix, operatorReadyTimeout); err != nil {
		return nil, fmt.Errorf("operator deployment not available: %w", err)
	}

	if err := s.client.CreateGateway(ctx, ns, stack.GatewayName, gatewaySpec(s.env, echo)); err != nil {
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

// gatewaySpec builds the Gateway CR spec for the run: the GCP placement from the
// suite env and the TCP+UDP forwards pointing at the in-cluster echo Services.
func gatewaySpec(env Env, echo hk8s.EchoFixtures) hk8s.GatewaySpec {
	return hk8s.GatewaySpec{
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
		},
	}
}

// installOperator renders the run's overlay values and installs the operator
// release in one shot. Wait blocks helm until the release's objects settle; the
// operator Deployment readiness is then asserted explicitly (it has no readiness
// dependency on a provisioned Gateway, so --wait suffices for the chart but the
// suite polls it before creating the Gateway).
func (s *Suite) installOperator(ctx context.Context, ns, release, prefix string) error {
	valuesPath, err := writeValues(os.TempDir(), valuesParams{
		namePrefix:    prefix,
		env:           s.env,
		operatorImage: s.operatorImage,
		linkImage:     s.linkImage,
	})
	if err != nil {
		return err
	}
	return s.helm.Install(ctx, hk8s.ReleaseSpec{
		Name:        release,
		Namespace:   ns,
		ChartPath:   "k8s/charts/wireguard-gateway-operator",
		ValuesFiles: []string{valuesPath},
		Wait:        true,
		Timeout:     operatorInstallTimeout,
	})
}

// registerTeardown registers, in reverse order, the operator uninstall, the
// namespace delete, and the Gateway-delete-driven GCP drain. The drain is
// ordered: delete the Gateway (the operator's finalizer deletes the XGateway and
// Crossplane drains the GCP VM), wait until both the Gateway and its XGateway are
// gone and the GCP orphan check reaches zero, all while the namespace stays
// alive; only then uninstall the operator and delete the namespace. On failure
// with CYNO_E2E_PRESERVE set the per-test resources are left in place for
// post-mortem.
func (s *Suite) registerTeardown(t *testing.T, stack *Stack) {
	t.Cleanup(func() {
		if t.Failed() && os.Getenv("CYNO_E2E_PRESERVE") != "" {
			s.log.Warn("test failed; preserving per-test resources", zap.String("ns", stack.Namespace))
			return
		}
		// The parent budget covers one full drain (WaitGatewayGone blocks on the
		// operator finalizer, which holds until the XGateway and its GCP resources
		// are gone) plus a second drain budget so the authoritative GCP orphan
		// check still gets its full window even if the in-cluster wait above timed
		// out, plus slack for the dump, uninstall, and namespace delete.
		cctx, cancel := context.WithTimeout(context.Background(), 2*orphanDrainTimeout+3*time.Minute)
		defer cancel()

		if t.Failed() {
			s.dumpDiagnostics(cctx, t, stack)
		}

		// Delete the Gateway first; its finalizer drives the ordered GCP drain.
		// Force-deleting the namespace here would bypass the finalizer and orphan
		// the GCP resources, so the namespace must outlive the drain.
		if err := s.client.DeleteGateway(cctx, stack.Namespace, stack.GatewayName); err != nil {
			s.log.Error("delete gateway", zap.Error(err))
		}
		// Wait for the operator's finalizer to clear (Gateway gone). The finalizer
		// requeues until the XGateway is absent, and the XGateway's own finalizer
		// holds until Crossplane drains its GCP resources, so the Gateway
		// disappearing is the in-cluster signal that the drain reached the cloud.
		// The GCP orphan check below is the authoritative zero signal.
		if err := s.client.WaitGatewayGone(cctx, stack.Namespace, stack.GatewayName, orphanDrainTimeout); err != nil {
			s.log.Error("wait gateway gone", zap.Error(err))
		}
		// Once the Gateway is gone the XGateway is already absent; this is a fast
		// confirmation, not a second drain wait.
		if err := s.client.WaitXGatewayGone(cctx, stack.Namespace, stack.GatewayName, orphanDrainTimeout); err != nil {
			s.log.Error("wait xgateway gone", zap.Error(err))
		}
		// The GCP drain reaching zero, with the namespace still alive so the
		// provider can write the per-namespace ProviderConfigUsage each composed
		// MR needs to release its GCP resource, is the authoritative drain signal.
		auth := gcpAuth{projectID: s.env.ProjectID, credsFile: s.env.CredsFile}
		if err := assertNoOrphans(cctx, auth, stack.NamePrefix, orphanDrainTimeout, s.log); err != nil {
			t.Errorf("orphaned GCP resources after teardown: %v", err)
		}
		if err := s.helm.Uninstall(cctx, stack.Release, stack.Namespace); err != nil {
			s.log.Error("helm uninstall operator", zap.Error(err))
		}
		if err := s.client.DeleteNamespace(cctx, stack.Namespace); err != nil {
			s.log.Error("delete namespace", zap.Error(err))
		}
	})
}
