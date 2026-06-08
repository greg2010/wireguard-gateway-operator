package e2e

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"

	hk8s "github.com/greg2010/wireguard-gateway-operator/test/harness/k8s"
	"github.com/greg2010/wireguard-gateway-operator/test/harness/shared"
)

const (
	crossplaneNamespace = "crossplane-system"
	crossplaneRelease   = "crossplane"
	providersRelease    = "crossplane-providers"
	configRelease       = "crossplane-config"

	// operatorNamespace and operatorRelease name the single, cluster-scoped
	// operator install. The chart renders cluster-singletons (the Gateway CRD, the
	// XGatewayGCP and XGatewayNetwork XRDs and Compositions, and a fixed-name
	// ClusterRole/ClusterRoleBinding), so it must be installed exactly once per
	// cluster; the one operator reconciles Gateways across every per-test namespace.
	operatorNamespace = "gateway-operator"
	operatorRelease   = "gateway-operator"
	// operatorNameOverride pins the chart name so the operator Deployment has a
	// deterministic name the suite waits on. With one install per cluster the
	// release prefix is redundant, so the chart-rendered objects are named after
	// this value directly.
	operatorNameOverride = "gateway-operator"

	// gatewayCRDName and xgatewayXRDName are the cluster-singleton custom-resource
	// definitions the operator install brings: the user-facing Gateway CRD and the
	// XGatewayGCP composite XRD. The suite waits on both before any Stack creates a
	// Gateway.
	gatewayCRDName  = "gateways.wgnet.dev"
	xgatewayXRDName = "xgatewaygcps.infra.wgnet.dev"

	// crossplaneChartVersion pins the Crossplane core chart.
	crossplaneChartVersion = "2.3.1"
	crossplaneChartRepo    = "https://charts.crossplane.io/stable"
	crossplaneChartName    = "crossplane"

	// coreInstallTimeout bounds the helm --wait for Crossplane core. Kept under
	// the go-test deadline so a stuck install fails fast instead of hanging
	// until the test is SIGKILLed.
	coreInstallTimeout = "5m"
	// providerInstallTimeout covers provider package download + CRD
	// establishment, which the providers chart's gate Job blocks --wait on.
	// Kept under the go-test deadline so a stuck install surfaces the gate
	// Job's diagnostics instead of hanging silently.
	providerInstallTimeout = "5m"
	// configInstallTimeout bounds the helm --wait for crossplane-config, which
	// applies ProviderConfigs against already-Healthy providers and so settles
	// faster than the provider install.
	configInstallTimeout = "3m"

	// operatorInstallTimeout bounds the helm --wait for the once-per-cluster
	// operator chart. The chart installs the operator Deployment, RBAC, CRDs, and
	// the XRD/Composition; none of those depend on a provisioned Gateway, so they
	// settle quickly. Kept under the go-test deadline so a stuck install fails fast.
	operatorInstallTimeout = "3m"
	// operatorReadyTimeout bounds the explicit wait for the operator Deployment to
	// report Available after the single install, before any Stack creates a Gateway.
	operatorReadyTimeout = 2 * time.Minute
	// crdEstablishedTimeout and xrdPresentTimeout bound the post-install waits for
	// the Gateway CRD's Established condition and the XGatewayGCP XRD's presence.
	// helm --wait does not gate on either, so the suite waits explicitly before a
	// Stack applies a Gateway of that kind.
	crdEstablishedTimeout = 2 * time.Minute
	xrdPresentTimeout     = 2 * time.Minute

	// gatewayReadyTimeout bounds the wait for the Gateway CR to report an address
	// and Ready=True. The operator must reconcile the Gateway into the XGatewayGCP,
	// every composed GCP resource (network, subnet, firewall, SA, secret,
	// instance) must reconcile, and the operator must mirror the IP back up.
	gatewayReadyTimeout = 6 * time.Minute
	// orphanDrainTimeout bounds the in-namespace GCP drain that must complete
	// before the namespace is deleted: teardown waits here for every composed
	// resource (instance, then subnet, then network, then secrets/SA, each gated
	// by the 15s composite poll) to finalize and release its GCP resource. The
	// namespace stays alive for the duration so the provider can write the
	// per-namespace ProviderConfigUsage each release needs.
	orphanDrainTimeout = 4 * time.Minute
)

// Suite holds state created once per `go test` invocation: the kind cluster,
// the helm driver, the API client, the built operator and link images, and the
// GCP env. Tests call Start to get a per-test Stack.
type Suite struct {
	env           Env
	cluster       *hk8s.KindCluster
	helm          *hk8s.Helm
	client        *hk8s.Client
	operatorImage hk8s.ImageRef
	linkImage     hk8s.ImageRef
	repoDir       string
	kubeCtx       string
	log           *zap.Logger
}

// Client returns the suite's Kubernetes client, so validation-failure tests can
// apply and inspect Gateways directly without going through Start (which would
// provision a GCP VM). The returned client targets the same cluster Start uses.
func (s *Suite) Client() *hk8s.Client { return s.client }

// Env returns the suite's GCP configuration, so tests building a Gateway CR
// outside Start can populate spec.gcp with the same region and zone.
func (s *Suite) Env() Env { return s.env }

// Setup provisions the kind cluster (or targets an existing one), builds and
// loads the operator and link images, installs Crossplane core + the
// GCP/Kubernetes providers + crossplane-config (credentials.source=Secret),
// loads the GCP service-account key as the creds Secret, and installs the operator
// chart exactly once. The operator is always cluster-scoped, so the single
// operator reconciles Gateways across every per-test namespace. Cluster teardown
// is not registered here: with
// multiple parallel Stacks sharing one cluster, deleting it must wait until every
// Stack's GCP drain completes. The caller drives that once-after-everything via
// Teardown from TestMain.
//
// Setup returns a non-nil *Suite from the moment the kind cluster handle exists,
// even alongside an error from a later step (image build, Crossplane install,
// operator install). The cluster is created early but the failure-prone steps
// come after; returning the partially-built suite on those error paths lets the
// caller's TestMain still delete the cluster via Teardown instead of leaking it.
// Only the pre-cluster failures (logger init, env validation) return a nil suite,
// and those happen before anything is created.
func Setup(ctx context.Context, t testing.TB) (*Suite, error) {
	log, err := zap.NewDevelopment()
	if err != nil {
		return nil, fmt.Errorf("zap: %w", err)
	}
	env := RequireEnv(t)
	repoDir := shared.RepoRoot()

	if err := os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true"); err != nil {
		return nil, fmt.Errorf("setenv TESTCONTAINERS_RYUK_DISABLED: %w", err)
	}

	cluster := hk8s.NewKindCluster(log)
	kubeCtx := cluster.KubeContext()

	// Capture the cluster handle into the suite before any failure-prone step.
	// Every error path past this point returns this same suite so TestMain's
	// Teardown can delete the cluster; Teardown deletes only what was created.
	suite := &Suite{
		env:     env,
		cluster: cluster,
		repoDir: repoDir,
		kubeCtx: contextOrCurrent(kubeCtx),
		log:     log,
	}

	if !useExisting() {
		if err := cluster.Ensure(ctx); err != nil {
			return suite, fmt.Errorf("kind ensure: %w", err)
		}
		// kind nodes share the host kernel; the link's kernel-mode WireGuard
		// interface needs the wireguard module loaded on the node.
		node := cluster.Name() + "-control-plane"
		log.Info("loading wireguard kernel module on kind node", zap.String("node", node))
		if out, err := shared.RunCmd(ctx, nil, "docker", "exec", node, "modprobe", "wireguard"); err != nil {
			return suite, fmt.Errorf("load wireguard module on kind node: %w\n%s", err, out)
		}
	}

	kubeconfig, err := resolveKubeconfig(cluster)
	if err != nil {
		return suite, err
	}
	contextOverride := ""
	if !useExisting() {
		contextOverride = kubeCtx
	}

	client, err := hk8s.NewClientFromKubeconfig(kubeconfig, contextOverride, log)
	if err != nil {
		return suite, fmt.Errorf("k8s client: %w", err)
	}
	suite.client = client

	// Both images share a run-unique tag so a rerun never reuses a stale layer
	// cached under the same ref. The operator and link are distinct Dockerfile
	// targets and distinct repositories; the chart points operator.image at the
	// former and link.image at the latter.
	imageTag := "e2e-" + shared.ShortID()
	operatorImage, err := hk8s.BuildImage(ctx, repoDir, "gateway-operator", imageTag, "operator", log)
	if err != nil {
		return suite, fmt.Errorf("build operator image: %w", err)
	}
	suite.operatorImage = operatorImage
	linkImage, err := hk8s.BuildImage(ctx, repoDir, "gateway-link", imageTag, "link", log)
	if err != nil {
		return suite, fmt.Errorf("build link image: %w", err)
	}
	suite.linkImage = linkImage
	if !useExisting() {
		if err := cluster.LoadImage(ctx, operatorImage.Ref()); err != nil {
			return suite, fmt.Errorf("kind load operator image: %w", err)
		}
		if err := cluster.LoadImage(ctx, linkImage.Ref()); err != nil {
			return suite, fmt.Errorf("kind load link image: %w", err)
		}
	}

	helm := hk8s.NewHelm(contextOrCurrent(kubeCtx), repoDir, log)
	suite.helm = helm

	if err := installCrossplaneStack(ctx, helm, env); err != nil {
		return suite, err
	}

	creds, err := env.readCredsJSON()
	if err != nil {
		return suite, err
	}
	if err := client.ApplyCredsSecret(ctx, env.CredsNamespace, env.CredsSecret, "credentials.json", creds); err != nil {
		return suite, fmt.Errorf("apply creds secret: %w", err)
	}

	if err := suite.installOperator(ctx); err != nil {
		return suite, fmt.Errorf("operator install: %w", err)
	}

	return suite, nil
}

// installOperator installs the operator chart exactly once per cluster into
// operatorNamespace. The single release brings the Gateway CRD, the XGatewayGCP
// and XGatewayNetwork XRDs and Compositions, the cluster-singleton
// ClusterRole/ClusterRoleBinding, and the operator Deployment. The operator is always cluster-scoped, so its cache is
// unrestricted and it reconciles Gateways in every per-test namespace. After
// --wait it asserts the
// Deployment is Available, the Gateway CRD is Established, and the XRD is present,
// the readiness signals helm --wait does not cover, before any Stack creates a
// Gateway.
func (s *Suite) installOperator(ctx context.Context) error {
	valuesPath, err := writeValues(os.TempDir(), valuesParams{
		nameOverride:  operatorNameOverride,
		operatorImage: s.operatorImage,
		linkImage:     s.linkImage,
	})
	if err != nil {
		return err
	}
	if err := s.helm.Install(ctx, hk8s.ReleaseSpec{
		Name:            operatorRelease,
		Namespace:       operatorNamespace,
		CreateNamespace: true,
		ChartPath:       "k8s/charts/wireguard-gateway-operator",
		ValuesFiles:     []string{valuesPath},
		Wait:            true,
		Timeout:         operatorInstallTimeout,
	}); err != nil {
		return err
	}
	if err := s.client.WaitDeploymentAvailable(ctx, operatorNamespace, operatorNameOverride, operatorReadyTimeout); err != nil {
		return fmt.Errorf("operator deployment not available: %w", err)
	}
	if err := s.client.WaitCRDEstablished(ctx, gatewayCRDName, crdEstablishedTimeout); err != nil {
		return fmt.Errorf("gateway crd not established: %w", err)
	}
	if err := s.client.WaitXRDPresent(ctx, xgatewayXRDName, xrdPresentTimeout); err != nil {
		return fmt.Errorf("xgatewaygcp xrd not present: %w", err)
	}
	return nil
}

// Teardown deletes the kind cluster the suite provisioned. It is the
// once-after-everything counterpart to Setup: the caller invokes it from
// TestMain after m.Run returns, which blocks until every parallel test and its
// per-Stack GCP drain (registered in Start's t.Cleanup) has completed, so the
// cluster is never deleted out from under a Stack still draining GCP. code is
// the binary's exit code, used as the run's pass/fail signal for the
// preserve-on-failure gate. Teardown is a no-op when targeting an existing
// cluster. It logs but does not fail on a delete error: the process is already
// exiting with code.
//
// Teardown is safe on a partially-initialized suite returned by a failed Setup:
// it deletes only the kind cluster, and that handle is captured before any
// failure-prone step, so a nil handle means nothing was created.
func (s *Suite) Teardown(ctx context.Context, code int) {
	if useExisting() || s.cluster == nil {
		return
	}
	kubeconfig := filepath.Join(os.TempDir(), "gateway-e2e-kubeconfig")
	// GATEWAY_E2E_KEEP leaves the kind cluster up regardless of pass or fail;
	// the per-test teardown leaves the GCP VM up to match.
	if s.env.Keep {
		s.log.Warn("GATEWAY_E2E_KEEP set; leaving kind cluster running for debugging",
			zap.String("cluster", s.cluster.Name()),
			zap.String("kubeconfig", kubeconfig),
			zap.String("namespaces_hint", "per-test link/echo pods live in the gw<id> namespaces; list with: kubectl get ns"),
			zap.String("cleanup", "kind delete cluster --name "+s.cluster.Name()),
		)
		return
	}
	// Mirror the per-test GCP-resource PRESERVE idiom: on a failed run with
	// GATEWAY_E2E_PRESERVE set, leave the kind cluster running so the in-cluster
	// link/echo pods survive for live debugging.
	if code != 0 && os.Getenv("GATEWAY_E2E_PRESERVE") != "" {
		s.log.Warn("run failed; leaving kind cluster running for debugging",
			zap.String("cluster", s.cluster.Name()),
			zap.String("kubeconfig", kubeconfig),
			zap.String("namespaces_hint", "per-test link/echo pods live in the gw<id> namespaces; list with: kubectl get ns"),
			zap.String("cleanup", "kind delete cluster --name "+s.cluster.Name()),
		)
		return
	}
	if err := s.cluster.Delete(ctx); err != nil {
		s.log.Error("kind delete", zap.Error(err))
	}
}

// installCrossplaneStack installs the Crossplane core, the providers chart, and
// crossplane-config wired to credentials.source=Secret. Each release blocks on
// --wait (the providers chart's gate Job gates on provider/CRD readiness).
func installCrossplaneStack(ctx context.Context, helm *hk8s.Helm, env Env) error {
	if err := helm.Install(ctx, hk8s.ReleaseSpec{
		Name:            crossplaneRelease,
		Namespace:       crossplaneNamespace,
		CreateNamespace: true,
		RemoteChart:     crossplaneChartName,
		Repo:            crossplaneChartRepo,
		Version:         crossplaneChartVersion,
		Wait:            true,
		Timeout:         coreInstallTimeout,
		// Realtime compositions trips a per-composite watch circuit-breaker on
		// create-time status churn that throttles reconciles past the gateway
		// readiness deadline; poll-driven reconciles are deterministic.
		SetStringValues: []string{
			"args[0]=--enable-realtime-compositions=false",
			"args[1]=--poll-interval=15s",
		},
	}); err != nil {
		return err
	}
	if err := helm.Install(ctx, hk8s.ReleaseSpec{
		Name:      providersRelease,
		Namespace: crossplaneNamespace,
		ChartPath: filepath.Join("k8s", "infra", "crossplane", "crossplane-providers"),
		Wait:      true,
		Timeout:   providerInstallTimeout,
	}); err != nil {
		return err
	}
	return helm.Install(ctx, hk8s.ReleaseSpec{
		Name:      configRelease,
		Namespace: crossplaneNamespace,
		ChartPath: filepath.Join("k8s", "infra", "crossplane", "crossplane-config"),
		SetValues: []string{
			"projectID=" + env.ProjectID,
			"credentials.source=Secret",
			"credentials.secretRef.namespace=" + env.CredsNamespace,
			"credentials.secretRef.name=" + env.CredsSecret,
			"credentials.secretRef.key=credentials.json",
		},
		Wait:    true,
		Timeout: configInstallTimeout,
	})
}

// resolveKubeconfig returns the kubeconfig path the client and helm should use.
// For a kind cluster it exports a dedicated kubeconfig to a temp file and points
// KUBECONFIG at it so helm's --kube-context resolves; for an existing cluster
// it returns the operator's KUBECONFIG (or the default path).
func resolveKubeconfig(cluster *hk8s.KindCluster) (string, error) {
	if useExisting() {
		if v := os.Getenv("KUBECONFIG"); v != "" {
			return v, nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home for kubeconfig: %w", err)
		}
		return filepath.Join(home, ".kube", "config"), nil
	}

	path := filepath.Join(os.TempDir(), "gateway-e2e-kubeconfig")
	if err := cluster.ExportKubeConfig(path); err != nil {
		return "", fmt.Errorf("export kubeconfig: %w", err)
	}
	if err := os.Setenv("KUBECONFIG", path); err != nil {
		return "", fmt.Errorf("setenv KUBECONFIG: %w", err)
	}
	return path, nil
}

// contextOrCurrent returns the kind kube context, or "" when targeting an
// existing cluster (helm then uses the current context).
func contextOrCurrent(kubeCtx string) string {
	if useExisting() {
		return ""
	}
	return kubeCtx
}
