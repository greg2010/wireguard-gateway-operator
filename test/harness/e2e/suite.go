package e2e

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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

	// operatorNamespace and operatorRelease name the single operator install. The
	// chart renders cluster-singletons (the Gateway CRD, the XRDs/Compositions, a
	// fixed-name ClusterRole), so it must be installed exactly once per cluster.
	operatorNamespace = "gateway-operator"
	operatorRelease   = "gateway-operator"
	// operatorNameOverride pins the chart name for a deterministic Deployment name.
	// With one install per cluster the release prefix is redundant.
	operatorNameOverride = "gateway-operator"

	// gatewayCRDName and xgatewayXRDName are the cluster-singletons the suite waits
	// on before any Stack creates a Gateway.
	gatewayCRDName  = "gateways.wgnet.dev"
	xgatewayXRDName = "xgatewaygcps.infra.wgnet.dev"

	crossplaneChartVersion = "2.3.1"
	crossplaneChartRepo    = "https://charts.crossplane.io/stable"
	crossplaneChartName    = "crossplane"

	// The install timeouts are kept under the go-test deadline so a stuck install
	// fails fast instead of hanging until the binary is SIGKILLed. providerInstall
	// covers package download plus CRD establishment, which the gate Job blocks on.
	coreInstallTimeout     = "5m"
	providerInstallTimeout = "5m"
	configInstallTimeout   = "3m"
	operatorInstallTimeout = "3m"
	// operatorReadyTimeout bounds the explicit wait for the operator Deployment to
	// report Available after install.
	operatorReadyTimeout = 2 * time.Minute
	// crdEstablishedTimeout and xrdPresentTimeout bound the post-install waits helm
	// --wait does not gate on.
	crdEstablishedTimeout = 2 * time.Minute
	xrdPresentTimeout     = 2 * time.Minute

	// gatewayReadyTimeout bounds the wait for the Gateway to report an address and
	// Ready=True: the operator reconciles it into the XGatewayGCP, every composed
	// GCP resource reconciles, and the operator mirrors the IP back up.
	gatewayReadyTimeout = 6 * time.Minute
	// orphanDrainTimeout bounds the in-namespace GCP drain before the namespace is
	// deleted: every composed resource (each gated by the 15s composite poll) must
	// finalize and release its GCP resource.
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

// Client returns the suite's Kubernetes client, so a test can apply and inspect
// Gateways directly without going through Start (which would provision a GCP VM).
func (s *Suite) Client() *hk8s.Client { return s.client }

// Env returns the suite's GCP configuration, for tests building a Gateway CR
// outside Start.
func (s *Suite) Env() Env { return s.env }

// Setup provisions the cluster, builds and loads the images, and installs the
// Crossplane stack, creds Secret, and operator chart. It returns a non-nil *Suite
// once the cluster handle exists so Teardown can run; only a pre-cluster failure is nil.
func Setup(ctx context.Context) (*Suite, error) {
	log, err := zap.NewDevelopment()
	if err != nil {
		return nil, fmt.Errorf("zap: %w", err)
	}
	env, err := RequireEnv()
	if err != nil {
		return nil, fmt.Errorf("e2e env: %w", err)
	}
	repoDir := shared.RepoRoot()

	if err := os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true"); err != nil {
		return nil, fmt.Errorf("setenv TESTCONTAINERS_RYUK_DISABLED: %w", err)
	}

	cluster := hk8s.NewKindCluster(log)
	kubeCtx := cluster.KubeContext()

	// Capture the cluster handle before any failure-prone step, so every error path
	// past here returns this suite and TestMain's Teardown can delete the cluster.
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

	// Both images share a run-unique tag so a rerun never reuses a stale layer under
	// the same ref. They are distinct Dockerfile targets and repositories.
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

// installOperator installs the operator chart once per cluster, then asserts the
// Deployment is Available, the Gateway CRD is Established, and the XRD is present,
// the readiness signals helm --wait does not cover.
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

// Teardown deletes the kind cluster the suite provisioned. Invoked from TestMain
// after m.Run so it never races a Stack still draining GCP; code gates the
// preserve-on-failure path. No-op on an existing cluster or a nil handle.
func (s *Suite) Teardown(ctx context.Context, code int) {
	if useExisting() || s.cluster == nil {
		return
	}
	kubeconfig := filepath.Join(os.TempDir(), "gateway-e2e-kubeconfig")
	// GATEWAY_E2E_KEEP leaves the kind cluster up regardless of result, matching the
	// per-test teardown that leaves the GCP VM up.
	if s.env.Keep {
		s.log.Warn("GATEWAY_E2E_KEEP set; leaving kind cluster running for debugging",
			zap.String("cluster", s.cluster.Name()),
			zap.String("kubeconfig", kubeconfig),
			zap.String("namespaces_hint", "per-test link/echo pods live in the gw<id> namespaces; list with: kubectl get ns"),
			zap.String("cleanup", "kind delete cluster --name "+s.cluster.Name()),
		)
		return
	}
	// On a failed run with GATEWAY_E2E_PRESERVE set, leave the kind cluster up so the
	// link/echo pods survive for debugging, mirroring the per-test PRESERVE idiom.
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

// installCrossplaneStack installs Crossplane core, the providers chart, and
// crossplane-config wired to credentials.source=Secret, each blocking on --wait.
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

// resolveKubeconfig returns the kubeconfig path for the client and helm. For a kind
// cluster it exports a temp kubeconfig and points KUBECONFIG at it so --kube-context
// resolves; for an existing cluster it returns the operator's KUBECONFIG or default.
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
