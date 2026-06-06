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

	// operatorInstallTimeout bounds the helm --wait for the operator chart. The
	// chart installs the operator Deployment, RBAC, CRDs, and the XRD/Composition;
	// none of those depend on a provisioned Gateway, so they settle quickly. Kept
	// under the go-test deadline so a stuck install fails fast.
	operatorInstallTimeout = "3m"
	// operatorReadyTimeout bounds the explicit wait for the operator Deployment to
	// report Available after install, before the Gateway CR is created.
	operatorReadyTimeout = 2 * time.Minute

	// gatewayReadyTimeout bounds the wait for the Gateway CR to report an address
	// and Ready=True. The operator must reconcile the Gateway into the XGateway,
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

// Setup provisions the kind cluster (or targets an existing one), builds and
// loads the operator and link images, installs Crossplane core + the
// GCP/Kubernetes providers + crossplane-config (credentials.source=Secret), and
// loads the GCP service-account key as the creds Secret. When t is non-nil,
// cluster teardown is registered via t.Cleanup.
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
	if !useExisting() {
		if err := cluster.Ensure(ctx); err != nil {
			return nil, fmt.Errorf("kind ensure: %w", err)
		}
		if t != nil {
			t.Cleanup(func() {
				// Mirror the per-test GCP-resource PRESERVE idiom: on a failed run
				// with CYNO_E2E_PRESERVE set, leave the kind cluster running so the
				// in-cluster link/echo pods survive for live debugging.
				if t.Failed() && os.Getenv("CYNO_E2E_PRESERVE") != "" {
					kubeconfig := filepath.Join(os.TempDir(), "cyno-e2e-kubeconfig")
					log.Warn("test failed; leaving kind cluster running for debugging",
						zap.String("cluster", cluster.Name()),
						zap.String("kubeconfig", kubeconfig),
						zap.String("namespaces_hint", "per-test link/echo pods live in the cyno<id> namespaces; list with: kubectl get ns"),
						zap.String("cleanup", "kind delete cluster --name "+cluster.Name()),
					)
					return
				}
				if err := cluster.Delete(context.Background()); err != nil {
					log.Error("kind delete", zap.Error(err))
				}
			})
		}
		// kind nodes share the host kernel; the link's kernel-mode WireGuard
		// interface needs the wireguard module loaded on the node.
		node := cluster.Name() + "-control-plane"
		log.Info("loading wireguard kernel module on kind node", zap.String("node", node))
		if out, err := shared.RunCmd(ctx, nil, "docker", "exec", node, "modprobe", "wireguard"); err != nil {
			return nil, fmt.Errorf("load wireguard module on kind node: %w\n%s", err, out)
		}
	}

	kubeconfig, err := resolveKubeconfig(cluster)
	if err != nil {
		return nil, err
	}
	contextOverride := ""
	if !useExisting() {
		contextOverride = kubeCtx
	}

	client, err := hk8s.NewClientFromKubeconfig(kubeconfig, contextOverride, log)
	if err != nil {
		return nil, fmt.Errorf("k8s client: %w", err)
	}

	// Both images share a run-unique tag so a rerun never reuses a stale layer
	// cached under the same ref. The operator and link are distinct Dockerfile
	// targets and distinct repositories; the chart points operator.image at the
	// former and link.image at the latter.
	imageTag := "e2e-" + shared.ShortID()
	operatorImage, err := hk8s.BuildImage(ctx, repoDir, "gateway-operator", imageTag, "operator", log)
	if err != nil {
		return nil, fmt.Errorf("build operator image: %w", err)
	}
	linkImage, err := hk8s.BuildImage(ctx, repoDir, "gateway-link", imageTag, "link", log)
	if err != nil {
		return nil, fmt.Errorf("build link image: %w", err)
	}
	if !useExisting() {
		if err := cluster.LoadImage(ctx, operatorImage.Ref()); err != nil {
			return nil, fmt.Errorf("kind load operator image: %w", err)
		}
		if err := cluster.LoadImage(ctx, linkImage.Ref()); err != nil {
			return nil, fmt.Errorf("kind load link image: %w", err)
		}
	}

	helm := hk8s.NewHelm(contextOrCurrent(kubeCtx), repoDir, log)

	if err := installCrossplaneStack(ctx, helm, env); err != nil {
		return nil, err
	}

	creds, err := env.readCredsJSON()
	if err != nil {
		return nil, err
	}
	if err := client.ApplyCredsSecret(ctx, env.CredsNamespace, env.CredsSecret, "credentials.json", creds); err != nil {
		return nil, fmt.Errorf("apply creds secret: %w", err)
	}

	return &Suite{
		env:           env,
		cluster:       cluster,
		helm:          helm,
		client:        client,
		operatorImage: operatorImage,
		linkImage:     linkImage,
		repoDir:       repoDir,
		kubeCtx:       contextOrCurrent(kubeCtx),
		log:           log,
	}, nil
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

	path := filepath.Join(os.TempDir(), "cyno-e2e-kubeconfig")
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
