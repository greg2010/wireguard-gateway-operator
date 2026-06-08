// Package k8s holds the gateway e2e harness drivers for the kind cluster, the
// Kubernetes API client (typed + dynamic), and the helm releases that deploy
// Crossplane and the gateway chart.
package k8s

import (
	"context"
	"fmt"
	"slices"

	"go.uber.org/zap"
	"sigs.k8s.io/kind/pkg/apis/config/v1alpha4"
	"sigs.k8s.io/kind/pkg/cluster"
	kindcmd "sigs.k8s.io/kind/pkg/cmd"

	"github.com/greg2010/wireguard-gateway-operator/test/harness/shared"
)

// e2eClusterName is the kind cluster the e2e suite provisions.
const e2eClusterName = "gateway-e2e"

// kubeletConfigPatch tunes the node kubelet for the e2e link pod. It is a kind
// kubeadmConfigPatch document that kind merges into the kubelet's
// KubeletConfiguration.
//
// allowedUnsafeSysctls allowlists net.ipv4.ip_forward, which the link pod sets via
// its pod-level securityContext; the kubelet rejects the unsafe sysctl unless it is
// allowlisted here.
//
// syncFrequency and configMapAndSecretChangeDetectionStrategy make mounted-ConfigMap
// updates prompt. The link reads its forward config from a mounted ConfigMap via
// fsnotify and applies nftables DNAT in place; the kubelet's default mounted-volume
// sync lag (~1m) otherwise delays a post-Ready forward edit reaching the link long
// enough to race the data-path probe deadline. Watch detection plus a 10s sync floor
// caps that lag at ~10s.
const kubeletConfigPatch = `apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
allowedUnsafeSysctls:
- "net.ipv4.ip_forward"
syncFrequency: 10s
configMapAndSecretChangeDetectionStrategy: Watch
`

// KindCluster manages the e2e kind cluster lifecycle via the kind Go API.
type KindCluster struct {
	name     string
	provider *cluster.Provider
	log      *zap.Logger
}

// NewKindCluster returns a KindCluster handle. Call Ensure to create the
// cluster.
func NewKindCluster(log *zap.Logger) *KindCluster {
	return &KindCluster{
		name: e2eClusterName,
		provider: cluster.NewProvider(
			cluster.ProviderWithLogger(kindcmd.NewLogger()),
			cluster.ProviderWithDocker(),
		),
		log: log,
	}
}

// Name returns the cluster name.
func (k *KindCluster) Name() string { return k.name }

// KubeContext returns the kubectl context name for this cluster.
func (k *KindCluster) KubeContext() string { return "kind-" + k.name }

// Ensure creates the cluster if it does not already exist. Idempotent: a
// pre-existing cluster of the same name is reused.
func (k *KindCluster) Ensure(_ context.Context) error {
	existing, err := k.provider.List()
	if err != nil {
		return fmt.Errorf("kind list clusters: %w", err)
	}
	if slices.Contains(existing, k.name) {
		k.log.Info("kind cluster already exists", zap.String("cluster", k.name))
		return nil
	}
	k.log.Info("creating kind cluster", zap.String("cluster", k.name))
	config := &v1alpha4.Cluster{
		Nodes: []v1alpha4.Node{{
			Role:                 v1alpha4.ControlPlaneRole,
			KubeadmConfigPatches: []string{kubeletConfigPatch},
		}},
	}
	if err := k.provider.Create(k.name,
		cluster.CreateWithV1Alpha4Config(config),
		cluster.CreateWithWaitForReady(0),
	); err != nil {
		return fmt.Errorf("kind create cluster %s: %w", k.name, err)
	}
	return nil
}

// KubeConfigBytes returns the cluster's kubeconfig as raw YAML.
func (k *KindCluster) KubeConfigBytes() ([]byte, error) {
	raw, err := k.provider.KubeConfig(k.name, false)
	if err != nil {
		return nil, fmt.Errorf("kind kubeconfig %s: %w", k.name, err)
	}
	return []byte(raw), nil
}

// ExportKubeConfig writes the cluster's kubeconfig to path.
func (k *KindCluster) ExportKubeConfig(path string) error {
	if err := k.provider.ExportKubeConfig(k.name, path, false); err != nil {
		return fmt.Errorf("kind export kubeconfig: %w", err)
	}
	return nil
}

// Delete removes the cluster. Safe to call when the cluster does not exist.
func (k *KindCluster) Delete(_ context.Context) error {
	k.log.Info("deleting kind cluster", zap.String("cluster", k.name))
	if err := k.provider.Delete(k.name, ""); err != nil {
		return fmt.Errorf("kind delete cluster %s: %w", k.name, err)
	}
	return nil
}

// LoadImage side-loads a local docker image into the cluster's nodes via the
// kind CLI. The Go API does not expose image loading, so the CLI is the
// supported path; kind must be on PATH.
func (k *KindCluster) LoadImage(ctx context.Context, imageRef string) error {
	k.log.Info("loading image into kind cluster",
		zap.String("cluster", k.name),
		zap.String("image", imageRef),
	)
	out, err := shared.RunCmd(ctx, nil, "kind", "load", "docker-image",
		"--name", k.name, imageRef)
	if err != nil {
		return fmt.Errorf("kind load docker-image %s: %w\n%s", imageRef, err, out)
	}
	return nil
}
