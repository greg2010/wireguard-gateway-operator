package k8s

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/client-go/util/retry"
)

// controlPlaneNodeLabel marks a kind control-plane node, which carries a NoSchedule
// taint whenever the cluster has workers, so it is never a placement target.
const controlPlaneNodeLabel = "node-role.kubernetes.io/control-plane"

// gatewayGVR is the GroupVersionResource of the user-facing Gateway CR the
// operator reconciles. The suite creates one and polls its status.address.
var gatewayGVR = schema.GroupVersionResource{
	Group:    "wgnet.dev",
	Version:  "v1alpha1",
	Resource: "gateways",
}

// xgatewayGCPGVR is the Crossplane composite the operator creates per Gateway. The suite reads it
// only for the teardown drain check (gone before the namespace delete) and for diagnostics.
var xgatewayGCPGVR = schema.GroupVersionResource{
	Group:    "infra.wgnet.dev",
	Version:  "v1alpha1",
	Resource: "xgatewaygcps",
}

// crdGVR and compositeResourceDefinitionGVR are the apiextensions resources the
// suite polls for readiness after the operator install: the Gateway CRD must be
// Established before any Gateway applies, and the XGatewayGCP XRD must be present.
var (
	crdGVR = schema.GroupVersionResource{
		Group:    "apiextensions.k8s.io",
		Version:  "v1",
		Resource: "customresourcedefinitions",
	}
	compositeResourceDefinitionGVR = schema.GroupVersionResource{
		Group:    "apiextensions.crossplane.io",
		Version:  "v2",
		Resource: "compositeresourcedefinitions",
	}
)

// harnessQPS and harnessBurst replace client-go's 5 QPS / 10 burst defaults. One Client is shared
// by every parallel test polling once a second, so the default budget queues requests in the rate
// limiter until their context expires and an assertion fails with a client error instead of the
// product's state. A local kind apiserver is unmetered, so the ceiling only clears that poll rate.
const (
	harnessQPS   = 100
	harnessBurst = 200
)

// Client wraps the typed and dynamic Kubernetes clients the e2e harness needs.
type Client struct {
	typed   kubernetes.Interface
	dynamic dynamic.Interface
	// rest is retained so ExecInPod can open a SPDY remotecommand stream, which needs the
	// transport config directly rather than a typed client.
	rest *rest.Config
	log  *zap.Logger
}

// restConfigFromKubeconfig resolves a REST config from a kubeconfig file with the harness rate
// limits applied. A non-empty context overrides the current-context.
func restConfigFromKubeconfig(path, context string) (*rest.Config, error) {
	loader := &clientcmd.ClientConfigLoadingRules{ExplicitPath: path}
	overrides := &clientcmd.ConfigOverrides{}
	if context != "" {
		overrides.CurrentContext = context
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, overrides).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("build rest config from %s: %w", path, err)
	}
	cfg.QPS, cfg.Burst = harnessQPS, harnessBurst
	return cfg, nil
}

// NewClientFromKubeconfig builds a Client from a kubeconfig file. When context
// is non-empty it overrides the current-context, which lets the suite target a
// specific kind context even when KUBECONFIG carries several.
func NewClientFromKubeconfig(path, context string, log *zap.Logger) (*Client, error) {
	cfg, err := restConfigFromKubeconfig(path, context)
	if err != nil {
		return nil, err
	}

	typed, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("typed client: %w", err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("dynamic client: %w", err)
	}
	return &Client{typed: typed, dynamic: dyn, rest: cfg, log: log}, nil
}

// EnsureNamespace creates ns if it does not already exist.
func (c *Client) EnsureNamespace(ctx context.Context, ns string) error {
	_, err := c.typed.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: ns},
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create namespace %s: %w", ns, err)
	}
	return nil
}

// DeleteNamespace deletes ns without blocking on finalization. Not-found is
// treated as success so teardown is idempotent.
func (c *Client) DeleteNamespace(ctx context.Context, ns string) error {
	err := c.typed.CoreV1().Namespaces().Delete(ctx, ns, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete namespace %s: %w", ns, err)
	}
	return nil
}

// SetNamespaceLabel sets label=value on ns so the operator's Namespace watch
// re-classifies any cross-namespace forward into ns. The read-modify-write retries
// on conflict so a concurrent status write does not fail the update.
func (c *Client) SetNamespaceLabel(ctx context.Context, ns, label, value string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		obj, err := c.typed.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get namespace %s: %w", ns, err)
		}
		if obj.Labels == nil {
			obj.Labels = map[string]string{}
		}
		obj.Labels[label] = value
		if _, err := c.typed.CoreV1().Namespaces().Update(ctx, obj, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("set namespace %s label %s: %w", ns, label, err)
		}
		return nil
	})
}

// RemoveNamespaceLabel deletes label from ns so the operator's Namespace watch
// re-denies any cross-namespace forward into ns. The read-modify-write retries on
// conflict so a concurrent status write does not fail the update.
func (c *Client) RemoveNamespaceLabel(ctx context.Context, ns, label string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		obj, err := c.typed.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get namespace %s: %w", ns, err)
		}
		delete(obj.Labels, label)
		if _, err := c.typed.CoreV1().Namespaces().Update(ctx, obj, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("remove namespace %s label %s: %w", ns, label, err)
		}
		return nil
	})
}

// DeleteService deletes the named Service in ns, so the operator's Service watch
// fires and re-classifies the forward that targeted it as ServiceNotFound.
// Not-found is treated as success so a scenario's cleanup is idempotent.
func (c *Client) DeleteService(ctx context.Context, ns, name string) error {
	err := c.typed.CoreV1().Services(ns).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete service %s/%s: %w", ns, name, err)
	}
	return nil
}

// DeleteDeployment deletes the named Deployment in ns. Not-found is treated as
// success so a scenario's cleanup is idempotent.
func (c *Client) DeleteDeployment(ctx context.Context, ns, name string) error {
	err := c.typed.AppsV1().Deployments(ns).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete deployment %s/%s: %w", ns, name, err)
	}
	return nil
}

// RestartDeployment forces a rollout by stamping the pod-template restartedAt
// annotation, like `kubectl rollout restart`. The read-modify-write retries on
// conflict so a concurrent status write does not lose the annotation update.
func (c *Client) RestartDeployment(ctx context.Context, ns, name string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		dep, err := c.typed.AppsV1().Deployments(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get deployment %s/%s: %w", ns, name, err)
		}
		if dep.Spec.Template.Annotations == nil {
			dep.Spec.Template.Annotations = map[string]string{}
		}
		dep.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339Nano)
		if _, err := c.typed.AppsV1().Deployments(ns).Update(ctx, dep, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("restart deployment %s/%s: %w", ns, name, err)
		}
		return nil
	})
}

// DeletePodsByLabel deletes every pod in ns matching the label selector and returns
// the number deleted, so a caller can assert the selector matched. A not-found on an
// individual delete is tolerated and not counted.
func (c *Client) DeletePodsByLabel(ctx context.Context, ns, selector string) (int, error) {
	pods, err := c.typed.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return 0, fmt.Errorf("list pods (ns=%s selector=%s): %w", ns, selector, err)
	}
	deleted := 0
	for i := range pods.Items {
		pod := &pods.Items[i]
		err := c.typed.CoreV1().Pods(ns).Delete(ctx, pod.Name, metav1.DeleteOptions{})
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return deleted, fmt.Errorf("delete pod %s/%s: %w", ns, pod.Name, err)
		}
		deleted++
	}
	return deleted, nil
}

// DeletePod deletes the single named pod in ns, targeting one pod by name (unlike
// DeletePodsByLabel) so the failover test can delete only the lease holder and
// leave the standby running. Not-found is treated as success.
func (c *Client) DeletePod(ctx context.Context, ns, name string) error {
	err := c.typed.CoreV1().Pods(ns).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete pod %s/%s: %w", ns, name, err)
	}
	return nil
}

// PodNode returns the node a pod is scheduled on, empty when it is still Pending.
func (c *Client) PodNode(ctx context.Context, ns, name string) (string, error) {
	pod, err := c.typed.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("get pod %s/%s: %w", ns, name, err)
	}
	return pod.Spec.NodeName, nil
}

// PodNamesByLabel returns the names of every pod in ns matching the label
// selector.
func (c *Client) PodNamesByLabel(ctx context.Context, ns, selector string) ([]string, error) {
	pods, err := c.typed.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, fmt.Errorf("list pods (ns=%s selector=%s): %w", ns, selector, err)
	}
	names := make([]string, 0, len(pods.Items))
	for i := range pods.Items {
		names = append(names, pods.Items[i].Name)
	}
	return names, nil
}

// ExecInPod runs command (argv, no shell) in the pod's default container over a
// SPDY remotecommand stream and returns the captured streams. A non-zero exit
// surfaces as a non-nil error, so a caller keys on err rather than a parsed code.
func (c *Client) ExecInPod(ctx context.Context, namespace, podName string, command []string) (stdout, stderr string, err error) {
	req := c.typed.CoreV1().RESTClient().
		Post().
		Resource("pods").
		Namespace(namespace).
		Name(podName).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Command: command,
			Stdout:  true,
			Stderr:  true,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(c.rest, "POST", req.URL())
	if err != nil {
		return "", "", fmt.Errorf("build exec executor for %s/%s: %w", namespace, podName, err)
	}

	var outBuf, errBuf bytes.Buffer
	streamErr := exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &outBuf,
		Stderr: &errBuf,
	})
	stdout, stderr = outBuf.String(), errBuf.String()
	if streamErr != nil {
		return stdout, stderr, fmt.Errorf("exec %v in %s/%s: %w", command, namespace, podName, streamErr)
	}
	return stdout, stderr, nil
}

// EvictPod requests a voluntary eviction via the policy/v1 Eviction subresource,
// the same path a node drain uses, so the pod's PodDisruptionBudget is enforced.
// A PDB violation rejects the eviction with TooManyRequests (HTTP 429).
func (c *Client) EvictPod(ctx context.Context, namespace, podName string) error {
	err := c.typed.PolicyV1().Evictions(namespace).Evict(ctx, &policyv1.Eviction{
		ObjectMeta: metav1.ObjectMeta{Name: podName, Namespace: namespace},
	})
	if err != nil {
		return fmt.Errorf("evict pod %s/%s: %w", namespace, podName, err)
	}
	return nil
}

// GetPodDisruptionBudgetStatus reads the named PodDisruptionBudget's status, which
// the disruption controller recomputes from the matching pods. A caller asserts on
// its computed fields to confirm the selector matches and the budget protects.
func (c *Client) GetPodDisruptionBudgetStatus(ctx context.Context, namespace, name string) (policyv1.PodDisruptionBudgetStatus, error) {
	pdb, err := c.typed.PolicyV1().PodDisruptionBudgets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return policyv1.PodDisruptionBudgetStatus{}, fmt.Errorf("get pdb %s/%s: %w", namespace, name, err)
	}
	return pdb.Status, nil
}

// ApplyCredsSecret creates or updates the crossplane creds Secret holding the
// GCP service-account key under the given data key. crossplane-config
// (credentials.source=Secret) reads it to authenticate provider-gcp.
func (c *Client) ApplyCredsSecret(ctx context.Context, ns, name, dataKey string, creds []byte) error {
	if err := c.EnsureNamespace(ctx, ns); err != nil {
		return err
	}
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Data:       map[string][]byte{dataKey: creds},
	}
	_, err := c.typed.CoreV1().Secrets(ns).Create(ctx, sec, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		_, err = c.typed.CoreV1().Secrets(ns).Update(ctx, sec, metav1.UpdateOptions{})
	}
	if err != nil {
		return fmt.Errorf("apply creds secret %s/%s: %w", ns, name, err)
	}
	return nil
}

// GatewayForward is one forwarded port on a Gateway CR: a public port DNAT'd
// through the gateway VM to an in-cluster Service. It mirrors the Gateway API's
// spec.forwards[] entry the suite needs to set.
type GatewayForward struct {
	// Port is the public port opened on the gateway VM.
	Port int
	// Protocol is "TCP" or "UDP" (the Gateway API enum casing).
	Protocol string
	// Service is the bare in-cluster Service name the link DNATs the port to; the
	// operator builds the FQDN from it and Namespace.
	Service string
	// Namespace is the target Service's namespace. Empty defaults to the Gateway's and omits the
	// field; another namespace is permitted only when it carries the ingress consent label.
	Namespace string
	// TargetPort is the port on Service.
	TargetPort int
}

// Traffic-policy values of spec.trafficPolicy, mirroring the CRD's enum so a test can
// branch on the mode without a bare string.
const (
	TrafficPolicyCluster = "Cluster"
	TrafficPolicyLocal   = "Local"
)

// GatewaySpec is the subset of a Gateway CR's spec the suite sets when creating
// the resource the operator reconciles.
type GatewaySpec struct {
	// ProjectID / Region / Zone / MachineType populate spec.gcp. ProjectID is
	// required.
	ProjectID   string
	Region      string
	Zone        string
	MachineType string
	// Forwards populate spec.forwards.
	Forwards []GatewayForward
	// DNSHostnames populate spec.dnsHostnames (empty omits the field).
	DNSHostnames []string
	// WireguardListenPort sets spec.wireguard.listenPort. Zero omits the field so the CRD default
	// (51820) applies; a non-zero value gives coexisting gateways distinct WG ports.
	WireguardListenPort int
	// Replicas sets spec.link.replicas. Zero omits the field so the CRD default (1)
	// applies; a value >1 runs a hot standby behind leader election.
	Replicas int32
	// TrafficPolicy sets spec.trafficPolicy. Empty omits the field so the CRD default
	// (Cluster) applies; "Local" runs the host-network DaemonSet data path.
	TrafficPolicy string
}

// CreateGateway applies a Gateway CR (wgnet.dev/v1alpha1) in ns, which the operator
// reconciles into the XGatewayGCP composite and the link Deployment. Idempotent on
// the already-exists path so re-running Start in a reused namespace is safe.
func (c *Client) CreateGateway(ctx context.Context, ns, name string, spec GatewaySpec) error {
	forwards := make([]any, 0, len(spec.Forwards))
	for _, f := range spec.Forwards {
		forward := map[string]any{
			"port":     int64(f.Port),
			"protocol": f.Protocol,
			"service":  f.Service,
		}
		// An explicit zero targetPort would fail the CRD's minimum=1 validation, so
		// omit the optional fields when unset.
		if f.Namespace != "" {
			forward["namespace"] = f.Namespace
		}
		if f.TargetPort != 0 {
			forward["targetPort"] = int64(f.TargetPort)
		}
		forwards = append(forwards, forward)
	}
	gcp := map[string]any{
		"projectID": spec.ProjectID,
		"region":    spec.Region,
		"zone":      spec.Zone,
	}
	if spec.MachineType != "" {
		gcp["machineType"] = spec.MachineType
	}
	gatewaySpec := map[string]any{
		"gcp":      gcp,
		"forwards": forwards,
	}
	if spec.WireguardListenPort != 0 {
		gatewaySpec["wireguard"] = map[string]any{
			"listenPort": int64(spec.WireguardListenPort),
		}
	}
	if spec.Replicas > 0 {
		gatewaySpec["link"] = map[string]any{
			"replicas": int64(spec.Replicas),
		}
	}
	if spec.TrafficPolicy != "" {
		gatewaySpec["trafficPolicy"] = spec.TrafficPolicy
	}
	if len(spec.DNSHostnames) > 0 {
		hostnames := make([]any, 0, len(spec.DNSHostnames))
		for _, h := range spec.DNSHostnames {
			hostnames = append(hostnames, h)
		}
		gatewaySpec["dnsHostnames"] = hostnames
	}

	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "wgnet.dev/v1alpha1",
		"kind":       "Gateway",
		"metadata": map[string]any{
			"name":      name,
			"namespace": ns,
		},
		"spec": gatewaySpec,
	}}

	_, err := c.dynamic.Resource(gatewayGVR).Namespace(ns).Create(ctx, obj, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create gateway %s/%s: %w", ns, name, err)
	}
	return nil
}

// GatewayStatus is the slice of Gateway status the data-path test gates on.
type GatewayStatus struct {
	// Address is status.address, mirrored by the operator from the XGatewayGCP's
	// observed public IP. Empty until observed.
	Address string
	// ActiveNode is status.link.activeNode, the node running the pod that holds the
	// link Lease. Empty until a holder pod is observed.
	ActiveNode string
	// Ready is true when the Gateway carries a Ready=True condition, meaning the
	// operator finished reconciling the XGatewayGCP and the link.
	Ready bool
	// LinkID is status.link.id, the allocated per-Gateway link id every Local-mode
	// node-global name derives from. Zero in Cluster mode and before allocation.
	LinkID int
}

// GetGatewayStatus reads the named Gateway in ns and extracts the address and
// the Ready condition the operator mirrors up from the XGatewayGCP.
func (c *Client) GetGatewayStatus(ctx context.Context, ns, name string) (GatewayStatus, error) {
	obj, err := c.dynamic.Resource(gatewayGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return GatewayStatus{}, fmt.Errorf("get gateway %s/%s: %w", ns, name, err)
	}
	address, _, _ := unstructured.NestedString(obj.Object, "status", "address")
	activeNode, _, _ := unstructured.NestedString(obj.Object, "status", "link", "activeNode")
	linkID, _, _ := unstructured.NestedInt64(obj.Object, "status", "link", "id")
	return GatewayStatus{
		Address:    address,
		ActiveNode: activeNode,
		Ready:      readyCondition(obj),
		LinkID:     int(linkID),
	}, nil
}

// WaitGatewayReady polls the named Gateway until it reports a non-empty
// status.address and a Ready=True condition, or timeout elapses. It returns the
// observed status on success.
func (c *Client) WaitGatewayReady(ctx context.Context, ns, name string, timeout time.Duration) (GatewayStatus, error) {
	c.log.Info("waiting for gateway ready", zap.String("namespace", ns), zap.String("name", name))
	var status GatewayStatus
	err := c.poll(ctx, timeout, 5*time.Second, func(ctx context.Context) (bool, error) {
		st, err := c.GetGatewayStatus(ctx, ns, name)
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		status = st
		return st.Ready && st.Address != "", nil
	})
	if err != nil {
		return GatewayStatus{}, fmt.Errorf("wait gateway %s/%s ready: %w", ns, name, err)
	}
	return status, nil
}

// WaitGatewayCondition polls the named Gateway until it carries a status condition
// matching condType, status, and reason (an empty reason matches any), or timeout
// elapses. Unlike WaitGatewayReady it does not gate on the address.
func (c *Client) WaitGatewayCondition(ctx context.Context, ns, name, condType, status, reason string, timeout time.Duration) error {
	return c.waitGatewayCondition(ctx, ns, name, condType, status, reason, "", timeout)
}

// WaitGatewayConditionMessage is WaitGatewayCondition with a message requirement: the
// condition's message must contain messageSubstring, an empty substring matching any
// message.
func (c *Client) WaitGatewayConditionMessage(ctx context.Context, ns, name, condType, status, reason, messageSubstring string, timeout time.Duration) error {
	return c.waitGatewayCondition(ctx, ns, name, condType, status, reason, messageSubstring, timeout)
}

func (c *Client) waitGatewayCondition(ctx context.Context, ns, name, condType, status, reason, messageSubstring string, timeout time.Duration) error {
	c.log.Info("waiting for gateway condition",
		zap.String("namespace", ns), zap.String("name", name),
		zap.String("type", condType), zap.String("status", status), zap.String("reason", reason),
		zap.String("message_substring", messageSubstring))
	var last conditionSnapshot
	err := c.poll(ctx, timeout, 5*time.Second, func(ctx context.Context) (bool, error) {
		obj, err := c.dynamic.Resource(gatewayGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("get gateway %s/%s: %w", ns, name, err)
		}
		last = readCondition(obj, condType)
		return hasCondition(obj, condType, status, reason) && strings.Contains(last.message, messageSubstring), nil
	})
	if err != nil {
		return fmt.Errorf("wait gateway %s/%s condition %s (last status=%q reason=%q message=%q): %w",
			ns, name, condType, last.status, last.reason, last.message, err)
	}
	return nil
}

// conditionSnapshot is one status condition as last observed, so a wait that times out
// can name what the Gateway actually reported.
type conditionSnapshot struct {
	status  string
	reason  string
	message string
}

// readCondition returns the named condition; a Gateway not carrying condType reads back
// the zero snapshot.
func readCondition(obj *unstructured.Unstructured, condType string) conditionSnapshot {
	conds, _, err := unstructured.NestedSlice(obj.Object, "status", "conditions")
	if err != nil {
		return conditionSnapshot{}
	}
	for _, raw := range conds {
		cond, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if t, _, _ := unstructured.NestedString(cond, "type"); t != condType {
			continue
		}
		var got conditionSnapshot
		got.status, _, _ = unstructured.NestedString(cond, "status")
		got.reason, _, _ = unstructured.NestedString(cond, "reason")
		got.message, _, _ = unstructured.NestedString(cond, "message")
		return got
	}
	return conditionSnapshot{}
}

// UpdateGateway applies a read-modify-write to the named Gateway's spec via mutate,
// retrying on conflict against a freshly fetched object. A non-nil error from mutate
// aborts the update; mutate must be safe to run more than once.
func (c *Client) UpdateGateway(ctx context.Context, ns, name string, mutate func(spec map[string]any) error) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		obj, err := c.dynamic.Resource(gatewayGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get gateway %s/%s: %w", ns, name, err)
		}
		spec, found, err := unstructured.NestedMap(obj.Object, "spec")
		if err != nil {
			return fmt.Errorf("read gateway %s/%s spec: %w", ns, name, err)
		}
		if !found {
			spec = map[string]any{}
		}
		if err := mutate(spec); err != nil {
			return fmt.Errorf("mutate gateway %s/%s spec: %w", ns, name, err)
		}
		if err := unstructured.SetNestedMap(obj.Object, spec, "spec"); err != nil {
			return fmt.Errorf("set gateway %s/%s spec: %w", ns, name, err)
		}
		if _, err := c.dynamic.Resource(gatewayGVR).Namespace(ns).Update(ctx, obj, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("update gateway %s/%s: %w", ns, name, err)
		}
		return nil
	})
}

// SetLinkReplicas sets spec.link.replicas on the named Gateway to n so the
// operator scales the link Deployment in place. n must be >=1 (the CRD's minimum).
func (c *Client) SetLinkReplicas(ctx context.Context, ns, name string, n int32) error {
	return c.UpdateGateway(ctx, ns, name, func(spec map[string]any) error {
		link, _ := spec["link"].(map[string]any)
		if link == nil {
			link = map[string]any{}
		}
		link["replicas"] = int64(n)
		spec["link"] = link
		return nil
	})
}

// GetLease returns the coordination.k8s.io Lease in ns. The link publishes its faults
// as annotations on it, which the failure dump reads alongside the holder.
func (c *Client) GetLease(ctx context.Context, ns, name string) (*coordinationv1.Lease, error) {
	lease, err := c.typed.CoordinationV1().Leases(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get lease %s/%s: %w", ns, name, err)
	}
	return lease, nil
}

// GetLeaseHolder returns the holder of the coordination.k8s.io Lease in ns: the link
// replica programming the data plane. An absent Lease or unset holder returns "" and
// a nil error, since before the first acquire and during failover there is no holder.
func (c *Client) GetLeaseHolder(ctx context.Context, ns, name string) (string, error) {
	lease, err := c.typed.CoordinationV1().Leases(ns).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get lease %s/%s: %w", ns, name, err)
	}
	if lease.Spec.HolderIdentity == nil {
		return "", nil
	}
	return *lease.Spec.HolderIdentity, nil
}

// WaitLeaseHolderChanges polls until the Lease holder is non-empty and differs from
// oldHolder, returning the new holder. It is the failover signal: leadership moving
// to a new pod. A still-empty holder keeps it polling.
func (c *Client) WaitLeaseHolderChanges(ctx context.Context, ns, name, oldHolder string, timeout time.Duration) (string, error) {
	c.log.Info("waiting for lease holder to change",
		zap.String("namespace", ns), zap.String("name", name), zap.String("oldHolder", oldHolder))
	var newHolder string
	err := c.poll(ctx, timeout, 2*time.Second, func(ctx context.Context) (bool, error) {
		holder, err := c.GetLeaseHolder(ctx, ns, name)
		if err != nil {
			return false, err
		}
		if holder != "" && holder != oldHolder {
			newHolder = holder
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return "", fmt.Errorf("wait lease %s/%s holder change from %q: %w", ns, name, oldHolder, err)
	}
	return newHolder, nil
}

// DeleteGateway deletes the named Gateway, triggering the operator's finalizer that
// drains the XGatewayGCP. Not-found is success so teardown is idempotent. It does
// not wait; pair it with WaitGatewayGone.
func (c *Client) DeleteGateway(ctx context.Context, ns, name string) error {
	err := c.dynamic.Resource(gatewayGVR).Namespace(ns).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete gateway %s/%s: %w", ns, name, err)
	}
	return nil
}

// WaitGatewayGone polls until the named Gateway is absent (the operator's
// finalizer cleared after the XGatewayGCP drain), or timeout elapses.
func (c *Client) WaitGatewayGone(ctx context.Context, ns, name string, timeout time.Duration) error {
	c.log.Info("waiting for gateway deletion", zap.String("namespace", ns), zap.String("name", name))
	return c.poll(ctx, timeout, 5*time.Second, func(ctx context.Context) (bool, error) {
		_, err := c.dynamic.Resource(gatewayGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		if err != nil {
			return false, fmt.Errorf("get gateway %s/%s: %w", ns, name, err)
		}
		return false, nil
	})
}

// DumpGateway returns the named Gateway as its Go %#v representation, for
// failure diagnostics.
func (c *Client) DumpGateway(ctx context.Context, ns, name string) (string, error) {
	obj, err := c.dynamic.Resource(gatewayGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("get gateway %s/%s: %w", ns, name, err)
	}
	return fmt.Sprintf("%#v", obj.Object), nil
}

// WaitXGatewayGCPGone polls until the named XGatewayGCP composite (named after the
// Gateway) is absent, or timeout elapses. Teardown uses it as the in-cluster signal
// that Crossplane drained the composite's GCP resources before the namespace delete.
func (c *Client) WaitXGatewayGCPGone(ctx context.Context, ns, name string, timeout time.Duration) error {
	c.log.Info("waiting for xgatewaygcp deletion", zap.String("namespace", ns), zap.String("name", name))
	return c.poll(ctx, timeout, 5*time.Second, func(ctx context.Context) (bool, error) {
		_, err := c.dynamic.Resource(xgatewayGCPGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		if err != nil {
			return false, fmt.Errorf("get xgatewaygcp %s/%s: %w", ns, name, err)
		}
		return false, nil
	})
}

// ownedChild is one in-cluster object the Gateway's delete path must reap, whether by
// owner-ref GC or by the finalizer, named for the failure message and probed via getErr.
type ownedChild struct {
	kind string
	name string
	// getErr fetches the object and returns the Get error; a NotFound means the
	// child has been reaped.
	getErr func(ctx context.Context, ns, name string) error
}

// OwnedChildren describes the set of children a Gateway is expected to have created,
// which varies with its traffic policy and replica count.
type OwnedChildren struct {
	// Namespace and Gateway name the Gateway whose children are checked.
	Namespace string
	Gateway   string
	// ExpectPDB gates the link PodDisruptionBudget, which exists only above one replica.
	ExpectPDB bool
	// Local selects the DaemonSet, no-NetworkPolicy shape.
	Local bool
	// ClusterRoleBindingName is the Local-mode cluster-scoped binding, reaped by the operator's
	// delete path rather than by garbage collection since it carries no ownerReference.
	ClusterRoleBindingName string
	// Timeout bounds the poll.
	Timeout time.Duration
}

// AssertOwnedChildrenGone polls until every object the Gateway owns is NotFound,
// failing if any remain. It must run after the Gateway CR is gone but before the
// namespace delete (which would mask an unreaped child).
func (c *Client) AssertOwnedChildrenGone(ctx context.Context, t *testing.T, want OwnedChildren) {
	t.Helper()

	ns, gateway := want.Namespace, want.Gateway
	local, expectPDB := want.Local, want.ExpectPDB
	crbName := want.ClusterRoleBindingName
	timeout := want.Timeout

	linkName := gateway + "-link"
	bundleName := gateway + "-bundle"

	workload := ownedChild{"Deployment", linkName, func(ctx context.Context, ns, name string) error {
		_, err := c.typed.AppsV1().Deployments(ns).Get(ctx, name, metav1.GetOptions{})
		return err
	}}
	if local {
		workload = ownedChild{"DaemonSet", linkName, func(ctx context.Context, ns, name string) error {
			_, err := c.typed.AppsV1().DaemonSets(ns).Get(ctx, name, metav1.GetOptions{})
			return err
		}}
	}

	children := []ownedChild{
		workload,
		{"ConfigMap", linkName, func(ctx context.Context, ns, name string) error {
			_, err := c.typed.CoreV1().ConfigMaps(ns).Get(ctx, name, metav1.GetOptions{})
			return err
		}},
		{"ServiceAccount", linkName, func(ctx context.Context, ns, name string) error {
			_, err := c.typed.CoreV1().ServiceAccounts(ns).Get(ctx, name, metav1.GetOptions{})
			return err
		}},
		{"Role", linkName, func(ctx context.Context, ns, name string) error {
			_, err := c.typed.RbacV1().Roles(ns).Get(ctx, name, metav1.GetOptions{})
			return err
		}},
		{"RoleBinding", linkName, func(ctx context.Context, ns, name string) error {
			_, err := c.typed.RbacV1().RoleBindings(ns).Get(ctx, name, metav1.GetOptions{})
			return err
		}},
		{"Secret", linkName, func(ctx context.Context, ns, name string) error {
			_, err := c.typed.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
			return err
		}},
		{"Secret", bundleName, func(ctx context.Context, ns, name string) error {
			_, err := c.typed.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
			return err
		}},
		// The link pods' leader election creates this Lease, so it carries no
		// ownerReference: the operator's delete path reaps it explicitly.
		{"Lease", linkName, func(ctx context.Context, ns, name string) error {
			_, err := c.typed.CoordinationV1().Leases(ns).Get(ctx, name, metav1.GetOptions{})
			return err
		}},
	}
	if !local {
		children = append(children, ownedChild{"NetworkPolicy", linkName, func(ctx context.Context, ns, name string) error {
			_, err := c.typed.NetworkingV1().NetworkPolicies(ns).Get(ctx, name, metav1.GetOptions{})
			return err
		}})
	}
	if local && crbName != "" {
		children = append(children, ownedChild{"ClusterRoleBinding", crbName, func(ctx context.Context, _, name string) error {
			_, err := c.typed.RbacV1().ClusterRoleBindings().Get(ctx, name, metav1.GetOptions{})
			return err
		}})
	}
	if expectPDB {
		children = append(children, ownedChild{"PodDisruptionBudget", linkName, func(ctx context.Context, ns, name string) error {
			_, err := c.typed.PolicyV1().PodDisruptionBudgets(ns).Get(ctx, name, metav1.GetOptions{})
			return err
		}})
	}

	c.log.Info("asserting the gateway delete path reaped its children",
		zap.String("namespace", ns), zap.String("gateway", gateway),
		zap.Bool("expectPDB", expectPDB), zap.Bool("local", local))

	var remaining []string
	err := c.poll(ctx, timeout, 5*time.Second, func(ctx context.Context) (bool, error) {
		remaining = remaining[:0]
		for _, child := range children {
			// A non-NotFound error is treated as still-present, not terminal, so a
			// transient API blip during in-flight GC does not abort the wait.
			if err := child.getErr(ctx, ns, child.name); !apierrors.IsNotFound(err) {
				remaining = append(remaining, fmt.Sprintf("%s/%s", child.kind, child.name))
			}
		}
		return len(remaining) == 0, nil
	})
	if err != nil {
		t.Errorf("wait for owner-ref GC of gateway %s/%s children: %v; still present: %v",
			ns, gateway, err, remaining)
	}
}

// GetXGatewayGCPServiceAccountEmail reads status.serviceAccountEmail from the
// named XGatewayGCP composite (named after the Gateway). An empty string with a
// nil error means the composite has not yet observed the SA; the caller retries.
func (c *Client) GetXGatewayGCPServiceAccountEmail(ctx context.Context, ns, name string) (string, error) {
	obj, err := c.dynamic.Resource(xgatewayGCPGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("get xgatewaygcp %s/%s: %w", ns, name, err)
	}
	email, _, err := unstructured.NestedString(obj.Object, "status", "serviceAccountEmail")
	if err != nil {
		return "", fmt.Errorf("read xgatewaygcp %s/%s status.serviceAccountEmail: %w", ns, name, err)
	}
	return email, nil
}

// readyCondition reports whether obj carries a status condition of type Ready
// with status True.
func readyCondition(obj *unstructured.Unstructured) bool {
	return hasCondition(obj, "Ready", "True", "")
}

// hasCondition reports whether obj carries a status condition matching condType, status and (when
// non-empty) reason, ignoring one whose observedGeneration is behind obj's generation.
func hasCondition(obj *unstructured.Unstructured, condType, status, reason string) bool {
	conds, found, err := unstructured.NestedSlice(obj.Object, "status", "conditions")
	if err != nil || !found {
		return false
	}
	generation, _, _ := unstructured.NestedInt64(obj.Object, "metadata", "generation")
	for _, raw := range conds {
		cond, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if cond["type"] != condType || cond["status"] != status {
			continue
		}
		if reason != "" && cond["reason"] != reason {
			continue
		}
		observed, found, err := unstructured.NestedInt64(cond, "observedGeneration")
		if err != nil {
			continue
		}
		if found && observed < generation {
			continue
		}
		return true
	}
	return false
}

// podReady reports whether pod carries a Ready condition of True.
func podReady(pod *corev1.Pod) bool {
	for _, cond := range pod.Status.Conditions {
		if cond.Type == corev1.PodReady {
			return cond.Status == corev1.ConditionTrue
		}
	}
	return false
}

// DumpXGatewayGCP returns the named XGatewayGCP as its Go %#v representation, for
// failure diagnostics.
func (c *Client) DumpXGatewayGCP(ctx context.Context, ns, name string) (string, error) {
	obj, err := c.dynamic.Resource(xgatewayGCPGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("get xgatewaygcp %s/%s: %w", ns, name, err)
	}
	return fmt.Sprintf("%#v", obj.Object), nil
}

// RecentEvents returns the namespace's events sorted by last-seen, newest
// last, capped to the most recent limit. Surfaces Crossplane composition and
// provider reconcile failures in a failed test's log.
func (c *Client) RecentEvents(ctx context.Context, ns string, limit int) (string, error) {
	events, err := c.typed.CoreV1().Events(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("list events %s: %w", ns, err)
	}
	items := events.Items
	slices.SortFunc(items, func(a, b corev1.Event) int {
		return eventTime(a).Compare(eventTime(b))
	})
	if len(items) > limit {
		items = items[len(items)-limit:]
	}
	var b strings.Builder
	for _, e := range items {
		fmt.Fprintf(&b, "%s %s/%s %s: %s\n",
			e.LastTimestamp.Format(time.RFC3339), e.InvolvedObject.Kind, e.InvolvedObject.Name, e.Reason, e.Message)
	}
	return b.String(), nil
}

// eventTime reports an event's effective last-seen time. Structured (Events API) events leave
// LastTimestamp zero and carry EventTime, so fall back to that, then to the creation time.
func eventTime(e corev1.Event) time.Time {
	if !e.LastTimestamp.IsZero() {
		return e.LastTimestamp.Time
	}
	if !e.EventTime.IsZero() {
		return e.EventTime.Time
	}
	return e.CreationTimestamp.Time
}

// WaitDeploymentAvailable polls until the named Deployment reports an Available
// condition of True, or the timeout elapses.
func (c *Client) WaitDeploymentAvailable(ctx context.Context, ns, name string, timeout time.Duration) error {
	c.log.Info("waiting for deployment available",
		zap.String("namespace", ns), zap.String("name", name))
	return c.poll(ctx, timeout, 2*time.Second, func(ctx context.Context) (bool, error) {
		dep, err := c.typed.AppsV1().Deployments(ns).Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("get deployment %s/%s: %w", ns, name, err)
		}
		for _, cond := range dep.Status.Conditions {
			if cond.Type == "Available" && cond.Status == corev1.ConditionTrue {
				return true, nil
			}
		}
		return false, nil
	})
}

// WorkerNodes returns the names of the cluster's schedulable worker nodes, sorted, so a
// test can pin a backend to a chosen one deterministically.
func (c *Client) WorkerNodes(ctx context.Context) ([]string, error) {
	nodes, err := c.typed.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	names := make([]string, 0, len(nodes.Items))
	for i := range nodes.Items {
		if _, isControlPlane := nodes.Items[i].Labels[controlPlaneNodeLabel]; isControlPlane {
			continue
		}
		names = append(names, nodes.Items[i].Name)
	}
	slices.Sort(names)
	return names, nil
}

// NodeAddressesAndPodCIDRs returns every node's addresses and every node's podCIDR, the
// excluded set a Local-mode /clientip assertion checks the observed address against.
func (c *Client) NodeAddressesAndPodCIDRs(ctx context.Context) (addresses []string, cidrs []string, err error) {
	nodes, err := c.typed.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("list nodes: %w", err)
	}
	for i := range nodes.Items {
		node := &nodes.Items[i]
		for _, addr := range node.Status.Addresses {
			if addr.Address != "" {
				addresses = append(addresses, addr.Address)
			}
		}
		if node.Spec.PodCIDR != "" {
			cidrs = append(cidrs, node.Spec.PodCIDR)
		}
		cidrs = append(cidrs, node.Spec.PodCIDRs...)
	}
	slices.Sort(addresses)
	slices.Sort(cidrs)
	return addresses, cidrs, nil
}

// linkPodSelector matches a gateway's link pods, mirroring the operator's unexported
// selector labels.
func linkPodSelector(gateway string) string {
	return fmt.Sprintf("app.kubernetes.io/name=wireguard-gateway-operator,app.kubernetes.io/instance=%s,app.kubernetes.io/component=link", gateway)
}

// LinkPodIPs returns the pod IPs of the gateway's link pods, the addresses a
// Cluster-mode masquerade rewrites a client's source to. A pod that has no IP yet is
// skipped, so an empty result means no link pod has been assigned one.
func (c *Client) LinkPodIPs(ctx context.Context, ns, gateway string) ([]string, error) {
	selector := linkPodSelector(gateway)
	pods, err := c.typed.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, fmt.Errorf("list link pods (ns=%s gateway=%s): %w", ns, gateway, err)
	}
	ips := make([]string, 0, len(pods.Items))
	for i := range pods.Items {
		if ip := pods.Items[i].Status.PodIP; ip != "" {
			ips = append(ips, ip)
		}
	}
	slices.Sort(ips)
	return ips, nil
}

// LinkClusterRoleBindingName returns the gateway's cluster-scoped ClusterRoleBinding, found by the
// operator's owner labels rather than recomputed, so the harness cannot drift from its hashing. It
// returns "" when there is none, the Cluster-mode case, and an error when more than one matches.
func (c *Client) LinkClusterRoleBindingName(ctx context.Context, ns, gateway string) (string, error) {
	selector := fmt.Sprintf("wgnet.dev/gateway-namespace=%s,wgnet.dev/gateway-name=%s", ns, gateway)
	list, err := c.typed.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return "", fmt.Errorf("list clusterrolebindings (ns=%s gateway=%s): %w", ns, gateway, err)
	}
	switch len(list.Items) {
	case 0:
		return "", nil
	case 1:
		return list.Items[0].Name, nil
	default:
		return "", fmt.Errorf("gateway %s/%s matched %d clusterrolebindings, want at most one", ns, gateway, len(list.Items))
	}
}

// WaitEndpointsReady polls the named Service's EndpointSlices until at least one
// address is Ready. The readinessProbe-less echo reports Available before it is a
// ready endpoint, so a retarget gates on this before the DNAT goes live.
func (c *Client) WaitEndpointsReady(ctx context.Context, namespace, serviceName string, timeout time.Duration) error {
	c.log.Info("waiting for service endpoints ready",
		zap.String("namespace", namespace), zap.String("service", serviceName))
	selector := fmt.Sprintf("%s=%s", discoveryv1.LabelServiceName, serviceName)
	return c.poll(ctx, timeout, 2*time.Second, func(ctx context.Context) (bool, error) {
		epSlices, err := c.typed.DiscoveryV1().EndpointSlices(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
		if err != nil {
			return false, fmt.Errorf("list endpointslices (ns=%s service=%s): %w", namespace, serviceName, err)
		}
		for i := range epSlices.Items {
			slice := &epSlices.Items[i]
			for j := range slice.Endpoints {
				ep := &slice.Endpoints[j]
				if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
					continue
				}
				if len(ep.Addresses) > 0 {
					return true, nil
				}
			}
		}
		return false, nil
	})
}

// ServiceRef names a Service by namespace, so one wait can cover backends spread over
// several namespaces.
type ServiceRef struct {
	Namespace, Name string
}

// WaitEndpointsReadyOnNode polls until every ref has a ready endpoint whose node is
// node, under one deadline rather than a per-service sum. It asserts placement as well
// as readiness, which is what a Local-mode handoff waits on.
func (c *Client) WaitEndpointsReadyOnNode(ctx context.Context, refs []ServiceRef, node string, timeout time.Duration) error {
	c.log.Info("waiting for service endpoints ready on node",
		zap.String("node", node), zap.Int("services", len(refs)))
	var pending ServiceRef
	err := c.poll(ctx, timeout, 2*time.Second, func(ctx context.Context) (bool, error) {
		for _, ref := range refs {
			ready, err := c.endpointReadyOnNode(ctx, ref, node)
			if err != nil {
				pending = ref
				return false, err
			}
			if !ready {
				pending = ref
				return false, nil
			}
		}
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("wait endpoints ready on node %s (last pending %s/%s): %w", node, pending.Namespace, pending.Name, err)
	}
	return nil
}

// endpointReadyOnNode reports whether ref has at least one ready endpoint address whose
// EndpointSlice entry names node.
func (c *Client) endpointReadyOnNode(ctx context.Context, ref ServiceRef, node string) (bool, error) {
	selector := fmt.Sprintf("%s=%s", discoveryv1.LabelServiceName, ref.Name)
	epSlices, err := c.typed.DiscoveryV1().EndpointSlices(ref.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return false, fmt.Errorf("list endpointslices (ns=%s service=%s): %w", ref.Namespace, ref.Name, err)
	}
	for i := range epSlices.Items {
		for j := range epSlices.Items[i].Endpoints {
			ep := &epSlices.Items[i].Endpoints[j]
			if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
				continue
			}
			if len(ep.Addresses) == 0 || ep.NodeName == nil || *ep.NodeName != node {
				continue
			}
			return true, nil
		}
	}
	return false, nil
}

// ScaleDeployment sets the named Deployment's replica count, the pod-scoped way to
// remove a backend's last ready endpoint without touching the node.
func (c *Client) ScaleDeployment(ctx context.Context, ns, name string, replicas int32) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		dep, err := c.typed.AppsV1().Deployments(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get deployment %s/%s: %w", ns, name, err)
		}
		dep.Spec.Replicas = &replicas
		if _, err := c.typed.AppsV1().Deployments(ns).Update(ctx, dep, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("scale deployment %s/%s to %d: %w", ns, name, replicas, err)
		}
		return nil
	})
}

// WaitLinkPodReadyOnNode polls until the gateway has a Ready link pod on node and
// returns its name, which is how a disruption assertion picks up the replacement.
func (c *Client) WaitLinkPodReadyOnNode(ctx context.Context, ns, gateway, node string, timeout time.Duration) (string, error) {
	c.log.Info("waiting for link pod ready on node",
		zap.String("namespace", ns), zap.String("gateway", gateway), zap.String("node", node))
	var name, lastSeen string
	err := c.poll(ctx, timeout, 2*time.Second, func(ctx context.Context) (bool, error) {
		pods, err := c.typed.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: linkPodSelector(gateway)})
		if err != nil {
			return false, fmt.Errorf("list link pods (ns=%s gateway=%s): %w", ns, gateway, err)
		}
		seen := make([]string, 0, len(pods.Items))
		for i := range pods.Items {
			pod := &pods.Items[i]
			seen = append(seen, describeLinkPod(pod))
			if pod.Spec.NodeName == node && pod.DeletionTimestamp == nil && podReady(pod) {
				name = pod.Name
				return true, nil
			}
		}
		lastSeen = strings.Join(seen, "; ")
		return false, nil
	})
	if err != nil {
		return "", fmt.Errorf("wait link pod of %s/%s ready on node %s (last seen: %s): %w", ns, gateway, node, lastSeen, err)
	}
	return name, nil
}

// describeLinkPod renders the fields a link-pod readiness wait is decided on, so a
// timeout says which candidate fell short and why.
func describeLinkPod(pod *corev1.Pod) string {
	ready := "Ready=<none>"
	for i := range pod.Status.Conditions {
		if pod.Status.Conditions[i].Type == corev1.PodReady {
			ready = fmt.Sprintf("Ready=%s", pod.Status.Conditions[i].Status)
			break
		}
	}
	return fmt.Sprintf("%s node=%s phase=%s deleting=%t %s",
		pod.Name, pod.Spec.NodeName, pod.Status.Phase, pod.DeletionTimestamp != nil, ready)
}

// NodeIfaceIndex reads /sys/class/net/<iface>/ifindex inside pod. The link pods run
// hostNetwork, so the value identifies the node's interface: an unchanged index across
// a restart means the interface was adopted rather than recreated.
func (c *Client) NodeIfaceIndex(ctx context.Context, ns, pod, iface string) (int, error) {
	path := "/sys/class/net/" + iface + "/ifindex"
	stdout, stderr, err := c.ExecInPod(ctx, ns, pod, []string{"cat", path})
	if err != nil {
		return 0, fmt.Errorf("read %s in %s/%s: %w (stderr: %s)", path, ns, pod, err, strings.TrimSpace(stderr))
	}
	index, err := strconv.Atoi(strings.TrimSpace(stdout))
	if err != nil {
		return 0, fmt.Errorf("parse %s in %s/%s from %q: %w", path, ns, pod, strings.TrimSpace(stdout), err)
	}
	return index, nil
}

// PodRestartCount returns the pod's summed container restart count, which rises when a
// container is replaced in place while the pod itself survives.
func (c *Client) PodRestartCount(ctx context.Context, ns, pod string) (int32, error) {
	p, err := c.typed.CoreV1().Pods(ns).Get(ctx, pod, metav1.GetOptions{})
	if err != nil {
		return 0, fmt.Errorf("get pod %s/%s: %w", ns, pod, err)
	}
	var restarts int32
	for i := range p.Status.ContainerStatuses {
		restarts += p.Status.ContainerStatuses[i].RestartCount
	}
	return restarts, nil
}

// RestartDaemonSet forces a rolling update by stamping the pod-template restartedAt
// annotation, the DaemonSet twin of RestartDeployment.
func (c *Client) RestartDaemonSet(ctx context.Context, ns, name string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		ds, err := c.typed.AppsV1().DaemonSets(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get daemonset %s/%s: %w", ns, name, err)
		}
		if ds.Spec.Template.Annotations == nil {
			ds.Spec.Template.Annotations = map[string]string{}
		}
		ds.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339Nano)
		if _, err := c.typed.AppsV1().DaemonSets(ns).Update(ctx, ds, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("restart daemonset %s/%s: %w", ns, name, err)
		}
		return nil
	})
}

// WaitDaemonSetReady polls until every desired DaemonSet pod is ready on the current
// generation, so a roll that is still replacing pods does not read as converged.
func (c *Client) WaitDaemonSetReady(ctx context.Context, ns, name string, timeout time.Duration) error {
	c.log.Info("waiting for daemonset ready", zap.String("namespace", ns), zap.String("name", name))
	lastSeen := "not observed"
	err := c.poll(ctx, timeout, 2*time.Second, func(ctx context.Context) (bool, error) {
		ds, err := c.typed.AppsV1().DaemonSets(ns).Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			lastSeen = "not found"
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("get daemonset %s/%s: %w", ns, name, err)
		}
		st := ds.Status
		lastSeen = fmt.Sprintf("generation=%d observedGeneration=%d desired=%d updated=%d ready=%d available=%d",
			ds.Generation, st.ObservedGeneration, st.DesiredNumberScheduled,
			st.UpdatedNumberScheduled, st.NumberReady, st.NumberAvailable)
		return st.ObservedGeneration >= ds.Generation &&
			st.UpdatedNumberScheduled == st.DesiredNumberScheduled &&
			st.NumberReady == st.DesiredNumberScheduled &&
			st.DesiredNumberScheduled > 0, nil
	})
	if err != nil {
		return fmt.Errorf("wait daemonset %s/%s ready (last seen: %s): %w", ns, name, lastSeen, err)
	}
	return nil
}

// WaitCRDEstablished polls the named CustomResourceDefinition until it reports an
// Established condition of True, or the timeout elapses. helm --wait does not gate
// on this, so the suite waits explicitly before applying a CR of that kind.
func (c *Client) WaitCRDEstablished(ctx context.Context, name string, timeout time.Duration) error {
	c.log.Info("waiting for crd established", zap.String("name", name))
	return c.poll(ctx, timeout, 2*time.Second, func(ctx context.Context) (bool, error) {
		crd, err := c.dynamic.Resource(crdGVR).Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("get crd %s: %w", name, err)
		}
		return hasCondition(crd, "Established", "True", ""), nil
	})
}

// WaitXRDPresent polls until the named Crossplane CompositeResourceDefinition
// exists, or the timeout elapses. Presence is sufficient: the XRD and its
// Composition ship in one release, so the XRD existing confirms the composite path.
func (c *Client) WaitXRDPresent(ctx context.Context, name string, timeout time.Duration) error {
	c.log.Info("waiting for xrd present", zap.String("name", name))
	return c.poll(ctx, timeout, 2*time.Second, func(ctx context.Context) (bool, error) {
		_, err := c.dynamic.Resource(compositeResourceDefinitionGVR).Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("get xrd %s: %w", name, err)
		}
		return true, nil
	})
}

// PodLogsByLabel returns the recent logs of the first pod in ns matching
// selector. tailLines bounds the output. Used by the failure-diagnostic dump.
func (c *Client) PodLogsByLabel(ctx context.Context, ns, selector string, tailLines int64) (string, error) {
	pods, err := c.typed.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return "", fmt.Errorf("list pods (ns=%s selector=%s): %w", ns, selector, err)
	}
	if len(pods.Items) == 0 {
		return "", fmt.Errorf("no pods match selector %q in %s", selector, ns)
	}
	pod := pods.Items[0]
	req := c.typed.CoreV1().Pods(ns).GetLogs(pod.Name, &corev1.PodLogOptions{TailLines: &tailLines})
	stream, err := req.Stream(ctx)
	if err != nil {
		return "", fmt.Errorf("stream logs %s/%s: %w", ns, pod.Name, err)
	}
	defer stream.Close()
	buf := make([]byte, 0, 64*1024)
	tmp := make([]byte, 32*1024)
	for {
		n, rerr := stream.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if rerr != nil {
			break
		}
	}
	return string(buf), nil
}

// PodsByLabel returns the pods in ns matching selector, sorted by name so a dump built
// from them is stable across runs.
func (c *Client) PodsByLabel(ctx context.Context, ns, selector string) ([]corev1.Pod, error) {
	pods, err := c.typed.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, fmt.Errorf("list pods (ns=%s selector=%s): %w", ns, selector, err)
	}
	items := pods.Items
	slices.SortFunc(items, func(a, b corev1.Pod) int { return strings.Compare(a.Name, b.Name) })
	return items, nil
}

// ContainerLogTail returns the last tailLines of one container's log. previous selects
// the log of the container's prior instance, which is the only record of why a
// restarting container died. Partial output is returned alongside a read error.
func (c *Client) ContainerLogTail(ctx context.Context, ns, pod, container string, previous bool, tailLines int64) (string, error) {
	stream, err := c.typed.CoreV1().Pods(ns).GetLogs(pod, &corev1.PodLogOptions{
		Container: container,
		Previous:  previous,
		TailLines: &tailLines,
	}).Stream(ctx)
	if err != nil {
		return "", fmt.Errorf("stream logs %s/%s container %s (previous=%t): %w", ns, pod, container, previous, err)
	}
	defer stream.Close()

	out, err := io.ReadAll(stream)
	if err != nil {
		return string(out), fmt.Errorf("read logs %s/%s container %s: %w", ns, pod, container, err)
	}
	return string(out), nil
}

// ServiceEndpointSummary returns a per-Service line for every Service in ns: name,
// ClusterIP, and the Ready endpoint addresses backing it. Addresses are deduplicated
// and sorted for a stable line across the slices one Service can own.
func (c *Client) ServiceEndpointSummary(ctx context.Context, ns string) (string, error) {
	services, err := c.typed.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("list services %s: %w", ns, err)
	}
	epSlices, err := c.typed.DiscoveryV1().EndpointSlices(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("list endpointslices %s: %w", ns, err)
	}

	readyByService := make(map[string]map[string]struct{})
	for i := range epSlices.Items {
		slice := &epSlices.Items[i]
		svc := slice.Labels[discoveryv1.LabelServiceName]
		if svc == "" {
			continue
		}
		addrs := readyByService[svc]
		if addrs == nil {
			addrs = make(map[string]struct{})
			readyByService[svc] = addrs
		}
		for j := range slice.Endpoints {
			ep := &slice.Endpoints[j]
			// A nil Ready is ready per the EndpointSlice contract; only an explicit
			// false excludes the address.
			if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
				continue
			}
			for _, a := range ep.Addresses {
				addrs[a] = struct{}{}
			}
		}
	}

	var b strings.Builder
	for i := range services.Items {
		svc := &services.Items[i]
		ready := readyByService[svc.Name]
		sorted := slices.Sorted(maps.Keys(ready))
		fmt.Fprintf(&b, "%s clusterIP=%s readyAddresses=%d %v\n",
			svc.Name, svc.Spec.ClusterIP, len(sorted), sorted)
	}
	return b.String(), nil
}

// PodStatusSummary returns one line per pod in ns matching selector: name, phase,
// Ready, and node. An empty selector summarizes every pod in the namespace.
func (c *Client) PodStatusSummary(ctx context.Context, ns, selector string) (string, error) {
	pods, err := c.typed.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return "", fmt.Errorf("list pods (ns=%s selector=%s): %w", ns, selector, err)
	}
	var b strings.Builder
	for i := range pods.Items {
		pod := &pods.Items[i]
		fmt.Fprintf(&b, "%s phase=%s ready=%t node=%s\n",
			pod.Name, pod.Status.Phase, podReady(pod), pod.Spec.NodeName)
	}
	return b.String(), nil
}

// ConfigMapData returns the value under key in the named ConfigMap in ns. A
// missing key is an error so the dump records the drift rather than an empty string.
func (c *Client) ConfigMapData(ctx context.Context, ns, name, key string) (string, error) {
	cm, err := c.typed.CoreV1().ConfigMaps(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("get configmap %s/%s: %w", ns, name, err)
	}
	val, ok := cm.Data[key]
	if !ok {
		return "", fmt.Errorf("configmap %s/%s has no key %q", ns, name, key)
	}
	return val, nil
}

// poll invokes fn every interval until it returns done=true or ctx/timeout
// expires. A non-nil error from fn is terminal.
func (c *Client) poll(ctx context.Context, timeout, interval time.Duration, fn func(context.Context) (bool, error)) error {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		done, err := fn(ctx)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s", timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
