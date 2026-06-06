package k8s

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// gatewayGVR is the GroupVersionResource of the user-facing Gateway CR the
// operator reconciles. The suite creates one and polls its status.address.
var gatewayGVR = schema.GroupVersionResource{
	Group:    "wgnet.dev",
	Version:  "v1alpha1",
	Resource: "gateways",
}

// xgatewayGVR is the GroupVersionResource of the Crossplane composite the
// operator creates per Gateway. The suite reads it only for the teardown drain
// check (it must be gone before the namespace is deleted) and for diagnostics.
var xgatewayGVR = schema.GroupVersionResource{
	Group:    "infra.wgnet.dev",
	Version:  "v1alpha1",
	Resource: "xgateways",
}

// Client wraps the typed and dynamic Kubernetes clients the e2e harness needs.
type Client struct {
	typed   kubernetes.Interface
	dynamic dynamic.Interface
	log     *zap.Logger
}

// NewClientFromKubeconfig builds a Client from a kubeconfig file. When context
// is non-empty it overrides the current-context, which lets the suite target a
// specific kind context even when KUBECONFIG carries several.
func NewClientFromKubeconfig(path, context string, log *zap.Logger) (*Client, error) {
	loader := &clientcmd.ClientConfigLoadingRules{ExplicitPath: path}
	overrides := &clientcmd.ConfigOverrides{}
	if context != "" {
		overrides.CurrentContext = context
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, overrides).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("build rest config from %s: %w", path, err)
	}

	typed, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("typed client: %w", err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("dynamic client: %w", err)
	}
	return &Client{typed: typed, dynamic: dyn, log: log}, nil
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
	// Service is the in-cluster Service DNS name the link DNATs the port to.
	Service string
	// TargetPort is the port on Service.
	TargetPort int
}

// GatewaySpec is the subset of a Gateway CR's spec the suite sets when creating
// the resource the operator reconciles.
type GatewaySpec struct {
	// Region / Zone / MachineType populate spec.gcp.
	Region      string
	Zone        string
	MachineType string
	// Forwards populate spec.forwards.
	Forwards []GatewayForward
	// DNSHostnames populate spec.dnsHostnames (empty omits the field).
	DNSHostnames []string
}

// CreateGateway applies a Gateway CR (wgnet.dev/v1alpha1) in ns with the given
// spec. The operator reconciles it into the XGateway composite and the link
// Deployment. Idempotent on the already-exists path so re-running Start in a
// reused namespace is safe.
func (c *Client) CreateGateway(ctx context.Context, ns, name string, spec GatewaySpec) error {
	forwards := make([]any, 0, len(spec.Forwards))
	for _, f := range spec.Forwards {
		forwards = append(forwards, map[string]any{
			"port":       int64(f.Port),
			"protocol":   f.Protocol,
			"service":    f.Service,
			"targetPort": int64(f.TargetPort),
		})
	}
	gcp := map[string]any{
		"region": spec.Region,
		"zone":   spec.Zone,
	}
	if spec.MachineType != "" {
		gcp["machineType"] = spec.MachineType
	}
	gatewaySpec := map[string]any{
		"gcp":      gcp,
		"forwards": forwards,
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
	// Address is status.address, mirrored by the operator from the XGateway's
	// observed public IP. Empty until observed.
	Address string
	// Ready is true when the Gateway carries a Ready=True condition, meaning the
	// operator finished reconciling the XGateway and the link.
	Ready bool
}

// GetGatewayStatus reads the named Gateway in ns and extracts the address and
// the Ready condition the operator mirrors up from the XGateway.
func (c *Client) GetGatewayStatus(ctx context.Context, ns, name string) (GatewayStatus, error) {
	obj, err := c.dynamic.Resource(gatewayGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return GatewayStatus{}, fmt.Errorf("get gateway %s/%s: %w", ns, name, err)
	}
	address, _, _ := unstructured.NestedString(obj.Object, "status", "address")
	return GatewayStatus{
		Address: address,
		Ready:   readyCondition(obj),
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

// DeleteGateway deletes the named Gateway, triggering the operator's finalizer
// (which drains the XGateway/GCP before the object is removed). Not-found is
// treated as success so teardown is idempotent. It does not wait; pair it with
// WaitGatewayGone.
func (c *Client) DeleteGateway(ctx context.Context, ns, name string) error {
	err := c.dynamic.Resource(gatewayGVR).Namespace(ns).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete gateway %s/%s: %w", ns, name, err)
	}
	return nil
}

// WaitGatewayGone polls until the named Gateway is absent (the operator's
// finalizer cleared after the XGateway/GCP drain), or timeout elapses.
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

// WaitXGatewayGone polls until the named XGateway composite is absent, or
// timeout elapses. The operator names the composite after the Gateway, so the
// composite shares the Gateway's name. Teardown uses it as the in-cluster signal
// that Crossplane drained the GCP resources the composite owned, before the
// namespace is deleted.
func (c *Client) WaitXGatewayGone(ctx context.Context, ns, name string, timeout time.Duration) error {
	c.log.Info("waiting for xgateway deletion", zap.String("namespace", ns), zap.String("name", name))
	return c.poll(ctx, timeout, 5*time.Second, func(ctx context.Context) (bool, error) {
		_, err := c.dynamic.Resource(xgatewayGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		if err != nil {
			return false, fmt.Errorf("get xgateway %s/%s: %w", ns, name, err)
		}
		return false, nil
	})
}

// readyCondition reports whether obj carries a status condition of type Ready
// with status True.
func readyCondition(obj *unstructured.Unstructured) bool {
	conds, found, err := unstructured.NestedSlice(obj.Object, "status", "conditions")
	if err != nil || !found {
		return false
	}
	for _, raw := range conds {
		cond, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if cond["type"] == "Ready" && cond["status"] == "True" {
			return true
		}
	}
	return false
}

// DumpXGateway returns the named XGateway as its Go %#v representation, for
// failure diagnostics.
func (c *Client) DumpXGateway(ctx context.Context, ns, name string) (string, error) {
	obj, err := c.dynamic.Resource(xgatewayGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("get xgateway %s/%s: %w", ns, name, err)
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
	sort.Slice(items, func(i, j int) bool {
		return eventTime(items[i]).Before(eventTime(items[j]))
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

// eventTime reports an event's effective last-seen time. Structured (Events API)
// events leave LastTimestamp zero and carry EventTime instead, so prefer
// LastTimestamp, then EventTime, then the creation time as a last resort.
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
