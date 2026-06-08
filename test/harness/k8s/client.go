package k8s

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
)

// gatewayGVR is the GroupVersionResource of the user-facing Gateway CR the
// operator reconciles. The suite creates one and polls its status.address.
var gatewayGVR = schema.GroupVersionResource{
	Group:    "wgnet.dev",
	Version:  "v1alpha1",
	Resource: "gateways",
}

// xgatewayGCPGVR is the GroupVersionResource of the Crossplane composite the
// operator creates per Gateway. The suite reads it only for the teardown drain
// check (it must be gone before the namespace is deleted) and for diagnostics.
var xgatewayGCPGVR = schema.GroupVersionResource{
	Group:    "infra.wgnet.dev",
	Version:  "v1alpha1",
	Resource: "xgatewaygcps",
}

// crdGVR and compositeResourceDefinitionGVR are the apiextensions resources the
// suite polls for readiness after the once-per-cluster operator install: the
// Gateway CRD must be Established before any Gateway applies, and the XGatewayGCP
// XRD must be present so the operator's composites bind.
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

// SetNamespaceLabel sets label=value on ns via a read-modify-write, so the
// operator's Namespace watch fires and re-classifies any cross-namespace forward
// into ns. Used by the consent-label lifecycle subtest.
//
// The read-modify-write runs inside retry.RetryOnConflict against a freshly
// fetched Namespace on each attempt, so a concurrent write that bumps the
// Namespace's resourceVersion (the namespace controller stamps status) does not
// fail the label update on an optimistic-concurrency conflict.
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

// RemoveNamespaceLabel deletes label from ns via a read-modify-write, so the
// operator's Namespace watch fires and re-denies any cross-namespace forward into
// ns. Used by the consent-label lifecycle subtest.
//
// The read-modify-write runs inside retry.RetryOnConflict against a freshly
// fetched Namespace on each attempt, so a concurrent write that bumps the
// Namespace's resourceVersion (the namespace controller stamps status) does not
// fail the label removal on an optimistic-concurrency conflict.
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

// RestartDeployment forces a rollout of the named Deployment by stamping the
// pod-template restartedAt annotation, mirroring `kubectl rollout restart`. The
// changed pod template makes the Deployment controller replace every pod, so a
// data-path probe after the rollout reaches a fresh pod. Used to prove a forward's
// DNAT to a backend's stable ClusterIP survives backend pod churn.
//
// The read-modify-write runs inside retry.RetryOnConflict against a freshly
// fetched Deployment on each attempt, so a concurrent status write does not lose
// the annotation update to an optimistic-concurrency conflict.
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

// DeletePodsByLabel deletes every pod in ns matching the label selector and
// returns the number successfully deleted. A not-found on an individual delete is
// tolerated (and not counted) so a pod the controller already reaped between the
// list and the delete does not fail the call. The count lets a caller assert the
// selector actually matched pods, so a selector or namespace drift fails loudly
// rather than silently deleting nothing. Used to evict a component's pods (e.g.
// the link) and prove its replacement re-establishes the data path.
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

// PodNamesByLabel returns the names of every pod in ns matching the label
// selector. Used to snapshot a component's pods before evicting them so a caller
// can wait for a replacement whose name is not in the pre-delete set.
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

// WaitForReplacementPod polls the label selector until a Ready pod whose name is
// not in oldNames is observed, or the timeout elapses. Pairs with PodNamesByLabel
// and DeletePodsByLabel to prove a component's pods were genuinely replaced (not
// merely that a delete was issued): the old pod can stay Ready while its delete is
// async, so gating on a new Ready name is the signal the replacement took over.
// Assumes the controller assigns the replacement a new name (e.g. a Deployment
// with the Recreate strategy, which tears the old pod down before creating one).
func (c *Client) WaitForReplacementPod(ctx context.Context, ns, selector string, oldNames []string, timeout time.Duration) error {
	c.log.Info("waiting for replacement pod",
		zap.String("namespace", ns), zap.String("selector", selector))
	old := make(map[string]struct{}, len(oldNames))
	for _, name := range oldNames {
		old[name] = struct{}{}
	}
	return c.poll(ctx, timeout, 2*time.Second, func(ctx context.Context) (bool, error) {
		pods, err := c.typed.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector})
		if err != nil {
			return false, fmt.Errorf("list pods (ns=%s selector=%s): %w", ns, selector, err)
		}
		for i := range pods.Items {
			pod := &pods.Items[i]
			if _, isOld := old[pod.Name]; isOld {
				continue
			}
			if podReady(pod) {
				return true, nil
			}
		}
		return false, nil
	})
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
	// Namespace is the target Service's namespace. Empty defaults to the
	// Gateway's namespace and omits the field from the CR; a non-empty value
	// targets a Service in another namespace, which the operator permits only when
	// that namespace carries the cross-namespace ingress consent label.
	Namespace string
	// TargetPort is the port on Service.
	TargetPort int
}

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
	// WireguardListenPort sets spec.wireguard.listenPort, the gateway VM's
	// WireGuard UDP listen port. Zero omits the field so the CRD default (51820)
	// applies; a non-zero value lets a test give coexisting gateways distinct WG
	// ports to assert per-gateway firewall isolation.
	WireguardListenPort int
}

// CreateGateway applies a Gateway CR (wgnet.dev/v1alpha1) in ns with the given
// spec. The operator reconciles it into the XGatewayGCP composite and the link
// Deployment. Idempotent on the already-exists path so re-running Start in a
// reused namespace is safe.
func (c *Client) CreateGateway(ctx context.Context, ns, name string, spec GatewaySpec) error {
	forwards := make([]any, 0, len(spec.Forwards))
	for _, f := range spec.Forwards {
		forward := map[string]any{
			"port":     int64(f.Port),
			"protocol": f.Protocol,
			"service":  f.Service,
		}
		// Omit the optional fields when unset so the CR mirrors the operator's
		// optional-field contract: an empty namespace defaults to the Gateway's own
		// namespace, and a zero targetPort defaults to port. Emitting an explicit
		// zero targetPort would also fail the CRD's minimum=1 validation.
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
	// Omit spec.wireguard.listenPort when unset so the CRD default (51820)
	// applies; a non-zero value pins a distinct WG port for the gateway.
	if spec.WireguardListenPort != 0 {
		gatewaySpec["wireguard"] = map[string]any{
			"listenPort": int64(spec.WireguardListenPort),
		}
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
	// Ready is true when the Gateway carries a Ready=True condition, meaning the
	// operator finished reconciling the XGatewayGCP and the link.
	Ready bool
}

// GetGatewayStatus reads the named Gateway in ns and extracts the address and
// the Ready condition the operator mirrors up from the XGatewayGCP.
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

// WaitGatewayCondition polls the named Gateway until it carries a status
// condition matching condType, status, and reason, or timeout elapses. An empty
// reason matches any reason. Unlike WaitGatewayReady it does not gate on the
// address, so it serves the validation-failure paths (e.g. Ready=False reason
// CrossNamespaceForwardDenied) that never reach a provisioned address.
func (c *Client) WaitGatewayCondition(ctx context.Context, ns, name, condType, status, reason string, timeout time.Duration) error {
	c.log.Info("waiting for gateway condition",
		zap.String("namespace", ns), zap.String("name", name),
		zap.String("type", condType), zap.String("status", status), zap.String("reason", reason))
	return c.poll(ctx, timeout, 5*time.Second, func(ctx context.Context) (bool, error) {
		obj, err := c.dynamic.Resource(gatewayGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("get gateway %s/%s: %w", ns, name, err)
		}
		return hasCondition(obj, condType, status, reason), nil
	})
}

// UpdateGateway applies a read-modify-write to the named Gateway's spec: it
// fetches the current object, hands mutate the spec map to edit in place, then
// writes the object back. mutate operates on .spec only; a non-nil error from it
// aborts the update. Used to edit spec.forwards live and exercise the operator's
// checksum-driven config rollout.
//
// The fetch-mutate-write runs inside retry.RetryOnConflict against a freshly
// fetched object on each attempt, so a concurrent operator write to the same
// Gateway (status, conditions, finalizers) does not lose the update to an
// optimistic-concurrency conflict. mutate must therefore be safe to run more
// than once.
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

// DeleteGateway deletes the named Gateway, triggering the operator's finalizer
// (which drains the XGatewayGCP before the object is removed). Not-found is
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

// WaitXGatewayGCPGone polls until the named XGatewayGCP composite is absent, or
// timeout elapses. The operator names the composite after the Gateway, so the
// composite shares the Gateway's name. Teardown uses it as the in-cluster signal
// that Crossplane drained the GCP resources the composite owned, before the
// namespace is deleted.
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

// GetXGatewayGCPServiceAccountEmail reads status.serviceAccountEmail from the
// named XGatewayGCP composite, the GCP service-account the operator scopes the
// gateway's firewall rule to via targetServiceAccounts. The operator names the
// composite after the Gateway, so name is the Gateway's name. An empty string
// (with no error) means the composite has not yet observed the SA; the caller
// should retry. A missing composite is returned as an error.
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

// hasCondition reports whether obj carries a status condition matching condType
// and status, and (when reason is non-empty) reason. An empty reason matches any
// reason, so callers can assert just type+status.
//
// When the condition carries observedGeneration, it must be at least the
// object's metadata.generation. Without this a poll right after a spec edit could
// match the stale pre-edit condition (which the operator has not yet re-stamped)
// and return prematurely. At steady state observedGeneration equals generation,
// so create-time waits are unaffected. Conditions that omit observedGeneration
// (CRD Established, Crossplane XRD, Deployment) are not gated.
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

// WaitEndpointsReady polls the named Service's EndpointSlices until at least one
// endpoint address is Ready, or the timeout elapses. EndpointSlices are matched
// to their owning Service by the kubernetes.io/service-name label the endpoint
// controller stamps; an endpoint counts as ready when Conditions.Ready is nil or
// true, per the EndpointSlice contract. WaitDeploymentAvailable alone leaves an
// endpoint-population lag (the echo Deployment carries no readinessProbe, so it
// reports Available before its pod is registered as a ready endpoint), so a
// caller that points a forward at a fresh backend gates on this to ensure the
// backend is actually serving before the DNAT goes live.
func (c *Client) WaitEndpointsReady(ctx context.Context, namespace, serviceName string, timeout time.Duration) error {
	c.log.Info("waiting for service endpoints ready",
		zap.String("namespace", namespace), zap.String("service", serviceName))
	selector := fmt.Sprintf("%s=%s", discoveryv1.LabelServiceName, serviceName)
	return c.poll(ctx, timeout, 2*time.Second, func(ctx context.Context) (bool, error) {
		slices, err := c.typed.DiscoveryV1().EndpointSlices(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
		if err != nil {
			return false, fmt.Errorf("list endpointslices (ns=%s service=%s): %w", namespace, serviceName, err)
		}
		for i := range slices.Items {
			slice := &slices.Items[i]
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

// WaitCRDEstablished polls the named CustomResourceDefinition until it reports an
// Established condition of True, or the timeout elapses. helm --wait does not gate
// on a CRD's Established condition, so the suite waits explicitly before applying
// any custom resource of that kind.
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
// exists, or the timeout elapses. Presence is sufficient for the suite: the
// operator hard-requires the XGatewayGCP CRD the XRD installs, and the Composition
// is created in the same release, so the XRD existing confirms the composite path
// is wired.
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

// ServiceEndpointSummary returns a per-Service summary of every Service in ns
// joined to its EndpointSlices: the Service name, its ClusterIP, and the count
// and list of Ready endpoint addresses backing it. EndpointSlices are matched to
// their owning Service by the kubernetes.io/service-name label the endpoint
// controller stamps. It serves the failure dump's "did the retargeted backend
// have ready endpoints" question, so a retarget that converged in the operator
// but raced an empty backend is visible. Addresses are deduplicated and sorted so
// the output is stable across the multiple slices a single Service can own.
func (c *Client) ServiceEndpointSummary(ctx context.Context, ns string) (string, error) {
	services, err := c.typed.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("list services %s: %w", ns, err)
	}
	slices, err := c.typed.DiscoveryV1().EndpointSlices(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("list endpointslices %s: %w", ns, err)
	}

	readyByService := make(map[string]map[string]struct{})
	for i := range slices.Items {
		slice := &slices.Items[i]
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
			// A nil Ready is treated as ready per the EndpointSlice contract; only
			// an explicit false excludes the address, so a backend mid-rollout with
			// an unready endpoint is counted as unready in the dump.
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
		sorted := make([]string, 0, len(ready))
		for a := range ready {
			sorted = append(sorted, a)
		}
		sort.Strings(sorted)
		fmt.Fprintf(&b, "%s clusterIP=%s readyAddresses=%d %v\n",
			svc.Name, svc.Spec.ClusterIP, len(sorted), sorted)
	}
	return b.String(), nil
}

// PodStatusSummary returns one line per pod in ns matching selector: the pod
// name, phase, whether its Ready condition is True, and the node it landed on. An
// empty selector summarizes every pod in the namespace. It serves the failure
// dump's backend-pod-health question without dumping raw pod YAML.
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

// ConfigMapData returns the value stored under key in the named ConfigMap in ns.
// It serves the failure dump's "what did the link actually consume" question by
// reading the link ConfigMap's rendered config.json. A missing key is returned as
// an error so the dump records the key drift rather than logging an empty string.
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
