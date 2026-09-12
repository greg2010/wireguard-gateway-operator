package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/events"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/greg2010/wireguard-gateway-operator/internal/link"
	"github.com/greg2010/wireguard-gateway-operator/internal/wg"
	wgnetv1alpha1 "github.com/greg2010/wireguard-gateway-operator/pkg/api/v1alpha1"
)

// gatewayFinalizer holds Gateway deletion until Crossplane has drained the cloud
// resources. The other children are reaped by owner-ref GC.
const gatewayFinalizer = "wgnet.dev/gateway-teardown"

// fieldOwner is the server-side-apply field manager for every applied object; a stable
// name keeps the operator from fighting Crossplane over defaulted fields.
const fieldOwner = client.FieldOwner("gateway-operator")

const (
	conditionReady = "Ready"

	reasonProvisioning    = "Provisioning"
	reasonReady           = "Ready"
	reasonReconcileFailed = "ReconcileFailed"
	reasonTerminating     = "Terminating"

	// actionReconcile is the action verb on emitted failure events. The events API
	// requires an UpperCamelCase action describing what the controller was doing.
	actionReconcile = "Reconcile"

	// Forward-validation Ready=False reasons. Each reflects external state a backend
	// change can clear without a spec edit, so all are transient.
	reasonCrossNamespaceForwardDenied = "CrossNamespaceForwardDenied"
	reasonTargetNamespaceNotFound     = "TargetNamespaceNotFound"
	reasonUnsupportedServiceType      = "UnsupportedServiceType"
	reasonServiceNotFound             = "ServiceNotFound"
	reasonTargetPortNotListening      = "TargetPortNotListening"
)

// reasonUnresolvedBackendPort is event-only, never a Ready reason: the forward stays
// valid, but its named targetPort widens the link's egress rule to the whole protocol.
const reasonUnresolvedBackendPort = "UnresolvedBackendPort"

// crossNamespaceIngressLabel is the consent label a target namespace must carry before a
// Gateway elsewhere may forward public traffic into it.
const (
	crossNamespaceIngressLabel = "wgnet.dev/allow-gateway-ingress"
	crossNamespaceIngressValue = "true"
)

// linkIDAnnotation records the allocated Local link id on the Gateway itself, so an id
// outlives a restore that keeps metadata and spec but drops status.
const linkIDAnnotation = "wgnet.dev/link-id"

// validationRequeueAfter is the transient backoff before re-checking an absent backend,
// kept separate from RequeueInterval (zero in tests) so it cannot spin a hot loop.
const validationRequeueAfter = 10 * time.Second

// KeyGenerator produces a WireGuard keypair. It is injected so tests can supply
// deterministic key material; production binds it to wg.GenerateKeypair.
type KeyGenerator func() (privateKey, publicKey string, err error)

// GatewayReconciler reconciles a Gateway into its XGatewayGCP composite, key Secrets,
// the link workload with its RBAC and NetworkPolicy, and an optional DNSEndpoint, then
// mirrors the composite's observed status back onto the Gateway.
type GatewayReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Config   Config
	Recorder events.EventRecorder

	// APIReader bypasses the manager cache for objects it never tracks: the shared
	// XGatewayNetwork, link Leases and holder pods. SetupWithManager binds it.
	APIReader client.Reader

	// GenerateKey supplies WireGuard keypairs. Nil defaults to wg.GenerateKeypair.
	GenerateKey KeyGenerator

	// unresolvedWarned maps a Gateway UID to the last warned unresolved-backend-port signature,
	// suppressing an identical Warning every requeue. In-memory: a restart warns once more.
	unresolvedWarned sync.Map
}

// +kubebuilder:rbac:groups=wgnet.dev,resources=gateways,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=wgnet.dev,resources=gateways/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=wgnet.dev,resources=gateways/finalizers,verbs=update
// +kubebuilder:rbac:groups=infra.wgnet.dev,resources=xgatewaygcps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=infra.wgnet.dev,resources=xgatewaygcps/status,verbs=get
// +kubebuilder:rbac:groups=infra.wgnet.dev,resources=xgatewaynetworks,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=infra.wgnet.dev,resources=xgatewaynetworks/status,verbs=get
// +kubebuilder:rbac:groups="",resources=secrets,verbs=create;get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterrolebindings,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=bind,resourceNames=gateway-link-endpointslice-reader
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=policy,resources=poddisruptionbudgets,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=externaldns.k8s.io,resources=dnsendpoints,verbs=create;get;patch;update
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile exposes exactly the valid forward subset and never provisions while every
// forward is invalid, but once provisioned keeps its VM through a backend outage.
func (r *GatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var gw wgnetv1alpha1.Gateway
	if err := r.Get(ctx, req.NamespacedName, &gw); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !gw.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, &gw)
	}

	if !controllerutil.ContainsFinalizer(&gw, gatewayFinalizer) {
		controllerutil.AddFinalizer(&gw, gatewayFinalizer)
		if err := r.Update(ctx, &gw); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer: %w", err)
		}
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}

	valid, invalid, err := r.classifyForwards(ctx, &gw)
	if err != nil {
		return r.fail(ctx, &gw, "classify forwards", err)
	}

	provisioned, err := r.xgatewayGCPExists(ctx, &gw)
	if err != nil {
		return r.fail(ctx, &gw, "check xgatewaygcp existence", err)
	}

	// Requeue on the transient floor when an invalid forward can clear on its own, so
	// the Gateway converges without a spec edit once a backend catches up.
	if len(valid) == 0 && !provisioned {
		// Read the link the healthy path's way: it may still hold its Lease and serve
		// the last applied config, and status.link must not blink on this pass.
		ls, lerr := r.linkStatusOf(ctx, &gw)
		if lerr != nil {
			return r.fail(ctx, &gw, "read link activity", lerr)
		}
		if serr := r.mirrorStatusWithForwards(ctx, &gw, "", "", false, invalid, ls, ""); serr != nil {
			return ctrl.Result{}, fmt.Errorf("mirror status: %w", serr)
		}
		result := ctrl.Result{}
		if anyTransientReason(invalid) {
			result.RequeueAfter = validationRequeueAfter
		}
		logger.V(1).Info("gateway not provisioned: no valid forwards", "invalid", len(invalid))
		return result, nil
	}

	if err := r.ensureLinkID(ctx, &gw); err != nil {
		if errors.Is(err, errNoFreeLinkID) {
			return r.failReported(ctx, &gw, "allocate link id", err)
		}
		return r.fail(ctx, &gw, "allocate link id", err)
	}

	if err := r.ensureSecrets(ctx, &gw); err != nil {
		return r.fail(ctx, &gw, "ensure key secrets", err)
	}
	if err := r.ensureXGatewayNetwork(ctx); err != nil {
		return r.fail(ctx, &gw, "ensure shared network", err)
	}
	if err := r.ensureXGatewayGCP(ctx, &gw, forwardSpecs(valid)); err != nil {
		return r.fail(ctx, &gw, "ensure xgatewaygcp", err)
	}

	address, saEmail, message, err := r.readXGatewayGCPStatus(ctx, &gw)
	if err != nil {
		return r.fail(ctx, &gw, "read xgatewaygcp status", err)
	}

	if err := r.ensureLink(ctx, &gw, address, valid, linkIdentityOf(&gw)); err != nil {
		return r.fail(ctx, &gw, "ensure link", err)
	}

	if err := r.ensureDNSEndpoint(ctx, &gw, address); err != nil {
		return r.fail(ctx, &gw, "ensure dns endpoint", err)
	}

	ls, err := r.linkStatusOf(ctx, &gw)
	if err != nil {
		return r.fail(ctx, &gw, "read link activity", err)
	}

	ready := address != "" && ls.Active && len(invalid) == 0 && ls.FaultReason == ""
	if err := r.mirrorStatusWithForwards(ctx, &gw, address, saEmail, ready, invalid, ls, message); err != nil {
		return ctrl.Result{}, fmt.Errorf("mirror status: %w", err)
	}

	// Transient invalid forwards requeue on the transient floor, independent of the
	// steady-state poll (which may be zero in tests).
	result := ctrl.Result{RequeueAfter: r.Config.RequeueInterval}
	if anyTransientReason(invalid) {
		result.RequeueAfter = validationRequeueAfter
	}

	logger.V(1).Info("reconciled gateway",
		"address", address, "linkActive", ls.Active, "activeNode", ls.Node, "linkFault", ls.FaultReason, "ready", ready,
		"valid", len(valid), "invalid", len(invalid))
	return result, nil
}

// invalidForward is a forward classifyForwards rejected, paired with the
// Ready=False reason and a human-readable message naming the specific failure.
type invalidForward struct {
	reason  string
	message string
}

// forwardBackend pairs a valid forward with its backend port and Service port name.
// BackendPort is 0 for a named targetPort; ServicePortName is empty for an unnamed port.
type forwardBackend struct {
	Forward         wgnetv1alpha1.Forward
	BackendPort     int32
	ServicePortName string
}

func forwardSpecs(backends []forwardBackend) []wgnetv1alpha1.Forward {
	forwards := make([]wgnetv1alpha1.Forward, 0, len(backends))
	for _, b := range backends {
		forwards = append(forwards, b.Forward)
	}
	return forwards
}

// classifyForwards partitions forwards into valid and invalid, preserving spec order. A
// non-NotFound API error fails the reconcile rather than misclassifying a forward.
func (r *GatewayReconciler) classifyForwards(ctx context.Context, gw *wgnetv1alpha1.Gateway) (valid []forwardBackend, invalid []invalidForward, err error) {
	local := isLocal(gw)
	var unresolved []unresolvedBackend
	for _, f := range gw.Spec.Forwards {
		ns := effectiveForwardNamespace(f, gw)

		if ns != gw.Namespace {
			allowed, aerr := r.namespaceAllowsIngress(ctx, ns)
			switch {
			case apierrors.IsNotFound(aerr):
				invalid = append(invalid, invalidForward{reasonTargetNamespaceNotFound,
					fmt.Sprintf("forward target namespace %q does not exist", ns)})
				continue
			case aerr != nil:
				return nil, nil, fmt.Errorf("get target namespace %q: %w", ns, aerr)
			case !allowed:
				invalid = append(invalid, invalidForward{reasonCrossNamespaceForwardDenied,
					fmt.Sprintf("cross-namespace forward to %q denied: target namespace must carry label %s=%s",
						ns, crossNamespaceIngressLabel, crossNamespaceIngressValue)})
				continue
			}
		}

		var svc corev1.Service
		serr := r.APIReader.Get(ctx, client.ObjectKey{Namespace: ns, Name: f.Service}, &svc)
		switch {
		case apierrors.IsNotFound(serr):
			invalid = append(invalid, invalidForward{reasonServiceNotFound,
				fmt.Sprintf("forward backend Service %q in namespace %q not found yet", f.Service, ns)})
			continue
		case serr != nil:
			return nil, nil, fmt.Errorf("get forward Service %s/%s: %w", ns, f.Service, serr)
		}

		if msg := unsupportedServiceMessage(&svc, local); msg != "" {
			invalid = append(invalid, invalidForward{reasonUnsupportedServiceType, msg})
			continue
		}

		port := effectiveServicePort(f)
		sp := servicePortFor(&svc, port, corev1.Protocol(f.Protocol))
		if sp == nil {
			invalid = append(invalid, invalidForward{reasonTargetPortNotListening,
				fmt.Sprintf("forward backend Service %q in namespace %q does not publish %s port %d",
					f.Service, ns, f.Protocol, port)})
			continue
		}

		backendPort := backendPortOf(sp)
		// Local resolves a named targetPort through the EndpointSlice and runs without an
		// egress NetworkPolicy, so an unresolved port widens nothing there.
		if backendPort == 0 && !local {
			unresolved = append(unresolved, unresolvedBackend{
				service: f.Service, namespace: ns, targetPort: sp.TargetPort.String(), protocol: string(f.Protocol),
			})
		}

		valid = append(valid, forwardBackend{Forward: f, BackendPort: backendPort, ServicePortName: sp.Name})
	}
	r.warnUnresolvedBackendPorts(gw, unresolved)
	return valid, invalid, nil
}

// unresolvedBackend is a valid forward whose backend Service names its targetPort, so
// the link's egress rule widens to the whole protocol.
type unresolvedBackend struct {
	service    string
	namespace  string
	targetPort string
	protocol   string
}

// warnUnresolvedBackendPorts emits one Warning per unresolved backend, only when the set
// changed: the condition is steady state, so every pass would otherwise re-emit it.
func (r *GatewayReconciler) warnUnresolvedBackendPorts(gw *wgnetv1alpha1.Gateway, unresolved []unresolvedBackend) {
	if r.Recorder == nil {
		return
	}

	key := unresolvedWarnKey(gw)
	if len(unresolved) == 0 {
		r.unresolvedWarned.Delete(key)
		return
	}

	signature := fmt.Sprintf("%v", unresolved)
	if prev, ok := r.unresolvedWarned.Load(key); ok && prev == signature {
		return
	}
	r.unresolvedWarned.Store(key, signature)

	for _, u := range unresolved {
		r.Recorder.Eventf(gw, nil, corev1.EventTypeWarning, reasonUnresolvedBackendPort, actionReconcile,
			"forward backend Service %q in namespace %q names its targetPort %q: the link's egress policy allows every %s port to the backend rather than that one",
			u.service, u.namespace, u.targetPort, u.protocol)
	}
}

// unresolvedWarnKey identifies a Gateway instance for unresolvedWarned, carrying the UID
// so a recreated same-named Gateway does not inherit its predecessor's suppression.
func unresolvedWarnKey(gw *wgnetv1alpha1.Gateway) string {
	return client.ObjectKeyFromObject(gw).String() + "/" + string(gw.UID)
}

// servicePortFor returns the port svc publishes for port and proto, or nil. It matches
// spec.ports[].port, not the containerPort; an empty protocol defaults to TCP.
func servicePortFor(svc *corev1.Service, port int32, proto corev1.Protocol) *corev1.ServicePort {
	for i := range svc.Spec.Ports {
		p := &svc.Spec.Ports[i]
		svcProto := p.Protocol
		if svcProto == "" {
			svcProto = corev1.ProtocolTCP
		}
		if p.Port == port && svcProto == proto {
			return p
		}
	}
	return nil
}

// backendPortOf is sp's numeric targetPort. A named targetPort yields 0: resolving it
// needs the backing EndpointSlices. An unset one is defaulted by the API server.
func backendPortOf(sp *corev1.ServicePort) int32 {
	if sp.TargetPort.Type == intstr.String {
		return 0
	}
	return sp.TargetPort.IntVal
}

// anyTransientReason reports whether any invalid forward can clear without a spec edit.
// Reasons are enumerated so a permanent one is excluded by default.
func anyTransientReason(invalid []invalidForward) bool {
	for _, inv := range invalid {
		switch inv.reason {
		case reasonServiceNotFound, reasonTargetPortNotListening, reasonTargetNamespaceNotFound,
			reasonCrossNamespaceForwardDenied, reasonUnsupportedServiceType:
			return true
		}
	}
	return false
}

// namespaceAllowsIngress reports whether the namespace carries the consent label. A
// NotFound is returned so the caller can tell a missing namespace from an unlabelled one.
func (r *GatewayReconciler) namespaceAllowsIngress(ctx context.Context, name string) (bool, error) {
	var ns corev1.Namespace
	if err := r.APIReader.Get(ctx, client.ObjectKey{Name: name}, &ns); err != nil {
		return false, err
	}
	return ns.Labels[crossNamespaceIngressLabel] == crossNamespaceIngressValue, nil
}

// unsupportedServiceMessage reports why svc cannot back a forward, or "" when it can.
// ExternalName publishes no endpoints; headless lacks the VIP Cluster mode DNATs to.
func unsupportedServiceMessage(svc *corev1.Service, local bool) string {
	switch {
	case svc.Spec.Type == corev1.ServiceTypeExternalName:
		return fmt.Sprintf("forward backend Service %q in namespace %q has unsupported type %q: an ExternalName Service publishes no endpoints to forward to",
			svc.Name, svc.Namespace, svc.Spec.Type)
	case !local && (svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == corev1.ClusterIPNone):
		return fmt.Sprintf("forward backend Service %q in namespace %q is headless: the Cluster traffic policy requires a ClusterIP to DNAT to, set spec.trafficPolicy to Local to forward to a headless Service",
			svc.Name, svc.Namespace)
	}
	return ""
}

// reconcileDelete waits for the XGatewayGCP to disappear before releasing the finalizer,
// so Crossplane drains GCP while the namespace still lives.
func (r *GatewayReconciler) reconcileDelete(ctx context.Context, gw *wgnetv1alpha1.Gateway) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(gw, gatewayFinalizer) {
		return ctrl.Result{}, nil
	}

	xg := newXGatewayGCP()
	err := r.Get(ctx, client.ObjectKey{Namespace: gw.Namespace, Name: gw.Name}, xg)
	switch {
	case apierrors.IsNotFound(err):
		return r.releaseAfterSharedNetwork(ctx, gw)
	case err != nil:
		return ctrl.Result{}, fmt.Errorf("get xgatewaygcp for deletion: %w", err)
	}

	if xg.GetDeletionTimestamp().IsZero() {
		if err := r.Delete(ctx, xg); err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("delete xgatewaygcp: %w", err)
		}
	}

	if changed := meta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{
		Type:               conditionReady,
		Status:             metav1.ConditionFalse,
		Reason:             reasonTerminating,
		Message:            "waiting for xgatewaygcp to finish draining cloud resources",
		ObservedGeneration: gw.Generation,
	}); changed {
		if err := r.Status().Update(ctx, gw); err != nil {
			return ctrl.Result{}, fmt.Errorf("update gateway status: %w", err)
		}
	}

	return ctrl.Result{RequeueAfter: validationRequeueAfter}, nil
}

// releaseAfterSharedNetwork refcounts the shared VPC: it releases the finalizer at once
// while any Gateway remains, and on the last delete holds until the network is gone.
func (r *GatewayReconciler) releaseAfterSharedNetwork(ctx context.Context, gw *wgnetv1alpha1.Gateway) (ctrl.Result, error) {
	var gateways wgnetv1alpha1.GatewayList
	if err := r.APIReader.List(ctx, &gateways); err != nil {
		return ctrl.Result{}, fmt.Errorf("list gateways for shared-network refcount: %w", err)
	}

	remaining := 0
	for i := range gateways.Items {
		if gateways.Items[i].DeletionTimestamp.IsZero() {
			remaining++
		}
	}

	if remaining > 0 {
		return r.releaseFinalizer(ctx, gw)
	}

	net := newXGatewayNetwork()
	err := r.APIReader.Get(ctx, client.ObjectKey{Name: r.Config.SharedNetworkName, Namespace: r.Config.PodNamespace}, net)
	switch {
	case apierrors.IsNotFound(err):
		return r.releaseFinalizer(ctx, gw)
	case err != nil:
		return ctrl.Result{}, fmt.Errorf("get shared network for deletion: %w", err)
	}

	if net.GetDeletionTimestamp().IsZero() {
		if err := r.Delete(ctx, net); err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("delete shared network: %w", err)
		}
		if changed := meta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{
			Type:               conditionReady,
			Status:             metav1.ConditionFalse,
			Reason:             reasonTerminating,
			Message:            "waiting for shared network to finish draining cloud resources",
			ObservedGeneration: gw.Generation,
		}); changed {
			if err := r.Status().Update(ctx, gw); err != nil {
				return ctrl.Result{}, fmt.Errorf("update gateway status: %w", err)
			}
		}
	}

	return ctrl.Result{RequeueAfter: validationRequeueAfter}, nil
}

// Deletes the link workload before the Lease and ClusterRoleBinding: nothing owner-reaps the Lease
// and a live elector re-creates it. The pod wait is bounded so one stuck Terminating cannot strand.
func (r *GatewayReconciler) releaseFinalizer(ctx context.Context, gw *wgnetv1alpha1.Gateway) (ctrl.Result, error) {
	if err := r.deleteLinkWorkload(ctx, gw); err != nil {
		return ctrl.Result{}, err
	}

	var pods corev1.PodList
	if err := r.APIReader.List(ctx, &pods,
		client.InNamespace(gw.Namespace), client.MatchingLabels(linkSelectorLabels(gw))); err != nil {
		return ctrl.Result{}, fmt.Errorf("list link pods for teardown: %w", err)
	}
	holding, stuck := partitionTerminatingLinkPods(pods.Items)
	if len(stuck) > 0 {
		log.FromContext(ctx).Info("proceeding with link teardown past pods stuck terminating",
			"pods", stuck, "reason", "deletionTimestamp older than the pod grace period plus slack",
			"slack", linkTeardownSlack.String())
	}
	if len(holding) > 0 {
		if err := r.markTerminatingOnLinkPods(ctx, gw, holding); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: linkTeardownRequeueAfter}, nil
	}

	if err := r.deleteLinkLease(ctx, gw); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.deleteLinkClusterRoleBinding(ctx, gw); err != nil {
		return ctrl.Result{}, err
	}
	controllerutil.RemoveFinalizer(gw, gatewayFinalizer)
	if err := r.Update(ctx, gw); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove finalizer: %w", err)
	}
	r.unresolvedWarned.Delete(unresolvedWarnKey(gw))
	return ctrl.Result{}, nil
}

// linkTeardownRequeueAfter paces the wait for the link pods to exit. Nothing watches
// those pods, so this requeue timer is the only trigger that re-checks them.
const linkTeardownRequeueAfter = 2 * time.Second

// linkTeardownSlack pads each pod's grace period before teardown stops waiting on it. A pod on a
// partitioned node stays Terminating until its Node goes away. Var so tests can shorten it.
var linkTeardownSlack = 30 * time.Second

// partitionTerminatingLinkPods splits link pods into those teardown waits for and those deleted
// longer ago than their grace period plus linkTeardownSlack. Sorted, so messages stay stable.
func partitionTerminatingLinkPods(pods []corev1.Pod) (holding, stuck []string) {
	for i := range pods {
		pod := &pods[i]
		deletedAt := pod.DeletionTimestamp
		grace := int64(corev1.DefaultTerminationGracePeriodSeconds)
		if pod.Spec.TerminationGracePeriodSeconds != nil {
			grace = *pod.Spec.TerminationGracePeriodSeconds
		}
		if deletedAt.IsZero() || time.Since(deletedAt.Time) <= time.Duration(grace)*time.Second+linkTeardownSlack {
			holding = append(holding, pod.Name)
			continue
		}
		stuck = append(stuck, pod.Name)
	}
	slices.Sort(holding)
	slices.Sort(stuck)
	return holding, stuck
}

// markTerminatingOnLinkPods publishes why the delete is still held, so a Gateway waiting
// on its link pods names them rather than showing a stale condition from before the delete.
func (r *GatewayReconciler) markTerminatingOnLinkPods(ctx context.Context, gw *wgnetv1alpha1.Gateway, pods []string) error {
	if changed := meta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{
		Type:               conditionReady,
		Status:             metav1.ConditionFalse,
		Reason:             reasonTerminating,
		Message:            "waiting for link pods to exit: " + strings.Join(pods, ", "),
		ObservedGeneration: gw.Generation,
	}); changed {
		if err := r.Status().Update(ctx, gw); err != nil {
			return fmt.Errorf("update gateway status: %w", err)
		}
	}
	return nil
}

// deleteLinkWorkload removes the mode's link workload, tolerating a NotFound. Deleting it
// explicitly rather than leaving it to owner-ref GC stops the electors before the Lease reap.
func (r *GatewayReconciler) deleteLinkWorkload(ctx context.Context, gw *wgnetv1alpha1.Gateway) error {
	objMeta := metav1.ObjectMeta{Namespace: gw.Namespace, Name: linkComponentName(gw)}
	var workload client.Object = &appsv1.Deployment{ObjectMeta: objMeta}
	if isLocal(gw) {
		workload = &appsv1.DaemonSet{ObjectMeta: objMeta}
	}
	if err := r.Delete(ctx, workload, client.PropagationPolicy(metav1.DeletePropagationBackground)); err != nil &&
		!apierrors.IsNotFound(err) {
		return fmt.Errorf("delete link workload %s/%s: %w", objMeta.Namespace, objMeta.Name, err)
	}
	return nil
}

// deleteLinkLease removes the leader-election Lease the link pods create. It must run
// only once no link pod is left, or a live elector re-creates it.
func (r *GatewayReconciler) deleteLinkLease(ctx context.Context, gw *wgnetv1alpha1.Gateway) error {
	lease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: linkComponentName(gw)},
	}
	if err := r.Delete(ctx, lease); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete link lease %s/%s: %w", lease.Namespace, lease.Name, err)
	}
	return nil
}

// errNoFreeLinkID reports that every id in 1..link.MaxLinkID is held. Only deleting a
// Local Gateway frees one, so it is surfaced on Ready instead of retried with backoff.
var errNoFreeLinkID = errors.New("no free link id")

// ensureLinkID records the Local link id in status and in linkIDAnnotation, which outlives a
// restore that drops status. A status id wins: it names node state a restarting link reclaims.
func (r *GatewayReconciler) ensureLinkID(ctx context.Context, gw *wgnetv1alpha1.Gateway) error {
	if !isLocal(gw) {
		return nil
	}
	if gw.Status.Link.ID > 0 {
		return r.persistLinkIDAnnotation(ctx, gw, gw.Status.Link.ID)
	}

	var gateways wgnetv1alpha1.GatewayList
	if err := r.APIReader.List(ctx, &gateways); err != nil {
		return fmt.Errorf("list gateways for link id allocation: %w", err)
	}
	self := client.ObjectKeyFromObject(gw)

	id, ok := r.adoptableLinkID(ctx, gw, gateways.Items, self)
	if !ok {
		if id, ok = lowestFreeLinkID(gateways.Items, self); !ok {
			return errNoFreeLinkID
		}
	}

	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var fresh wgnetv1alpha1.Gateway
		// Re-Get uncached: the cache can still hold the copy whose resourceVersion lost
		// the conflict, so a cached retry would resubmit the same stale object forever.
		if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(gw), &fresh); err != nil {
			return fmt.Errorf("get gateway for link id update: %w", err)
		}
		if fresh.Status.Link.ID > 0 {
			id = fresh.Status.Link.ID
			return nil
		}
		fresh.Status.Link.ID = id
		if err := r.Status().Update(ctx, &fresh); err != nil {
			return fmt.Errorf("update gateway link id: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}

	gw.Status.Link.ID = id
	return r.persistLinkIDAnnotation(ctx, gw, id)
}

// adoptableLinkID reports the id gw's annotation claims when well-formed and unheld elsewhere.
// Rejections are logged: the Gateway then takes an id its node state is not named after.
func (r *GatewayReconciler) adoptableLinkID(ctx context.Context, gw *wgnetv1alpha1.Gateway, gateways []wgnetv1alpha1.Gateway, self client.ObjectKey) (int32, bool) {
	raw, present := gw.Annotations[linkIDAnnotation]
	if !present {
		return 0, false
	}
	logger := log.FromContext(ctx)
	claimed, err := parseLinkID(raw)
	if err != nil {
		logger.Info("ignoring link id annotation, allocating a fresh id",
			"gateway", self.String(), "annotation", raw, "reason", err.Error())
		return 0, false
	}
	if holder, taken := linkIDHolders(gateways, self)[claimed]; taken {
		logger.Info("ignoring link id annotation, allocating a fresh id",
			"gateway", self.String(), "annotation", raw, "reason", "held by "+holder.String())
		return 0, false
	}
	return claimed, true
}

// persistLinkIDAnnotation records id in gw's linkIDAnnotation, both on the server and on
// the in-memory copy. It is a no-op when the annotation already matches.
func (r *GatewayReconciler) persistLinkIDAnnotation(ctx context.Context, gw *wgnetv1alpha1.Gateway, id int32) error {
	want := strconv.FormatInt(int64(id), 10)
	if gw.Annotations[linkIDAnnotation] == want {
		return nil
	}

	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var fresh wgnetv1alpha1.Gateway
		// Re-Get uncached: the cache can still hold the copy whose resourceVersion lost
		// the conflict, so a cached retry would resubmit the same stale object forever.
		if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(gw), &fresh); err != nil {
			return fmt.Errorf("get gateway for link id annotation update: %w", err)
		}
		if fresh.Annotations[linkIDAnnotation] == want {
			return nil
		}
		if fresh.Annotations == nil {
			fresh.Annotations = make(map[string]string, 1)
		}
		fresh.Annotations[linkIDAnnotation] = want
		if err := r.Update(ctx, &fresh); err != nil {
			return fmt.Errorf("update gateway link id annotation: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}

	if gw.Annotations == nil {
		gw.Annotations = make(map[string]string, 1)
	}
	gw.Annotations[linkIDAnnotation] = want
	return nil
}

// parseLinkID reads an annotated id, rejecting anything outside 1..link.MaxLinkID.
func parseLinkID(raw string) (int32, error) {
	parsed, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("malformed link id annotation %q", raw)
	}
	if parsed < 1 || parsed > link.MaxLinkID {
		return 0, fmt.Errorf("link id annotation %q out of range 1..%d", raw, link.MaxLinkID)
	}
	return int32(parsed), nil
}

// linkIDHolders maps each held id to its Gateway, skipping self. Status id and annotated id both
// reserve: reallocating an annotated id would hand two links the same node-global names.
func linkIDHolders(gateways []wgnetv1alpha1.Gateway, self client.ObjectKey) map[int32]client.ObjectKey {
	holders := make(map[int32]client.ObjectKey, len(gateways))
	for i := range gateways {
		g := &gateways[i]
		key := client.ObjectKeyFromObject(g)
		if key == self {
			continue
		}
		if g.Status.Link.ID > 0 {
			holders[g.Status.Link.ID] = key
		}
		if raw, ok := g.Annotations[linkIDAnnotation]; ok {
			if id, err := parseLinkID(raw); err == nil {
				holders[id] = key
			}
		}
	}
	return holders
}

// lowestFreeLinkID returns the lowest id in 1..link.MaxLinkID held by no Gateway,
// skipping self. A single active operator serialises the allocation.
func lowestFreeLinkID(gateways []wgnetv1alpha1.Gateway, self client.ObjectKey) (int32, bool) {
	taken := linkIDHolders(gateways, self)
	for id := int32(1); id <= link.MaxLinkID; id++ {
		if _, ok := taken[id]; !ok {
			return id, true
		}
	}
	return 0, false
}

// ensureSecrets generates the key material once into the owner-ref'd bundle and link
// Secrets. Existing Secrets are untouched: keys are never rotated, and GC reaps them.
func (r *GatewayReconciler) ensureSecrets(ctx context.Context, gw *wgnetv1alpha1.Gateway) error {
	bundleExists, err := r.objectExists(ctx, gw.Namespace, bundleSecretName(gw), &corev1.Secret{})
	if err != nil {
		return err
	}
	linkExists, err := r.objectExists(ctx, gw.Namespace, linkSecretName(gw), &corev1.Secret{})
	if err != nil {
		return err
	}
	if bundleExists && linkExists {
		return nil
	}

	gen := r.GenerateKey
	if gen == nil {
		gen = wg.GenerateKeypair
	}
	gatewayPriv, gatewayPub, err := gen()
	if err != nil {
		return fmt.Errorf("generate gateway keypair: %w", err)
	}
	linkPriv, linkPub, err := gen()
	if err != nil {
		return fmt.Errorf("generate link keypair: %w", err)
	}

	if err := r.createOwned(ctx, gw, buildBundleSecret(gw, gatewayPriv, linkPub)); err != nil {
		return fmt.Errorf("create bundle secret: %w", err)
	}
	if err := r.createOwned(ctx, gw, buildLinkSecret(gw, linkPriv, gatewayPub)); err != nil {
		return fmt.Errorf("create link secret: %w", err)
	}
	return nil
}

// ensureXGatewayGCP server-side-applies the composite, leaving Crossplane's status and
// defaulted fields intact. forwards is the subset whose ports the firewall opens.
func (r *GatewayReconciler) ensureXGatewayGCP(ctx context.Context, gw *wgnetv1alpha1.Gateway, forwards []wgnetv1alpha1.Forward) error {
	desired, err := buildXGatewayGCP(gw, r.Config, forwards)
	if err != nil {
		return err
	}
	if err := controllerutil.SetControllerReference(gw, desired, r.Scheme); err != nil {
		return fmt.Errorf("set xgatewaygcp owner reference: %w", err)
	}
	data, err := json.Marshal(desired)
	if err != nil {
		return fmt.Errorf("marshal xgatewaygcp: %w", err)
	}
	if err := r.Patch(ctx, desired, client.RawPatch(types.ApplyPatchType, data), fieldOwner, client.ForceOwnership); err != nil {
		return fmt.Errorf("apply xgatewaygcp: %w", err)
	}
	return nil
}

// ensureXGatewayNetwork applies the singleton shared-VPC composite before anything
// references it. It is unowned and re-created here if a racing last-delete tore it down.
func (r *GatewayReconciler) ensureXGatewayNetwork(ctx context.Context) error {
	desired := buildXGatewayNetwork(r.Config)
	data, err := json.Marshal(desired)
	if err != nil {
		return fmt.Errorf("marshal xgatewaynetwork: %w", err)
	}
	if err := r.Patch(ctx, desired, client.RawPatch(types.ApplyPatchType, data), fieldOwner, client.ForceOwnership); err != nil {
		return fmt.Errorf("apply xgatewaynetwork: %w", err)
	}
	return nil
}

// ensureLink applies the link RBAC and ConfigMap, then the mode's workload. Local skips the
// NetworkPolicy (it cannot select host-network pods) and the PDB (it would block node drains).
func (r *GatewayReconciler) ensureLink(ctx context.Context, gw *wgnetv1alpha1.Gateway, address string, backends []forwardBackend, ident *link.Identity) error {
	if err := r.apply(ctx, gw, buildLinkServiceAccount(gw)); err != nil {
		return err
	}
	if err := r.apply(ctx, gw, buildLinkRole(gw)); err != nil {
		return err
	}
	if err := r.apply(ctx, gw, buildLinkRoleBinding(gw)); err != nil {
		return err
	}

	cm, err := buildLinkConfigMap(gw, address, backends, ident)
	if err != nil {
		return err
	}
	if err := r.apply(ctx, gw, cm); err != nil {
		return err
	}

	if ident != nil {
		if err := r.apply(ctx, nil, buildLinkClusterRoleBinding(gw)); err != nil {
			return err
		}
		return r.apply(ctx, gw, buildLinkDaemonSet(gw, r.Config, ident))
	}

	if err := r.apply(ctx, gw, buildLinkNetworkPolicy(gw, backends)); err != nil {
		return err
	}
	if err := r.apply(ctx, gw, buildLinkDeployment(gw, r.Config)); err != nil {
		return err
	}

	if effectiveLinkReplicas(gw) > 1 {
		return r.apply(ctx, gw, buildLinkPodDisruptionBudget(gw))
	}
	return r.deleteLinkPodDisruptionBudget(ctx, gw)
}

// deleteLinkPodDisruptionBudget removes the link PDB, tolerating a NotFound. It runs at
// a single replica so a scale-down cannot leave a PDB behind to block node drains.
func (r *GatewayReconciler) deleteLinkPodDisruptionBudget(ctx context.Context, gw *wgnetv1alpha1.Gateway) error {
	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      linkComponentName(gw),
			Namespace: gw.Namespace,
		},
	}
	if err := r.Delete(ctx, pdb); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete link poddisruptionbudget: %w", err)
	}
	return nil
}

// deleteLinkClusterRoleBinding removes the EndpointSlice-reader binding, tolerating a
// NotFound so it can run unconditionally in a mode that never created one.
func (r *GatewayReconciler) deleteLinkClusterRoleBinding(ctx context.Context, gw *wgnetv1alpha1.Gateway) error {
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: linkClusterRoleBindingName(gw)},
	}
	if err := r.Delete(ctx, crb); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete link clusterrolebinding: %w", err)
	}
	return nil
}

// ensureDNSEndpoint applies the DNSEndpoint once hostnames and the address are known.
// It is owner-ref'd but not watched, so startup does not depend on the external-dns CRD.
func (r *GatewayReconciler) ensureDNSEndpoint(ctx context.Context, gw *wgnetv1alpha1.Gateway, address string) error {
	desired := buildDNSEndpoint(gw, address)
	if desired == nil {
		return nil
	}
	if err := controllerutil.SetControllerReference(gw, desired, r.Scheme); err != nil {
		return fmt.Errorf("set dns endpoint owner reference: %w", err)
	}
	data, err := json.Marshal(desired)
	if err != nil {
		return fmt.Errorf("marshal dns endpoint: %w", err)
	}
	if err := r.Patch(ctx, desired, client.RawPatch(types.ApplyPatchType, data), fieldOwner, client.ForceOwnership); err != nil {
		return fmt.Errorf("apply dns endpoint: %w", err)
	}
	return nil
}

// xgatewayGCPExists reports whether the Gateway provisioned at least once, so it keeps
// its VM under an all-invalid forward set. Errors other than NotFound are surfaced.
func (r *GatewayReconciler) xgatewayGCPExists(ctx context.Context, gw *wgnetv1alpha1.Gateway) (bool, error) {
	xg := newXGatewayGCP()
	err := r.Get(ctx, client.ObjectKey{Namespace: gw.Namespace, Name: gw.Name}, xg)
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("get xgatewaygcp: %w", err)
	}
	return true, nil
}

// readXGatewayGCPStatus reads the composite's observed address, serviceAccountEmail and
// message. A missing composite yields empty values: the apply has not yet propagated.
func (r *GatewayReconciler) readXGatewayGCPStatus(ctx context.Context, gw *wgnetv1alpha1.Gateway) (address, saEmail, message string, err error) {
	xg := newXGatewayGCP()
	if err := r.Get(ctx, client.ObjectKey{Namespace: gw.Namespace, Name: gw.Name}, xg); err != nil {
		if apierrors.IsNotFound(err) {
			return "", "", "", nil
		}
		return "", "", "", fmt.Errorf("get xgatewaygcp: %w", err)
	}
	address, _, err = unstructured.NestedString(xg.Object, "status", "address")
	if err != nil {
		return "", "", "", fmt.Errorf("read status.address: %w", err)
	}
	saEmail, _, err = unstructured.NestedString(xg.Object, "status", "serviceAccountEmail")
	if err != nil {
		return "", "", "", fmt.Errorf("read status.serviceAccountEmail: %w", err)
	}
	message, _, err = unstructured.NestedString(xg.Object, "status", "message")
	if err != nil {
		return "", "", "", fmt.Errorf("read status.message: %w", err)
	}
	return address, saEmail, message, nil
}

// linkStatus is what the operator observes about a Gateway's link from the Lease and
// the pod holding it.
type linkStatus struct {
	// Active is true when a Lease holder pod exists and reports PodReady. Idle standbys
	// report Ready too, so this gates on the holder, not workload availability.
	Active bool
	// Node is the holder pod's node name, empty when there is no readable holder.
	Node string
	// FaultReason and FaultMessage carry the holder's link-fault annotations.
	FaultReason  string
	FaultMessage string
}

// knownLinkFaults are the fault reasons a link may publish. An unrecognised value is
// ignored rather than copied into the API-validated Ready condition reason.
var knownLinkFaults = func() map[string]bool {
	faults := link.KnownFaults()
	m := make(map[string]bool, len(faults))
	for _, reason := range faults {
		m[reason] = true
	}
	return m
}()

// maxFaultMessageBytes bounds the Lease fault message copied into the Ready condition;
// the API rejects messages beyond 32768 characters, turning a fault into a write loop.
const maxFaultMessageBytes = 4096

const faultMessageTruncationMarker = "... (truncated)"

// truncateFaultMessage shortens msg to maxFaultMessageBytes, cutting on a rune boundary
// so the result stays valid UTF-8 and the API server accepts it.
func truncateFaultMessage(msg string) string {
	if len(msg) <= maxFaultMessageBytes {
		return msg
	}
	cut := maxFaultMessageBytes - len(faultMessageTruncationMarker)
	for cut > 0 && !utf8.RuneStart(msg[cut]) {
		cut--
	}
	return msg[:cut] + faultMessageTruncationMarker
}

// linkStatusOf reports the Lease holder's readiness, node and fault; a missing holder is a zero
// value, not an error. It reads the holder, not the expiry, which fail-static leaves stale.
func (r *GatewayReconciler) linkStatusOf(ctx context.Context, gw *wgnetv1alpha1.Gateway) (linkStatus, error) {
	var lease coordinationv1.Lease
	leaseKey := client.ObjectKey{Namespace: gw.Namespace, Name: linkComponentName(gw)}
	if err := r.APIReader.Get(ctx, leaseKey, &lease); err != nil {
		if apierrors.IsNotFound(err) {
			return linkStatus{}, nil
		}
		return linkStatus{}, fmt.Errorf("get link lease %s: %w", leaseKey, err)
	}
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity == "" {
		return linkStatus{}, nil
	}

	var ls linkStatus
	if reason := lease.Annotations[link.LeaseFaultAnnotation]; knownLinkFaults[reason] {
		ls.FaultReason = reason
		ls.FaultMessage = truncateFaultMessage(lease.Annotations[link.LeaseFaultMessageAnnotation])
		if ls.FaultMessage == "" {
			ls.FaultMessage = fmt.Sprintf("link reported %s", reason)
		}
	}

	var holder corev1.Pod
	holderKey := client.ObjectKey{Namespace: gw.Namespace, Name: *lease.Spec.HolderIdentity}
	if err := r.APIReader.Get(ctx, holderKey, &holder); err != nil {
		if apierrors.IsNotFound(err) {
			return ls, nil
		}
		return linkStatus{}, fmt.Errorf("get link lease holder pod %s: %w", holderKey, err)
	}
	ls.Node = holder.Spec.NodeName
	for _, cond := range holder.Status.Conditions {
		if cond.Type == corev1.PodReady {
			ls.Active = cond.Status == corev1.ConditionTrue
			break
		}
	}
	return ls, nil
}

// Ready precedence: invalid forward, then link fault, then ready, then provisioning. An unchanged
// status is not written, to avoid a write loop; compositeMessage reaches Provisioning only.
func (r *GatewayReconciler) mirrorStatusWithForwards(ctx context.Context, gw *wgnetv1alpha1.Gateway, address, saEmail string, ready bool, invalid []invalidForward, ls linkStatus, compositeMessage string) error {
	cond := metav1.Condition{Type: conditionReady}
	switch {
	case len(invalid) > 0:
		cond.Status = metav1.ConditionFalse
		cond.Reason = invalid[0].reason
		cond.Message = invalidForwardsMessage(invalid)
	case ls.FaultReason != "":
		cond.Status = metav1.ConditionFalse
		cond.Reason = ls.FaultReason
		cond.Message = ls.FaultMessage
	case ready:
		cond.Status = metav1.ConditionTrue
		cond.Reason = reasonReady
		cond.Message = "gateway address provisioned and active link tunnel up"
	default:
		cond.Status = metav1.ConditionFalse
		cond.Reason = reasonProvisioning
		cond.Message = "waiting for gateway address and active link tunnel"
		if m := truncateFaultMessage(compositeMessage); m != "" {
			cond.Message += ": " + m
		}
	}

	// Earlier SSA applies stale the in-memory resourceVersion, so the write re-Gets a
	// fresh copy inside RetryOnConflict rather than losing the concurrency race.
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var fresh wgnetv1alpha1.Gateway
		// Re-Get uncached: the cache can still hold the copy whose resourceVersion lost
		// the conflict, so a cached retry would resubmit the same stale object forever.
		if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(gw), &fresh); err != nil {
			return fmt.Errorf("get gateway for status update: %w", err)
		}

		// Stamp observedGeneration from the fresh object: the passed-in gw may be stale
		// relative to a spec edit that landed mid-reconcile.
		cond.ObservedGeneration = fresh.Generation

		prevAddress := fresh.Status.Address
		prevSAEmail := fresh.Status.ServiceAccountEmail
		prevNode := fresh.Status.Link.ActiveNode
		fresh.Status.Address = address
		fresh.Status.ServiceAccountEmail = saEmail
		fresh.Status.Link.ActiveNode = ls.Node
		conditionChanged := meta.SetStatusCondition(&fresh.Status.Conditions, cond)

		if prevAddress == address && prevSAEmail == saEmail && prevNode == ls.Node && !conditionChanged {
			return nil
		}

		if err := r.Status().Update(ctx, &fresh); err != nil {
			return fmt.Errorf("update gateway status: %w", err)
		}
		return nil
	})
}

// invalidForwardsMessage joins the per-forward messages into one Ready condition line,
// so kubectl alone shows which forwards are rejected and why.
func invalidForwardsMessage(invalid []invalidForward) string {
	parts := make([]string, 0, len(invalid))
	for _, inv := range invalid {
		parts = append(parts, inv.message)
	}
	return fmt.Sprintf("%d forward(s) invalid: %s", len(invalid), strings.Join(parts, "; "))
}

// recordFailure emits the Warning and writes Ready=False for a reconcile failure,
// returning the wrapped cause and any status-write error.
func (r *GatewayReconciler) recordFailure(ctx context.Context, gw *wgnetv1alpha1.Gateway, op string, cause error) (wrapped, statusErr error) {
	wrapped = fmt.Errorf("%s: %w", op, cause)
	if r.Recorder != nil {
		r.Recorder.Eventf(gw, nil, corev1.EventTypeWarning, reasonReconcileFailed, actionReconcile, "%s", wrapped.Error())
	}
	statusErr = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var fresh wgnetv1alpha1.Gateway
		// Re-Get uncached: the cache can still hold the copy whose resourceVersion lost
		// the conflict, so a cached retry would resubmit the same stale object forever.
		if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(gw), &fresh); err != nil {
			return fmt.Errorf("get gateway for status update: %w", err)
		}
		meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
			Type:               conditionReady,
			Status:             metav1.ConditionFalse,
			Reason:             reasonReconcileFailed,
			Message:            wrapped.Error(),
			ObservedGeneration: fresh.Generation,
		})
		return r.Status().Update(ctx, &fresh)
	})
	return wrapped, statusErr
}

// fail records the error on the Gateway's Ready condition and surfaces it so the
// manager requeues with backoff.
func (r *GatewayReconciler) fail(ctx context.Context, gw *wgnetv1alpha1.Gateway, op string, cause error) (ctrl.Result, error) {
	wrapped, uerr := r.recordFailure(ctx, gw, op, cause)
	if uerr != nil {
		return ctrl.Result{}, fmt.Errorf("%w; additionally failed to update status: %w", wrapped, uerr)
	}
	return ctrl.Result{}, wrapped
}

// failReported records the error like fail but requeues on the regular interval instead
// of returning it, for causes retrying cannot resolve.
func (r *GatewayReconciler) failReported(ctx context.Context, gw *wgnetv1alpha1.Gateway, op string, cause error) (ctrl.Result, error) {
	wrapped, uerr := r.recordFailure(ctx, gw, op, cause)
	if uerr != nil {
		return ctrl.Result{}, fmt.Errorf("%w; additionally failed to update status: %w", wrapped, uerr)
	}
	return ctrl.Result{RequeueAfter: r.Config.RequeueInterval}, nil
}

// objectExists reports whether the named object is present. probe is mutated by the Get;
// callers pass a fresh empty object of the desired kind.
func (r *GatewayReconciler) objectExists(ctx context.Context, namespace, name string, probe client.Object) (bool, error) {
	err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, probe)
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("get %s/%s: %w", namespace, name, err)
	}
	return true, nil
}

// createOwned sets the Gateway owner reference on obj and creates it, treating an
// already-exists result as success.
func (r *GatewayReconciler) createOwned(ctx context.Context, gw *wgnetv1alpha1.Gateway, obj client.Object) error {
	if err := controllerutil.SetControllerReference(gw, obj, r.Scheme); err != nil {
		return fmt.Errorf("set owner reference: %w", err)
	}
	if err := r.Create(ctx, obj); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

// apply server-side-applies desired, filling the GVK from the scheme because typed builders omit
// the TypeMeta SSA requires. A nil gw stamps no ownerReference, as cluster-scoped children need.
func (r *GatewayReconciler) apply(ctx context.Context, gw *wgnetv1alpha1.Gateway, desired client.Object) error {
	gvks, _, err := r.Scheme.ObjectKinds(desired)
	if err != nil {
		return fmt.Errorf("gvk for %T: %w", desired, err)
	}
	desired.GetObjectKind().SetGroupVersionKind(gvks[0])
	if gw != nil {
		if err := controllerutil.SetControllerReference(gw, desired, r.Scheme); err != nil {
			return fmt.Errorf("set owner reference: %w", err)
		}
	}
	data, err := json.Marshal(desired)
	if err != nil {
		return fmt.Errorf("marshal %T: %w", desired, err)
	}
	if err := r.Patch(ctx, desired, client.RawPatch(types.ApplyPatchType, data), fieldOwner, client.ForceOwnership); err != nil {
		return fmt.Errorf("apply %T: %w", desired, err)
	}
	return nil
}

// SetupWithManager registers the reconciler. The XGatewayGCP watch omits
// GenerationChangedPredicate so its status-only address writes trigger a reconcile.
func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.APIReader = mgr.GetAPIReader()

	xg := &unstructured.Unstructured{}
	xg.SetGroupVersionKind(XGatewayGCPGVK)

	genChanged := builder.WithPredicates(predicate.GenerationChangedPredicate{})

	return ctrl.NewControllerManagedBy(mgr).
		For(&wgnetv1alpha1.Gateway{}).
		Owns(&appsv1.Deployment{}).
		Owns(&appsv1.DaemonSet{}).
		Owns(&corev1.ConfigMap{}, genChanged).
		Owns(&corev1.Secret{}, genChanged).
		Owns(&networkingv1.NetworkPolicy{}, genChanged).
		Owns(xg).
		Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(r.gatewaysForService)).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.gatewaysForNamespace)).
		Complete(r)
}

// gatewaysForService maps a changed Service to the Gateways forwarding to it, matching
// on effective namespace so cross-namespace forwards resolve.
func (r *GatewayReconciler) gatewaysForService(ctx context.Context, obj client.Object) []reconcile.Request {
	var gateways wgnetv1alpha1.GatewayList
	if err := r.List(ctx, &gateways); err != nil {
		log.FromContext(ctx).Error(err, "list gateways for service watch", "service", client.ObjectKeyFromObject(obj))
		return nil
	}

	var requests []reconcile.Request
	for i := range gateways.Items {
		gw := &gateways.Items[i]
		for _, f := range gw.Spec.Forwards {
			if f.Service == obj.GetName() && effectiveForwardNamespace(f, gw) == obj.GetNamespace() {
				requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(gw)})
				break
			}
		}
	}
	return requests
}

// gatewaysForNamespace maps a Namespace to the Gateways forwarding into it from elsewhere, so a
// consent-label edit re-classifies them. Same-namespace forwards need no consent.
func (r *GatewayReconciler) gatewaysForNamespace(ctx context.Context, obj client.Object) []reconcile.Request {
	var gateways wgnetv1alpha1.GatewayList
	if err := r.List(ctx, &gateways); err != nil {
		log.FromContext(ctx).Error(err, "list gateways for namespace watch", "namespace", obj.GetName())
		return nil
	}

	var requests []reconcile.Request
	for i := range gateways.Items {
		gw := &gateways.Items[i]
		for _, f := range gw.Spec.Forwards {
			ns := effectiveForwardNamespace(f, gw)
			if ns == obj.GetName() && ns != gw.Namespace {
				requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(gw)})
				break
			}
		}
	}
	return requests
}
