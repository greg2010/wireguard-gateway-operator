package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
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

	"github.com/greg2010/wireguard-gateway-operator/internal/wg"
	wgnetv1alpha1 "github.com/greg2010/wireguard-gateway-operator/pkg/api/v1alpha1"
)

// gatewayFinalizer blocks Gateway deletion until the operator has deleted the
// XGatewayGCP and Crossplane has drained the cloud resources. The link, Secrets,
// and DNSEndpoint are reaped by owner-ref GC, but the XGatewayGCP is deleted
// explicitly here so the drain completes before the namespace and CRD go away.
const gatewayFinalizer = "wgnet.dev/gateway-teardown"

// fieldOwner is the server-side-apply field manager for every object the
// reconciler applies. A stable manager name lets the API server track exactly
// which fields the operator owns, so it never fights Crossplane's composite
// controller or the built-in Deployment controller over server-defaulted fields.
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

	// Forward-validation Ready=False reasons. Every one reflects mutable external
	// state a backend change can clear without a Gateway spec edit: a Service
	// appearing, disappearing, changing type, or publishing the target port; a
	// target namespace being created; a consent label being added or removed. So
	// all are transient (see anyTransientReason) and pair with the requeue floor,
	// which bounds convergence even when the corresponding watch event is missed.
	reasonCrossNamespaceForwardDenied = "CrossNamespaceForwardDenied"
	reasonTargetNamespaceNotFound     = "TargetNamespaceNotFound"
	reasonUnsupportedServiceType      = "UnsupportedServiceType"
	reasonServiceNotFound             = "ServiceNotFound"
	reasonTargetPortNotListening      = "TargetPortNotListening"
)

// crossNamespaceIngressLabel is the opt-in label a namespace must carry, set to
// crossNamespaceIngressValue, before a Gateway in another namespace may forward
// public traffic to a Service in it. It is the consent gate that closes the
// cross-tenancy exposure hole: without it a Gateway owner could expose any
// namespace's Service to the public internet.
const (
	crossNamespaceIngressLabel = "wgnet.dev/allow-gateway-ingress"
	crossNamespaceIngressValue = "true"
)

// validationRequeueAfter is how long to wait before re-checking a forward whose
// backend Service is not yet present. It is a fixed transient backoff, decoupled
// from the steady-state RequeueInterval (which may be zero in tests) so a missing
// Service never spins a hot requeue loop.
const validationRequeueAfter = 10 * time.Second

// KeyGenerator produces a WireGuard keypair. It is injected so tests can supply
// deterministic key material; production binds it to wg.GenerateKeypair.
type KeyGenerator func() (privateKey, publicKey string, err error)

// GatewayReconciler reconciles a Gateway into its XGatewayGCP composite, WireGuard
// key Secrets, link Deployment and NetworkPolicy, and optional DNSEndpoint, then
// mirrors the composite's observed status back onto the Gateway.
type GatewayReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Config   Config
	Recorder events.EventRecorder

	// APIReader reads directly from the API server, bypassing the manager cache.
	// The shared-network refcount in releaseAfterSharedNetwork uses it to read the
	// shared XGatewayNetwork composite, which carries no owner ref and is not
	// watched, so the cache never tracks it. SetupWithManager binds it to the
	// manager's APIReader.
	APIReader client.Reader

	// GenerateKey supplies WireGuard keypairs. Nil defaults to wg.GenerateKeypair.
	GenerateKey KeyGenerator
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
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=externaldns.k8s.io,resources=dnsendpoints,verbs=create;get;update
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=create;get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile drives a Gateway toward its desired state. On deletion it deletes the
// XGatewayGCP and requeues until the composite is gone before releasing the
// finalizer; otherwise it ensures the finalizer, classifies the forwards, and
// ensures the key Secrets, the XGatewayGCP, and the link children rendered with
// the valid forward subset, then mirrors the composite status and requeues.
//
// Forward classification gates provisioning per forward rather than all-or-
// nothing. A Gateway with at least one valid forward provisions, exposing exactly
// the valid subset. A Gateway whose forwards are all invalid does not provision
// while unprovisioned; once provisioned it keeps its VM and re-applies the
// children with an empty forward set, which closes the firewall to the WireGuard
// underlay only and stops the link serving any forward, rather than tearing the VM
// down on a transient backend outage. Invalid forwards always surface on the Ready
// condition.
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

	// No valid forward and nothing provisioned yet: do not provision. Report the
	// invalid forwards and requeue on the transient floor when any can clear on its
	// own (a Service or its port appearing), so the Gateway converges without a spec
	// edit once a backend catches up.
	if len(valid) == 0 && !provisioned {
		if serr := r.mirrorStatusWithForwards(ctx, &gw, "", "", false, invalid); serr != nil {
			return ctrl.Result{}, fmt.Errorf("mirror status: %w", serr)
		}
		result := ctrl.Result{}
		if anyTransientReason(invalid) {
			result.RequeueAfter = validationRequeueAfter
		}
		logger.V(1).Info("gateway not provisioned: no valid forwards", "invalid", len(invalid))
		return result, nil
	}

	if err := r.ensureSecrets(ctx, &gw); err != nil {
		return r.fail(ctx, &gw, "ensure key secrets", err)
	}
	if err := r.ensureXGatewayNetwork(ctx); err != nil {
		return r.fail(ctx, &gw, "ensure shared network", err)
	}
	if err := r.ensureXGatewayGCP(ctx, &gw, valid); err != nil {
		return r.fail(ctx, &gw, "ensure xgatewaygcp", err)
	}

	address, saEmail, err := r.readXGatewayGCPStatus(ctx, &gw)
	if err != nil {
		return r.fail(ctx, &gw, "read xgatewaygcp status", err)
	}

	if err := r.ensureLink(ctx, &gw, address, valid); err != nil {
		return r.fail(ctx, &gw, "ensure link", err)
	}

	if err := r.ensureDNSEndpoint(ctx, &gw, address); err != nil {
		return r.fail(ctx, &gw, "ensure dns endpoint", err)
	}

	linkAvailable, err := r.linkAvailable(ctx, &gw)
	if err != nil {
		return r.fail(ctx, &gw, "read link availability", err)
	}

	ready := address != "" && linkAvailable && len(invalid) == 0
	if err := r.mirrorStatusWithForwards(ctx, &gw, address, saEmail, ready, invalid); err != nil {
		return ctrl.Result{}, fmt.Errorf("mirror status: %w", err)
	}

	// A provisioned Gateway carrying transient invalid forwards requeues on the
	// transient floor so it re-renders once the backend appears, independent of the
	// steady-state poll (which may be zero in tests).
	result := ctrl.Result{RequeueAfter: r.Config.RequeueInterval}
	if anyTransientReason(invalid) {
		result.RequeueAfter = validationRequeueAfter
	}

	logger.V(1).Info("reconciled gateway",
		"address", address, "linkAvailable", linkAvailable, "ready", ready,
		"valid", len(valid), "invalid", len(invalid))
	return result, nil
}

// invalidForward is a forward classifyForwards rejected, paired with the
// Ready=False reason and a human-readable message naming the specific failure.
type invalidForward struct {
	reason  string
	message string
}

// classifyForwards partitions a Gateway's forwards into those resolving to a
// real, DNAT-able backend the Gateway is permitted to expose (valid) and those
// failing a check (invalid), preserving spec order in both. Unlike an
// all-or-nothing gate it evaluates every forward, so a Gateway with a mix
// provisions its valid forwards while reporting the invalid ones.
//
// Per forward the first failing check, in order, classifies it: the
// cross-namespace consent gate, then Service existence, then Service type, then
// whether the Service publishes the forward's target port. The cross-namespace
// gate is the security boundary: forwarding into another namespace requires that
// namespace to carry the opt-in consent label, so a Gateway owner cannot expose an
// unconsenting tenant's Service to the public internet. The Service-type check
// rejects backends with no stable ClusterIP to DNAT to (ExternalName, headless),
// which would otherwise produce an invalid or SSRF-prone rule. The target-port
// check rejects a forward whose backend Service does not actually publish the port
// the link would DNAT to, which would otherwise install a black-hole rule.
//
// A non-NotFound API error reading a namespace or Service is returned as err: it
// is an infrastructure failure, not a user error, so it fails the whole reconcile
// and the manager retries with backoff rather than misclassifying the forward.
//
// All reads go through the uncached APIReader. Validation is infrequent, so the
// direct API reads are negligible, and a single read path keeps same- and
// cross-namespace targets uniform.
func (r *GatewayReconciler) classifyForwards(ctx context.Context, gw *wgnetv1alpha1.Gateway) (valid []wgnetv1alpha1.Forward, invalid []invalidForward, err error) {
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

		if !serviceHasClusterIP(&svc) {
			invalid = append(invalid, invalidForward{reasonUnsupportedServiceType,
				fmt.Sprintf("forward backend Service %q in namespace %q has unsupported type %q: a ClusterIP is required to DNAT to",
					f.Service, ns, svc.Spec.Type)})
			continue
		}

		port := effectiveTargetPort(f)
		if !serviceListensOn(&svc, port, corev1.Protocol(f.Protocol)) {
			invalid = append(invalid, invalidForward{reasonTargetPortNotListening,
				fmt.Sprintf("forward backend Service %q in namespace %q does not publish %s port %d",
					f.Service, ns, f.Protocol, port)})
			continue
		}

		valid = append(valid, f)
	}
	return valid, invalid, nil
}

// serviceListensOn reports whether svc publishes a service port matching port and
// proto. A Service port with an empty protocol defaults to TCP per the Kubernetes
// API, so an empty value is treated as TCP for the comparison. The check is
// against the Service's published port (spec.ports[].port), the value
// effectiveTargetPort yields, not the pods' containerPort (spec.ports[].targetPort).
func serviceListensOn(svc *corev1.Service, port int32, proto corev1.Protocol) bool {
	for _, p := range svc.Spec.Ports {
		svcProto := p.Protocol
		if svcProto == "" {
			svcProto = corev1.ProtocolTCP
		}
		if p.Port == port && svcProto == proto {
			return true
		}
	}
	return false
}

// anyTransientReason reports whether any invalid forward carries a reason a
// backend change can clear without a Gateway spec edit. It is the transient-floor
// backstop: a Gateway with such an invalid forward is requeued on the fixed floor
// so it re-converges even if the watch event that would normally re-trigger
// classification is missed (a coalesced update, a dropped informer event, a label
// edit on a namespace the cache was not yet tracking).
//
// Every forward-validation reason qualifies because each reflects mutable external
// state: a Service appearing, disappearing, changing type, or publishing the
// target port; a target namespace being created; a consent label toggling. The
// reasons are enumerated rather than collapsed to len(invalid) > 0 so a future
// reason that is genuinely permanent (a spec-only error) is excluded by default
// until deliberately added here.
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

// namespaceAllowsIngress reports whether the named namespace carries the
// cross-namespace ingress consent label. A NotFound error is returned to the
// caller so it can distinguish a missing namespace from a present one lacking the
// label.
func (r *GatewayReconciler) namespaceAllowsIngress(ctx context.Context, name string) (bool, error) {
	var ns corev1.Namespace
	if err := r.APIReader.Get(ctx, client.ObjectKey{Name: name}, &ns); err != nil {
		return false, err
	}
	return ns.Labels[crossNamespaceIngressLabel] == crossNamespaceIngressValue, nil
}

// serviceHasClusterIP reports whether svc exposes a routable ClusterIP the link
// can DNAT to. ExternalName Services have no ClusterIP (DNAT to an external CNAME
// is invalid and SSRF-prone), and headless Services (clusterIP None or empty) have
// no stable VIP (a DNAT would pin to a single pod). ClusterIP and NodePort both
// carry a real ClusterIP and are accepted.
func serviceHasClusterIP(svc *corev1.Service) bool {
	if svc.Spec.Type == corev1.ServiceTypeExternalName {
		return false
	}
	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == corev1.ClusterIPNone {
		return false
	}
	return true
}

// reconcileDelete deletes the XGatewayGCP and waits for it to disappear before
// releasing the finalizer, so Crossplane finishes draining GCP while the
// namespace is still alive. Owner-ref GC reaps the remaining children. While the
// drain is in flight it marks the Gateway Ready=False/Terminating so a stuck GCP
// teardown is visible in kubectl, and requeues on the fixed transient floor rather
// than RequeueInterval (zero in tests) so it never hot-loops.
//
// Once the per-gateway composite is gone it refcounts the shared XGatewayNetwork:
// if this is the last Gateway, it deletes the shared network and holds the
// finalizer until the network is confirmed NotFound. Removing the last finalizer
// only after that confirmation is the anti-orphan guarantee. Concurrent
// last-deletes are safe because Delete is NotFound-tolerant, and a Gateway created
// while the last delete is in flight re-ensures the network on its own reconcile.
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

// releaseAfterSharedNetwork runs once a deleting Gateway's per-gateway composite
// is gone. The shared VPC is one per cluster, so the refcount counts Gateways
// cluster-wide: it removes the finalizer immediately when any other Gateway
// remains anywhere in the cluster, and only when this is the last Gateway does it
// tear the shared XGatewayNetwork down and hold the finalizer until the network is
// confirmed NotFound, so the last Gateway never disappears while a shared VPC it
// provisioned is still draining.
//
// The network read goes through the uncached APIReader because the shared network
// carries no owner ref and is not watched, so the cache never tracks it and a
// cached read could miss its deletion timestamp. The Gateway count uses the same
// reader so the cluster-wide refcount is read consistently with the network. The
// deleting Gateway carries a non-zero DeletionTimestamp, so the zero-timestamp
// filter excludes it from the count without special-casing its name.
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

// releaseFinalizer removes the teardown finalizer and persists the Gateway,
// letting the API server complete its deletion.
func (r *GatewayReconciler) releaseFinalizer(ctx context.Context, gw *wgnetv1alpha1.Gateway) (ctrl.Result, error) {
	controllerutil.RemoveFinalizer(gw, gatewayFinalizer)
	if err := r.Update(ctx, gw); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove finalizer: %w", err)
	}
	return ctrl.Result{}, nil
}

// ensureSecrets generates the WireGuard key material once and persists it as the
// owner-ref'd bundle and link Secrets. Existing Secrets are left untouched: the
// keys are never rotated, and the owner-ref ensures GC reaps them on delete since
// the operator's secrets RBAC withholds the delete verb.
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

// ensureXGatewayGCP server-side-applies the composite. Apply touches only the
// operator-owned fields (spec, labels, owner ref), so Crossplane's status and
// any field it defaults are left intact and the two controllers stop fighting.
// ForceOwnership lets the apply manager take sole ownership of those spec fields
// without erroring on a pre-existing field manager.
//
// forwards is the validated subset whose ports the composite opens on the GCP
// firewall.
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

// ensureXGatewayNetwork server-side-applies the singleton shared-VPC composite so
// the network exists before any per-gateway firewall or instance references it by
// name. It is idempotent: re-applying the unchanged object is a no-op. The
// composite carries no controller/owner reference because it is shared across
// every Gateway and refcount-managed by reconcileDelete, not garbage-collected
// with any single Gateway. Every provisioning reconcile calls it, so a network
// torn down by a racing last-delete is re-created on the next reconcile.
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

// ensureLink server-side-applies the link ConfigMap, NetworkPolicy, and
// Deployment, all owner-ref'd to the Gateway. These resources have a stable,
// fully operator-specified shape, so applying the built object is idempotent and
// never fights the built-in Deployment controller over server-defaulted fields.
//
// address is the gateway IP observed from the XGatewayGCP status; it is rendered as
// the WireGuard peer endpoint into the ConfigMap so the link reloads in place
// when it first appears or changes. An empty address leaves the endpoint unset
// and the link waits.
//
// forwards is the validated subset rendered into the link ConfigMap (the runtime
// forwards the link serves) and the NetworkPolicy (the backend egress rules). The
// link Deployment is forward-independent, so it carries no forward argument.
func (r *GatewayReconciler) ensureLink(ctx context.Context, gw *wgnetv1alpha1.Gateway, address string, forwards []wgnetv1alpha1.Forward) error {
	cm, err := buildLinkConfigMap(gw, address, forwards)
	if err != nil {
		return err
	}
	if err := r.apply(ctx, gw, cm); err != nil {
		return err
	}
	if err := r.apply(ctx, gw, buildLinkNetworkPolicy(gw, forwards)); err != nil {
		return err
	}
	return r.apply(ctx, gw, buildLinkDeployment(gw, r.Config))
}

// ensureDNSEndpoint server-side-applies the DNSEndpoint when hostnames are set
// and the address is known. It is owner-ref'd for GC but deliberately not watched
// (Owns) so the manager start does not depend on the external-dns CRD.
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

// xgatewayGCPExists reports whether the Gateway's composite is already present,
// which is the signal that the Gateway has provisioned at least once. The gate
// uses it to decide whether an all-invalid forward set should hold provisioning
// (never provisioned) or re-apply the children with an empty forward set (already
// provisioned, keep the VM). A NotFound is reported as false; any other error is
// surfaced so the reconcile fails rather than misreading a transient API error as
// not-provisioned and tearing nothing down.
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

// readXGatewayGCPStatus reads the composite's observed address and serviceAccountEmail.
// A missing composite yields empty values rather than an error: it means the
// apply has not yet propagated.
func (r *GatewayReconciler) readXGatewayGCPStatus(ctx context.Context, gw *wgnetv1alpha1.Gateway) (address, saEmail string, err error) {
	xg := newXGatewayGCP()
	if err := r.Get(ctx, client.ObjectKey{Namespace: gw.Namespace, Name: gw.Name}, xg); err != nil {
		if apierrors.IsNotFound(err) {
			return "", "", nil
		}
		return "", "", fmt.Errorf("get xgatewaygcp: %w", err)
	}
	address, _, err = unstructured.NestedString(xg.Object, "status", "address")
	if err != nil {
		return "", "", fmt.Errorf("read status.address: %w", err)
	}
	saEmail, _, err = unstructured.NestedString(xg.Object, "status", "serviceAccountEmail")
	if err != nil {
		return "", "", fmt.Errorf("read status.serviceAccountEmail: %w", err)
	}
	return address, saEmail, nil
}

// linkAvailable reports whether the link Deployment this Gateway owns has reached
// its DeploymentAvailable condition. The link's readiness probe only passes once
// a fresh WireGuard handshake exists, so an Available link means the tunnel is up
// and the data path is usable. A missing or not-yet-Available Deployment yields
// false with no error: it means the link has not converged yet.
func (r *GatewayReconciler) linkAvailable(ctx context.Context, gw *wgnetv1alpha1.Gateway) (bool, error) {
	var dep appsv1.Deployment
	key := client.ObjectKey{Namespace: gw.Namespace, Name: linkComponentName(gw)}
	if err := r.Get(ctx, key, &dep); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("get link deployment %s: %w", key, err)
	}
	for _, cond := range dep.Status.Conditions {
		if cond.Type == appsv1.DeploymentAvailable {
			return cond.Status == corev1.ConditionTrue, nil
		}
	}
	return false, nil
}

// mirrorStatusWithForwards copies the composite's observed fields onto the Gateway
// status and sets the Ready condition. When any forward is invalid the condition
// is Ready=False with the first invalid forward's reason (spec order is preserved,
// so a single-forward Gateway reports exactly that forward's reason) and a message
// enumerating every invalid forward, so the condition reflects the user-actionable
// failure rather than the generic provisioning state. Otherwise it sets Ready from
// ready, which the caller computes from the composite address and the link
// Deployment's availability. It skips the status write when nothing changed, so a
// status-only requeue does not self-trigger the For(&Gateway{}) watch into a write
// loop.
func (r *GatewayReconciler) mirrorStatusWithForwards(ctx context.Context, gw *wgnetv1alpha1.Gateway, address, saEmail string, ready bool, invalid []invalidForward) error {
	cond := metav1.Condition{Type: conditionReady}
	switch {
	case len(invalid) > 0:
		cond.Status = metav1.ConditionFalse
		cond.Reason = invalid[0].reason
		cond.Message = invalidForwardsMessage(invalid)
	case ready:
		cond.Status = metav1.ConditionTrue
		cond.Reason = reasonReady
		cond.Message = "gateway address provisioned and link tunnel up"
	default:
		cond.Status = metav1.ConditionFalse
		cond.Reason = reasonProvisioning
		cond.Message = "waiting for gateway address and link tunnel"
	}

	// Earlier SSA applies in the reconcile (the XGatewayGCP owner-ref/labels
	// round-trip) bump the in-memory Gateway's resourceVersion against the API
	// server's, so a direct Status().Update here would lose the optimistic-
	// concurrency race and log a spurious conflict every reconcile. Re-Get a fresh
	// Gateway inside RetryOnConflict and apply the computed status to that copy so
	// the write carries an up-to-date resourceVersion. The computed values are
	// identical regardless of which copy they land on.
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var fresh wgnetv1alpha1.Gateway
		if err := r.Get(ctx, client.ObjectKeyFromObject(gw), &fresh); err != nil {
			return fmt.Errorf("get gateway for status update: %w", err)
		}

		// Stamp observedGeneration from the freshly-Got object: the passed-in gw may
		// be stale relative to a spec edit that landed mid-reconcile, and the
		// condition must report the generation the status actually reflects.
		cond.ObservedGeneration = fresh.Generation

		prevAddress := fresh.Status.Address
		prevSAEmail := fresh.Status.ServiceAccountEmail
		fresh.Status.Address = address
		fresh.Status.ServiceAccountEmail = saEmail
		conditionChanged := meta.SetStatusCondition(&fresh.Status.Conditions, cond)

		if prevAddress == address && prevSAEmail == saEmail && !conditionChanged {
			return nil
		}

		if err := r.Status().Update(ctx, &fresh); err != nil {
			return fmt.Errorf("update gateway status: %w", err)
		}
		return nil
	})
}

// invalidForwardsMessage renders a concise one-line enumeration of the invalid
// forwards for the Ready condition message, joining each forward's per-check
// message so an operator sees which forwards are rejected and why straight from
// kubectl, without reading the controller logs.
func invalidForwardsMessage(invalid []invalidForward) string {
	parts := make([]string, 0, len(invalid))
	for _, inv := range invalid {
		parts = append(parts, inv.message)
	}
	return fmt.Sprintf("%d forward(s) invalid: %s", len(invalid), strings.Join(parts, "; "))
}

// fail records the error on the Gateway's Ready condition and surfaces it so the
// manager requeues with backoff. The status write is conflict-safe for the same
// reason as mirrorStatusWithForwards: fail runs after SSA applies that bump the
// in-memory Gateway's resourceVersion, so a direct Status().Update on the passed-in
// copy would lose the optimistic-concurrency race. It re-Gets a fresh copy inside
// RetryOnConflict and stamps observedGeneration from it.
func (r *GatewayReconciler) fail(ctx context.Context, gw *wgnetv1alpha1.Gateway, op string, cause error) (ctrl.Result, error) {
	wrapped := fmt.Errorf("%s: %w", op, cause)
	if r.Recorder != nil {
		r.Recorder.Eventf(gw, nil, corev1.EventTypeWarning, reasonReconcileFailed, actionReconcile, "%s", wrapped.Error())
	}
	uerr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var fresh wgnetv1alpha1.Gateway
		if err := r.Get(ctx, client.ObjectKeyFromObject(gw), &fresh); err != nil {
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
	if uerr != nil {
		return ctrl.Result{}, fmt.Errorf("%w; additionally failed to update status: %w", wrapped, uerr)
	}
	return ctrl.Result{}, wrapped
}

// objectExists reports whether the named object is present. probe is mutated by
// the Get and otherwise unused; the caller passes a fresh empty object of the
// desired kind.
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

// apply server-side-applies desired with the operator field manager, stamping the
// Gateway owner reference first. Typed builders omit TypeMeta, so the GVK is
// populated from the scheme: SSA needs apiVersion+kind on the wire to target the
// right resource. ForceOwnership lets the apply manager take sole ownership of the
// fields it sets without erroring on a pre-existing field manager.
func (r *GatewayReconciler) apply(ctx context.Context, gw *wgnetv1alpha1.Gateway, desired client.Object) error {
	gvks, _, err := r.Scheme.ObjectKinds(desired)
	if err != nil {
		return fmt.Errorf("gvk for %T: %w", desired, err)
	}
	desired.GetObjectKind().SetGroupVersionKind(gvks[0])
	if err := controllerutil.SetControllerReference(gw, desired, r.Scheme); err != nil {
		return fmt.Errorf("set owner reference: %w", err)
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

// SetupWithManager registers the reconciler, watching the Gateway and owning the
// children GC reaps by owner-ref plus the unstructured XGatewayGCP. The DNSEndpoint
// is intentionally not owned: an Owns watch would make manager start require the
// external-dns CRD.
//
// The XGatewayGCP and link Deployment watches deliberately omit
// GenerationChangedPredicate so their status-only updates trigger a reconcile:
// readiness gates on the XGatewayGCP's status.address and the Deployment's
// DeploymentAvailable condition, and the predicate would filter exactly those
// status writes, leaving readiness to flip only on the RequeueAfter fallback.
// This does not reintroduce a write loop: child applies are server-side and
// idempotent (re-applying an unchanged object is a no-op that bumps no
// resourceVersion) and mirrorStatusWithForwards writes only on change. The
// remaining child watches keep the predicate because nothing reads their status.
//
// The Service and Namespace watches drive forward classification: a forward's
// backend Service appearing, disappearing, or changing its published ports, and a
// target namespace's consent label being added or removed, all change which
// forwards are valid. Mapping each such event back to the affected Gateways makes
// the operator converge promptly. These are external objects the operator does not
// own, so they are watched with explicit map functions rather than Owns. The
// operator watches all namespaces, so these watches observe a forward's backend
// Service or target namespace wherever it lives. Convergence does not depend on the
// watch alone: a Gateway with an invalid forward is also requeued on the fixed
// transient floor (anyTransientReason), so it reconverges even if a watch event is
// coalesced or missed.
func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.APIReader = mgr.GetAPIReader()

	xg := &unstructured.Unstructured{}
	xg.SetGroupVersionKind(XGatewayGCPGVK)

	genChanged := builder.WithPredicates(predicate.GenerationChangedPredicate{})

	return ctrl.NewControllerManagedBy(mgr).
		For(&wgnetv1alpha1.Gateway{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.ConfigMap{}, genChanged).
		Owns(&corev1.Secret{}, genChanged).
		Owns(&networkingv1.NetworkPolicy{}, genChanged).
		Owns(xg).
		Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(r.gatewaysForService)).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.gatewaysForNamespace)).
		Complete(r)
}

// gatewaysForService maps a changed Service to the Gateways that forward to it, so
// a backend Service appearing, disappearing, or changing its published ports
// re-runs classification for exactly those Gateways. It matches a forward by its
// effective (namespace, name): a same-namespace forward resolves to the Gateway's
// namespace, a cross-namespace forward to its explicit namespace. The list is the
// cluster-wide cached read, so a Service in any namespace maps to its Gateways
// wherever they live.
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

// gatewaysForNamespace maps a changed Namespace to the Gateways that have a
// cross-namespace forward into it, so adding or removing the consent label re-runs
// classification for exactly those Gateways. Only cross-namespace forwards are
// considered: a forward whose effective namespace is the Gateway's own namespace is
// governed by no consent label, so the Gateway's own namespace changing is
// irrelevant to classification.
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
