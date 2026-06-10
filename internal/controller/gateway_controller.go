package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
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

// gatewayFinalizer blocks Gateway deletion until the XGatewayGCP is deleted and
// Crossplane has drained the cloud resources, so the drain completes before the
// namespace and CRD go away. The other children are reaped by owner-ref GC.
const gatewayFinalizer = "wgnet.dev/gateway-teardown"

// fieldOwner is the server-side-apply field manager for every object the reconciler
// applies. A stable name lets the API server track which fields the operator owns, so
// it never fights Crossplane or the Deployment controller over defaulted fields.
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

	// Forward-validation Ready=False reasons. Each reflects mutable external state a
	// backend change can clear without a spec edit, so all are transient (see
	// anyTransientReason).
	reasonCrossNamespaceForwardDenied = "CrossNamespaceForwardDenied"
	reasonTargetNamespaceNotFound     = "TargetNamespaceNotFound"
	reasonUnsupportedServiceType      = "UnsupportedServiceType"
	reasonServiceNotFound             = "ServiceNotFound"
	reasonTargetPortNotListening      = "TargetPortNotListening"
)

// crossNamespaceIngressLabel is the opt-in consent label a target namespace must carry
// before a Gateway elsewhere may forward public traffic into it, so a Gateway owner
// cannot expose an arbitrary namespace's Service to the internet.
const (
	crossNamespaceIngressLabel = "wgnet.dev/allow-gateway-ingress"
	crossNamespaceIngressValue = "true"
)

// validationRequeueAfter is the fixed transient backoff before re-checking a forward
// whose backend is not yet present, decoupled from the steady-state RequeueInterval
// (which may be zero in tests) so a missing Service never spins a hot requeue loop.
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

	// APIReader reads directly from the API server, bypassing the manager cache, for
	// the unwatched, owner-ref-less objects the cache never tracks (the shared
	// XGatewayNetwork, link Leases, and holder pods). SetupWithManager binds it.
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
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=policy,resources=poddisruptionbudgets,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=externaldns.k8s.io,resources=dnsendpoints,verbs=create;get;patch;update
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=create;get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile drives a Gateway toward its desired state: it exposes exactly the valid
// forward subset and never provisions while all forwards are invalid, but once
// provisioned keeps its VM rather than tearing down on a transient backend outage.
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

	// No valid forward and never provisioned: hold off, but requeue on the transient
	// floor when an invalid forward can clear on its own, so the Gateway converges
	// without a spec edit once a backend catches up.
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

	linkActive, err := r.linkActive(ctx, &gw)
	if err != nil {
		return r.fail(ctx, &gw, "read link activity", err)
	}

	ready := address != "" && linkActive && len(invalid) == 0
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
		"address", address, "linkActive", linkActive, "ready", ready,
		"valid", len(valid), "invalid", len(invalid))
	return result, nil
}

// invalidForward is a forward classifyForwards rejected, paired with the
// Ready=False reason and a human-readable message naming the specific failure.
type invalidForward struct {
	reason  string
	message string
}

// classifyForwards partitions a Gateway's forwards into the valid subset it may DNAT
// to and the invalid ones, preserving spec order. A non-NotFound API error fails the
// whole reconcile rather than misclassifying; reads use the uncached APIReader.
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
// proto, comparing against the published spec.ports[].port (not the pods'
// containerPort). An empty Service-port protocol defaults to TCP per the API.
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

// anyTransientReason reports whether any invalid forward carries a reason a backend
// change can clear without a spec edit, the signal to requeue on the fixed floor.
// Reasons are enumerated so a permanent (spec-only) reason is excluded by default.
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

// namespaceAllowsIngress reports whether the named namespace carries the consent
// label. A NotFound error is returned so the caller can distinguish a missing
// namespace from a present one lacking the label.
func (r *GatewayReconciler) namespaceAllowsIngress(ctx context.Context, name string) (bool, error) {
	var ns corev1.Namespace
	if err := r.APIReader.Get(ctx, client.ObjectKey{Name: name}, &ns); err != nil {
		return false, err
	}
	return ns.Labels[crossNamespaceIngressLabel] == crossNamespaceIngressValue, nil
}

// serviceHasClusterIP reports whether svc exposes a routable ClusterIP to DNAT to.
// ExternalName (SSRF-prone CNAME) and headless (no stable VIP) Services are rejected;
// ClusterIP and NodePort both carry a real ClusterIP and are accepted.
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
// releasing the finalizer, so Crossplane drains GCP while the namespace is still
// alive, then hands off to releaseAfterSharedNetwork for the shared-VPC refcount.
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

// releaseAfterSharedNetwork refcounts the one-per-cluster shared VPC, releasing the
// finalizer at once while any Gateway remains and only on the last delete tearing the
// XGatewayNetwork down and holding until it is NotFound. Reads use the uncached APIReader.
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
// owner-ref'd bundle and link Secrets. Existing Secrets are left untouched (keys are
// never rotated); owner-ref GC reaps them since the secrets RBAC withholds delete.
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

// ensureXGatewayGCP server-side-applies the composite, touching only operator-owned
// fields so Crossplane's status and defaulted fields stay intact. forwards is the
// validated subset whose ports the composite opens on the GCP firewall.
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

// ensureXGatewayNetwork server-side-applies the singleton shared-VPC composite so the
// network exists before any firewall or instance references it. It is unowned
// (refcount-managed) and re-created here if a racing last-delete tore it down.
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

// ensureLink server-side-applies the link's ServiceAccount, Role, RoleBinding,
// ConfigMap, NetworkPolicy, and Deployment, all owner-ref'd. The PDB is applied only
// at replicas>1 and deleted below that so a stale PDB cannot block drains.
func (r *GatewayReconciler) ensureLink(ctx context.Context, gw *wgnetv1alpha1.Gateway, address string, forwards []wgnetv1alpha1.Forward) error {
	if err := r.apply(ctx, gw, buildLinkServiceAccount(gw)); err != nil {
		return err
	}
	if err := r.apply(ctx, gw, buildLinkRole(gw)); err != nil {
		return err
	}
	if err := r.apply(ctx, gw, buildLinkRoleBinding(gw)); err != nil {
		return err
	}

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
	if err := r.apply(ctx, gw, buildLinkDeployment(gw, r.Config)); err != nil {
		return err
	}

	if effectiveLinkReplicas(gw) > 1 {
		return r.apply(ctx, gw, buildLinkPodDisruptionBudget(gw))
	}
	return r.deleteLinkPodDisruptionBudget(ctx, gw)
}

// deleteLinkPodDisruptionBudget removes the link PDB if present, tolerating a
// NotFound. It runs at a single replica so scaling a Gateway from many replicas
// down to one does not leave the prior PDB behind to block node drains.
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

// xgatewayGCPExists reports whether the composite is present, the signal that the
// Gateway provisioned at least once and so keeps its VM under an all-invalid forward
// set. A NotFound is false; any other error is surfaced rather than read as absent.
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

// linkActive reports whether the link tunnel is up, gating on the lease-holder pod's
// readiness rather than the Deployment's Available condition because idle standbys also
// report Ready. A NotFound or empty holder is "not active yet", not an error.
func (r *GatewayReconciler) linkActive(ctx context.Context, gw *wgnetv1alpha1.Gateway) (bool, error) {
	var lease coordinationv1.Lease
	leaseKey := client.ObjectKey{Namespace: gw.Namespace, Name: linkComponentName(gw)}
	if err := r.APIReader.Get(ctx, leaseKey, &lease); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("get link lease %s: %w", leaseKey, err)
	}
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity == "" {
		return false, nil
	}

	var holder corev1.Pod
	holderKey := client.ObjectKey{Namespace: gw.Namespace, Name: *lease.Spec.HolderIdentity}
	if err := r.APIReader.Get(ctx, holderKey, &holder); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("get link lease holder pod %s: %w", holderKey, err)
	}
	for _, cond := range holder.Status.Conditions {
		if cond.Type == corev1.PodReady {
			return cond.Status == corev1.ConditionTrue, nil
		}
	}
	return false, nil
}

// mirrorStatusWithForwards copies the composite's observed fields onto the Gateway
// status and sets the Ready condition, any invalid forward taking priority. It skips
// the write when nothing changed so a status-only requeue cannot self-trigger a loop.
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
		cond.Message = "gateway address provisioned and active link tunnel up"
	default:
		cond.Status = metav1.ConditionFalse
		cond.Reason = reasonProvisioning
		cond.Message = "waiting for gateway address and active link tunnel"
	}

	// Earlier SSA applies stale the in-memory resourceVersion, so a direct
	// Status().Update would lose the optimistic-concurrency race. Re-Get a fresh copy
	// inside RetryOnConflict so the write carries an up-to-date resourceVersion.
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var fresh wgnetv1alpha1.Gateway
		if err := r.Get(ctx, client.ObjectKeyFromObject(gw), &fresh); err != nil {
			return fmt.Errorf("get gateway for status update: %w", err)
		}

		// Stamp observedGeneration from the fresh object: the passed-in gw may be stale
		// relative to a spec edit that landed mid-reconcile.
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

// invalidForwardsMessage joins the per-forward messages into a one-line Ready
// condition message so an operator sees which forwards are rejected and why from
// kubectl alone, without reading the controller logs.
func invalidForwardsMessage(invalid []invalidForward) string {
	parts := make([]string, 0, len(invalid))
	for _, inv := range invalid {
		parts = append(parts, inv.message)
	}
	return fmt.Sprintf("%d forward(s) invalid: %s", len(invalid), strings.Join(parts, "; "))
}

// fail records the error on the Gateway's Ready condition and surfaces it so the
// manager requeues with backoff. The status write re-Gets a fresh copy inside
// RetryOnConflict for the same reason as mirrorStatusWithForwards.
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
// owner reference first. The GVK is populated from the scheme because typed builders
// omit TypeMeta and SSA needs apiVersion+kind on the wire.
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

// SetupWithManager registers the reconciler. The XGatewayGCP watch omits
// GenerationChangedPredicate so its status-only address writes trigger a reconcile;
// Service and Namespace watches drive forward classification.
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

// gatewaysForService maps a changed Service to the Gateways that forward to it,
// matching by effective (namespace, name) so same- and cross-namespace forwards both
// resolve. The list is cluster-wide.
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

// gatewaysForNamespace maps a changed Namespace to the Gateways with a cross-namespace
// forward into it, so a consent-label edit re-classifies them. A forward into the
// Gateway's own namespace is governed by no consent label and is skipped.
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
