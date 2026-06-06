package controller

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	wgnetv1alpha1 "github.com/greg2010/wireguard-gateway-operator/api/v1alpha1"
	"github.com/greg2010/wireguard-gateway-operator/internal/wg"
)

// gatewayFinalizer blocks Gateway deletion until the operator has deleted the
// XGateway and Crossplane has drained the cloud resources. The link, Secrets,
// and DNSEndpoint are reaped by owner-ref GC, but the XGateway is deleted
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
)

// KeyGenerator produces a WireGuard keypair. It is injected so tests can supply
// deterministic key material; production binds it to wg.GenerateKeypair.
type KeyGenerator func() (privateKey, publicKey string, err error)

// GatewayReconciler reconciles a Gateway into its XGateway composite, WireGuard
// key Secrets, link Deployment and RBAC, and optional DNSEndpoint, then mirrors
// the composite's observed status back onto the Gateway.
type GatewayReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Config   Config
	Recorder record.EventRecorder

	// GenerateKey supplies WireGuard keypairs. Nil defaults to wg.GenerateKeypair.
	GenerateKey KeyGenerator
}

// +kubebuilder:rbac:groups=wgnet.dev,resources=gateways,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=wgnet.dev,resources=gateways/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=wgnet.dev,resources=gateways/finalizers,verbs=update
// +kubebuilder:rbac:groups=infra.wgnet.dev,resources=xgateways,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=infra.wgnet.dev,resources=xgateways/status,verbs=get
// +kubebuilder:rbac:groups="",resources=secrets,verbs=create;get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=configmaps;serviceaccounts,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;rolebindings,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=externaldns.k8s.io,resources=dnsendpoints,verbs=create;get;update
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=create;get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile drives a Gateway toward its desired state. On deletion it deletes the
// XGateway and requeues until the composite is gone before releasing the
// finalizer; otherwise it ensures the finalizer, the key Secrets (generated once),
// the XGateway, and the link children, then mirrors the composite status and
// requeues to keep polling.
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
		return ctrl.Result{Requeue: true}, nil
	}

	if err := r.ensureSecrets(ctx, &gw); err != nil {
		return r.fail(ctx, &gw, "ensure key secrets", err)
	}
	if err := r.ensureXGateway(ctx, &gw); err != nil {
		return r.fail(ctx, &gw, "ensure xgateway", err)
	}
	if err := r.ensureLink(ctx, &gw); err != nil {
		return r.fail(ctx, &gw, "ensure link", err)
	}

	address, saEmail, err := r.readXGatewayStatus(ctx, &gw)
	if err != nil {
		return r.fail(ctx, &gw, "read xgateway status", err)
	}

	if err := r.ensureDNSEndpoint(ctx, &gw, address); err != nil {
		return r.fail(ctx, &gw, "ensure dns endpoint", err)
	}

	linkAvailable, err := r.linkAvailable(ctx, &gw)
	if err != nil {
		return r.fail(ctx, &gw, "read link availability", err)
	}

	ready := address != "" && linkAvailable
	if err := r.mirrorStatus(ctx, &gw, address, saEmail, ready); err != nil {
		return ctrl.Result{}, fmt.Errorf("mirror status: %w", err)
	}

	logger.V(1).Info("reconciled gateway", "address", address, "linkAvailable", linkAvailable, "ready", ready)
	return ctrl.Result{RequeueAfter: r.Config.RequeueInterval}, nil
}

// reconcileDelete deletes the XGateway and waits for it to disappear before
// releasing the finalizer, so Crossplane finishes draining GCP while the
// namespace is still alive. Owner-ref GC reaps the remaining children.
func (r *GatewayReconciler) reconcileDelete(ctx context.Context, gw *wgnetv1alpha1.Gateway) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(gw, gatewayFinalizer) {
		return ctrl.Result{}, nil
	}

	xg := newXGateway()
	err := r.Get(ctx, client.ObjectKey{Namespace: gw.Namespace, Name: gw.Name}, xg)
	switch {
	case apierrors.IsNotFound(err):
		controllerutil.RemoveFinalizer(gw, gatewayFinalizer)
		if err := r.Update(ctx, gw); err != nil {
			return ctrl.Result{}, fmt.Errorf("remove finalizer: %w", err)
		}
		return ctrl.Result{}, nil
	case err != nil:
		return ctrl.Result{}, fmt.Errorf("get xgateway for deletion: %w", err)
	}

	if xg.GetDeletionTimestamp().IsZero() {
		if err := r.Delete(ctx, xg); err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("delete xgateway: %w", err)
		}
	}
	return ctrl.Result{RequeueAfter: r.Config.RequeueInterval}, nil
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

// ensureXGateway server-side-applies the composite. Apply touches only the
// operator-owned fields (spec, labels, owner ref), so Crossplane's status and
// any field it defaults are left intact and the two controllers stop fighting.
// ForceOwnership migrates the spec fields previously owned by the Update-based
// upsert into the operator's apply manager without a conflict.
func (r *GatewayReconciler) ensureXGateway(ctx context.Context, gw *wgnetv1alpha1.Gateway) error {
	desired, err := buildXGateway(gw, r.Config)
	if err != nil {
		return err
	}
	if err := controllerutil.SetControllerReference(gw, desired, r.Scheme); err != nil {
		return fmt.Errorf("set xgateway owner reference: %w", err)
	}
	if err := r.Patch(ctx, desired, client.Apply, fieldOwner, client.ForceOwnership); err != nil {
		return fmt.Errorf("apply xgateway: %w", err)
	}
	return nil
}

// ensureLink server-side-applies the link ConfigMap, ServiceAccount, Role,
// RoleBinding, NetworkPolicy, and Deployment, all owner-ref'd to the Gateway.
// These resources have a stable, fully operator-specified shape, so applying the
// built object is idempotent and never fights the built-in Deployment controller
// over server-defaulted fields.
func (r *GatewayReconciler) ensureLink(ctx context.Context, gw *wgnetv1alpha1.Gateway) error {
	cm, err := buildLinkConfigMap(gw, r.Config)
	if err != nil {
		return err
	}
	if err := r.apply(ctx, gw, cm); err != nil {
		return err
	}
	if err := r.apply(ctx, gw, buildLinkServiceAccount(gw)); err != nil {
		return err
	}
	if err := r.apply(ctx, gw, buildLinkRole(gw)); err != nil {
		return err
	}
	if err := r.apply(ctx, gw, buildLinkRoleBinding(gw)); err != nil {
		return err
	}
	if err := r.apply(ctx, gw, buildLinkNetworkPolicy(gw, r.Config)); err != nil {
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
	if err := r.Patch(ctx, desired, client.Apply, fieldOwner, client.ForceOwnership); err != nil {
		return fmt.Errorf("apply dns endpoint: %w", err)
	}
	return nil
}

// readXGatewayStatus reads the composite's observed address and serviceAccountEmail.
// A missing composite yields empty values rather than an error: it means the
// apply has not yet propagated.
func (r *GatewayReconciler) readXGatewayStatus(ctx context.Context, gw *wgnetv1alpha1.Gateway) (address, saEmail string, err error) {
	xg := newXGateway()
	if err := r.Get(ctx, client.ObjectKey{Namespace: gw.Namespace, Name: gw.Name}, xg); err != nil {
		if apierrors.IsNotFound(err) {
			return "", "", nil
		}
		return "", "", fmt.Errorf("get xgateway: %w", err)
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

// mirrorStatus copies the composite's observed fields onto the Gateway status and
// sets the Ready condition from ready, which the caller computes from the
// composite address and the link Deployment's availability. It skips the status
// write when nothing changed, so a status-only requeue does not self-trigger the
// For(&Gateway{}) watch into a write loop.
func (r *GatewayReconciler) mirrorStatus(ctx context.Context, gw *wgnetv1alpha1.Gateway, address, saEmail string, ready bool) error {
	prevAddress := gw.Status.Address
	prevSAEmail := gw.Status.ServiceAccountEmail

	cond := metav1.Condition{Type: conditionReady, ObservedGeneration: gw.Generation}
	if ready {
		cond.Status = metav1.ConditionTrue
		cond.Reason = reasonReady
		cond.Message = "gateway address provisioned and link tunnel up"
	} else {
		cond.Status = metav1.ConditionFalse
		cond.Reason = reasonProvisioning
		cond.Message = "waiting for gateway address and link tunnel"
	}

	gw.Status.Address = address
	gw.Status.ServiceAccountEmail = saEmail
	conditionChanged := meta.SetStatusCondition(&gw.Status.Conditions, cond)

	if prevAddress == address && prevSAEmail == saEmail && !conditionChanged {
		return nil
	}

	if err := r.Status().Update(ctx, gw); err != nil {
		return fmt.Errorf("update gateway status: %w", err)
	}
	return nil
}

// fail records the error on the Gateway's Ready condition and surfaces it so the
// manager requeues with backoff.
func (r *GatewayReconciler) fail(ctx context.Context, gw *wgnetv1alpha1.Gateway, op string, cause error) (ctrl.Result, error) {
	wrapped := fmt.Errorf("%s: %w", op, cause)
	if r.Recorder != nil {
		r.Recorder.Event(gw, corev1.EventTypeWarning, reasonReconcileFailed, wrapped.Error())
	}
	meta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{
		Type:               conditionReady,
		Status:             metav1.ConditionFalse,
		Reason:             reasonReconcileFailed,
		Message:            wrapped.Error(),
		ObservedGeneration: gw.Generation,
	})
	if uerr := r.Status().Update(ctx, gw); uerr != nil {
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
// right resource. ForceOwnership takes over fields a prior Update-based upsert
// owned without erroring on the ownership handover.
func (r *GatewayReconciler) apply(ctx context.Context, gw *wgnetv1alpha1.Gateway, desired client.Object) error {
	gvks, _, err := r.Scheme.ObjectKinds(desired)
	if err != nil {
		return fmt.Errorf("gvk for %T: %w", desired, err)
	}
	desired.GetObjectKind().SetGroupVersionKind(gvks[0])
	if err := controllerutil.SetControllerReference(gw, desired, r.Scheme); err != nil {
		return fmt.Errorf("set owner reference: %w", err)
	}
	if err := r.Patch(ctx, desired, client.Apply, fieldOwner, client.ForceOwnership); err != nil {
		return fmt.Errorf("apply %T: %w", desired, err)
	}
	return nil
}

// SetupWithManager registers the reconciler, watching the Gateway and owning the
// children GC reaps by owner-ref plus the unstructured XGateway. The DNSEndpoint
// is intentionally not owned: an Owns watch would make manager start require the
// external-dns CRD.
//
// The XGateway and link Deployment watches deliberately omit
// GenerationChangedPredicate so their status-only updates trigger a reconcile:
// readiness gates on the XGateway's status.address and the Deployment's
// DeploymentAvailable condition, and the predicate would filter exactly those
// status writes, leaving readiness to flip only on the RequeueAfter fallback.
// This does not reintroduce a write loop: child applies are server-side and
// idempotent (re-applying an unchanged object is a no-op that bumps no
// resourceVersion) and mirrorStatus writes only on change. The remaining child
// watches keep the predicate because nothing reads their status.
func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	xg := &unstructured.Unstructured{}
	xg.SetGroupVersionKind(XGatewayGVK)

	genChanged := builder.WithPredicates(predicate.GenerationChangedPredicate{})

	return ctrl.NewControllerManagedBy(mgr).
		For(&wgnetv1alpha1.Gateway{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.ConfigMap{}, genChanged).
		Owns(&corev1.Secret{}, genChanged).
		Owns(&corev1.ServiceAccount{}, genChanged).
		Owns(&rbacv1.Role{}, genChanged).
		Owns(&rbacv1.RoleBinding{}, genChanged).
		Owns(&networkingv1.NetworkPolicy{}, genChanged).
		Owns(xg).
		Complete(r)
}
