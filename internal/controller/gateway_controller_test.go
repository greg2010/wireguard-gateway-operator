package controller

import (
	"context"
	"fmt"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	wgnetv1alpha1 "github.com/greg2010/wireguard-gateway-operator/api/v1alpha1"
	"github.com/greg2010/wireguard-gateway-operator/internal/wg"
)

// reconcileConfig is the operator config the controller tests reconcile with.
func reconcileConfig() Config {
	return Config{
		LinkImage:           "registry.example.com/gateway-link:test",
		LinkImagePullPolicy: "IfNotPresent",
		WGSubnet:            "10.99.0.0/29",
		WGLinkAddress:       "10.99.0.2",
		WGListenPort:        51820,
		WGKeepalive:         25,
		WGMTU:               1380,
		GCPSubnetCIDR:       "10.200.0.0/24",
		GCPReservedIP:       true,
		UserData:            "#ignition\n",
		// Zero requeue keeps the test from depending on wall-clock requeue timing;
		// the test re-invokes Reconcile explicitly.
		RequeueInterval: 0,
	}
}

// countingKeyGen returns a deterministic KeyGenerator and a pointer to its call
// count, so a test can assert key material is generated exactly once.
func countingKeyGen() (KeyGenerator, *int) {
	calls := 0
	gen := func() (string, string, error) {
		calls++
		return fmt.Sprintf("priv-%d", calls), fmt.Sprintf("pub-%d", calls), nil
	}
	return gen, &calls
}

// drainReconcile invokes Reconcile a few times so the finalizer-add pass and the
// subsequent ensure/mirror passes all run. Reconcile is idempotent, so the fixed
// iteration count is safe; the surrounding subtests assert the converged state.
func drainReconcile(ctx context.Context, t *testing.T, r *GatewayReconciler, key client.ObjectKey) {
	t.Helper()
	req := ctrl.Request{NamespacedName: key}
	for range 3 {
		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
	}
}

func sampleGateway(name, namespace string) *wgnetv1alpha1.Gateway {
	return newGateway(name, namespace,
		[]wgnetv1alpha1.Forward{
			{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
			{Port: 1194, Protocol: wgnetv1alpha1.ProtocolUDP, Service: "vpn"},
		},
		[]string{"edge.example.com"},
	)
}

// reconcileFixture starts envtest, creates the wg-system namespace and a sample
// Gateway, and returns a reconciler wired to the real API server. The reconciler
// applies its children with server-side apply, which the controller-runtime fake
// client cannot model (its structured-merge-diff converter rejects typed objects
// carrying a status subresource), so the reconcile tests run against a real
// control plane and skip when envtest assets are unavailable.
func reconcileFixture(ctx context.Context, t *testing.T) (*testEnv, *GatewayReconciler, *wgnetv1alpha1.Gateway, client.ObjectKey, *int) {
	t.Helper()
	te := setupEnvtest(t)

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "wg-system"}}
	if err := te.client.Create(ctx, ns); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create namespace: %v", err)
	}

	gw := sampleGateway("edge", "wg-system")
	if err := te.client.Create(ctx, gw); err != nil {
		t.Fatalf("create gateway: %v", err)
	}

	gen, calls := countingKeyGen()
	r := &GatewayReconciler{
		Client:      te.client,
		Scheme:      te.scheme,
		Config:      reconcileConfig(),
		GenerateKey: gen,
	}
	return te, r, gw, client.ObjectKeyFromObject(gw), calls
}

// TestReconcileLifecycle exercises the full Gateway lifecycle subtest by subtest
// against a real API server. The reconciler applies its children with server-side
// apply, which only a real control plane models, so this test skips when envtest
// assets are unavailable.
func TestReconcileLifecycle(t *testing.T) {
	ctx := context.Background()
	te, r, gw, key, calls := reconcileFixture(ctx, t)
	cl := te.client

	drainReconcile(ctx, t, r, key)

	t.Run("finalizer added", func(t *testing.T) {
		var got wgnetv1alpha1.Gateway
		mustGet(ctx, t, cl, key, &got)
		if !controllerutil.ContainsFinalizer(&got, gatewayFinalizer) {
			t.Errorf("finalizer %q not present: %v", gatewayFinalizer, got.Finalizers)
		}
	})

	t.Run("secrets created once and owner-ref'd", func(t *testing.T) {
		var bundle corev1.Secret
		mustGet(ctx, t, cl, client.ObjectKey{Namespace: "wg-system", Name: "edge-bundle"}, &bundle)
		if got := string(bundle.Data[wg.BundleKey]); got != "priv-1\npub-2\n" {
			t.Errorf("bundle = %q, want priv-1\\npub-2\\n", got)
		}
		assertOwnedByGateway(t, &bundle, gw)

		var linkSec corev1.Secret
		mustGet(ctx, t, cl, client.ObjectKey{Namespace: "wg-system", Name: "edge-link"}, &linkSec)
		if got := string(linkSec.Data[wg.LinkPrivateKey]); got != "priv-2" {
			t.Errorf("link private = %q, want priv-2", got)
		}
		if got := string(linkSec.Data[wg.LinkPeerPublicKey]); got != "pub-1" {
			t.Errorf("link peer public = %q, want pub-1", got)
		}
		assertOwnedByGateway(t, &linkSec, gw)

		// A second reconcile must not regenerate keys.
		drainReconcile(ctx, t, r, key)
		if *calls != 2 {
			t.Errorf("keygen calls = %d, want 2 (generate once)", *calls)
		}
	})

	t.Run("xgateway created and owner-ref'd", func(t *testing.T) {
		xg := newXGateway()
		mustGet(ctx, t, cl, key, xg)
		assertNestedString(t, xg, "us-central1", "spec", "region")
		assertNestedString(t, xg, bundleSecretName(gw), "spec", "wgKeySecretRef", "name")
		assertOwnedByGatewayUnstructured(t, xg, gw)
	})

	t.Run("link children created and owner-ref'd", func(t *testing.T) {
		var dep appsv1.Deployment
		mustGet(ctx, t, cl, client.ObjectKey{Namespace: "wg-system", Name: "edge-link"}, &dep)
		assertOwnedByGateway(t, &dep, gw)

		var cm corev1.ConfigMap
		mustGet(ctx, t, cl, client.ObjectKey{Namespace: "wg-system", Name: "edge-link"}, &cm)
		assertOwnedByGateway(t, &cm, gw)

		var sa corev1.ServiceAccount
		mustGet(ctx, t, cl, client.ObjectKey{Namespace: "wg-system", Name: "edge-link"}, &sa)
		assertOwnedByGateway(t, &sa, gw)

		var role rbacv1.Role
		mustGet(ctx, t, cl, client.ObjectKey{Namespace: "wg-system", Name: "edge-link"}, &role)
		assertOwnedByGateway(t, &role, gw)

		var rb rbacv1.RoleBinding
		mustGet(ctx, t, cl, client.ObjectKey{Namespace: "wg-system", Name: "edge-link"}, &rb)
		assertOwnedByGateway(t, &rb, gw)
	})

	t.Run("status mirrored after composite reports address", func(t *testing.T) {
		setXGatewayStatus(ctx, t, cl, key, "203.0.113.9", "sa@example.iam.gserviceaccount.com")
		setLinkDeploymentAvailable(ctx, t, cl, key)
		drainReconcile(ctx, t, r, key)

		var got wgnetv1alpha1.Gateway
		mustGet(ctx, t, cl, key, &got)
		if got.Status.Address != "203.0.113.9" {
			t.Errorf("status.address = %q, want 203.0.113.9", got.Status.Address)
		}
		if got.Status.ServiceAccountEmail != "sa@example.iam.gserviceaccount.com" {
			t.Errorf("status.serviceAccountEmail = %q, want sa@...", got.Status.ServiceAccountEmail)
		}
		if c := apimeta.FindStatusCondition(got.Status.Conditions, conditionReady); c == nil || c.Status != metav1.ConditionTrue {
			t.Errorf("Ready condition = %+v, want True", c)
		}
	})

	t.Run("dns endpoint created once address known", func(t *testing.T) {
		ep := &unstructured.Unstructured{}
		ep.SetGroupVersionKind(buildDNSEndpoint(gw, "x").GroupVersionKind())
		mustGet(ctx, t, cl, key, ep)
		endpoints, found, err := unstructured.NestedSlice(ep.Object, "spec", "endpoints")
		if err != nil || !found || len(endpoints) != 1 {
			t.Errorf("dns endpoints = %v (found=%v err=%v), want one", endpoints, found, err)
		}
		assertOwnedByGatewayUnstructured(t, ep, gw)
	})

	t.Run("delete removes xgateway and releases finalizer", func(t *testing.T) {
		var live wgnetv1alpha1.Gateway
		mustGet(ctx, t, cl, key, &live)
		if err := cl.Delete(ctx, &live); err != nil {
			t.Fatalf("delete gateway: %v", err)
		}

		eventually(ctx, t, "gateway finalizer release after drain", func() bool {
			if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
				t.Fatalf("reconcile delete: %v", err)
			}
			var after wgnetv1alpha1.Gateway
			return apierrors.IsNotFound(cl.Get(ctx, key, &after))
		})

		xg := newXGateway()
		if err := cl.Get(ctx, key, xg); !apierrors.IsNotFound(err) {
			t.Errorf("xgateway get after gateway purge = %v, want NotFound", err)
		}
	})
}

// TestReconcileIdempotent asserts that once a Gateway has converged, a further
// reconcile of the unchanged Gateway neither errors nor rewrites the Gateway
// (its resourceVersion is stable). This guards the SSA + idempotent-status fix
// against the prior hot-write loop, in both the provisioning and ready states.
func TestReconcileIdempotent(t *testing.T) {
	tests := []struct {
		name    string
		address string
		saEmail string
	}{
		{
			name: "provisioning, no composite address yet",
		},
		{
			name:    "ready, composite reports address",
			address: "203.0.113.9",
			saEmail: "sa@example.iam.gserviceaccount.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			te, r, _, key, _ := reconcileFixture(ctx, t)
			cl := te.client

			drainReconcile(ctx, t, r, key)
			if tc.address != "" {
				setXGatewayStatus(ctx, t, cl, key, tc.address, tc.saEmail)
				setLinkDeploymentAvailable(ctx, t, cl, key)
				drainReconcile(ctx, t, r, key)
			}

			var converged wgnetv1alpha1.Gateway
			mustGet(ctx, t, cl, key, &converged)
			if converged.Status.Address != tc.address {
				t.Fatalf("status.address = %q, want %q", converged.Status.Address, tc.address)
			}

			rvBefore := converged.ResourceVersion
			if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
				t.Fatalf("redundant reconcile: %v", err)
			}

			var after wgnetv1alpha1.Gateway
			mustGet(ctx, t, cl, key, &after)
			if after.ResourceVersion != rvBefore {
				t.Errorf("gateway resourceVersion changed on redundant reconcile: %s -> %s (status write loop)",
					rvBefore, after.ResourceVersion)
			}
			if after.Status.Address != tc.address {
				t.Errorf("status.address drifted to %q, want %q", after.Status.Address, tc.address)
			}
			wantReady := metav1.ConditionFalse
			if tc.address != "" {
				wantReady = metav1.ConditionTrue
			}
			if c := apimeta.FindStatusCondition(after.Status.Conditions, conditionReady); c == nil || c.Status != wantReady {
				t.Errorf("Ready condition = %+v, want %s", c, wantReady)
			}
		})
	}
}

// mustGet fetches obj at key, failing the test on error.
func mustGet(ctx context.Context, t *testing.T, cl client.Client, key client.ObjectKey, obj client.Object) {
	t.Helper()
	if err := cl.Get(ctx, key, obj); err != nil {
		t.Fatalf("get %s %s: %v", obj.GetObjectKind().GroupVersionKind().Kind, key, err)
	}
}

// setXGatewayStatus patches the composite's status subresource with an observed
// address and serviceAccountEmail, simulating Crossplane's status write.
func setXGatewayStatus(ctx context.Context, t *testing.T, cl client.Client, key client.ObjectKey, address, saEmail string) {
	t.Helper()
	xg := newXGateway()
	mustGet(ctx, t, cl, key, xg)
	if err := unstructured.SetNestedField(xg.Object, address, "status", "address"); err != nil {
		t.Fatalf("set status.address: %v", err)
	}
	if err := unstructured.SetNestedField(xg.Object, saEmail, "status", "serviceAccountEmail"); err != nil {
		t.Fatalf("set status.serviceAccountEmail: %v", err)
	}
	if err := cl.Status().Update(ctx, xg); err != nil {
		t.Fatalf("update xgateway status: %v", err)
	}
}

// setLinkDeploymentAvailable patches the link Deployment owned by the Gateway at
// gwKey with a DeploymentAvailable=True condition, simulating the built-in
// Deployment controller marking the link healthy once its readiness probe passes.
// Readiness gating requires this, since envtest runs no kubelet to make the
// Deployment Available on its own. The Deployment name is derived from the real
// builder so it cannot drift from what the reconciler creates.
func setLinkDeploymentAvailable(ctx context.Context, t *testing.T, cl client.Client, gwKey client.ObjectKey) {
	t.Helper()
	name := linkComponentName(&wgnetv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: gwKey.Name, Namespace: gwKey.Namespace},
	})
	var dep appsv1.Deployment
	mustGet(ctx, t, cl, client.ObjectKey{Namespace: gwKey.Namespace, Name: name}, &dep)
	dep.Status.Conditions = []appsv1.DeploymentCondition{{
		Type:   appsv1.DeploymentAvailable,
		Status: corev1.ConditionTrue,
		Reason: "MinimumReplicasAvailable",
	}}
	if err := cl.Status().Update(ctx, &dep); err != nil {
		t.Fatalf("update link deployment status: %v", err)
	}
}

// assertOwnedByGateway fails unless obj carries a controller owner reference to
// gw.
func assertOwnedByGateway(t *testing.T, obj metav1.Object, gw *wgnetv1alpha1.Gateway) {
	t.Helper()
	for _, ref := range obj.GetOwnerReferences() {
		if ref.Kind == "Gateway" && ref.Name == gw.Name && ref.Controller != nil && *ref.Controller {
			return
		}
	}
	t.Errorf("object %s/%s missing controller owner-ref to Gateway %s; refs=%v",
		obj.GetNamespace(), obj.GetName(), gw.Name, obj.GetOwnerReferences())
}

// assertOwnedByGatewayUnstructured is assertOwnedByGateway for unstructured
// children.
func assertOwnedByGatewayUnstructured(t *testing.T, u *unstructured.Unstructured, gw *wgnetv1alpha1.Gateway) {
	t.Helper()
	assertOwnedByGateway(t, u, gw)
}
