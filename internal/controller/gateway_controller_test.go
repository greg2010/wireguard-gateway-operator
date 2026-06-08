package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/greg2010/wireguard-gateway-operator/internal/link"
	"github.com/greg2010/wireguard-gateway-operator/internal/wg"
	wgnetv1alpha1 "github.com/greg2010/wireguard-gateway-operator/pkg/api/v1alpha1"
)

// reconcileConfig is the operator config the controller tests reconcile with.
// PodNamespace is "default" because every envtest control plane provisions it, so the
// singleton shared network applies cleanly in every test.
func reconcileConfig() Config {
	return Config{
		LinkImage:           "registry.example.com/gateway-link:test",
		LinkImagePullPolicy: "IfNotPresent",
		UserData:            "#ignition\n",
		SharedNetworkName:   "wgnet-test",
		PodNamespace:        "default",
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
// Gateway, and returns a reconciler wired to the real API server. SSA, which the fake
// client cannot model, is why these tests need a real control plane.
func reconcileFixture(ctx context.Context, t *testing.T) (*testEnv, *GatewayReconciler, *wgnetv1alpha1.Gateway, client.ObjectKey, *int) {
	t.Helper()
	te := setupEnvtest(t)

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "wg-system"}}
	if err := te.client.Create(ctx, ns); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create namespace: %v", err)
	}

	// sampleGateway's forwards target these Services; classification requires each
	// backend to exist with a ClusterIP publishing the forward's port before
	// provisioning, so the lifecycle path must create them with matching ports.
	for _, svc := range []*corev1.Service{
		portedClusterIPService("wg-system", "web", 443, corev1.ProtocolTCP),
		portedClusterIPService("wg-system", "vpn", 1194, corev1.ProtocolUDP),
	} {
		if err := te.client.Create(ctx, svc); err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatalf("create service %s: %v", svc.Name, err)
		}
	}

	gw := sampleGateway("edge", "wg-system")
	if err := te.client.Create(ctx, gw); err != nil {
		t.Fatalf("create gateway: %v", err)
	}

	gen, calls := countingKeyGen()
	r := &GatewayReconciler{
		Client:      te.client,
		APIReader:   te.client,
		Scheme:      te.scheme,
		Config:      reconcileConfig(),
		GenerateKey: gen,
	}
	return te, r, gw, client.ObjectKeyFromObject(gw), calls
}

// TestReconcileLifecycle exercises the full Gateway lifecycle subtest by subtest
// against a real API server, required because the reconciler applies its children with
// server-side apply.
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

	t.Run("xgatewaygcp created and owner-ref'd", func(t *testing.T) {
		xg := newXGatewayGCP()
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

		var np networkingv1.NetworkPolicy
		mustGet(ctx, t, cl, client.ObjectKey{Namespace: "wg-system", Name: "edge-link"}, &np)
		assertOwnedByGateway(t, &np, gw)

		// The link runs leader election, so the operator creates its dedicated
		// ServiceAccount, Role, and RoleBinding, each owner-ref'd to the Gateway.
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

	t.Run("status mirrored and endpoint rendered after composite reports address", func(t *testing.T) {
		setXGatewayGCPStatus(ctx, t, cl, key, "203.0.113.9", "sa@example.iam.gserviceaccount.com")
		setLinkLeaseActive(ctx, t, cl, key, "edge-link-0", true)
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

		// Once the composite reports an address, the reconciler renders it as the
		// link's WireGuard peer endpoint so the link reloads in place.
		var cm corev1.ConfigMap
		mustGet(ctx, t, cl, client.ObjectKey{Namespace: "wg-system", Name: "edge-link"}, &cm)
		var rc link.RuntimeConfig
		decodeJSON(t, cm.Data[linkConfigKey], &rc)
		if want := "203.0.113.9:51820"; rc.WireGuard.Peer.Endpoint != want {
			t.Errorf("link configmap peer.endpoint = %q, want %q", rc.WireGuard.Peer.Endpoint, want)
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

	t.Run("delete removes xgatewaygcp and releases finalizer", func(t *testing.T) {
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

		xg := newXGatewayGCP()
		if err := cl.Get(ctx, key, xg); !apierrors.IsNotFound(err) {
			t.Errorf("xgatewaygcp get after gateway purge = %v, want NotFound", err)
		}

		// edge is the only Gateway, so its teardown is the last delete: the refcount
		// path must have deleted the shared network too.
		if err := cl.Get(ctx, sharedNetworkKey(r), newXGatewayNetwork()); !apierrors.IsNotFound(err) {
			t.Errorf("shared network get after last gateway purge = %v, want NotFound", err)
		}
	})
}

// TestReconcileLinkPodDisruptionBudget asserts the PDB tracks the link replica count:
// absent at one replica, present at replicas>1, and removed again when scaling back to
// one so a stale PDB cannot strand a node drain.
func TestReconcileLinkPodDisruptionBudget(t *testing.T) {
	ctx := context.Background()
	te, r, gw, key, _ := reconcileFixture(ctx, t)
	cl := te.client
	pdbKey := client.ObjectKey{Namespace: key.Namespace, Name: linkComponentName(gw)}

	// Default single replica: the link provisions but carries no PDB.
	drainReconcile(ctx, t, r, key)
	if err := cl.Get(ctx, pdbKey, &policyv1.PodDisruptionBudget{}); !apierrors.IsNotFound(err) {
		t.Fatalf("pdb get at one replica = %v, want NotFound", err)
	}

	// Scaling to >1 must create the PDB, owner-ref'd for GC.
	setLinkReplicas(ctx, t, cl, key, 3)
	drainReconcile(ctx, t, r, key)
	var pdb policyv1.PodDisruptionBudget
	mustGet(ctx, t, cl, pdbKey, &pdb)
	assertOwnedByGateway(t, &pdb, gw)
	if pdb.Spec.MinAvailable == nil || pdb.Spec.MinAvailable.IntVal != 1 {
		t.Errorf("pdb minAvailable = %+v, want 1", pdb.Spec.MinAvailable)
	}

	// Scaling back to one must delete the PDB so it cannot block a drain.
	setLinkReplicas(ctx, t, cl, key, 1)
	drainReconcile(ctx, t, r, key)
	if err := cl.Get(ctx, pdbKey, &policyv1.PodDisruptionBudget{}); !apierrors.IsNotFound(err) {
		t.Errorf("pdb get after scaling 3->1 = %v, want NotFound (deleted)", err)
	}
}

// setLinkReplicas sets spec.link.replicas on the live Gateway at key via a
// read-modify-write, so the reconciler reads the updated count.
func setLinkReplicas(ctx context.Context, t *testing.T, cl client.Client, key client.ObjectKey, replicas int32) {
	t.Helper()
	var gw wgnetv1alpha1.Gateway
	mustGet(ctx, t, cl, key, &gw)
	gw.Spec.Link.Replicas = replicas
	if err := cl.Update(ctx, &gw); err != nil {
		t.Fatalf("set link replicas to %d: %v", replicas, err)
	}
}

// TestReconcileIdempotent asserts that once a Gateway has converged, a further
// reconcile neither errors nor rewrites it (resourceVersion stays stable), guarding
// against a status-write loop in both the provisioning and ready states.
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
				setXGatewayGCPStatus(ctx, t, cl, key, tc.address, tc.saEmail)
				setLinkLeaseActive(ctx, t, cl, key, key.Name+"-link-0", true)
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

// sharedNetworkKey is the object key of the singleton shared network the
// reconciler r ensures, derived from its config so it cannot drift from what the
// reconciler applies.
func sharedNetworkKey(r *GatewayReconciler) client.ObjectKey {
	return client.ObjectKey{Name: r.Config.SharedNetworkName, Namespace: r.Config.PodNamespace}
}

// reconcileUntilGone drives Reconcile until the Gateway at key is purged. The refcount
// teardown spans several reconciles, so polling until the finalizer releases is
// deterministic where a fixed iteration count would be brittle.
func reconcileUntilGone(ctx context.Context, t *testing.T, r *GatewayReconciler, cl client.Client, key client.ObjectKey) {
	t.Helper()
	eventually(ctx, t, "gateway "+key.String()+" purged after delete", func() bool {
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
			t.Fatalf("reconcile delete %s: %v", key, err)
		}
		return apierrors.IsNotFound(cl.Get(ctx, key, &wgnetv1alpha1.Gateway{}))
	})
}

// TestReconcileSharedNetworkRefcount asserts the shared network is refcounted across
// Gateways: with two sharing one network, deleting the first leaves it in place while
// deleting the second (the last) tears it down.
func TestReconcileSharedNetworkRefcount(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	cl := te.client

	const ns = "wg-system"
	mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))
	mustCreate(ctx, t, cl, portedClusterIPService(ns, "web", 443, corev1.ProtocolTCP))
	mustCreate(ctx, t, cl, portedClusterIPService(ns, "vpn", 1194, corev1.ProtocolUDP))

	gen, _ := countingKeyGen()
	r := &GatewayReconciler{Client: cl, APIReader: cl, Scheme: te.scheme, Config: reconcileConfig(), GenerateKey: gen}

	gw1 := sampleGateway("gw-one", ns)
	gw2 := sampleGateway("gw-two", ns)
	mustCreate(ctx, t, cl, gw1)
	mustCreate(ctx, t, cl, gw2)
	key1 := client.ObjectKeyFromObject(gw1)
	key2 := client.ObjectKeyFromObject(gw2)

	drainReconcile(ctx, t, r, key1)
	drainReconcile(ctx, t, r, key2)

	// Both Gateways converged, so the singleton shared network exists exactly once.
	if err := cl.Get(ctx, sharedNetworkKey(r), newXGatewayNetwork()); err != nil {
		t.Fatalf("shared network get after both gateways provisioned = %v, want present", err)
	}

	// Deleting the first of two Gateways is not the last delete: the network must
	// survive and gw-one must be fully purged.
	mustDeleteGateway(ctx, t, cl, key1)
	reconcileUntilGone(ctx, t, r, cl, key1)
	if err := cl.Get(ctx, sharedNetworkKey(r), newXGatewayNetwork()); err != nil {
		t.Errorf("shared network get after first of two gateways deleted = %v, want still present", err)
	}

	// Deleting the second Gateway is the last delete: the refcount path must tear
	// the shared network down and only then release gw-two's finalizer.
	mustDeleteGateway(ctx, t, cl, key2)
	reconcileUntilGone(ctx, t, r, cl, key2)
	if err := cl.Get(ctx, sharedNetworkKey(r), newXGatewayNetwork()); !apierrors.IsNotFound(err) {
		t.Errorf("shared network get after last gateway deleted = %v, want NotFound", err)
	}
}

// mustDeleteGateway re-reads the live Gateway at key and deletes it, so the delete
// carries the server's current resourceVersion rather than a stale fixture copy.
func mustDeleteGateway(ctx context.Context, t *testing.T, cl client.Client, key client.ObjectKey) {
	t.Helper()
	var live wgnetv1alpha1.Gateway
	mustGet(ctx, t, cl, key, &live)
	if err := cl.Delete(ctx, &live); err != nil {
		t.Fatalf("delete gateway %s: %v", key, err)
	}
}

// newGatewayCELFixture builds a Gateway with the given forwards and an explicit
// spec.wireguard.listenPort for the CEL validation test. A zero wgPort is left unset so
// the CRD default applies.
func newGatewayCELFixture(name, namespace string, wgPort int32, forwards []wgnetv1alpha1.Forward) *wgnetv1alpha1.Gateway {
	gw := newGateway(name, namespace, forwards, nil)
	gw.Spec.Wireguard.ListenPort = wgPort
	return gw
}

// newGatewayNoWireguard builds a Gateway as unstructured with spec.wireguard entirely
// absent, so the CRD default and CEL rules run against a fully defaulted block. A typed
// fixture cannot express this: omitempty does not drop a non-pointer struct.
func newGatewayNoWireguard(name, namespace string, forwards []wgnetv1alpha1.Forward) *unstructured.Unstructured {
	rawForwards := make([]any, 0, len(forwards))
	for _, f := range forwards {
		rawForwards = append(rawForwards, map[string]any{
			"port":     int64(f.Port),
			"protocol": string(f.Protocol),
			"service":  f.Service,
		})
	}

	spec := map[string]any{
		"gcp": map[string]any{
			"projectID": "test-project",
			"region":    "us-central1",
			"zone":      "us-central1-a",
		},
	}
	if len(rawForwards) > 0 {
		spec["forwards"] = rawForwards
	}

	gw := &unstructured.Unstructured{Object: map[string]any{"spec": spec}}
	gw.SetGroupVersionKind(wgnetv1alpha1.GroupVersion.WithKind("Gateway"))
	gw.SetName(name)
	gw.SetNamespace(namespace)
	return gw
}

// TestGatewayCELValidation exercises the spec-level CEL rules at admission: the
// per-(port,protocol) uniqueness rule and the rule barring a UDP forward on the
// WireGuard listen port. Accepted Gateways create cleanly; rejected ones fail Invalid.
func TestGatewayCELValidation(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	cl := te.client

	tcp := wgnetv1alpha1.ProtocolTCP
	udp := wgnetv1alpha1.ProtocolUDP

	tests := []struct {
		name string
		// omitWireguard builds the Gateway with spec.wireguard absent so the rules
		// run against the CRD-defaulted block; otherwise wgPort sets the listen port
		// explicitly (zero leaves it unset for the default).
		omitWireguard bool
		wgPort        int32
		forwards      []wgnetv1alpha1.Forward
		accept        bool
	}{
		{
			name:   "duplicate port and protocol rejected",
			wgPort: 0,
			forwards: []wgnetv1alpha1.Forward{
				{Port: 443, Protocol: tcp, Service: "a"},
				{Port: 443, Protocol: tcp, Service: "b"},
			},
			accept: false,
		},
		{
			name:   "same port differing protocol accepted",
			wgPort: 0,
			forwards: []wgnetv1alpha1.Forward{
				{Port: 443, Protocol: tcp, Service: "a"},
				{Port: 443, Protocol: udp, Service: "b"},
			},
			accept: true,
		},
		{
			name:   "udp forward on defaulted wireguard port rejected",
			wgPort: 0,
			forwards: []wgnetv1alpha1.Forward{
				{Port: 51820, Protocol: udp, Service: "a"},
			},
			accept: false,
		},
		{
			name:          "udp forward on omitted wireguard port rejected",
			omitWireguard: true,
			forwards: []wgnetv1alpha1.Forward{
				{Port: 51820, Protocol: udp, Service: "a"},
			},
			accept: false,
		},
		{
			name:   "udp forward on explicit wireguard port rejected",
			wgPort: 51821,
			forwards: []wgnetv1alpha1.Forward{
				{Port: 51821, Protocol: udp, Service: "a"},
			},
			accept: false,
		},
		{
			name:   "udp forward on default port accepted when wireguard port moved",
			wgPort: 51821,
			forwards: []wgnetv1alpha1.Forward{
				{Port: 51820, Protocol: udp, Service: "a"},
			},
			accept: true,
		},
		{
			name:   "tcp forward on wireguard port accepted",
			wgPort: 51820,
			forwards: []wgnetv1alpha1.Forward{
				{Port: 51820, Protocol: tcp, Service: "a"},
			},
			accept: true,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := fmt.Sprintf("cel-%d", i)
			mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))

			var gw client.Object
			if tt.omitWireguard {
				gw = newGatewayNoWireguard(ns, ns, tt.forwards)
			} else {
				gw = newGatewayCELFixture(ns, ns, tt.wgPort, tt.forwards)
			}
			err := cl.Create(ctx, gw)

			if tt.accept {
				if err != nil {
					t.Fatalf("create accepted Gateway: %v", err)
				}
				if delErr := cl.Delete(ctx, gw); delErr != nil {
					t.Errorf("delete Gateway: %v", delErr)
				}
				return
			}

			if !apierrors.IsInvalid(err) {
				t.Fatalf("create rejected Gateway: err = %v, want Invalid", err)
			}
		})
	}
}

// TestGatewayWireguardDefaulting verifies spec.wireguard is optional: a Gateway that
// omits the block is admitted and read back with every sub-field carrying its CRD
// default.
func TestGatewayWireguardDefaulting(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	cl := te.client

	const ns = "wg-default"
	mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))

	gw := newGatewayNoWireguard(ns, ns, nil)
	if err := cl.Create(ctx, gw); err != nil {
		t.Fatalf("create Gateway with omitted spec.wireguard: %v", err)
	}

	var got wgnetv1alpha1.Gateway
	mustGet(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: ns}, &got)

	wantWG := wgnetv1alpha1.GatewayWireguardSpec{
		ListenPort:        51820,
		Subnet:            "10.99.0.0/29",
		GatewayAddress:    "10.99.0.1",
		LinkAddress:       "10.99.0.2",
		Keepalive:         25,
		MTU:               1380,
		ReconcileInterval: "10s",
	}
	if got.Spec.Wireguard != wantWG {
		t.Errorf("defaulted spec.wireguard = %+v, want %+v", got.Spec.Wireguard, wantWG)
	}
}

// portedClusterIPService builds a ClusterIP Service in ns publishing port/proto; the
// envtest API server assigns spec.clusterIP on create, so classification sees a
// routable VIP.
func portedClusterIPService(ns, name string, port int32, proto corev1.Protocol) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.ServiceSpec{
			Type:  corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{{Port: port, Protocol: proto}},
		},
	}
}

// portedNodePortService builds a NodePort Service publishing port/proto; like
// ClusterIP it carries a real ClusterIP, so classification must accept it when the
// published port matches the forward.
func portedNodePortService(ns, name string, port int32, proto corev1.Protocol) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.ServiceSpec{
			Type:  corev1.ServiceTypeNodePort,
			Ports: []corev1.ServicePort{{Port: port, Protocol: proto}},
		},
	}
}

// externalNameService builds an ExternalName Service, which has no ClusterIP and
// must be rejected by forward classification.
func externalNameService(ns, name string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.ServiceSpec{
			Type:         corev1.ServiceTypeExternalName,
			ExternalName: "example.com",
		},
	}
}

// headlessService builds a headless ClusterIP Service (clusterIP None), which has
// no stable VIP and must be rejected by forward classification.
func headlessService(ns, name string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.ServiceSpec{
			Type:      corev1.ServiceTypeClusterIP,
			ClusterIP: corev1.ClusterIPNone,
			Ports:     []corev1.ServicePort{{Port: 443, Protocol: corev1.ProtocolTCP}},
		},
	}
}

// TestClassifyForwards exercises the single-forward classification path: an accepted
// forward provisions, a denied one leaves Ready=False with the specific reason and
// provisions nothing, and transient reasons requeue rather than fail.
func TestClassifyForwards(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	cl := te.client

	type outcome struct {
		// accepted means classification passed and provisioning ran.
		accepted bool
		// wantReason is the expected Ready reason on a denial (ignored when accepted).
		wantReason string
		// wantRequeue is the expected RequeueAfter from the reconcile that ran
		// classification; zero means none asserted.
		wantRequeue time.Duration
	}

	tests := []struct {
		name string
		// setup creates the prerequisite namespaces/services for the case in the
		// given gateway namespace and returns the forward under test.
		setup func(t *testing.T, gwNS string) wgnetv1alpha1.Forward
		want  outcome
	}{
		{
			name: "same-namespace ClusterIP service accepted",
			setup: func(t *testing.T, gwNS string) wgnetv1alpha1.Forward {
				mustCreate(ctx, t, cl, portedClusterIPService(gwNS, "web", 443, corev1.ProtocolTCP))
				return wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}
			},
			want: outcome{accepted: true},
		},
		{
			name: "NodePort service accepted",
			setup: func(t *testing.T, gwNS string) wgnetv1alpha1.Forward {
				mustCreate(ctx, t, cl, portedNodePortService(gwNS, "web", 443, corev1.ProtocolTCP))
				return wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}
			},
			want: outcome{accepted: true},
		},
		{
			name: "target port matching a published service port accepted",
			setup: func(t *testing.T, gwNS string) wgnetv1alpha1.Forward {
				mustCreate(ctx, t, cl, portedClusterIPService(gwNS, "web", 8443, corev1.ProtocolTCP))
				return wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web", TargetPort: 8443}
			},
			want: outcome{accepted: true},
		},
		{
			name: "ExternalName service rejected",
			setup: func(t *testing.T, gwNS string) wgnetv1alpha1.Forward {
				mustCreate(ctx, t, cl, externalNameService(gwNS, "web"))
				return wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}
			},
			want: outcome{wantReason: reasonUnsupportedServiceType},
		},
		{
			name: "headless service rejected",
			setup: func(t *testing.T, gwNS string) wgnetv1alpha1.Forward {
				mustCreate(ctx, t, cl, headlessService(gwNS, "web"))
				return wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}
			},
			want: outcome{wantReason: reasonUnsupportedServiceType},
		},
		{
			name: "target port not among published ports rejected",
			setup: func(t *testing.T, gwNS string) wgnetv1alpha1.Forward {
				mustCreate(ctx, t, cl, portedClusterIPService(gwNS, "web", 80, corev1.ProtocolTCP))
				return wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}
			},
			want: outcome{wantReason: reasonTargetPortNotListening, wantRequeue: validationRequeueAfter},
		},
		{
			name: "target port published under a different protocol rejected",
			setup: func(t *testing.T, gwNS string) wgnetv1alpha1.Forward {
				mustCreate(ctx, t, cl, portedClusterIPService(gwNS, "web", 443, corev1.ProtocolUDP))
				return wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}
			},
			want: outcome{wantReason: reasonTargetPortNotListening, wantRequeue: validationRequeueAfter},
		},
		{
			name: "cross-namespace with consent label accepted",
			setup: func(t *testing.T, gwNS string) wgnetv1alpha1.Forward {
				target := gwNS + "-target"
				mustCreate(ctx, t, cl, namespaceWithLabels(target, map[string]string{
					crossNamespaceIngressLabel: crossNamespaceIngressValue,
				}))
				mustCreate(ctx, t, cl, portedClusterIPService(target, "web", 443, corev1.ProtocolTCP))
				return wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web", Namespace: target}
			},
			want: outcome{accepted: true},
		},
		{
			name: "cross-namespace without consent label denied",
			setup: func(t *testing.T, gwNS string) wgnetv1alpha1.Forward {
				target := gwNS + "-target"
				mustCreate(ctx, t, cl, namespaceWithLabels(target, nil))
				mustCreate(ctx, t, cl, portedClusterIPService(target, "web", 443, corev1.ProtocolTCP))
				return wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web", Namespace: target}
			},
			want: outcome{wantReason: reasonCrossNamespaceForwardDenied},
		},
		{
			name: "cross-namespace target namespace missing denied",
			setup: func(_ *testing.T, gwNS string) wgnetv1alpha1.Forward {
				return wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web", Namespace: gwNS + "-ghost"}
			},
			want: outcome{wantReason: reasonTargetNamespaceNotFound, wantRequeue: validationRequeueAfter},
		},
		{
			name: "backend service not found requeues",
			setup: func(_ *testing.T, _ string) wgnetv1alpha1.Forward {
				return wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}
			},
			want: outcome{wantReason: reasonServiceNotFound, wantRequeue: validationRequeueAfter},
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gwNS := fmt.Sprintf("vf-%d", i)
			mustCreate(ctx, t, cl, namespaceWithLabels(gwNS, nil))

			forward := tt.setup(t, gwNS)
			gw := newGateway(gwNS, gwNS, []wgnetv1alpha1.Forward{forward}, nil)
			mustCreate(ctx, t, cl, gw)

			gen, _ := countingKeyGen()
			r := &GatewayReconciler{Client: cl, APIReader: cl, Scheme: te.scheme, Config: reconcileConfig(), GenerateKey: gen}
			key := client.ObjectKeyFromObject(gw)

			result := reconcileToClassification(ctx, t, r, key)

			var got wgnetv1alpha1.Gateway
			mustGet(ctx, t, cl, key, &got)
			cond := apimeta.FindStatusCondition(got.Status.Conditions, conditionReady)

			bundleExists := !apierrors.IsNotFound(
				cl.Get(ctx, client.ObjectKey{Namespace: gwNS, Name: bundleSecretName(gw)}, &corev1.Secret{}))

			if tt.want.accepted {
				if !bundleExists {
					t.Errorf("accepted forward did not provision: bundle Secret absent")
				}
				if cond != nil && isValidationDenialReason(cond.Reason) {
					t.Errorf("accepted forward carries denial reason %q", cond.Reason)
				}
				return
			}

			if bundleExists {
				t.Errorf("denied forward provisioned children: bundle Secret present")
			}
			if cond == nil || cond.Status != metav1.ConditionFalse {
				t.Fatalf("Ready condition = %+v, want False", cond)
			}
			if cond.Reason != tt.want.wantReason {
				t.Errorf("Ready reason = %q, want %q (message: %q)", cond.Reason, tt.want.wantReason, cond.Message)
			}
			if tt.want.wantRequeue != 0 && result.RequeueAfter != tt.want.wantRequeue {
				t.Errorf("RequeueAfter = %v, want %v", result.RequeueAfter, tt.want.wantRequeue)
			}
		})
	}
}

// isValidationDenialReason reports whether reason is one of the forward-validation
// denial reasons, used to assert an accepted forward did not land in a denied
// state.
func isValidationDenialReason(reason string) bool {
	switch reason {
	case reasonCrossNamespaceForwardDenied, reasonTargetNamespaceNotFound,
		reasonUnsupportedServiceType, reasonServiceNotFound, reasonTargetPortNotListening:
		return true
	default:
		return false
	}
}

// reconcileToClassification reconciles past the finalizer-add pass (which requeues
// before classification runs) and returns the result of the second pass, which
// classifies the forwards.
func reconcileToClassification(ctx context.Context, t *testing.T, r *GatewayReconciler, key client.ObjectKey) ctrl.Result {
	t.Helper()
	req := ctrl.Request{NamespacedName: key}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("reconcile (finalizer pass): %v", err)
	}
	result, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("reconcile (classification pass): %v", err)
	}
	return result
}

// namespaceWithLabels builds a Namespace carrying the given labels.
func namespaceWithLabels(name string, labels map[string]string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

// mustCreate creates obj, tolerating an already-exists result so a shared envtest
// control plane can be reused across rows.
func mustCreate(ctx context.Context, t *testing.T, cl client.Client, obj client.Object) {
	t.Helper()
	if err := cl.Create(ctx, obj); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create %T %s/%s: %v", obj, obj.GetNamespace(), obj.GetName(), err)
	}
}

// mustGet fetches obj at key, failing the test on error.
func mustGet(ctx context.Context, t *testing.T, cl client.Client, key client.ObjectKey, obj client.Object) {
	t.Helper()
	if err := cl.Get(ctx, key, obj); err != nil {
		t.Fatalf("get %s %s: %v", obj.GetObjectKind().GroupVersionKind().Kind, key, err)
	}
}

// setXGatewayGCPStatus patches the composite's status subresource with an observed
// address and serviceAccountEmail, simulating Crossplane's status write.
func setXGatewayGCPStatus(ctx context.Context, t *testing.T, cl client.Client, key client.ObjectKey, address, saEmail string) {
	t.Helper()
	xg := newXGatewayGCP()
	mustGet(ctx, t, cl, key, xg)
	if err := unstructured.SetNestedField(xg.Object, address, "status", "address"); err != nil {
		t.Fatalf("set status.address: %v", err)
	}
	if err := unstructured.SetNestedField(xg.Object, saEmail, "status", "serviceAccountEmail"); err != nil {
		t.Fatalf("set status.serviceAccountEmail: %v", err)
	}
	if err := cl.Status().Update(ctx, xg); err != nil {
		t.Fatalf("update xgatewaygcp status: %v", err)
	}
}

// setLinkLeaseActive makes linkActive observe podName as the active link tunnel for the
// Gateway at gwKey: it points the lease holder at podName and sets that pod's PodReady
// condition, which envtest's missing scheduler and kubelet leave unset.
func setLinkLeaseActive(ctx context.Context, t *testing.T, cl client.Client, gwKey client.ObjectKey, podName string, ready bool) {
	t.Helper()
	leaseName := linkComponentName(&wgnetv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: gwKey.Name, Namespace: gwKey.Namespace},
	})

	upsertLeaseHolder(ctx, t, cl, client.ObjectKey{Namespace: gwKey.Namespace, Name: leaseName}, podName)
	upsertPodReady(ctx, t, cl, client.ObjectKey{Namespace: gwKey.Namespace, Name: podName}, ready)
}

// upsertLeaseHolder ensures a coordination Lease at key exists with its
// HolderIdentity set to holder, creating it on first call and patching the holder
// thereafter.
func upsertLeaseHolder(ctx context.Context, t *testing.T, cl client.Client, key client.ObjectKey, holder string) {
	t.Helper()
	var lease coordinationv1.Lease
	err := cl.Get(ctx, key, &lease)
	switch {
	case apierrors.IsNotFound(err):
		lease = coordinationv1.Lease{
			ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name},
			Spec:       coordinationv1.LeaseSpec{HolderIdentity: &holder},
		}
		if err := cl.Create(ctx, &lease); err != nil {
			t.Fatalf("create link lease %s: %v", key, err)
		}
	case err != nil:
		t.Fatalf("get link lease %s: %v", key, err)
	default:
		lease.Spec.HolderIdentity = &holder
		if err := cl.Update(ctx, &lease); err != nil {
			t.Fatalf("update link lease %s holder: %v", key, err)
		}
	}
}

// upsertPodReady ensures a minimal pod at key exists with its PodReady condition set to
// ready, writing the status subresource directly since envtest has no kubelet. It is
// idempotent across readiness flips.
func upsertPodReady(ctx context.Context, t *testing.T, cl client.Client, key client.ObjectKey, ready bool) {
	t.Helper()
	status := corev1.ConditionFalse
	if ready {
		status = corev1.ConditionTrue
	}

	var pod corev1.Pod
	if err := cl.Get(ctx, key, &pod); err != nil {
		if !apierrors.IsNotFound(err) {
			t.Fatalf("get link holder pod %s: %v", key, err)
		}
		pod = corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "link", Image: "registry.example.com/gateway-link:test"}},
			},
		}
		if err := cl.Create(ctx, &pod); err != nil {
			t.Fatalf("create link holder pod %s: %v", key, err)
		}
	}

	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: status}}
	if err := cl.Status().Update(ctx, &pod); err != nil {
		t.Fatalf("update link holder pod %s status: %v", key, err)
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

// recordedEvent captures one events.EventRecorder.Eventf call so a test can
// assert on the emitted event.
type recordedEvent struct {
	regarding runtime.Object
	eventtype string
	reason    string
	action    string
	note      string
}

// fakeEventRecorder is a hand fake of events.EventRecorder that records every
// Eventf call. The interface has a single method, so a generated mock would add
// nothing over capturing the args directly.
type fakeEventRecorder struct {
	events []recordedEvent
}

func (f *fakeEventRecorder) Eventf(regarding runtime.Object, _ runtime.Object, eventtype, reason, action, note string, args ...interface{}) {
	f.events = append(f.events, recordedEvent{
		regarding: regarding,
		eventtype: eventtype,
		reason:    reason,
		action:    action,
		note:      fmt.Sprintf(note, args...),
	})
}

// TestReconcilerFailEmitsEvent covers the reconcile-failure path: fail emits a Warning
// event describing the failure when a recorder is wired, and does not panic when the
// recorder is nil.
func TestReconcilerFailEmitsEvent(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	cl := te.client

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "wg-system"}}
	mustCreate(ctx, t, cl, ns)

	tests := []struct {
		name         string
		gateway      string
		withRecorder bool
		wantEvents   int
	}{
		{name: "records warning event when recorder wired", gateway: "fail-recorded", withRecorder: true, wantEvents: 1},
		{name: "no panic when recorder nil", gateway: "fail-nil-recorder", withRecorder: false, wantEvents: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway(tt.gateway, "wg-system", nil, nil)
			mustCreate(ctx, t, cl, gw)

			rec := &fakeEventRecorder{}
			r := &GatewayReconciler{Client: cl, APIReader: cl, Scheme: te.scheme, Config: reconcileConfig()}
			if tt.withRecorder {
				r.Recorder = rec
			}

			cause := fmt.Errorf("boom")
			_, err := r.fail(ctx, gw, "ensure xgatewaygcp", cause)
			if err == nil {
				t.Fatalf("fail returned nil error; want the wrapped cause surfaced")
			}
			if !errors.Is(err, cause) {
				t.Errorf("fail error = %v; want it to wrap %v", err, cause)
			}

			if len(rec.events) != tt.wantEvents {
				t.Fatalf("recorded %d events; want %d", len(rec.events), tt.wantEvents)
			}
			if tt.wantEvents == 0 {
				return
			}

			ev := rec.events[0]
			if ev.eventtype != corev1.EventTypeWarning {
				t.Errorf("event type = %q; want %q", ev.eventtype, corev1.EventTypeWarning)
			}
			if ev.reason != reasonReconcileFailed {
				t.Errorf("event reason = %q; want %q", ev.reason, reasonReconcileFailed)
			}
			if ev.action != actionReconcile {
				t.Errorf("event action = %q; want %q", ev.action, actionReconcile)
			}
			if evGW, ok := ev.regarding.(*wgnetv1alpha1.Gateway); !ok || evGW.Name != tt.gateway {
				t.Errorf("event regarding = %#v; want Gateway %q", ev.regarding, tt.gateway)
			}
			if !strings.Contains(ev.note, "ensure xgatewaygcp") || !strings.Contains(ev.note, "boom") {
				t.Errorf("event note = %q; want it to describe the wrapped failure", ev.note)
			}

			var got wgnetv1alpha1.Gateway
			mustGet(ctx, t, cl, client.ObjectKeyFromObject(gw), &got)
			cond := apimeta.FindStatusCondition(got.Status.Conditions, conditionReady)
			if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != reasonReconcileFailed {
				t.Errorf("Ready condition = %#v; want False/%s", cond, reasonReconcileFailed)
			}
		})
	}
}

// linkConfigForwards reads the link ConfigMap the reconciler rendered for the Gateway
// at key and returns its runtime forwards, the assertion surface for which forwards the
// operator exposed.
func linkConfigForwards(ctx context.Context, t *testing.T, cl client.Client, key client.ObjectKey) []link.Forward {
	t.Helper()
	var cm corev1.ConfigMap
	cmKey := client.ObjectKey{Namespace: key.Namespace, Name: key.Name + "-link"}
	if err := cl.Get(ctx, cmKey, &cm); err != nil {
		t.Fatalf("get link configmap %s: %v", cmKey, err)
	}
	raw, ok := cm.Data[linkConfigKey]
	if !ok {
		t.Fatalf("link configmap %s missing %q", cmKey, linkConfigKey)
	}
	var rc link.RuntimeConfig
	decodeJSON(t, raw, &rc)
	return rc.Forwards
}

// forwardServiceNames returns the Service FQDNs of the given runtime forwards, the
// stable field for asserting which forwards a link config carries.
func forwardServiceNames(forwards []link.Forward) []string {
	names := make([]string, 0, len(forwards))
	for _, f := range forwards {
		names = append(names, f.Service)
	}
	return names
}

// TestMixedForwards covers the per-forward classification contract: a Gateway with one
// valid and one invalid forward provisions, exposes only the valid forward, and reports
// Ready=False with the invalid forward's reason (a missing backend, ServiceNotFound).
func TestMixedForwards(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	cl := te.client

	const ns = "mixed"
	mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))
	mustCreate(ctx, t, cl, portedClusterIPService(ns, "web", 443, corev1.ProtocolTCP))

	gw := newGateway("mixed-gw", ns, []wgnetv1alpha1.Forward{
		{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
		{Port: 1194, Protocol: wgnetv1alpha1.ProtocolUDP, Service: "absent"},
	}, nil)
	mustCreate(ctx, t, cl, gw)

	gen, _ := countingKeyGen()
	r := &GatewayReconciler{Client: cl, APIReader: cl, Scheme: te.scheme, Config: reconcileConfig(), GenerateKey: gen}
	key := client.ObjectKeyFromObject(gw)

	result := reconcileToClassification(ctx, t, r, key)

	// A valid forward exists, so the Gateway provisions: the bundle Secret appears.
	if err := cl.Get(ctx, client.ObjectKey{Namespace: ns, Name: bundleSecretName(gw)}, &corev1.Secret{}); err != nil {
		t.Fatalf("mixed Gateway did not provision (bundle Secret absent): %v", err)
	}

	// The link config carries only the valid forward, not the invalid one.
	got := forwardServiceNames(linkConfigForwards(ctx, t, cl, key))
	want := []string{"web." + ns + ".svc.cluster.local"}
	if !slices.Equal(got, want) {
		t.Errorf("link config forwards = %v, want %v (only the valid forward)", got, want)
	}

	// Ready=False with the invalid forward's reason.
	var live wgnetv1alpha1.Gateway
	mustGet(ctx, t, cl, key, &live)
	cond := apimeta.FindStatusCondition(live.Status.Conditions, conditionReady)
	if cond == nil || cond.Status != metav1.ConditionFalse {
		t.Fatalf("Ready condition = %+v, want False", cond)
	}
	if cond.Reason != reasonServiceNotFound {
		t.Errorf("Ready reason = %q, want %q (message: %q)", cond.Reason, reasonServiceNotFound, cond.Message)
	}
	// The invalid forward's reason is transient, so the reconcile requeues.
	if result.RequeueAfter != validationRequeueAfter {
		t.Errorf("RequeueAfter = %v, want %v (transient invalid forward)", result.RequeueAfter, validationRequeueAfter)
	}
}

// TestLinkActiveReadyGate covers the active-tunnel gate: a provisioned Gateway with a
// valid forward and a known address is Ready only when the link lease holder is a Ready
// pod, so a Ready idle standby must not mask a holder that is not Ready.
func TestLinkActiveReadyGate(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	cl := te.client

	tests := []struct {
		name string
		// arrange sets up the lease/holder-pod state for the Gateway in ns after it has
		// provisioned and been given an address. holderName is the deterministic name
		// the row may use for the lease holder pod.
		arrange   func(t *testing.T, ns, holderName string)
		wantReady metav1.ConditionStatus
	}{
		{
			name: "holder pod ready, tunnel up",
			arrange: func(t *testing.T, ns, holderName string) {
				setLinkLeaseActive(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: "gw"}, holderName, true)
			},
			wantReady: metav1.ConditionTrue,
		},
		{
			name: "holder pod not ready masks a ready standby",
			arrange: func(t *testing.T, ns, holderName string) {
				// A standby pod is Ready, but it is not the lease holder. The holder is
				// the one whose readiness gates the tunnel, and it is not Ready, so the
				// Gateway must be Ready=False despite the Ready standby.
				upsertPodReady(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: "gw-link-standby"}, true)
				setLinkLeaseActive(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: "gw"}, holderName, false)
			},
			wantReady: metav1.ConditionFalse,
		},
		{
			name: "lease absent, no active tunnel",
			arrange: func(_ *testing.T, _, _ string) {
				// No lease and no holder pod: linkActive must read NotFound and report
				// the tunnel as not active without erroring.
			},
			wantReady: metav1.ConditionFalse,
		},
		{
			name: "lease present but holder pod absent",
			arrange: func(t *testing.T, ns, holderName string) {
				// The lease names a holder pod that does not exist, simulating the
				// failover window between the prior holder releasing the lease and the
				// new holder publishing itself. linkActive must tolerate the missing pod.
				upsertLeaseHolder(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: "gw-link"}, holderName)
			},
			wantReady: metav1.ConditionFalse,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := fmt.Sprintf("la-%d", i)
			mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))
			mustCreate(ctx, t, cl, portedClusterIPService(ns, "web", 443, corev1.ProtocolTCP))

			gw := newGateway("gw", ns, []wgnetv1alpha1.Forward{
				{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
			}, nil)
			mustCreate(ctx, t, cl, gw)
			key := client.ObjectKeyFromObject(gw)

			gen, _ := countingKeyGen()
			r := &GatewayReconciler{Client: cl, APIReader: cl, Scheme: te.scheme, Config: reconcileConfig(), GenerateKey: gen}

			// Provision the Gateway, then give the composite an address so the address
			// gate is satisfied and the Ready outcome turns solely on the active tunnel.
			drainReconcile(ctx, t, r, key)
			setXGatewayGCPStatus(ctx, t, cl, key, "203.0.113.30", "sa@example.iam.gserviceaccount.com")

			tt.arrange(t, ns, "gw-link-0")

			// Reconcile must succeed: every tunnel-gate case (including the NotFound
			// ones) is a non-error outcome, so a failure here means linkActive surfaced
			// a NotFound as an error.
			if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
				t.Fatalf("reconcile after arranging tunnel state: %v", err)
			}

			var got wgnetv1alpha1.Gateway
			mustGet(ctx, t, cl, key, &got)
			cond := apimeta.FindStatusCondition(got.Status.Conditions, conditionReady)
			if cond == nil {
				t.Fatalf("Ready condition absent")
			}
			if cond.Status != tt.wantReady {
				t.Errorf("Ready status = %s, want %s (reason %q, message %q)",
					cond.Status, tt.wantReady, cond.Reason, cond.Message)
			}
			if tt.wantReady == metav1.ConditionTrue && cond.Reason != reasonReady {
				t.Errorf("Ready reason = %q, want %q", cond.Reason, reasonReady)
			}
		})
	}
}

// startManager builds a controller manager on the envtest config, registers the
// GatewayReconciler so the Service and Namespace watches are live, starts it in a
// goroutine (stopped via t.Cleanup), and returns its client.
func startManager(ctx context.Context, t *testing.T, te *testEnv) client.Client {
	t.Helper()

	mgr, err := ctrl.NewManager(te.cfg, ctrl.Options{
		Scheme: te.scheme,
		// Disable the metrics listener so parallel managers in one test binary do
		// not contend for a port.
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	gen, _ := countingKeyGen()
	r := &GatewayReconciler{
		Client:      mgr.GetClient(),
		Scheme:      mgr.GetScheme(),
		Config:      reconcileConfig(),
		GenerateKey: gen,
	}
	if err := r.SetupWithManager(mgr); err != nil {
		t.Fatalf("setup reconciler with manager: %v", err)
	}

	mgrCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := mgr.Start(mgrCtx); err != nil {
			// Start returns an error on a genuine manager failure; a cancel-driven
			// shutdown returns nil, so a non-nil error here is a real problem worth
			// surfacing without racing the test goroutine's t.Fatalf.
			t.Errorf("manager start: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	if !mgr.GetCache().WaitForCacheSync(mgrCtx) {
		t.Fatal("manager cache failed to sync")
	}
	return mgr.GetClient()
}

// pollUntil polls cond until it returns true or timeout elapses, failing with msg on
// timeout. It is the manager-backed transition test's await primitive, with a longer
// deadline than the package eventually helper.
func pollUntil(ctx context.Context, t *testing.T, timeout time.Duration, msg string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("%s: context done: %v", msg, ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatalf("timed out waiting for %s", msg)
}

// transitionTimeout bounds each manager-backed transition wait, generous because it
// covers a watch event firing, a reconcile running, and the dependent status patches.
const transitionTimeout = 30 * time.Second

// gatewayReadyReason fetches the Gateway at key with cl and returns its Ready
// condition status and reason, or empty strings if the condition is absent.
func gatewayReadyReason(ctx context.Context, t *testing.T, cl client.Client, key client.ObjectKey) (metav1.ConditionStatus, string) {
	t.Helper()
	var gw wgnetv1alpha1.Gateway
	if err := cl.Get(ctx, key, &gw); err != nil {
		t.Fatalf("get gateway %s: %v", key, err)
	}
	cond := apimeta.FindStatusCondition(gw.Status.Conditions, conditionReady)
	if cond == nil {
		return "", ""
	}
	return cond.Status, cond.Reason
}

// driveProvisionedReady supplies the readiness preconditions envtest cannot: it waits
// for the operator to create the composite and link Deployment, then patches the
// composite address and makes the link lease hold a Ready pod so the watches flip Ready.
func driveProvisionedReady(ctx context.Context, t *testing.T, direct client.Client, key client.ObjectKey) {
	t.Helper()

	pollUntil(ctx, t, transitionTimeout, "composite created for "+key.String(), func() bool {
		return !apierrors.IsNotFound(direct.Get(ctx, key, newXGatewayGCP()))
	})

	depKey := client.ObjectKey{Namespace: key.Namespace, Name: key.Name + "-link"}
	pollUntil(ctx, t, transitionTimeout, "link deployment created for "+key.String(), func() bool {
		return !apierrors.IsNotFound(direct.Get(ctx, depKey, &appsv1.Deployment{}))
	})

	// Seed the active-tunnel precondition before the composite status: the lease and pod
	// are not watched, so writing the watched composite status last lets its reconcile
	// observe both the address and the active tunnel together and flip Ready=True.
	setLinkLeaseActive(ctx, t, direct, key, key.Name+"-link-0", true)
	setXGatewayGCPStatus(ctx, t, direct, key, "203.0.113.20", "sa@example.iam.gserviceaccount.com")
}

// TestForwardValidationTransitions runs a real manager so the Service and Namespace
// watches enqueue, then drives backend changes and asserts the link config and Gateway
// Ready condition reconverge without a manual reconcile. Reads use the direct client.
func TestForwardValidationTransitions(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	direct := te.client
	startManager(ctx, t, te)

	t.Run("service created after gateway", func(t *testing.T) {
		const ns = "tr-svc-create"
		mustCreate(ctx, t, direct, namespaceWithLabels(ns, nil))

		gw := newGateway("gw", ns, []wgnetv1alpha1.Forward{
			{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
		}, nil)
		mustCreate(ctx, t, direct, gw)
		key := client.ObjectKeyFromObject(gw)

		// No backend Service yet: the operator must not provision, and Ready=False
		// carries ServiceNotFound.
		pollUntil(ctx, t, transitionTimeout, "ServiceNotFound before backend exists", func() bool {
			status, reason := gatewayReadyReason(ctx, t, direct, key)
			return status == metav1.ConditionFalse && reason == reasonServiceNotFound
		})
		if err := direct.Get(ctx, client.ObjectKey{Namespace: ns, Name: bundleSecretName(gw)}, &corev1.Secret{}); !apierrors.IsNotFound(err) {
			t.Fatalf("bundle Secret get = %v, want NotFound (no valid forward, not provisioned)", err)
		}

		// Creating the backend Service must trigger the Service watch, re-classify
		// the forward as valid, and provision it.
		mustCreate(ctx, t, direct, portedClusterIPService(ns, "web", 443, corev1.ProtocolTCP))
		pollUntil(ctx, t, transitionTimeout, "forward present after service created", func() bool {
			var cm corev1.ConfigMap
			if err := direct.Get(ctx, client.ObjectKey{Namespace: ns, Name: "gw-link"}, &cm); err != nil {
				return false
			}
			var rc link.RuntimeConfig
			if err := jsonUnmarshalString(cm.Data[linkConfigKey], &rc); err != nil {
				return false
			}
			return len(rc.Forwards) == 1 && rc.Forwards[0].Service == "web."+ns+".svc.cluster.local"
		})

		driveProvisionedReady(ctx, t, direct, key)
		pollUntil(ctx, t, transitionTimeout, "Ready=True after backend created", func() bool {
			status, reason := gatewayReadyReason(ctx, t, direct, key)
			return status == metav1.ConditionTrue && reason == reasonReady
		})
	})

	t.Run("service deleted removes only that forward", func(t *testing.T) {
		const ns = "tr-svc-delete"
		mustCreate(ctx, t, direct, namespaceWithLabels(ns, nil))
		mustCreate(ctx, t, direct, portedClusterIPService(ns, "web", 443, corev1.ProtocolTCP))
		mustCreate(ctx, t, direct, portedClusterIPService(ns, "api", 8080, corev1.ProtocolTCP))

		gw := newGateway("gw", ns, []wgnetv1alpha1.Forward{
			{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
			{Port: 8080, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "api"},
		}, nil)
		mustCreate(ctx, t, direct, gw)
		key := client.ObjectKeyFromObject(gw)

		// Both forwards valid: the link config carries both and the Gateway is Ready.
		pollUntil(ctx, t, transitionTimeout, "both forwards present", func() bool {
			var cm corev1.ConfigMap
			if err := direct.Get(ctx, client.ObjectKey{Namespace: ns, Name: "gw-link"}, &cm); err != nil {
				return false
			}
			var rc link.RuntimeConfig
			if err := jsonUnmarshalString(cm.Data[linkConfigKey], &rc); err != nil {
				return false
			}
			return len(rc.Forwards) == 2
		})
		driveProvisionedReady(ctx, t, direct, key)
		pollUntil(ctx, t, transitionTimeout, "Ready=True with both forwards", func() bool {
			status, _ := gatewayReadyReason(ctx, t, direct, key)
			return status == metav1.ConditionTrue
		})

		// Deleting the "web" backend must drop only its forward; "api" stays, the
		// Gateway keeps its VM, and Ready=False carries the ServiceNotFound reason.
		if err := direct.Delete(ctx, portedClusterIPService(ns, "web", 443, corev1.ProtocolTCP)); err != nil {
			t.Fatalf("delete web service: %v", err)
		}
		pollUntil(ctx, t, transitionTimeout, "only api forward remains after web deleted", func() bool {
			var cm corev1.ConfigMap
			if err := direct.Get(ctx, client.ObjectKey{Namespace: ns, Name: "gw-link"}, &cm); err != nil {
				return false
			}
			var rc link.RuntimeConfig
			if err := jsonUnmarshalString(cm.Data[linkConfigKey], &rc); err != nil {
				return false
			}
			return len(rc.Forwards) == 1 && rc.Forwards[0].Service == "api."+ns+".svc.cluster.local"
		})
		pollUntil(ctx, t, transitionTimeout, "Ready=False/ServiceNotFound after web deleted", func() bool {
			status, reason := gatewayReadyReason(ctx, t, direct, key)
			return status == metav1.ConditionFalse && reason == reasonServiceNotFound
		})
		// The Gateway stays provisioned: deleting one backend does not tear the VM
		// down.
		if err := direct.Get(ctx, key, newXGatewayGCP()); err != nil {
			t.Fatalf("composite get after one backend deleted = %v, want still present", err)
		}
	})

	t.Run("consent label toggles cross-namespace forward", func(t *testing.T) {
		const gwNS = "tr-consent"
		target := gwNS + "-target"
		mustCreate(ctx, t, direct, namespaceWithLabels(gwNS, nil))
		mustCreate(ctx, t, direct, namespaceWithLabels(target, nil))
		mustCreate(ctx, t, direct, portedClusterIPService(target, "web", 443, corev1.ProtocolTCP))

		gw := newGateway("gw", gwNS, []wgnetv1alpha1.Forward{
			{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web", Namespace: target},
		}, nil)
		mustCreate(ctx, t, direct, gw)
		key := client.ObjectKeyFromObject(gw)

		// Unlabelled target: the cross-namespace forward is denied and, as the only
		// forward, the Gateway does not provision.
		pollUntil(ctx, t, transitionTimeout, "CrossNamespaceForwardDenied while unlabelled", func() bool {
			status, reason := gatewayReadyReason(ctx, t, direct, key)
			return status == metav1.ConditionFalse && reason == reasonCrossNamespaceForwardDenied
		})

		// Adding the consent label must trigger the Namespace watch and let the
		// forward through.
		setNamespaceLabel(ctx, t, direct, target, crossNamespaceIngressLabel, crossNamespaceIngressValue)
		pollUntil(ctx, t, transitionTimeout, "cross-ns forward present after label added", func() bool {
			var cm corev1.ConfigMap
			if err := direct.Get(ctx, client.ObjectKey{Namespace: gwNS, Name: "gw-link"}, &cm); err != nil {
				return false
			}
			var rc link.RuntimeConfig
			if err := jsonUnmarshalString(cm.Data[linkConfigKey], &rc); err != nil {
				return false
			}
			return len(rc.Forwards) == 1 && rc.Forwards[0].Service == "web."+target+".svc.cluster.local"
		})
		driveProvisionedReady(ctx, t, direct, key)
		pollUntil(ctx, t, transitionTimeout, "Ready=True after consent label added", func() bool {
			status, _ := gatewayReadyReason(ctx, t, direct, key)
			return status == metav1.ConditionTrue
		})

		// Removing the label must re-deny the forward; the Gateway keeps its VM
		// (now provisioned) and reports Ready=False with the denial reason.
		removeNamespaceLabel(ctx, t, direct, target, crossNamespaceIngressLabel)
		pollUntil(ctx, t, transitionTimeout, "Ready=False/denied after label removed", func() bool {
			status, reason := gatewayReadyReason(ctx, t, direct, key)
			return status == metav1.ConditionFalse && reason == reasonCrossNamespaceForwardDenied
		})
		pollUntil(ctx, t, transitionTimeout, "no forwards after label removed", func() bool {
			var cm corev1.ConfigMap
			if err := direct.Get(ctx, client.ObjectKey{Namespace: gwNS, Name: "gw-link"}, &cm); err != nil {
				return false
			}
			var rc link.RuntimeConfig
			if err := jsonUnmarshalString(cm.Data[linkConfigKey], &rc); err != nil {
				return false
			}
			return len(rc.Forwards) == 0
		})
	})

	t.Run("target port appearing admits the forward", func(t *testing.T) {
		const ns = "tr-targetport"
		mustCreate(ctx, t, direct, namespaceWithLabels(ns, nil))
		// The Service exists but publishes the wrong port, so the forward's target
		// port (443) is not listening.
		mustCreate(ctx, t, direct, portedClusterIPService(ns, "web", 80, corev1.ProtocolTCP))

		gw := newGateway("gw", ns, []wgnetv1alpha1.Forward{
			{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
		}, nil)
		mustCreate(ctx, t, direct, gw)
		key := client.ObjectKeyFromObject(gw)

		pollUntil(ctx, t, transitionTimeout, "TargetPortNotListening before port published", func() bool {
			status, reason := gatewayReadyReason(ctx, t, direct, key)
			return status == metav1.ConditionFalse && reason == reasonTargetPortNotListening
		})
		if err := direct.Get(ctx, client.ObjectKey{Namespace: ns, Name: bundleSecretName(gw)}, &corev1.Secret{}); !apierrors.IsNotFound(err) {
			t.Fatalf("bundle Secret get = %v, want NotFound (target port not listening, not provisioned)", err)
		}

		// Publishing port 443 on the Service must trigger the Service watch and admit
		// the forward.
		addServicePort(ctx, t, direct, ns, "web", 443, corev1.ProtocolTCP)
		pollUntil(ctx, t, transitionTimeout, "forward present after target port published", func() bool {
			var cm corev1.ConfigMap
			if err := direct.Get(ctx, client.ObjectKey{Namespace: ns, Name: "gw-link"}, &cm); err != nil {
				return false
			}
			var rc link.RuntimeConfig
			if err := jsonUnmarshalString(cm.Data[linkConfigKey], &rc); err != nil {
				return false
			}
			return len(rc.Forwards) == 1
		})
		driveProvisionedReady(ctx, t, direct, key)
		pollUntil(ctx, t, transitionTimeout, "Ready=True after target port published", func() bool {
			status, _ := gatewayReadyReason(ctx, t, direct, key)
			return status == metav1.ConditionTrue
		})
	})

	t.Run("target port disappearing revokes the forward", func(t *testing.T) {
		const ns = "tr-targetport-revoke"
		mustCreate(ctx, t, direct, namespaceWithLabels(ns, nil))
		// The Service publishes the forward's target port (443) plus an unrelated
		// port, so removing 443 leaves the Service present: the revocation reason must
		// be TargetPortNotListening, not ServiceNotFound.
		mustCreate(ctx, t, direct, portedClusterIPService(ns, "web", 443, corev1.ProtocolTCP))
		addServicePort(ctx, t, direct, ns, "web", 9000, corev1.ProtocolTCP)

		gw := newGateway("gw", ns, []wgnetv1alpha1.Forward{
			{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
		}, nil)
		mustCreate(ctx, t, direct, gw)
		key := client.ObjectKeyFromObject(gw)

		// Target port published: the forward is valid, provisions, and reaches Ready.
		pollUntil(ctx, t, transitionTimeout, "forward present while target port published", func() bool {
			var cm corev1.ConfigMap
			if err := direct.Get(ctx, client.ObjectKey{Namespace: ns, Name: "gw-link"}, &cm); err != nil {
				return false
			}
			var rc link.RuntimeConfig
			if err := jsonUnmarshalString(cm.Data[linkConfigKey], &rc); err != nil {
				return false
			}
			return len(rc.Forwards) == 1
		})
		driveProvisionedReady(ctx, t, direct, key)
		pollUntil(ctx, t, transitionTimeout, "Ready=True with target port published", func() bool {
			status, _ := gatewayReadyReason(ctx, t, direct, key)
			return status == metav1.ConditionTrue
		})

		// Removing the target port must trigger the Service watch and revoke the
		// forward: Ready=False/TargetPortNotListening, the link config empties, and
		// the Gateway keeps its VM.
		removeServicePort(ctx, t, direct, ns, "web", 443, corev1.ProtocolTCP)
		pollUntil(ctx, t, transitionTimeout, "Ready=False/TargetPortNotListening after target port removed", func() bool {
			status, reason := gatewayReadyReason(ctx, t, direct, key)
			return status == metav1.ConditionFalse && reason == reasonTargetPortNotListening
		})
		pollUntil(ctx, t, transitionTimeout, "no forwards after target port removed", func() bool {
			var cm corev1.ConfigMap
			if err := direct.Get(ctx, client.ObjectKey{Namespace: ns, Name: "gw-link"}, &cm); err != nil {
				return false
			}
			var rc link.RuntimeConfig
			if err := jsonUnmarshalString(cm.Data[linkConfigKey], &rc); err != nil {
				return false
			}
			return len(rc.Forwards) == 0
		})
		if err := direct.Get(ctx, key, newXGatewayGCP()); err != nil {
			t.Fatalf("composite get after target port removed = %v, want still present", err)
		}
	})
}

// jsonUnmarshalString unmarshals raw into v, returning the error so a poll
// predicate can treat a not-yet-written ConfigMap as "keep waiting" rather than
// failing the whole test the way decodeJSON would.
func jsonUnmarshalString(raw string, v any) error {
	return json.Unmarshal([]byte(raw), v)
}

// setNamespaceLabel sets label=value on the named namespace via a read-modify-
// write with the direct client, so the operator's Namespace watch fires.
func setNamespaceLabel(ctx context.Context, t *testing.T, cl client.Client, name, label, value string) {
	t.Helper()
	var ns corev1.Namespace
	mustGet(ctx, t, cl, client.ObjectKey{Name: name}, &ns)
	if ns.Labels == nil {
		ns.Labels = map[string]string{}
	}
	ns.Labels[label] = value
	if err := cl.Update(ctx, &ns); err != nil {
		t.Fatalf("set namespace %s label %s: %v", name, label, err)
	}
}

// removeNamespaceLabel deletes label from the named namespace via a read-modify-
// write with the direct client, so the operator's Namespace watch fires.
func removeNamespaceLabel(ctx context.Context, t *testing.T, cl client.Client, name, label string) {
	t.Helper()
	var ns corev1.Namespace
	mustGet(ctx, t, cl, client.ObjectKey{Name: name}, &ns)
	delete(ns.Labels, label)
	if err := cl.Update(ctx, &ns); err != nil {
		t.Fatalf("remove namespace %s label %s: %v", name, label, err)
	}
}

// addServicePort appends a published port/proto to the named Service via the direct
// client, so the operator's Service watch fires. It assigns every port a deterministic
// name first, since a multi-port Service requires named ports.
func addServicePort(ctx context.Context, t *testing.T, cl client.Client, ns, name string, port int32, proto corev1.Protocol) {
	t.Helper()
	var svc corev1.Service
	mustGet(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: name}, &svc)
	svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{Port: port, Protocol: proto})
	for i := range svc.Spec.Ports {
		svc.Spec.Ports[i].Name = fmt.Sprintf("p%d", svc.Spec.Ports[i].Port)
	}
	if err := cl.Update(ctx, &svc); err != nil {
		t.Fatalf("add port %d to service %s/%s: %v", port, ns, name, err)
	}
}

// removeServicePort drops the port matching port/proto from the named Service via the
// direct client, so the operator's Service watch fires. It renames the survivors
// deterministically to keep the named-port invariant, and fails if no port matched.
func removeServicePort(ctx context.Context, t *testing.T, cl client.Client, ns, name string, port int32, proto corev1.Protocol) {
	t.Helper()
	var svc corev1.Service
	mustGet(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: name}, &svc)
	kept := make([]corev1.ServicePort, 0, len(svc.Spec.Ports))
	for _, p := range svc.Spec.Ports {
		if p.Port == port && p.Protocol == proto {
			continue
		}
		kept = append(kept, p)
	}
	if len(kept) == len(svc.Spec.Ports) {
		t.Fatalf("remove port %d/%s from service %s/%s: no matching port", port, proto, ns, name)
	}
	for i := range kept {
		kept[i].Name = fmt.Sprintf("p%d", kept[i].Port)
	}
	svc.Spec.Ports = kept
	if err := cl.Update(ctx, &svc); err != nil {
		t.Fatalf("remove port %d from service %s/%s: %v", port, ns, name, err)
	}
}
