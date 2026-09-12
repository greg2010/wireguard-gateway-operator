package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

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
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/greg2010/wireguard-gateway-operator/internal/link"
	"github.com/greg2010/wireguard-gateway-operator/internal/wg"
	wgnetv1alpha1 "github.com/greg2010/wireguard-gateway-operator/pkg/api/v1alpha1"
)

// reconcileConfig is the operator config the controller tests reconcile with. PodNamespace is
// "default": every envtest control plane provisions it, so the shared network applies cleanly.
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

// drainReconcile invokes Reconcile a few times so the finalizer-add pass and the ensure/mirror
// passes all run. Reconcile is idempotent, so the fixed iteration count is safe.
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

// reconcileFixture starts envtest with the wg-system namespace and a sample Gateway. SSA, which
// the fake client cannot model, is why these tests need a real control plane.
func reconcileFixture(ctx context.Context, t *testing.T) (*testEnv, *GatewayReconciler, *wgnetv1alpha1.Gateway, client.ObjectKey, *int) {
	t.Helper()
	te := setupEnvtestRBAC(t)

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "wg-system"}}
	if err := te.client.Create(ctx, ns); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create namespace: %v", err)
	}

	// Classification requires each backend to exist with a ClusterIP publishing the forward's
	// port before provisioning, so the lifecycle path must create them with matching ports.
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
	r := newOperatorReconciler(te, &GatewayReconciler{Config: reconcileConfig(), GenerateKey: gen})
	return te, r, gw, client.ObjectKeyFromObject(gw), calls
}

// TestReconcileLifecycle runs against a real API server, required because the reconciler applies
// its children with server-side apply.
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
		setXGatewayGCPStatus(ctx, t, cl, key, "203.0.113.9", "sa@example.iam.gserviceaccount.com", "")
		setLinkLeaseActive(ctx, t, cl, key, "edge-link-0", true, "node-a")
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

// TestReconcileLinkPodDisruptionBudget asserts the PDB tracks the link replica count: absent at
// one replica, present above it, removed on scale-back so a stale PDB cannot strand a drain.
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

// TestReconcileIdempotent asserts a converged Gateway is not rewritten (resourceVersion stays
// stable), guarding against a status-write loop in the provisioning and ready states.
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
				setXGatewayGCPStatus(ctx, t, cl, key, tc.address, tc.saEmail, "")
				setLinkLeaseActive(ctx, t, cl, key, key.Name+"-link-0", true, "node-a")
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

// sharedNetworkKey is the key of the singleton shared network r ensures, derived from its config
// so it cannot drift from what the reconciler applies.
func sharedNetworkKey(r *GatewayReconciler) client.ObjectKey {
	return client.ObjectKey{Name: r.Config.SharedNetworkName, Namespace: r.Config.PodNamespace}
}

// reconcileUntilGone drives Reconcile until the Gateway at key is purged. The refcount teardown
// spans several reconciles, where a fixed iteration count would be brittle.
func reconcileUntilGone(ctx context.Context, t *testing.T, r *GatewayReconciler, cl client.Client, key client.ObjectKey) {
	t.Helper()
	eventually(ctx, t, "gateway "+key.String()+" purged after delete", func() bool {
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
			t.Fatalf("reconcile delete %s: %v", key, err)
		}
		return apierrors.IsNotFound(cl.Get(ctx, key, &wgnetv1alpha1.Gateway{}))
	})
}

// TestReconcileSharedNetworkRefcount asserts the shared network survives deleting the first of
// two Gateways sharing it and is torn down only by the last delete.
func TestReconcileSharedNetworkRefcount(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	const ns = "wg-system"
	mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))
	mustCreate(ctx, t, cl, portedClusterIPService(ns, "web", 443, corev1.ProtocolTCP))
	mustCreate(ctx, t, cl, portedClusterIPService(ns, "vpn", 1194, corev1.ProtocolUDP))

	gen, _ := countingKeyGen()
	r := newOperatorReconciler(te, &GatewayReconciler{Config: reconcileConfig(), GenerateKey: gen})

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

// newGatewayCELFixture builds a Gateway with the given forwards and an explicit listen port. A
// zero wgPort is left unset so the CRD default applies.
func newGatewayCELFixture(name, namespace string, wgPort int32, forwards []wgnetv1alpha1.Forward) *wgnetv1alpha1.Gateway {
	gw := newGateway(name, namespace, forwards, nil)
	gw.Spec.Wireguard.ListenPort = wgPort
	return gw
}

// newGatewayNoWireguard builds a Gateway as unstructured with spec.wireguard absent. A typed
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

// TestGatewayCELValidation exercises the spec-level CEL rules at admission: per-(port,protocol)
// uniqueness and the bar on a UDP forward over the WireGuard listen port.
func TestGatewayCELValidation(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	cl := te.client

	tcp := wgnetv1alpha1.ProtocolTCP
	udp := wgnetv1alpha1.ProtocolUDP

	tests := []struct {
		name string
		// omitWireguard runs the rules against the CRD-defaulted block; otherwise wgPort
		// sets the listen port explicitly (zero leaves it unset for the default).
		omitWireguard bool
		wgPort        int32
		forwards      []wgnetv1alpha1.Forward
		trafficPolicy wgnetv1alpha1.TrafficPolicy
		linkReplicas  int32
		accept        bool
		// wantMessage, when set, must appear in the rejection error.
		wantMessage string
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
		{
			name:          "local with multiple link replicas rejected",
			trafficPolicy: wgnetv1alpha1.TrafficPolicyLocal,
			linkReplicas:  2,
			accept:        false,
			wantMessage:   "spec.link.replicas applies only to trafficPolicy Cluster",
		},
		{
			name:          "local with no link block accepted",
			trafficPolicy: wgnetv1alpha1.TrafficPolicyLocal,
			accept:        true,
		},
		{
			name:          "cluster with multiple link replicas accepted",
			trafficPolicy: wgnetv1alpha1.TrafficPolicyCluster,
			linkReplicas:  2,
			accept:        true,
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
				typed := newGatewayCELFixture(ns, ns, tt.wgPort, tt.forwards)
				typed.Spec.TrafficPolicy = tt.trafficPolicy
				typed.Spec.Link.Replicas = tt.linkReplicas
				gw = typed
			}
			assertAdmission(ctx, t, cl, gw, cl.Create(ctx, gw), tt.accept, tt.wantMessage)
		})
	}
}

// TestGatewayWireguardDefaulting verifies spec.wireguard is optional: a Gateway omitting the
// block is admitted and reads back with every sub-field carrying its CRD default.
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

// portedClusterIPService builds a ClusterIP Service in ns publishing port/proto; envtest assigns
// spec.clusterIP on create, so classification sees a routable VIP.
func portedClusterIPService(ns, name string, port int32, proto corev1.Protocol) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.ServiceSpec{
			Type:  corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{{Port: port, Protocol: proto}},
		},
	}
}

// portedNodePortService builds a NodePort Service publishing port/proto; like ClusterIP it
// carries a real ClusterIP, so classification must accept it when the port matches.
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

// headlessService builds a headless ClusterIP Service (clusterIP None), which has no
// stable VIP and so backs a forward in Local mode only.
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

func TestClassifyForwards(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
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
			name: "headless service rejected in cluster mode",
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
			r := newOperatorReconciler(te, &GatewayReconciler{Config: reconcileConfig(), GenerateKey: gen})
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

// TestBackendPortOf pins the pod-side port classification hands to the NetworkPolicy builder.
// An unset targetPort is not a case here: the API server defaults it, so envtest covers it.
func TestBackendPortOf(t *testing.T) {
	tests := []struct {
		name string
		port corev1.ServicePort
		want int32
	}{
		{
			name: "numeric target port resolves to the pod port",
			port: corev1.ServicePort{Port: 443, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromInt32(10443)},
			want: 10443,
		},
		{
			name: "named target port is unresolved",
			port: corev1.ServicePort{Port: 443, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromString("https")},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := backendPortOf(&tt.port); got != tt.want {
				t.Errorf("backendPortOf = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestClassifyForwardsResolvesBackendPort runs against a real API server: every case turns on
// server-side behaviour the fake client does not reproduce, starting with targetPort defaulting.
func TestClassifyForwardsResolvesBackendPort(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	tests := []struct {
		name string
		// ports are the backing Service's published ports.
		ports []corev1.ServicePort
		// forwardPort is the public port of the single forward under test; the forward
		// carries no TargetPort, so it matches the Service port of the same number.
		forwardPort int32
		want        int32
		// wantWarning expects one UnresolvedBackendPort Warning event.
		wantWarning bool
		// local runs the case under the Local traffic policy.
		local bool
	}{
		{
			name:        "api server defaults an unset target port to the service port",
			ports:       []corev1.ServicePort{{Port: 443, Protocol: corev1.ProtocolTCP}},
			forwardPort: 443,
			want:        443,
		},
		{
			name: "forward matching the second published port resolves that port's target",
			ports: []corev1.ServicePort{
				{Name: "https", Port: 443, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromInt32(10443)},
				{Name: "http", Port: 80, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromInt32(10080)},
			},
			forwardPort: 80,
			want:        10080,
		},
		{
			name:        "named target port stays unresolved and warns",
			ports:       []corev1.ServicePort{{Port: 443, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromString("https")}},
			forwardPort: 443,
			want:        0,
			wantWarning: true,
		},
		{
			name:        "named target port in local mode warns about nothing",
			ports:       []corev1.ServicePort{{Name: "https", Port: 443, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromString("https")}},
			forwardPort: 443,
			want:        0,
			local:       true,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gwNS := fmt.Sprintf("bp-%d", i)
			mustCreate(ctx, t, cl, namespaceWithLabels(gwNS, nil))

			mustCreate(ctx, t, cl, &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: gwNS},
				Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, Ports: tt.ports},
			})

			gw := newGateway(gwNS, gwNS, []wgnetv1alpha1.Forward{
				{Port: tt.forwardPort, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
			}, nil)
			if tt.local {
				gw.Spec.TrafficPolicy = wgnetv1alpha1.TrafficPolicyLocal
			}
			rec := &fakeEventRecorder{}
			r := newOperatorReconciler(te, &GatewayReconciler{Config: reconcileConfig(), Recorder: rec})

			valid, invalid, err := r.classifyForwards(ctx, gw)
			if err != nil {
				t.Fatalf("classify forwards: %v", err)
			}
			if len(invalid) != 0 {
				t.Fatalf("invalid = %+v, want none", invalid)
			}
			if len(valid) != 1 {
				t.Fatalf("valid = %d, want 1", len(valid))
			}
			if got := valid[0].BackendPort; got != tt.want {
				t.Errorf("backend port = %d, want %d", got, tt.want)
			}

			// A second pass stands in for the steady-state requeue: the warning is tied to
			// the unresolved set changing, so the event counts also assert it is not re-emitted.
			if _, _, err := r.classifyForwards(ctx, gw); err != nil {
				t.Fatalf("classify forwards (second pass): %v", err)
			}

			if !tt.wantWarning {
				if len(rec.events) != 0 {
					t.Errorf("recorded %+v, want no events", rec.events)
				}
				return
			}
			if len(rec.events) != 1 {
				t.Fatalf("recorded %d events, want 1: %+v", len(rec.events), rec.events)
			}
			ev := rec.events[0]
			if ev.eventtype != corev1.EventTypeWarning || ev.reason != reasonUnresolvedBackendPort {
				t.Errorf("event = %s/%s, want %s/%s", ev.eventtype, ev.reason, corev1.EventTypeWarning, reasonUnresolvedBackendPort)
			}
			if !strings.Contains(ev.note, "https") {
				t.Errorf("event note = %q, want it to name the unresolved targetPort", ev.note)
			}
		})
	}
}

// TestReconcileNetworkPolicyAllowsRemappedBackendPort pins port resolution through a real apply:
// egress must open the pod port kube-proxy DNATs to, and a named targetPort a protocol-only rule.
func TestReconcileNetworkPolicyAllowsRemappedBackendPort(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	tests := []struct {
		name       string
		namespace  string
		targetPort intstr.IntOrString
		// wantPorts are the numeric TCP ports the applied policy must open to
		// 0.0.0.0/0.
		wantPorts []int32
		// wantProtocolOnly expects a port-less (whole-protocol) egress rule instead,
		// the shape an unresolved backend port renders.
		wantProtocolOnly bool
	}{
		{
			name:       "numeric target port opens both the service port and the pod port",
			namespace:  "np-remap",
			targetPort: intstr.FromInt32(10443),
			wantPorts:  []int32{443, 10443},
		},
		{
			name:             "named target port leaves a protocol-only rule",
			namespace:        "np-named",
			targetPort:       intstr.FromString("https"),
			wantProtocolOnly: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mustCreate(ctx, t, cl, namespaceWithLabels(tt.namespace, nil))

			svc := portedClusterIPService(tt.namespace, "web", 443, corev1.ProtocolTCP)
			svc.Spec.Ports[0].Name = "https"
			svc.Spec.Ports[0].TargetPort = tt.targetPort
			mustCreate(ctx, t, cl, svc)

			gw := newGateway("edge", tt.namespace, []wgnetv1alpha1.Forward{
				{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
			}, nil)
			mustCreate(ctx, t, cl, gw)

			gen, _ := countingKeyGen()
			r := newOperatorReconciler(te, &GatewayReconciler{Config: reconcileConfig(), GenerateKey: gen})
			drainReconcile(ctx, t, r, client.ObjectKeyFromObject(gw))

			var np networkingv1.NetworkPolicy
			mustGet(ctx, t, cl, client.ObjectKey{Namespace: tt.namespace, Name: "edge-link"}, &np)

			for _, port := range tt.wantPorts {
				if !hasOpenEgressPort(np.Spec.Egress, corev1.ProtocolTCP, port) {
					t.Errorf("applied networkpolicy missing egress to TCP %d: %+v", port, np.Spec.Egress)
				}
			}
			if tt.wantProtocolOnly {
				if !hasProtocolOnlyEgress(np.Spec.Egress, corev1.ProtocolTCP) {
					t.Errorf("applied networkpolicy has no protocol-only TCP egress rule: %+v", np.Spec.Egress)
				}
				if hasOpenEgressPort(np.Spec.Egress, corev1.ProtocolTCP, 443) {
					t.Errorf("applied networkpolicy pins TCP 443 for an unresolved backend port: %+v", np.Spec.Egress)
				}
			}
		})
	}
}

// isValidationDenialReason reports whether reason is one of the forward-validation denial
// reasons, used to assert an accepted forward did not land in a denied state.
func isValidationDenialReason(reason string) bool {
	switch reason {
	case reasonCrossNamespaceForwardDenied, reasonTargetNamespaceNotFound,
		reasonUnsupportedServiceType, reasonServiceNotFound, reasonTargetPortNotListening:
		return true
	default:
		return false
	}
}

// reconcileToClassification reconciles past the finalizer-add pass, which requeues before
// classification runs, and returns the result of the second pass.
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

// TestGatewayReadyProvisioningMessage exercises the operator-side fold: the composite's
// status.message is appended to the Provisioning Ready message, truncated like a link fault.
func TestGatewayReadyProvisioningMessage(t *testing.T) {
	const baseMsg = "waiting for gateway address and active link tunnel"
	longM := strings.Repeat("m", 5000)
	wantTruncated := baseMsg + ": " + longM[:maxFaultMessageBytes-len(faultMessageTruncationMarker)] + faultMessageTruncationMarker

	tests := []struct {
		name        string
		address     string
		saEmail     string
		message     string
		wantMessage string
	}{
		{name: "address empty, message empty", wantMessage: baseMsg},
		{name: "address empty, message set", message: "address not found", wantMessage: baseMsg + ": address not found"},
		{name: "address set, message empty", address: "203.0.113.60", wantMessage: baseMsg},
		{name: "address set, message set", address: "203.0.113.60", message: "bind failed", wantMessage: baseMsg + ": bind failed"},
		{name: "message over budget is truncated with the prefix kept", message: longM, wantMessage: wantTruncated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			te, r, _, key, _ := reconcileFixture(ctx, t)
			cl := te.client

			drainReconcile(ctx, t, r, key)
			setXGatewayGCPStatus(ctx, t, cl, key, tt.address, tt.saEmail, tt.message)
			drainReconcile(ctx, t, r, key)

			var got wgnetv1alpha1.Gateway
			mustGet(ctx, t, cl, key, &got)
			c := apimeta.FindStatusCondition(got.Status.Conditions, conditionReady)
			if c == nil {
				t.Fatalf("Ready condition absent")
			}
			if c.Status != metav1.ConditionFalse || c.Reason != reasonProvisioning {
				t.Fatalf("Ready = %s/%s, want False/Provisioning", c.Status, c.Reason)
			}
			if c.Message != tt.wantMessage {
				t.Errorf("Ready message = %q, want %q", c.Message, tt.wantMessage)
			}
		})
	}
}

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

func mustGet(ctx context.Context, t *testing.T, cl client.Client, key client.ObjectKey, obj client.Object) {
	t.Helper()
	if err := cl.Get(ctx, key, obj); err != nil {
		t.Fatalf("get %s %s: %v", obj.GetObjectKind().GroupVersionKind().Kind, key, err)
	}
}

// Simulates Crossplane's status write; an empty message leaves status.message unset, matching a
// composite that never wrote it.
func setXGatewayGCPStatus(ctx context.Context, t *testing.T, cl client.Client, key client.ObjectKey, address, saEmail, message string) {
	t.Helper()
	xg := newXGatewayGCP()
	mustGet(ctx, t, cl, key, xg)
	if err := unstructured.SetNestedField(xg.Object, address, "status", "address"); err != nil {
		t.Fatalf("set status.address: %v", err)
	}
	if err := unstructured.SetNestedField(xg.Object, saEmail, "status", "serviceAccountEmail"); err != nil {
		t.Fatalf("set status.serviceAccountEmail: %v", err)
	}
	if message != "" {
		if err := unstructured.SetNestedField(xg.Object, message, "status", "message"); err != nil {
			t.Fatalf("set status.message: %v", err)
		}
	}
	if err := cl.Status().Update(ctx, xg); err != nil {
		t.Fatalf("update xgatewaygcp status: %v", err)
	}
}

// setLinkLeaseActive points the link Lease holder at podName and sets that pod's PodReady
// condition, which envtest's missing scheduler and kubelet leave unset.
func setLinkLeaseActive(ctx context.Context, t *testing.T, cl client.Client, gwKey client.ObjectKey, podName string, ready bool, nodeName string) {
	t.Helper()
	leaseName := linkComponentName(&wgnetv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: gwKey.Name, Namespace: gwKey.Namespace},
	})

	upsertLeaseHolder(ctx, t, cl, client.ObjectKey{Namespace: gwKey.Namespace, Name: leaseName}, podName, nil)
	upsertPodReady(ctx, t, cl, client.ObjectKey{Namespace: gwKey.Namespace, Name: podName}, ready, nodeName)
}

// setLinkLeaseFault stamps the link-fault annotations onto the Gateway's link Lease. An empty
// reason clears them, which is how the holder signals it has finished programming.
func setLinkLeaseFault(ctx context.Context, t *testing.T, cl client.Client, gwKey client.ObjectKey, reason, message string) {
	t.Helper()
	leaseKey := client.ObjectKey{Namespace: gwKey.Namespace, Name: gwKey.Name + "-link"}

	var lease coordinationv1.Lease
	if err := cl.Get(ctx, leaseKey, &lease); err != nil {
		t.Fatalf("get link lease %s: %v", leaseKey, err)
	}
	if reason == "" {
		lease.Annotations = nil
	} else {
		lease.Annotations = map[string]string{
			link.LeaseFaultAnnotation:        reason,
			link.LeaseFaultMessageAnnotation: message,
		}
	}
	if err := cl.Update(ctx, &lease); err != nil {
		t.Fatalf("update link lease %s annotations: %v", leaseKey, err)
	}
}

// upsertLeaseHolder ensures a Lease at key exists with HolderIdentity set to holder, creating
// it on first call and patching the holder thereafter.
func upsertLeaseHolder(ctx context.Context, t *testing.T, cl client.Client, key client.ObjectKey, holder string, annotations map[string]string) {
	t.Helper()
	var lease coordinationv1.Lease
	err := cl.Get(ctx, key, &lease)
	switch {
	case apierrors.IsNotFound(err):
		lease = coordinationv1.Lease{
			ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name, Annotations: annotations},
			Spec:       coordinationv1.LeaseSpec{HolderIdentity: &holder},
		}
		if err := cl.Create(ctx, &lease); err != nil {
			t.Fatalf("create link lease %s: %v", key, err)
		}
	case err != nil:
		t.Fatalf("get link lease %s: %v", key, err)
	default:
		lease.Spec.HolderIdentity = &holder
		lease.Annotations = annotations
		if err := cl.Update(ctx, &lease); err != nil {
			t.Fatalf("update link lease %s holder: %v", key, err)
		}
	}
}

// upsertPodReady ensures a minimal pod at key has its PodReady condition set to ready, writing
// the status subresource directly since envtest has no kubelet. Idempotent across flips.
func upsertPodReady(ctx context.Context, t *testing.T, cl client.Client, key client.ObjectKey, ready bool, nodeName string) {
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
				NodeName:   nodeName,
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

func assertOwnedByGatewayUnstructured(t *testing.T, u *unstructured.Unstructured, gw *wgnetv1alpha1.Gateway) {
	t.Helper()
	assertOwnedByGateway(t, u, gw)
}

type recordedEvent struct {
	regarding runtime.Object
	eventtype string
	reason    string
	action    string
	note      string
}

// fakeEventRecorder records every Eventf call. The interface has a single method, so a generated
// mock would add nothing over capturing the args directly.
type fakeEventRecorder struct {
	events []recordedEvent
}

func (f *fakeEventRecorder) Eventf(regarding runtime.Object, _ runtime.Object, eventtype, reason, action, note string, args ...any) {
	f.events = append(f.events, recordedEvent{
		regarding: regarding,
		eventtype: eventtype,
		reason:    reason,
		action:    action,
		note:      fmt.Sprintf(note, args...),
	})
}

// TestReconcilerFailEmitsEvent covers the reconcile-failure path: fail emits a Warning event
// when a recorder is wired, and does not panic when the recorder is nil.
func TestReconcilerFailEmitsEvent(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
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
			r := newOperatorReconciler(te, &GatewayReconciler{Config: reconcileConfig()})
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

// linkConfigForwards reads the link ConfigMap rendered for the Gateway at key and returns its
// runtime forwards, the assertion surface for which forwards the operator exposed.
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

// TestMixedForwards covers per-forward classification: one valid and one invalid forward still
// provisions, exposes only the valid forward, and reports Ready=False with the invalid reason.
func TestMixedForwards(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
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
	r := newOperatorReconciler(te, &GatewayReconciler{Config: reconcileConfig(), GenerateKey: gen})
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

// TestLinkActiveReadyGate covers the active-tunnel gate: readiness follows the lease holder pod,
// so a Ready idle standby must not mask a holder that is not Ready.
func TestLinkActiveReadyGate(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	tests := []struct {
		name string
		// arrange sets up the lease/holder-pod state after the Gateway has provisioned and
		// been given an address. holderName is the name the row may use for the holder pod.
		arrange   func(t *testing.T, ns, holderName string)
		wantReady metav1.ConditionStatus
	}{
		{
			name: "holder pod ready, tunnel up",
			arrange: func(t *testing.T, ns, holderName string) {
				setLinkLeaseActive(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: "gw"}, holderName, true, "node-a")
			},
			wantReady: metav1.ConditionTrue,
		},
		{
			name: "holder pod not ready masks a ready standby",
			arrange: func(t *testing.T, ns, holderName string) {
				// The Ready standby is not the lease holder. The holder gates the tunnel,
				// and it is not Ready, so the Gateway must be Ready=False.
				upsertPodReady(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: "gw-link-standby"}, true, "node-b")
				setLinkLeaseActive(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: "gw"}, holderName, false, "node-a")
			},
			wantReady: metav1.ConditionFalse,
		},
		{
			name: "lease absent, no active tunnel",
			arrange: func(_ *testing.T, _, _ string) {
				// No lease and no holder pod: linkStatusOf must read NotFound and report
				// the tunnel as not active without erroring.
			},
			wantReady: metav1.ConditionFalse,
		},
		{
			name: "lease present but holder pod absent",
			arrange: func(t *testing.T, ns, holderName string) {
				// The lease names a missing holder pod, the failover window between the old
				// holder releasing and the new one publishing. linkStatusOf must tolerate it.
				upsertLeaseHolder(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: "gw-link"}, holderName, nil)
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
			r := newOperatorReconciler(te, &GatewayReconciler{Config: reconcileConfig(), GenerateKey: gen})

			// Provision the Gateway, then give the composite an address so the address
			// gate is satisfied and the Ready outcome turns solely on the active tunnel.
			drainReconcile(ctx, t, r, key)
			setXGatewayGCPStatus(ctx, t, cl, key, "203.0.113.30", "sa@example.iam.gserviceaccount.com", "")

			tt.arrange(t, ns, "gw-link-0")

			// Every tunnel-gate case is a non-error outcome, so a failure here means
			// linkStatusOf surfaced a NotFound as an error.
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

// startManager runs a manager on the envtest config with the GatewayReconciler registered, so
// the Service and Namespace watches are live. It is stopped via t.Cleanup.
func startManager(ctx context.Context, t *testing.T, te *testEnv) client.Client {
	t.Helper()

	mgr, err := ctrl.NewManager(te.operatorCfg, ctrl.Options{
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
			// A cancel-driven shutdown returns nil, so a non-nil error here is real and
			// worth surfacing without racing the test goroutine's t.Fatalf.
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

// pollUntil polls cond until true or timeout elapses, failing with msg. The manager-backed
// transition tests need a longer deadline than the package eventually helper.
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

// driveProvisionedReady supplies the readiness preconditions envtest cannot: it patches the
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

	// The lease and pod are not watched, so writing the watched composite status last lets its
	// reconcile observe the address and the active tunnel together and flip Ready=True.
	setLinkLeaseActive(ctx, t, direct, key, key.Name+"-link-0", true, "node-a")
	setXGatewayGCPStatus(ctx, t, direct, key, "203.0.113.20", "sa@example.iam.gserviceaccount.com", "")
}

// TestForwardValidationTransitions runs a real manager so the Service and Namespace watches
// enqueue, then drives backend changes and asserts reconvergence without a manual reconcile.
func TestForwardValidationTransitions(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
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
		// The Service publishes an unrelated port too, so removing 443 leaves it present:
		// the revocation reason must be TargetPortNotListening, not ServiceNotFound.
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

		// Removing the target port must trigger the Service watch and revoke the forward:
		// Ready=False/TargetPortNotListening, the link config empties, the Gateway keeps its VM.
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

// jsonUnmarshalString unmarshals raw into v, returning the error so a poll predicate can treat
// a not-yet-written ConfigMap as "keep waiting" rather than failing the test.
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

// addServicePort appends a published port/proto to the named Service, so the Service watch
// fires. It names every port first: a multi-port Service requires named ports.
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

// removeServicePort drops the matching port from the named Service, so the Service watch fires.
// It renames the survivors to keep the named-port invariant, and fails if no port matched.
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

// TestGatewayTrafficPolicyDefaulting verifies spec.trafficPolicy is optional and reads back as
// Cluster, so an object created before the field existed keeps its data path.
func TestGatewayTrafficPolicyDefaulting(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	cl := te.client

	const ns = "tp-default"
	mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))

	gw := newGatewayNoWireguard(ns, ns, nil)
	if err := cl.Create(ctx, gw); err != nil {
		t.Fatalf("create Gateway with omitted spec.trafficPolicy: %v", err)
	}

	var got wgnetv1alpha1.Gateway
	mustGet(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: ns}, &got)
	if got.Spec.TrafficPolicy != wgnetv1alpha1.TrafficPolicyCluster {
		t.Errorf("defaulted spec.trafficPolicy = %q, want %q", got.Spec.TrafficPolicy, wgnetv1alpha1.TrafficPolicyCluster)
	}
}

// TestGatewayTrafficPolicyImmutable pins the transition rule: the VM's ruleset is baked at boot,
// so a live mode change is rejected at admission in either direction.
func TestGatewayTrafficPolicyImmutable(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	cl := te.client

	tests := []struct {
		name string
		// omitOnCreate builds the Gateway through the unstructured path with no
		// trafficPolicy at all, so the update runs against the CRD-defaulted value.
		omitOnCreate bool
		create       wgnetv1alpha1.TrafficPolicy
		update       wgnetv1alpha1.TrafficPolicy
	}{
		{name: "local to cluster rejected", create: wgnetv1alpha1.TrafficPolicyLocal, update: wgnetv1alpha1.TrafficPolicyCluster},
		{name: "cluster to local rejected", create: wgnetv1alpha1.TrafficPolicyCluster, update: wgnetv1alpha1.TrafficPolicyLocal},
		{name: "defaulted cluster to local rejected", omitOnCreate: true, update: wgnetv1alpha1.TrafficPolicyLocal},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := fmt.Sprintf("tp-imm-%d", i)
			mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))

			if tt.omitOnCreate {
				mustCreate(ctx, t, cl, newGatewayNoWireguard(ns, ns, nil))
			} else {
				gw := newGateway(ns, ns, nil, nil)
				gw.Spec.TrafficPolicy = tt.create
				mustCreate(ctx, t, cl, gw)
			}

			var got wgnetv1alpha1.Gateway
			mustGet(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: ns}, &got)
			if tt.omitOnCreate && got.Spec.TrafficPolicy != wgnetv1alpha1.TrafficPolicyCluster {
				t.Fatalf("defaulted spec.trafficPolicy = %q, want Cluster", got.Spec.TrafficPolicy)
			}

			got.Spec.TrafficPolicy = tt.update
			assertAdmission(ctx, t, cl, &got, cl.Update(ctx, &got), false, "spec.trafficPolicy is immutable")
		})
	}
}

// TestLowestFreeLinkID pins the dense-range allocator: the lowest unused id, the caller's own id
// reused, and exhaustion reported rather than wrapped.
func TestLowestFreeLinkID(t *testing.T) {
	self := client.ObjectKey{Namespace: "wg-system", Name: "edge"}

	withIDs := func(ids ...int32) []wgnetv1alpha1.Gateway {
		gateways := make([]wgnetv1alpha1.Gateway, 0, len(ids))
		for i, id := range ids {
			gateways = append(gateways, wgnetv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Namespace: "wg-system", Name: fmt.Sprintf("other-%d", i)},
				Status:     wgnetv1alpha1.GatewayStatus{Link: wgnetv1alpha1.GatewayLinkStatus{ID: id}},
			})
		}
		return gateways
	}

	all := make([]wgnetv1alpha1.Gateway, 0, link.MaxLinkID)
	for id := int32(1); id <= link.MaxLinkID; id++ {
		all = append(all, wgnetv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: "wg-system", Name: fmt.Sprintf("g-%d", id)},
			Status:     wgnetv1alpha1.GatewayStatus{Link: wgnetv1alpha1.GatewayLinkStatus{ID: id}},
		})
	}

	tests := []struct {
		name     string
		gateways []wgnetv1alpha1.Gateway
		want     int32
		wantOK   bool
	}{
		{"empty list allocates 1", nil, 1, true},
		{"lowest gap taken", withIDs(1, 3), 2, true},
		{"cluster gateways holding no id are ignored", withIDs(0, 0), 1, true},
		{"whole range taken reports exhaustion", all, 0, false},
		{
			name: "annotated id reserves it even with status empty",
			gateways: []wgnetv1alpha1.Gateway{{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:   "wg-system",
					Name:        "restored",
					Annotations: map[string]string{linkIDAnnotation: "1"},
				},
			}},
			want:   2,
			wantOK: true,
		},
		{
			name: "malformed annotation reserves nothing",
			gateways: []wgnetv1alpha1.Gateway{{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:   "wg-system",
					Name:        "broken",
					Annotations: map[string]string{linkIDAnnotation: "not-a-number"},
				},
			}},
			want:   1,
			wantOK: true,
		},
		{
			name: "out-of-range annotation reserves nothing",
			gateways: []wgnetv1alpha1.Gateway{{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:   "wg-system",
					Name:        "over",
					Annotations: map[string]string{linkIDAnnotation: fmt.Sprint(link.MaxLinkID + 1)},
				},
			}},
			want:   1,
			wantOK: true,
		},
		{
			name: "own annotation is reusable",
			gateways: []wgnetv1alpha1.Gateway{{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:   self.Namespace,
					Name:        self.Name,
					Annotations: map[string]string{linkIDAnnotation: "1"},
				},
			}},
			want:   1,
			wantOK: true,
		},
		{
			name: "own id is reusable",
			gateways: []wgnetv1alpha1.Gateway{{
				ObjectMeta: metav1.ObjectMeta{Namespace: self.Namespace, Name: self.Name},
				Status:     wgnetv1alpha1.GatewayStatus{Link: wgnetv1alpha1.GatewayLinkStatus{ID: 1}},
			}},
			want:   1,
			wantOK: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := lowestFreeLinkID(tt.gateways, self)
			if ok != tt.wantOK {
				t.Fatalf("lowestFreeLinkID ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Errorf("lowestFreeLinkID = %d, want %d", got, tt.want)
			}
		})
	}
}

// localGatewayFixture creates a namespace, a backend Service and a Local Gateway in it,
// returning a reconciler authorized as the operator and the Gateway's key.
func localGatewayFixture(ctx context.Context, t *testing.T, te *testEnv, ns string) (*GatewayReconciler, client.ObjectKey) {
	t.Helper()
	return linkGatewayFixture(ctx, t, te, ns, wgnetv1alpha1.TrafficPolicyLocal)
}

// linkGatewayFixture creates ns, the backend Service its single forward targets, and a Gateway
// on the given traffic policy, returning a reconciler wired to the operator identity.
func linkGatewayFixture(ctx context.Context, t *testing.T, te *testEnv, ns string, policy wgnetv1alpha1.TrafficPolicy) (*GatewayReconciler, client.ObjectKey) {
	t.Helper()
	cl := te.client
	mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))
	mustCreate(ctx, t, cl, portedClusterIPService(ns, "web", 443, corev1.ProtocolTCP))

	gw := newGateway("gw", ns, []wgnetv1alpha1.Forward{
		{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
	}, nil)
	gw.Spec.TrafficPolicy = policy
	mustCreate(ctx, t, cl, gw)

	gen, _ := countingKeyGen()
	r := newOperatorReconciler(te, &GatewayReconciler{Config: reconcileConfig(), GenerateKey: gen})
	return r, client.ObjectKeyFromObject(gw)
}

// TestEnsureLinkIDIsAuthoritative pins that a persisted id is read, never recomputed even once a
// lower id frees up: the names derived from it are what a restarting link reclaims.
func TestEnsureLinkIDIsAuthoritative(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	// A squatter holds id 1 so the Gateway under test allocates 2, leaving a lower id
	// to free up.
	squatter := newGateway("squatter", "default", nil, nil)
	squatter.Spec.TrafficPolicy = wgnetv1alpha1.TrafficPolicyLocal
	mustCreate(ctx, t, cl, squatter)
	squatter.Status.Link.ID = 1
	if err := cl.Status().Update(ctx, squatter); err != nil {
		t.Fatalf("seed squatter link id: %v", err)
	}

	r, key := localGatewayFixture(ctx, t, te, "lid-auth")
	drainReconcile(ctx, t, r, key)

	var got wgnetv1alpha1.Gateway
	mustGet(ctx, t, cl, key, &got)
	if got.Status.Link.ID != 2 {
		t.Fatalf("status.link.id = %d, want 2 (1 is held by the squatter)", got.Status.Link.ID)
	}

	if err := cl.Delete(ctx, squatter); err != nil {
		t.Fatalf("delete squatter: %v", err)
	}
	drainReconcile(ctx, t, r, key)

	mustGet(ctx, t, cl, key, &got)
	if got.Status.Link.ID != 2 {
		t.Errorf("status.link.id = %d after id 1 freed, want the authoritative 2", got.Status.Link.ID)
	}
}

// seedLinkIDHolder creates a Local Gateway carrying the given status id and link id annotation,
// standing in for another Gateway that already holds an id.
func seedLinkIDHolder(ctx context.Context, t *testing.T, cl client.Client, ns, name string, statusID int32, annotation string) {
	t.Helper()
	holder := newGateway(name, ns, nil, nil)
	holder.Spec.TrafficPolicy = wgnetv1alpha1.TrafficPolicyLocal
	if annotation != "" {
		holder.Annotations = map[string]string{linkIDAnnotation: annotation}
	}
	mustCreate(ctx, t, cl, holder)
	if statusID == 0 {
		return
	}
	holder.Status.Link.ID = statusID
	if err := cl.Status().Update(ctx, holder); err != nil {
		t.Fatalf("seed link id %d on %s/%s: %v", statusID, ns, name, err)
	}
}

func setLinkIDAnnotation(ctx context.Context, t *testing.T, cl client.Client, key client.ObjectKey, value string) {
	t.Helper()
	var gw wgnetv1alpha1.Gateway
	mustGet(ctx, t, cl, key, &gw)
	if gw.Annotations == nil {
		gw.Annotations = map[string]string{}
	}
	gw.Annotations[linkIDAnnotation] = value
	if err := cl.Update(ctx, &gw); err != nil {
		t.Fatalf("set link id annotation on %s: %v", key, err)
	}
}

// TestEnsureLinkIDAnnotation pins the second record of the allocated id: an unheld annotated id
// is adopted, so a Gateway restored without status keeps the id its node state is named after.
func TestEnsureLinkIDAnnotation(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	tests := []struct {
		name string
		ns   string
		// seed runs on the created Gateway before the first reconcile.
		seed  func(key client.ObjectKey)
		check func(t *testing.T, got *wgnetv1alpha1.Gateway)
	}{
		{
			name: "restored gateway adopts its annotated id",
			ns:   "lid-restored",
			seed: func(key client.ObjectKey) { setLinkIDAnnotation(ctx, t, cl, key, "3") },
			check: func(t *testing.T, got *wgnetv1alpha1.Gateway) {
				t.Helper()
				if got.Status.Link.ID != 3 {
					t.Errorf("status.link.id = %d, want the annotated 3", got.Status.Link.ID)
				}
				if ann := got.Annotations[linkIDAnnotation]; ann != "3" {
					t.Errorf("annotation = %q, want it left at \"3\"", ann)
				}
			},
		},
		{
			name: "fresh gateway is annotated with its allocated id",
			ns:   "lid-fresh",
			check: func(t *testing.T, got *wgnetv1alpha1.Gateway) {
				t.Helper()
				assertLinkIDAnnotationMatchesStatus(t, got)
			},
		},
		{
			name: "annotated id held in another status is not adopted",
			ns:   "lid-taken-status",
			seed: func(key client.ObjectKey) {
				seedLinkIDHolder(ctx, t, cl, key.Namespace, "status-holder", 40, "")
				setLinkIDAnnotation(ctx, t, cl, key, "40")
			},
			check: func(t *testing.T, got *wgnetv1alpha1.Gateway) {
				t.Helper()
				if got.Status.Link.ID == 40 {
					t.Errorf("status.link.id = 40, want an id other than the one held in status")
				}
				assertLinkIDAnnotationMatchesStatus(t, got)
			},
		},
		{
			name: "an id another gateway only annotates is skipped",
			ns:   "lid-taken-annotation",
			seed: func(key client.ObjectKey) {
				seedLinkIDHolder(ctx, t, cl, key.Namespace, "annotation-holder", 0, "41")
			},
			check: func(t *testing.T, got *wgnetv1alpha1.Gateway) {
				t.Helper()
				if got.Status.Link.ID == 41 {
					t.Errorf("status.link.id = 41, want an id another gateway does not annotate")
				}
				assertLinkIDAnnotationMatchesStatus(t, got)
			},
		},
		{
			name: "status wins over a differing annotation",
			ns:   "lid-status-wins",
			seed: func(key client.ObjectKey) {
				setLinkIDAnnotation(ctx, t, cl, key, "42")
				var gw wgnetv1alpha1.Gateway
				mustGet(ctx, t, cl, key, &gw)
				gw.Status.Link.ID = 43
				if err := cl.Status().Update(ctx, &gw); err != nil {
					t.Fatalf("seed status link id: %v", err)
				}
			},
			check: func(t *testing.T, got *wgnetv1alpha1.Gateway) {
				t.Helper()
				if got.Status.Link.ID != 43 {
					t.Errorf("status.link.id = %d, want the authoritative 43", got.Status.Link.ID)
				}
				assertLinkIDAnnotationMatchesStatus(t, got)
			},
		},
		{
			name: "malformed annotation is replaced by a fresh allocation",
			ns:   "lid-malformed",
			seed: func(key client.ObjectKey) { setLinkIDAnnotation(ctx, t, cl, key, "not-a-number") },
			check: func(t *testing.T, got *wgnetv1alpha1.Gateway) {
				t.Helper()
				assertLinkIDAnnotationMatchesStatus(t, got)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, key := localGatewayFixture(ctx, t, te, tt.ns)
			if tt.seed != nil {
				tt.seed(key)
			}
			drainReconcile(ctx, t, r, key)

			var got wgnetv1alpha1.Gateway
			mustGet(ctx, t, cl, key, &got)
			tt.check(t, &got)
		})
	}
}

// assertLinkIDAnnotationMatchesStatus fails unless an id was allocated and the annotation
// records exactly it, which is what makes the annotation usable on a restore.
func assertLinkIDAnnotationMatchesStatus(t *testing.T, gw *wgnetv1alpha1.Gateway) {
	t.Helper()
	if gw.Status.Link.ID <= 0 {
		t.Fatalf("status.link.id = %d, want an allocated id", gw.Status.Link.ID)
	}
	want := strconv.FormatInt(int64(gw.Status.Link.ID), 10)
	if got := gw.Annotations[linkIDAnnotation]; got != want {
		t.Errorf("annotation = %q, want %q (status.link.id)", got, want)
	}
}

// TestEnsureLinkIDClusterConsumesNone pins that a Cluster Gateway allocates no id, so
// the dense range is not spent on Gateways whose data path derives nothing from it.
func TestEnsureLinkIDClusterConsumesNone(t *testing.T) {
	ctx := context.Background()
	te, r, _, key, _ := reconcileFixture(ctx, t)
	drainReconcile(ctx, t, r, key)

	var got wgnetv1alpha1.Gateway
	mustGet(ctx, t, te.client, key, &got)
	if got.Status.Link.ID != 0 {
		t.Errorf("status.link.id = %d, want 0 in Cluster mode", got.Status.Link.ID)
	}
}

// TestEnsureLinkIDExhausted pins the exhaustion path: ReconcileFailed and a regular-interval
// requeue, rather than an error backoff or reusing an id another link is programming under.
func TestEnsureLinkIDExhausted(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	mustCreate(ctx, t, cl, namespaceWithLabels("lid-full", nil))
	for id := int32(1); id <= link.MaxLinkID; id++ {
		holder := newGateway(fmt.Sprintf("holder-%d", id), "lid-full", nil, nil)
		holder.Spec.TrafficPolicy = wgnetv1alpha1.TrafficPolicyLocal
		mustCreate(ctx, t, cl, holder)
		holder.Status.Link.ID = id
		if err := cl.Status().Update(ctx, holder); err != nil {
			t.Fatalf("seed holder link id %d: %v", id, err)
		}
	}

	r, key := localGatewayFixture(ctx, t, te, "lid-exhausted")
	// The shared fixture requeues immediately; a real interval makes the reported
	// (non-error) requeue observable.
	r.Config.RequeueInterval = 30 * time.Second
	req := ctrl.Request{NamespacedName: key}

	// The finalizer-add pass succeeds; the pass that reaches allocation reports the
	// exhaustion and requeues on the regular cadence instead of erroring.
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("reconcile (finalizer pass): %v", err)
	}
	res, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("reconcile = %v, want nil error on exhaustion", err)
	}
	if res.RequeueAfter <= 0 {
		t.Errorf("RequeueAfter = %v, want the regular requeue interval", res.RequeueAfter)
	}

	var got wgnetv1alpha1.Gateway
	mustGet(ctx, t, cl, key, &got)
	cond := apimeta.FindStatusCondition(got.Status.Conditions, conditionReady)
	if cond == nil {
		t.Fatal("Ready condition absent")
	}
	if cond.Status != metav1.ConditionFalse || cond.Reason != reasonReconcileFailed {
		t.Errorf("Ready = %s/%s, want False/%s", cond.Status, cond.Reason, reasonReconcileFailed)
	}
	if !strings.Contains(cond.Message, "no free link id") {
		t.Errorf("Ready message = %q, want it to name the exhaustion", cond.Message)
	}
	if got.Status.Link.ID != 0 {
		t.Errorf("status.link.id = %d, want 0 when allocation failed", got.Status.Link.ID)
	}
}

// TestReconcileLocalAppliesDaemonSetNotDeployment pins the Local-mode workload swap through the
// operator's own RBAC, including the cluster-scoped grant that must be reaped explicitly.
func TestReconcileLocalAppliesDaemonSetNotDeployment(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	r, key := localGatewayFixture(ctx, t, te, "local-ds")
	drainReconcile(ctx, t, r, key)

	var gw wgnetv1alpha1.Gateway
	mustGet(ctx, t, cl, key, &gw)

	linkKey := client.ObjectKey{Namespace: key.Namespace, Name: key.Name + "-link"}
	if err := cl.Get(ctx, linkKey, &appsv1.DaemonSet{}); err != nil {
		t.Fatalf("get link daemonset %s: %v", linkKey, err)
	}
	for _, absent := range []struct {
		kind string
		obj  client.Object
	}{
		{"deployment", &appsv1.Deployment{}},
		{"networkpolicy", &networkingv1.NetworkPolicy{}},
		{"poddisruptionbudget", &policyv1.PodDisruptionBudget{}},
	} {
		if err := cl.Get(ctx, linkKey, absent.obj); !apierrors.IsNotFound(err) {
			t.Errorf("get link %s: err = %v, want NotFound in Local mode", absent.kind, err)
		}
	}

	crbKey := client.ObjectKey{Name: linkClusterRoleBindingName(&gw)}
	var crb rbacv1.ClusterRoleBinding
	if err := cl.Get(ctx, crbKey, &crb); err != nil {
		t.Fatalf("get link clusterrolebinding %s: %v", crbKey, err)
	}
	if crb.RoleRef.Name != linkEndpointSliceClusterRole {
		t.Errorf("roleRef = %q, want %q", crb.RoleRef.Name, linkEndpointSliceClusterRole)
	}

	if err := cl.Delete(ctx, &gw); err != nil {
		t.Fatalf("delete gateway: %v", err)
	}
	drainReconcile(ctx, t, r, key)

	if err := cl.Get(ctx, crbKey, &rbacv1.ClusterRoleBinding{}); !apierrors.IsNotFound(err) {
		t.Errorf("get link clusterrolebinding after delete: err = %v, want NotFound", err)
	}
}

// TestLinkReadyReasonPrecedence pins the Ready-reason ordering: an invalid forward over a link
// fault over Ready and Provisioning, with an unrecognised fault value ignored, never copied.
func TestLinkReadyReasonPrecedence(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	tests := []struct {
		name string
		// breakForward deletes the backend Service so classification rejects the only
		// forward, which must outrank any published fault.
		breakForward bool
		// holderReady drives the Lease holder pod's readiness gate.
		holderReady bool
		faultReason string
		// compositeMessage is the composite's status.message, which only the Provisioning
		// arm folds in; a fault or an invalid forward must win the arm and drop it.
		compositeMessage string
		wantStatus       metav1.ConditionStatus
		wantReason       string
		// wantMessage, when non-nil, asserts the whole Ready message for a row's namespace.
		wantMessage func(ns string) string
	}{
		{
			name:             "no fault and a ready holder is Ready",
			holderReady:      true,
			compositeMessage: "address: cannot find address prod-edge",
			wantStatus:       metav1.ConditionTrue,
			wantReason:       reasonReady,
			wantMessage: func(string) string {
				return "gateway address provisioned and active link tunnel up"
			},
		},
		{
			name:        "fault outranks Ready",
			holderReady: true,
			faultReason: link.FaultRPFilterStrict,
			wantStatus:  metav1.ConditionFalse,
			wantReason:  link.FaultRPFilterStrict,
		},
		{
			name:        "fault outranks Provisioning",
			holderReady: false,
			faultReason: link.FaultNoLocalEndpoint,
			wantStatus:  metav1.ConditionFalse,
			wantReason:  link.FaultNoLocalEndpoint,
		},
		{
			name:         "invalid forward outranks a fault",
			breakForward: true,
			holderReady:  true,
			faultReason:  link.FaultApplyFailed,
			wantStatus:   metav1.ConditionFalse,
			wantReason:   reasonServiceNotFound,
		},
		{
			name:             "fault outranks a composite message",
			holderReady:      true,
			faultReason:      link.FaultNoLocalEndpoint,
			compositeMessage: "instance: quota exceeded",
			wantStatus:       metav1.ConditionFalse,
			wantReason:       link.FaultNoLocalEndpoint,
			wantMessage: func(string) string {
				return "link on node-a reported " + link.FaultNoLocalEndpoint
			},
		},
		{
			name:             "invalid forward outranks a composite message",
			breakForward:     true,
			holderReady:      true,
			faultReason:      link.FaultApplyFailed,
			compositeMessage: "instance: quota exceeded",
			wantStatus:       metav1.ConditionFalse,
			wantReason:       reasonServiceNotFound,
			wantMessage: func(ns string) string {
				return fmt.Sprintf("1 forward(s) invalid: forward backend Service %q in namespace %q not found yet", "web", ns)
			},
		},
		{
			name:        "unrecognised fault value is ignored",
			holderReady: true,
			faultReason: "SomethingElse",
			wantStatus:  metav1.ConditionTrue,
			wantReason:  reasonReady,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := fmt.Sprintf("fault-%d", i)
			mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))
			svc := portedClusterIPService(ns, "web", 443, corev1.ProtocolTCP)
			mustCreate(ctx, t, cl, svc)

			gw := newGateway("gw", ns, []wgnetv1alpha1.Forward{
				{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
			}, nil)
			mustCreate(ctx, t, cl, gw)
			key := client.ObjectKeyFromObject(gw)

			gen, _ := countingKeyGen()
			r := newOperatorReconciler(te, &GatewayReconciler{Config: reconcileConfig(), GenerateKey: gen})

			drainReconcile(ctx, t, r, key)
			setXGatewayGCPStatus(ctx, t, cl, key, "203.0.113.40", "sa@example.iam.gserviceaccount.com", tt.compositeMessage)
			setLinkLeaseActive(ctx, t, cl, key, "gw-link-0", tt.holderReady, "node-a")
			setLinkLeaseFault(ctx, t, cl, key, tt.faultReason, "link on node-a reported "+tt.faultReason)

			if tt.breakForward {
				if err := cl.Delete(ctx, svc); err != nil {
					t.Fatalf("delete backend service: %v", err)
				}
			}

			if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
				t.Fatalf("reconcile: %v", err)
			}

			var got wgnetv1alpha1.Gateway
			mustGet(ctx, t, cl, key, &got)
			cond := apimeta.FindStatusCondition(got.Status.Conditions, conditionReady)
			if cond == nil {
				t.Fatal("Ready condition absent")
			}
			if cond.Status != tt.wantStatus || cond.Reason != tt.wantReason {
				t.Fatalf("Ready = %s/%s, want %s/%s (message %q)",
					cond.Status, cond.Reason, tt.wantStatus, tt.wantReason, cond.Message)
			}
			if tt.wantMessage != nil {
				if want := tt.wantMessage(ns); cond.Message != want {
					t.Errorf("Ready message = %q, want %q", cond.Message, want)
				}
			}

			if tt.wantReason != link.FaultRPFilterStrict {
				return
			}
			// Clearing the annotation is how the holder signals it finished programming;
			// the Gateway must return to Ready without any other input changing.
			setLinkLeaseFault(ctx, t, cl, key, "", "")
			if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
				t.Fatalf("reconcile after clearing the fault: %v", err)
			}
			mustGet(ctx, t, cl, key, &got)
			cond = apimeta.FindStatusCondition(got.Status.Conditions, conditionReady)
			if cond.Status != metav1.ConditionTrue || cond.Reason != reasonReady {
				t.Errorf("Ready after clearing the fault = %s/%s, want True/%s", cond.Status, cond.Reason, reasonReady)
			}
		})
	}
}

// TestLinkStatusActiveNode pins that status.link.activeNode follows the Lease holder pod's node
// and clears once the holder is gone, so kubectl names the node carrying traffic.
func TestLinkStatusActiveNode(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	mustCreate(ctx, t, cl, namespaceWithLabels("active-node", nil))
	mustCreate(ctx, t, cl, portedClusterIPService("active-node", "web", 443, corev1.ProtocolTCP))

	gw := newGateway("gw", "active-node", []wgnetv1alpha1.Forward{
		{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
	}, nil)
	mustCreate(ctx, t, cl, gw)
	key := client.ObjectKeyFromObject(gw)

	gen, _ := countingKeyGen()
	r := newOperatorReconciler(te, &GatewayReconciler{Config: reconcileConfig(), GenerateKey: gen})

	drainReconcile(ctx, t, r, key)
	setXGatewayGCPStatus(ctx, t, cl, key, "203.0.113.50", "sa@example.iam.gserviceaccount.com", "")
	setLinkLeaseActive(ctx, t, cl, key, "gw-link-0", true, "node-a")

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile with a holder on node-a: %v", err)
	}
	var got wgnetv1alpha1.Gateway
	mustGet(ctx, t, cl, key, &got)
	if got.Status.Link.ActiveNode != "node-a" {
		t.Errorf("status.link.activeNode = %q, want node-a", got.Status.Link.ActiveNode)
	}

	holderKey := client.ObjectKey{Namespace: "active-node", Name: "gw-link-0"}
	// envtest runs no kubelet, so a graceful pod delete would hang in Terminating
	// forever; force it so the holder is genuinely gone.
	holder := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: holderKey.Namespace, Name: holderKey.Name}}
	if err := cl.Delete(ctx, holder, client.GracePeriodSeconds(0)); err != nil {
		t.Fatalf("delete holder pod: %v", err)
	}
	eventually(ctx, t, "holder pod gone", func() bool {
		return apierrors.IsNotFound(cl.Get(ctx, holderKey, &corev1.Pod{}))
	})

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile after the holder disappeared: %v", err)
	}
	mustGet(ctx, t, cl, key, &got)
	if got.Status.Link.ActiveNode != "" {
		t.Errorf("status.link.activeNode = %q, want it cleared once the holder is gone", got.Status.Link.ActiveNode)
	}
}

// TestClassifyForwardsRecordsServicePortName pins that the matched Service port name is carried
// through: a Local link matches it in the EndpointSlice, and an unnamed port stays empty.
func TestClassifyForwardsRecordsServicePortName(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	tests := []struct {
		name  string
		ports []corev1.ServicePort
		want  string
	}{
		{
			name:  "unnamed single port carries no name",
			ports: []corev1.ServicePort{{Port: 443, Protocol: corev1.ProtocolTCP}},
			want:  "",
		},
		{
			name: "named port carries its name",
			ports: []corev1.ServicePort{
				{Name: "https", Port: 443, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromInt32(8443)},
				{Name: "http", Port: 80, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromInt32(8080)},
			},
			want: "https",
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := fmt.Sprintf("spn-%d", i)
			mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))
			mustCreate(ctx, t, cl, &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: ns},
				Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, Ports: tt.ports},
			})

			gw := newGateway(ns, ns, []wgnetv1alpha1.Forward{
				{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
			}, nil)
			r := newOperatorReconciler(te, &GatewayReconciler{Config: reconcileConfig(), Recorder: &fakeEventRecorder{}})

			valid, invalid, err := r.classifyForwards(ctx, gw)
			if err != nil {
				t.Fatalf("classify forwards: %v", err)
			}
			if len(invalid) != 0 || len(valid) != 1 {
				t.Fatalf("valid = %d, invalid = %+v, want 1 valid and none invalid", len(valid), invalid)
			}
			if got := valid[0].ServicePortName; got != tt.want {
				t.Errorf("servicePortName = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestClassifyForwardsHeadlessByTrafficPolicy pins which backend shapes each policy accepts:
// only Cluster mode DNATs to a ClusterIP, so only it needs one.
func TestClassifyForwardsHeadlessByTrafficPolicy(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	tests := []struct {
		name   string
		policy wgnetv1alpha1.TrafficPolicy
		// service builds the forward's backend in ns.
		service func(ns string) *corev1.Service
		// wantValid expects the forward to classify as valid.
		wantValid bool
	}{
		{
			name:      "cluster mode rejects a headless service",
			policy:    wgnetv1alpha1.TrafficPolicyCluster,
			service:   func(ns string) *corev1.Service { return headlessService(ns, "web") },
			wantValid: false,
		},
		{
			name:      "local mode accepts a headless service",
			policy:    wgnetv1alpha1.TrafficPolicyLocal,
			service:   func(ns string) *corev1.Service { return headlessService(ns, "web") },
			wantValid: true,
		},
		{
			name:      "local mode rejects an externalname service",
			policy:    wgnetv1alpha1.TrafficPolicyLocal,
			service:   func(ns string) *corev1.Service { return externalNameService(ns, "web") },
			wantValid: false,
		},
		{
			name:   "cluster mode accepts a clusterip service",
			policy: wgnetv1alpha1.TrafficPolicyCluster,
			service: func(ns string) *corev1.Service {
				return portedClusterIPService(ns, "web", 443, corev1.ProtocolTCP)
			},
			wantValid: true,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gwNS := fmt.Sprintf("hl-%d", i)
			mustCreate(ctx, t, cl, namespaceWithLabels(gwNS, nil))
			mustCreate(ctx, t, cl, tt.service(gwNS))

			forward := wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}
			gw := newGateway(gwNS, gwNS, []wgnetv1alpha1.Forward{forward}, nil)
			gw.Spec.TrafficPolicy = tt.policy
			mustCreate(ctx, t, cl, gw)

			r := newOperatorReconciler(te, &GatewayReconciler{Config: reconcileConfig()})
			valid, invalid, err := r.classifyForwards(ctx, gw)
			if err != nil {
				t.Fatalf("classify forwards: %v", err)
			}

			if !tt.wantValid {
				if len(valid) != 0 {
					t.Fatalf("valid = %+v, want the forward rejected", valid)
				}
				if len(invalid) != 1 || invalid[0].reason != reasonUnsupportedServiceType {
					t.Fatalf("invalid = %+v, want one %s", invalid, reasonUnsupportedServiceType)
				}
				return
			}

			if len(invalid) != 0 {
				t.Fatalf("invalid = %+v, want none", invalid)
			}
			if len(valid) != 1 || valid[0].Forward != forward {
				t.Fatalf("valid = %+v, want the forward carried through", valid)
			}
		})
	}
}

// TestLinkStatusHeldThroughAllForwardsInvalid pins that the all-invalid early return leaves
// status.link.activeNode alone: the link still holds its Lease and serves the last config.
func TestLinkStatusHeldThroughAllForwardsInvalid(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	mustCreate(ctx, t, cl, namespaceWithLabels("held-link", nil))

	gw := newGateway("gw", "held-link", []wgnetv1alpha1.Forward{
		{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "absent"},
	}, nil)
	mustCreate(ctx, t, cl, gw)
	key := client.ObjectKeyFromObject(gw)

	gen, _ := countingKeyGen()
	r := newOperatorReconciler(te, &GatewayReconciler{Config: reconcileConfig(), GenerateKey: gen})

	drainReconcile(ctx, t, r, key)
	setLinkLeaseActive(ctx, t, cl, key, "gw-link-0", true, "node-a")

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile with every forward invalid: %v", err)
	}

	var got wgnetv1alpha1.Gateway
	mustGet(ctx, t, cl, key, &got)
	if got.Status.Link.ActiveNode != "node-a" {
		t.Errorf("status.link.activeNode = %q, want node-a: the holder still serves", got.Status.Link.ActiveNode)
	}
	if c := apimeta.FindStatusCondition(got.Status.Conditions, conditionReady); c == nil || c.Reason != reasonServiceNotFound {
		t.Errorf("Ready condition = %+v, want False/%s", c, reasonServiceNotFound)
	}
}

// TestTruncateFaultMessage pins the condition-message budget: an oversized fault message is cut
// to a length the API accepts, on a rune boundary, and marked truncated.
func TestTruncateFaultMessage(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want func(t *testing.T, got string)
	}{
		{
			name: "short message is unchanged",
			msg:  "rp_filter is strict on node-a",
			want: func(t *testing.T, got string) {
				t.Helper()
				if got != "rp_filter is strict on node-a" {
					t.Errorf("message = %q, want it unchanged", got)
				}
			},
		},
		{
			name: "empty message is unchanged",
			msg:  "",
			want: func(t *testing.T, got string) {
				t.Helper()
				if got != "" {
					t.Errorf("message = %q, want empty", got)
				}
			},
		},
		{
			name: "message at the budget is unchanged",
			msg:  strings.Repeat("a", maxFaultMessageBytes),
			want: func(t *testing.T, got string) {
				t.Helper()
				if len(got) != maxFaultMessageBytes {
					t.Errorf("length = %d, want %d", len(got), maxFaultMessageBytes)
				}
				if strings.HasSuffix(got, faultMessageTruncationMarker) {
					t.Error("message at the budget was marked truncated")
				}
			},
		},
		{
			name: "oversized message is cut and marked",
			msg:  strings.Repeat("b", 40000),
			want: func(t *testing.T, got string) {
				t.Helper()
				if len(got) != maxFaultMessageBytes {
					t.Errorf("length = %d, want %d", len(got), maxFaultMessageBytes)
				}
				if !strings.HasSuffix(got, faultMessageTruncationMarker) {
					t.Errorf("message = %q, want the truncation marker", got[len(got)-40:])
				}
			},
		},
		{
			name: "invalid byte before the cut does not shrink it",
			msg:  "\xff" + strings.Repeat("c", 40000),
			want: func(t *testing.T, got string) {
				t.Helper()
				if len(got) != maxFaultMessageBytes {
					t.Errorf("length = %d, want %d", len(got), maxFaultMessageBytes)
				}
				if !strings.HasSuffix(got, faultMessageTruncationMarker) {
					t.Error("oversized message was not marked truncated")
				}
			},
		},
		{
			name: "multibyte message stays valid UTF-8",
			msg:  strings.Repeat("é", 40000),
			want: func(t *testing.T, got string) {
				t.Helper()
				if !utf8.ValidString(got) {
					t.Error("truncated message is not valid UTF-8")
				}
				if len(got) > maxFaultMessageBytes {
					t.Errorf("length = %d, want at most %d", len(got), maxFaultMessageBytes)
				}
				if !strings.HasSuffix(got, faultMessageTruncationMarker) {
					t.Error("oversized multibyte message was not marked truncated")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.want(t, truncateFaultMessage(tt.msg))
		})
	}
}

// linkTeardownTimeout bounds each teardown wait: several reconciles, each doing a
// handful of API round trips.
const linkTeardownTimeout = 30 * time.Second

// TestReleaseFinalizerReapsLinkLease asserts the delete path holds the finalizer until the link
// pods are gone, then reaps the Lease nothing owner-refs and a live elector would re-create.
func TestReleaseFinalizerReapsLinkLease(t *testing.T) {
	tests := []struct {
		name     string
		policy   wgnetv1alpha1.TrafficPolicy
		workload func() client.Object
		// stuck deletes the hand-made pod up front and leaves a finalizer on it, so it
		// stays Terminating the way a pod on a partitioned node does.
		stuck bool
	}{
		{
			name:     "cluster mode deletes the link deployment",
			policy:   wgnetv1alpha1.TrafficPolicyCluster,
			workload: func() client.Object { return &appsv1.Deployment{} },
		},
		{
			name:     "local mode deletes the link daemonset",
			policy:   wgnetv1alpha1.TrafficPolicyLocal,
			workload: func() client.Object { return &appsv1.DaemonSet{} },
		},
		{
			name:     "pod stuck terminating past its grace period stops holding the delete",
			policy:   wgnetv1alpha1.TrafficPolicyCluster,
			workload: func() client.Object { return &appsv1.Deployment{} },
			stuck:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			te := setupEnvtestRBAC(t)
			cl := te.client

			r, key := linkGatewayFixture(ctx, t, te, "lease-reap", tc.policy)
			drainReconcile(ctx, t, r, key)

			var gw wgnetv1alpha1.Gateway
			mustGet(ctx, t, cl, key, &gw)
			linkKey := client.ObjectKey{Namespace: key.Namespace, Name: linkComponentName(&gw)}
			if err := cl.Get(ctx, linkKey, tc.workload()); err != nil {
				t.Fatalf("get link workload %s before delete: %v", linkKey, err)
			}

			podKey := client.ObjectKey{Namespace: key.Namespace, Name: linkComponentName(&gw) + "-0"}
			pod := linkElectorPod(&gw, podKey.Name)
			if tc.stuck {
				pod.Finalizers = []string{stuckPodFinalizer}
				pod.Spec.TerminationGracePeriodSeconds = new(int64(1))
			}
			mustCreate(ctx, t, cl, pod)
			mustCreate(ctx, t, cl, &coordinationv1.Lease{
				ObjectMeta: metav1.ObjectMeta{Namespace: linkKey.Namespace, Name: linkKey.Name},
				Spec:       coordinationv1.LeaseSpec{HolderIdentity: new(podKey.Name)},
			})

			if tc.stuck {
				withLinkTeardownSlack(t, time.Second)
				if err := cl.Delete(ctx, pod); err != nil {
					t.Fatalf("delete link holder pod %s: %v", podKey, err)
				}
				t.Cleanup(func() { removePodFinalizer(context.Background(), t, cl, podKey) })
			}

			mustDeleteGateway(ctx, t, cl, key)

			if tc.stuck {
				pollUntil(ctx, t, linkTeardownTimeout, "gateway purged past the stuck pod", func() bool {
					if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
						t.Fatalf("reconcile delete past stuck pod: %v", err)
					}
					return apierrors.IsNotFound(cl.Get(ctx, key, &wgnetv1alpha1.Gateway{}))
				})
				if err := cl.Get(ctx, linkKey, &coordinationv1.Lease{}); !apierrors.IsNotFound(err) {
					t.Errorf("get link lease after purge past stuck pod = %v, want NotFound", err)
				}
				return
			}

			pollUntil(ctx, t, linkTeardownTimeout, "link workload deleted while the holder pod lives", func() bool {
				if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
					t.Fatalf("reconcile delete: %v", err)
				}
				return apierrors.IsNotFound(cl.Get(ctx, linkKey, tc.workload()))
			})

			// The elector pod still runs, so the finalizer must hold and the Lease
			// must survive: deleting it now would let the elector re-create it.
			if err := cl.Get(ctx, key, &wgnetv1alpha1.Gateway{}); err != nil {
				t.Fatalf("get gateway while holder pod lives = %v, want still present", err)
			}
			if err := cl.Get(ctx, linkKey, &coordinationv1.Lease{}); err != nil {
				t.Fatalf("get link lease while holder pod lives = %v, want still present", err)
			}

			var waiting wgnetv1alpha1.Gateway
			mustGet(ctx, t, cl, key, &waiting)
			cond := apimeta.FindStatusCondition(waiting.Status.Conditions, conditionReady)
			switch {
			case cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != reasonTerminating:
				t.Errorf("Ready condition while waiting on link pods = %+v, want False/%s", cond, reasonTerminating)
			case cond.Message != "waiting for link pods to exit: "+podKey.Name:
				t.Errorf("Ready message while waiting on link pods = %q, want %q",
					cond.Message, "waiting for link pods to exit: "+podKey.Name)
			}

			if err := cl.Delete(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: podKey.Namespace, Name: podKey.Name}}); err != nil {
				t.Fatalf("delete link holder pod %s: %v", podKey, err)
			}

			pollUntil(ctx, t, linkTeardownTimeout, "gateway purged once the holder pod is gone", func() bool {
				if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
					t.Fatalf("reconcile delete after pod removal: %v", err)
				}
				return apierrors.IsNotFound(cl.Get(ctx, key, &wgnetv1alpha1.Gateway{}))
			})

			if err := cl.Get(ctx, linkKey, &coordinationv1.Lease{}); !apierrors.IsNotFound(err) {
				t.Errorf("get link lease after gateway purge = %v, want NotFound", err)
			}
		})
	}
}

// linkElectorPod builds a minimal pod carrying the link selector labels, standing in
// for a running elector: envtest has no workload controller to create one.
func linkElectorPod(gw *wgnetv1alpha1.Gateway, name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: gw.Namespace,
			Name:      name,
			Labels:    linkSelectorLabels(gw),
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "link", Image: "registry.example.com/gateway-link:test"}},
		},
	}
}

// stuckPodFinalizer keeps a hand-made link pod in Terminating, standing in for a pod on
// a node the kubelet no longer reports from.
const stuckPodFinalizer = "wgnet.dev/test-hold-pod"

// withLinkTeardownSlack shortens the teardown slack for one test and restores it after,
// so a row can reach the stuck-pod branch without waiting out the production padding.
func withLinkTeardownSlack(t *testing.T, slack time.Duration) {
	t.Helper()
	previous := linkTeardownSlack
	linkTeardownSlack = slack
	t.Cleanup(func() { linkTeardownSlack = previous })
}

// removePodFinalizer clears the test finalizer so the pod can be collected, tolerating a
// pod already gone.
func removePodFinalizer(ctx context.Context, t *testing.T, cl client.Client, key client.ObjectKey) {
	t.Helper()
	var pod corev1.Pod
	if err := cl.Get(ctx, key, &pod); err != nil {
		if !apierrors.IsNotFound(err) {
			t.Errorf("get pod %s for finalizer removal: %v", key, err)
		}
		return
	}
	pod.Finalizers = nil
	if err := cl.Update(ctx, &pod); err != nil && !apierrors.IsNotFound(err) {
		t.Errorf("remove finalizer from pod %s: %v", key, err)
	}
}
