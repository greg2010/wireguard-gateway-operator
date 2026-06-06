package link

import (
	"context"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

// testLogger returns a no-op sugared logger; reconcile's logging is incidental
// to its behaviour, so tests do not assert on log output.
func testLogger(t *testing.T) *zap.SugaredLogger {
	t.Helper()
	return zap.NewNop().Sugar()
}

var xgatewayGVK = xgatewayGVR.GroupVersion().WithKind("XGateway")

// newFakeDynamic builds a dynamic fake client that knows the XGateway GVR->List
// mapping and is seeded with objs. The list kind is pinned and objects are
// seeded through the tracker under xgatewayGVR explicitly: the fake client's
// preset path guesses the resource name from the kind, and that heuristic
// pluralizes "XGateway" to "xgatewaies" rather than the real "xgateways",
// which would file seeds under a GVR no client call ever reads.
func newFakeDynamic(t *testing.T, objs ...*unstructured.Unstructured) dynamic.Interface {
	t.Helper()
	scheme := runtime.NewScheme()
	scheme.AddKnownTypeWithName(xgatewayGVK, &unstructured.Unstructured{})
	scheme.AddKnownTypeWithName(xgatewayGVR.GroupVersion().WithKind("XGatewayList"), &unstructured.UnstructuredList{})
	c := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme,
		map[schema.GroupVersionResource]string{
			xgatewayGVR: "XGatewayList",
		},
	)
	for _, obj := range objs {
		if err := c.Tracker().Create(xgatewayGVR, obj, obj.GetNamespace()); err != nil {
			t.Fatalf("seed xgateway %s/%s: %v", obj.GetNamespace(), obj.GetName(), err)
		}
	}
	return c
}

// newXGateway builds an unstructured XGateway in ns/name. When address is
// non-empty it is set at status.address; otherwise no status is written, to
// model the case where the provision Job has not yet observed the gateway's IP.
func newXGateway(ns, name, address string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": xgatewayGVR.GroupVersion().String(),
		"kind":       "XGateway",
		"metadata": map[string]any{
			"name":      name,
			"namespace": ns,
		},
	}}
	if address != "" {
		_ = unstructured.SetNestedField(u.Object, address, "status", "address")
	}
	return u
}

// ipSource is an injectable readIP backing store: a mutex-guarded string and
// optional error the reconcile loop reads each tick. Tests mutate it to model
// the XGateway transitioning from unprovisioned to provisioned, or its IP
// changing, without driving a fake dynamic client through the loop.
type ipSource struct {
	mu  sync.Mutex
	ip  string
	err error
}

func newIPSource(ip string) *ipSource {
	return &ipSource{ip: ip}
}

func (s *ipSource) set(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ip = ip
}

func (s *ipSource) read(_ context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ip, s.err
}

// applyRecorder is an injectable applyFunc that records the peer endpoint of
// each apply and signals each call on a channel so tests can wait deterministically
// rather than sleeping. It never shells out.
type applyRecorder struct {
	mu        sync.Mutex
	endpoints []string
	calls     chan string
}

func newApplyRecorder() *applyRecorder {
	return &applyRecorder{calls: make(chan string, 16)}
}

func (r *applyRecorder) apply(_ context.Context, rc RuntimeConfig, _, _ string) error {
	r.mu.Lock()
	r.endpoints = append(r.endpoints, rc.WireGuard.Peer.Endpoint)
	r.mu.Unlock()
	r.calls <- rc.WireGuard.Peer.Endpoint
	return nil
}

func (r *applyRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.endpoints...)
}

// waitApply blocks for the next apply endpoint or fails the test on timeout.
func waitApply(t *testing.T, r *applyRecorder) string {
	t.Helper()
	select {
	case ep := <-r.calls:
		return ep
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for apply; recorded so far: %v", r.snapshot())
		return ""
	}
}

// assertNoApply fails if an apply happens within d.
func assertNoApply(t *testing.T, r *applyRecorder, d time.Duration) {
	t.Helper()
	select {
	case ep := <-r.calls:
		t.Fatalf("unexpected apply with endpoint %q", ep)
	case <-time.After(d):
	}
}

func testRuntimeConfig() RuntimeConfig {
	return RuntimeConfig{
		WireGuard: WireGuard{
			Address: "10.99.0.2/32",
			Peer: Peer{
				AllowedIPs:          []string{"10.99.0.1/32"},
				PersistentKeepalive: 25,
			},
		},
	}
}

// startReconcile runs reconcile in a goroutine with an injected readIP and
// returns a cancel func plus a done channel carrying its return value, so tests
// can assert it does not exit early and observe its final error.
func startReconcile(t *testing.T, readIP func(context.Context) (string, error), r *applyRecorder, interval time.Duration) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	log := testLogger(t)
	done := make(chan error, 1)
	go func() {
		done <- reconcile(ctx, testRuntimeConfig(), "priv", "pub", readIP, 51820, interval, r.apply, log)
	}()
	return cancel, done
}

func TestReconcileEmptyThenPopulated(t *testing.T) {
	src := newIPSource("")
	rec := newApplyRecorder()
	cancel, done := startReconcile(t, src.read, rec, 20*time.Millisecond)
	defer cancel()

	// No gateway IP yet: the loop must wait, not apply or exit.
	assertNoApply(t, rec, 150*time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("reconcile returned early while waiting for gateway ip: %v", err)
	default:
	}

	src.set("203.0.113.5")

	if ep := waitApply(t, rec); ep != "203.0.113.5:51820" {
		t.Fatalf("apply endpoint = %q, want 203.0.113.5:51820", ep)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("reconcile returned error on cancel: %v", err)
	}
}

func TestReconcileIPChange(t *testing.T) {
	src := newIPSource("203.0.113.5")
	rec := newApplyRecorder()
	cancel, done := startReconcile(t, src.read, rec, 20*time.Millisecond)
	defer cancel()

	if ep := waitApply(t, rec); ep != "203.0.113.5:51820" {
		t.Fatalf("first apply endpoint = %q, want 203.0.113.5:51820", ep)
	}
	// Unchanged IP must not re-apply.
	assertNoApply(t, rec, 100*time.Millisecond)

	src.set("203.0.113.9")

	if ep := waitApply(t, rec); ep != "203.0.113.9:51820" {
		t.Fatalf("second apply endpoint = %q, want 203.0.113.9:51820", ep)
	}
	assertNoApply(t, rec, 100*time.Millisecond)

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("reconcile returned error on cancel: %v", err)
	}
}

func TestReconcileIdempotentUnchanged(t *testing.T) {
	src := newIPSource("203.0.113.5")
	rec := newApplyRecorder()
	cancel, done := startReconcile(t, src.read, rec, 20*time.Millisecond)
	defer cancel()

	if ep := waitApply(t, rec); ep != "203.0.113.5:51820" {
		t.Fatalf("apply endpoint = %q, want 203.0.113.5:51820", ep)
	}
	// Several more ticks with an unchanged IP must produce no further applies.
	assertNoApply(t, rec, 200*time.Millisecond)

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("reconcile returned error on cancel: %v", err)
	}

	if got := rec.snapshot(); len(got) != 1 {
		t.Fatalf("apply count = %d (%v), want exactly 1", len(got), got)
	}
}

func TestReconcileNotFoundTolerated(t *testing.T) {
	// readIP perpetually reports the gateway as unobserved (the not-found case
	// collapses to "" at the reader); the loop must wait, never apply or exit.
	src := newIPSource("")
	rec := newApplyRecorder()
	cancel, done := startReconcile(t, src.read, rec, 20*time.Millisecond)
	defer cancel()

	assertNoApply(t, rec, 200*time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("reconcile exited while gateway ip unobserved: %v", err)
	default:
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("reconcile returned error on cancel: %v", err)
	}
}

func TestReadGatewayIP(t *testing.T) {
	tcs := []struct {
		name string
		seed []*unstructured.Unstructured
		want string
	}{
		{
			name: "present",
			seed: []*unstructured.Unstructured{newXGateway("cyno-system", "gateway", "203.0.113.5")},
			want: "203.0.113.5",
		},
		{
			name: "empty_status",
			seed: []*unstructured.Unstructured{newXGateway("cyno-system", "gateway", "")},
			want: "",
		},
		{
			name: "not_found",
			seed: nil,
			want: "",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			dyn := newFakeDynamic(t, tc.seed...)
			got, err := readGatewayIP(context.Background(), dyn, "gateway", "cyno-system")
			if err != nil {
				t.Fatalf("readGatewayIP: %v", err)
			}
			if got != tc.want {
				t.Fatalf("address = %q, want %q", got, tc.want)
			}
		})
	}
}
