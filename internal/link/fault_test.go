package link

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
)

// TestLeaderFault exercises the fault the Lease holder publishes, including the
// precedence between a failed apply and unmet forwards.
func TestLeaderFault(t *testing.T) {
	const node = "node-a"

	// A folded stderr big enough to make the Lease update itself fail, and what the
	// bound leaves of it.
	oversizedErr := fmt.Errorf("nft -f -: %s", strings.Repeat("x", 8000))
	oversizedWant := (node + ": apply: " + oversizedErr.Error())[:maxFaultMessageBytes-len(faultMessageTruncationMarker)] + faultMessageTruncationMarker

	tcs := []struct {
		name        string
		applyErr    error
		unsatisfied []unsatisfiedForward
		wantReason  string
		wantMessage string
	}{
		{
			name:       "healthy_holder_clears",
			wantReason: "",
		},
		{
			name:        "unmet_forwards_report_no_local_endpoint",
			unsatisfied: []unsatisfiedForward{{name: "web", reason: reasonNoLocalPod}, {name: "api", reason: reasonWatchUnsynced}},
			wantReason:  FaultNoLocalEndpoint,
			wantMessage: "node-a: forwards without a ready local endpoint: web (no ready backend pod on this node), api (endpoint watch not synced)",
		},
		{
			name:        "apply_failure_reports_apply_failed",
			applyErr:    fmt.Errorf("nft -f -: exit status 1"),
			unsatisfied: []unsatisfiedForward{{name: "web", reason: reasonNoLocalPod}},
			wantReason:  FaultApplyFailed,
			wantMessage: "node-a: apply: nft -f -: exit status 1",
		},
		{
			name:        "oversized_apply_failure_is_bounded",
			applyErr:    oversizedErr,
			wantReason:  FaultApplyFailed,
			wantMessage: oversizedWant,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			reason, message := leaderFault(node, tc.applyErr, tc.unsatisfied)
			if reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", reason, tc.wantReason)
			}
			if message != tc.wantMessage {
				t.Errorf("message = %q, want %q", message, tc.wantMessage)
			}
			if len(message) > maxFaultMessageBytes {
				t.Errorf("message is %d bytes, want at most %d", len(message), maxFaultMessageBytes)
			}
		})
	}
}

// TestLeaderReconcilePublishesFault covers the holder's fault channel: an unmet forward reaches the
// Lease as NoLocalEndpoint and a failed apply as ApplyFailed, which also gates standby readiness.
func TestLeaderReconcilePublishesFault(t *testing.T) {
	const namespace, leaseName, node = "gw-ns", "gw-link", "node-a"

	forwards := []Forward{
		{Name: "web", PublicPort: 443, Protocol: "tcp", Namespace: namespace, ServiceName: "web"},
		{Name: "api", PublicPort: 8443, Protocol: "tcp", Namespace: namespace, ServiceName: "api"},
	}
	satisfiedIndexer := newTestIndexer(t)
	addSlices(t, satisfiedIndexer, makeSlice("web-abcde", discoveryv1.AddressTypeIPv4,
		[]discoveryv1.EndpointPort{{Name: new(""), Port: new(int32(9080))}},
		epEntry([]string{"10.244.1.7"}, node, new(true)),
	))

	gwIdent := NewGatewayIdentity(1)
	localRC := RuntimeConfig{
		TrafficPolicy: TrafficPolicyLocal,
		Identity:      &gwIdent,
		Forwards:      forwards,
	}

	tcs := []struct {
		name          string
		watcher       *endpointWatcher
		applyResults  []SlotResult
		applyErr      error
		wantReason    string
		wantMessage   string
		wantGateFault string
	}{
		{
			name: "unmet_forward_publishes_no_local_endpoint",
			watcher: newWatcherFromIndexers(node, forwards, map[endpointWatcherKey]cache.Indexer{
				{namespace: namespace, serviceName: "web"}: satisfiedIndexer,
				{namespace: namespace, serviceName: "api"}: newTestIndexer(t),
			}),
			applyResults: []SlotResult{{Slot: 0, Applied: true}},
			wantReason:   FaultNoLocalEndpoint,
			wantMessage:  "node-a: forwards without a ready local endpoint: api (no ready backend pod on this node)",
		},
		{
			name: "failed_apply_publishes_and_gates",
			watcher: newWatcherFromIndexers(node, forwards, map[endpointWatcherKey]cache.Indexer{
				{namespace: namespace, serviceName: "web"}: satisfiedIndexer,
				{namespace: namespace, serviceName: "api"}: satisfiedIndexer,
			}),
			applyErr:      fmt.Errorf("nft -f -: exit status 1"),
			wantReason:    FaultApplyFailed,
			wantMessage:   "node-a: apply: nft -f -: exit status 1",
			wantGateFault: FaultApplyFailed,
		},
		{
			name: "every_forward_satisfied_clears",
			watcher: newWatcherFromIndexers(node, forwards, map[endpointWatcherKey]cache.Indexer{
				{namespace: namespace, serviceName: "web"}: satisfiedIndexer,
				{namespace: namespace, serviceName: "api"}: satisfiedIndexer,
			}),
			applyResults: []SlotResult{{Slot: 0, Applied: true}},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			lease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{
				Name:        leaseName,
				Namespace:   namespace,
				Annotations: map[string]string{LeaseFaultAnnotation: "stale", LeaseFaultMessageAnnotation: "stale"},
			}}
			cs := fake.NewClientset(lease)
			rd := newReadiness(true, 1, time.Now, nil, testLogger(t))
			cfg := Config{PodNamespace: namespace, LeaseName: leaseName, NodeName: node}

			reconcile := newLeaderReconcile(cs, cfg, rd, preCheckFault{},
				func(context.Context, RuntimeConfig, string, []ResolvedForward) ([]SlotResult, error) {
					return tc.applyResults, tc.applyErr
				},
				testLogger(t))

			forwards, unsatisfied, _ := tc.watcher.snapshot()
			_, err := reconcile(context.Background(), localRC, "priv", forwards, unsatisfied)
			if (err != nil) != (tc.applyErr != nil) {
				t.Fatalf("reconcile error = %v, want %v", err, tc.applyErr)
			}

			got, err := cs.CoordinationV1().Leases(namespace).Get(context.Background(), leaseName, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("get lease: %v", err)
			}
			if got.Annotations[LeaseFaultAnnotation] != tc.wantReason {
				t.Errorf("lease fault = %q, want %q", got.Annotations[LeaseFaultAnnotation], tc.wantReason)
			}
			if got.Annotations[LeaseFaultMessageAnnotation] != tc.wantMessage {
				t.Errorf("lease fault message = %q, want %q", got.Annotations[LeaseFaultMessageAnnotation], tc.wantMessage)
			}
			if rd.gatingFault() != tc.wantGateFault {
				t.Errorf("gating fault = %q, want %q", rd.gatingFault(), tc.wantGateFault)
			}
		})
	}
}

// TestLeaderReconcileRetriesAfterFailedPublish pins that a fault the holder could not publish does
// not count as applied: the loop records no digest and the next tick applies the same config again.
func TestLeaderReconcileRetriesAfterFailedPublish(t *testing.T) {
	// No Lease object, so every publish attempt fails on the Get.
	cs := fake.NewClientset()
	rd := newReadiness(false, 0, time.Now, nil, testLogger(t))

	applied := make(chan struct{}, 8)
	reconcile := newLeaderReconcile(cs, Config{PodNamespace: "gw-ns", LeaseName: "gw-link", NodeName: "node-a"},
		rd, preCheckFault{},
		func(context.Context, RuntimeConfig, string, []ResolvedForward) ([]SlotResult, error) {
			applied <- struct{}{}
			return nil, nil
		}, testLogger(t))

	path := filepath.Join(t.TempDir(), "config.json")
	writeConfig(t, path, configJSON("203.0.113.5:51820", "web.default.svc"))
	cfg := Config{ConfigPath: path, ReconcileInterval: 20 * time.Millisecond}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- watchAndReload(ctx, cfg, nil, nil, false, "priv", reconcile, noReassert, testLogger(t))
	}()

	for i := range 2 {
		select {
		case <-applied:
		case <-time.After(2 * time.Second):
			t.Fatalf("apply %d never happened; a failed publish must leave the digests unset so the next tick retries", i+1)
		}
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("watchAndReload returned error on cancel: %v", err)
	}
}

// TestLeaderReconcileRefusesToProgramFaultedNode pins that a node the startup pre-check failed
// is never programmed: no interface, sysctl, route or nft table is installed, no digest kept.
func TestLeaderReconcileRefusesToProgramFaultedNode(t *testing.T) {
	const namespace, leaseName, node = "gw-ns", "gw-link", "node-a"
	rpFilter := preCheckFault{Reason: FaultRPFilterStrict, Message: node + ": rp_filter is 1"}

	tcs := []struct {
		name        string
		preCheck    preCheckFault
		wantApplied bool
		wantErr     bool
		wantReason  string
		wantMessage string
	}{
		{
			name:        "node_fault_skips_apply",
			preCheck:    rpFilter,
			wantErr:     true,
			wantReason:  rpFilter.Reason,
			wantMessage: rpFilter.Message,
		},
		{
			name:        "healthy_node_applies",
			wantApplied: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			lease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{
				Name:        leaseName,
				Namespace:   namespace,
				Annotations: map[string]string{LeaseFaultAnnotation: "stale", LeaseFaultMessageAnnotation: "stale"},
			}}
			cs := fake.NewClientset(lease)
			rd := newReadiness(true, 1, time.Now, nil, testLogger(t))
			rd.setNodeFault(tc.preCheck.Reason)

			applied := false
			reconcile := newLeaderReconcile(cs, Config{PodNamespace: namespace, LeaseName: leaseName, NodeName: node},
				rd, tc.preCheck,
				func(context.Context, RuntimeConfig, string, []ResolvedForward) ([]SlotResult, error) {
					applied = true
					return []SlotResult{{Slot: 0, Applied: true}}, nil
				}, testLogger(t))

			gwIdent := NewGatewayIdentity(1)
			rc := RuntimeConfig{TrafficPolicy: TrafficPolicyLocal, Identity: &gwIdent}
			_, err := reconcile(context.Background(), rc, "priv", nil, nil)
			if (err != nil) != tc.wantErr {
				t.Fatalf("reconcile error = %v, want error %v", err, tc.wantErr)
			}
			if applied != tc.wantApplied {
				t.Errorf("apply called = %v, want %v", applied, tc.wantApplied)
			}

			got, getErr := cs.CoordinationV1().Leases(namespace).Get(context.Background(), leaseName, metav1.GetOptions{})
			if getErr != nil {
				t.Fatalf("get lease: %v", getErr)
			}
			if got.Annotations[LeaseFaultAnnotation] != tc.wantReason {
				t.Errorf("lease fault = %q, want %q", got.Annotations[LeaseFaultAnnotation], tc.wantReason)
			}
			if got.Annotations[LeaseFaultMessageAnnotation] != tc.wantMessage {
				t.Errorf("lease fault message = %q, want %q", got.Annotations[LeaseFaultMessageAnnotation], tc.wantMessage)
			}
		})
	}
}

// TestPublishFault covers the writes publishFault issues: an unchanged fault issues none, since a
// needless write invalidates the elector's cached resourceVersion and can delay the successor.
func TestPublishFault(t *testing.T) {
	const namespace, leaseName, self = "gw-ns", "gw-link", "gw-link-abc"

	tcs := []struct {
		name        string
		annotations map[string]string
		holder      string
		reason      string
		message     string
		wantUpdates int
		wantReason  string
		wantMessage string
	}{
		{
			name:        "first_fault_is_written",
			reason:      FaultApplyFailed,
			message:     "node-a: apply failed",
			wantUpdates: 1,
			wantReason:  FaultApplyFailed,
			wantMessage: "node-a: apply failed",
		},
		{
			name: "unchanged_fault_is_not_written",
			annotations: map[string]string{
				LeaseFaultAnnotation:        FaultApplyFailed,
				LeaseFaultMessageAnnotation: "node-a: apply failed",
			},
			reason:      FaultApplyFailed,
			message:     "node-a: apply failed",
			wantReason:  FaultApplyFailed,
			wantMessage: "node-a: apply failed",
		},
		{
			name: "changed_message_is_written",
			annotations: map[string]string{
				LeaseFaultAnnotation:        FaultApplyFailed,
				LeaseFaultMessageAnnotation: "node-a: apply failed",
			},
			reason:      FaultApplyFailed,
			message:     "node-a: apply failed again",
			wantUpdates: 1,
			wantReason:  FaultApplyFailed,
			wantMessage: "node-a: apply failed again",
		},
		{
			name: "fault_is_cleared",
			annotations: map[string]string{
				LeaseFaultAnnotation:        FaultApplyFailed,
				LeaseFaultMessageAnnotation: "node-a: apply failed",
			},
			wantUpdates: 1,
		},
		{
			name:        "clearing_an_unfaulted_lease_is_not_written",
			wantUpdates: 0,
		},
		{
			name: "own_lease_is_cleared",
			annotations: map[string]string{
				LeaseFaultAnnotation:        FaultApplyFailed,
				LeaseFaultMessageAnnotation: "node-a: apply failed",
			},
			holder:      self,
			wantUpdates: 1,
		},
		{
			name:    "another_holder_is_not_written",
			holder:  "gw-link-xyz",
			reason:  FaultApplyFailed,
			message: "node-a: apply failed",
		},
		{
			name: "another_holder_fault_is_not_cleared",
			annotations: map[string]string{
				LeaseFaultAnnotation:        FaultNoLocalEndpoint,
				LeaseFaultMessageAnnotation: "node-b: no ready local endpoint",
			},
			holder:      "gw-link-xyz",
			wantReason:  FaultNoLocalEndpoint,
			wantMessage: "node-b: no ready local endpoint",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			lease := &coordinationv1.Lease{
				ObjectMeta: metav1.ObjectMeta{Name: leaseName, Namespace: namespace, Annotations: tc.annotations},
			}
			if tc.holder != "" {
				lease.Spec.HolderIdentity = new(tc.holder)
			}
			cs := fake.NewClientset(lease)
			var updates int
			cs.PrependReactor("update", "leases", func(k8stesting.Action) (bool, runtime.Object, error) {
				updates++
				return false, nil, nil
			})

			if err := publishFault(context.Background(), cs, namespace, leaseName, self, tc.reason, tc.message, testLogger(t)); err != nil {
				t.Fatalf("publishFault: %v", err)
			}

			if updates != tc.wantUpdates {
				t.Errorf("lease updates = %d, want %d", updates, tc.wantUpdates)
			}
			got, err := cs.CoordinationV1().Leases(namespace).Get(context.Background(), leaseName, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("get lease: %v", err)
			}
			if got.Annotations[LeaseFaultAnnotation] != tc.wantReason {
				t.Errorf("lease fault = %q, want %q", got.Annotations[LeaseFaultAnnotation], tc.wantReason)
			}
			if got.Annotations[LeaseFaultMessageAnnotation] != tc.wantMessage {
				t.Errorf("lease fault message = %q, want %q", got.Annotations[LeaseFaultMessageAnnotation], tc.wantMessage)
			}
		})
	}
}

// TestKnownFaults pins that every fault reason the link can publish is exported through
// KnownFaults, since the operator accepts no reason missing from it, and that it returns a copy.
func TestKnownFaults(t *testing.T) {
	tcs := []struct {
		name   string
		reason string
	}{
		{name: "rp_filter_strict", reason: FaultRPFilterStrict},
		{name: "apply_failed", reason: FaultApplyFailed},
		{name: "no_local_endpoint", reason: FaultNoLocalEndpoint},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if known := KnownFaults(); !slices.Contains(known, tc.reason) {
				t.Errorf("KnownFaults() = %v, missing %q", known, tc.reason)
			}
		})
	}

	known := KnownFaults()
	if len(known) != len(tcs) {
		t.Errorf("KnownFaults() has %d reasons, want the %d in this table", len(known), len(tcs))
	}

	known[0] = "mutated"
	if slices.Contains(KnownFaults(), "mutated") {
		t.Error("KnownFaults() returned a slice a caller can mutate")
	}
}

// TestPublishSlotState covers publishSlotState's writes to LeaseSlotStateAnnotation, distinct
// from and never touching the Gateway-wide fault annotation.
func TestPublishSlotState(t *testing.T) {
	const namespace, leaseName, self = "gw-ns", "gw-link", "gw-link-abc"

	tcs := []struct {
		name       string
		results    []SlotResult
		wantStates map[string]SlotState
		wantHasAnn bool
	}{
		{
			name:       "publishes_down_slot_with_message",
			results:    []SlotResult{{Slot: 1, Applied: false, Err: fmt.Errorf("ip link add wg-gw7-1: File exists")}},
			wantStates: map[string]SlotState{"1": {State: "down", Message: "ip link add wg-gw7-1: File exists"}},
			wantHasAnn: true,
		},
		{
			name: "applied_slots_published_alongside_down",
			results: []SlotResult{
				{Slot: 0, Applied: true},
				{Slot: 1, Applied: false, Err: fmt.Errorf("ip link add wg-gw7-1: File exists")},
			},
			wantStates: map[string]SlotState{
				"0": {State: "applied"},
				"1": {State: "down", Message: "ip link add wg-gw7-1: File exists"},
			},
			wantHasAnn: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			lease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: leaseName, Namespace: namespace}}
			cs := fake.NewClientset(lease)

			if err := publishSlotState(context.Background(), cs, namespace, leaseName, self, tc.results, testLogger(t)); err != nil {
				t.Fatalf("publishSlotState: %v", err)
			}

			got, err := cs.CoordinationV1().Leases(namespace).Get(context.Background(), leaseName, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("get lease: %v", err)
			}
			raw, has := got.Annotations[LeaseSlotStateAnnotation]
			if has != tc.wantHasAnn {
				t.Fatalf("slot state annotation present = %v, want %v", has, tc.wantHasAnn)
			}
			var states map[string]SlotState
			if err := json.Unmarshal([]byte(raw), &states); err != nil {
				t.Fatalf("decode slot state annotation %q: %v", raw, err)
			}
			if len(states) != len(tc.wantStates) {
				t.Fatalf("slot state = %+v, want %+v", states, tc.wantStates)
			}
			for slot, want := range tc.wantStates {
				if got := states[slot]; got != want {
					t.Errorf("slot %s state = %+v, want %+v", slot, got, want)
				}
			}
		})
	}
}

// TestPublishSlotStateLeavesGatewayFaultUntouched preserves the Gateway fault annotation.
func TestPublishSlotStateLeavesGatewayFaultUntouched(t *testing.T) {
	const namespace, leaseName, self = "gw-ns", "gw-link", "gw-link-abc"
	lease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{
		Name:      leaseName,
		Namespace: namespace,
		Annotations: map[string]string{
			LeaseFaultAnnotation:        "stale",
			LeaseFaultMessageAnnotation: "stale message",
		},
	}}
	cs := fake.NewClientset(lease)
	results := []SlotResult{{Slot: 1, Applied: false, Err: fmt.Errorf("ip link add wg-gw7-1: File exists")}}

	if err := publishSlotState(context.Background(), cs, namespace, leaseName, self, results, testLogger(t)); err != nil {
		t.Fatalf("publishSlotState: %v", err)
	}

	got, err := cs.CoordinationV1().Leases(namespace).Get(context.Background(), leaseName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get lease: %v", err)
	}
	if got.Annotations[LeaseFaultAnnotation] != "stale" {
		t.Errorf("gateway fault annotation = %q, want unchanged %q", got.Annotations[LeaseFaultAnnotation], "stale")
	}
	if got.Annotations[LeaseFaultMessageAnnotation] != "stale message" {
		t.Errorf("gateway fault message annotation = %q, want unchanged %q", got.Annotations[LeaseFaultMessageAnnotation], "stale message")
	}
}
