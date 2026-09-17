package link

import (
	"context"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

const (
	tunnelLockNamespace = "default"
	tunnelLockName      = "gw-link"
	tunnelLockIdentity  = "gw-link-0"
)

func newTestRecord(identity string) resourcelock.LeaderElectionRecord {
	return resourcelock.LeaderElectionRecord{
		HolderIdentity:       identity,
		LeaseDurationSeconds: 15,
		AcquireTime:          metav1.Time{Time: time.Unix(1700000000, 0)},
		RenewTime:            metav1.Time{Time: time.Unix(1700000010, 0)},
	}
}

// TestTunnelLeaseLockCreate pins that Create stamps both tunnel-state annotations from the state
// function, table-driven over ready and not-ready results.
func TestTunnelLeaseLockCreate(t *testing.T) {
	tests := []struct {
		name       string
		ready      bool
		reason     string
		wantReady  string
		wantReason string
	}{
		{name: "ready clears the reason", ready: true, reason: "ignored while ready", wantReady: "true", wantReason: ""},
		{name: "not ready carries the reason", ready: false, reason: "no recent handshake", wantReady: "false", wantReason: "no recent handshake"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewClientset()
			lock := newTunnelLeaseLock(tunnelLockNamespace, tunnelLockName, cs.CoordinationV1(), tunnelLockIdentity,
				func(context.Context) (bool, string) { return tc.ready, tc.reason })

			if err := lock.Create(context.Background(), newTestRecord(tunnelLockIdentity)); err != nil {
				t.Fatalf("Create: %v", err)
			}

			lease, err := cs.CoordinationV1().Leases(tunnelLockNamespace).Get(context.Background(), tunnelLockName, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("get lease: %v", err)
			}
			if got := lease.Annotations[LeaseTunnelReadyAnnotation]; got != tc.wantReady {
				t.Errorf("%s = %q, want %q", LeaseTunnelReadyAnnotation, got, tc.wantReady)
			}
			if got := lease.Annotations[LeaseTunnelReasonAnnotation]; got != tc.wantReason {
				t.Errorf("%s = %q, want %q", LeaseTunnelReasonAnnotation, got, tc.wantReason)
			}
			if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != tunnelLockIdentity {
				t.Errorf("HolderIdentity = %v, want %q", lease.Spec.HolderIdentity, tunnelLockIdentity)
			}
		})
	}
}

// TestTunnelLeaseLockUpdateReflectsStateFlip pins that Update re-stamps the annotations on every
// call, so the Lease shows "true" as soon as the state function's result flips.
func TestTunnelLeaseLockUpdateReflectsStateFlip(t *testing.T) {
	ready := false
	cs := fake.NewClientset()
	lock := newTunnelLeaseLock(tunnelLockNamespace, tunnelLockName, cs.CoordinationV1(), tunnelLockIdentity,
		func(context.Context) (bool, string) {
			if ready {
				return true, ""
			}
			return false, "no recent handshake"
		})

	if err := lock.Create(context.Background(), newTestRecord(tunnelLockIdentity)); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, _, err := lock.Get(context.Background()); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if err := lock.Update(context.Background(), newTestRecord(tunnelLockIdentity)); err != nil {
		t.Fatalf("Update (not ready): %v", err)
	}

	lease, err := cs.CoordinationV1().Leases(tunnelLockNamespace).Get(context.Background(), tunnelLockName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get lease: %v", err)
	}
	if got := lease.Annotations[LeaseTunnelReadyAnnotation]; got != "false" {
		t.Fatalf("%s = %q, want %q before the flip", LeaseTunnelReadyAnnotation, got, "false")
	}

	ready = true
	if err := lock.Update(context.Background(), newTestRecord(tunnelLockIdentity)); err != nil {
		t.Fatalf("Update (ready): %v", err)
	}

	lease, err = cs.CoordinationV1().Leases(tunnelLockNamespace).Get(context.Background(), tunnelLockName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get lease: %v", err)
	}
	if got := lease.Annotations[LeaseTunnelReadyAnnotation]; got != "true" {
		t.Errorf("%s = %q, want %q after the flip", LeaseTunnelReadyAnnotation, got, "true")
	}
	if got := lease.Annotations[LeaseTunnelReasonAnnotation]; got != "" {
		t.Errorf("%s = %q, want empty once ready", LeaseTunnelReasonAnnotation, got)
	}
}

// TestTunnelLeaseLockGetPreservesOtherAnnotations pins that Get decodes the record and Update
// leaves an annotation the lock does not own, such as the fault annotation, untouched.
func TestTunnelLeaseLockGetPreservesOtherAnnotations(t *testing.T) {
	cs := fake.NewClientset(&coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   tunnelLockNamespace,
			Name:        tunnelLockName,
			Annotations: map[string]string{LeaseFaultAnnotation: FaultApplyFailed},
		},
		Spec: resourcelock.LeaderElectionRecordToLeaseSpec(&resourcelock.LeaderElectionRecord{HolderIdentity: tunnelLockIdentity}),
	})
	lock := newTunnelLeaseLock(tunnelLockNamespace, tunnelLockName, cs.CoordinationV1(), tunnelLockIdentity,
		func(context.Context) (bool, string) { return true, "" })

	record, _, err := lock.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if record.HolderIdentity != tunnelLockIdentity {
		t.Fatalf("record.HolderIdentity = %q, want %q", record.HolderIdentity, tunnelLockIdentity)
	}

	if err := lock.Update(context.Background(), newTestRecord(tunnelLockIdentity)); err != nil {
		t.Fatalf("Update: %v", err)
	}

	lease, err := cs.CoordinationV1().Leases(tunnelLockNamespace).Get(context.Background(), tunnelLockName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get lease: %v", err)
	}
	if got := lease.Annotations[LeaseFaultAnnotation]; got != FaultApplyFailed {
		t.Errorf("%s = %q, want %q preserved from the fetched lease", LeaseFaultAnnotation, got, FaultApplyFailed)
	}
	if got := lease.Annotations[LeaseTunnelReadyAnnotation]; got != "true" {
		t.Errorf("%s = %q, want %q", LeaseTunnelReadyAnnotation, got, "true")
	}
}

// TestTunnelLeaseLockIdentityAndDescribe pins the lock's static Identity and Describe strings,
// which the leader elector relies on to name the holder and the resource it contends for.
func TestTunnelLeaseLockIdentityAndDescribe(t *testing.T) {
	cs := fake.NewClientset()
	lock := newTunnelLeaseLock(tunnelLockNamespace, tunnelLockName, cs.CoordinationV1(), tunnelLockIdentity,
		func(context.Context) (bool, string) { return true, "" })
	if got := lock.Identity(); got != tunnelLockIdentity {
		t.Errorf("Identity() = %q, want %q", got, tunnelLockIdentity)
	}
	if want := tunnelLockNamespace + "/" + tunnelLockName; lock.Describe() != want {
		t.Errorf("Describe() = %q, want %q", lock.Describe(), want)
	}
}
