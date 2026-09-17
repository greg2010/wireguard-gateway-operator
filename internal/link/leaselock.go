package link

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coordinationv1client "k8s.io/client-go/kubernetes/typed/coordination/v1"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

// LeaseTunnelReadyAnnotation records the Lease holder's tunnel state, "true" or "false", written
// on every Lease commit the holder makes so the operator never sees a stale HolderIdentity without
// its readiness. Absent on a Lease no tunnelLeaseLock has ever written.
const LeaseTunnelReadyAnnotation = "wgnet.dev/tunnel-ready"

// LeaseTunnelReasonAnnotation carries the reason LeaseTunnelReadyAnnotation is "false", empty once
// the tunnel is ready.
const LeaseTunnelReasonAnnotation = "wgnet.dev/tunnel-reason"

// tunnelState reports the current holder's tunnel readiness, sampled fresh on every Lease write.
type tunnelState func(ctx context.Context) (ready bool, reason string)

// tunnelLeaseLock mirrors client-go's resourcelock.LeaseLock, stamping the holder's tunnel state
// on every Lease write; a standby never wins a write, so the annotations describe the holder.
type tunnelLeaseLock struct {
	namespace, name string
	client          coordinationv1client.LeasesGetter
	identity        string
	state           tunnelState
	lease           *coordinationv1.Lease
}

// newTunnelLeaseLock builds a Lease lock for namespace/name under identity, annotating every
// write it makes with state's result.
func newTunnelLeaseLock(namespace, name string, client coordinationv1client.LeasesGetter, identity string, state tunnelState) *tunnelLeaseLock {
	return &tunnelLeaseLock{namespace: namespace, name: name, client: client, identity: identity, state: state}
}

// Get fetches the Lease and decodes its record, keeping the fetched object for the Update this
// cycle's acquire or renew write may follow it with.
func (l *tunnelLeaseLock) Get(ctx context.Context) (*resourcelock.LeaderElectionRecord, []byte, error) {
	lease, err := l.client.Leases(l.namespace).Get(ctx, l.name, metav1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}
	l.lease = lease
	record := resourcelock.LeaseSpecToLeaderElectionRecord(&lease.Spec)
	recordBytes, err := json.Marshal(*record)
	if err != nil {
		return nil, nil, err
	}
	return record, recordBytes, nil
}

// Create creates the Lease with ler's record and this write's tunnel-state annotations.
func (l *tunnelLeaseLock) Create(ctx context.Context, ler resourcelock.LeaderElectionRecord) error {
	lease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Name: l.name, Namespace: l.namespace},
		Spec:       resourcelock.LeaderElectionRecordToLeaseSpec(&ler),
	}
	l.annotate(ctx, lease)
	created, err := l.client.Leases(l.namespace).Create(ctx, lease, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	l.lease = created
	return nil
}

// Update rewrites the Lease Get or Create fetched with ler's record and this write's fresh
// tunnel-state annotations, leaving every other annotation on the fetched object intact.
func (l *tunnelLeaseLock) Update(ctx context.Context, ler resourcelock.LeaderElectionRecord) error {
	if l.lease == nil {
		return errors.New("lease not initialized, call get or create first")
	}
	l.lease.Spec = resourcelock.LeaderElectionRecordToLeaseSpec(&ler)
	l.annotate(ctx, l.lease)
	updated, err := l.client.Leases(l.namespace).Update(ctx, l.lease, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	l.lease = updated
	return nil
}

// annotate stamps lease with l.state's current result, clearing the reason once ready.
func (l *tunnelLeaseLock) annotate(ctx context.Context, lease *coordinationv1.Lease) {
	if lease.Annotations == nil {
		lease.Annotations = map[string]string{}
	}
	ready, reason := l.state(ctx)
	if ready {
		reason = ""
	}
	lease.Annotations[LeaseTunnelReadyAnnotation] = strconv.FormatBool(ready)
	lease.Annotations[LeaseTunnelReasonAnnotation] = reason
}

// RecordEvent is a no-op: the elector's Lease events are not surfaced anywhere this lock's
// caller consumes.
func (l *tunnelLeaseLock) RecordEvent(string) {}

// Describe identifies the Lease this lock contends for.
func (l *tunnelLeaseLock) Describe() string {
	return fmt.Sprintf("%s/%s", l.namespace, l.name)
}

// Identity returns this replica's identity, the value it writes as HolderIdentity.
func (l *tunnelLeaseLock) Identity() string {
	return l.identity
}

var _ resourcelock.Interface = (*tunnelLeaseLock)(nil)
