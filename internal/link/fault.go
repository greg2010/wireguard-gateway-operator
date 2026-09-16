package link

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
)

// leaderFault is the fault the holder publishes for its node, in the operator's
// Ready-reason precedence: a failed apply first, then unsatisfied forwards.
func leaderFault(node string, applyErr error, unsatisfied []unsatisfiedForward) (reason, message string) {
	switch {
	case applyErr != nil:
		return FaultApplyFailed, boundMessage(nodeMessage(node, fmt.Sprintf("apply: %v", applyErr)))
	case len(unsatisfied) > 0:
		return FaultNoLocalEndpoint, nodeMessage(node, "forwards without a ready local endpoint: "+describeUnsatisfied(unsatisfied))
	default:
		return "", ""
	}
}

// maxFaultMessageBytes bounds a published fault message: an oversized annotation fails
// the Lease update itself, so the fault would never reach the Gateway.
const maxFaultMessageBytes = 4096

const faultMessageTruncationMarker = "... (truncated)"

// boundMessage shortens msg to maxFaultMessageBytes, cutting on a rune boundary so the
// result stays valid UTF-8 and the apiserver accepts the annotation.
func boundMessage(msg string) string {
	if len(msg) <= maxFaultMessageBytes {
		return msg
	}
	cut := maxFaultMessageBytes - len(faultMessageTruncationMarker)
	for cut > 0 && !utf8.RuneStart(msg[cut]) {
		cut--
	}
	return msg[:cut] + faultMessageTruncationMarker
}

// describeUnsatisfied renders the unsatisfied forwards as "name (reason)" in forward
// order, so the message names the forward the spec names.
func describeUnsatisfied(unsatisfied []unsatisfiedForward) string {
	parts := make([]string, 0, len(unsatisfied))
	for _, u := range unsatisfied {
		parts = append(parts, fmt.Sprintf("%s (%s)", u.name, u.reason))
	}
	return strings.Join(parts, ", ")
}

// nodeMessage prefixes a fault message with the node it describes, or returns it
// unchanged when the node is unknown.
func nodeMessage(node, msg string) string {
	if node == "" {
		return msg
	}
	return node + ": " + msg
}

// LeaseFaultAnnotation carries the holder's current fault reason on the Lease it holds,
// absent once everything is programmed. The operator mirrors it into Ready.
const LeaseFaultAnnotation = "wgnet.dev/link-fault"

// LeaseFaultMessageAnnotation carries the human-readable detail for
// LeaseFaultAnnotation, including the node name.
const LeaseFaultMessageAnnotation = "wgnet.dev/link-fault-message"

// Fault reasons published through LeaseFaultAnnotation. They double as Gateway
// Ready=False reasons, so each is a valid Kubernetes condition reason.
const (
	FaultRPFilterStrict  = "RPFilterStrict"
	FaultApplyFailed     = "ApplyFailed"
	FaultNoLocalEndpoint = "NoLocalEndpoint"
)

var knownFaults = []string{FaultRPFilterStrict, FaultApplyFailed, FaultNoLocalEndpoint}

// KnownFaults is every reason published through LeaseFaultAnnotation, which is what the
// operator accepts. Each call returns a fresh copy.
func KnownFaults() []string {
	return slices.Clone(knownFaults)
}

// publishFault sets the fault annotations, or clears them when reason is empty, retrying
// on conflict. It writes nothing unless the value changes and self still holds the Lease.
func publishFault(ctx context.Context, cs kubernetes.Interface, namespace, name, self, reason, message string, log *zap.SugaredLogger) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		lease, err := cs.CoordinationV1().Leases(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get lease %s/%s: %w", namespace, name, err)
		}
		holder := ""
		if lease.Spec.HolderIdentity != nil {
			holder = *lease.Spec.HolderIdentity
		}
		if holder != "" && holder != self {
			log.Infow("lease already held elsewhere, not writing its fault", "holder", holder, "self", self, "reason", reason)
			return nil
		}
		if lease.Annotations == nil {
			lease.Annotations = map[string]string{}
		}
		if reason == "" {
			if _, hasReason := lease.Annotations[LeaseFaultAnnotation]; !hasReason {
				return nil
			}
			delete(lease.Annotations, LeaseFaultAnnotation)
			delete(lease.Annotations, LeaseFaultMessageAnnotation)
		} else {
			if lease.Annotations[LeaseFaultAnnotation] == reason && lease.Annotations[LeaseFaultMessageAnnotation] == message {
				return nil
			}
			lease.Annotations[LeaseFaultAnnotation] = reason
			lease.Annotations[LeaseFaultMessageAnnotation] = message
		}
		if _, err := cs.CoordinationV1().Leases(namespace).Update(ctx, lease, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("update lease %s/%s: %w", namespace, name, err)
		}
		return nil
	})
}

// LeaseSlotStateAnnotation carries the per-slot apply state, distinct from the Gateway-wide fault
// annotation.
const LeaseSlotStateAnnotation = "wgnet.dev/link-slot-state"

// SlotState is one slot's published apply state.
type SlotState struct {
	State   string `json:"state"`             // "applied" or "down"
	Message string `json:"message,omitempty"` // set only when State is "down"
}

const (
	slotStateApplied = "applied"
	slotStateDown    = "down"
)

// publishSlotState publishes per-slot outcomes without changing the Gateway fault.
func publishSlotState(ctx context.Context, cs kubernetes.Interface, namespace, name, self string, results []SlotResult, log *zap.SugaredLogger) error {
	value, err := slotStateJSON(results)
	if err != nil {
		return fmt.Errorf("marshal slot state: %w", err)
	}
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		lease, err := cs.CoordinationV1().Leases(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get lease %s/%s: %w", namespace, name, err)
		}
		holder := ""
		if lease.Spec.HolderIdentity != nil {
			holder = *lease.Spec.HolderIdentity
		}
		if holder != "" && holder != self {
			log.Infow("lease already held elsewhere, not writing its slot state", "holder", holder, "self", self)
			return nil
		}
		if lease.Annotations == nil {
			lease.Annotations = map[string]string{}
		}
		if len(results) == 0 {
			if _, has := lease.Annotations[LeaseSlotStateAnnotation]; !has {
				return nil
			}
			delete(lease.Annotations, LeaseSlotStateAnnotation)
		} else {
			if lease.Annotations[LeaseSlotStateAnnotation] == value {
				return nil
			}
			lease.Annotations[LeaseSlotStateAnnotation] = value
		}
		if _, err := cs.CoordinationV1().Leases(namespace).Update(ctx, lease, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("update lease %s/%s: %w", namespace, name, err)
		}
		return nil
	})
}

// slotStateJSON renders results as LeaseSlotStateAnnotation's value: one entry per slot, keyed by
// decimal slot number, since Lease annotation values are strings.
func slotStateJSON(results []SlotResult) (string, error) {
	states := make(map[string]SlotState, len(results))
	for _, r := range results {
		s := SlotState{State: slotStateApplied}
		if !r.Applied {
			s.State = slotStateDown
			if r.Err != nil {
				s.Message = r.Err.Error()
			}
		}
		states[strconv.Itoa(r.Slot)] = s
	}
	data, err := json.Marshal(states)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
