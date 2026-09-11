package e2e

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
)

// linkConfigMapKey is the data key the operator stores the link's rendered
// RuntimeConfig under. It mirrors the operator's unexported linkConfigKey.
const linkConfigMapKey = "config.json"

// linkPodTailLines bounds each container log in the dump. The link is quiet in
// steady state, so a few hundred lines reach back past the election.
const linkPodTailLines = 300

// linkConfigMapName returns the link ConfigMap name for a gateway: <gateway>-link.
// It mirrors the operator's unexported linkComponentName.
func linkConfigMapName(gatewayName string) string { return gatewayName + "-link" }

// linkLeaseName returns the Lease the link replicas contend for: <gateway>-link. It
// mirrors the operator's GATEWAY_LEASE_NAME value.
func linkLeaseName(gatewayName string) string { return gatewayName + "-link" }

// linkPodSelector matches the link pods of one Gateway.
func linkPodSelector(gatewayName string) string {
	return fmt.Sprintf("app.kubernetes.io/component=link,app.kubernetes.io/instance=%s", gatewayName)
}

// dumpDiagnostics logs every diagnostic of a failing Gateway. Each probe's error is logged and
// skipped so a dump never masks the failure under test.
func (s *Suite) dumpDiagnostics(ctx context.Context, t *testing.T, stack *Stack, auth gcpAuth) {
	t.Helper()

	if obj, err := s.client.DumpGateway(ctx, stack.Namespace, stack.GatewayName); err == nil {
		t.Logf("---- Gateway %s/%s ----\n%s\n---- end Gateway ----", stack.Namespace, stack.GatewayName, obj)
	} else {
		s.log.Warn("dump gateway", zap.Error(err))
	}

	if obj, err := s.client.DumpXGatewayGCP(ctx, stack.Namespace, stack.GatewayName); err == nil {
		t.Logf("---- XGatewayGCP %s/%s ----\n%s\n---- end XGatewayGCP ----", stack.Namespace, stack.GatewayName, obj)
	} else {
		s.log.Warn("dump xgatewaygcp", zap.Error(err))
	}

	if events, err := s.client.RecentEvents(ctx, stack.Namespace, 100); err == nil {
		t.Logf("---- events %s (last 100) ----\n%s\n---- end events ----", stack.Namespace, events)
	} else {
		s.log.Warn("dump events", zap.Error(err))
	}

	// Shows whether a just-retargeted forward's backend had ready endpoints when
	// the probe failed.
	if summary, err := s.client.ServiceEndpointSummary(ctx, stack.Namespace); err == nil {
		t.Logf("---- backend services + endpoints %s ----\n%s\n---- end services + endpoints ----", stack.Namespace, summary)
	} else {
		s.log.Warn("dump service endpoints", zap.Error(err))
	}

	// Surfaces an unscheduled or crash-looping backend behind a stalled retarget.
	if summary, err := s.client.PodStatusSummary(ctx, stack.Namespace, ""); err == nil {
		t.Logf("---- pod statuses %s ----\n%s\n---- end pod statuses ----", stack.Namespace, summary)
	} else {
		s.log.Warn("dump pod statuses", zap.Error(err))
	}

	// Pairs with the link logs to tell a stale-config link from a stale-DNAT link
	// that applied the right config.
	cmName := linkConfigMapName(stack.GatewayName)
	if cfg, err := s.client.ConfigMapData(ctx, stack.Namespace, cmName, linkConfigMapKey); err == nil {
		t.Logf("---- link configmap %s/%s [%s] ----\n%s\n---- end link configmap ----", stack.Namespace, cmName, linkConfigMapKey, cfg)
	} else {
		s.log.Warn("dump link configmap", zap.Error(err))
	}

	// The operator runs once per cluster in operatorNamespace, not in the
	// per-gateway namespace, so its logs must be read there.
	if logs, err := s.client.PodLogsByLabel(ctx, operatorNamespace, "app.kubernetes.io/component=operator", 200); err == nil {
		t.Logf("---- operator pod logs (last 200 lines) ----\n%s\n---- end operator logs ----", logs)
	} else {
		s.log.Warn("dump operator logs", zap.Error(err))
	}

	// Every link pod, not just the first: which replica holds the Lease and why the
	// other is unready is only visible across all of them.
	s.dumpLinkPods(ctx, t, stack)
	s.dumpLinkLease(ctx, t, stack)
	s.dumpLocalDataPlane(ctx, t, stack)

	if logs, err := s.client.PodLogsByLabel(ctx, crossplaneNamespace, "app=crossplane", 200); err == nil {
		t.Logf("---- crossplane core logs (last 200 lines) ----\n%s\n---- end crossplane logs ----", logs)
	} else {
		s.log.Warn("dump crossplane logs", zap.Error(err))
	}

	if console, err := serialConsoleOutput(ctx, auth, s.env.Zone, stack.NamePrefix); err == nil {
		t.Logf("---- gateway VM serial console ----\n%s\n---- end gateway VM serial console ----", console)
	} else {
		s.log.Warn("dump gateway serial console", zap.Error(err))
	}
}

func (s *Suite) dumpLinkPods(ctx context.Context, t *testing.T, stack *Stack) {
	t.Helper()

	pods, err := s.client.PodsByLabel(ctx, stack.Namespace, linkPodSelector(stack.GatewayName))
	if err != nil {
		s.log.Warn("dump link pods", zap.Error(err))
		return
	}

	for _, pod := range pods {
		var b strings.Builder
		fmt.Fprintf(&b, "%s\n", linkPodSummary(&pod))
		for _, c := range pod.Spec.Containers {
			fmt.Fprintf(&b, "-- container %s log (last %d lines) --\n%s\n", c.Name, linkPodTailLines, s.containerLog(ctx, stack.Namespace, pod.Name, c.Name, false))
			if containerRestarts(&pod, c.Name) > 0 {
				fmt.Fprintf(&b, "-- container %s previous log (last %d lines) --\n%s\n", c.Name, linkPodTailLines, s.containerLog(ctx, stack.Namespace, pod.Name, c.Name, true))
			}
		}
		t.Logf("---- link pod %s/%s ----\n%s---- end link pod %s ----", stack.Namespace, pod.Name, b.String(), pod.Name)
	}
}

// dumpLinkLease logs the link Lease's holder, renewal and annotations. The wgnet.dev/link-fault
// annotations are the link's only fault channel to the operator.
func (s *Suite) dumpLinkLease(ctx context.Context, t *testing.T, stack *Stack) {
	t.Helper()

	name := linkLeaseName(stack.GatewayName)
	lease, err := s.client.GetLease(ctx, stack.Namespace, name)
	if err != nil {
		s.log.Warn("dump link lease", zap.Error(err))
		return
	}

	var b strings.Builder
	holder := ""
	if lease.Spec.HolderIdentity != nil {
		holder = *lease.Spec.HolderIdentity
	}
	fmt.Fprintf(&b, "holder=%s", holder)
	if lease.Spec.LeaseTransitions != nil {
		fmt.Fprintf(&b, " transitions=%d", *lease.Spec.LeaseTransitions)
	}
	if lease.Spec.RenewTime != nil {
		fmt.Fprintf(&b, " renewed=%s", lease.Spec.RenewTime.Format(time.RFC3339))
	}
	b.WriteString("\n")
	keys := slices.Sorted(maps.Keys(lease.Annotations))
	for _, k := range keys {
		fmt.Fprintf(&b, "annotation %s=%s\n", k, lease.Annotations[k])
	}

	t.Logf("---- link Lease %s/%s ----\n%s---- end link Lease ----", stack.Namespace, name, b.String())
}

// linkPodSummary is the one-line status header of a link pod block.
func linkPodSummary(pod *corev1.Pod) string {
	ready, since := "false", ""
	for _, c := range pod.Status.Conditions {
		if c.Type != corev1.PodReady {
			continue
		}
		ready = string(c.Status)
		if !c.LastTransitionTime.IsZero() {
			since = c.LastTransitionTime.Format(time.RFC3339)
		}
	}
	restarts := int32(0)
	for _, cs := range pod.Status.ContainerStatuses {
		restarts += cs.RestartCount
	}
	return fmt.Sprintf("node=%s phase=%s ready=%s readySince=%s restarts=%d",
		pod.Spec.NodeName, pod.Status.Phase, ready, since, restarts)
}

// containerRestarts returns the restart count of one container, 0 when its status is
// not reported yet.
func containerRestarts(pod *corev1.Pod, container string) int32 {
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.Name == container {
			return cs.RestartCount
		}
	}
	return 0
}

// containerLog returns the tail of one container's log, or the read error as the
// body so a dump never masks the failure it is explaining.
func (s *Suite) containerLog(ctx context.Context, namespace, pod, container string, previous bool) string {
	out, err := s.client.ContainerLogTail(ctx, namespace, pod, container, previous, linkPodTailLines)
	if err != nil {
		s.log.Warn("dump link container log", zap.String("pod", pod), zap.String("container", container), zap.Bool("previous", previous), zap.Error(err))
		if out == "" {
			return fmt.Sprintf("<unavailable: %v>", err)
		}
		return fmt.Sprintf("%s\n<truncated: %v>", out, err)
	}
	return out
}
