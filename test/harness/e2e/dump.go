package e2e

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

// linkConfigMapKey is the data key the operator stores the link's rendered
// RuntimeConfig under. It mirrors the operator's unexported linkConfigKey.
const linkConfigMapKey = "config.json"

// linkConfigMapName returns the link ConfigMap name for a gateway: <gateway>-link.
// It mirrors the operator's unexported linkComponentName.
func linkConfigMapName(gatewayName string) string { return gatewayName + "-link" }

// dumpDiagnostics logs the Gateway/XGatewayGCP objects, events, backend endpoints,
// pod statuses, the link config, the operator/link/crossplane logs, and the VM serial
// console. Each probe's error is logged and skipped so a dump never masks the failure.
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

	if logs, err := s.client.PodLogsByLabel(ctx, stack.Namespace, "app.kubernetes.io/component=link", 400); err == nil {
		t.Logf("---- link pod logs (last 400 lines) ----\n%s\n---- end link logs ----", logs)
	} else {
		s.log.Warn("dump link logs", zap.Error(err))
	}

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
