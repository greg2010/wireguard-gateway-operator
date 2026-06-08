package e2e

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

// linkConfigMapKey is the data key the operator stores the link's rendered
// RuntimeConfig under in its ConfigMap. It mirrors the operator's linkConfigKey
// (internal/controller), duplicated here because that constant is unexported and
// the harness must not import the controller package.
const linkConfigMapKey = "config.json"

// linkConfigMapName returns the link ConfigMap name for a gateway. It mirrors the
// operator's linkComponentName (internal/controller): <gateway>-link. Duplicated
// here because that helper is unexported and the harness must not import the
// controller package.
func linkConfigMapName(gatewayName string) string { return gatewayName + "-link" }

// dumpDiagnostics writes, to the test log, the Gateway and XGatewayGCP objects,
// the namespace's recent events, the backend Services + their EndpointSlice ready
// addresses, the backend pod statuses, the link's rendered config.json, the
// operator + link + crossplane logs, and the gateway VM's serial console (where
// the keyfetch boot unit logs). The Service/endpoint, pod-status, and config.json
// sections target a data-path probe failure: they capture whether a retargeted
// backend had ready endpoints and what DNAT the link was actually serving at
// failure time. Best-effort: each probe's error is logged and skipped so a dump
// failure never masks the original test failure. Called from the teardown path
// only when the test has already failed. auth and the suite's Zone resolve the VM
// serial console.
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

	// Backend Services + their ready EndpointSlice addresses: shows whether the
	// forward's (or a just-retargeted forward's) backend had ready endpoints when
	// the data-path probe failed.
	if summary, err := s.client.ServiceEndpointSummary(ctx, stack.Namespace); err == nil {
		t.Logf("---- backend services + endpoints %s ----\n%s\n---- end services + endpoints ----", stack.Namespace, summary)
	} else {
		s.log.Warn("dump service endpoints", zap.Error(err))
	}

	// Backend pod statuses: phase, Ready, and node for every pod in the gateway
	// namespace, so an unscheduled or crash-looping backend behind a stalled
	// retarget is visible alongside its Service's endpoints.
	if summary, err := s.client.PodStatusSummary(ctx, stack.Namespace, ""); err == nil {
		t.Logf("---- pod statuses %s ----\n%s\n---- end pod statuses ----", stack.Namespace, summary)
	} else {
		s.log.Warn("dump pod statuses", zap.Error(err))
	}

	// Link ConfigMap config.json: the rendered forwards/targets the link consumes.
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
