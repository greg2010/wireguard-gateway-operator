package e2e

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

// dumpDiagnostics writes the Gateway and XGateway objects, the namespace's
// recent events, and the operator + link pod logs to the test log. Best-effort:
// each probe's error is logged and skipped so a dump failure never masks the
// original test failure. Called from the teardown path only when the test has
// already failed.
func (s *Suite) dumpDiagnostics(ctx context.Context, t *testing.T, stack *Stack) {
	t.Helper()

	if obj, err := s.client.DumpGateway(ctx, stack.Namespace, stack.GatewayName); err == nil {
		t.Logf("---- Gateway %s/%s ----\n%s\n---- end Gateway ----", stack.Namespace, stack.GatewayName, obj)
	} else {
		s.log.Warn("dump gateway", zap.Error(err))
	}

	if obj, err := s.client.DumpXGateway(ctx, stack.Namespace, stack.GatewayName); err == nil {
		t.Logf("---- XGateway %s/%s ----\n%s\n---- end XGateway ----", stack.Namespace, stack.GatewayName, obj)
	} else {
		s.log.Warn("dump xgateway", zap.Error(err))
	}

	if events, err := s.client.RecentEvents(ctx, stack.Namespace, 100); err == nil {
		t.Logf("---- events %s (last 100) ----\n%s\n---- end events ----", stack.Namespace, events)
	} else {
		s.log.Warn("dump events", zap.Error(err))
	}

	if logs, err := s.client.PodLogsByLabel(ctx, stack.Namespace, "app.kubernetes.io/component=operator", 400); err == nil {
		t.Logf("---- operator pod logs (last 400 lines) ----\n%s\n---- end operator logs ----", logs)
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
}
