package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// SharedNetworkName matches the chart's release-derived VPC name for e2e installs.
const SharedNetworkName = "wgnet-" + operatorRelease

// FirewallRule is the GCP firewall-rule shape read by the isolation assertion.
// JSON tags follow the `gcloud compute firewall-rules list --format=json` REST shape.
type FirewallRule struct {
	// Name starts with the gateway's NamePrefix, the basis the orphan check filters
	// on.
	Name    string            `json:"name"`
	Allowed []FirewallAllowed `json:"allowed"`
	// TargetServiceAccounts limits a rule to a gateway VM, preventing port admission across gateways.
	// An empty list applies VPC-wide.
	TargetServiceAccounts []string `json:"targetServiceAccounts"`
}

// FirewallAllowed is one protocol+ports entry in a firewall rule's allow list.
type FirewallAllowed struct {
	// Protocol is the IP protocol, e.g. "tcp" or "udp".
	Protocol string `json:"IPProtocol"`
	// Ports are the ports admitted for Protocol. An entry with no ports admits the
	// whole protocol; the gateway's rules always enumerate ports.
	Ports []string `json:"ports"`
}

// SharedNetworkCount returns 1 if SharedNetworkName exists, else 0.
// It avoids the eventually consistent list API after teardown.
func (s *Suite) SharedNetworkCount(ctx context.Context) (int, error) {
	auth := gcpAuth{projectID: s.env.ProjectID, credsFile: s.env.CredsFile}
	out, err := runGcloud(ctx, auth,
		"compute", "networks", "describe", SharedNetworkName,
		"--project", auth.projectID,
		"--format", "value(name)",
	)
	if err != nil {
		if isNotFound(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("describe shared network %s: %w\n%s", SharedNetworkName, err, out)
	}
	return 1, nil
}

// isNotFound matches case-insensitive gcloud "not found" or 404 errors.
// A nil error does not match.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") || strings.Contains(msg, "404")
}

// GatewayFirewallTargets returns rules with names starting with namePrefix.
// Their allow lists and service-account scopes support shared-VPC isolation assertions.
func (s *Suite) GatewayFirewallTargets(ctx context.Context, namePrefix string) ([]FirewallRule, error) {
	auth := gcpAuth{projectID: s.env.ProjectID, credsFile: s.env.CredsFile}
	out, err := runGcloud(ctx, auth,
		"compute", "firewall-rules", "list",
		"--project", auth.projectID,
		"--filter", "name~^"+namePrefix,
		"--format", "json",
	)
	if err != nil {
		return nil, fmt.Errorf("list firewall rules for prefix %s: %w\n%s", namePrefix, err, out)
	}
	var rules []FirewallRule
	if err := json.Unmarshal([]byte(out), &rules); err != nil {
		return nil, fmt.Errorf("decode firewall rules for prefix %s: %w", namePrefix, err)
	}
	return rules, nil
}

// GatewayServiceAccountEmail returns the service-account email scoped to the Gateway firewall rule.
// An empty result without error means the composite has not observed the service account.
func (s *Suite) GatewayServiceAccountEmail(ctx context.Context, namespace, name string) (string, error) {
	return s.client.GetXGatewayGCPServiceAccountEmail(ctx, namespace, name)
}

// GatewaySharedNetworkName returns the VPC network the Gateway's composite declares.
func (s *Suite) GatewaySharedNetworkName(ctx context.Context, namespace, name string) (string, error) {
	return s.client.GetXGatewayGCPSharedNetworkName(ctx, namespace, name)
}
