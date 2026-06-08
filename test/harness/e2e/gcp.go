package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// SharedNetworkName mirrors the chart's release-derived VPC name (wgnet-<release>) for the e2e operator install.
const SharedNetworkName = "wgnet-" + operatorRelease

// FirewallRule is the slice of a GCP firewall rule the isolation assertion reads,
// decoded from `gcloud compute firewall-rules list --format=json` (GCP's REST
// resource shape, hence the json tags).
type FirewallRule struct {
	// Name starts with the gateway's NamePrefix, the basis the orphan check filters
	// on.
	Name    string            `json:"name"`
	Allowed []FirewallAllowed `json:"allowed"`
	// TargetServiceAccounts scopes the rule to a gateway's own VM, so two gateways
	// in one shared VPC do not admit each other's ports. An empty list applies the
	// rule VPC-wide.
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

// SharedNetworkCount returns 1 if the VPC named SharedNetworkName exists, else 0. It
// uses the strongly-consistent `networks describe`, not the eventually-consistent
// list API that can enumerate a just-deleted network and false-fail a post-teardown drain.
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

// isNotFound reports whether a gcloud error signals the queried resource does not
// exist. The match is case-insensitive and covers gcloud's "was not found" wording
// and a bare "not found"/404.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") || strings.Contains(msg, "404")
}

// GatewayFirewallTargets returns the firewall rules whose names start with namePrefix,
// with their allow list and service-account scoping, so a caller can assert
// per-gateway firewall isolation in the shared VPC.
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

// GatewayServiceAccountEmail returns the SA email the operator scopes the named
// Gateway's firewall rule to. An empty result with a nil error means the composite
// has not yet observed the SA, distinct from a missing composite, which errors.
func (s *Suite) GatewayServiceAccountEmail(ctx context.Context, namespace, name string) (string, error) {
	return s.client.GetXGatewayGCPServiceAccountEmail(ctx, namespace, name)
}
