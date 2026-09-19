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

// sharedNetwork is the subset of `gcloud compute networks describe --format=json` the
// residual description reports.
type sharedNetwork struct {
	Name        string   `json:"name"`
	Subnetworks []string `json:"subnetworks"`
}

// SharedNetworkResidual describes what is left of SharedNetworkName, empty once it is gone.
// It describes rather than lists to avoid the eventually consistent list API after teardown.
func (s *Suite) SharedNetworkResidual(ctx context.Context) (string, error) {
	auth := gcpAuth{projectID: s.env.ProjectID, credsFile: s.env.CredsFile}
	out, err := runGcloud(ctx, auth,
		"compute", "networks", "describe", SharedNetworkName,
		"--project", auth.projectID,
		"--format", "json",
	)
	if err != nil {
		if isNotFound(err) {
			return "", nil
		}
		return "", fmt.Errorf("describe shared network %s: %w\n%s", SharedNetworkName, err, out)
	}
	var network sharedNetwork
	if err := json.Unmarshal([]byte(out), &network); err != nil {
		return "", fmt.Errorf("decode shared network %s: %w", SharedNetworkName, err)
	}
	return fmt.Sprintf("network %s present, subnetworks=%d", SharedNetworkName, len(network.Subnetworks)), nil
}

// SharedNetworkAttachments names the firewall rules and routes still on SharedNetworkName,
// the resources whose deletion the VPC waits on. Auto-created default-route-* entries are
// listed too; they are informative rather than leaks.
func (s *Suite) SharedNetworkAttachments(ctx context.Context) (string, error) {
	auth := gcpAuth{projectID: s.env.ProjectID, credsFile: s.env.CredsFile}
	rules, err := networkAttachmentNames(ctx, auth, "firewall-rules")
	if err != nil {
		return "", err
	}
	routes, err := networkAttachmentNames(ctx, auth, "routes")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("firewall-rules=[%s] routes=[%s]", rules, routes), nil
}

func networkAttachmentNames(ctx context.Context, auth gcpAuth, kind string) (string, error) {
	out, err := runGcloud(ctx, auth,
		"compute", kind, "list",
		"--project", auth.projectID,
		"--filter", "network~/"+SharedNetworkName+"$",
		"--format", "value(name)",
	)
	if err != nil {
		return "", fmt.Errorf("list %s on network %s: %w\n%s", kind, SharedNetworkName, err, out)
	}
	return strings.Join(strings.Fields(out), " "), nil
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
