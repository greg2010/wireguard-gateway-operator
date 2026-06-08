package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// SharedNetworkName mirrors the chart's release-derived VPC name (wgnet-<release>) for the e2e operator install.
const SharedNetworkName = "wgnet-" + operatorRelease

// FirewallRule is the slice of a GCP firewall rule the isolation assertion
// reads: its name, the protocol+ports it admits, and the service accounts it is
// scoped to. It is decoded from `gcloud compute firewall-rules list
// --format=json`, whose objects use GCP's REST resource shape (the allow list is
// keyed "allowed", each entry carries "IPProtocol", and the scoping list is
// "targetServiceAccounts").
type FirewallRule struct {
	// Name is the firewall rule's name. Per-gateway rules start with the
	// gateway's NamePrefix, the same basis the orphan check filters on.
	Name string `json:"name"`
	// Allowed is the protocol+ports the rule admits.
	Allowed []FirewallAllowed `json:"allowed"`
	// TargetServiceAccounts is the set of GCP service-account emails the rule
	// applies to. A shared VPC relies on this list to scope a gateway's rule to
	// that gateway's own VM, so two gateways in one VPC do not admit each other's
	// ports. An empty list would mean the rule applies VPC-wide.
	TargetServiceAccounts []string `json:"targetServiceAccounts"`
}

// FirewallAllowed is one protocol+ports entry in a firewall rule's allow list.
type FirewallAllowed struct {
	// Protocol is the IP protocol the entry admits, e.g. "tcp" or "udp". gcloud
	// emits it under the "IPProtocol" key.
	Protocol string `json:"IPProtocol"`
	// Ports are the ports the entry admits for Protocol. A protocol entry with no
	// ports admits the whole protocol; the gateway's rules always enumerate
	// ports, so the isolation assertion reads them directly.
	Ports []string `json:"ports"`
}

// SharedNetworkCount reports whether the GCP VPC named SharedNetworkName exists,
// returning 1 if present and 0 if absent. With the shared-VPC refcount design
// every Gateway attaches to this one network, created on the first Gateway and
// deleted on the last, so the result is 1 while any Gateway is up and 0 once the
// last is drained. It authenticates with the suite's service-account key, like
// the orphan check.
//
// It uses `gcloud compute networks describe`, which reads the named resource and
// is strongly consistent: a network deleted moments earlier reports NOT FOUND
// immediately. The list API the orphan check uses is eventually consistent and
// can still enumerate a just-deleted network for several seconds, which would
// false-fail a drain assertion run right after teardown.
//
// A NOT FOUND describe error (matched case-insensitively in the gcloud
// error/stderr) is the absent case and returns (0, nil). Any other gcloud
// failure (auth, transport) returns a non-nil error rather than masquerading as
// a zero count.
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

// isNotFound reports whether a gcloud error signals the queried resource does
// not exist. gcloud emits the absence as a non-zero exit with the phrase on
// stderr, which runGcloud folds into the returned error; the match is
// case-insensitive and covers gcloud's "was not found" wording and a bare "not
// found"/404.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") || strings.Contains(msg, "404")
}

// GatewayFirewallTargets returns the firewall rules whose names start with
// namePrefix, with their allow list and service-account scoping, so a caller can
// assert per-gateway firewall isolation in the shared VPC: that a gateway's
// rules target only its own service account and admit only its own ports. It
// authenticates with the suite's service-account key, like the orphan check.
//
// namePrefix is the gateway's NamePrefix, the run-unique prefix every per-gateway
// firewall rule inherits (the same basis the orphan check's firewall-rule count
// uses). It decodes `gcloud ... --format=json` rather than the value-format the
// orphan check uses, because the assertion needs the rules' nested allow list
// and targetServiceAccounts, not just their names.
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

// GatewayServiceAccountEmail returns the GCP service-account email the operator
// scopes the named Gateway's firewall rule to, read from the Gateway's
// XGatewayGCP composite status.serviceAccountEmail. It is the SA a caller
// asserts every one of that gateway's firewall rules targets (and the other
// gateway's rules never do). An empty result (with no error) means the composite
// has not yet observed the SA, distinct from a missing composite, which errors.
func (s *Suite) GatewayServiceAccountEmail(ctx context.Context, namespace, name string) (string, error) {
	return s.client.GetXGatewayGCPServiceAccountEmail(ctx, namespace, name)
}
