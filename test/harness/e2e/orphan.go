package e2e

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/greg2010/wireguard-gateway-operator/test/harness/shared"
)

// gcpAuth bundles the gcloud invocation context: the project and the
// service-account key used to authenticate. Every gcloud call activates the key
// inline so the orphan check does not depend on the operator's ambient gcloud
// login.
type gcpAuth struct {
	projectID string
	credsFile string
}

// resourceCount is one resource family's residual count after teardown, used in
// the orphan assertion's failure message.
type resourceCount struct {
	kind  string
	count int
	names string
}

// assertNoOrphans polls every GCP resource family the gateway composition
// creates, filtered to the run's namePrefix, until all reach zero or the
// deadline elapses. A non-zero residual after the deadline is returned as an
// error naming the leaked resources.
//
// Filtering is by name prefix because the composition does not stamp GCP labels
// on the managed resources; the suite makes the prefix unique per run via the
// chart nameOverride and the serviceAccountId / secretId values.
func assertNoOrphans(ctx context.Context, auth gcpAuth, namePrefix string, timeout time.Duration, log *zap.Logger) error {
	start := time.Now()
	deadline := start.Add(timeout)
	var last []resourceCount
	for {
		counts, err := countResources(ctx, auth, namePrefix)
		if err != nil {
			return fmt.Errorf("count gcp resources: %w", err)
		}
		last = counts
		if total(counts) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("gcp resources still present after %s: %s", timeout, describe(last))
		}
		log.Info("waiting for gcp resources to drain",
			zap.String("prefix", namePrefix),
			zap.String("residual", describe(counts)),
		)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

// countResources queries each GCP resource family for names beginning with
// namePrefix and returns the per-family counts.
func countResources(ctx context.Context, auth gcpAuth, namePrefix string) ([]resourceCount, error) {
	queries := []struct {
		kind string
		args []string
		// nameFilter is the gcloud --filter expression matching the run prefix
		// against the resource's identifying field.
		nameFilter string
	}{
		{"instance", []string{"compute", "instances", "list"}, "name~^" + namePrefix},
		{"address", []string{"compute", "addresses", "list"}, "name~^" + namePrefix},
		{"firewall-rule", []string{"compute", "firewall-rules", "list"}, "name~^" + namePrefix},
		{"network", []string{"compute", "networks", "list"}, "name~^" + namePrefix},
		{"subnetwork", []string{"compute", "networks", "subnets", "list"}, "name~^" + namePrefix},
		{"service-account", []string{"iam", "service-accounts", "list"}, "email~^" + namePrefix},
		{"secret", []string{"secrets", "list"}, "name~^" + namePrefix},
	}

	var out []resourceCount
	for _, q := range queries {
		names, err := listNames(ctx, auth, q.args, q.nameFilter)
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", q.kind, err)
		}
		out = append(out, resourceCount{kind: q.kind, count: len(names), names: strings.Join(names, ",")})
	}
	return out, nil
}

// listNames runs `gcloud <args> --filter=<f> --format='value(name)'` with the
// run's project and key, returning the non-empty result lines.
func listNames(ctx context.Context, auth gcpAuth, args []string, filter string) ([]string, error) {
	full := append([]string{}, args...)
	full = append(full,
		"--project", auth.projectID,
		"--filter", filter,
		"--format", "value(name)",
	)
	out, err := runGcloud(ctx, auth, full...)
	if err != nil {
		return nil, fmt.Errorf("gcloud %s: %w\n%s", strings.Join(args, " "), err, out)
	}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		if s := strings.TrimSpace(line); s != "" {
			names = append(names, s)
		}
	}
	return names, nil
}

// gcloudCallTimeout bounds a single gcloud invocation. A slow or wedged call
// (auth stall, API hiccup) must not block to the suite's global deadline and
// starve the teardown drain; it fails fast so the caller can surface or retry.
const gcloudCallTimeout = 30 * time.Second

// runGcloud invokes gcloud with the service-account key activated for the call
// via CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE, so it does not mutate the
// operator's active gcloud configuration. Each call is bounded by
// gcloudCallTimeout so a single slow invocation cannot hang the suite.
func runGcloud(ctx context.Context, auth gcpAuth, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, gcloudCallTimeout)
	defer cancel()
	env := []string{"CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE=" + auth.credsFile}
	out, err := shared.RunCmdStdout(cctx, env, "gcloud", args...)
	if err != nil && cctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("gcloud %s timed out after %s: %w", strings.Join(args, " "), gcloudCallTimeout, err)
	}
	return out, err
}

func total(counts []resourceCount) int {
	n := 0
	for _, c := range counts {
		n += c.count
	}
	return n
}

func describe(counts []resourceCount) string {
	var parts []string
	for _, c := range counts {
		if c.count == 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%d[%s]", c.kind, c.count, c.names))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, " ")
}
