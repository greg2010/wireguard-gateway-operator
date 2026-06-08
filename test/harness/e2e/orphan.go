package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/greg2010/wireguard-gateway-operator/test/harness/shared"
)

// gcpAuth bundles the project and service-account key for gcloud. Every call
// activates the key inline so the orphan check never depends on an ambient login.
type gcpAuth struct {
	projectID string
	credsFile string
}

// resourceCount is one resource family's residual count after teardown.
type resourceCount struct {
	kind  string
	count int
	names string
}

// assertNoOrphans polls every GCP resource family the gateway provisions until all
// reach zero or the deadline elapses, returning an error naming any leak. Compute
// resources match namePrefix; the operator-derived SA and Secret match the gw- ID.
func assertNoOrphans(ctx context.Context, auth gcpAuth, namespace, gatewayName, namePrefix string, timeout time.Duration, log *zap.Logger) error {
	derivedID := gcpID(namespace, gatewayName)
	start := time.Now()
	deadline := start.Add(timeout)
	var last []resourceCount
	for {
		counts, err := countResources(ctx, auth, namePrefix, derivedID)
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

// serialConsoleOutput returns the gateway VM's serial-port-1 console output, where
// the keyfetch boot unit logs. It is best-effort diagnostics: a missing instance
// yields a descriptive string rather than an error.
func serialConsoleOutput(ctx context.Context, auth gcpAuth, zone, namePrefix string) (string, error) {
	names, err := listNames(ctx, auth,
		[]string{"compute", "instances", "list"}, "name~^"+namePrefix, "name")
	if err != nil {
		return "", fmt.Errorf("list instances: %w", err)
	}
	if len(names) == 0 {
		return "no gateway instance found for prefix " + namePrefix, nil
	}

	out, err := runGcloud(ctx, auth,
		"compute", "instances", "get-serial-port-output", names[0],
		"--project", auth.projectID,
		"--zone", zone,
		"--port", "1",
	)
	if err != nil {
		return "", fmt.Errorf("get-serial-port-output %s: %w", names[0], err)
	}
	return out, nil
}

// gcpID replicates the operator's unexported gcpID byte-for-byte so the harness
// matches the SA/secret external-names the operator derives.
func gcpID(namespace, name string) string {
	sum := sha256.Sum256([]byte(namespace + "/" + name))
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])
	id := "gw-" + strings.ToLower(enc)
	if len(id) > 30 {
		id = id[:30]
	}
	return id
}

// countResources returns the per-family counts of every GCP resource family the
// gateway provisions. Compute resources match namePrefix; the operator-derived
// ServiceAccount and Secret match derivedID.
func countResources(ctx context.Context, auth gcpAuth, namePrefix, derivedID string) ([]resourceCount, error) {
	queries := []struct {
		kind       string
		args       []string
		nameFilter string
		// field is the attribute gcloud emits per match and the one nameFilter
		// matches against, so the count and the reported names stay consistent.
		field string
	}{
		{"instance", []string{"compute", "instances", "list"}, "name~^" + namePrefix, "name"},
		{"address", []string{"compute", "addresses", "list"}, "name~^" + namePrefix, "name"},
		{"firewall-rule", []string{"compute", "firewall-rules", "list"}, "name~^" + namePrefix, "name"},
		{"network", []string{"compute", "networks", "list"}, "name~^" + namePrefix, "name"},
		{"subnetwork", []string{"compute", "networks", "subnets", "list"}, "name~^" + namePrefix, "name"},
		{"service-account", []string{"iam", "service-accounts", "list"}, "email~^" + derivedID + "@", "email"},
		{"secret", []string{"secrets", "list"}, "name~/secrets/" + derivedID + "$", "name"},
	}

	var out []resourceCount
	for _, q := range queries {
		names, err := listNames(ctx, auth, q.args, q.nameFilter, q.field)
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", q.kind, err)
		}
		out = append(out, resourceCount{kind: q.kind, count: len(names), names: strings.Join(names, ",")})
	}
	return out, nil
}

// listNames runs `gcloud <args> --filter=<f> --format='value(<field>)'` with the
// run's project and key, returning the non-empty result lines.
func listNames(ctx context.Context, auth gcpAuth, args []string, filter, field string) ([]string, error) {
	full := append([]string{}, args...)
	full = append(full,
		"--project", auth.projectID,
		"--filter", filter,
		"--format", "value("+field+")",
	)
	out, err := runGcloud(ctx, auth, full...)
	if err != nil {
		return nil, fmt.Errorf("gcloud %s: %w\n%s", strings.Join(args, " "), err, out)
	}
	var names []string
	for line := range strings.SplitSeq(out, "\n") {
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

// runGcloud invokes gcloud with the service-account key activated per call via
// CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE, so it does not mutate the operator's
// active gcloud configuration. Each call is bounded by gcloudCallTimeout.
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
