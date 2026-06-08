// Package e2e wires the gateway end-to-end harness: a kind cluster, the Crossplane
// core + GCP/Kubernetes providers, and the gateway chart provisioning a real GCP
// gateway. The data-path test forwards an in-cluster echo Service through the
// gateway and asserts the gateway's public IP is reachable from the host.
//
// The suite only runs when GATEWAY_E2E is set (the TestMain gate enforces this);
// it talks to a real GCP project and is not part of `go test ./...`.
package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/greg2010/wireguard-gateway-operator/test/harness/shared"
)

// Env holds the GCP configuration the suite reads from the process
// environment. `make test-e2e` (and the operator) source these from .env.
type Env struct {
	// ProjectID is the GCP project that owns the gateway VM, its network, and
	// its Secret Manager secret.
	ProjectID string
	// Region is the compute region for the subnet and any reserved address.
	Region string
	// Zone is the compute zone the gateway instance boots in.
	Zone string
	// CredsFile is the filesystem path to the provider-gcp service-account
	// JSON key. The harness loads it into the cluster as the crossplane creds
	// Secret.
	CredsFile string
	// CredsNamespace is the namespace the creds Secret is created in.
	// Defaults to crossplane-system.
	CredsNamespace string
	// CredsSecret is the name of the creds Secret crossplane-config consumes.
	// Defaults to gcp-creds.
	CredsSecret string
	// Keep, when true, skips all teardown (kind cluster delete, helm uninstall,
	// namespace deletes, and the GCP-resource drain) so the cluster and the GCP
	// gateway VM survive a run for live debugging, regardless of pass or fail.
	// Set via GATEWAY_E2E_KEEP. Unlike GATEWAY_E2E_PRESERVE it does not gate on
	// failure, so it leaks the GCP VM until manually drained; use it only for
	// interactive iteration, never in CI.
	Keep bool
}

// Environment variable names the suite reads.
const (
	envProjectID      = "GCP_PROJECT_ID"
	envRegion         = "GCP_REGION"
	envZone           = "GCP_ZONE"
	envCredsFile      = "GCP_CREDS_FILE"
	envCredsNamespace = "CROSSPLANE_NAMESPACE"
	envCredsSecret    = "CROSSPLANE_CREDS_SECRET"

	// EnvUseExisting, when set, makes the suite deploy into the cluster named
	// by $KUBECONFIG / the current context instead of creating a kind cluster.
	EnvUseExisting = "GATEWAY_E2E_USE_EXISTING"

	// EnvKeep, when set, makes the suite skip all teardown so the cluster and the
	// GCP gateway VM survive for live debugging. See Env.Keep.
	EnvKeep = "GATEWAY_E2E_KEEP"

	defaultCredsNamespace = "crossplane-system"
	defaultCredsSecret    = "gcp-creds"
)

// RequireEnv reads the GCP configuration from the environment and fails the
// test via t.Fatal if any required variable is missing or the creds file does
// not exist. It is called after the TestMain GATEWAY_E2E gate, so reaching it with
// an unset variable is an operator misconfiguration, not a skip condition.
func RequireEnv(t testing.TB) Env {
	t.Helper()

	env := Env{
		ProjectID:      os.Getenv(envProjectID),
		Region:         os.Getenv(envRegion),
		Zone:           os.Getenv(envZone),
		CredsFile:      os.Getenv(envCredsFile),
		CredsNamespace: os.Getenv(envCredsNamespace),
		CredsSecret:    os.Getenv(envCredsSecret),
		Keep:           os.Getenv(EnvKeep) != "",
	}
	if env.CredsNamespace == "" {
		env.CredsNamespace = defaultCredsNamespace
	}
	if env.CredsSecret == "" {
		env.CredsSecret = defaultCredsSecret
	}

	var missing []string
	for name, val := range map[string]string{
		envProjectID: env.ProjectID,
		envRegion:    env.Region,
		envZone:      env.Zone,
		envCredsFile: env.CredsFile,
	} {
		if val == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("GATEWAY_E2E is set but required GCP env vars are missing: %v "+
			"(source them from .env; see .env.example)", missing)
	}

	// Resolve a relative creds path against the repo root rather than the test's
	// working directory, so a direct `go test ./test/e2e/...` from the package dir
	// reaches the same file `make test-e2e` does from the repo root.
	if !filepath.IsAbs(env.CredsFile) {
		env.CredsFile = filepath.Join(shared.RepoRoot(), env.CredsFile)
	}

	if _, err := os.Stat(env.CredsFile); err != nil {
		t.Fatalf("%s=%q is not readable: %v", envCredsFile, env.CredsFile, err)
	}

	return env
}

// useExisting reports whether the suite should target an existing cluster
// rather than provisioning a kind cluster.
func useExisting() bool {
	return os.Getenv(EnvUseExisting) != ""
}

// readCredsJSON reads the service-account key bytes from the configured path.
func (e Env) readCredsJSON() ([]byte, error) {
	data, err := os.ReadFile(e.CredsFile)
	if err != nil {
		return nil, fmt.Errorf("read creds file %s: %w", e.CredsFile, err)
	}
	return data, nil
}
