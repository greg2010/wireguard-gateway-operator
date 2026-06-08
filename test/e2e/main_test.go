package e2e_test

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	e2eharness "github.com/greg2010/wireguard-gateway-operator/test/harness/e2e"
)

// sharedNetworkDrainTimeout bounds the post-teardown poll for the shared VPC to
// disappear. SharedNetworkCount uses the strongly-consistent describe API, so a
// genuinely drained VPC reports absent on the first poll; the window only absorbs a
// slow final delete still settling when the suite reaches here. An auto-mode VPC
// carries 40 implicit per-region subnets whose deletion can tail well past a minute,
// so this matches the per-gateway orphan drain budget (orphanDrainTimeout, 4m in the
// e2e harness suite) rather than assuming a near-instant teardown.
const sharedNetworkDrainTimeout = 4 * time.Minute

// sharedNetworkDrainInterval is the gap between shared-VPC drain polls, matching
// the per-gateway orphan drain's cadence.
const sharedNetworkDrainInterval = 5 * time.Second

// TestMain gates the entire e2e package on GATEWAY_E2E so `go test ./...` never
// provisions a kind cluster or touches GCP. The required GCP env is validated
// per-test (via getSuite -> RequireEnv) so a missing var fails the test with a
// clear t.Fatal message rather than an opaque package-level exit.
//
// Cluster teardown runs here, after m.Run returns. m.Run blocks until every
// parallel test AND its per-Stack t.Cleanup (the GCP drain) completes, so
// deleting the shared kind cluster exactly once here cannot race a Stack still
// draining GCP. The binary exit code is passed through to Teardown as the run's
// pass/fail signal for the preserve-on-failure gate.
func TestMain(m *testing.M) {
	if os.Getenv("GATEWAY_E2E") == "" {
		os.Exit(0)
	}
	code := m.Run()
	if sharedSuite != nil {
		sharedSuite.Teardown(context.Background(), code)
		code = assertSharedNetworkDrained(sharedSuite, code)
	}
	os.Exit(code)
}

// assertSharedNetworkDrained verifies the shared GCP VPC was deleted once the
// last gateway drained, the refcounted counterpart to the per-stack orphan check
// (which filters by gateway prefix and so never sees the shared network). It runs
// after m.Run, so every parallel Stack's GCP drain has completed, and after
// Teardown deleted the kind cluster: the GCP query authenticates with the suite's
// own service-account key, independent of the cluster. A residual VPC is a leak,
// logged and folded into a non-zero exit consistent with the run's exit code.
//
// It polls SharedNetworkCount until zero or sharedNetworkDrainTimeout elapses,
// mirroring the per-gateway orphan drain: the refcount delete of the last gateway
// and this check race, so a brief residual is the delete still settling, not a
// leak. A persistent count after the deadline is the leak. It returns the exit
// code to use, leaving a passing run's code at zero unless it finds the leak.
//
// It is skipped on an already-failing run (code != 0) and when GATEWAY_E2E_KEEP
// is set: both legitimately leave gateways (and thus the shared VPC) up, so the
// drain never ran and a zero count is not expected.
func assertSharedNetworkDrained(suite *e2eharness.Suite, code int) int {
	if code != 0 || suite.Env().Keep {
		return code
	}
	ctx, cancel := context.WithTimeout(context.Background(), sharedNetworkDrainTimeout)
	defer cancel()
	deadline := time.Now().Add(sharedNetworkDrainTimeout)
	var last int
	for {
		n, err := suite.SharedNetworkCount(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "e2e: shared network drain check failed: %v\n", err)
			return 1
		}
		last = n
		if n == 0 {
			return code
		}
		if time.Now().After(deadline) {
			fmt.Fprintf(os.Stderr,
				"e2e: shared network %q still present (count=%d) after all gateways drained "+
					"and %s of polling; the refcounted shared VPC leaked\n",
				e2eharness.SharedNetworkName, last, sharedNetworkDrainTimeout)
			return 1
		}
		select {
		case <-ctx.Done():
			fmt.Fprintf(os.Stderr,
				"e2e: shared network %q drain check interrupted (count=%d): %v\n",
				e2eharness.SharedNetworkName, last, ctx.Err())
			return 1
		case <-time.After(sharedNetworkDrainInterval):
		}
	}
}

// sharedSuite lazily builds the suite (kind cluster, Crossplane stack, gateway
// image) once per `go test` invocation. The first test to call getSuite builds
// it under setupOnce; subsequent parallel tests reuse the handle. Cluster
// teardown is driven once from TestMain after m.Run, not from a test's
// t.Cleanup, so it waits for every parallel Stack's GCP drain to finish.
var (
	setupOnce   sync.Once
	sharedSuite *e2eharness.Suite
	setupErr    error
)

// getSuite returns the shared suite, building it on first call. It is safe for
// parallel tests: the build runs once and later callers observe the result.
//
// Setup returns a non-nil suite holding the kind cluster handle even when it
// fails after creating the cluster, so sharedSuite is assigned unconditionally
// (before the error check) to keep the cluster reachable for TestMain's
// Teardown. The setupErr check still fails the calling test.
func getSuite(t *testing.T) *e2eharness.Suite {
	t.Helper()
	setupOnce.Do(func() {
		sharedSuite, setupErr = e2eharness.Setup(context.Background())
	})
	if setupErr != nil {
		t.Fatalf("e2e suite setup: %v", setupErr)
	}
	return sharedSuite
}
