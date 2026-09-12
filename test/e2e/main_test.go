package e2e_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	e2eharness "github.com/greg2010/wireguard-gateway-operator/test/harness/e2e"
)

// sharedNetworkDrainTimeout matches the per-gateway orphan drain budget; an auto-mode VPC's
// 40 implicit subnets can tail past a minute after teardown.
const sharedNetworkDrainTimeout = 4 * time.Minute

const sharedNetworkDrainInterval = 5 * time.Second

// TestMain gates the package on GATEWAY_E2E and runs Setup before m.Run, outside the -timeout
// alarm; Teardown follows m.Run, which returns only after every Stack's GCP drain completes.
func TestMain(m *testing.M) {
	if os.Getenv("GATEWAY_E2E") == "" {
		os.Exit(0)
	}
	sharedSuite, setupErr = e2eharness.Setup(context.Background())
	code := m.Run()
	if sharedSuite != nil {
		sharedSuite.Teardown(context.Background(), code)
		code = assertSharedNetworkDrained(sharedSuite, code)
	}
	os.Exit(code)
}

// assertSharedNetworkDrained polls until the refcounted shared VPC is gone; the per-stack orphan
// check filters by prefix and never sees it. Skipped on a failing run and under GATEWAY_E2E_KEEP.
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

// sharedSuite is built by TestMain before m.Run; parallel tests share the handle and
// a failed Setup fails each test in getSuite.
var (
	sharedSuite *e2eharness.Suite
	setupErr    error
)

// getSuite returns the suite TestMain built, failing the test when Setup failed.
func getSuite(t *testing.T) *e2eharness.Suite {
	t.Helper()
	if setupErr != nil {
		t.Fatalf("e2e suite setup: %v", setupErr)
	}
	return sharedSuite
}
