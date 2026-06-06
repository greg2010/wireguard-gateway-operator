package e2e_test

import (
	"context"
	"os"
	"sync"
	"testing"

	e2eharness "github.com/greg2010/wireguard-gateway-operator/test/harness/e2e"
)

// TestMain gates the entire e2e package on CYNO_E2E so `go test ./...` never
// provisions a kind cluster or touches GCP. The required GCP env is validated
// per-test (via getSuite -> RequireEnv) so a missing var fails the test with a
// clear t.Fatal message rather than an opaque package-level exit.
func TestMain(m *testing.M) {
	if os.Getenv("CYNO_E2E") == "" {
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// sharedSuite lazily builds the suite (kind cluster, Crossplane stack, cyno
// image) once per `go test` invocation. The first test to call getSuite builds
// it under setupOnce; cluster teardown is registered via that test's t.Cleanup
// inside Setup. Subsequent parallel tests reuse the handle.
var (
	setupOnce   sync.Once
	sharedSuite *e2eharness.Suite
	setupErr    error
)

// getSuite returns the shared suite, building it on first call. It is safe for
// parallel tests: the build runs once and later callers observe the result.
func getSuite(t *testing.T) *e2eharness.Suite {
	t.Helper()
	setupOnce.Do(func() {
		sharedSuite, setupErr = e2eharness.Setup(context.Background(), t)
	})
	if setupErr != nil {
		t.Fatalf("e2e suite setup: %v", setupErr)
	}
	return sharedSuite
}
