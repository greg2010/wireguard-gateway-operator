// Package netns drives network-stack tests inside a throwaway privileged container.
// It loads a rendered nftables ruleset into a real kernel, so a syntax error or a
// construct the kernel rejects fails in a test instead of on a booting gateway, and
// it lets a test build netns topologies with the ip tooling and run traffic through
// them from whatever extra packages it asks for.
package netns

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	// image is pinned so rulesets load against a known nftables build.
	image = "alpine:3.20"

	// rulesetPath stands in for `nft -f -` because exec cannot pipe stdin; the
	// transaction nft runs is identical.
	rulesetPath = "/tmp/ruleset.nft"

	startTimeout = 2 * time.Minute
	execTimeout  = 30 * time.Second
)

// Start brings up the pinned image with nft and the ip tooling installed, plus any
// extraPackages, and returns the running container, terminated when t finishes.
// NET_ADMIN lets nft program the netns; Privileged is a fallback for runtimes that
// ignore the capability add. Callers gate on
// testcontainers.SkipIfProviderIsNotHealthy; an apk failure here is a real
// environment failure and fails the test.
func Start(ctx context.Context, t testing.TB, extraPackages ...string) testcontainers.Container {
	t.Helper()

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:      image,
			Entrypoint: []string{"sleep", "infinity"},
			Labels:     map[string]string{"gateway.test": "integration"},
			HostConfigModifier: func(hc *container.HostConfig) {
				hc.CapAdd = append(hc.CapAdd, "NET_ADMIN")
				hc.Privileged = true
			},
			WaitingFor: wait.ForExec([]string{"true"}).WithStartupTimeout(startTimeout),
		},
		Started: true,
	})
	// Registered before the error check: a start that fails its wait strategy still
	// returns a live container, which would otherwise leak for the runtime's lifetime.
	if ctr != nil {
		t.Cleanup(func() {
			if terr := ctr.Terminate(context.Background()); terr != nil {
				t.Logf("terminate netns container: %v", terr)
			}
		})
	}
	if err != nil {
		t.Fatalf("start netns container: %v", err)
	}

	packages := append([]string{"apk", "add", "--no-cache", "nftables", "iproute2"}, extraPackages...)
	code, out := Exec(ctx, t, ctr, packages...)
	if code != 0 {
		t.Fatalf("%v failed (exit %d):\n%s", packages, code, out)
	}
	return ctr
}

// Apply copies ruleset into the container and loads it with `nft -f`, the same
// atomic transaction production runs.
func Apply(ctx context.Context, t testing.TB, ctr testcontainers.Container, ruleset string) {
	t.Helper()
	if err := ctr.CopyToContainer(ctx, []byte(ruleset), rulesetPath, 0o644); err != nil {
		t.Fatalf("copy ruleset to container: %v", err)
	}
	code, out := Exec(ctx, t, ctr, "nft", "-f", rulesetPath)
	if code != 0 {
		t.Fatalf("nft -f %s failed (exit %d):\n%s\n--- ruleset ---\n%s", rulesetPath, code, out, ruleset)
	}
}

// List returns the kernel's view of the loaded ruleset, running `nft list` with
// args (e.g. "ruleset", or "table", "inet", "gateway").
func List(ctx context.Context, t testing.TB, ctr testcontainers.Container, args ...string) string {
	t.Helper()
	cmd := append([]string{"nft", "list"}, args...)
	code, out := Exec(ctx, t, ctr, cmd...)
	if code != 0 {
		t.Fatalf("%v failed (exit %d):\n%s", cmd, code, out)
	}
	return out
}

// Exec runs cmd in the container and returns its exit code and combined output.
func Exec(ctx context.Context, t testing.TB, ctr testcontainers.Container, cmd ...string) (int, string) {
	t.Helper()
	execCtx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()

	code, reader, err := ctr.Exec(execCtx, cmd, tcexec.Multiplexed())
	if err != nil {
		t.Fatalf("exec %v: %v", cmd, err)
	}
	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read output of %v: %v", cmd, err)
	}
	return code, string(out)
}
