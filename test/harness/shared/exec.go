// Package shared provides cross-cutting test-harness utilities: repo-root
// resolution, command execution, and tee-to-file output capture used by the
// e2e harness.
package shared

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// RepoRoot returns the absolute path of the repository root by navigating from
// this source file (test/harness/shared/exec.go -> repo root is three levels
// up). Callers need not hard-code paths.
func RepoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..")
}

// RunCmd executes name with args, inheriting os.Environ() and appending
// extraEnv. It returns the combined stdout+stderr output and any error. The
// command is bound to ctx, so a cancelled context kills the process.
func RunCmd(ctx context.Context, extraEnv []string, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), extraEnv...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// RunCmdStdout runs name with args like RunCmd but returns only stdout. stderr is
// captured separately and surfaced only inside the returned error on failure. Use
// when stderr carries diagnostics that must not contaminate parsed stdout (e.g.
// gcloud prints a benign WARNING to stderr when a --filter matches an empty list).
func RunCmdStdout(ctx context.Context, extraEnv []string, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), extraEnv...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return strings.TrimSpace(stdout.String()), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// RunCmdTee executes name with args like RunCmd but additionally streams the
// combined output to logPath as it runs. Long-running deploy commands tee here
// so multi-megabyte output lands in a file under .test-output/ rather than the
// test's inline log. The returned string is still the full captured output so
// callers can fold it into error messages.
func RunCmdTee(ctx context.Context, extraEnv []string, logPath, name string, args ...string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return "", fmt.Errorf("create tee dir %s: %w", filepath.Dir(logPath), err)
	}
	f, err := os.Create(logPath)
	if err != nil {
		return "", fmt.Errorf("create tee file %s: %w", logPath, err)
	}
	defer f.Close()

	var buf strings.Builder
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), extraEnv...)
	cmd.Stdout = teeWriter{&buf, f}
	cmd.Stderr = teeWriter{&buf, f}
	err = cmd.Run()
	return strings.TrimSpace(buf.String()), err
}

// teeWriter fans a single write to both an in-memory buffer (so the caller can
// inspect the output) and a file (so the operator can tail it live).
type teeWriter struct {
	buf *strings.Builder
	f   *os.File
}

func (t teeWriter) Write(p []byte) (int, error) {
	t.buf.Write(p)
	return t.f.Write(p)
}

// TestOutputDir returns the repo's .test-output directory, the standard
// destination for tee'd long-running command logs.
func TestOutputDir() string {
	return filepath.Join(RepoRoot(), ".test-output")
}
