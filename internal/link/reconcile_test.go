package link

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// testLogger returns a no-op sugared logger for tests that do not assert on logs.
func testLogger(t *testing.T) *zap.SugaredLogger {
	t.Helper()
	return zap.NewNop().Sugar()
}

// observedLogger returns a sugared logger backed by an in-memory observer so a
// test can assert on emitted log entries, paired with the recorded logs.
func observedLogger(t testing.TB) (*zap.SugaredLogger, *observer.ObservedLogs) {
	t.Helper()
	core, logs := observer.New(zapcore.DebugLevel)
	return zap.New(core).Sugar(), logs
}

// applyRecorder is an injectable applyFunc that records each apply's peer
// endpoint and signals every call on a channel so tests wait without sleeping.
type applyRecorder struct {
	mu        sync.Mutex
	endpoints []string
	calls     chan string
}

func newApplyRecorder() *applyRecorder {
	return &applyRecorder{calls: make(chan string, 16)}
}

func (r *applyRecorder) apply(_ context.Context, rc RuntimeConfig, _, _ string) error {
	r.mu.Lock()
	r.endpoints = append(r.endpoints, rc.WireGuard.Peer.Endpoint)
	r.mu.Unlock()
	r.calls <- rc.WireGuard.Peer.Endpoint
	return nil
}

func (r *applyRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.endpoints...)
}

// waitApply blocks for the next apply endpoint or fails the test on timeout.
func waitApply(t *testing.T, r *applyRecorder) string {
	t.Helper()
	select {
	case ep := <-r.calls:
		return ep
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for apply; recorded so far: %v", r.snapshot())
		return ""
	}
}

// assertNoApply fails if an apply happens within d.
func assertNoApply(t *testing.T, r *applyRecorder, d time.Duration) {
	t.Helper()
	select {
	case ep := <-r.calls:
		t.Fatalf("unexpected apply with endpoint %q", ep)
	case <-time.After(d):
	}
}

// configJSON renders a RuntimeConfig JSON body with the given endpoint and a
// single forward. An empty endpoint models the operator not yet having observed
// the gateway address.
func configJSON(endpoint, service string) string {
	ep := ""
	if endpoint != "" {
		ep = `"endpoint":"` + endpoint + `",`
	}
	return `{"wireguard":{"address":"10.99.0.2/32","peer":{` + ep +
		`"allowedIPs":["10.99.0.1/32"],"persistentKeepalive":25}},` +
		`"forwards":[{"name":"web","publicPort":443,"protocol":"tcp","service":"` + service +
		`","targetPort":8443}]}`
}

// writeConfig writes body to path with 0600 perms, failing the test on error.
func writeConfig(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config %s: %v", path, err)
	}
}

// startWatchAndReload writes an initial config and runs watchAndReload in a
// goroutine, returning the config path, a cancel func, and a done channel
// carrying the loop's return value.
func startWatchAndReload(t *testing.T, body string, r *applyRecorder) (string, context.CancelFunc, <-chan error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	writeConfig(t, path, body)

	cfg := Config{ConfigPath: path, ReconcileInterval: 20 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- watchAndReload(ctx, cfg, "priv", "pub", r.apply, testLogger(t))
	}()
	return path, cancel, done
}

func TestWatchAndReloadInitialApply(t *testing.T) {
	rec := newApplyRecorder()
	_, cancel, done := startWatchAndReload(t, configJSON("203.0.113.5:51820", "web.default.svc"), rec)
	defer cancel()

	if ep := waitApply(t, rec); ep != "203.0.113.5:51820" {
		t.Fatalf("initial apply endpoint = %q, want 203.0.113.5:51820", ep)
	}
	// An unchanged config must not re-apply on the safety-net ticks.
	assertNoApply(t, rec, 100*time.Millisecond)

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("watchAndReload returned error on cancel: %v", err)
	}
}

func TestWatchAndReloadEndpointChange(t *testing.T) {
	rec := newApplyRecorder()
	path, cancel, done := startWatchAndReload(t, configJSON("203.0.113.5:51820", "web.default.svc"), rec)
	defer cancel()

	if ep := waitApply(t, rec); ep != "203.0.113.5:51820" {
		t.Fatalf("initial apply endpoint = %q, want 203.0.113.5:51820", ep)
	}

	writeConfig(t, path, configJSON("203.0.113.9:51820", "web.default.svc"))

	if ep := waitApply(t, rec); ep != "203.0.113.9:51820" {
		t.Fatalf("post-change apply endpoint = %q, want 203.0.113.9:51820", ep)
	}
	assertNoApply(t, rec, 100*time.Millisecond)

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("watchAndReload returned error on cancel: %v", err)
	}
}

func TestWatchAndReloadForwardsChange(t *testing.T) {
	rec := newApplyRecorder()
	path, cancel, done := startWatchAndReload(t, configJSON("203.0.113.5:51820", "web.default.svc"), rec)
	defer cancel()

	if ep := waitApply(t, rec); ep != "203.0.113.5:51820" {
		t.Fatalf("initial apply endpoint = %q, want 203.0.113.5:51820", ep)
	}

	// Endpoint unchanged, forwards changed: the digest differs, so it must re-apply.
	writeConfig(t, path, configJSON("203.0.113.5:51820", "api.default.svc"))

	if ep := waitApply(t, rec); ep != "203.0.113.5:51820" {
		t.Fatalf("post-forwards-change apply endpoint = %q, want 203.0.113.5:51820", ep)
	}
	assertNoApply(t, rec, 100*time.Millisecond)

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("watchAndReload returned error on cancel: %v", err)
	}
}

func TestWatchAndReloadEmptyEndpointWaits(t *testing.T) {
	rec := newApplyRecorder()
	path, cancel, done := startWatchAndReload(t, configJSON("", "web.default.svc"), rec)
	defer cancel()

	// No endpoint yet: the loop must wait across several safety-net ticks, not
	// apply or exit.
	assertNoApply(t, rec, 150*time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("watchAndReload exited while waiting for endpoint: %v", err)
	default:
	}

	// Once the operator fills the endpoint in, the next reload applies.
	writeConfig(t, path, configJSON("203.0.113.5:51820", "web.default.svc"))
	if ep := waitApply(t, rec); ep != "203.0.113.5:51820" {
		t.Fatalf("apply endpoint after endpoint appears = %q, want 203.0.113.5:51820", ep)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("watchAndReload returned error on cancel: %v", err)
	}
}

func TestWatchAndReloadCancelReturnsNil(t *testing.T) {
	rec := newApplyRecorder()
	_, cancel, done := startWatchAndReload(t, configJSON("203.0.113.5:51820", "web.default.svc"), rec)
	defer cancel()

	if ep := waitApply(t, rec); ep != "203.0.113.5:51820" {
		t.Fatalf("initial apply endpoint = %q, want 203.0.113.5:51820", ep)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("watchAndReload returned %v on cancel, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watchAndReload did not return after cancel")
	}
}

func TestConfigDigestStableAndSensitive(t *testing.T) {
	base := RuntimeConfig{
		WireGuard: WireGuard{
			Address: "10.99.0.2/32",
			Peer: Peer{
				Endpoint:            "203.0.113.5:51820",
				AllowedIPs:          []string{"10.99.0.1/32"},
				PersistentKeepalive: 25,
			},
		},
		Forwards: []Forward{{Name: "web", PublicPort: 443, Protocol: "tcp", Service: "web", TargetPort: 8443}},
	}

	d1, err := configDigest(base)
	if err != nil {
		t.Fatalf("configDigest: %v", err)
	}
	d2, err := configDigest(base)
	if err != nil {
		t.Fatalf("configDigest: %v", err)
	}
	if d1 != d2 {
		t.Errorf("digest not stable: %q then %q", d1, d2)
	}

	changed := base
	changed.WireGuard.Peer.Endpoint = "203.0.113.9:51820"
	dc, err := configDigest(changed)
	if err != nil {
		t.Fatalf("configDigest: %v", err)
	}
	if dc == d1 {
		t.Errorf("endpoint change produced identical digest %q", d1)
	}
}

// eventually polls cond until true or the deadline passes, failing with msg on
// timeout.
func eventually(t testing.TB, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met within deadline: %s", msg)
}

// TestWatchAndReloadReAddsWatchOnDirRemoval covers the watch-lost branch: removing the
// watched config dir makes the loop re-add the watch and keep functioning, with the
// safety-net ticker as the guaranteed recovery path.
func TestWatchAndReloadReAddsWatchOnDirRemoval(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "configdir")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir watched dir: %v", err)
	}
	path := filepath.Join(dir, "config.json")
	writeConfig(t, path, configJSON("203.0.113.5:51820", "web.default.svc"))

	rec := newApplyRecorder()
	log, logs := observedLogger(t)
	cfg := Config{ConfigPath: path, ReconcileInterval: 200 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- watchAndReload(ctx, cfg, "priv", "pub", rec.apply, log)
	}()

	if ep := waitApply(t, rec); ep != "203.0.113.5:51820" {
		t.Fatalf("initial apply endpoint = %q, want 203.0.113.5:51820", ep)
	}

	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("remove watched dir: %v", err)
	}
	eventually(t, func() bool {
		return logs.FilterMessage("config dir watch lost, re-adding").Len() > 0
	}, "expected a watch-lost warning after removing the watched dir")

	// Recreate the dir with a changed config; the loop must recover and apply it,
	// via either the re-added watch or the safety-net ticker.
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("recreate watched dir: %v", err)
	}
	writeConfig(t, path, configJSON("203.0.113.9:51820", "web.default.svc"))
	if ep := waitRecoveryApply(t, rec, "203.0.113.9:51820"); ep != "203.0.113.9:51820" {
		t.Fatalf("recovery apply endpoint = %q, want 203.0.113.9:51820", ep)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("watchAndReload returned error on cancel: %v", err)
	}
}

// waitRecoveryApply drains apply notifications until it sees want or the deadline
// passes. After a dir-removal recovery a stale-config apply may precede the
// recreated one, so it skips intermediate endpoints rather than failing on them.
func waitRecoveryApply(t testing.TB, r *applyRecorder, want string) string {
	t.Helper()
	deadline := time.After(4 * time.Second)
	for {
		select {
		case ep := <-r.calls:
			if ep == want {
				return ep
			}
		case <-deadline:
			t.Fatalf("timed out waiting for recovery apply %q; recorded so far: %v", want, r.snapshot())
			return ""
		}
	}
}
