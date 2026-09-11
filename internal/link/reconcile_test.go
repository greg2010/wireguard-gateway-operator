package link

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
)

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

// applyRecorder is an injectable applyFunc that records each apply's peer endpoint, resolved and
// unsatisfied forwards, and signals every call on a channel so tests wait without sleeping.
type applyRecorder struct {
	mu          sync.Mutex
	endpoints   []string
	forwards    [][]ResolvedForward
	unsatisfied [][]unsatisfiedForward
	calls       chan string
}

func newApplyRecorder() *applyRecorder {
	return &applyRecorder{calls: make(chan string, 16)}
}

func (r *applyRecorder) apply(_ context.Context, rc RuntimeConfig, _, _ string, forwards []ResolvedForward, unsatisfied []unsatisfiedForward) error {
	r.mu.Lock()
	r.endpoints = append(r.endpoints, rc.WireGuard.Peer.Endpoint)
	r.forwards = append(r.forwards, forwards)
	r.unsatisfied = append(r.unsatisfied, unsatisfied)
	r.mu.Unlock()
	r.calls <- rc.WireGuard.Peer.Endpoint
	return nil
}

func (r *applyRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.endpoints...)
}

func (r *applyRecorder) forwardsAt(t *testing.T, i int) []ResolvedForward {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if i >= len(r.forwards) {
		t.Fatalf("apply %d not recorded; %d applies so far", i, len(r.forwards))
	}
	return r.forwards[i]
}

func (r *applyRecorder) unsatisfiedAt(t *testing.T, i int) []unsatisfiedForward {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if i >= len(r.unsatisfied) {
		t.Fatalf("apply %d not recorded; %d applies so far", i, len(r.unsatisfied))
	}
	return r.unsatisfied[i]
}

func (r *applyRecorder) applyCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.forwards)
}

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

func assertNoApply(t *testing.T, r *applyRecorder, d time.Duration) {
	t.Helper()
	select {
	case ep := <-r.calls:
		t.Fatalf("unexpected apply with endpoint %q", ep)
	case <-time.After(d):
	}
}

// configJSON renders a RuntimeConfig body with the given endpoint and a single forward. An empty
// endpoint models the operator not yet having observed the gateway address.
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

func writeConfig(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config %s: %v", path, err)
	}
}

// startWatchAndReload writes an initial config and runs watchAndReload in a goroutine, returning
// the config path, a cancel func and a done channel carrying the loop's return value.
func startWatchAndReload(t *testing.T, body string, r *applyRecorder) (string, context.CancelFunc, <-chan error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	writeConfig(t, path, body)

	cfg := Config{ConfigPath: path, ReconcileInterval: 20 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- watchAndReload(ctx, cfg, nil, nil, false, "priv", "pub", r.apply, testLogger(t))
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

func TestRulesetDigestStableAndSensitive(t *testing.T) {
	rc := RuntimeConfig{
		TrafficPolicy: TrafficPolicyLocal,
		Identity:      new(NewIdentity(3)),
	}
	forwards := []ResolvedForward{
		{Name: "web", PublicPort: 443, Protocol: "tcp", Target: "10.244.1.7", TargetPort: 9080},
	}

	first, err := RenderNftables(rc, forwards)
	if err != nil {
		t.Fatalf("RenderNftables: %v", err)
	}
	d1 := rulesetDigest(first, nil)
	d2 := rulesetDigest(first, nil)
	if d1 != d2 {
		t.Errorf("digest not stable: %q then %q", d1, d2)
	}

	changedForwards := []ResolvedForward{
		{Name: "web", PublicPort: 443, Protocol: "tcp", Target: "10.244.1.9", TargetPort: 9080},
	}
	second, err := RenderNftables(rc, changedForwards)
	if err != nil {
		t.Fatalf("RenderNftables: %v", err)
	}
	dc := rulesetDigest(second, nil)
	if dc == d1 {
		t.Errorf("endpoint address change produced identical digest %q", d1)
	}

	// An unsatisfied forward renders no rule, so the unsatisfied set is the only
	// thing that can carry its change into the digest.
	unsatisfied := rulesetDigest(first, []unsatisfiedForward{{name: "api", reason: reasonNoLocalPod}})
	if unsatisfied == d1 {
		t.Errorf("an unsatisfied forward produced identical digest %q", d1)
	}
	if reasonChanged := rulesetDigest(first, []unsatisfiedForward{{name: "api", reason: reasonWatchUnsynced}}); reasonChanged == unsatisfied {
		t.Errorf("a changed unsatisfied reason produced identical digest %q", unsatisfied)
	}
}

// TestWatchAndReloadReactsToEndpointChange pins that a Local-mode loop re-applies when the endpoint
// watcher signals a change, even though the on-disk config, and so configDigest, is unchanged.
func TestWatchAndReloadReactsToEndpointChange(t *testing.T) {
	webIndexer := newTestIndexer(t)
	addSlices(t, webIndexer, makeSlice("web-abcde", discoveryv1.AddressTypeIPv4,
		[]discoveryv1.EndpointPort{{Name: new(""), Port: new(int32(9080))}},
		epEntry([]string{"10.244.1.7"}, "node-a", new(true)),
	))
	ew := newWatcherFromIndexers("node-a", []Forward{{Name: "web", PublicPort: 443, Protocol: "tcp", Namespace: "default", ServiceName: "web"}},
		map[endpointWatcherKey]cache.Indexer{
			{namespace: "default", serviceName: "web"}: webIndexer,
		})

	rec := newApplyRecorder()
	path := filepath.Join(t.TempDir(), "config.json")
	body := `{"trafficPolicy":"Local","identity":{"id":3,"interface":"wg-gw3","nftTable":"gw3","mark":"0x00030000","markMask":"0xffff0000","routeTable":100003,"healthPort":27003},"podSelector":{"app":"gateway-link"},` +
		`"wireguard":{"address":"10.244.1.7/32","peer":{"endpoint":"203.0.113.5:51820","allowedIPs":["0.0.0.0/0"]}},` +
		`"forwards":[{"name":"web","publicPort":443,"protocol":"tcp","namespace":"default","serviceName":"web"}]}`
	writeConfig(t, path, body)

	cfg := Config{ConfigPath: path, ReconcileInterval: time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- watchAndReload(ctx, cfg, ew, localConfigIdentity(), false, "priv", "pub", rec.apply, testLogger(t))
	}()

	if ep := waitApply(t, rec); ep != "203.0.113.5:51820" {
		t.Fatalf("initial apply endpoint = %q, want 203.0.113.5:51820", ep)
	}
	assertNoApply(t, rec, 100*time.Millisecond)

	// Change the endpoint address without touching the on-disk config: the ruleset
	// digest changes even though configDigest does not.
	webIndexer2 := newTestIndexer(t)
	addSlices(t, webIndexer2, makeSlice("web-abcde", discoveryv1.AddressTypeIPv4,
		[]discoveryv1.EndpointPort{{Name: new(""), Port: new(int32(9080))}},
		epEntry([]string{"10.244.1.9"}, "node-a", new(true)),
	))
	ew.mu.Lock()
	ew.slices[endpointWatcherKey{namespace: "default", serviceName: "web"}] = newSyncedSliceInformer(webIndexer2)
	ew.mu.Unlock()
	ew.signalChange()

	if ep := waitApply(t, rec); ep != "203.0.113.5:51820" {
		t.Fatalf("post-endpoint-change apply endpoint = %q, want 203.0.113.5:51820", ep)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("watchAndReload returned error on cancel: %v", err)
	}
}

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

// TestWatchAndReloadReAddsWatchOnDirRemoval covers the watch-lost branch: removing the watched dir
// makes the loop re-add the watch, with the safety-net ticker as the guaranteed recovery path.
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
		done <- watchAndReload(ctx, cfg, nil, nil, false, "priv", "pub", rec.apply, log)
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

// waitRecoveryApply drains apply notifications until it sees want. After a dir-removal recovery a
// stale-config apply may precede the recreated one, so intermediate endpoints are skipped.
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

// localConfigJSON is a Local-mode RuntimeConfig body for one forward against the
// default/web Service.
const localConfigJSON = `{"trafficPolicy":"Local","identity":{"id":3,"interface":"wg-gw3","nftTable":"gw3","mark":"0x00030000","markMask":"0xffff0000","routeTable":100003,"healthPort":27003},"podSelector":{"app":"gateway-link"},` +
	`"wireguard":{"address":"10.244.1.7/32","peer":{"endpoint":"203.0.113.5:51820","allowedIPs":["0.0.0.0/0"]}},` +
	`"forwards":[{"name":"web","publicPort":443,"protocol":"tcp","namespace":"default","serviceName":"web"}]}`

// localConfigIdentity is the identity every Local config body in these tests encodes.
func localConfigIdentity() *Identity { return new(NewIdentity(3)) }

// localConfigJSONIdentity is the one-forward Local config body under the identity
// derived for id, so a test can put a config of another identity on disk.
func localConfigJSONIdentity(t *testing.T, id int) string {
	t.Helper()
	ident, err := json.Marshal(NewIdentity(id))
	if err != nil {
		t.Fatalf("marshal identity %d: %v", id, err)
	}
	body := localConfigJSONWith("web")
	startupIdent, err := json.Marshal(*localConfigIdentity())
	if err != nil {
		t.Fatalf("marshal identity: %v", err)
	}
	out := strings.Replace(body, string(startupIdent), string(ident), 1)
	if out == body {
		t.Fatalf("identity block %s not found in %s", startupIdent, body)
	}
	return out
}

// alternatingIndexer answers each List with the next entry of lists, cycling, so a second snapshot
// within one apply resolves differently: that tells digesting one snapshot from applying another.
type alternatingIndexer struct {
	cache.Indexer
	mu    sync.Mutex
	calls int
	lists [][]any
}

func (a *alternatingIndexer) List() []any {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := a.lists[a.calls%len(a.lists)]
	a.calls++
	return out
}

func (a *alternatingIndexer) listCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

// TestWatchAndReloadAppliesTheSnapshotItDigested pins that one apply resolves the endpoints once: a
// store answering two lists differently would leave the digest on a ruleset never installed.
func TestWatchAndReloadAppliesTheSnapshotItDigested(t *testing.T) {
	first := makeSlice("web-abcde", discoveryv1.AddressTypeIPv4,
		[]discoveryv1.EndpointPort{{Name: new(""), Port: new(int32(9080))}},
		epEntry([]string{"10.244.1.7"}, "node-a", new(true)),
	)
	second := makeSlice("web-abcde", discoveryv1.AddressTypeIPv4,
		[]discoveryv1.EndpointPort{{Name: new(""), Port: new(int32(9080))}},
		epEntry([]string{"10.244.1.9"}, "node-a", new(true)),
	)
	indexer := &alternatingIndexer{lists: [][]any{{first}, {second}}}

	ew := newWatcherFromIndexers("node-a", []Forward{{Name: "web", PublicPort: 443, Protocol: "tcp", Namespace: "default", ServiceName: "web"}},
		map[endpointWatcherKey]cache.Indexer{
			{namespace: "default", serviceName: "web"}: indexer,
		})

	rec := newApplyRecorder()
	path := filepath.Join(t.TempDir(), "config.json")
	writeConfig(t, path, localConfigJSON)

	cfg := Config{ConfigPath: path, ReconcileInterval: time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- watchAndReload(ctx, cfg, ew, localConfigIdentity(), false, "priv", "pub", rec.apply, testLogger(t))
	}()

	waitApply(t, rec)
	got := rec.forwardsAt(t, 0)
	if len(got) != 1 || got[0].Target != "10.244.1.7" {
		t.Errorf("applied forwards = %+v, want the first listing 10.244.1.7 the digest was taken from", got)
	}
	if calls := indexer.listCalls(); calls != 1 {
		t.Errorf("endpoint store listed %d times for one apply, want 1", calls)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("watchAndReload returned error on cancel: %v", err)
	}
}

// localConfigJSONWith renders a Local-mode RuntimeConfig body forwarding one public
// port per named backend Service in default, in order.
func localConfigJSONWith(services ...string) string {
	return localConfigJSONEndpoint(localConfigEndpoint, services...)
}

// localConfigEndpoint is the gateway endpoint localConfigJSONWith renders, the one a
// revision that moves the tunnel changes.
const localConfigEndpoint = "203.0.113.5:51820"

// localConfigJSONEndpoint renders localConfigJSONWith's body against a chosen gateway
// endpoint, so a test can model a revision that moves the tunnel.
func localConfigJSONEndpoint(endpoint string, services ...string) string {
	forwards := make([]string, 0, len(services))
	for i, svc := range services {
		forwards = append(forwards, fmt.Sprintf(
			`{"name":"%s","publicPort":%d,"protocol":"tcp","namespace":"default","serviceName":"%s"}`,
			svc, 443+i, svc))
	}
	return `{"trafficPolicy":"Local","identity":{"id":3,"interface":"wg-gw3","nftTable":"gw3","mark":"0x00030000","markMask":"0xffff0000","routeTable":100003,"healthPort":27003},"podSelector":{"app":"gateway-link"},` +
		`"wireguard":{"address":"10.244.1.7/32","peer":{"endpoint":"` + endpoint + `","allowedIPs":["0.0.0.0/0"]}},` +
		`"forwards":[` + strings.Join(forwards, ",") + `]}`
}

// blockingSliceClientset holds the EndpointSlice list for one service open until the returned func
// is called, so a test can keep exactly one forward's watch unsynced while the others sync.
func blockingSliceClientset(t *testing.T, service string, objects ...runtime.Object) (*fake.Clientset, func()) {
	t.Helper()
	release := make(chan struct{})
	cs := fake.NewClientset(objects...)
	cs.PrependReactor("list", "endpointslices", func(action k8stesting.Action) (bool, runtime.Object, error) {
		list, ok := action.(k8stesting.ListAction)
		if ok && strings.Contains(list.GetListRestrictions().Labels.String(), discoveryv1.LabelServiceName+"="+service) {
			<-release
		}
		return false, nil, nil
	})
	var once sync.Once
	return cs, func() { once.Do(func() { close(release) }) }
}

// applyMatching waits for an apply carrying endpoint and exactly the named forwards, from
// index from onwards, and returns nothing but the failure when none arrives.
func applyMatching(t *testing.T, r *applyRecorder, from int, endpoint string, names ...string) {
	t.Helper()
	eventually(t, func() bool {
		for i := from; i < r.applyCount(); i++ {
			if r.snapshot()[i] != endpoint {
				continue
			}
			got := make([]string, 0, len(names))
			for _, f := range r.forwardsAt(t, i) {
				got = append(got, f.Name)
			}
			if slices.Equal(got, names) {
				return true
			}
		}
		return false
	}, fmt.Sprintf("an apply with endpoint %s carrying forwards %v", endpoint, names))
}

// TestWatchAndReloadPendingForwardDefersOnlyWhenApplied pins which pending forward holds an apply
// back: one the last apply programmed, whose rules a re-apply would drop, not one never applied.
func TestWatchAndReloadPendingForwardDefersOnlyWhenApplied(t *testing.T) {
	const node = "node-a"
	const movedEndpoint = "203.0.113.9:51820"

	tcs := []struct {
		name string
		// endpoint is the gateway endpoint the revision carries.
		endpoint string
	}{
		{name: "added_pending_forward_does_not_defer_the_revision", endpoint: localConfigEndpoint},
		{name: "added_pending_forward_does_not_defer_a_tunnel_move", endpoint: movedEndpoint},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			cs, release := blockingSliceClientset(t, "api",
				makeServiceSlice("default", "web", node, "10.244.1.7", 9080),
				makeServiceSlice("default", "api", node, "10.244.1.8", 9090),
			)
			defer release()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			web := Forward{Name: "web", PublicPort: 443, Protocol: "tcp", Namespace: "default", ServiceName: "web"}
			ew, err := newEndpointWatcher(ctx, cs, node, []Forward{web}, "gw-ns",
				labels.SelectorFromSet(map[string]string{"app": "gateway-link"}), time.Minute, testLogger(t))
			if err != nil {
				t.Fatalf("newEndpointWatcher: %v", err)
			}

			rec := newApplyRecorder()
			path := filepath.Join(t.TempDir(), "config.json")
			writeConfig(t, path, localConfigJSONWith("web"))
			cfg := Config{ConfigPath: path, ReconcileInterval: 20 * time.Millisecond}
			done := make(chan error, 1)
			go func() {
				done <- watchAndReload(ctx, cfg, ew, localConfigIdentity(), false, "priv", "pub", rec.apply, testLogger(t))
			}()

			applyMatching(t, rec, 0, localConfigEndpoint, "web")
			before := rec.applyCount()

			writeConfig(t, path, localConfigJSONEndpoint(tc.endpoint, "web", "api"))
			applyMatching(t, rec, before, tc.endpoint, "web")

			release()
			applyMatching(t, rec, before, tc.endpoint, "web", "api")

			cancel()
			if err := <-done; err != nil {
				t.Fatalf("watchAndReload returned error on cancel: %v", err)
			}
		})
	}
}

// TestWatchAndReloadTracksAddedForward pins that a forward added on disk reaches the apply: the
// holder installs the new set on the watcher before snapshotting, rather than ignoring it for life.
func TestWatchAndReloadTracksAddedForward(t *testing.T) {
	const node = "node-a"
	cs := fake.NewClientset(
		makeServiceSlice("default", "web", node, "10.244.1.7", 9080),
		makeServiceSlice("default", "api", node, "10.244.1.8", 9090),
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ew, err := newEndpointWatcher(ctx, cs, node, []Forward{{Name: "web", PublicPort: 443, Protocol: "tcp", Namespace: "default", ServiceName: "web"}},
		"gw-ns", labels.SelectorFromSet(map[string]string{"app": "gateway-link"}), time.Minute, testLogger(t))
	if err != nil {
		t.Fatalf("newEndpointWatcher: %v", err)
	}

	rec := newApplyRecorder()
	path := filepath.Join(t.TempDir(), "config.json")
	writeConfig(t, path, localConfigJSONWith("web"))

	cfg := Config{ConfigPath: path, ReconcileInterval: 20 * time.Millisecond}
	done := make(chan error, 1)
	go func() {
		done <- watchAndReload(ctx, cfg, ew, localConfigIdentity(), false, "priv", "pub", rec.apply, testLogger(t))
	}()

	// The first apply can precede the web informer's initial list, which resolves
	// nothing yet; the apply the sync signals is the one that carries the forward.
	waitApply(t, rec)
	eventually(t, func() bool {
		for i := range rec.applyCount() {
			got := rec.forwardsAt(t, i)
			if len(got) == 1 && got[0].Name == "web" {
				return true
			}
		}
		return false
	}, "an apply carrying the web forward from the initial config")

	writeConfig(t, path, localConfigJSONWith("web", "api"))
	eventually(t, func() bool {
		for i := range rec.applyCount() {
			got := rec.forwardsAt(t, i)
			if len(got) == 2 && got[1].Name == "api" && got[1].Target == "10.244.1.8" {
				return true
			}
		}
		return false
	}, "an apply carrying the forward added to the config on disk")

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("watchAndReload returned error on cancel: %v", err)
	}
}

// blockedSliceClientset blocks every EndpointSlice list until the returned channel is closed, so a
// test can hold an informer unsynced as long as it needs and then let it sync on an empty list.
func blockedSliceClientset(t *testing.T) (*fake.Clientset, chan struct{}) {
	t.Helper()
	release := make(chan struct{})
	cs := fake.NewClientset()
	cs.PrependReactor("list", "endpointslices", func(k8stesting.Action) (bool, runtime.Object, error) {
		<-release
		return false, nil, nil
	})
	return cs, release
}

// startLocalWatchAndReload runs watchAndReload over ew with the one-forward Local config.
// keptDataPlane says the cycle took over a data plane already carrying that forward's rules.
func startLocalWatchAndReload(ctx context.Context, t *testing.T, ew *endpointWatcher, rec *applyRecorder, keptDataPlane bool) (*observer.ObservedLogs, <-chan error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	writeConfig(t, path, localConfigJSON)
	log, logs := observedLogger(t)
	cfg := Config{ConfigPath: path, ReconcileInterval: 20 * time.Millisecond}
	done := make(chan error, 1)
	go func() {
		done <- watchAndReload(ctx, cfg, ew, localConfigIdentity(), keptDataPlane, "priv", "pub", rec.apply, log)
	}()
	return logs, done
}

// TestWatchAndReloadDefersWhilePending pins what a forward whose watch is still listing holds back:
// a cycle that took over its rules waits, one that starts from nothing has none to lose.
func TestWatchAndReloadDefersWhilePending(t *testing.T) {
	const node = "node-a"
	web := Forward{Name: "web", PublicPort: 443, Protocol: "tcp", Namespace: "default", ServiceName: "web"}

	tcs := []struct {
		name string
		// keptDataPlane starts the loop as a cycle that took the node's data plane over.
		keptDataPlane bool
	}{
		{name: "kept_data_plane_defers_the_apply", keptDataPlane: true},
		{name: "fresh_cycle_applies_without_the_pending_forward"},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			cs, release := blockedSliceClientset(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			ew, err := newEndpointWatcher(ctx, cs, node, []Forward{web}, "gw-ns",
				labels.SelectorFromSet(map[string]string{"app": "gateway-link"}), time.Minute, testLogger(t))
			if err != nil {
				t.Fatalf("newEndpointWatcher: %v", err)
			}

			rec := newApplyRecorder()
			logs, done := startLocalWatchAndReload(ctx, t, ew, rec, tc.keptDataPlane)

			if tc.keptDataPlane {
				assertNoApply(t, rec, 200*time.Millisecond)
			} else {
				waitApply(t, rec)
				if got := rec.forwardsAt(t, 0); len(got) != 0 {
					t.Errorf("forwards at first apply = %+v, want none: the watch has not synced", got)
				}
				if got := rec.unsatisfiedAt(t, 0); len(got) != 0 {
					t.Errorf("unsatisfied at first apply = %+v, want none: the watch has not synced", got)
				}
			}
			eventually(t, func() bool {
				return logs.FilterMessage("waiting for endpoint watches to sync").Len() > 0
			}, "expected the pending forward to be logged while the watch is still listing")

			close(release)
			want := []unsatisfiedForward{{name: "web", reason: reasonNoLocalPod}}
			eventually(t, func() bool {
				for i := range rec.applyCount() {
					if slices.Equal(rec.unsatisfiedAt(t, i), want) {
						return true
					}
				}
				return false
			}, "an apply carrying the synced forward as unsatisfied")

			cancel()
			if err := <-done; err != nil {
				t.Fatalf("watchAndReload returned error on cancel: %v", err)
			}
		})
	}
}

// TestWatchAndReloadAppliesAfterSyncGrace pins that a watch that never syncs stops deferring once
// the grace passes: the forward applies as unsatisfied, so the holder faults instead of waiting.
func TestWatchAndReloadAppliesAfterSyncGrace(t *testing.T) {
	const node = "node-a"
	web := Forward{Name: "web", PublicPort: 443, Protocol: "tcp", Namespace: "default", ServiceName: "web"}

	cs, release := blockedSliceClientset(t)
	defer close(release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ew, err := newEndpointWatcher(ctx, cs, node, nil, "gw-ns",
		labels.SelectorFromSet(map[string]string{"app": "gateway-link"}), time.Minute, testLogger(t))
	if err != nil {
		t.Fatalf("newEndpointWatcher: %v", err)
	}
	ew.syncGrace = testSyncGrace
	ew.setForwards([]Forward{web})

	rec := newApplyRecorder()
	_, done := startLocalWatchAndReload(ctx, t, ew, rec, true)

	waitApply(t, rec)
	want := []unsatisfiedForward{{name: "web", reason: reasonWatchUnsynced}}
	if got := rec.unsatisfiedAt(t, 0); !slices.Equal(got, want) {
		t.Errorf("unsatisfied at first apply = %+v, want %+v", got, want)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("watchAndReload returned error on cancel: %v", err)
	}
}

// TestWatchLocalForwards pins that the forward watch tracks the config on disk whatever this
// replica's leadership state, and that an unusable config leaves the last usable set in place.
func TestWatchLocalForwards(t *testing.T) {
	const node = "node-a"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ew, err := newEndpointWatcher(ctx, fake.NewClientset(), node, nil, "gw-ns",
		labels.SelectorFromSet(map[string]string{"app": "gateway-link"}), time.Minute, testLogger(t))
	if err != nil {
		t.Fatalf("newEndpointWatcher: %v", err)
	}

	path := filepath.Join(t.TempDir(), "config.json")
	writeConfig(t, path, localConfigJSONWith("web"))
	cfg := Config{ConfigPath: path, ReconcileInterval: 20 * time.Millisecond}
	done := make(chan error, 1)
	go func() {
		done <- watchLocalForwards(ctx, cfg, ew, localConfigIdentity(), testLogger(t))
	}()

	tcs := []struct {
		name      string
		body      string
		wantCount int
	}{
		{name: "initial_forward_set", body: localConfigJSONWith("web"), wantCount: 1},
		{name: "added_forward_reaches_the_watcher", body: localConfigJSONWith("web", "api"), wantCount: 2},
		{name: "malformed_config_keeps_the_last_set", body: "{not json", wantCount: 2},
		{name: "cluster_config_keeps_the_last_set", body: configJSON("203.0.113.5:51820", "web.default.svc"), wantCount: 2},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			writeConfig(t, path, tc.body)
			// A rejected config changes nothing, so give the loop a tick to
			// process the write before the count is read as evidence.
			time.Sleep(100 * time.Millisecond)
			eventually(t, func() bool { return ew.evaluate().forwardCount == tc.wantCount }, "the watcher to track "+tc.name)
			select {
			case err := <-done:
				t.Fatalf("watchLocalForwards returned early: %v", err)
			default:
			}
		})
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("watchLocalForwards returned error on cancel: %v", err)
	}
}

// TestWatchAndReloadRefusesMismatchedConfig pins the startup guard: the watcher, RBAC, netns and
// the names the fence removes are fixed at start, so another mode or identity applies nothing.
func TestWatchAndReloadRefusesMismatchedConfig(t *testing.T) {
	tcs := []struct {
		name string
		body func(t *testing.T) string
		// local runs the loop as a Local-mode process started with identity 1.
		local bool
	}{
		{name: "other_mode", body: func(*testing.T) string { return localConfigJSONWith("web") }},
		{
			name:  "other_identity",
			body:  func(t *testing.T) string { return localConfigJSONIdentity(t, 2) },
			local: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			rec := newApplyRecorder()
			var ew *endpointWatcher
			var identity *Identity
			if tc.local {
				ew = newWatcherFromIndexers("node-a", nil, nil)
				identity = new(NewIdentity(1))
			}

			path := filepath.Join(t.TempDir(), "config.json")
			writeConfig(t, path, tc.body(t))
			cfg := Config{ConfigPath: path, ReconcileInterval: 20 * time.Millisecond}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- watchAndReload(ctx, cfg, ew, identity, false, "priv", "pub", rec.apply, testLogger(t))
			}()

			assertNoApply(t, rec, 100*time.Millisecond)

			cancel()
			if err := <-done; err != nil {
				t.Fatalf("watchAndReload returned error on cancel: %v", err)
			}
		})
	}
}
