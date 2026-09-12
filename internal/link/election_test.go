package link

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	coordinationv1client "k8s.io/client-go/kubernetes/typed/coordination/v1"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

// TestElectionDecisions exercises entryDecision and handoffDecision, the pure functions behind
// the election loops, against spec 7's gating table.
func TestElectionDecisions(t *testing.T) {
	const forwardCount = 2
	now := time.Unix(1700001000, 0)
	longAgo := now.Add(-handoffHold - time.Second)
	recently := now.Add(-time.Second)

	view := func(live map[string]bool, scores map[string]int) electionView {
		return electionView{forwardCount: forwardCount, live: live, scores: scores}
	}

	t.Run("entry", func(t *testing.T) {
		tcs := []struct {
			name                string
			node                string
			live                map[string]bool
			scores              map[string]int
			noEligiblePeerSince time.Time
			// noHolderSince is when the Lease was first seen free, zero while a live
			// holder is on it.
			noHolderSince time.Time
			want          bool
		}{
			{
				name:   "self_fully_eligible_no_holder_enters_now",
				node:   "node-a",
				live:   map[string]bool{"node-a": true},
				scores: map[string]int{"node-a": forwardCount},
				want:   true,
			},
			{
				name:                "self_partial_no_peer_fully_eligible_elapsed_under_hold_waits",
				node:                "node-a",
				live:                map[string]bool{"node-a": true},
				scores:              map[string]int{"node-a": 1},
				noEligiblePeerSince: recently,
				noHolderSince:       longAgo,
				want:                false,
			},
			{
				name:                "self_partial_no_peer_fully_eligible_elapsed_over_hold_enters",
				node:                "node-a",
				live:                map[string]bool{"node-a": true},
				scores:              map[string]int{"node-a": 1},
				noEligiblePeerSince: longAgo,
				noHolderSince:       longAgo,
				want:                true,
			},
			{
				name:                "self_partial_peer_fully_eligible_defers_regardless_of_elapsed",
				node:                "node-a",
				live:                map[string]bool{"node-a": true, "node-b": true},
				scores:              map[string]int{"node-a": 1, "node-b": forwardCount},
				noEligiblePeerSince: longAgo,
				noHolderSince:       longAgo,
				want:                false,
			},
			{
				name:                "self_partial_not_best_score_waits_even_after_hold",
				node:                "node-a",
				live:                map[string]bool{"node-a": true, "node-b": true},
				scores:              map[string]int{"node-a": 0, "node-b": 1},
				noEligiblePeerSince: longAgo,
				noHolderSince:       longAgo,
				want:                false,
			},
			{
				name:                "self_partial_held_lease_waits_however_long_it_has_been_the_best",
				node:                "node-a",
				live:                map[string]bool{"node-a": true},
				scores:              map[string]int{"node-a": 1},
				noEligiblePeerSince: longAgo,
				want:                false,
			},
			{
				name:                "self_partial_lease_free_under_hold_waits",
				node:                "node-a",
				live:                map[string]bool{"node-a": true},
				scores:              map[string]int{"node-a": 1},
				noEligiblePeerSince: longAgo,
				noHolderSince:       recently,
				want:                false,
			},
			{
				name:                "self_partial_peer_seen_recently_waits_although_the_lease_is_long_free",
				node:                "node-a",
				live:                map[string]bool{"node-a": true},
				scores:              map[string]int{"node-a": 1},
				noEligiblePeerSince: recently,
				noHolderSince:       longAgo,
				want:                false,
			},
			{
				name:                "self_fully_eligible_enters_although_the_lease_is_held",
				node:                "node-a",
				live:                map[string]bool{"node-a": true},
				scores:              map[string]int{"node-a": forwardCount},
				noEligiblePeerSince: longAgo,
				want:                true,
			},
		}
		for _, tc := range tcs {
			t.Run(tc.name, func(t *testing.T) {
				got := entryDecision(tc.node, view(tc.live, tc.scores), tc.noEligiblePeerSince, tc.noHolderSince, now, handoffHold)
				if got != tc.want {
					t.Errorf("entryDecision = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("handoff", func(t *testing.T) {
		tcs := []struct {
			name              string
			node              string
			live              map[string]bool
			scores            map[string]int
			eligiblePeerSince time.Time
			want              bool
		}{
			{
				name:   "fully_eligible_leader_never_hands_off",
				node:   "node-a",
				live:   map[string]bool{"node-a": true, "node-b": true},
				scores: map[string]int{"node-a": forwardCount, "node-b": forwardCount},
				want:   false,
			},
			{
				name:   "score_zero_peer_scores_above_zero_releases_at_once",
				node:   "node-a",
				live:   map[string]bool{"node-a": true, "node-b": true},
				scores: map[string]int{"node-a": 0, "node-b": 1},
				want:   true,
			},
			{
				name:   "score_zero_no_peer_scores_above_zero_holds",
				node:   "node-a",
				live:   map[string]bool{"node-a": true, "node-b": true},
				scores: map[string]int{"node-a": 0, "node-b": 0},
				want:   false,
			},
			{
				name:              "partial_score_no_fully_eligible_peer_holds_despite_elapsed",
				node:              "node-a",
				live:              map[string]bool{"node-a": true, "node-b": true},
				scores:            map[string]int{"node-a": 1, "node-b": 1},
				eligiblePeerSince: longAgo,
				want:              false,
			},
			{
				name:              "partial_score_fully_eligible_peer_under_hold_holds",
				node:              "node-a",
				live:              map[string]bool{"node-a": true, "node-b": true},
				scores:            map[string]int{"node-a": 1, "node-b": forwardCount},
				eligiblePeerSince: recently,
				want:              false,
			},
			{
				name:              "partial_score_fully_eligible_peer_over_hold_releases",
				node:              "node-a",
				live:              map[string]bool{"node-a": true, "node-b": true},
				scores:            map[string]int{"node-a": 1, "node-b": forwardCount},
				eligiblePeerSince: longAgo,
				want:              true,
			},
		}
		for _, tc := range tcs {
			t.Run(tc.name, func(t *testing.T) {
				got := handoffDecision(tc.node, view(tc.live, tc.scores), tc.eligiblePeerSince, now, handoffHold)
				if got != tc.want {
					t.Errorf("handoffDecision = %v, want %v", got, tc.want)
				}
			})
		}
	})
}

// TestTeardownDecision covers the step-down, SIGTERM, forced-end and fail-static choice against
// spec 7's Lease-loss row and the three exit paths that always fence.
func TestTeardownDecision(t *testing.T) {
	const self = "pod-a"

	tcs := []struct {
		name         string
		steppedDown  bool
		sigterm      bool
		forced       bool
		readOK       bool
		holder       string
		self         string
		term         int32
		acquiredTerm int32
		// acquiredTermUnknown models a failed acquire-time read of
		// spec.leaseTransitions, where no floor to compare term against exists.
		acquiredTermUnknown bool
		want                bool
	}{
		{
			name:         "different_holder_higher_term_tears_down",
			readOK:       true,
			holder:       "pod-b",
			self:         self,
			term:         2,
			acquiredTerm: 1,
			want:         true,
		},
		{
			name:         "different_holder_equal_term_keeps_serving",
			readOK:       true,
			holder:       "pod-b",
			self:         self,
			term:         1,
			acquiredTerm: 1,
			want:         false,
		},
		{
			name:         "same_holder_keeps_serving",
			readOK:       true,
			holder:       self,
			self:         self,
			term:         5,
			acquiredTerm: 1,
			want:         false,
		},
		{
			name:         "read_failed_keeps_serving",
			readOK:       false,
			holder:       "pod-b",
			self:         self,
			term:         2,
			acquiredTerm: 1,
			want:         false,
		},
		{
			name:        "voluntary_step_down_tears_down",
			steppedDown: true,
			self:        self,
			want:        true,
		},
		{
			name:                "unknown_acquired_term_keeps_serving",
			readOK:              true,
			holder:              "pod-b",
			self:                self,
			term:                2,
			acquiredTermUnknown: true,
			want:                false,
		},
		{
			name:    "sigterm_tears_down",
			sigterm: true,
			self:    self,
			want:    true,
		},
		{
			name:         "forced_end_tears_down",
			forced:       true,
			readOK:       true,
			holder:       self,
			self:         self,
			term:         1,
			acquiredTerm: 1,
			want:         true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got := teardownDecision(tc.steppedDown, tc.sigterm, tc.forced, tc.readOK, tc.holder, tc.self, tc.term, tc.acquiredTerm, !tc.acquiredTermUnknown)
			if got != tc.want {
				t.Errorf("teardownDecision = %v, want %v", got, tc.want)
			}
		})
	}
}

// electionFixture builds an endpointWatcher over per-node EndpointSlices and link pods. Every
// store is a locked cache.Indexer, so a test can edit endpoints while a loop reads.
type electionFixture struct {
	watcher  *endpointWatcher
	indexers map[string]cache.Indexer
}

// newElectionFixture wires one indexer per service in services plus a pod indexer
// holding a ready link pod on each node in liveNodes.
func newElectionFixture(t *testing.T, node string, services, liveNodes []string) *electionFixture {
	t.Helper()
	forwards := make([]Forward, 0, len(services))
	indexers := make(map[string]cache.Indexer, len(services))
	sliceIndexers := make(map[endpointWatcherKey]cache.Indexer, len(services))
	for _, svc := range services {
		forwards = append(forwards, Forward{Name: svc, Namespace: "default", ServiceName: svc})
		idx := newTestIndexer(t)
		indexers[svc] = idx
		sliceIndexers[endpointWatcherKey{namespace: "default", serviceName: svc}] = idx
	}

	podIndexer := newTestIndexer(t)
	for _, n := range liveNodes {
		addPods(t, podIndexer, makePod("link-"+n, n, true))
	}

	watcher := newWatcherFromIndexers(node, forwards, sliceIndexers)
	watcher.podIndexer = podIndexer
	return &electionFixture{watcher: watcher, indexers: indexers}
}

// addForward extends the watched forward set with a service no node serves, raising the score a
// fully eligible node must reach, which is what the election loops must observe live.
func (f *electionFixture) addForward(t *testing.T, service string) {
	t.Helper()
	idx := newTestIndexer(t)
	f.indexers[service] = idx

	f.watcher.mu.Lock()
	f.watcher.slices[endpointWatcherKey{namespace: "default", serviceName: service}] = newSyncedSliceInformer(idx)
	f.watcher.forwards = append(f.watcher.forwards, Forward{Name: service, Namespace: "default", ServiceName: service})
	f.watcher.mu.Unlock()

	f.watcher.signalChange()
}

// pendingForward adds a forward whose EndpointSlice informer has not synced and returns the func
// that marks it synced. The grace is widened so the pending window outlasts the test's ticks.
func (f *electionFixture) pendingForward(t *testing.T, service string) func() {
	t.Helper()
	idx := newTestIndexer(t)
	f.indexers[service] = idx

	var synced atomic.Bool
	f.watcher.mu.Lock()
	f.watcher.syncGrace = time.Minute
	f.watcher.slices[endpointWatcherKey{namespace: "default", serviceName: service}] = &sliceInformer{
		indexer:   idx,
		hasSynced: synced.Load,
		started:   time.Now(),
		stop:      func() {},
	}
	f.watcher.forwards = append(f.watcher.forwards, Forward{Name: service, Namespace: "default", ServiceName: service})
	f.watcher.mu.Unlock()
	f.watcher.signalChange()

	return func() {
		synced.Store(true)
		f.watcher.signalChange()
	}
}

// endpointOn adds a ready endpoint for service on node, raising that node's score.
func (f *electionFixture) endpointOn(t *testing.T, service, node string) {
	t.Helper()
	addSlices(t, f.indexers[service], makeSlice(service+"-"+node, discoveryv1.AddressTypeIPv4,
		[]discoveryv1.EndpointPort{{Name: new(""), Port: new(int32(9080))}},
		epEntry([]string{"10.244.1.7"}, node, new(true)),
	))
}

// dropEndpointOn removes service's endpoint on node, lowering that node's score.
func (f *electionFixture) dropEndpointOn(t *testing.T, service, node string) {
	t.Helper()
	obj, ok, err := f.indexers[service].GetByKey("default/" + service + "-" + node)
	if err != nil || !ok {
		t.Fatalf("get slice %s-%s: ok=%v err=%v", service, node, ok, err)
	}
	if err := f.indexers[service].Delete(obj); err != nil {
		t.Fatalf("delete slice %s-%s: %v", service, node, err)
	}
}

// fastElectionTiming polls often and holds briefly so a loop test runs in
// milliseconds instead of the production lease multiples.
var fastElectionTiming = electionTiming{
	retry: 5 * time.Millisecond,
	hold:  150 * time.Millisecond,
	lease: 300 * time.Millisecond,
	renew: 200 * time.Millisecond,
	fence: 50 * time.Millisecond,
}

// TestMonitorHandoff drives the real loop, not just handoffDecision: a peer must be visible for
// the whole hold, and a leader that can serve nothing releases at once.
func TestMonitorHandoff(t *testing.T) {
	const node, peer = "node-a", "node-b"

	tcs := []struct {
		name string
		// setup seeds the endpoint stores before the monitor starts.
		setup func(t *testing.T, f *electionFixture)
		// mutate runs once the monitor is going, modelling a change mid-hold.
		mutate     func(t *testing.T, f *electionFixture)
		wantCancel bool
	}{
		{
			name: "fully_eligible_peer_persists_releases_after_hold",
			setup: func(t *testing.T, f *electionFixture) {
				f.endpointOn(t, "web", node)
				f.endpointOn(t, "web", peer)
				f.endpointOn(t, "api", peer)
			},
			wantCancel: true,
		},
		{
			name: "fully_eligible_peer_disappears_before_hold_keeps_lease",
			setup: func(t *testing.T, f *electionFixture) {
				f.endpointOn(t, "web", node)
				f.endpointOn(t, "web", peer)
				f.endpointOn(t, "api", peer)
			},
			mutate: func(t *testing.T, f *electionFixture) {
				f.dropEndpointOn(t, "api", peer)
			},
			wantCancel: false,
		},
		{
			name: "score_zero_against_scoring_peer_releases_at_once",
			setup: func(t *testing.T, f *electionFixture) {
				f.endpointOn(t, "web", peer)
			},
			wantCancel: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			f := newElectionFixture(t, node, []string{"web", "api"}, []string{node, peer})
			tc.setup(t, f)

			cancelled := make(chan struct{})
			var once sync.Once
			endCycle := func() { once.Do(func() { close(cancelled) }) }

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var steppedDown atomic.Bool
			done := make(chan struct{})
			go func() {
				defer close(done)
				monitorHandoff(ctx, endCycle, node, f.watcher, fastElectionTiming, &steppedDown, testLogger(t))
			}()

			if tc.mutate != nil {
				// Well inside the hold, so the loop has seen the peer but not yet
				// acted on it.
				time.Sleep(fastElectionTiming.hold / 3)
				tc.mutate(t, f)
			}

			select {
			case <-cancelled:
				if !tc.wantCancel {
					t.Fatal("monitorHandoff released the lease, want it held")
				}
			case <-time.After(3 * fastElectionTiming.hold):
				if tc.wantCancel {
					t.Fatal("monitorHandoff did not release the lease within three holds")
				}
			}

			cancel()
			<-done
			if got := steppedDown.Load(); got != tc.wantCancel {
				t.Errorf("steppedDown = %v, want %v", got, tc.wantCancel)
			}
		})
	}
}

// TestWaitForEntryEligible drives the entry loop, including that a candidate that never becomes
// eligible still returns on context end rather than pinning the election goroutine.
func TestWaitForEntryEligible(t *testing.T) {
	const node, peer = "node-a", "node-b"

	tcs := []struct {
		name string
		// unblock makes the loop's exit condition true, or cancels for the ctx case.
		unblock func(t *testing.T, f *electionFixture, cancel context.CancelFunc)
	}{
		{
			name: "returns_once_self_is_fully_eligible",
			unblock: func(t *testing.T, f *electionFixture, _ context.CancelFunc) {
				f.endpointOn(t, "web", node)
				f.endpointOn(t, "api", node)
				f.watcher.signalChange()
			},
		},
		{
			name: "returns_on_ctx_cancel",
			unblock: func(_ *testing.T, _ *electionFixture, cancel context.CancelFunc) {
				cancel()
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			f := newElectionFixture(t, node, []string{"web", "api"}, []string{node, peer})
			// A live peer scoring higher keeps node out of the election until the
			// test unblocks it.
			f.endpointOn(t, "web", peer)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			returned := make(chan struct{})
			go func() {
				defer close(returned)
				waitForEntryEligible(ctx, node, f.watcher, fastElectionTiming, func(context.Context) bool { return true }, func(context.Context) {}, testLogger(t))
			}()

			select {
			case <-returned:
				t.Fatal("waitForEntryEligible returned while a fitter peer was live")
			case <-time.After(3 * fastElectionTiming.retry):
			}

			tc.unblock(t, f, cancel)
			select {
			case <-returned:
			case <-time.After(2 * time.Second):
				t.Fatal("waitForEntryEligible did not return after the gate was lifted")
			}
		})
	}
}

// TestWaitForEntryEligibleLease drives rule 2's Lease precondition: a less-fit candidate enters
// only after the hold with the Lease free, so a release keeps the tunnel served.
func TestWaitForEntryEligibleLease(t *testing.T) {
	const node, peer = "node-a", "node-b"

	tcs := []struct {
		name string
		// free is the Lease's state when the gate starts.
		free bool
		// script drives the Lease while the gate runs and returns the instant a full
		// hold must pass from, or the zero time when the gate must never open.
		script func(t *testing.T, free *atomic.Bool) time.Time
	}{
		{
			name:   "held_lease_keeps_a_less_fit_candidate_out",
			script: func(*testing.T, *atomic.Bool) time.Time { return time.Time{} },
		},
		{
			name: "freed_lease_admits_it_a_hold_later",
			script: func(_ *testing.T, free *atomic.Bool) time.Time {
				time.Sleep(fastElectionTiming.hold / 2)
				free.Store(true)
				return time.Now()
			},
		},
		{
			name: "a_holder_reappearing_restarts_the_hold",
			free: true,
			script: func(_ *testing.T, free *atomic.Bool) time.Time {
				time.Sleep(fastElectionTiming.hold / 2)
				free.Store(false)
				time.Sleep(fastElectionTiming.hold / 2)
				free.Store(true)
				return time.Now()
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			// node-a serves one of the two forwards and node-b none, so node-a is the
			// best candidate and no live node is fully eligible.
			f := newElectionFixture(t, node, []string{"web", "api"}, []string{node, peer})
			f.endpointOn(t, "web", node)

			var free atomic.Bool
			free.Store(tc.free)

			ctx := t.Context()
			returned := make(chan struct{})
			go func() {
				defer close(returned)
				waitForEntryEligible(ctx, node, f.watcher, fastElectionTiming,
					func(context.Context) bool { return free.Load() }, func(context.Context) {}, testLogger(t))
			}()

			freeSince := tc.script(t, &free)
			if freeSince.IsZero() {
				select {
				case <-returned:
					t.Fatal("the entry gate opened while another replica held the lease")
				case <-time.After(3 * fastElectionTiming.hold):
				}
				return
			}

			// A gate that ignored the Lease would open before this deadline.
			select {
			case <-returned:
				t.Fatalf("the entry gate opened %v after the lease came free, want a full hold of %v",
					time.Since(freeSince), fastElectionTiming.hold)
			case <-time.After(time.Until(freeSince.Add(fastElectionTiming.hold * 9 / 10))):
			}
			select {
			case <-returned:
			case <-time.After(5 * time.Second):
				t.Fatal("the entry gate did not open after the lease had been free for the hold")
			}
		})
	}
}

// TestLeaseHeld pins what counts as a Lease another replica still holds, the state that keeps
// a candidate out under rule 2: only a named holder whose renewal has not lapsed.
func TestLeaseHeld(t *testing.T) {
	now := time.Unix(1700001000, 0)

	tcs := []struct {
		name     string
		holder   string
		noHolder bool
		// renewedAgo is how long before now the holder last renewed; noRenew leaves
		// renewTime unset.
		renewedAgo time.Duration
		noRenew    bool
		duration   int32
		want       bool
	}{
		{name: "live_holder_is_held", holder: "pod-b", renewedAgo: time.Second, duration: 15, want: true},
		{name: "absent_holder_is_free", noHolder: true, duration: 15},
		{name: "empty_holder_is_free", holder: "", duration: 15},
		{name: "expired_holder_is_free", holder: "pod-b", renewedAgo: 30 * time.Second, duration: 15},
		{name: "holder_that_never_renewed_is_free", holder: "pod-b", noRenew: true, duration: 15},
		{name: "holder_without_a_duration_is_free", holder: "pod-b", renewedAgo: time.Second},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			lease := &coordinationv1.Lease{Spec: coordinationv1.LeaseSpec{}}
			if !tc.noHolder {
				lease.Spec.HolderIdentity = new(tc.holder)
			}
			if !tc.noRenew {
				lease.Spec.RenewTime = new(metav1.NewMicroTime(now.Add(-tc.renewedAgo)))
			}
			if tc.duration != 0 {
				lease.Spec.LeaseDurationSeconds = new(tc.duration)
			}
			if got := leaseHeld(lease, now); got != tc.want {
				t.Errorf("leaseHeld = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestEntryStillEligible pins when a candidate in the acquire poll goes back to the entry gate:
// another replica on the Lease, a fully eligible node appearing, or a live node outscoring it.
func TestEntryStillEligible(t *testing.T) {
	const forwardCount = 2
	now := time.Unix(1700001000, 0)

	tcs := []struct {
		name        string
		scores      map[string]int
		otherHolder bool
		want        bool
	}{
		{name: "fully_eligible_stays_although_another_replica_holds", scores: map[string]int{"node-a": forwardCount}, otherHolder: true, want: true},
		{name: "best_live_score_and_no_holder_stays", scores: map[string]int{"node-a": 1}, want: true},
		{name: "another_holder_sends_a_less_fit_candidate_back", scores: map[string]int{"node-a": 1}, otherHolder: true},
		{name: "a_fully_eligible_node_sends_it_back", scores: map[string]int{"node-a": 1, "node-b": forwardCount}},
		{name: "being_outscored_sends_it_back", scores: map[string]int{"node-a": 0, "node-b": 1}},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			v := electionView{
				forwardCount: forwardCount,
				live:         map[string]bool{"node-a": true, "node-b": true},
				scores:       tc.scores,
			}
			if got := entryStillEligible("node-a", v, tc.otherHolder, now, handoffHold); got != tc.want {
				t.Errorf("entryStillEligible = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestElectionLoopsDeferWhilePending pins that neither loop decides on an unsynced forward:
// score resolves an unsynced store to nothing, so a holder mid re-point would look emptied.
func TestElectionLoopsDeferWhilePending(t *testing.T) {
	const node, peer = "node-a", "node-b"

	tcs := []struct {
		name string
		// seed populates the pending forward's store with the endpoints that make
		// the loop decide once the watch syncs.
		seed func(t *testing.T, f *electionFixture)
		// start runs the loop under test and returns a channel closed on its
		// decision: the handoff monitor's release, the entry gate's return.
		start func(t *testing.T, ctx context.Context, f *electionFixture) <-chan struct{}
	}{
		{
			name: "handoff_monitor_does_not_release",
			seed: func(t *testing.T, f *electionFixture) { f.endpointOn(t, "web", peer) },
			start: func(t *testing.T, ctx context.Context, f *electionFixture) <-chan struct{} {
				released := make(chan struct{})
				var once sync.Once
				var steppedDown atomic.Bool
				go monitorHandoff(ctx, func() { once.Do(func() { close(released) }) }, node, f.watcher, fastElectionTiming, &steppedDown, testLogger(t))
				return released
			},
		},
		{
			name: "entry_gate_does_not_enter",
			seed: func(t *testing.T, f *electionFixture) { f.endpointOn(t, "web", node) },
			start: func(t *testing.T, ctx context.Context, f *electionFixture) <-chan struct{} {
				entered := make(chan struct{})
				go func() {
					defer close(entered)
					waitForEntryEligible(ctx, node, f.watcher, fastElectionTiming, func(context.Context) bool { return true }, func(context.Context) {}, testLogger(t))
				}()
				return entered
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			f := newElectionFixture(t, node, nil, []string{node, peer})
			markSynced := f.pendingForward(t, "web")
			tc.seed(t, f)

			ctx := t.Context()
			decided := tc.start(t, ctx, f)

			select {
			case <-decided:
				t.Fatal("election loop decided while a forward's endpoint watch was still syncing")
			case <-time.After(5 * fastElectionTiming.retry):
			}

			markSynced()
			select {
			case <-decided:
			case <-time.After(3 * time.Second):
				t.Fatal("election loop did not decide once the endpoint watch synced")
			}
		})
	}
}

// TestMonitorHandoffObservesAddedForward pins that the handoff loop reads the forward count
// live: a count captured at process start would keep an unfit leader leading forever.
func TestMonitorHandoffObservesAddedForward(t *testing.T) {
	const node, peer = "node-a", "node-b"

	f := newElectionFixture(t, node, []string{"web"}, []string{node, peer})
	f.endpointOn(t, "web", node)
	f.endpointOn(t, "web", peer)

	cancelled := make(chan struct{})
	var once sync.Once
	endCycle := func() { once.Do(func() { close(cancelled) }) }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var steppedDown atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		monitorHandoff(ctx, endCycle, node, f.watcher, fastElectionTiming, &steppedDown, testLogger(t))
	}()

	select {
	case <-cancelled:
		t.Fatal("monitorHandoff released the lease while the leader served every forward")
	case <-time.After(2 * fastElectionTiming.hold):
	}

	f.addForward(t, "api")
	f.endpointOn(t, "api", peer)
	f.watcher.signalChange()

	select {
	case <-cancelled:
	case <-time.After(3 * fastElectionTiming.hold):
		t.Fatal("monitorHandoff kept the lease after a forward it cannot serve was added")
	}

	cancel()
	<-done
	if !steppedDown.Load() {
		t.Error("steppedDown = false, want true")
	}
}

// TestReadLeaseTransitions covers the acquire-time term read: any read failure reports the term
// unknown rather than 0, which the caller must tell apart from a Lease with no transitions.
func TestReadLeaseTransitions(t *testing.T) {
	const namespace, leaseName = "gw-ns", "gw-link"

	tcs := []struct {
		name      string
		lease     *coordinationv1.Lease
		getErr    error
		wantTerm  int32
		wantKnown bool
		wantCalls int
	}{
		{
			name: "term_is_read",
			lease: &coordinationv1.Lease{
				ObjectMeta: metav1.ObjectMeta{Name: leaseName, Namespace: namespace},
				Spec:       coordinationv1.LeaseSpec{LeaseTransitions: new(int32(7))},
			},
			wantTerm:  7,
			wantKnown: true,
			wantCalls: 1,
		},
		{
			name: "nil_transitions_is_a_known_zero",
			lease: &coordinationv1.Lease{
				ObjectMeta: metav1.ObjectMeta{Name: leaseName, Namespace: namespace},
			},
			wantKnown: true,
			wantCalls: 1,
		},
		{
			name:      "missing_lease_is_unknown",
			wantKnown: false,
			wantCalls: 1,
		},
		{
			name:      "read_error_is_unknown",
			getErr:    fmt.Errorf("apiserver unreachable"),
			wantKnown: false,
			wantCalls: 1,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var objs []runtime.Object
			if tc.lease != nil {
				objs = append(objs, tc.lease)
			}
			cs := fake.NewClientset(objs...)
			var calls int
			cs.PrependReactor("get", "leases", func(k8stesting.Action) (bool, runtime.Object, error) {
				calls++
				if tc.getErr != nil {
					return true, nil, tc.getErr
				}
				return false, nil, nil
			})

			term, known := readLeaseTransitions(context.Background(), cs, namespace, leaseName, testLogger(t))
			if term != tc.wantTerm || known != tc.wantKnown {
				t.Errorf("readLeaseTransitions = (%d, %v), want (%d, %v)", term, known, tc.wantTerm, tc.wantKnown)
			}
			if calls != tc.wantCalls {
				t.Errorf("get calls = %d, want %d", calls, tc.wantCalls)
			}
		})
	}
}

// TestReadLeaseHolderTerm covers the read teardownDecision needs positive evidence from: three
// attempts, ok only when one succeeds, and giving up at once when the context ends mid-retry.
func TestReadLeaseHolderTerm(t *testing.T) {
	const namespace, leaseName = "gw-ns", "gw-link"
	lease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Name: leaseName, Namespace: namespace},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity:   new("pod-b"),
			LeaseTransitions: new(int32(4)),
		},
	}

	tcs := []struct {
		name string
		// failures is how many leading Get attempts are made to fail.
		failures int
		// cancelAfter cancels the context after that many Get attempts, 0 for never.
		cancelAfter int
		// withLease seeds the Lease object, so a false here makes every Get NotFound.
		withLease  bool
		wantHolder string
		wantTerm   int32
		wantOK     bool
		wantCalls  int
	}{
		{
			name:       "first_attempt_succeeds",
			withLease:  true,
			wantHolder: "pod-b",
			wantTerm:   4,
			wantOK:     true,
			wantCalls:  1,
		},
		{
			name:       "failure_then_success",
			withLease:  true,
			failures:   1,
			wantHolder: "pod-b",
			wantTerm:   4,
			wantOK:     true,
			wantCalls:  2,
		},
		{
			name:      "every_attempt_fails",
			withLease: true,
			failures:  3,
			wantCalls: 3,
		},
		{
			name:      "missing_lease_exhausts_attempts",
			wantCalls: 3,
		},
		{
			name:        "context_cancelled_between_attempts",
			withLease:   true,
			failures:    1,
			cancelAfter: 1,
			wantCalls:   1,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var objs []runtime.Object
			if tc.withLease {
				objs = append(objs, lease)
			}
			cs := fake.NewClientset(objs...)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			var calls int
			cs.PrependReactor("get", "leases", func(k8stesting.Action) (bool, runtime.Object, error) {
				calls++
				if tc.cancelAfter > 0 && calls >= tc.cancelAfter {
					cancel()
				}
				if calls <= tc.failures {
					return true, nil, fmt.Errorf("apiserver unreachable")
				}
				return false, nil, nil
			})

			holder, term, ok := readLeaseHolderTerm(ctx, cs, namespace, leaseName, time.Millisecond, testLogger(t))
			if holder != tc.wantHolder || term != tc.wantTerm || ok != tc.wantOK {
				t.Errorf("readLeaseHolderTerm = (%q, %d, %v), want (%q, %d, %v)",
					holder, term, ok, tc.wantHolder, tc.wantTerm, tc.wantOK)
			}
			if calls != tc.wantCalls {
				t.Errorf("get calls = %d, want %d", calls, tc.wantCalls)
			}
		})
	}
}

// runElectionFixture wires runElection against a fake apiserver and a recording apply and
// teardown, so a whole leadership cycle runs in-process with no exec and no watcher.
type runElectionFixture struct {
	deps      electionDeps
	cs        *fake.Clientset
	teardowns atomic.Int32
	// clearedFault records that some update dropped the seeded fault annotation: the release
	// writes back the lease it cached at acquire, so it can reappear on the stored object.
	clearedFault atomic.Bool
}

// newRunElectionFixture seeds the Lease unheld and carrying a fault, so a cycle both
// acquires it on the first attempt and has a fault the fence can decide to clear.
func newRunElectionFixture(t *testing.T, namespace, leaseName, podName string) *runElectionFixture {
	t.Helper()

	path := writeRuntimeConfig(t, validRuntimeJSON)
	rc, err := LoadRuntimeConfig(path)
	if err != nil {
		t.Fatalf("LoadRuntimeConfig: %v", err)
	}

	f := &runElectionFixture{}
	cs := fake.NewClientset(&coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Name:        leaseName,
			Namespace:   namespace,
			Annotations: map[string]string{LeaseFaultAnnotation: FaultApplyFailed, LeaseFaultMessageAnnotation: "seeded"},
		},
	})
	cs.PrependReactor("update", "leases", func(action k8stesting.Action) (bool, runtime.Object, error) {
		lease, ok := action.(k8stesting.UpdateAction).GetObject().(*coordinationv1.Lease)
		if ok {
			if _, faulted := lease.Annotations[LeaseFaultAnnotation]; !faulted {
				f.clearedFault.Store(true)
			}
		}
		return false, nil, nil
	})
	lock, err := resourcelock.New(
		resourcelock.LeasesResourceLock,
		namespace, leaseName,
		cs.CoreV1(), cs.CoordinationV1(),
		resourcelock.ResourceLockConfig{Identity: podName},
	)
	if err != nil {
		t.Fatalf("resourcelock.New: %v", err)
	}

	f.cs = cs
	f.deps = electionDeps{
		cfg: Config{
			ConfigPath:        path,
			ReconcileInterval: 20 * time.Millisecond,
			PodNamespace:      namespace,
			PodName:           podName,
			LeaseName:         leaseName,
		},
		lock: lock,
		rd:   newReadiness(interfaceName(rc), 0, time.Now, func(context.Context, string) (string, error) { return "", nil }),
		cs:   cs,
		fence: func(context.Context) error {
			f.teardowns.Add(1)
			return nil
		},
		timing: fastElectionTiming,
		log:    testLogger(t),
	}
	return f
}

// leaseFault reports the fault reason currently annotated on the Lease.
func (f *runElectionFixture) leaseFault(t *testing.T, namespace, leaseName string) string {
	t.Helper()
	lease, err := f.cs.CoordinationV1().Leases(namespace).Get(context.Background(), leaseName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get lease: %v", err)
	}
	return lease.Annotations[LeaseFaultAnnotation]
}

// waitFor blocks on ch until the test's own deadline, so a stuck cycle fails the test
// instead of hanging the package.
func waitFor(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// TestRunElection drives a full leadership cycle against a fake apiserver: acquire, apply, and
// each way the cycle can end reaching the fence.
func TestRunElection(t *testing.T) {
	const namespace, leaseName, podName = "gw-ns", "gw-link", "pod-a"

	tcs := []struct {
		name string
		// groupOnly ends the cycle by cancelling the errgroup context alone,
		// leaving the process context live: a sibling goroutine's failure.
		groupOnly bool
		// cycles is how many times runElection is called on the same deps.
		cycles           int
		wantFaultCleared bool
	}{
		{name: "sigterm_tears_down_and_clears_the_fault", cycles: 1, wantFaultCleared: true},
		{name: "sibling_failure_tears_down_and_keeps_the_fault", groupOnly: true, cycles: 1},
		{name: "second_cycle_acquires_again", cycles: 2, wantFaultCleared: true},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			f := newRunElectionFixture(t, namespace, leaseName, podName)

			for cycle := range tc.cycles {
				applied := make(chan struct{})
				var appliedOnce sync.Once
				f.deps.reconcile = func(context.Context, RuntimeConfig, string, string, []ResolvedForward, []unsatisfiedForward) error {
					appliedOnce.Do(func() { close(applied) })
					return nil
				}

				outerCtx, cancelOuter := context.WithCancel(context.Background())
				gctx, cancelGroup := context.WithCancel(outerCtx)
				errs := make(chan error, 1)
				go func() { errs <- f.deps.runElection(outerCtx, gctx) }()

				waitFor(t, applied, fmt.Sprintf("first apply of cycle %d", cycle))
				if !f.deps.rd.isLeader() {
					t.Errorf("cycle %d: isLeader = false while the reload loop is running", cycle)
				}

				if tc.groupOnly {
					cancelGroup()
				} else {
					cancelOuter()
				}
				select {
				case err := <-errs:
					if err != nil {
						t.Fatalf("cycle %d: runElection = %v, want nil", cycle, err)
					}
				case <-time.After(10 * time.Second):
					t.Fatalf("cycle %d: runElection did not return", cycle)
				}
				cancelGroup()
				cancelOuter()

				if got := f.teardowns.Load(); got != int32(cycle+1) {
					t.Errorf("cycle %d: teardowns = %d, want %d", cycle, got, cycle+1)
				}
				if f.deps.rd.isLeader() {
					t.Errorf("cycle %d: isLeader = true after the cycle ended", cycle)
				}
			}

			if got := f.clearedFault.Load(); got != tc.wantFaultCleared {
				t.Errorf("fence cleared the lease fault = %v, want %v", got, tc.wantFaultCleared)
			}
			if !tc.wantFaultCleared {
				if got := f.leaseFault(t, namespace, leaseName); got != FaultApplyFailed {
					t.Errorf("lease fault = %q, want %q", got, FaultApplyFailed)
				}
			}
		})
	}
}

// TestObservedHolderFences pins the rule that turns an observed Lease holder into the
// fence of a data plane an earlier cycle kept: only a named other replica is evidence.
func TestObservedHolderFences(t *testing.T) {
	const self = "pod-a"

	tcs := []struct {
		name    string
		pending bool
		holder  string
		want    bool
	}{
		{name: "pending_and_another_holder_fences", pending: true, holder: "pod-b", want: true},
		{name: "pending_and_self_is_not_evidence", pending: true, holder: self},
		{name: "pending_and_free_lease_is_not_evidence", pending: true},
		{name: "not_pending_never_fences", holder: "pod-b"},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if got := observedHolderFences(tc.pending, self, tc.holder); got != tc.want {
				t.Errorf("observedHolderFences(%v, %q, %q) = %v, want %v", tc.pending, self, tc.holder, got, tc.want)
			}
		})
	}
}

// TestFencePendingOnPoll covers the entry gate's pending fence: it fences only on a named other
// holder, keeps the data plane on a failed read, and fences at most once.
func TestFencePendingOnPoll(t *testing.T) {
	const namespace, leaseName, self = "gw-ns", "gw-link", "pod-a"

	tcs := []struct {
		name        string
		pending     bool
		holder      string
		readFails   bool
		polls       int
		wantFences  int32
		wantPending bool
	}{
		{name: "another_holder_fences_once", pending: true, holder: "pod-b", polls: 1, wantFences: 1},
		{name: "repeated_polls_fence_once", pending: true, holder: "pod-b", polls: 3, wantFences: 1},
		{name: "failed_read_keeps_the_data_plane", pending: true, holder: "pod-b", readFails: true, polls: 3, wantPending: true},
		{name: "self_is_not_evidence", pending: true, holder: self, polls: 3, wantPending: true},
		{name: "free_lease_is_not_evidence", pending: true, polls: 3, wantPending: true},
		{name: "no_pending_fence_does_not_read", polls: 3},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			lease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: leaseName, Namespace: namespace}}
			if tc.holder != "" {
				lease.Spec.HolderIdentity = new(tc.holder)
			}
			cs := fake.NewClientset(lease)
			if tc.readFails {
				cs.PrependReactor("get", "leases", func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, fmt.Errorf("apiserver unreachable")
				})
			}

			var fences atomic.Int32
			deps := electionDeps{
				cfg: Config{PodNamespace: namespace, PodName: self, LeaseName: leaseName},
				cs:  cs,
				fence: func(context.Context) error {
					fences.Add(1)
					return nil
				},
				timing: fastElectionTiming,
				log:    testLogger(t),
			}

			var pending atomic.Bool
			pending.Store(tc.pending)
			for range tc.polls {
				deps.fencePendingOnPoll(context.Background(), &pending)
			}

			if got := fences.Load(); got != tc.wantFences {
				t.Errorf("fences = %d, want %d", got, tc.wantFences)
			}
			if got := pending.Load(); got != tc.wantPending {
				t.Errorf("pending = %v, want %v", got, tc.wantPending)
			}
		})
	}
}

// TestFencePendingHolderNode covers the Local-mode exception: only a holder the pod informer
// places on another node is evidence, while Cluster mode fences on the identity alone.
func TestFencePendingHolderNode(t *testing.T) {
	const namespace, leaseName, self, node = "gw-ns", "gw-link", "link-node-a", "node-a"

	tcs := []struct {
		name string
		// clusterMode drops the endpoint watcher, as a Cluster-mode link has none.
		clusterMode bool
		// extraPod joins the pod informer before the holder is observed.
		extraPod   *corev1.Pod
		holder     string
		wantFences int32
	}{
		{name: "holder_on_another_node_fences", holder: "link-node-b", wantFences: 1},
		{name: "holder_on_this_node_keeps_the_data_plane", extraPod: makePod("link-old-node-a", node, true), holder: "link-old-node-a"},
		{name: "holder_unknown_to_the_informer_keeps_the_data_plane", holder: "link-node-c"},
		{name: "cluster_mode_fences_on_the_identity_alone", clusterMode: true, holder: "pod-b", wantFences: 1},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var fences atomic.Int32
			deps := electionDeps{
				cfg: Config{PodNamespace: namespace, PodName: self, LeaseName: leaseName, NodeName: node},
				fence: func(context.Context) error {
					fences.Add(1)
					return nil
				},
				timing: fastElectionTiming,
				log:    testLogger(t),
			}
			if !tc.clusterMode {
				ef := newElectionFixture(t, node, []string{"web"}, []string{node, "node-b"})
				if tc.extraPod != nil {
					addPods(t, ef.watcher.podIndexer, tc.extraPod)
				}
				deps.ew = ef.watcher
			}

			var pending atomic.Bool
			pending.Store(true)
			deps.fencePendingOnHolder(context.Background(), &pending, tc.holder)

			if got := fences.Load(); got != tc.wantFences {
				t.Errorf("fences = %d, want %d", got, tc.wantFences)
			}
			if got := pending.Load(); got != (tc.wantFences == 0) {
				t.Errorf("pending = %v, want %v", got, tc.wantFences == 0)
			}
		})
	}
}

// TestAcquisitionLock pins the acquisition signal the join depends on: the first write
// that records this identity as the holder closes acquired, and nothing else does.
func TestAcquisitionLock(t *testing.T) {
	const namespace, leaseName, self = "gw-ns", "gw-link", "pod-a"

	tcs := []struct {
		name string
		// create writes through Create, the path taken when no Lease exists yet.
		create bool
		// holder is the identity carried by the record written.
		holder string
		// writeFails makes the apiserver reject the write.
		writeFails bool
		// writes is how many times the write is repeated.
		writes       int
		wantAcquired bool
	}{
		{name: "create_with_own_identity_closes", create: true, holder: self, writes: 1, wantAcquired: true},
		{name: "update_with_own_identity_closes", holder: self, writes: 1, wantAcquired: true},
		{name: "update_with_another_identity_does_not_close", holder: "pod-b", writes: 1},
		{name: "failed_update_does_not_close", holder: self, writeFails: true, writes: 1},
		{name: "second_successful_write_closes_once", holder: self, writes: 2, wantAcquired: true},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var objs []runtime.Object
			if !tc.create {
				objs = append(objs, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: leaseName, Namespace: namespace}})
			}
			cs := fake.NewClientset(objs...)
			if tc.writeFails {
				cs.PrependReactor("update", "leases", func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, fmt.Errorf("apiserver unreachable")
				})
			}
			inner, err := resourcelock.New(
				resourcelock.LeasesResourceLock,
				namespace, leaseName,
				cs.CoreV1(), cs.CoordinationV1(),
				resourcelock.ResourceLockConfig{Identity: self},
			)
			if err != nil {
				t.Fatalf("resourcelock.New: %v", err)
			}

			lock := newAcquisitionLock(inner)
			record := resourcelock.LeaderElectionRecord{
				HolderIdentity:       tc.holder,
				LeaseDurationSeconds: 15,
				AcquireTime:          metav1.NewTime(time.Now()),
				RenewTime:            metav1.NewTime(time.Now()),
			}
			ctx := context.Background()
			for range tc.writes {
				if tc.create {
					if err := lock.Create(ctx, record); err != nil {
						t.Fatalf("create: %v", err)
					}
					continue
				}
				// The lock caches the Lease it writes back, so an update needs a
				// read first; Get is the embedded lock's own method.
				if _, _, err := lock.Get(ctx); err != nil {
					t.Fatalf("get: %v", err)
				}
				err := lock.Update(ctx, record)
				if (err != nil) != tc.writeFails {
					t.Fatalf("update = %v, want an error: %v", err, tc.writeFails)
				}
			}

			select {
			case <-lock.acquired:
				if !tc.wantAcquired {
					t.Error("acquired closed, want it open")
				}
			default:
				if tc.wantAcquired {
					t.Error("acquired open, want it closed")
				}
			}
		})
	}
}

// TestRunElectionNeverAcquired pins the join on a cycle that never leads: nothing is fenced and
// the cancel returns at once rather than after a grace.
func TestRunElectionNeverAcquired(t *testing.T) {
	const namespace, leaseName, podName = "gw-ns", "gw-link", "pod-a"

	f := newRunElectionFixture(t, namespace, leaseName, podName)
	seedHeldLease(t, f, namespace, leaseName, "pod-b", 3600)

	f.deps.reconcile = func(context.Context, RuntimeConfig, string, string, []ResolvedForward, []unsatisfiedForward) error {
		t.Error("the reload loop ran although the lease was held elsewhere")
		return nil
	}

	outerCtx, cancelOuter := context.WithCancel(context.Background())
	defer cancelOuter()
	errs := make(chan error, 1)
	go func() { errs <- f.deps.runElection(outerCtx, outerCtx) }()

	time.Sleep(50 * time.Millisecond)
	cancelOuter()
	select {
	case err := <-errs:
		if err != nil {
			t.Fatalf("runElection = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runElection did not return within two seconds of the cancel")
	}
	if got := f.teardowns.Load(); got != 0 {
		t.Errorf("teardowns = %d, want 0", got)
	}
}

// seedHeldLease writes the Lease as held by holder for durationSeconds from now, the
// state a replica that cannot acquire it sees.
func seedHeldLease(t *testing.T, f *runElectionFixture, namespace, leaseName, holder string, durationSeconds int32) {
	t.Helper()
	lease, err := f.cs.CoordinationV1().Leases(namespace).Get(context.Background(), leaseName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get lease: %v", err)
	}
	lease.Spec = coordinationv1.LeaseSpec{
		HolderIdentity:       new(holder),
		LeaseDurationSeconds: new(durationSeconds),
		AcquireTime:          new(metav1.NewMicroTime(time.Now())),
		RenewTime:            new(metav1.NewMicroTime(time.Now())),
		LeaseTransitions:     new(int32(1)),
	}
	if _, err := f.cs.CoordinationV1().Leases(namespace).Update(context.Background(), lease, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("seed held lease: %v", err)
	}
}

// TestPendingFenceSerialisesWithLeadership pins that a fence started for an earlier cycle cannot
// tear down the next cycle's data plane: OnNewLeader is unjoined, so only fenceMu orders them.
func TestPendingFenceSerialisesWithLeadership(t *testing.T) {
	const namespace, leaseName, self = "gw-ns", "gw-link", "pod-a"

	tcs := []struct {
		name string
		// fenceFirst starts the fence before leadership rather than after it.
		fenceFirst bool
		wantEvents []string
	}{
		{name: "fence_in_flight_completes_before_the_apply", fenceFirst: true, wantEvents: []string{"fence begin", "fence end", "apply"}},
		{name: "fence_after_leadership_started_does_not_tear_down", wantEvents: []string{"apply"}},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			lease := &coordinationv1.Lease{
				ObjectMeta: metav1.ObjectMeta{Name: leaseName, Namespace: namespace},
				Spec:       coordinationv1.LeaseSpec{HolderIdentity: new("pod-b")},
			}

			var mu sync.Mutex
			var events []string
			record := func(what string) {
				mu.Lock()
				defer mu.Unlock()
				events = append(events, what)
			}

			fenceStarted := make(chan struct{})
			releaseFence := make(chan struct{})
			deps := electionDeps{
				cfg: Config{PodNamespace: namespace, PodName: self, LeaseName: leaseName},
				cs:  fake.NewClientset(lease),
				fence: func(context.Context) error {
					record("fence begin")
					close(fenceStarted)
					<-releaseFence
					record("fence end")
					return nil
				},
				timing: fastElectionTiming,
				log:    testLogger(t),
			}

			var pending atomic.Bool
			pending.Store(true)

			led := make(chan struct{})
			startLeading := func() {
				go func() {
					defer close(led)
					deps.claimPendingFence(&pending)
					record("apply")
				}()
			}

			if !tc.fenceFirst {
				startLeading()
				waitFor(t, led, "leadership to start")
				close(releaseFence)
				deps.fencePendingOnHolder(context.Background(), &pending, "pod-b")
			} else {
				fenced := make(chan struct{})
				go func() {
					defer close(fenced)
					deps.fencePendingOnHolder(context.Background(), &pending, "pod-b")
				}()
				waitFor(t, fenceStarted, "the fence to start")
				startLeading()
				// The fence holds fenceMu, so leadership must still be blocked.
				select {
				case <-led:
					t.Fatal("leadership started while a fence was tearing the data plane down")
				case <-time.After(50 * time.Millisecond):
				}
				close(releaseFence)
				waitFor(t, fenced, "the fence to finish")
				waitFor(t, led, "leadership to start")
			}

			mu.Lock()
			got := slices.Clone(events)
			mu.Unlock()
			if !slices.Equal(got, tc.wantEvents) {
				t.Errorf("events = %v, want %v", got, tc.wantEvents)
			}
			if pending.Load() {
				t.Error("pending fence still set after the cycle claimed or ran it")
			}
		})
	}
}

// TestRunElectionPendingFence drives a cycle ending in an apiserver outage: fail-static keeps the
// data plane, and once the reads recover another replica's hold fences exactly once.
func TestRunElectionPendingFence(t *testing.T) {
	const namespace, leaseName, podName = "gw-ns", "gw-link", "pod-a"
	leaseGVR := coordinationv1.SchemeGroupVersion.WithResource("leases")

	tcs := []struct {
		name string
		// recoveredHolder is the Lease's holder once the reads recover.
		recoveredHolder string
		// noRecovery leaves the apiserver unreachable, so the process exits with the
		// fence still pending.
		noRecovery    bool
		wantFences    int32
		wantReacquire bool
	}{
		{name: "another_holder_fences_the_kept_data_plane", recoveredHolder: "pod-b", wantFences: 1},
		{name: "still_self_keeps_the_data_plane", recoveredHolder: podName, wantReacquire: true},
		{name: "sigterm_while_pending_fences_on_exit", noRecovery: true},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			f := newRunElectionFixture(t, namespace, leaseName, podName)

			var unreachable atomic.Bool
			f.cs.PrependReactor("*", "leases", func(k8stesting.Action) (bool, runtime.Object, error) {
				if unreachable.Load() {
					return true, nil, fmt.Errorf("apiserver unreachable")
				}
				return false, nil, nil
			})

			applied := make(chan struct{})
			var applies atomic.Int32
			var appliedOnce sync.Once
			f.deps.reconcile = func(context.Context, RuntimeConfig, string, string, []ResolvedForward, []unsatisfiedForward) error {
				applies.Add(1)
				appliedOnce.Do(func() { close(applied) })
				return nil
			}

			outerCtx, cancelOuter := context.WithCancel(context.Background())
			defer cancelOuter()
			errs := make(chan error, 1)
			go func() { errs <- f.deps.runElection(outerCtx, outerCtx) }()

			waitFor(t, applied, "first apply")
			appliesBefore := applies.Load()

			// Losing every Lease write ends the cycle at the renew deadline, and
			// losing every read leaves it with no evidence of a successor.
			unreachable.Store(true)
			waitUntil(t, func() bool { return !f.deps.rd.isLeader() }, "the leadership cycle to end")
			if got := f.teardowns.Load(); got != 0 {
				t.Fatalf("teardowns = %d during the outage, want 0 (fail-static)", got)
			}

			if !tc.noRecovery {
				// The tracker is written behind the failing reactor so the recovered
				// Lease is visible in the same instant the reads start succeeding.
				recovered := &coordinationv1.Lease{
					ObjectMeta: metav1.ObjectMeta{Name: leaseName, Namespace: namespace},
					Spec: coordinationv1.LeaseSpec{
						HolderIdentity:       new(tc.recoveredHolder),
						LeaseDurationSeconds: new(int32(60)),
						RenewTime:            new(metav1.NewMicroTime(time.Now())),
						LeaseTransitions:     new(int32(5)),
					},
				}
				if err := f.cs.Tracker().Update(leaseGVR, recovered, namespace); err != nil {
					t.Fatalf("seed recovered lease: %v", err)
				}
				unreachable.Store(false)
			}

			switch {
			case tc.noRecovery:
			case tc.wantReacquire:
				waitUntil(t, func() bool { return applies.Load() > appliesBefore }, "the replica to lead again")
				if got := f.teardowns.Load(); got != 0 {
					t.Errorf("teardowns = %d after re-acquiring, want 0", got)
				}
			default:
				waitUntil(t, func() bool { return f.teardowns.Load() == tc.wantFences }, "the pending fence to run")
			}

			cancelOuter()
			select {
			case err := <-errs:
				if err != nil {
					t.Fatalf("runElection = %v, want nil", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("runElection did not return")
			}

			// A cycle that never led adds no fence, one that led again fences on the SIGTERM
			// path, and a pending fence fences on the way out: the total is one either way.
			if got := f.teardowns.Load(); got != 1 {
				t.Errorf("teardowns = %d, want 1", got)
			}
		})
	}
}

// waitUntil polls cond until it holds or the test's own deadline passes, so a stuck
// election fails the test instead of hanging the package.
func waitUntil(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(fastElectionTiming.retry)
	}
}

// newLocalRunElectionFixture is the run fixture in Local mode. The watcher tracks exactly the
// forwards the config carries, so the re-key starts no informer against an absent apiserver.
func newLocalRunElectionFixture(t *testing.T, namespace, leaseName string, liveNodes []string) (*runElectionFixture, *electionFixture) {
	t.Helper()

	f := newRunElectionFixture(t, namespace, leaseName, "link-node-a")
	f.deps.cfg.NodeName = "node-a"
	writeConfig(t, f.deps.cfg.ConfigPath, localConfigJSONWith("web"))
	rc, err := loadRuntimeConfigMatching(f.deps.cfg.ConfigPath, localConfigIdentity())
	if err != nil {
		t.Fatalf("load local runtime config: %v", err)
	}

	ef := newElectionFixture(t, "node-a", []string{"web"}, liveNodes)
	ef.endpointOn(t, "web", "node-a")
	ef.watcher.mu.Lock()
	ef.watcher.forwards = rc.Forwards
	ef.watcher.mu.Unlock()

	f.deps.ew = ef.watcher
	f.deps.identity = rc.Identity
	return f, ef
}

// TestRunElectionInheritedDataPlane drives adoption of a data plane an earlier process left:
// fenced on a holder elsewhere, kept otherwise, re-applied on acquire, fenced on the way out.
func TestRunElectionInheritedDataPlane(t *testing.T) {
	const namespace, leaseName = "gw-ns", "gw-link"

	tcs := []struct {
		name   string
		holder string
		// extraPod joins the pod informer before the cycle starts.
		extraPod *corev1.Pod
		// noInheritance starts the process with no data plane on the node.
		noInheritance bool
		// wantFenceWhileRunning expects the fence before the process is asked to exit.
		wantFenceWhileRunning bool
		wantLead              bool
		wantFencesAfterExit   int32
	}{
		{
			name:                  "holder_on_another_node_fences_at_once",
			holder:                "link-node-b",
			wantFenceWhileRunning: true,
			wantFencesAfterExit:   1,
		},
		{
			name:                "holder_is_self_re_applies_in_place",
			holder:              "link-node-a",
			wantLead:            true,
			wantFencesAfterExit: 1,
		},
		{
			name:                "holder_unknown_to_the_informer_is_kept_until_exit",
			holder:              "link-node-c",
			wantFencesAfterExit: 1,
		},
		{
			name:                "holder_is_another_pod_on_this_node_is_kept_until_exit",
			holder:              "link-old-node-a",
			extraPod:            makePod("link-old-node-a", "node-a", true),
			wantFencesAfterExit: 1,
		},
		{
			name:          "no_inherited_data_plane_never_fences",
			holder:        "link-node-b",
			noInheritance: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			f, _ := newLocalRunElectionFixture(t, namespace, leaseName, []string{"node-a", "node-b"})
			f.deps.inheritedDataPlane = !tc.noInheritance
			if tc.extraPod != nil {
				addPods(t, f.deps.ew.podIndexer, tc.extraPod)
			}
			seedHeldLease(t, f, namespace, leaseName, tc.holder, 60)

			var applies atomic.Int32
			f.deps.reconcile = func(context.Context, RuntimeConfig, string, string, []ResolvedForward, []unsatisfiedForward) error {
				applies.Add(1)
				return nil
			}

			outerCtx, cancelOuter := context.WithCancel(context.Background())
			defer cancelOuter()
			errs := make(chan error, 1)
			go func() { errs <- f.deps.runElection(outerCtx, outerCtx) }()

			switch {
			case tc.wantFenceWhileRunning:
				waitUntil(t, func() bool { return f.teardowns.Load() == 1 }, "the inherited data plane to be fenced")
			case tc.wantLead:
				waitUntil(t, func() bool { return applies.Load() > 0 }, "the replica to lead")
				if got := f.teardowns.Load(); got != 0 {
					t.Errorf("teardowns = %d while leading, want 0", got)
				}
			default:
				time.Sleep(200 * time.Millisecond)
				if got := f.teardowns.Load(); got != 0 {
					t.Errorf("teardowns = %d before the process exits, want 0", got)
				}
			}
			if !tc.wantLead && applies.Load() != 0 {
				t.Errorf("applies = %d, want 0 while another replica holds the lease", applies.Load())
			}

			cancelOuter()
			select {
			case err := <-errs:
				if err != nil {
					t.Fatalf("runElection = %v, want nil", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("runElection did not return")
			}
			if got := f.teardowns.Load(); got != tc.wantFencesAfterExit {
				t.Errorf("teardowns after exit = %d, want %d", got, tc.wantFencesAfterExit)
			}
		})
	}
}

// TestRunElectionLeavesAcquireWhenOutranked pins the re-gate: staying in the acquire poll would
// take the Lease the instant the holder releases, however unfit the candidate is by then.
func TestRunElectionLeavesAcquireWhenOutranked(t *testing.T) {
	const namespace, leaseName = "gw-ns", "gw-link"

	tcs := []struct {
		name string
		// fullyEligible keeps this node's endpoint, so it enters under rule 1.
		fullyEligible bool
	}{
		{name: "another_holder_sends_a_less_fit_candidate_back"},
		{name: "a_fully_eligible_candidate_keeps_contending", fullyEligible: true},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			f, ef := newLocalRunElectionFixture(t, namespace, leaseName, []string{"node-a", "node-b"})
			if !tc.fullyEligible {
				// No node serves the forward, so this candidate enters under rule 2.
				ef.dropEndpointOn(t, "web", "node-a")
			}
			seedHeldLease(t, f, namespace, leaseName, "link-node-b", 60)

			contending := make(chan struct{})
			var contendingOnce sync.Once
			f.cs.PrependReactor("get", "leases", func(k8stesting.Action) (bool, runtime.Object, error) {
				contendingOnce.Do(func() { close(contending) })
				return false, nil, nil
			})

			applied := make(chan struct{})
			var appliedOnce sync.Once
			f.deps.reconcile = func(context.Context, RuntimeConfig, string, string, []ResolvedForward, []unsatisfiedForward) error {
				appliedOnce.Do(func() { close(applied) })
				return nil
			}

			outerCtx, cancelOuter := context.WithCancel(context.Background())
			defer cancelOuter()
			errs := make(chan error, 1)
			go func() { errs <- f.deps.runElection(outerCtx, outerCtx) }()

			// Whoever is contending reads the Lease, in the acquire poll or in the entry
			// gate; when it acquires the freed Lease is what separates the two.
			waitFor(t, contending, "the candidate to read the lease")
			time.Sleep(20 * fastElectionTiming.retry)

			freeLease(t, f, namespace, leaseName)
			freed := time.Now()
			if tc.fullyEligible {
				// Still in the poll: it takes the Lease on the next tick, holding out
				// for nothing.
				select {
				case <-applied:
				case <-time.After(fastElectionTiming.hold / 2):
					t.Fatalf("a fully eligible candidate had not taken the freed lease %v after it came free", time.Since(freed))
				}
			} else {
				// Back in the gate: admitted only after the hold with the Lease free.
				select {
				case <-applied:
					t.Fatalf("the candidate acquired the freed lease %v after it came free, want a hold of %v",
						time.Since(freed), fastElectionTiming.hold)
				case <-time.After(fastElectionTiming.hold * 9 / 10):
				}
				waitFor(t, applied, "the candidate to acquire the freed lease and apply")
			}

			cancelOuter()
			select {
			case err := <-errs:
				if err != nil {
					t.Fatalf("runElection = %v, want nil", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("runElection did not return")
			}
		})
	}
}

// TestEndCycleDuringAcquisition drives client-go's window: the acquisition is recorded inside
// the write and the callback starts after it, so a cycle ending between must still fence.
func TestEndCycleDuringAcquisition(t *testing.T) {
	const namespace, leaseName = "gw-ns", "gw-link"

	f, _ := newLocalRunElectionFixture(t, namespace, leaseName, []string{"node-a"})
	// The elector's own retry period bounds how long an end of cycle waits for an
	// acquisition write in flight; the production value dwarfs one write.
	timing := fastElectionTiming
	timing.retry = 100 * time.Millisecond
	f.deps.timing = timing

	var mu sync.Mutex
	var events []string
	record := func(what string) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, what)
	}

	acquiring := make(chan struct{})
	var acquiringOnce sync.Once
	proceed := make(chan struct{})
	f.cs.PrependReactor("update", "leases", func(action k8stesting.Action) (bool, runtime.Object, error) {
		lease, ok := action.(k8stesting.UpdateAction).GetObject().(*coordinationv1.Lease)
		if !ok || lease.Spec.HolderIdentity == nil {
			return false, nil, nil
		}
		switch *lease.Spec.HolderIdentity {
		case f.deps.cfg.PodName:
			acquiringOnce.Do(func() {
				close(acquiring)
				<-proceed
			})
		case "":
			record("release")
		}
		return false, nil, nil
	})
	f.deps.fence = func(context.Context) error {
		f.teardowns.Add(1)
		record("fence")
		return nil
	}

	outerCtx, cancelOuter := context.WithCancel(context.Background())
	defer cancelOuter()
	errs := make(chan error, 1)
	go func() { errs <- f.deps.runElection(outerCtx, outerCtx) }()

	waitFor(t, acquiring, "the acquisition write to start")
	cancelOuter()
	// Long enough for the shutdown to reach endCycle, short enough to stay inside the
	// bound it waits for the write in flight.
	time.Sleep(20 * time.Millisecond)
	close(proceed)

	select {
	case err := <-errs:
		if err != nil {
			t.Fatalf("runElection = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runElection did not return")
	}

	mu.Lock()
	got := slices.Clone(events)
	mu.Unlock()
	if !slices.Equal(got, []string{"fence", "release"}) {
		t.Errorf("events = %v, want [fence release]", got)
	}
	if teardowns := f.teardowns.Load(); teardowns != 1 {
		t.Errorf("teardowns = %d, want 1: the cycle must not leave a fence pending for a plane it programmed", teardowns)
	}
}

// TestEndCycleWaitsForRegistration pins that once the acquire write has landed the reload loop
// is on its way, so the fence waits for it to register and exit.
func TestEndCycleWaitsForRegistration(t *testing.T) {
	tcs := []struct {
		name string
		// acquired closes the lock's acquisition signal before the cycle ends.
		acquired bool
		// registerLate leaves the reload loop unregistered until the end of cycle is
		// already blocked on it.
		registerLate bool
		wantEvents   []string
	}{
		{name: "never_acquired_only_cancels", wantEvents: []string{"cancel"}},
		{name: "registered_fences_then_cancels", acquired: true, wantEvents: []string{"fence", "cancel"}},
		{name: "acquired_before_registration_waits_for_it", acquired: true, registerLate: true, wantEvents: []string{"fence", "cancel"}},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var events []string
			record := func(what string) {
				mu.Lock()
				defer mu.Unlock()
				events = append(events, what)
			}

			// The registration wait is bounded by the fence budget, which production
			// sizes in seconds; the fast timing would lapse mid-assertion.
			timing := fastElectionTiming
			timing.fence = 2 * time.Second
			deps := electionDeps{
				fence: func(context.Context) error {
					record("fence")
					return nil
				},
				timing: timing,
				log:    testLogger(t),
			}
			var pending atomic.Bool
			lock := newAcquisitionLock(nil)
			torndown := make(chan struct{})
			close(torndown)
			cycle := &leadershipCycle{
				cancelElection: func() { record("cancel") },
				pending:        &pending,
				lock:           lock,
				registered:     make(chan struct{}),
				teardownDone:   torndown,
			}
			if tc.acquired {
				lock.once.Do(func() { close(lock.acquired) })
			}

			reloadDone := make(chan struct{})
			var stopOnce sync.Once
			stop := func() { stopOnce.Do(func() { close(reloadDone) }) }
			if !tc.registerLate {
				cycle.lead(stop, reloadDone)
			}

			ended := make(chan struct{})
			go func() {
				defer close(ended)
				deps.endCycle(context.Background(), cycle, "reason", "test")
			}()

			if tc.registerLate {
				// Nothing may happen until the reload loop is registered: fencing
				// without it would tear down a plane still being programmed.
				select {
				case <-ended:
					t.Fatal("the cycle ended before the leadership callback registered the reload loop")
				case <-time.After(50 * time.Millisecond):
				}
				cycle.lead(stop, reloadDone)
			}
			waitFor(t, ended, "the cycle to end")

			mu.Lock()
			got := slices.Clone(events)
			mu.Unlock()
			if !slices.Equal(got, tc.wantEvents) {
				t.Errorf("events = %v, want %v", got, tc.wantEvents)
			}
		})
	}
}

// freeLease clears the Lease's holder, the state a released Lease is in and the one a
// contending replica can acquire from.
func freeLease(t *testing.T, f *runElectionFixture, namespace, leaseName string) {
	t.Helper()
	lease, err := f.cs.CoordinationV1().Leases(namespace).Get(context.Background(), leaseName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get lease: %v", err)
	}
	lease.Spec.HolderIdentity = new("")
	lease.Spec.RenewTime = new(metav1.NewMicroTime(time.Now()))
	if _, err := f.cs.CoordinationV1().Leases(namespace).Update(context.Background(), lease, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("free lease: %v", err)
	}
}

// TestRunElectionFencesBeforeRelease pins the order of a voluntary release: client-go frees the
// Lease as its renew loop ends, so the fence must finish before the release write lands.
func TestRunElectionFencesBeforeRelease(t *testing.T) {
	const namespace, leaseName = "gw-ns", "gw-link"

	tcs := []struct {
		name string
		// handoff ends the cycle through the handoff monitor: this node loses its only
		// endpoint while a live peer keeps one, which releases at once.
		handoff bool
		// reloadFails points the loop at a config dir that does not exist, so its own exit ends
		// the cycle: the loop-stopped assertions do not apply and runElection returns the error.
		reloadFails bool
	}{
		{name: "sigterm_releases_after_the_fence"},
		{name: "handoff_releases_after_the_fence", handoff: true},
		{name: "reload_loop_failure_releases_after_the_fence", reloadFails: true},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			f, ef := newLocalRunElectionFixture(t, namespace, leaseName, []string{"node-a", "node-b"})

			var mu sync.Mutex
			var reloadCtx context.Context
			var fenceDone, fenceSawLoopStopped, fenceSawApplyInFlight bool
			var releasedFenced, releasedLoopStopped bool
			var appliesInFlight atomic.Int32
			released := make(chan struct{})
			var releasedOnce sync.Once

			applied := make(chan struct{})
			var appliedOnce sync.Once
			f.deps.reconcile = func(ctx context.Context, _ RuntimeConfig, _, _ string, _ []ResolvedForward, _ []unsatisfiedForward) error {
				appliesInFlight.Add(1)
				defer appliesInFlight.Add(-1)
				mu.Lock()
				reloadCtx = ctx
				mu.Unlock()
				appliedOnce.Do(func() { close(applied) })
				return nil
			}
			// loopStopped reports whether the reload loop's context has been cancelled,
			// which is the only thing that ends the loop on a voluntary path.
			loopStopped := func() bool {
				return reloadCtx != nil && reloadCtx.Err() != nil
			}
			f.deps.fence = func(context.Context) error {
				f.teardowns.Add(1)
				mu.Lock()
				fenceSawLoopStopped = loopStopped()
				fenceSawApplyInFlight = appliesInFlight.Load() > 0
				mu.Unlock()
				// A real teardown runs several commands: without the ordering the
				// release write wins this race, which is the whole defect.
				time.Sleep(100 * time.Millisecond)
				mu.Lock()
				fenceDone = true
				mu.Unlock()
				return nil
			}
			f.cs.PrependReactor("update", "leases", func(action k8stesting.Action) (bool, runtime.Object, error) {
				lease, ok := action.(k8stesting.UpdateAction).GetObject().(*coordinationv1.Lease)
				if !ok || (lease.Spec.HolderIdentity != nil && *lease.Spec.HolderIdentity != "") {
					return false, nil, nil
				}
				mu.Lock()
				releasedFenced, releasedLoopStopped = fenceDone, loopStopped()
				mu.Unlock()
				releasedOnce.Do(func() { close(released) })
				return false, nil, nil
			})

			if tc.reloadFails {
				f.deps.cfg.ConfigPath = filepath.Join(t.TempDir(), "missing", "config.json")
			}

			outerCtx, cancelOuter := context.WithCancel(context.Background())
			defer cancelOuter()
			errs := make(chan error, 1)
			go func() { errs <- f.deps.runElection(outerCtx, outerCtx) }()

			switch {
			case tc.reloadFails:
			case tc.handoff:
				waitFor(t, applied, "the first apply")
				ef.dropEndpointOn(t, "web", "node-a")
				ef.endpointOn(t, "web", "node-b")
				ef.watcher.signalChange()
			default:
				waitFor(t, applied, "the first apply")
				cancelOuter()
			}

			waitFor(t, released, "the lease to be released")
			mu.Lock()
			gotReleasedLoopStopped, gotReleasedFenced := releasedLoopStopped, releasedFenced
			gotFenceSawLoopStopped, gotFenceSawApplyInFlight := fenceSawLoopStopped, fenceSawApplyInFlight
			mu.Unlock()
			if !gotReleasedFenced {
				t.Error("the lease was released before the fence had torn the data plane down")
			}
			if !tc.reloadFails {
				if !gotReleasedLoopStopped {
					t.Error("the lease was released while the reload loop could still apply")
				}
				if !gotFenceSawLoopStopped {
					t.Error("the fence ran before the reload loop was stopped")
				}
				if gotFenceSawApplyInFlight {
					t.Error("the fence ran while an apply was in flight")
				}
			}

			cancelOuter()
			select {
			case err := <-errs:
				if gotErr := err != nil; gotErr != tc.reloadFails {
					t.Fatalf("runElection = %v, want an error = %v", err, tc.reloadFails)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("runElection did not return")
			}
		})
	}
}

// TestRunElectionReloadLoopFailure drives a cycle whose reload loop cannot start: nothing
// programs the data plane while client-go renews, so the cycle must end itself and return.
func TestRunElectionReloadLoopFailure(t *testing.T) {
	const namespace, leaseName, podName = "gw-ns", "gw-link", "pod-a"

	f := newRunElectionFixture(t, namespace, leaseName, podName)
	f.deps.cfg.ConfigPath = filepath.Join(t.TempDir(), "missing", "config.json")

	var applied atomic.Bool
	f.deps.reconcile = func(context.Context, RuntimeConfig, string, string, []ResolvedForward, []unsatisfiedForward) error {
		applied.Store(true)
		return nil
	}

	outerCtx := t.Context()
	errs := make(chan error, 1)
	go func() { errs <- f.deps.runElection(outerCtx, outerCtx) }()

	select {
	case err := <-errs:
		if err == nil || !strings.Contains(err.Error(), "watch config dir") {
			t.Fatalf("runElection = %v, want an error naming the failed config dir watch", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runElection did not return")
	}

	if applied.Load() {
		t.Error("the apply ran although the reload loop never started")
	}
	if got := f.teardowns.Load(); got != 1 {
		t.Errorf("teardowns = %d, want 1", got)
	}
	if f.deps.rd.isLeader() {
		t.Error("isLeader = true after the cycle ended")
	}
	if got := f.leaseFault(t, namespace, leaseName); got != FaultApplyFailed {
		t.Errorf("lease fault = %q, want %q", got, FaultApplyFailed)
	}

	lease, err := f.cs.CoordinationV1().Leases(namespace).Get(context.Background(), leaseName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get lease: %v", err)
	}
	if msg := lease.Annotations[LeaseFaultMessageAnnotation]; !strings.Contains(msg, "reload loop ended") {
		t.Errorf("lease fault message = %q, want one naming the ended reload loop", msg)
	}
	if h := lease.Spec.HolderIdentity; h != nil && *h != "" {
		t.Errorf("lease holder = %q, want the lease released", *h)
	}
}

// ctxAwareClientset makes Lease reads and writes fail on a done context: the fake clientset
// ignores the context, so a test could not otherwise tell a live call from an expired one.
type ctxAwareClientset struct {
	kubernetes.Interface
}

func (c ctxAwareClientset) CoordinationV1() coordinationv1client.CoordinationV1Interface {
	return ctxAwareCoordination{CoordinationV1Interface: c.Interface.CoordinationV1()}
}

type ctxAwareCoordination struct {
	coordinationv1client.CoordinationV1Interface
}

func (c ctxAwareCoordination) Leases(namespace string) coordinationv1client.LeaseInterface {
	return ctxAwareLeases{LeaseInterface: c.CoordinationV1Interface.Leases(namespace)}
}

type ctxAwareLeases struct {
	coordinationv1client.LeaseInterface
}

func (l ctxAwareLeases) Get(ctx context.Context, name string, opts metav1.GetOptions) (*coordinationv1.Lease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return l.LeaseInterface.Get(ctx, name, opts)
}

func (l ctxAwareLeases) Update(ctx context.Context, lease *coordinationv1.Lease, opts metav1.UpdateOptions) (*coordinationv1.Lease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return l.LeaseInterface.Update(ctx, lease, opts)
}

// TestRunElectionClearSurvivesFenceDeadline pins that a teardown running to its own deadline
// still leaves the Lease describing no fault: the clear on step-down has its own budget.
func TestRunElectionClearSurvivesFenceDeadline(t *testing.T) {
	const namespace, leaseName, podName = "gw-ns", "gw-link", "pod-a"

	f := newRunElectionFixture(t, namespace, leaseName, podName)
	f.deps.cs = ctxAwareClientset{Interface: f.cs}
	f.deps.fence = func(ctx context.Context) error {
		f.teardowns.Add(1)
		<-ctx.Done()
		return ctx.Err()
	}

	applied := make(chan struct{})
	var appliedOnce sync.Once
	f.deps.reconcile = func(context.Context, RuntimeConfig, string, string, []ResolvedForward, []unsatisfiedForward) error {
		appliedOnce.Do(func() { close(applied) })
		return nil
	}

	outerCtx, cancelOuter := context.WithCancel(context.Background())
	defer cancelOuter()
	gctx, cancelGroup := context.WithCancel(outerCtx)
	defer cancelGroup()
	errs := make(chan error, 1)
	go func() { errs <- f.deps.runElection(outerCtx, gctx) }()

	waitFor(t, applied, "first apply")
	cancelOuter()
	select {
	case err := <-errs:
		if err != nil {
			t.Fatalf("runElection = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runElection did not return")
	}

	if !f.clearedFault.Load() {
		t.Error("fence cleared the lease fault = false, want true")
	}
	if got := f.teardowns.Load(); got != 1 {
		t.Errorf("teardowns = %d, want 1", got)
	}
}
