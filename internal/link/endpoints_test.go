package link

import (
	"context"
	"maps"
	"slices"
	"testing"
	"time"

	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

// newTestIndexer builds an empty namespace-indexed cache.Indexer, mirroring the shape
// a real informer's GetIndexer() returns.
func newTestIndexer(t *testing.T) cache.Indexer {
	t.Helper()
	return cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
}

// newWatcherFromIndexers builds a watcher over pre-populated stores, the shape the
// informers leave behind, so a test can exercise resolution without an apiserver.
func newWatcherFromIndexers(node string, forwards []Forward, indexers map[endpointWatcherKey]cache.Indexer) *endpointWatcher {
	informers := make(map[endpointWatcherKey]*sliceInformer, len(indexers))
	for key, indexer := range indexers {
		informers[key] = newSyncedSliceInformer(indexer)
	}
	return &endpointWatcher{node: node, forwards: forwards, slices: informers, syncGrace: testSyncGrace, log: zap.NewNop().Sugar()}
}

// newSyncedSliceInformer wraps a pre-populated store as an informer that has already
// synced, so a reader treats it as authoritative rather than pending.
func newSyncedSliceInformer(indexer cache.Indexer) *sliceInformer {
	return &sliceInformer{
		indexer:   indexer,
		hasSynced: func() bool { return true },
		started:   time.Now(),
		stop:      func() {},
	}
}

// testSyncGrace keeps the pending window short enough that a test can watch a stuck
// watch cross it without waiting on endpointSyncGrace.
const testSyncGrace = 50 * time.Millisecond

// waitSnapshot polls w.snapshot until cond holds, failing on timeout: the informers fill
// asynchronously, so a resolution a test expects is reached rather than observed at once.
func waitSnapshot(t *testing.T, w *endpointWatcher, timeout time.Duration, cond func(resolved []ResolvedForward, unsatisfied []unsatisfiedForward) bool) ([]ResolvedForward, []unsatisfiedForward) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		resolved, unsatisfied, _ := w.snapshot()
		if cond(resolved, unsatisfied) {
			return resolved, unsatisfied
		}
		if time.Now().After(deadline) {
			t.Fatalf("snapshot never satisfied the condition within %v: resolved=%+v unsatisfied=%v", timeout, resolved, unsatisfied)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func addSlices(t *testing.T, indexer cache.Indexer, slices ...*discoveryv1.EndpointSlice) {
	t.Helper()
	for _, s := range slices {
		if err := indexer.Add(s); err != nil {
			t.Fatalf("add slice %s: %v", s.Name, err)
		}
	}
}

func TestSelectEndpoint(t *testing.T) {
	tcs := []struct {
		name     string
		slices   []*discoveryv1.EndpointSlice
		node     string
		portName string
		wantAddr string
		wantPort int
		wantOK   bool
	}{
		{
			name: "node_filter_excludes_other_node",
			slices: []*discoveryv1.EndpointSlice{
				makeSlice("s1", discoveryv1.AddressTypeIPv4,
					[]discoveryv1.EndpointPort{{Name: new(""), Port: new(int32(8080))}},
					epEntry([]string{"10.244.1.1"}, "node-a", new(true)),
					epEntry([]string{"10.244.2.1"}, "node-b", new(true)),
				),
			},
			node:     "node-a",
			wantAddr: "10.244.1.1",
			wantPort: 8080,
			wantOK:   true,
		},
		{
			name: "ready_true_kept",
			slices: []*discoveryv1.EndpointSlice{
				makeSlice("s1", discoveryv1.AddressTypeIPv4,
					[]discoveryv1.EndpointPort{{Name: new(""), Port: new(int32(8080))}},
					epEntry([]string{"10.244.1.1"}, "node-a", new(true)),
				),
			},
			node:     "node-a",
			wantAddr: "10.244.1.1",
			wantPort: 8080,
			wantOK:   true,
		},
		{
			name: "ready_false_excluded",
			slices: []*discoveryv1.EndpointSlice{
				makeSlice("s1", discoveryv1.AddressTypeIPv4,
					[]discoveryv1.EndpointPort{{Name: new(""), Port: new(int32(8080))}},
					epEntry([]string{"10.244.1.1"}, "node-a", new(false)),
				),
			},
			node:   "node-a",
			wantOK: false,
		},
		{
			name: "ready_nil_treated_as_ready",
			slices: []*discoveryv1.EndpointSlice{
				makeSlice("s1", discoveryv1.AddressTypeIPv4,
					[]discoveryv1.EndpointPort{{Name: new(""), Port: new(int32(8080))}},
					epEntry([]string{"10.244.1.1"}, "node-a", nil),
				),
			},
			node:     "node-a",
			wantAddr: "10.244.1.1",
			wantPort: 8080,
			wantOK:   true,
		},
		{
			name: "ipv6_slice_excluded",
			slices: []*discoveryv1.EndpointSlice{
				makeSlice("s1", discoveryv1.AddressTypeIPv6,
					[]discoveryv1.EndpointPort{{Name: new(""), Port: new(int32(8080))}},
					epEntry([]string{"fd00::1"}, "node-a", new(true)),
				),
			},
			node:   "node-a",
			wantOK: false,
		},
		{
			name: "deterministic_pick_from_multi_address_slice",
			slices: []*discoveryv1.EndpointSlice{
				makeSlice("s1", discoveryv1.AddressTypeIPv4,
					[]discoveryv1.EndpointPort{{Name: new(""), Port: new(int32(8080))}},
					epEntry([]string{"10.244.1.9"}, "node-a", new(true)),
					epEntry([]string{"10.244.1.2"}, "node-a", new(true)),
				),
			},
			node:     "node-a",
			wantAddr: "10.244.1.2",
			wantPort: 8080,
			wantOK:   true,
		},
		{
			name: "named_port_resolution",
			slices: []*discoveryv1.EndpointSlice{
				makeSlice("s1", discoveryv1.AddressTypeIPv4,
					[]discoveryv1.EndpointPort{{Name: new("https"), Port: new(int32(9443))}},
					epEntry([]string{"10.244.1.1"}, "node-a", new(true)),
				),
			},
			node:     "node-a",
			portName: "https",
			wantAddr: "10.244.1.1",
			wantPort: 9443,
			wantOK:   true,
		},
		{
			name: "unnamed_port_resolution",
			slices: []*discoveryv1.EndpointSlice{
				makeSlice("s1", discoveryv1.AddressTypeIPv4,
					[]discoveryv1.EndpointPort{{Name: new(""), Port: new(int32(8080))}},
					epEntry([]string{"10.244.1.1"}, "node-a", new(true)),
				),
			},
			node:     "node-a",
			portName: "",
			wantAddr: "10.244.1.1",
			wantPort: 8080,
			wantOK:   true,
		},
		{
			name: "same_port_name_two_slices_pairs_address_with_its_own_slice_port",
			slices: []*discoveryv1.EndpointSlice{
				makeSlice("s1", discoveryv1.AddressTypeIPv4,
					[]discoveryv1.EndpointPort{{Name: new("http"), Port: new(int32(8080))}},
					epEntry([]string{"10.244.1.9"}, "node-a", new(true)),
				),
				makeSlice("s2", discoveryv1.AddressTypeIPv4,
					[]discoveryv1.EndpointPort{{Name: new("http"), Port: new(int32(9090))}},
					epEntry([]string{"10.244.1.2"}, "node-a", new(true)),
				),
			},
			node:     "node-a",
			portName: "http",
			wantAddr: "10.244.1.2",
			wantPort: 9090,
			wantOK:   true,
		},
		{
			name: "same_port_name_two_slices_reversed_insert_order_same_pair",
			slices: []*discoveryv1.EndpointSlice{
				makeSlice("s2", discoveryv1.AddressTypeIPv4,
					[]discoveryv1.EndpointPort{{Name: new("http"), Port: new(int32(9090))}},
					epEntry([]string{"10.244.1.2"}, "node-a", new(true)),
				),
				makeSlice("s1", discoveryv1.AddressTypeIPv4,
					[]discoveryv1.EndpointPort{{Name: new("http"), Port: new(int32(8080))}},
					epEntry([]string{"10.244.1.9"}, "node-a", new(true)),
				),
			},
			node:     "node-a",
			portName: "http",
			wantAddr: "10.244.1.2",
			wantPort: 9090,
			wantOK:   true,
		},
		{
			name: "slice_without_port_name_contributes_no_candidate",
			slices: []*discoveryv1.EndpointSlice{
				makeSlice("s1", discoveryv1.AddressTypeIPv4,
					[]discoveryv1.EndpointPort{{Name: new("metrics"), Port: new(int32(9100))}},
					epEntry([]string{"10.244.1.1"}, "node-a", new(true)),
				),
				makeSlice("s2", discoveryv1.AddressTypeIPv4,
					[]discoveryv1.EndpointPort{{Name: new("http"), Port: new(int32(8080))}},
					epEntry([]string{"10.244.1.5"}, "node-a", new(true)),
				),
			},
			node:     "node-a",
			portName: "http",
			wantAddr: "10.244.1.5",
			wantPort: 8080,
			wantOK:   true,
		},
		{
			name: "address_that_is_not_an_ip_is_skipped",
			slices: []*discoveryv1.EndpointSlice{
				makeSlice("s1", discoveryv1.AddressTypeIPv4,
					[]discoveryv1.EndpointPort{{Name: new(""), Port: new(int32(8080))}},
					// The malformed address sorts first, so it would win the
					// selection if it were not rejected.
					epEntry([]string{"10.244.1.1; drop", "10.244.1.7"}, "node-a", new(true)),
				),
			},
			node:     "node-a",
			wantAddr: "10.244.1.7",
			wantPort: 8080,
			wantOK:   true,
		},
		{
			name: "nil_port_unsatisfied",
			slices: []*discoveryv1.EndpointSlice{
				makeSlice("s1", discoveryv1.AddressTypeIPv4,
					[]discoveryv1.EndpointPort{{Name: new(""), Port: nil}},
					epEntry([]string{"10.244.1.1"}, "node-a", new(true)),
				),
			},
			node:   "node-a",
			wantOK: false,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			indexer := newTestIndexer(t)
			addSlices(t, indexer, tc.slices...)

			addr, port, ok := selectEndpoint(indexer, tc.node, tc.portName, testLogger(t))
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if addr != tc.wantAddr {
				t.Errorf("addr = %q, want %q", addr, tc.wantAddr)
			}
			if port != tc.wantPort {
				t.Errorf("port = %d, want %d", port, tc.wantPort)
			}
		})
	}
}

func TestEndpointWatcherSnapshot(t *testing.T) {
	forwards := []Forward{
		{Name: "web", PublicPort: 443, Protocol: "tcp", Namespace: "default", ServiceName: "web", ServicePortName: ""},
		{Name: "api", PublicPort: 8443, Protocol: "tcp", Namespace: "default", ServiceName: "api", ServicePortName: "https"},
	}

	webIndexer := newTestIndexer(t)
	addSlices(t, webIndexer, makeSlice("web-abcde", discoveryv1.AddressTypeIPv4,
		[]discoveryv1.EndpointPort{{Name: new(""), Port: new(int32(9080))}},
		epEntry([]string{"10.244.1.7"}, "node-a", new(true)),
	))
	apiIndexer := newTestIndexer(t)
	// api has no endpoint on node-a: unsatisfied.

	w := newWatcherFromIndexers("node-a", forwards, map[endpointWatcherKey]cache.Indexer{
		{namespace: "default", serviceName: "web"}: webIndexer,
		{namespace: "default", serviceName: "api"}: apiIndexer,
	})

	resolved, unsatisfied, _ := w.snapshot()
	if len(resolved) != 1 || resolved[0].Name != "web" || resolved[0].Target != "10.244.1.7" || resolved[0].TargetPort != 9080 {
		t.Fatalf("resolved = %+v, want one web forward at 10.244.1.7:9080", resolved)
	}
	if len(unsatisfied) != 1 || unsatisfied[0].name != "api" || unsatisfied[0].reason != reasonNoLocalPod {
		t.Fatalf("unsatisfied = %+v, want [{api %s}]", unsatisfied, reasonNoLocalPod)
	}
}

// TestEndpointWatcherEvaluate covers the one locked reading of the election's inputs. A forward
// whose endpoint is ready but whose port does not resolve counts for no node, so none looks ready.
func TestEndpointWatcherEvaluate(t *testing.T) {
	// build wires three forwards: web resolves on node-a alone, api on node-a and
	// node-b, and metrics on neither because its slice carries no port number.
	build := func(t *testing.T, node string) *endpointWatcher {
		t.Helper()
		webIndexer := newTestIndexer(t)
		addSlices(t, webIndexer, makeSlice("web-abcde", discoveryv1.AddressTypeIPv4,
			[]discoveryv1.EndpointPort{{Name: new(""), Port: new(int32(9080))}},
			epEntry([]string{"10.244.1.7"}, "node-a", new(true)),
		))
		apiIndexer := newTestIndexer(t)
		addSlices(t, apiIndexer, makeSlice("api-abcde", discoveryv1.AddressTypeIPv4,
			[]discoveryv1.EndpointPort{{Name: new(""), Port: new(int32(9090))}},
			epEntry([]string{"10.244.1.9"}, "node-a", new(true)),
			epEntry([]string{"10.244.2.1"}, "node-b", new(true)),
		))
		metricsIndexer := newTestIndexer(t)
		addSlices(t, metricsIndexer, makeSlice("metrics-abcde", discoveryv1.AddressTypeIPv4,
			[]discoveryv1.EndpointPort{{Name: new(""), Port: nil}},
			epEntry([]string{"10.244.1.11"}, "node-a", new(true)),
			epEntry([]string{"10.244.2.3"}, "node-b", new(true)),
		))

		forwards := []Forward{
			{Name: "web", Namespace: "default", ServiceName: "web"},
			{Name: "api", Namespace: "default", ServiceName: "api"},
			{Name: "metrics", Namespace: "default", ServiceName: "metrics"},
		}
		return newWatcherFromIndexers(node, forwards, map[endpointWatcherKey]cache.Indexer{
			{namespace: "default", serviceName: "web"}:     webIndexer,
			{namespace: "default", serviceName: "api"}:     apiIndexer,
			{namespace: "default", serviceName: "metrics"}: metricsIndexer,
		})
	}

	tcs := []struct {
		name string
		node string
		pods []*corev1.Pod
		// pendingForward adds a fourth forward whose watch has not synced yet.
		pendingForward   bool
		wantForwardCount int
		wantPending      []string
		wantLive         map[string]bool
		wantScores       map[string]int
	}{
		{
			name:             "scores_every_live_node_and_self",
			node:             "node-c",
			pods:             []*corev1.Pod{makePod("link-a", "node-a", true), makePod("link-b", "node-b", true)},
			wantForwardCount: 3,
			wantLive:         map[string]bool{"node-a": true, "node-b": true},
			wantScores:       map[string]int{"node-a": 2, "node-b": 1, "node-c": 0},
		},
		{
			name:             "not_ready_pod_is_not_live",
			node:             "node-a",
			pods:             []*corev1.Pod{makePod("link-a", "node-a", true), makePod("link-b", "node-b", false)},
			wantForwardCount: 3,
			wantLive:         map[string]bool{"node-a": true},
			wantScores:       map[string]int{"node-a": 2},
		},
		{
			name:             "unsynced_forward_is_pending",
			node:             "node-a",
			pods:             []*corev1.Pod{makePod("link-a", "node-a", true)},
			pendingForward:   true,
			wantForwardCount: 4,
			wantPending:      []string{"extra"},
			wantLive:         map[string]bool{"node-a": true},
			wantScores:       map[string]int{"node-a": 2},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			w := build(t, tc.node)
			podIndexer := newTestIndexer(t)
			addPods(t, podIndexer, tc.pods...)
			w.podIndexer = podIndexer
			if tc.pendingForward {
				w.syncGrace = time.Minute
				w.forwards = append(w.forwards, Forward{Name: "extra", Namespace: "default", ServiceName: "extra"})
				w.slices[endpointWatcherKey{namespace: "default", serviceName: "extra"}] = &sliceInformer{
					indexer:   newTestIndexer(t),
					hasSynced: func() bool { return false },
					started:   time.Now(),
					stop:      func() {},
				}
			}

			v := w.evaluate()
			if v.forwardCount != tc.wantForwardCount {
				t.Errorf("forwardCount = %d, want %d", v.forwardCount, tc.wantForwardCount)
			}
			if !slices.Equal(v.pending, tc.wantPending) {
				t.Errorf("pending = %v, want %v", v.pending, tc.wantPending)
			}
			if !maps.Equal(v.live, tc.wantLive) {
				t.Errorf("live = %v, want %v", v.live, tc.wantLive)
			}
			if !maps.Equal(v.scores, tc.wantScores) {
				t.Errorf("scores = %v, want %v", v.scores, tc.wantScores)
			}
		})
	}
}

// TestPodNode covers turning a Lease holder identity into the node its data plane
// lives on: only a pod the informer knows, and only one that is scheduled, answers.
func TestPodNode(t *testing.T) {
	podIndexer := newTestIndexer(t)
	addPods(t, podIndexer,
		makePod("link-a", "node-a", true),
		makePod("link-unscheduled", "", true),
	)
	w := &endpointWatcher{podIndexer: podIndexer}

	tcs := []struct {
		name     string
		pod      string
		wantNode string
		wantOK   bool
	}{
		{name: "known_pod_names_its_node", pod: "link-a", wantNode: "node-a", wantOK: true},
		{name: "unknown_pod_is_not_known", pod: "link-z"},
		{name: "unscheduled_pod_is_not_known", pod: "link-unscheduled"},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			node, ok := w.podNode(tc.pod)
			if node != tc.wantNode || ok != tc.wantOK {
				t.Errorf("podNode(%q) = (%q, %v), want (%q, %v)", tc.pod, node, ok, tc.wantNode, tc.wantOK)
			}
		})
	}
}

// TestEndpointWatcherLastKnownRetained pins that snapshot and evaluate read straight from the
// informer stores, so there is no separately maintained cache to go stale.
func TestEndpointWatcherLastKnownRetained(t *testing.T) {
	webIndexer := newTestIndexer(t)
	addSlices(t, webIndexer, makeSlice("web-abcde", discoveryv1.AddressTypeIPv4,
		[]discoveryv1.EndpointPort{{Name: new(""), Port: new(int32(9080))}},
		epEntry([]string{"10.244.1.7"}, "node-a", new(true)),
	))

	w := newWatcherFromIndexers("node-a", []Forward{{Name: "web", Namespace: "default", ServiceName: "web"}},
		map[endpointWatcherKey]cache.Indexer{
			{namespace: "default", serviceName: "web"}: webIndexer,
		})

	first, _, _ := w.snapshot()
	second, _, _ := w.snapshot()
	if len(first) != 1 || len(second) != 1 || first[0] != second[0] {
		t.Fatalf("snapshot changed across calls with an untouched store: first=%+v second=%+v", first, second)
	}
}

// TestNewEndpointWatcherPodSelector pins that the pod watch is built from the caller's podSelector,
// not labels.Everything(): a pod without the selector's labels is never counted live.
func TestNewEndpointWatcherPodSelector(t *testing.T) {
	tcs := []struct {
		name         string
		matchingPod  bool
		wantLiveNode bool
	}{
		{
			name:         "selector_matches_labelled_pod_only",
			matchingPod:  true,
			wantLiveNode: true,
		},
		{
			name:         "selector_excludes_unlabelled_pod",
			matchingPod:  false,
			wantLiveNode: false,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "link-a", Namespace: "gw-ns"},
				Spec:       corev1.PodSpec{NodeName: "node-a"},
				Status: corev1.PodStatus{
					Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
				},
			}
			if tc.matchingPod {
				pod.Labels = map[string]string{"app": "gateway-link"}
			} else {
				pod.Labels = map[string]string{"app": "unrelated"}
			}

			cs := fake.NewClientset(pod)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			selector := labels.SelectorFromSet(map[string]string{"app": "gateway-link"})
			w, err := newEndpointWatcher(ctx, cs, "node-a", nil, "gw-ns", selector, time.Minute, testLogger(t))
			if err != nil {
				t.Fatalf("newEndpointWatcher: %v", err)
			}

			if got := w.evaluate().live["node-a"]; got != tc.wantLiveNode {
				t.Errorf("evaluate().live[node-a] = %v, want %v", got, tc.wantLiveNode)
			}
		})
	}
}

func makeSlice(name string, addrType discoveryv1.AddressType, ports []discoveryv1.EndpointPort, endpoints ...discoveryv1.Endpoint) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta:  metav1.ObjectMeta{Name: name, Namespace: "default"},
		AddressType: addrType,
		Ports:       ports,
		Endpoints:   endpoints,
	}
}

// epEntry builds one EndpointSlice endpoint; a nil ready leaves Ready unset.
func epEntry(addrs []string, node string, ready *bool) discoveryv1.Endpoint {
	n := node
	return discoveryv1.Endpoint{
		Addresses:  addrs,
		NodeName:   &n,
		Conditions: discoveryv1.EndpointConditions{Ready: ready},
	}
}

func addPods(t *testing.T, indexer cache.Indexer, pods ...*corev1.Pod) {
	t.Helper()
	for _, p := range pods {
		if err := indexer.Add(p); err != nil {
			t.Fatalf("add pod %s: %v", p.Name, err)
		}
	}
}

func makePod(name, node string, ready bool) *corev1.Pod {
	status := corev1.ConditionFalse
	if ready {
		status = corev1.ConditionTrue
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec:       corev1.PodSpec{NodeName: node},
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: status}},
		},
	}
}

// TestEndpointWatcherSubscribeFanOut pins that every subscriber sees every change: a wakeup one
// consumes still reaches the other, and a cancelled one neither blocks the notifier nor receives.
func TestEndpointWatcherSubscribeFanOut(t *testing.T) {
	w := &endpointWatcher{}

	first, cancelFirst := w.subscribe()
	second, cancelSecond := w.subscribe()
	defer cancelSecond()

	w.signalChange()
	for i, ch := range []<-chan struct{}{first, second} {
		select {
		case <-ch:
		default:
			t.Fatalf("subscriber %d received no signal", i)
		}
	}

	cancelFirst()
	w.signalChange()
	select {
	case <-first:
		t.Error("cancelled subscriber still received a signal")
	default:
	}
	select {
	case <-second:
	default:
		t.Error("live subscriber received no signal after another was cancelled")
	}
}

// makeServiceSlice builds an EndpointSlice carrying the kubernetes.io/service-name
// label the watcher's informers select on, with one ready IPv4 endpoint on node.
func makeServiceSlice(namespace, service, node, addr string, port int32) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      service + "-abcde",
			Namespace: namespace,
			Labels:    map[string]string{discoveryv1.LabelServiceName: service},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Ports:       []discoveryv1.EndpointPort{{Name: new(""), Port: &port}},
		Endpoints:   []discoveryv1.Endpoint{epEntry([]string{addr}, node, new(true))},
	}
}

// TestEndpointWatcherSetForwards drives the forward set a running watcher tracks: an added forward
// brings up its informer, a removed one takes it away, an unchanged set restarts nothing.
func TestEndpointWatcherSetForwards(t *testing.T) {
	const namespace, node = "default", "node-a"
	web := Forward{Name: "web", PublicPort: 443, Protocol: "tcp", Namespace: namespace, ServiceName: "web"}
	api := Forward{Name: "api", PublicPort: 8443, Protocol: "tcp", Namespace: namespace, ServiceName: "api"}

	cs := fake.NewClientset(
		makeServiceSlice(namespace, "web", node, "10.244.1.7", 9080),
		makeServiceSlice(namespace, "api", node, "10.244.1.8", 9090),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	w, err := newEndpointWatcher(ctx, cs, node, []Forward{web}, "gw-ns",
		labels.SelectorFromSet(map[string]string{"app": "gateway-link"}), time.Minute, testLogger(t))
	if err != nil {
		t.Fatalf("newEndpointWatcher: %v", err)
	}

	t.Run("added_forward_is_watched_and_resolves", func(t *testing.T) {
		w.setForwards([]Forward{web, api})
		if got := w.evaluate().forwardCount; got != 2 {
			t.Errorf("forwardCount = %d, want 2", got)
		}
		resolved, unsatisfied := waitSnapshot(t, w, 5*time.Second, func(resolved []ResolvedForward, _ []unsatisfiedForward) bool {
			return len(resolved) == 2
		})
		if len(unsatisfied) != 0 {
			t.Fatalf("snapshot = %+v, unsatisfied %v; want both forwards resolved", resolved, unsatisfied)
		}
		if resolved[1].Target != "10.244.1.8" || resolved[1].TargetPort != 9090 {
			t.Errorf("added forward resolved to %s:%d, want 10.244.1.8:9090", resolved[1].Target, resolved[1].TargetPort)
		}
	})

	t.Run("removed_forward_stops_its_informer", func(t *testing.T) {
		w.setForwards([]Forward{api})
		resolved, _ := waitSnapshot(t, w, 5*time.Second, func(resolved []ResolvedForward, _ []unsatisfiedForward) bool {
			return len(resolved) == 1
		})
		if resolved[0].Name != "api" {
			t.Fatalf("snapshot = %+v, want the api forward alone", resolved)
		}
		w.mu.Lock()
		_, stillRunning := w.slices[endpointWatcherKey{namespace: namespace, serviceName: "web"}]
		w.mu.Unlock()
		if stillRunning {
			t.Error("web informer still registered after its forward was removed")
		}
	})

	t.Run("unchanged_set_signals_nothing", func(t *testing.T) {
		changes, cancelChanges := w.subscribe()
		defer cancelChanges()
		w.setForwards([]Forward{api})
		select {
		case <-changes:
			t.Error("an unchanged forward set woke a subscriber")
		default:
		}
	})
}

// TestSetForwardsNeverBlocksOnTheApiserver pins that an EndpointSlice watch that cannot list does
// not stall readers: one blocked here is a leader that can neither hand off nor tear down.
func TestSetForwardsNeverBlocksOnTheApiserver(t *testing.T) {
	const namespace, node = "default", "node-a"
	web := Forward{Name: "web", PublicPort: 443, Protocol: "tcp", Namespace: namespace, ServiceName: "web"}

	blocked := make(chan struct{})
	defer close(blocked)

	cs := fake.NewClientset()
	cs.PrependReactor("list", "endpointslices", func(k8stesting.Action) (bool, runtime.Object, error) {
		<-blocked
		return false, nil, nil
	})

	ctx := t.Context()
	w, err := newEndpointWatcher(ctx, cs, node, nil, "gw-ns",
		labels.SelectorFromSet(map[string]string{"app": "gateway-link"}), time.Minute, testLogger(t))
	if err != nil {
		t.Fatalf("newEndpointWatcher: %v", err)
	}

	tcs := []struct {
		name string
		call func()
	}{
		{name: "setForwards", call: func() { w.setForwards([]Forward{web}) }},
		{name: "snapshot", call: func() { w.snapshot() }},
		{name: "evaluate", call: func() { w.evaluate() }},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			done := make(chan struct{})
			go func() {
				defer close(done)
				tc.call()
			}()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatalf("%s did not return while an endpointslice list was blocked", tc.name)
			}
		})
	}
}

// TestSnapshotSyncGrace pins how a forward whose watch has not synced is reported: pending inside
// the grace, so no fault is published, then unsatisfied naming the stuck watch after it.
func TestSnapshotSyncGrace(t *testing.T) {
	const namespace, node = "default", "node-a"
	web := Forward{Name: "web", PublicPort: 443, Protocol: "tcp", Namespace: namespace, ServiceName: "web"}

	tcs := []struct {
		name            string
		synced          bool
		startedAgo      time.Duration
		wantResolved    int
		wantUnsatisfied []unsatisfiedForward
		wantPending     []string
		// slice is added to the forward's store before the snapshot, so a row can
		// distinguish an empty store from an endpoint publishing no matching port.
		slice *discoveryv1.EndpointSlice
	}{
		{
			name:        "unsynced_inside_grace_is_pending",
			startedAgo:  0,
			wantPending: []string{"web"},
		},
		{
			name:            "unsynced_past_grace_is_unsatisfied",
			startedAgo:      4 * testSyncGrace,
			wantUnsatisfied: []unsatisfiedForward{{name: "web", reason: reasonWatchUnsynced}},
		},
		{
			name:            "synced_and_empty_is_unsatisfied_by_name",
			synced:          true,
			wantUnsatisfied: []unsatisfiedForward{{name: "web", reason: reasonNoLocalPod}},
		},
		{
			name:   "ready_endpoint_without_the_port_is_port_not_found",
			synced: true,
			slice: makeSlice("web-abcde", discoveryv1.AddressTypeIPv4,
				[]discoveryv1.EndpointPort{{Name: new("https"), Port: new(int32(9080))}},
				epEntry([]string{"10.244.1.7"}, node, new(true)),
			),
			wantUnsatisfied: []unsatisfiedForward{{name: "web", reason: reasonPortNotFound}},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			indexer := newTestIndexer(t)
			if tc.slice != nil {
				addSlices(t, indexer, tc.slice)
			}
			informers := map[endpointWatcherKey]*sliceInformer{
				{namespace: namespace, serviceName: "web"}: {
					indexer:   indexer,
					hasSynced: func() bool { return tc.synced },
					started:   time.Now().Add(-tc.startedAgo),
					stop:      func() {},
				},
			}
			w := &endpointWatcher{
				node:      node,
				syncGrace: testSyncGrace,
				forwards:  []Forward{web},
				slices:    informers,
			}

			resolved, unsatisfied, pending := w.snapshot()
			if len(resolved) != tc.wantResolved {
				t.Errorf("resolved = %+v, want %d entries", resolved, tc.wantResolved)
			}
			if !slices.Equal(unsatisfied, tc.wantUnsatisfied) {
				t.Errorf("unsatisfied = %+v, want %+v", unsatisfied, tc.wantUnsatisfied)
			}
			if !slices.Equal(pending, tc.wantPending) {
				t.Errorf("pending = %v, want %v", pending, tc.wantPending)
			}
		})
	}
}
