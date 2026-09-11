package link

import (
	"context"
	"fmt"
	"iter"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// endpointWatcherKey identifies one watched (namespace, serviceName) pair, shared
// across every forward that targets the same backend Service.
type endpointWatcherKey struct {
	namespace   string
	serviceName string
}

// sliceInformer is one running EndpointSlice informer. started dates the initial list,
// so a store that is still filling reads differently from one that is genuinely empty.
type sliceInformer struct {
	indexer   cache.Indexer
	hasSynced cache.InformerSynced
	started   time.Time
	stop      context.CancelFunc
}

// pendingSync reports whether the initial list is still running and within grace, the
// window in which the forwards this informer backs count as pending, not unsatisfied.
func (i *sliceInformer) pendingSync(now time.Time, grace time.Duration) bool {
	return !i.hasSynced() && now.Sub(i.started) < grace
}

// unsatisfiedForward is one tracked forward with no ready local endpoint, paired with
// why, so a fault message can name the forward the spec names and what is wrong.
type unsatisfiedForward struct {
	name   string
	reason string
}

// Reasons carried by unsatisfiedForward, rendered into the holder's fault message.
const (
	reasonWatchUnsynced = "endpoint watch not synced"
	reasonNoLocalPod    = "no ready backend pod on this node"
	reasonPortNotFound  = "service port not found on the ready local endpoints"
)

// endpointSyncGrace is how long a fresh EndpointSlice informer may go unsynced before its
// forwards report unsatisfied. Shorter would flap Ready on every spec.forwards edit.
const endpointSyncGrace = 30 * time.Second

// endpointResync backstops the EndpointSlice and pod informers' event delivery.
const endpointResync = 5 * time.Minute

// endpointWatcher is Local mode's endpoint resolution and per-node score inputs, derived
// live from informer caches. No method waits on the apiserver under the lock.
type endpointWatcher struct {
	node   string
	cs     kubernetes.Interface
	resync time.Duration
	log    *zap.SugaredLogger

	// informerCtx is the watcher's own lifetime, not the caller's: a forward set
	// installed from a short-lived context keeps its informers running after it ends.
	informerCtx context.Context

	podIndexer cache.Indexer

	// syncGrace is how long a forward whose informer has not synced yet is treated
	// as pending rather than unsatisfied.
	syncGrace time.Duration

	mu       sync.Mutex
	forwards []Forward
	slices   map[endpointWatcherKey]*sliceInformer
	// subscribers each receive a coalescing, non-blocking signal, so a burst of
	// informer events collapses to one wakeup per subscriber.
	subscribers map[chan struct{}]struct{}
}

// newEndpointWatcher blocks until the pod informer's initial list syncs or ctx is done.
// ctx is the watcher's lifetime; a later dropped watch is logged, not returned.
func newEndpointWatcher(ctx context.Context, cs kubernetes.Interface, node string, forwards []Forward, podNamespace string, podSelector labels.Selector, resync time.Duration, log *zap.SugaredLogger) (*endpointWatcher, error) {
	w := &endpointWatcher{
		node:        node,
		cs:          cs,
		resync:      resync,
		log:         log,
		informerCtx: ctx,
		syncGrace:   endpointSyncGrace,
		slices:      make(map[endpointWatcherKey]*sliceInformer),
	}

	podFactory := informers.NewSharedInformerFactoryWithOptions(cs, resync,
		informers.WithNamespace(podNamespace),
		informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.LabelSelector = podSelector.String()
		}),
	)
	podInf := podFactory.Core().V1().Pods().Informer()
	w.watchErrors(podInf, "namespace", podNamespace)
	w.notifyOnChange(podInf)
	w.podIndexer = podInf.GetIndexer()
	podFactory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), podInf.HasSynced) {
		return nil, fmt.Errorf("wait for pod informer cache sync: %w", ctx.Err())
	}

	w.setForwards(forwards)
	return w, nil
}

// setForwards re-keys the informers and signals the change, never waiting on the
// apiserver. It is the only writer of w.forwards and w.slices, updating both at once.
func (w *endpointWatcher) setForwards(forwards []Forward) {
	w.mu.Lock()
	if slices.Equal(w.forwards, forwards) {
		w.mu.Unlock()
		return
	}

	want := make(map[endpointWatcherKey]bool, len(forwards))
	for _, f := range forwards {
		want[endpointWatcherKey{namespace: f.Namespace, serviceName: f.ServiceName}] = true
	}

	type startedInformer struct {
		inf *sliceInformer
		ctx context.Context
	}
	var started []startedInformer
	for key := range want {
		if _, running := w.slices[key]; running {
			continue
		}
		inf, ctx := w.startSliceInformer(key)
		w.slices[key] = inf
		started = append(started, startedInformer{inf: inf, ctx: ctx})
	}
	for key, inf := range w.slices {
		if want[key] {
			continue
		}
		inf.stop()
		delete(w.slices, key)
	}
	w.forwards = slices.Clone(forwards)
	w.mu.Unlock()

	w.signalChange()

	// An informer whose initial list is empty delivers no add event, so nothing else
	// would wake the reload loop for the apply that first includes its forward.
	for _, s := range started {
		go func() {
			ctx, cancel := context.WithTimeout(s.ctx, w.syncGrace)
			defer cancel()
			if cache.WaitForCacheSync(ctx.Done(), s.inf.hasSynced) {
				w.signalChange()
			}
		}()
	}
}

// startSliceInformer starts key's informer under a context of its own, so setForwards can
// stop it alone, and returns both. The caller holds w.mu.
func (w *endpointWatcher) startSliceInformer(key endpointWatcherKey) (*sliceInformer, context.Context) {
	ctx, stop := context.WithCancel(w.informerCtx)
	selector := labels.Set{discoveryv1.LabelServiceName: key.serviceName}.String()
	factory := informers.NewSharedInformerFactoryWithOptions(w.cs, w.resync,
		informers.WithNamespace(key.namespace),
		informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.LabelSelector = selector
		}),
	)
	inf := factory.Discovery().V1().EndpointSlices().Informer()
	w.watchErrors(inf, "namespace", key.namespace, "serviceName", key.serviceName)
	w.notifyOnChange(inf)
	factory.Start(ctx.Done())
	return &sliceInformer{
		indexer:   inf.GetIndexer(),
		hasSynced: inf.HasSynced,
		started:   time.Now(),
		stop:      stop,
	}, ctx
}

// watchErrors logs a dropped watch at WARN with the given structured context; the
// informer's own backoff handles the reconnect.
func (w *endpointWatcher) watchErrors(inf cache.SharedIndexInformer, kv ...any) {
	if err := inf.SetWatchErrorHandlerWithContext(func(_ context.Context, _ *cache.Reflector, err error) {
		w.log.Warnw("endpoint watch dropped", append([]any{"error", err}, kv...)...)
	}); err != nil {
		w.log.Warnw("register watch error handler", "error", err)
	}
}

// notifyOnChange wires inf's add/update/delete events into the coalescing change
// signal.
func (w *endpointWatcher) notifyOnChange(inf cache.SharedIndexInformer) {
	_, err := inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { w.signalChange() },
		UpdateFunc: func(any, any) { w.signalChange() },
		DeleteFunc: func(any) { w.signalChange() },
	})
	if err != nil {
		w.log.Warnw("register informer event handler", "error", err)
	}
}

func (w *endpointWatcher) signalChange() {
	w.mu.Lock()
	defer w.mu.Unlock()
	for ch := range w.subscribers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// subscribe returns a per-consumer change channel and the func that unregisters it; a
// shared channel would let one consumer swallow another's wakeup. Unregister is safe twice.
func (w *endpointWatcher) subscribe() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	w.mu.Lock()
	if w.subscribers == nil {
		w.subscribers = make(map[chan struct{}]struct{})
	}
	w.subscribers[ch] = struct{}{}
	w.mu.Unlock()

	return ch, func() {
		w.mu.Lock()
		delete(w.subscribers, ch)
		w.mu.Unlock()
	}
}

// snapshot resolves every tracked forward against the watcher's own node, in forward
// order. Within syncGrace an unsynced forward is pending, so no fault is published.
func (w *endpointWatcher) snapshot() (resolved []ResolvedForward, unsatisfied []unsatisfiedForward, pending []string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	now := time.Now()
	for _, f := range w.forwards {
		inf := w.slices[endpointWatcherKey{namespace: f.Namespace, serviceName: f.ServiceName}]
		if inf.pendingSync(now, w.syncGrace) {
			pending = append(pending, f.Name)
			continue
		}
		if !inf.hasSynced() {
			unsatisfied = append(unsatisfied, unsatisfiedForward{name: f.Name, reason: reasonWatchUnsynced})
			continue
		}
		addr, port, ok := selectEndpoint(inf.indexer, w.node, f.ServicePortName, w.log)
		if !ok {
			reason := reasonNoLocalPod
			if hasReadyEndpoint(inf.indexer, w.node) {
				reason = reasonPortNotFound
			}
			unsatisfied = append(unsatisfied, unsatisfiedForward{name: f.Name, reason: reason})
			continue
		}
		resolved = append(resolved, ResolvedForward{
			Name:       f.Name,
			PublicPort: f.PublicPort,
			Protocol:   f.Protocol,
			Target:     addr,
			TargetPort: port,
		})
	}
	return resolved, unsatisfied, pending
}

// electionView is one reading of the election's inputs, taken under the watcher's lock.
// scores covers every live node and the watcher's own node.
type electionView struct {
	forwardCount int
	pending      []string
	live         map[string]bool
	scores       map[string]int
}

// evaluate reads the election's inputs once. Callers must not decide while pending is
// non-empty: an unsynced informer scores 0 and would look like a leader that lost.
func (w *endpointWatcher) evaluate() electionView {
	w.mu.Lock()
	defer w.mu.Unlock()

	v := electionView{
		forwardCount: len(w.forwards),
		live:         w.liveNodes(),
		scores:       make(map[string]int),
	}
	now := time.Now()
	for _, f := range w.forwards {
		inf := w.slices[endpointWatcherKey{namespace: f.Namespace, serviceName: f.ServiceName}]
		if inf.pendingSync(now, w.syncGrace) {
			v.pending = append(v.pending, f.Name)
		}
	}
	for node := range v.live {
		v.scores[node] = w.scoreLocked(node)
	}
	if _, ok := v.scores[w.node]; !ok {
		v.scores[w.node] = w.scoreLocked(w.node)
	}
	return v
}

// podNode is the node carrying the link pod named name, and whether the informer knows
// one there. It turns a Lease holder identity into the node its data plane lives on.
func (w *endpointWatcher) podNode(name string) (node string, ok bool) {
	for _, obj := range w.podIndexer.List() {
		pod, isPod := obj.(*corev1.Pod)
		if !isPod || pod.Name != name {
			continue
		}
		return pod.Spec.NodeName, pod.Spec.NodeName != ""
	}
	return "", false
}

// scoreLocked counts the tracked forwards node could serve, through snapshot's own
// predicate so a full score means an apply that satisfies every forward. Holds w.mu.
func (w *endpointWatcher) scoreLocked(node string) int {
	n := 0
	for _, f := range w.forwards {
		inf := w.slices[endpointWatcherKey{namespace: f.Namespace, serviceName: f.ServiceName}]
		if _, _, ok := selectEndpoint(inf.indexer, node, f.ServicePortName, w.log); ok {
			n++
		}
	}
	return n
}

// liveNodes returns the nodes carrying a Ready link pod. It reads only the pod indexer,
// which locks internally, so it needs no lock of its own.
func (w *endpointWatcher) liveNodes() map[string]bool {
	live := make(map[string]bool)
	for _, obj := range w.podIndexer.List() {
		pod, ok := obj.(*corev1.Pod)
		if !ok || pod.Spec.NodeName == "" {
			continue
		}
		if podReady(pod) {
			live[pod.Spec.NodeName] = true
		}
	}
	return live
}

// podReady reports whether pod's PodReady condition is True.
func podReady(pod *corev1.Pod) bool {
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// readyIPv4Endpoints iterates the endpoints on node eligible to serve Local traffic, with
// their slice. IPv4 only, because the DNAT is; a nil Ready counts as ready.
func readyIPv4Endpoints(indexer cache.Indexer, node string) iter.Seq2[*discoveryv1.EndpointSlice, discoveryv1.Endpoint] {
	return func(yield func(*discoveryv1.EndpointSlice, discoveryv1.Endpoint) bool) {
		for _, obj := range indexer.List() {
			slice, isSlice := obj.(*discoveryv1.EndpointSlice)
			if !isSlice || slice.AddressType != discoveryv1.AddressTypeIPv4 {
				continue
			}
			for _, ep := range slice.Endpoints {
				if ep.NodeName == nil || *ep.NodeName != node {
					continue
				}
				if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
					continue
				}
				if !yield(slice, ep) {
					return
				}
			}
		}
	}
}

// hasReadyEndpoint reports whether node carries any ready IPv4 endpoint, whatever ports
// its slice publishes. It separates a missing backend pod from a missing port.
func hasReadyEndpoint(indexer cache.Indexer, node string) bool {
	for range readyIPv4Endpoints(indexer, node) {
		return true
	}
	return false
}

// selectEndpoint takes the lowest (address, port) among node's eligible endpoints whose
// own slice resolves portName, so an unchanged endpoint set re-renders byte-identically.
func selectEndpoint(indexer cache.Indexer, node, portName string, log *zap.SugaredLogger) (addr string, port int, ok bool) {
	type candidate struct {
		addr string
		port int
	}
	var candidates []candidate

	warned := false
	for slice, ep := range readyIPv4Endpoints(indexer, node) {
		p, portOK := findPort(slice.Ports, portName)
		if !portOK {
			continue
		}
		for _, a := range ep.Addresses {
			if net.ParseIP(a) == nil {
				if !warned {
					warned = true
					log.Warnw("skipping endpoint address that is not an IP", "slice", slice.Namespace+"/"+slice.Name, "address", a)
				}
				continue
			}
			candidates = append(candidates, candidate{addr: a, port: p})
		}
	}

	if len(candidates) == 0 {
		return "", 0, false
	}
	slices.SortFunc(candidates, func(a, b candidate) int {
		if c := strings.Compare(a.addr, b.addr); c != 0 {
			return c
		}
		return a.port - b.port
	})
	return candidates[0].addr, candidates[0].port, true
}

// findPort returns the slice port entry whose Name matches name (an empty name
// matches a nil or empty Name) and whether it carries a resolved Port.
func findPort(ports []discoveryv1.EndpointPort, name string) (int, bool) {
	for _, p := range ports {
		pname := ""
		if p.Name != nil {
			pname = *p.Name
		}
		if pname != name {
			continue
		}
		if p.Port == nil {
			return 0, false
		}
		return int(*p.Port), true
	}
	return 0, false
}
