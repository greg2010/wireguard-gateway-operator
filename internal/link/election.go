package link

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

const (
	leaseDuration = 15 * time.Second
	renewDeadline = 10 * time.Second
	retryPeriod   = 2 * time.Second
)

// electionTiming carries the elector's own durations plus the entry and handoff loops'
// poll interval and hold, so a whole leadership cycle can be driven at test speed.
type electionTiming struct {
	retry time.Duration
	hold  time.Duration
	lease time.Duration
	renew time.Duration
	// fence bounds a single teardown, pending or step-down.
	fence time.Duration
}

var defaultElectionTiming = electionTiming{
	retry: retryPeriod,
	hold:  handoffHold,
	lease: leaseDuration,
	renew: renewDeadline,
	fence: fenceTimeout,
}

// handoffHold is how long a fully eligible peer must be observed continuously before a
// less-fit leader hands off, and how long a less-fit candidate waits before entering.
const handoffHold = 2 * leaseDuration

// fenceTimeout bounds one teardown: it must fit inside leaseDuration minus retryPeriod (10s of
// 13s) and, with the release write's renewDeadline, inside terminationGracePeriodSeconds (30s).
const fenceTimeout = 10 * time.Second

// ShutdownBudget is what a voluntary release needs at worst: the teardown, then the release
// write client-go bounds by its renew deadline. It must stay below the link pod's
// terminationGracePeriodSeconds, or the kubelet kills the process mid-teardown.
const ShutdownBudget = fenceTimeout + renewDeadline

// faultClearTimeout bounds the Lease write that clears this replica's fault after a step
// down. Outside the fence's budget: it runs even when the teardown used all of its time.
const faultClearTimeout = 5 * time.Second

// electionDeps is what a leadership cycle needs beyond its contexts: identity, the Lease
// lock, readiness and fault slots, key material, the apply and teardown steps, timing.
type electionDeps struct {
	cfg  Config
	lock resourcelock.Interface
	rd   *readiness
	ew   *endpointWatcher
	// identity is the startup config's identity block, nil in Cluster mode; a reload
	// that changes it is refused.
	identity   *Identity
	cs         kubernetes.Interface
	privKey    string
	peerPubKey string
	reconcile  applyFunc
	timing     electionTiming
	// fence removes this replica's data plane. Required: Run populates it with the
	// Teardown closure for the loaded RuntimeConfig.
	fence func(ctx context.Context) error
	log   *zap.SugaredLogger

	// inheritedDataPlane records an interface an earlier process left on the node.
	// The first cycle starts with a pending fence so the entry gate tears it down.
	inheritedDataPlane bool

	// fenceMu serialises every fence with the start of a leadership cycle: client-go
	// dispatches OnNewLeader unjoined, so a fence can outlive the cycle that began it.
	fenceMu sync.Mutex
}

// leadershipCycle is what ending one elector cycle in order needs: the reload loop's stop
// and exit signals, the cancel that releases the Lease, and the fence-once flag.
type leadershipCycle struct {
	// cancelElection cancels the elector's context, which is what makes ReleaseOnCancel
	// free the Lease. A voluntary end calls it only once the fence has finished.
	cancelElection context.CancelFunc
	// pending is the process-wide kept-data-plane flag. A cycle that set it left its data
	// plane to the process's exit fence, so ending the cycle must not tear it down.
	pending *atomic.Bool
	// lock is this cycle's Lease lock: it says whether the acquire write has landed and
	// refuses a new one once the cycle is leaving.
	lock *acquisitionLock
	// otherHolder records that the elector observed the Lease in another replica's hands,
	// which sends a candidate that is not fully eligible back to the entry gate.
	otherHolder atomic.Bool
	// registered is closed once lead has stored the reload loop's signals, which the
	// acquire write can precede.
	registered chan struct{}

	mu         sync.Mutex
	ended      bool
	stopReload context.CancelFunc
	reloadDone chan struct{}

	// fenced is guarded by electionDeps.fenceMu, so a second path blocks until the fence
	// it would repeat has finished rather than racing past it.
	fenced bool
}

// lead registers the reload loop's stop and exit signals. A loop that starts after the
// cycle has already been ended is stopped at once, so nothing applies behind the fence.
func (c *leadershipCycle) lead(stop context.CancelFunc, done chan struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopReload, c.reloadDone = stop, done
	close(c.registered)
	if c.ended {
		stop()
	}
}

// stopped reports whether the cycle was ended deliberately, which is what separates a
// reload loop that was asked to stop from one that returned on its own.
func (c *leadershipCycle) stopped() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ended
}

// errCycleLeaving refuses an acquisition write for a cycle that is leaving the election:
// taking the Lease behind the fence would leave it held by a replica with no data plane.
var errCycleLeaving = errors.New("leadership cycle is leaving the election")

// acquisitionLock wraps the Lease lock to record whether this cycle acquired it and to refuse
// a new acquisition once the cycle leaves.
type acquisitionLock struct {
	resourcelock.Interface
	acquired chan struct{}
	once     sync.Once

	// mu guards leaving and orders inFlight: no write is counted once leaving is set, so
	// leave can wait out the writes that started before it.
	mu       sync.Mutex
	leaving  bool
	inFlight sync.WaitGroup
}

func newAcquisitionLock(lock resourcelock.Interface) *acquisitionLock {
	return &acquisitionLock{Interface: lock, acquired: make(chan struct{})}
}

func (l *acquisitionLock) Create(ctx context.Context, ler resourcelock.LeaderElectionRecord) error {
	done, err := l.begin(ler)
	if err != nil {
		return err
	}
	defer done()
	err = l.Interface.Create(ctx, ler)
	l.observe(err, ler)
	return err
}

func (l *acquisitionLock) Update(ctx context.Context, ler resourcelock.LeaderElectionRecord) error {
	done, err := l.begin(ler)
	if err != nil {
		return err
	}
	defer done()
	err = l.Interface.Update(ctx, ler)
	l.observe(err, ler)
	return err
}

// begin admits one write, counting it while it is in flight when it would acquire the Lease
// rather than renew or release one this cycle already holds.
func (l *acquisitionLock) begin(ler resourcelock.LeaderElectionRecord) (done func(), err error) {
	if l.isAcquired() || ler.HolderIdentity != l.Identity() {
		return func() {}, nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.leaving {
		return nil, errCycleLeaving
	}
	l.inFlight.Add(1)
	return l.inFlight.Done, nil
}

// leave refuses every further acquisition write and waits up to bound for the ones already
// in flight, reporting whether they finished.
func (l *acquisitionLock) leave(bound time.Duration) bool {
	l.mu.Lock()
	l.leaving = true
	l.mu.Unlock()

	waited := make(chan struct{})
	go func() {
		defer close(waited)
		l.inFlight.Wait()
	}()
	timer := time.NewTimer(bound)
	defer timer.Stop()
	select {
	case <-waited:
		return true
	case <-timer.C:
		return false
	}
}

// isAcquired reports whether a write has already recorded this identity as the holder.
func (l *acquisitionLock) isAcquired() bool {
	select {
	case <-l.acquired:
		return true
	default:
		return false
	}
}

// observe closes acquired on the first write that successfully recorded this
// identity as the holder.
func (l *acquisitionLock) observe(err error, ler resourcelock.LeaderElectionRecord) {
	if err != nil || ler.HolderIdentity != l.Identity() {
		return
	}
	l.once.Do(func() { close(l.acquired) })
}

// runElection programs the data plane only while this replica holds the Lease, keeping it on an
// unexplained loss and tearing it down before any voluntary release. outerCtx outlives gctx.
func (d *electionDeps) runElection(outerCtx, gctx context.Context) error {
	var pendingFence atomic.Bool
	pendingFence.Store(d.inheritedDataPlane)
	defer d.fenceKept(outerCtx, &pendingFence, "reason", "process exit")
	for gctx.Err() == nil {
		if d.ew != nil {
			waitForEntryEligible(gctx, d.cfg.NodeName, d.ew, d.timing, d.leaseAvailable, func(ctx context.Context) {
				d.fencePendingOnPoll(ctx, &pendingFence)
			}, d.log)
			if gctx.Err() != nil {
				break
			}
		}

		done := make(chan struct{})
		// The elector's context is not gctx's child: cancelling it is what makes ReleaseOnCancel
		// release the Lease, and every voluntary end must fence first, which endCycle does.
		electionCtx, cancelElection := context.WithCancel(context.WithoutCancel(gctx))
		lock := newAcquisitionLock(d.lock)
		cycle := &leadershipCycle{
			cancelElection: cancelElection,
			pending:        &pendingFence,
			lock:           lock,
			registered:     make(chan struct{}),
		}
		stopShutdownWatch := context.AfterFunc(gctx, func() {
			d.endCycle(outerCtx, cycle, "reason", "shutdown")
		})
		if d.ew != nil {
			go d.watchEntryEligibility(electionCtx, cycle, func() {
				d.endCycle(outerCtx, cycle, "reason", "entry conditions lapsed")
			})
		}
		var cycleErr error
		elector, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
			Lock:            lock,
			ReleaseOnCancel: true,
			LeaseDuration:   d.timing.lease,
			RenewDeadline:   d.timing.renew,
			RetryPeriod:     d.timing.retry,
			Callbacks: leaderelection.LeaderCallbacks{
				OnStartedLeading: func(leaderCtx context.Context) {
					defer close(done)
					keptDataPlane := d.claimPendingFence(&pendingFence)
					d.rd.setLeader(true)
					defer d.rd.setLeader(false)
					// The fault describes a cycle that has ended and must not gate
					// readiness for the rest of the process's life.
					defer d.rd.setFault("")

					watchCtx, cancelWatch := context.WithCancel(leaderCtx)
					reloadDone := make(chan struct{})
					cycle.lead(cancelWatch, reloadDone)
					var steppedDown atomic.Bool
					if d.ew != nil {
						endCycle := func() { d.endCycle(outerCtx, cycle, "reason", "handoff") }
						go monitorHandoff(watchCtx, endCycle, d.cfg.NodeName, d.ew, d.timing, &steppedDown, d.log)
					}

					// On watchCtx, not leaderCtx: a hung read on an unreachable apiserver would hold the
					// Lease past the termination grace period while a voluntary end waits for the fence.
					acquiredTerm, acquiredTermKnown := readLeaseTransitions(watchCtx, d.cs, d.cfg.PodNamespace, d.cfg.LeaseName, d.log)

					reloadErr := watchAndReload(watchCtx, d.cfg, d.ew, d.identity, keptDataPlane, d.privKey, d.peerPubKey, d.reconcile, d.log)
					close(reloadDone)
					cancelWatch()
					// A return while leadership continues and nothing asked the loop to stop means
					// nothing keeps the data plane current, and client-go renews the Lease regardless.
					reloadFailed := leaderCtx.Err() == nil && !cycle.stopped()
					if reloadFailed {
						d.log.Errorw("reload loop ended while holding the lease, stepping down", "error", reloadErr)
						cycleErr = fmt.Errorf("watch and reload: %w", reloadErr)
						// Published before the release so the holder guard still passes; the
						// next holder overwrites it on its first apply.
						if err := publishFault(leaderCtx, d.cs, d.cfg.PodNamespace, d.cfg.LeaseName, d.cfg.PodName, FaultApplyFailed, nodeMessage(d.cfg.NodeName, "reload loop ended: "+reloadErr.Error()), d.log); err != nil {
							d.log.Warnw("publish reload loop fault", "error", err)
						}
						// The loop has already exited, so the fence runs before the
						// release here too: this replica leaves the Lease deliberately.
						d.fenceCycle(outerCtx, cycle, "reason", "reload loop ended")
						cancelElection()
					} else if reloadErr != nil {
						d.log.Errorw("watch and reload", "error", reloadErr)
					}

					sigterm := outerCtx.Err() != nil
					// A sibling goroutine's failure ends gctx while the process lives:
					// ReleaseOnCancel will free the Lease, so nothing may stay programmed.
					siblingFailure := gctx.Err() != nil && !sigterm
					forced := siblingFailure || reloadFailed
					var holder string
					var term int32
					var readOK bool
					// One read: two reads of the flag could disagree and split the decision below from
					// the read that fed it. Any deliberate end is a step-down, and has already fenced.
					stepped := steppedDown.Load() || cycle.stopped()
					if !stepped && !sigterm && !forced {
						holder, term, readOK = readLeaseHolderTerm(outerCtx, d.cs, d.cfg.PodNamespace, d.cfg.LeaseName, d.timing.retry, d.log)
					}

					if !teardownDecision(stepped, sigterm, forced, readOK, holder, d.cfg.PodName, term, acquiredTerm, acquiredTermKnown) {
						pendingFence.Store(true)
						return
					}

					d.fenceCycle(outerCtx, cycle, "reason", "leadership ended")
					// A forced end published the fault that explains it; clearing it
					// here would erase the only record.
					if !forced {
						// Separate from the fence's budget: a teardown that ran to its deadline
						// must not leave the Lease describing a fault from a cycle that is over.
						clearCtx, cancelClear := context.WithTimeout(context.WithoutCancel(outerCtx), faultClearTimeout)
						defer cancelClear()
						if err := publishFault(clearCtx, d.cs, d.cfg.PodNamespace, d.cfg.LeaseName, d.cfg.PodName, "", "", d.log); err != nil {
							d.log.Warnw("clear lease fault on step down", "error", err)
						}
					}
				},
				// The fence and fault clear run on the paths that end a cycle;
				// OnStoppedLeading also fires when the Lease was never acquired.
				OnStoppedLeading: func() {},
				OnNewLeader: func(identity string) {
					d.log.Debugw("observed leader", "identity", identity)
					if identity != "" && identity != d.cfg.PodName {
						cycle.otherHolder.Store(true)
					}
					// The acquire phase is where a contending replica learns who
					// holds the Lease, so where a kept data plane gets fenced.
					d.fencePendingOnHolder(electionCtx, &pendingFence, identity)
				},
			},
		})
		if err != nil {
			stopShutdownWatch()
			cancelElection()
			return fmt.Errorf("create leader elector: %w", err)
		}

		elector.Run(electionCtx)

		// Run has returned, so acquired is either closed (the callback was started
		// and closes done) or never will be.
		select {
		case <-lock.acquired:
			<-done
		default:
		}
		stopShutdownWatch()
		cancelElection()
		if cycleErr != nil {
			return cycleErr
		}
	}
	return nil
}

// endCycle releases in order: refuse a new acquisition, stop the reload loop and wait for it to
// exit, fence, then cancel the elector, so the Lease goes free no earlier than the fence. An
// acquisition write that outlives the retry bound and then lands is fenced after its release.
func (d *electionDeps) endCycle(ctx context.Context, c *leadershipCycle, kv ...any) {
	c.mu.Lock()
	c.ended = true
	c.mu.Unlock()

	if !c.lock.leave(d.timing.retry) {
		d.log.Warnw("acquisition write still in flight while leaving the election", kv...)
	}
	if c.lock.isAcquired() {
		// client-go closes acquired inside the acquire write and starts the leadership callback
		// after it, so fencing without the reload loop would tear down a plane being programmed.
		select {
		case <-c.registered:
		case <-time.After(d.timing.fence):
			d.log.Warnw("leadership callback did not register the reload loop within the fence budget", kv...)
		}
		c.mu.Lock()
		stop, reloadDone := c.stopReload, c.reloadDone
		c.mu.Unlock()
		if stop != nil {
			stop()
			<-reloadDone
			d.fenceCycle(ctx, c, kv...)
		}
	}
	c.cancelElection()
}

// fenceCycle tears one cycle's data plane down at most once, skipping a cycle that fail-static
// left to the process's exit fence, which owns that data plane instead.
func (d *electionDeps) fenceCycle(ctx context.Context, c *leadershipCycle, kv ...any) {
	d.fenceMu.Lock()
	defer d.fenceMu.Unlock()
	if c.fenced || c.pending.Load() {
		return
	}
	c.fenced = true
	d.runFence(ctx, "fencing the data plane", kv...)
}

// runFence logs msg, then tears the data plane down within the fence budget on ctx's values
// only, since a teardown on the way out runs cancelled. The caller must hold fenceMu.
func (d *electionDeps) runFence(ctx context.Context, msg string, kv ...any) {
	d.log.Infow(msg, kv...)
	fenceCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), d.timing.fence)
	defer cancel()
	if err := d.fence(fenceCtx); err != nil {
		d.log.Warnw("link fence incomplete", "error", err)
	}
}

// claimPendingFence hands a data plane an earlier cycle kept to the starting cycle and reports
// whether there was one. It blocks on fenceMu so a running teardown finishes first.
func (d *electionDeps) claimPendingFence(pending *atomic.Bool) bool {
	d.fenceMu.Lock()
	defer d.fenceMu.Unlock()
	return pending.Swap(false)
}

// fencePendingOnPoll fences a kept data plane when one Lease read names another replica.
// A failed read is not evidence, so it changes nothing.
func (d *electionDeps) fencePendingOnPoll(ctx context.Context, pending *atomic.Bool) {
	if !pending.Load() {
		return
	}
	holder, _, err := readLeaseHolderTermOnce(ctx, d.cs, d.cfg.PodNamespace, d.cfg.LeaseName)
	if err != nil {
		d.log.Debugw("read lease holder while a fence is pending", "error", err)
		return
	}
	d.fencePendingOnHolder(ctx, pending, holder)
}

// fencePendingOnHolder fences a kept data plane once holder is evidence another replica
// took over: in Local mode, only a holder the pod informer places on another node.
func (d *electionDeps) fencePendingOnHolder(ctx context.Context, pending *atomic.Bool, holder string) {
	if !observedHolderFences(pending.Load(), d.cfg.PodName, holder) {
		return
	}
	if d.ew != nil {
		node, known := d.ew.podNode(holder)
		if !known || node == d.cfg.NodeName {
			d.log.Debugw("holder is not a link pod on another node, keeping the data plane",
				"holder", holder, "node", node, "known", known)
			return
		}
	}
	d.fenceKept(ctx, pending, "holder", holder, "self", d.cfg.PodName)
}

// fenceKept tears down a kept data plane at most once, clearing pending under fenceMu.
func (d *electionDeps) fenceKept(ctx context.Context, pending *atomic.Bool, kv ...any) {
	d.fenceMu.Lock()
	defer d.fenceMu.Unlock()
	if !pending.CompareAndSwap(true, false) {
		return
	}
	d.runFence(ctx, "fencing the data plane kept by an earlier cycle", kv...)
}

// observedHolderFences reports whether an observed holder is evidence enough to fence.
// An empty holder means a free Lease, which is where a fail-static holder sits.
func observedHolderFences(pending bool, self, holder string) bool {
	return pending && holder != "" && holder != self
}

// waitForEntryEligible blocks until this replica may attempt to acquire the Lease: a less-fit
// candidate only once the hold has passed with the Lease free. onTick may block the gate shut.
func waitForEntryEligible(ctx context.Context, node string, ew *endpointWatcher, timing electionTiming, leaseAvailable func(ctx context.Context) bool, onTick func(ctx context.Context), log *zap.SugaredLogger) {
	ticker := time.NewTicker(timing.retry)
	defer ticker.Stop()

	changes, cancelChanges := ew.subscribe()
	defer cancelChanges()

	var noEligiblePeerSince, noHolderSince time.Time
	var loggedPending bool
	for {
		onTick(ctx)
		v := ew.evaluate()
		if decisionDeferred(v.pending, &loggedPending, "entry gate", log) {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			case <-changes:
			}
			continue
		}
		if entryDecision(node, v, noEligiblePeerSince, noHolderSince, time.Now(), timing.hold) {
			return
		}
		if hasFullyEligiblePeer(node, v) {
			noEligiblePeerSince = time.Time{}
			// A fitter node is live, so the Lease cannot admit this replica and is not
			// read; both clocks start again when that node goes.
			noHolderSince = time.Time{}
		} else {
			if noEligiblePeerSince.IsZero() {
				noEligiblePeerSince = time.Now()
			}
			if !leaseAvailable(ctx) {
				noHolderSince = time.Time{}
			} else if noHolderSince.IsZero() {
				noHolderSince = time.Now()
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-changes:
		}
	}
}

// watchEntryEligibility leaves the elector when the view stops satisfying the entry rules this
// candidate contended under. It stops at acquisition, from where monitorHandoff decides.
func (d *electionDeps) watchEntryEligibility(ctx context.Context, c *leadershipCycle, endCycle func()) {
	ticker := time.NewTicker(d.timing.retry)
	defer ticker.Stop()

	changes, cancelChanges := d.ew.subscribe()
	defer cancelChanges()

	var loggedPending bool
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.lock.acquired:
			return
		case <-ticker.C:
		case <-changes:
		}

		v := d.ew.evaluate()
		if decisionDeferred(v.pending, &loggedPending, "acquire gate", d.log) {
			continue
		}
		if entryStillEligible(d.cfg.NodeName, v, c.otherHolder.Load(), time.Now(), d.timing.hold) {
			continue
		}
		d.log.Infow("entry conditions lapsed while contending, leaving the election", "node", d.cfg.NodeName)
		endCycle()
		return
	}
}

// entryStillEligible reports whether a candidate past the entry gate may stay in the acquire
// poll: a less-fit one may not once another replica holds it, since rule 2 needs it free.
func entryStillEligible(node string, v electionView, otherHolder bool, now time.Time, hold time.Duration) bool {
	if v.live[node] && v.scores[node] == v.forwardCount {
		return true
	}
	if otherHolder {
		return false
	}
	elapsed := now.Add(-hold)
	return entryDecision(node, v, elapsed, elapsed, now, hold)
}

func hasFullyEligiblePeer(node string, v electionView) bool {
	for peer := range v.live {
		if peer != node && v.scores[peer] == v.forwardCount {
			return true
		}
	}
	return false
}

// entryDecision is waitForEntryEligible's decision on one view, without the wall clock. The wait
// on a free Lease keeps a less-fit node off one a departing holder has just released.
func entryDecision(node string, v electionView, noEligiblePeerSince, noHolderSince, now time.Time, hold time.Duration) bool {
	if v.live[node] && v.scores[node] == v.forwardCount {
		return true
	}
	if hasFullyEligiblePeer(node, v) {
		return false
	}

	bestNode := node
	bestScore := v.scores[node]
	for peer := range v.live {
		if peer == node {
			continue
		}
		s := v.scores[peer]
		if s > bestScore || (s == bestScore && peer < bestNode) {
			bestScore = s
			bestNode = peer
		}
	}
	if noEligiblePeerSince.IsZero() || noHolderSince.IsZero() || bestNode != node {
		return false
	}
	since := noEligiblePeerSince
	if noHolderSince.After(since) {
		since = noHolderSince
	}
	return now.Sub(since) >= hold
}

// monitorHandoff releases a held Lease per spec 7 through endCycle, which must fence before
// cancelling the elector's context: only that reaches ReleaseOnCancel. endCycle may block.
func monitorHandoff(ctx context.Context, endCycle context.CancelFunc, node string, ew *endpointWatcher, timing electionTiming, steppedDown *atomic.Bool, log *zap.SugaredLogger) {
	ticker := time.NewTicker(timing.retry)
	defer ticker.Stop()

	changes, cancelChanges := ew.subscribe()
	defer cancelChanges()

	var eligiblePeerSince time.Time
	var loggedPending bool
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-changes:
		}

		v := ew.evaluate()
		if decisionDeferred(v.pending, &loggedPending, "handoff monitor", log) {
			continue
		}
		if handoffDecision(node, v, eligiblePeerSince, time.Now(), timing.hold) {
			log.Warnw("election handoff conditions met, releasing lease", "node", node)
			steppedDown.Store(true)
			endCycle()
			return
		}
		if hasFullyEligiblePeer(node, v) {
			if eligiblePeerSince.IsZero() {
				eligiblePeerSince = time.Now()
			}
		} else {
			eligiblePeerSince = time.Time{}
		}
	}
}

// decisionDeferred reports whether a loop must skip this tick because an endpoint watch
// has not synced, logging the first such tick. logged is the caller's own flag.
func decisionDeferred(pending []string, logged *bool, loop string, log *zap.SugaredLogger) bool {
	if len(pending) == 0 {
		*logged = false
		return false
	}
	if !*logged {
		*logged = true
		log.Infow("deferring election decisions while endpoint watches sync", "loop", loop, "forwards", pending)
	}
	return true
}

// handoffDecision is monitorHandoff's decision on one view, split out to test without the
// wall clock. A fully eligible leader never releases.
func handoffDecision(node string, v electionView, eligiblePeerSince, now time.Time, hold time.Duration) bool {
	if v.live[node] && v.scores[node] == v.forwardCount {
		return false
	}

	if v.scores[node] == 0 {
		for peer := range v.live {
			if peer != node && v.scores[peer] > 0 {
				return true
			}
		}
		return false
	}

	if !hasFullyEligiblePeer(node, v) {
		return false
	}
	return !eligiblePeerSince.IsZero() && now.Sub(eligiblePeerSince) >= hold
}

// leaseAvailable reports whether the Lease is absent, free, or held by a replica whose renewal
// lapsed. A failed read is not evidence of a free Lease, so it reads as held.
func (d *electionDeps) leaseAvailable(ctx context.Context) bool {
	lease, err := d.cs.CoordinationV1().Leases(d.cfg.PodNamespace).Get(ctx, d.cfg.LeaseName, metav1.GetOptions{})
	if err != nil {
		// A Lease nobody has created yet is free: the first election of a Gateway is
		// what creates it, and treating absence as held would admit nobody.
		if apierrors.IsNotFound(err) {
			return true
		}
		d.log.Warnw("read lease while waiting to contend", "error", err)
		return false
	}
	return !leaseHeld(lease, time.Now())
}

// leaseHeld reports whether lease names a holder that is still live at now. An empty holder
// is free, and so is a renewal that has lapsed or was never written.
func leaseHeld(lease *coordinationv1.Lease, now time.Time) bool {
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity == "" {
		return false
	}
	if lease.Spec.RenewTime == nil {
		return false
	}
	var duration time.Duration
	if lease.Spec.LeaseDurationSeconds != nil {
		duration = time.Duration(*lease.Spec.LeaseDurationSeconds) * time.Second
	}
	return lease.Spec.RenewTime.Add(duration).After(now)
}

// readLeaseTransitions reads spec.leaseTransitions just after acquiring. known is false
// when the read failed: the term is then unknown, not 0, and must not be compared.
func readLeaseTransitions(ctx context.Context, cs kubernetes.Interface, namespace, name string, log *zap.SugaredLogger) (term int32, known bool) {
	_, term, err := readLeaseHolderTermOnce(ctx, cs, namespace, name)
	if err != nil {
		log.Warnw("read lease transitions on acquire", "error", err)
		return 0, false
	}
	return term, true
}

// readLeaseHolderTerm reads the holder identity and spec.leaseTransitions, retrying up to
// 3 times spaced at delay. ok false is absence of evidence, never evidence to tear down.
func readLeaseHolderTerm(ctx context.Context, cs kubernetes.Interface, namespace, name string, delay time.Duration, log *zap.SugaredLogger) (holder string, term int32, ok bool) {
	const maxAttempts = 3
	var lastErr error
	for attempt := range maxAttempts {
		if attempt > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				log.Warnw("read lease holder/term after leadership end", "error", ctx.Err(), "attempts", attempt)
				return "", 0, false
			case <-timer.C:
			}
		}
		h, t, err := readLeaseHolderTermOnce(ctx, cs, namespace, name)
		if err != nil {
			lastErr = err
			continue
		}
		return h, t, true
	}
	log.Warnw("read lease holder/term after leadership end", "error", lastErr, "attempts", maxAttempts)
	return "", 0, false
}

// readLeaseHolderTermOnce is one read of the holder identity and spec.leaseTransitions.
// An absent holder reads empty and an absent count 0, neither of which is the error.
func readLeaseHolderTermOnce(ctx context.Context, cs kubernetes.Interface, namespace, name string) (holder string, term int32, err error) {
	lease, err := cs.CoordinationV1().Leases(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", 0, fmt.Errorf("get lease %s/%s: %w", namespace, name, err)
	}
	if lease.Spec.HolderIdentity != nil {
		holder = *lease.Spec.HolderIdentity
	}
	if lease.Spec.LeaseTransitions != nil {
		term = *lease.Spec.LeaseTransitions
	}
	return holder, term, nil
}

// teardownDecision reports whether an ended cycle tears the data plane down: always on a
// step-down, SIGTERM or forced end, else only on a read naming a holder with a new term.
func teardownDecision(steppedDown, sigterm, forced, readOK bool, holder, self string, term, acquiredTerm int32, acquiredTermKnown bool) bool {
	if steppedDown || sigterm || forced {
		return true
	}
	return readOK && acquiredTermKnown && holder != self && term > acquiredTerm
}
