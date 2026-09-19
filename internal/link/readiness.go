package link

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// defaultStaleness is the handshake age threshold when the peer has no
// PersistentKeepalive cadence to derive a tighter bound from.
const defaultStaleness = 180 * time.Second

// minStaleness floors the handshake age above the ~120s rekey interval. WireGuard refreshes the
// timestamp only on rekey, so a lower floor would flap a live tunnel unready between rekeys.
const minStaleness = 150 * time.Second

// bodyNoHandshake and bodyNoPeers are the /healthz failure bodies for a fault-free holder whose
// tunnel has no fresh handshake, and for a Cluster holder whose config carries no peer.
const (
	bodyNoHandshake = "no recent handshake"
	bodyNoPeers     = "no peers configured"
)

// readiness reports tunnel health safely across concurrent election and apply paths.
type readiness struct {
	// local is set in Local mode, where each slot has its own interface. Cluster mode carries no
	// slots and gates on clusterInterface instead.
	local bool
	// gatewayID derives each slot's interface name from its SlotResult.Slot. Unused in Cluster
	// mode, whose passes carry no slot.
	gatewayID int
	keepalive atomic.Int64
	now       func() time.Time
	// wgShow returns the output of `wg show <iface> latest-handshakes`.
	wgShow func(ctx context.Context, iface string) (string, error)
	log    *zap.SugaredLogger
	leader atomic.Bool
	// applied is set once an apply pass has completed, to whether that pass applied. It is false
	// before the first pass, so a holder answers neither route until it has programmed the node.
	applied atomic.Bool
	// peers is the number of peers the last pass's config carried. A Local holder with none is a
	// pending fleet, ready on its empty pass; a Cluster holder with none has nothing to serve.
	peers atomic.Int64

	// nodeFault is the startup pre-check's finding, empty when none. It holds for the life of the
	// process and outranks fault.
	nodeFault atomic.Pointer[string]

	// fault is what the reload loop's last apply found, empty when none. Only a holder runs that
	// loop, so it is cleared on step-down; a replica is ready only while the combined fault is empty.
	fault atomic.Pointer[string]

	mu    sync.Mutex
	slots []SlotResult
}

// newReadiness builds a readiness checker, with now and wgShow injected so the decision is
// testable without a real interface or clock. It starts as a standby until setLeader activates it.
func newReadiness(local bool, gatewayID int, now func() time.Time, wgShow func(ctx context.Context, iface string) (string, error), log *zap.SugaredLogger) *readiness {
	return &readiness{local: local, gatewayID: gatewayID, now: now, wgShow: wgShow, log: log}
}

// setLeader records this replica's leadership, clearing the last pass first so a new holder is
// unready until its own completes. Called from the election callbacks concurrently with reads.
func (r *readiness) setLeader(leader bool) {
	r.setPass(nil, 0, 0, false)
	r.leader.Store(leader)
}

// isLeader reports whether this replica currently holds leadership.
func (r *readiness) isLeader() bool {
	return r.leader.Load()
}

// setFault records what the reload loop's last apply found, empty to clear it. Called from the
// apply and step-down paths concurrently with handler reads.
func (r *readiness) setFault(reason string) {
	r.fault.Store(&reason)
}

// setNodeFault records the startup pre-check's finding, empty when none.
func (r *readiness) setNodeFault(reason string) {
	r.nodeFault.Store(&reason)
}

// setPass records completed passes for readiness handlers without config-file reads.
func (r *readiness) setPass(slots []SlotResult, peers, keepalive int, applied bool) {
	r.mu.Lock()
	r.slots = slices.Clone(slots)
	r.mu.Unlock()
	r.peers.Store(int64(peers))
	r.keepalive.Store(int64(keepalive))
	r.applied.Store(applied)
}

func (r *readiness) snapshotSlots() []SlotResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.slots)
}

// gatingFault reports the fault holding this replica unready, empty when none. The pre-check
// outranks the reload loop, so clearing the loop's fault on step-down cannot mask a failed check.
func (r *readiness) gatingFault() string {
	if f := loadFault(&r.nodeFault); f != "" {
		return f
	}
	return loadFault(&r.fault)
}

// loadFault reads a fault slot, treating never-set as empty.
func loadFault(p *atomic.Pointer[string]) string {
	if v := p.Load(); v != nil {
		return *v
	}
	return ""
}

// staleness is three keepalive intervals floored at minStaleness, or
// defaultStaleness when keepalive is disabled.
func (r *readiness) staleness() time.Duration {
	if r.keepalive.Load() <= 0 {
		return defaultStaleness
	}
	return max(time.Duration(3*r.keepalive.Load())*time.Second, minStaleness)
}

// kubeletStatus checks faults, standby state, and applied handshakes before mode-specific peer
// checks. Local holders with no peer pass; Cluster holders require a peer and fresh handshake.
func (r *readiness) kubeletStatus(ctx context.Context) (bool, string) {
	if fault := r.gatingFault(); fault != "" {
		return false, "node fault: " + fault
	}
	if !r.isLeader() {
		return true, ""
	}
	return r.tunnelStatus(ctx)
}

// tunnelStatus reports leader tunnel state for the Lease lock, independent of gating faults.
// It mirrors kubeletStatus's leader path so operator readiness matches the probe.
func (r *readiness) tunnelStatus(ctx context.Context) (bool, string) {
	if !r.applied.Load() {
		return false, bodyNoHandshake
	}
	if r.local {
		if r.peers.Load() == 0 || r.anyFreshSlot(ctx) {
			return true, ""
		}
		return false, bodyNoHandshake
	}
	if r.peers.Load() == 0 {
		return false, bodyNoPeers
	}
	if r.freshClusterInterface(ctx) {
		return true, ""
	}
	return false, bodyNoHandshake
}

// freshClusterInterface reports whether the single Cluster interface has a handshake inside the
// staleness window.
func (r *readiness) freshClusterInterface(ctx context.Context) bool {
	out, err := r.wgShow(ctx, clusterInterface)
	if err != nil {
		r.log.Warnw("read cluster interface handshakes", "interface", clusterInterface,
			"command", "wg show "+clusterInterface+" latest-handshakes", "error", err)
		return false
	}
	ts, ok := freshestHandshake(out)
	return ok && r.now().Sub(ts) < r.staleness()
}

// anyFreshSlot reports whether one applied slot has a handshake inside the staleness window, so
// one member's stale tunnel never holds the holder, and its fleet's probes, down.
func (r *readiness) anyFreshSlot(ctx context.Context) bool {
	for _, s := range r.snapshotSlots() {
		if !s.Applied {
			continue
		}
		iface := NewSlotIdentity(r.gatewayID, s.Slot).Interface
		out, err := r.wgShow(ctx, iface)
		if err != nil {
			r.log.Warnw("read slot interface handshakes", "slot", s.Slot, "interface", iface,
				"command", "wg show "+iface+" latest-handshakes", "error", err)
			continue
		}
		ts, ok := freshestHandshake(out)
		if !ok {
			continue
		}
		if r.now().Sub(ts) < r.staleness() {
			return true
		}
	}
	return false
}

func (r *readiness) handler(w http.ResponseWriter, req *http.Request) {
	ready, body := r.kubeletStatus(req.Context())
	if ready {
		w.WriteHeader(http.StatusOK)
		r.writeReadinessBody(w, "ok")
		return
	}
	w.WriteHeader(http.StatusServiceUnavailable)
	r.writeReadinessBody(w, body)
}

func (r *readiness) writeReadinessBody(w http.ResponseWriter, body string) {
	if _, err := w.Write([]byte(body)); err != nil {
		r.log.Warnw("write readiness response", "error", err)
	}
}

// freshestHandshake returns the most recent non-zero handshake in `wg show latest-handshakes`
// output. ok is false when no peer has completed a handshake.
func freshestHandshake(wgShowOutput string) (time.Time, bool) {
	var newest int64
	for line := range strings.SplitSeq(wgShowOutput, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		epoch, err := strconv.ParseInt(fields[len(fields)-1], 10, 64)
		if err != nil || epoch <= 0 {
			continue
		}
		if epoch > newest {
			newest = epoch
		}
	}
	if newest == 0 {
		return time.Time{}, false
	}
	return time.Unix(newest, 0), true
}
