package link

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// defaultStaleness is the handshake age threshold when the peer has no
// PersistentKeepalive cadence to derive a tighter bound from.
const defaultStaleness = 180 * time.Second

// minStaleness floors the handshake age above the ~120s rekey interval. WireGuard refreshes the
// timestamp only on rekey, so a lower floor would flap a live tunnel unready between rekeys.
const minStaleness = 150 * time.Second

// readiness reports tunnel health over HTTP. Any replica carrying a gating fault reports not
// ready; the leader also needs a handshake newer than the staleness window. Concurrency-safe.
type readiness struct {
	iface     string
	keepalive int
	now       func() time.Time
	// wgShow returns the output of `wg show <iface> latest-handshakes`.
	wgShow func(ctx context.Context, iface string) (string, error)
	leader atomic.Bool

	// nodeFault is the startup pre-check's finding, empty when none. It holds for the life of the
	// process and outranks fault.
	nodeFault atomic.Pointer[string]

	// fault is what the reload loop's last apply found, empty when none. Only a holder runs that
	// loop, so it is cleared on step-down; a replica is ready only while the combined fault is empty.
	fault atomic.Pointer[string]
}

// newReadiness builds a readiness checker, with now and wgShow injected so the decision is
// testable without a real interface or clock. It starts as a standby until setLeader activates it.
func newReadiness(iface string, keepalive int, now func() time.Time, wgShow func(ctx context.Context, iface string) (string, error)) *readiness {
	return &readiness{iface: iface, keepalive: keepalive, now: now, wgShow: wgShow}
}

// setLeader records whether this replica currently holds leadership. It is
// called from the leader-election callbacks concurrently with handler reads.
func (r *readiness) setLeader(leader bool) {
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
	if r.keepalive <= 0 {
		return defaultStaleness
	}
	return max(time.Duration(3*r.keepalive)*time.Second, minStaleness)
}

// ready reports whether this replica answers the readiness probe. A gating fault holds it unready
// whether or not it leads, since the election derives liveness from pod readiness.
func (r *readiness) ready(ctx context.Context) bool {
	if r.gatingFault() != "" {
		return false
	}
	if !r.isLeader() {
		return true
	}
	out, err := r.wgShow(ctx, r.iface)
	if err != nil {
		return false
	}
	ts, ok := freshestHandshake(out)
	if !ok {
		return false
	}
	return r.now().Sub(ts) < r.staleness()
}

func (r *readiness) handler(w http.ResponseWriter, req *http.Request) {
	if r.ready(req.Context()) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return
	}
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(r.notReadyMessage()))
}

// notReadyMessage is the body of a not-ready reply. A fault outranks the handshake, matching the
// order ready checks them in, so the probe never blames a handshake for a node that cannot forward.
func (r *readiness) notReadyMessage() string {
	if fault := r.gatingFault(); fault != "" {
		return "node fault: " + fault
	}
	return "no recent handshake"
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
