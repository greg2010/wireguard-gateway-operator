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

// minStaleness floors the handshake age threshold above the ~120s rekey interval.
// WireGuard refreshes the timestamp only on rekey, so a lower floor would flap an
// otherwise live tunnel unready between rekeys.
const minStaleness = 150 * time.Second

// readiness reports tunnel health over HTTP, gated on leadership. A non-leader always
// reports ready without probing wg0; the leader reports ready only on a peer handshake
// newer than the staleness window. The leader flag is concurrency-safe.
type readiness struct {
	keepalive int
	now       func() time.Time
	// wgShow returns the output of `wg show wg0 latest-handshakes`.
	wgShow func(ctx context.Context) (string, error)
	leader atomic.Bool
}

// newReadiness builds a readiness checker. now and wgShow are injected so the
// readiness decision is testable without a real interface or clock. It starts as
// a standby (not leader) until setLeader marks it active.
func newReadiness(keepalive int, now func() time.Time, wgShow func(ctx context.Context) (string, error)) *readiness {
	return &readiness{keepalive: keepalive, now: now, wgShow: wgShow}
}

// setLeader records whether this replica currently holds leadership. It is
// called from the leader-election callbacks concurrently with handler reads.
func (r *readiness) setLeader(leader bool) {
	r.leader.Store(leader)
}

// staleness is three keepalive intervals floored at minStaleness, or
// defaultStaleness when keepalive is disabled.
func (r *readiness) staleness() time.Duration {
	if r.keepalive <= 0 {
		return defaultStaleness
	}
	return max(time.Duration(3*r.keepalive)*time.Second, minStaleness)
}

func (r *readiness) ready(ctx context.Context) bool {
	if !r.leader.Load() {
		return true
	}
	out, err := r.wgShow(ctx)
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
	_, _ = w.Write([]byte("no recent handshake"))
}

// freshestHandshake parses `wg show wg0 latest-handshakes` lines
// ("<pubkey>\t<unix-epoch>") and returns the most recent non-zero handshake time. ok
// is false when no peer has completed a handshake (every epoch 0).
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
