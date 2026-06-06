package link

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// defaultStaleness is the handshake age threshold used when the peer has no
// PersistentKeepalive configured and so no fixed handshake cadence to derive a
// tighter bound from.
const defaultStaleness = 180 * time.Second

// minStaleness is a floor on the handshake age threshold. WireGuard refreshes
// the latest-handshake timestamp only on rekey (REKEY_AFTER_TIME, ~120s) or
// on-demand traffic, never on keepalive packets, so between rekeys a healthy
// peer's handshake legitimately ages toward 120s. The floor must exceed that
// rekey interval to avoid flapping unready on an otherwise live tunnel.
const minStaleness = 150 * time.Second

// readiness reports tunnel health over HTTP. It is ready when wg show reports a
// peer handshake newer than a staleness window derived from PersistentKeepalive.
type readiness struct {
	keepalive int
	now       func() time.Time
	// wgShow returns the output of `wg show wg0 latest-handshakes`.
	wgShow func(ctx context.Context) (string, error)
}

// newReadiness builds a readiness checker. now and wgShow are injected so the
// readiness decision is testable without a real interface or clock.
func newReadiness(keepalive int, now func() time.Time, wgShow func(ctx context.Context) (string, error)) *readiness {
	return &readiness{keepalive: keepalive, now: now, wgShow: wgShow}
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

// freshestHandshake parses the output of `wg show wg0 latest-handshakes`, whose
// lines are "<pubkey>\t<unix-epoch>", and returns the most recent non-zero
// handshake time. An epoch of 0 means the peer has never completed a handshake.
// ok is false when no peer has a non-zero handshake.
func freshestHandshake(wgShowOutput string) (time.Time, bool) {
	var newest int64
	for _, line := range strings.Split(wgShowOutput, "\n") {
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
