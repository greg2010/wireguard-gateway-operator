package link

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestFreshestHandshake(t *testing.T) {
	tcs := []struct {
		name      string
		output    string
		wantOK    bool
		wantEpoch int64
	}{
		{
			name:   "empty",
			output: "",
			wantOK: false,
		},
		{
			name:   "single_zero_epoch",
			output: "PUBKEY=\t0",
			wantOK: false,
		},
		{
			name:      "single_fresh",
			output:    "PUBKEY=\t1700000000",
			wantOK:    true,
			wantEpoch: 1700000000,
		},
		{
			name:      "newest_of_many",
			output:    "PK1=\t1700000000\nPK2=\t1700000500\nPK3=\t0\n",
			wantOK:    true,
			wantEpoch: 1700000500,
		},
		{
			name:   "garbage_lines_ignored",
			output: "not-a-handshake\n\nPK=\tnotanumber\n",
			wantOK: false,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			ts, ok := freshestHandshake(tc.output)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && ts.Unix() != tc.wantEpoch {
				t.Errorf("epoch = %d, want %d", ts.Unix(), tc.wantEpoch)
			}
		})
	}
}

func TestReadinessReady(t *testing.T) {
	const nowEpoch = int64(1700001000)
	now := func() time.Time { return time.Unix(nowEpoch, 0) }

	tcs := []struct {
		name      string
		leader    bool
		keepalive int
		showOut   string
		showErr   error
		want      bool
	}{
		{
			name:      "leader_fresh_within_keepalive_window",
			leader:    true,
			keepalive: 25, // staleness = max(75s, 150s) = 150s
			showOut:   fmt.Sprintf("PK=\t%d", nowEpoch-30),
			want:      true,
		},
		{
			name:      "leader_handshake_aged_past_keepalive_but_within_rekey_floor",
			leader:    true,
			keepalive: 25, // staleness floor = 150s covers the ~120s rekey interval
			showOut:   fmt.Sprintf("PK=\t%d", nowEpoch-120),
			want:      true,
		},
		{
			name:      "leader_stale_beyond_rekey_floor",
			leader:    true,
			keepalive: 25, // staleness = max(75s, 150s) = 150s
			showOut:   fmt.Sprintf("PK=\t%d", nowEpoch-200),
			want:      false,
		},
		{
			name:      "leader_no_handshake",
			leader:    true,
			keepalive: 25,
			showOut:   "PK=\t0",
			want:      false,
		},
		{
			name:      "leader_wg_show_error",
			leader:    true,
			keepalive: 25,
			showErr:   fmt.Errorf("wg0 does not exist"),
			want:      false,
		},
		{
			name:      "leader_keepalive_zero_fresh_within_default_window",
			leader:    true,
			keepalive: 0, // staleness = 180s
			showOut:   fmt.Sprintf("PK=\t%d", nowEpoch-120),
			want:      true,
		},
		{
			name:      "leader_keepalive_zero_stale_beyond_default_window",
			leader:    true,
			keepalive: 0, // staleness = 180s
			showOut:   fmt.Sprintf("PK=\t%d", nowEpoch-200),
			want:      false,
		},
		{
			name:      "standby_ready_despite_stale_handshake",
			leader:    false,
			keepalive: 25,
			showOut:   fmt.Sprintf("PK=\t%d", nowEpoch-3600),
			want:      true,
		},
		{
			name:      "standby_ready_despite_no_handshake",
			leader:    false,
			keepalive: 25,
			showOut:   "PK=\t0",
			want:      true,
		},
		{
			name:      "standby_ready_despite_wg_show_error",
			leader:    false,
			keepalive: 25,
			showErr:   fmt.Errorf("wg0 does not exist"),
			want:      true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			wgShow := func(_ context.Context) (string, error) {
				return tc.showOut, tc.showErr
			}
			rd := newReadiness(tc.keepalive, now, wgShow)
			rd.setLeader(tc.leader)
			if got := rd.ready(context.Background()); got != tc.want {
				t.Errorf("ready = %v, want %v (leader=%v, staleness=%s)", got, tc.want, tc.leader, rd.staleness())
			}
		})
	}
}

// TestReadinessStandbyIgnoresWGShow pins that a non-leader never shells out for
// handshake state: ready() must short-circuit to true before calling wgShow.
func TestReadinessStandbyIgnoresWGShow(t *testing.T) {
	called := false
	rd := newReadiness(25, time.Now, func(_ context.Context) (string, error) {
		called = true
		return "", fmt.Errorf("wgShow must not be called for a standby")
	})

	if !rd.ready(context.Background()) {
		t.Fatal("standby ready = false, want true")
	}
	if called {
		t.Error("wgShow was called for a non-leader; ready() must short-circuit first")
	}
}
