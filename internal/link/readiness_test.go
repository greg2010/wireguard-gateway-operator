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
		keepalive int
		showOut   string
		showErr   error
		want      bool
	}{
		{
			name:      "fresh_within_keepalive_window",
			keepalive: 25, // staleness = max(75s, 150s) = 150s
			showOut:   fmt.Sprintf("PK=\t%d", nowEpoch-30),
			want:      true,
		},
		{
			name:      "handshake_aged_past_keepalive_but_within_rekey_floor",
			keepalive: 25, // staleness floor = 150s covers the ~120s rekey interval
			showOut:   fmt.Sprintf("PK=\t%d", nowEpoch-120),
			want:      true,
		},
		{
			name:      "stale_beyond_rekey_floor",
			keepalive: 25, // staleness = max(75s, 150s) = 150s
			showOut:   fmt.Sprintf("PK=\t%d", nowEpoch-200),
			want:      false,
		},
		{
			name:      "no_handshake",
			keepalive: 25,
			showOut:   "PK=\t0",
			want:      false,
		},
		{
			name:      "wg_show_error",
			keepalive: 25,
			showErr:   fmt.Errorf("wg0 does not exist"),
			want:      false,
		},
		{
			name:      "keepalive_zero_fresh_within_default_window",
			keepalive: 0, // staleness = 180s
			showOut:   fmt.Sprintf("PK=\t%d", nowEpoch-120),
			want:      true,
		},
		{
			name:      "keepalive_zero_stale_beyond_default_window",
			keepalive: 0, // staleness = 180s
			showOut:   fmt.Sprintf("PK=\t%d", nowEpoch-200),
			want:      false,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			wgShow := func(_ context.Context) (string, error) {
				return tc.showOut, tc.showErr
			}
			rd := newReadiness(tc.keepalive, now, wgShow)
			if got := rd.ready(context.Background()); got != tc.want {
				t.Errorf("ready = %v, want %v (staleness=%s)", got, tc.want, rd.staleness())
			}
		})
	}
}
