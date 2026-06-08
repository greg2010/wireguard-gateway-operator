package link

import (
	"context"
	"testing"
)

// TestTeardownCommandPlan pins the fence plan and its best-effort contract:
// Teardown deletes wg0 then the nft table, runs the nft delete even when the wg0
// delete fails, and returns a non-nil joined error exactly when a step failed.
func TestTeardownCommandPlan(t *testing.T) {
	wantPlan := [][]string{
		{"ip", "link", "del", "wg0"},
		{"nft", "delete", "table", "inet", "gateway"},
	}

	tcs := []struct {
		name    string
		failOn  string
		wantErr bool
	}{
		{
			name:    "all_succeed_returns_nil",
			failOn:  "",
			wantErr: false,
		},
		{
			name:    "first_fails_second_still_runs_and_error_joined",
			failOn:  "ip",
			wantErr: true,
		},
		{
			name:    "second_fails_error_joined",
			failOn:  "nft",
			wantErr: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			rec := &runRecorder{failOn: tc.failOn}

			err := Teardown(context.Background(), rec.run)

			if tc.wantErr && err == nil {
				t.Fatalf("Teardown failOn=%q returned nil, want joined error", tc.failOn)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Teardown failOn=%q returned %v, want nil", tc.failOn, err)
			}

			cmds := rec.snapshot()
			if len(cmds) != len(wantPlan) {
				t.Fatalf("ran %d commands, want %d (best-effort runs every step); got: %+v", len(cmds), len(wantPlan), cmds)
			}
			for i, want := range wantPlan {
				gotName, gotArgs := cmds[i].name, cmds[i].args
				if gotName != want[0] {
					t.Errorf("cmd[%d] name = %q, want %q", i, gotName, want[0])
				}
				if got := append([]string{gotName}, gotArgs...); !equalStrings(got, want) {
					t.Errorf("cmd[%d] = %v, want %v", i, got, want)
				}
			}
		})
	}
}

// equalStrings reports whether two string slices are element-wise equal.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
