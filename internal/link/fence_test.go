package link

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// TestTeardownCommandPlan pins the exported fence plan in both modes and Teardown's best-effort
// contract: it runs exactly those steps in order, continues past a failing one and joins failures.
func TestTeardownCommandPlan(t *testing.T) {
	tcs := []struct {
		name     string
		rc       RuntimeConfig
		wantPlan [][]string
	}{
		{
			name: "cluster",
			rc:   RuntimeConfig{},
			wantPlan: [][]string{
				{"nft", "delete", "table", "inet", "gateway"},
				{"ip", "link", "del", "wg0"},
			},
		},
		{
			name: "local",
			rc:   RuntimeConfig{TrafficPolicy: TrafficPolicyLocal, Identity: new(NewIdentity(3))},
			wantPlan: [][]string{
				{"nft", "delete", "table", "inet", "gw3"},
				{"ip", "rule", "del", "fwmark", "0x00030000/0xffff0000", "lookup", "100003", "priority", "10000"},
				{"ip", "route", "flush", "table", "100003"},
				{"ip", "link", "del", "wg-gw3"},
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("exported_plan", func(t *testing.T) {
				assertSteps(t, TeardownCommands(tc.rc), tc.wantPlan)
			})

			t.Run("teardown_runs_the_plan", func(t *testing.T) {
				rec := &runRecorder{}
				if err := Teardown(context.Background(), rec.run, tc.rc); err != nil {
					t.Fatalf("Teardown: %v", err)
				}
				assertRanPlan(t, rec.snapshot(), tc.wantPlan)
			})

			t.Run("every_step_fails_error_joins_all", func(t *testing.T) {
				rec := &runRecorder{hook: func(c command) error { return &teardownStepError{cmd: c} }}
				err := Teardown(context.Background(), rec.run, tc.rc)
				if err == nil {
					t.Fatal("expected joined error when every step fails")
				}
				for _, want := range tc.wantPlan {
					name := strings.Join(want, " ")
					if !strings.Contains(err.Error(), name) {
						t.Errorf("joined error missing step %q: %v", name, err)
					}
				}
				assertRanPlan(t, rec.snapshot(), tc.wantPlan)
			})

			t.Run("first_step_failure_does_not_abort", func(t *testing.T) {
				rec := &runRecorder{hook: func(c command) error {
					if c.name == "nft" {
						return &teardownStepError{cmd: c}
					}
					return nil
				}}
				err := Teardown(context.Background(), rec.run, tc.rc)
				if err == nil {
					t.Fatal("expected an error naming the failed nft step")
				}
				plan := TeardownCommands(tc.rc)
				failed := strings.Join(append([]string{plan[0].Name}, plan[0].Args...), " ")
				if !strings.Contains(err.Error(), failed) {
					t.Errorf("error %v does not name the failed step %q", err, failed)
				}
				assertRanPlan(t, rec.snapshot(), tc.wantPlan)
			})
		})
	}
}

// teardownStepError names the failing step so a joined-error assertion can find it.
type teardownStepError struct {
	cmd command
}

func (e *teardownStepError) Error() string {
	return strings.Join(append([]string{e.cmd.name}, e.cmd.args...), " ") + ": injected failure"
}

// assertSteps compares an exported plan against the wanted argv lists, in order.
func assertSteps(t *testing.T, steps []TeardownStep, wantPlan [][]string) {
	t.Helper()
	got := make([][]string, 0, len(steps))
	for _, s := range steps {
		got = append(got, append([]string{s.Name}, s.Args...))
	}
	assertArgvPlan(t, got, wantPlan)
}

// assertRanPlan compares the commands a recording runner saw against the wanted plan.
func assertRanPlan(t *testing.T, cmds []command, wantPlan [][]string) {
	t.Helper()
	got := make([][]string, 0, len(cmds))
	for _, c := range cmds {
		got = append(got, append([]string{c.name}, c.args...))
	}
	assertArgvPlan(t, got, wantPlan)
}

func assertArgvPlan(t *testing.T, got, want [][]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("plan has %d steps, want %d; got: %v", len(got), len(want), got)
	}
	for i := range want {
		if !slices.Equal(got[i], want[i]) {
			t.Errorf("step[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}
