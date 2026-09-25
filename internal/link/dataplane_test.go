package link

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// dpLinkID is the link id every fixture in this file derives its names from.
const dpLinkID = 3

func dpRuntimeConfig(slots ...int) RuntimeConfig {
	ident := NewGatewayIdentity(dpLinkID)
	peers := make([]Peer, 0, len(slots))
	for _, s := range slots {
		peers = append(peers, Peer{Slot: s, PublicKey: fmt.Sprintf("PUB%d=", s)})
	}
	return RuntimeConfig{
		TrafficPolicy: TrafficPolicyLocal,
		Identity:      &ident,
		HealthPort:    ident.HealthPort,
		WireGuard:     WireGuard{Peers: peers},
	}
}

// ipSteps returns the argv of every ip(8) command run, in order.
func ipSteps(cmds []command) [][]string {
	steps := [][]string{}
	for _, c := range cmds {
		if c.name == "ip" {
			steps = append(steps, append([]string{c.name}, c.args...))
		}
	}
	return steps
}

// resultsFor is one scripted apply outcome per slot: a slot in failed carries an error, the rest
// applied.
func resultsFor(slots []int, failed ...int) []SlotResult {
	results := make([]SlotResult, 0, len(slots))
	for _, s := range slots {
		if slices.Contains(failed, s) {
			results = append(results, SlotResult{Slot: s, Err: fmt.Errorf("injected apply failure for slot %d", s)})
			continue
		}
		results = append(results, SlotResult{Slot: s, Applied: true})
	}
	return results
}

// applyPassWith runs one pass whose apply step returns results, so a test drives the per-slot
// outcome without a real apply.
func applyPassWith(t *testing.T, d *dataPlane, run runner, rc RuntimeConfig, results []SlotResult) []SlotResult {
	t.Helper()
	got, err := d.applyPass(context.Background(), run, rc, func(context.Context, []ResolvedForward, string) ([]SlotResult, []ResolvedForward, error) {
		return results, nil, nil
	}, testLogger(t))
	if err != nil {
		t.Fatalf("applyPass: %v", err)
	}
	return got
}

// TestDepartedSlotTeardown retains failed departures for the next pass.
func TestDepartedSlotTeardown(t *testing.T) {
	slot2 := NewSlotIdentity(dpLinkID, 2)
	wantSteps := [][]string{
		{"ip", "rule", "del", "fwmark", slot2.Mark + "/" + slot2.MarkMask, "lookup", "100515", "priority", rulePriority},
		{"ip", "route", "flush", "table", "100515"},
		{"ip", "link", "del", slot2.Interface},
	}

	tcs := []struct {
		name string
		// applied is the pass run before the config drops slot 2, empty when the replica never
		// applied it.
		applied   []int
		failure   error
		wantSteps [][]string
		wantDown  []SlotResult
		wantHeld  []int
	}{
		{
			name:      "slot_dropped_before_it_was_ever_applied_is_never_torn_down",
			applied:   []int{0},
			wantSteps: [][]string{},
			wantHeld:  []int{0},
		},
		{
			name:      "absent_interface_is_skipped_and_the_remaining_slot_applies",
			applied:   []int{0, 2},
			failure:   errors.New(`ip [link del wg-gw3-2]: exit status 1: Cannot find device "wg-gw3-2"`),
			wantSteps: wantSteps,
			wantHeld:  []int{0},
		},
		{
			name:      "other_teardown_failure_keeps_the_slot_and_applies_the_remaining_one",
			applied:   []int{0, 2},
			failure:   errors.New("ip [link del wg-gw3-2]: exit status 2: Operation not permitted"),
			wantSteps: wantSteps,
			wantDown:  []SlotResult{{Slot: 2}},
			wantHeld:  []int{0, 2},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			seed := dpRuntimeConfig(tc.applied...)
			d := newDataPlane(seed)
			rec := &runRecorder{}
			applyPassWith(t, d, rec.run, seed, resultsFor(tc.applied))

			current := dpRuntimeConfig(0)
			rec = &runRecorder{hook: func(c command) error {
				if tc.failure != nil && c.name == "ip" && slices.Equal(c.args, []string{"link", "del", slot2.Interface}) {
					return tc.failure
				}
				return nil
			}}
			got := applyPassWith(t, d, rec.run, current, resultsFor([]int{0}))

			if diff := ipSteps(rec.snapshot()); !slices.EqualFunc(diff, tc.wantSteps, slices.Equal) {
				t.Errorf("teardown steps = %v, want %v", diff, tc.wantSteps)
			}
			wantResults := append(resultsFor([]int{0}), tc.wantDown...)
			assertSlotOutcomes(t, got, wantResults)
			if held := d.heldSlots(); !slices.Equal(held, tc.wantHeld) {
				t.Errorf("held slots = %v, want %v", held, tc.wantHeld)
			}
		})
	}
}

// TestDepartedTeardownRetriesNextPass pins that a departed slot whose teardown failed is retried
// by the next pass and leaves the set once it succeeds.
func TestDepartedTeardownRetriesNextPass(t *testing.T) {
	slot2 := NewSlotIdentity(dpLinkID, 2)
	seed := dpRuntimeConfig(0, 2)
	d := newDataPlane(seed)
	rec := &runRecorder{}
	applyPassWith(t, d, rec.run, seed, resultsFor([]int{0, 2}))

	current := dpRuntimeConfig(0)
	failing := &runRecorder{hook: func(c command) error {
		if c.name == "ip" && slices.Equal(c.args, []string{"link", "del", slot2.Interface}) {
			return errors.New("ip [link del wg-gw3-2]: exit status 2: Operation not permitted")
		}
		return nil
	}}
	applyPassWith(t, d, failing.run, current, resultsFor([]int{0}))

	retry := &runRecorder{}
	got := applyPassWith(t, d, retry.run, current, resultsFor([]int{0}))

	assertSlotOutcomes(t, got, resultsFor([]int{0}))
	if held := d.heldSlots(); !slices.Equal(held, []int{0}) {
		t.Errorf("held slots after the successful retry = %v, want %v", held, []int{0})
	}
	wantSteps := [][]string{
		{"ip", "rule", "del", "fwmark", slot2.Mark + "/" + slot2.MarkMask, "lookup", "100515", "priority", rulePriority},
		{"ip", "route", "flush", "table", "100515"},
		{"ip", "link", "del", slot2.Interface},
	}
	if steps := ipSteps(retry.snapshot()); !slices.EqualFunc(steps, wantSteps, slices.Equal) {
		t.Errorf("retried teardown steps = %v, want %v", steps, wantSteps)
	}
}

// TestStandbyPass keeps every held slot on a standby pass and tears them down only once the
// election has observed another replica holding the Lease.
func TestStandbyPass(t *testing.T) {
	slot0 := NewSlotIdentity(dpLinkID, 0)
	slotSteps := [][]string{
		{"ip", "rule", "del", "fwmark", slot0.Mark + "/" + slot0.MarkMask, "lookup", "100003", "priority", rulePriority},
		{"ip", "route", "flush", "table", "100003"},
		{"ip", "link", "del", slot0.Interface},
	}

	tcs := []struct {
		name string
		// configSlots is the peer set the accepted config carries.
		configSlots []int
		// applied is seeded by a pass of this replica's own, inherited by discovery at start.
		applied     []int
		inherited   []int
		otherHolder bool
		leader      bool
		wantSteps   [][]string
		wantHeld    []int
	}{
		{
			name:        "standby_holding_nothing_runs_no_command",
			configSlots: []int{0},
			wantSteps:   [][]string{},
			wantHeld:    []int{},
		},
		{
			name:        "standby_keeps_an_inherited_slot_with_no_observed_holder",
			configSlots: []int{0},
			inherited:   []int{0},
			wantSteps:   [][]string{},
			wantHeld:    []int{0},
		},
		{
			name:      "standby_keeps_an_inherited_slot_the_config_no_longer_lists",
			inherited: []int{0},
			wantSteps: [][]string{},
			wantHeld:  []int{0},
		},
		{
			name:        "standby_keeps_a_slot_its_own_pass_applied_with_no_observed_holder",
			configSlots: []int{0},
			applied:     []int{0},
			wantSteps:   [][]string{},
			wantHeld:    []int{0},
		},
		{
			name:        "an_observed_other_holder_tears_down_an_inherited_slot",
			configSlots: []int{0},
			inherited:   []int{0},
			otherHolder: true,
			wantSteps:   slotSteps,
			wantHeld:    []int{},
		},
		{
			name:        "an_observed_other_holder_tears_down_an_applied_slot",
			configSlots: []int{0},
			applied:     []int{0},
			otherHolder: true,
			wantSteps:   slotSteps,
			wantHeld:    []int{},
		},
		{
			name:        "a_holders_config_is_left_to_its_apply_pass",
			configSlots: []int{0},
			applied:     []int{0},
			otherHolder: true,
			leader:      true,
			wantSteps:   [][]string{},
			wantHeld:    []int{0},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			rc := dpRuntimeConfig(tc.configSlots...)
			d := newDataPlane(rc)
			if len(tc.applied) > 0 {
				applyPassWith(t, d, (&runRecorder{}).run, dpRuntimeConfig(tc.applied...), resultsFor(tc.applied))
			}
			for _, slot := range tc.inherited {
				d.hold(slot)
			}
			if tc.otherHolder {
				d.observeOtherHolder()
			}

			rec := &runRecorder{}
			if err := d.standbyPass(context.Background(), rec.run, rc, func() bool { return tc.leader }, testLogger(t)); err != nil {
				t.Fatalf("standbyPass: %v", err)
			}

			cmds := rec.snapshot()
			if steps := ipSteps(cmds); !slices.EqualFunc(steps, tc.wantSteps, slices.Equal) {
				t.Errorf("standby steps = %v, want %v", steps, tc.wantSteps)
			}
			if held := d.heldSlots(); !slices.Equal(held, tc.wantHeld) {
				t.Errorf("held slots = %v, want %v", held, tc.wantHeld)
			}
			if len(cmds) != len(tc.wantSteps) {
				t.Errorf("standby pass ran %d commands, want exactly its %d ip steps: %v", len(cmds), len(tc.wantSteps), cmds)
			}
		})
	}
}

// TestStandbyPassAfterAFailedTeardown covers the step-down whose teardown of one slot failed: the
// next accepted config retries it only once the election has observed another holder.
func TestStandbyPassAfterAFailedTeardown(t *testing.T) {
	slot0 := NewSlotIdentity(dpLinkID, 0)
	retrySteps := [][]string{
		{"ip", "rule", "del", "fwmark", slot0.Mark + "/" + slot0.MarkMask, "lookup", "100003", "priority", rulePriority},
		{"ip", "route", "flush", "table", "100003"},
		{"ip", "link", "del", slot0.Interface},
	}

	tcs := []struct {
		name        string
		otherHolder bool
		wantSteps   [][]string
		wantHeld    []int
	}{
		{
			name:      "no_observed_holder_keeps_the_retained_slot",
			wantSteps: [][]string{},
			wantHeld:  []int{0},
		},
		{
			name:        "an_observed_other_holder_retries_the_teardown",
			otherHolder: true,
			wantSteps:   retrySteps,
			wantHeld:    []int{},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			rc := dpRuntimeConfig(0)
			d := newDataPlane(rc)
			applyPassWith(t, d, (&runRecorder{}).run, rc, resultsFor([]int{0}))

			failing := &runRecorder{hook: func(c command) error {
				if c.name == "ip" && slices.Equal(c.args, []string{"link", "del", slot0.Interface}) {
					return errors.New("ip [link del wg-gw3]: exit status 2: Operation not permitted")
				}
				return nil
			}}
			if err := d.stepDown(context.Background(), failing.run, testLogger(t)); err == nil {
				t.Fatal("stepDown with a failing link delete returned no error")
			}
			if held := d.heldSlots(); !slices.Equal(held, []int{0}) {
				t.Fatalf("held slots after the failed step-down = %v, want %v", held, []int{0})
			}
			if tc.otherHolder {
				d.observeOtherHolder()
			}

			rec := &runRecorder{}
			if err := d.standbyPass(context.Background(), rec.run, rc, func() bool { return false }, testLogger(t)); err != nil {
				t.Fatalf("standbyPass: %v", err)
			}

			cmds := rec.snapshot()
			if steps := ipSteps(cmds); !slices.EqualFunc(steps, tc.wantSteps, slices.Equal) {
				t.Errorf("standby steps = %v, want %v", steps, tc.wantSteps)
			}
			if held := d.heldSlots(); !slices.Equal(held, tc.wantHeld) {
				t.Errorf("held slots after the standby pass = %v, want %v", held, tc.wantHeld)
			}
			if len(cmds) != len(tc.wantSteps) {
				t.Errorf("standby pass ran %d commands, want exactly its %d ip steps: %v", len(cmds), len(tc.wantSteps), cmds)
			}
		})
	}
}

// TestInheritedSlotAdoptedAfterAStandbyRace pins adoption of an inherited interface when the first
// standby pass precedes leadership reporting while this pod still owns the Lease.
func TestInheritedSlotAdoptedAfterAStandbyRace(t *testing.T) {
	slot0 := NewSlotIdentity(dpLinkID, 0)
	rc := dpRuntimeConfig(0)
	rc.WireGuard.Address = "10.244.1.7/32"
	rc.WireGuard.Peers[0].Endpoint = "203.0.113.5:51820"
	rc.WireGuard.Peers[0].AllowedIPs = []string{"0.0.0.0/0"}
	table := strconv.Itoa(slot0.RouteTable)

	applySteps := []string{
		"ip link show " + slot0.Interface,
		"wg syncconf " + slot0.Interface + " " + wgConfArg,
		"ip addr replace 10.244.1.7/32 dev " + slot0.Interface,
		"ip link set " + slot0.Interface + " up",
		"write " + HostProcSysNetPath + "/ipv4/conf/" + slot0.Interface + "/rp_filter=0",
		"write " + HostProcSysNetPath + "/ipv4/conf/" + slot0.Interface + "/forwarding=1",
		"ip route replace default dev " + slot0.Interface + " table " + table,
		"ip route flush table " + table + " type throw",
		"ip rule add fwmark " + slot0.Mark + "/" + slot0.MarkMask + " lookup " + table + " priority " + rulePriority,
		"nft -f -",
	}

	tcs := []struct {
		name string
		// standbyFirst runs the watcher's initial callback before leadership; it runs no
		// command, since standbyPass leaves a held slot untouched absent an observed holder.
		standbyFirst bool
		wantSteps    []string
	}{
		{
			name:         "the_standby_pass_that_precedes_leadership_keeps_the_interface",
			standbyFirst: true,
			wantSteps:    applySteps,
		},
		{
			name:      "leadership_without_an_earlier_standby_pass",
			wantSteps: applySteps,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			d := newDataPlane(rc)
			d.hold(0)
			// A sysctl step carries no command name, which the recorder's default failOn matches.
			rec := &runRecorder{hook: func(command) error { return nil }}

			if tc.standbyFirst {
				if err := d.standbyPass(context.Background(), rec.run, rc, func() bool { return false }, testLogger(t)); err != nil {
					t.Fatalf("standbyPass: %v", err)
				}
				if held := d.heldSlots(); !slices.Equal(held, []int{0}) {
					t.Fatalf("held slots after the standby pass = %v, want %v", held, []int{0})
				}
			}

			results, err := d.applyPass(context.Background(), rec.run, rc, func(ctx context.Context, previous []ResolvedForward, previousAddress string) ([]SlotResult, []ResolvedForward, error) {
				return applyConfig(ctx, rec.run, rc, "priv", func(context.Context, string) (string, error) { return "", nil }, previous, previousAddress, nil, "", &responderProbeLatch{}, testLogger(t))
			}, testLogger(t))
			if err != nil {
				t.Fatalf("applyPass: %v", err)
			}

			assertSlotOutcomes(t, results, resultsFor([]int{0}))
			if steps := stepLines(t, rec.snapshot()); !slices.Equal(steps, tc.wantSteps) {
				t.Errorf("executed steps =\n%s\nwant\n%s", strings.Join(steps, "\n"), strings.Join(tc.wantSteps, "\n"))
			}
			if held := d.heldSlots(); !slices.Equal(held, []int{0}) {
				t.Errorf("held slots after the apply = %v, want %v", held, []int{0})
			}
		})
	}
}

// TestApplyPassThreadsForwards pins how applyPass threads the forward set: a success's returned
// set becomes the next call's previous, a failure's does not, and a no-op standbyPass leaves it.
func TestApplyPassThreadsForwards(t *testing.T) {
	forwardA := []ResolvedForward{{Name: "a", PublicPort: 443, Protocol: "tcp", Target: "10.96.1.10", TargetPort: 8443}}
	forwardB := []ResolvedForward{{Name: "a", PublicPort: 443, Protocol: "tcp", Target: "10.96.1.20", TargetPort: 8443}}
	failErr := errors.New("injected apply failure")

	tcs := []struct {
		name string
		// standbyAfterFirst runs a no-op standbyPass between the first and second applyPass calls.
		standbyAfterFirst bool
		// secondFails makes the second call fail and return forwardB, which must not replace the
		// stored set; a third call then checks the set the first call stored survived.
		secondFails bool
	}{
		{name: "two_successful_calls"},
		{name: "a_standby_pass_between_two_successful_calls", standbyAfterFirst: true},
		{name: "a_failing_call_does_not_replace_the_stored_set", secondFails: true},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			rc := RuntimeConfig{WireGuard: WireGuard{Address: "10.99.0.2/32"}}
			d := newDataPlane(rc)
			rec := &runRecorder{}

			var previous [][]ResolvedForward
			apply := func(_ context.Context, prev []ResolvedForward, _ string) ([]SlotResult, []ResolvedForward, error) {
				previous = append(previous, prev)
				if len(previous) == 2 && tc.secondFails {
					return nil, forwardB, failErr
				}
				if len(previous) == 1 {
					return nil, forwardA, nil
				}
				return nil, forwardB, nil
			}

			if _, err := d.applyPass(context.Background(), rec.run, rc, apply, testLogger(t)); err != nil {
				t.Fatalf("call 1: %v", err)
			}
			if tc.standbyAfterFirst {
				if err := d.standbyPass(context.Background(), rec.run, rc, func() bool { return true }, testLogger(t)); err != nil {
					t.Fatalf("standbyPass: %v", err)
				}
			}
			_, err := d.applyPass(context.Background(), rec.run, rc, apply, testLogger(t))
			switch {
			case tc.secondFails && !errors.Is(err, failErr):
				t.Fatalf("call 2 error = %v, want one wrapping %v", err, failErr)
			case !tc.secondFails && err != nil:
				t.Fatalf("call 2: %v", err)
			}
			if tc.secondFails {
				if _, err := d.applyPass(context.Background(), rec.run, rc, apply, testLogger(t)); err != nil {
					t.Fatalf("call 3: %v", err)
				}
			}

			wantLen := 2
			if tc.secondFails {
				wantLen = 3
			}
			if len(previous) != wantLen {
				t.Fatalf("apply callback ran %d times, want %d", len(previous), wantLen)
			}
			if !reflect.DeepEqual(previous[0], []ResolvedForward(nil)) {
				t.Errorf("call 1's previous = %+v, want nil", previous[0])
			}
			if !reflect.DeepEqual(previous[wantLen-1], forwardA) {
				t.Errorf("last call's previous = %+v, want %+v", previous[wantLen-1], forwardA)
			}
		})
	}
}

// TestApplyPassRemembersPublicAddress pins the public address a pass hands the next apply: the
// last successful apply's, kept across a failure, and empty after the leadership-start reset.
func TestApplyPassRemembersPublicAddress(t *testing.T) {
	const addrA, addrB = "198.51.100.7", "198.51.100.9"
	failErr := errors.New("injected apply failure")

	tcs := []struct {
		name        string
		secondAddr  string
		secondFails bool
		startCycle  bool
		// wantHanded is the previous address each of the three passes receives.
		wantHanded []string
	}{
		{name: "successful_apply_is_remembered", secondAddr: addrB, wantHanded: []string{"", addrA, addrB}},
		{name: "failed_apply_keeps_the_previous_address", secondAddr: addrB, secondFails: true, wantHanded: []string{"", addrA, addrA}},
		{name: "leadership_start_clears_the_address", secondAddr: addrA, startCycle: true, wantHanded: []string{"", "", addrA}},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			first := dpRuntimeConfig(0)
			first.PublicAddress = addrA
			second := dpRuntimeConfig(0)
			second.PublicAddress = tc.secondAddr
			d := newDataPlane(first)
			rec := &runRecorder{}

			var handed []string
			apply := func(fails bool) func(context.Context, []ResolvedForward, string) ([]SlotResult, []ResolvedForward, error) {
				return func(_ context.Context, _ []ResolvedForward, previousAddress string) ([]SlotResult, []ResolvedForward, error) {
					handed = append(handed, previousAddress)
					if fails {
						return resultsFor([]int{0}), nil, failErr
					}
					return resultsFor([]int{0}), nil, nil
				}
			}

			if _, err := d.applyPass(context.Background(), rec.run, first, apply(false), testLogger(t)); err != nil {
				t.Fatalf("pass 1: %v", err)
			}
			if tc.startCycle {
				d.startLeading()
			}
			if _, err := d.applyPass(context.Background(), rec.run, second, apply(tc.secondFails), testLogger(t)); (err != nil) != tc.secondFails {
				t.Fatalf("pass 2 error = %v, want failure %t", err, tc.secondFails)
			}
			if _, err := d.applyPass(context.Background(), rec.run, second, apply(false), testLogger(t)); err != nil {
				t.Fatalf("pass 3: %v", err)
			}

			if !slices.Equal(handed, tc.wantHanded) {
				t.Errorf("previous addresses handed to apply = %q, want %q", handed, tc.wantHanded)
			}
		})
	}
}

// TestStepDown pins step-down's teardown plan in both modes: the data-plane table goes first,
// then every slot this replica holds.
func TestStepDown(t *testing.T) {
	slot0, slot2 := NewSlotIdentity(dpLinkID, 0), NewSlotIdentity(dpLinkID, 2)

	t.Run("local_step_down_removes_the_table_then_every_held_slot", func(t *testing.T) {
		rc := dpRuntimeConfig(0, 2)
		d := newDataPlane(rc)
		seed := &runRecorder{}
		applyPassWith(t, d, seed.run, rc, resultsFor([]int{0, 2}))

		rec := &runRecorder{}
		if err := d.stepDown(context.Background(), rec.run, testLogger(t)); err != nil {
			t.Fatalf("stepDown: %v", err)
		}

		cmds := rec.snapshot()
		wantPlan := [][]string{
			{"nft", "delete", "table", "inet", "gw3"},
			{"ip", "rule", "del", "fwmark", slot0.Mark + "/" + slot0.MarkMask, "lookup", "100003", "priority", rulePriority},
			{"ip", "route", "flush", "table", "100003"},
			{"ip", "link", "del", slot0.Interface},
			{"ip", "rule", "del", "fwmark", slot2.Mark + "/" + slot2.MarkMask, "lookup", "100515", "priority", rulePriority},
			{"ip", "route", "flush", "table", "100515"},
			{"ip", "link", "del", slot2.Interface},
		}
		assertRanPlan(t, cmds, wantPlan)
		if held := d.heldSlots(); !slices.Equal(held, []int{}) {
			t.Errorf("held slots after the step-down = %v, want none", held)
		}
	})

	t.Run("cluster_step_down_runs_the_cluster_plan", func(t *testing.T) {
		d := newDataPlane(RuntimeConfig{})
		rec := &runRecorder{}
		if err := d.stepDown(context.Background(), rec.run, testLogger(t)); err != nil {
			t.Fatalf("stepDown: %v", err)
		}
		assertRanPlan(t, rec.snapshot(), [][]string{
			{"nft", "delete", "table", "inet", "gateway"},
			{"ip", "link", "del", "wg0"},
		})
	})

	t.Run("a_failing_step_does_not_abort_the_rest", func(t *testing.T) {
		rc := dpRuntimeConfig(0)
		d := newDataPlane(rc)
		seed := &runRecorder{}
		applyPassWith(t, d, seed.run, rc, resultsFor([]int{0}))

		rec := &runRecorder{hook: func(c command) error {
			if c.name == "nft" && slices.Equal(c.args, []string{"delete", "table", "inet", "gw3"}) {
				return &teardownStepError{cmd: c}
			}
			return nil
		}}
		err := d.stepDown(context.Background(), rec.run, testLogger(t))
		if err == nil || !strings.Contains(err.Error(), "nft delete table inet gw3") {
			t.Fatalf("stepDown error = %v, want one naming the failed nft step", err)
		}
		assertRanPlan(t, rec.snapshot(), [][]string{
			{"nft", "delete", "table", "inet", "gw3"},
			{"ip", "rule", "del", "fwmark", slot0.Mark + "/" + slot0.MarkMask, "lookup", "100003", "priority", rulePriority},
			{"ip", "route", "flush", "table", "100003"},
			{"ip", "link", "del", slot0.Interface},
		})
	})
}

// assertSlotOutcomes compares per-slot outcomes by slot and applied flag, and requires a down
// slot to carry an error.
func assertSlotOutcomes(t *testing.T, got, want []SlotResult) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("slot outcomes = %v, want %d entries", got, len(want))
	}
	for i := range want {
		if got[i].Slot != want[i].Slot || got[i].Applied != want[i].Applied {
			t.Errorf("slot outcome[%d] = {slot %d applied %t}, want {slot %d applied %t}",
				i, got[i].Slot, got[i].Applied, want[i].Slot, want[i].Applied)
		}
		if !want[i].Applied && got[i].Err == nil {
			t.Errorf("slot outcome[%d] for slot %d carries no error", i, got[i].Slot)
		}
	}
}

// TestFirstAttemptedSlotIsHeld retains partial state for departure teardown.
func TestFirstAttemptedSlotIsHeld(t *testing.T) {
	slot2 := NewSlotIdentity(dpLinkID, 2)
	wantPlan := [][]string{
		{"ip", "rule", "del", "fwmark", slot2.Mark + "/" + slot2.MarkMask, "lookup", "100515", "priority", rulePriority},
		{"ip", "route", "flush", "table", "100515"},
		{"ip", "link", "del", slot2.Interface},
	}

	tcs := []struct {
		name string
		// first is the outcome of the only pass slot 2 was configured for.
		first    []SlotResult
		wantHeld []int
	}{
		{
			name:     "slot_failing_its_first_attempt_is_torn_down_when_it_departs",
			first:    resultsFor([]int{0, 2}, 2),
			wantHeld: []int{0},
		},
		{
			name:     "slot_applied_on_its_first_attempt_is_torn_down_when_it_departs",
			first:    resultsFor([]int{0, 2}),
			wantHeld: []int{0},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			seed := dpRuntimeConfig(0, 2)
			d := newDataPlane(seed)
			applyPassWith(t, d, (&runRecorder{}).run, seed, tc.first)

			current := dpRuntimeConfig(0)
			rec := &runRecorder{}
			applyPassWith(t, d, rec.run, current, resultsFor([]int{0}))

			assertRanPlan(t, rec.snapshot(), wantPlan)
			if held := d.heldSlots(); !slices.Equal(held, tc.wantHeld) {
				t.Errorf("held slots after the departure = %v, want %v", held, tc.wantHeld)
			}
		})
	}
}

// TestRulesetFailureHoldsThenTearsDownTheDepartedSlot covers two passes: a pass
// whose ruleset failed holds every slot it attempted, so the next tears a dropped one down.
func TestRulesetFailureHoldsThenTearsDownTheDepartedSlot(t *testing.T) {
	slot0, slot2 := NewSlotIdentity(dpLinkID, 0), NewSlotIdentity(dpLinkID, 2)
	nftErr := fmt.Errorf("nft -f -: exit status 1: Error: syntax error")
	resolve := func(_ context.Context, _ string) (string, error) { return "", nil }

	pass := func(rec *runRecorder, d *dataPlane, rc RuntimeConfig) error {
		_, err := d.applyPass(context.Background(), rec.run, rc, func(ctx context.Context, previous []ResolvedForward, previousAddress string) ([]SlotResult, []ResolvedForward, error) {
			return applyConfig(ctx, rec.run, rc, "priv", resolve, previous, previousAddress, nil, "", &responderProbeLatch{}, testLogger(t))
		}, testLogger(t))
		return err
	}

	first := dpApplyConfig(0, 2)
	d := newDataPlane(first)
	failing := &runRecorder{hook: func(c command) error {
		if c.name == "nft" {
			return nftErr
		}
		return nil
	}}
	if err := pass(failing, d, first); !errors.Is(err, nftErr) {
		t.Fatalf("first pass error = %v, want one wrapping %v", err, nftErr)
	}
	if held := d.heldSlots(); !slices.Equal(held, []int{0, 2}) {
		t.Fatalf("held slots after the failed ruleset = %v, want %v", held, []int{0, 2})
	}

	second := dpApplyConfig(0)
	// A recorder without a hook fails every file-write step: their command carries no name, which
	// matches its empty failOn.
	rec := &runRecorder{hook: func(command) error { return nil }}
	if err := pass(rec, d, second); err != nil {
		t.Fatalf("second pass: %v", err)
	}

	wantPlan := []string{
		"ip rule del fwmark " + slot2.Mark + "/" + slot2.MarkMask + " lookup 100515 priority " + rulePriority,
		"ip route flush table 100515",
		"ip link del " + slot2.Interface,
		"ip link show " + slot0.Interface,
		"wg syncconf " + slot0.Interface + " " + wgConfArg,
		"ip addr replace 10.244.1.7/32 dev " + slot0.Interface,
		"ip link set " + slot0.Interface + " up",
		"write " + HostProcSysNetPath + "/ipv4/conf/" + slot0.Interface + "/rp_filter=0",
		"write " + HostProcSysNetPath + "/ipv4/conf/" + slot0.Interface + "/forwarding=1",
		"ip route replace default dev " + slot0.Interface + " table 100003",
		"ip route flush table 100003 type throw",
		"ip rule add fwmark " + slot0.Mark + "/" + slot0.MarkMask + " lookup 100003 priority " + rulePriority,
		"nft -f -",
	}
	cmds := rec.snapshot()
	if steps := stepLines(t, cmds); !slices.Equal(steps, wantPlan) {
		t.Errorf("second pass ran\n%s\nwant\n%s", strings.Join(steps, "\n"), strings.Join(wantPlan, "\n"))
	}
	if held := d.heldSlots(); !slices.Equal(held, []int{0}) {
		t.Errorf("held slots after the departure = %v, want %v", held, []int{0})
	}
}

// dpApplyConfig is dpRuntimeConfig with the address and endpoints a real Apply renders from.
func dpApplyConfig(slots ...int) RuntimeConfig {
	rc := dpRuntimeConfig(slots...)
	rc.WireGuard.Address = "10.244.1.7/32"
	for i := range rc.WireGuard.Peers {
		rc.WireGuard.Peers[i].Endpoint = fmt.Sprintf("203.0.113.%d:51820", 5+i)
		rc.WireGuard.Peers[i].AllowedIPs = []string{"0.0.0.0/0"}
	}
	return rc
}

func TestStandbyPassOtherHolderEvidenceIsPerTerm(t *testing.T) {
	slot := NewSlotIdentity(dpLinkID, 0)
	teardown := [][]string{
		{"ip", "rule", "del", "fwmark", slot.Mark + "/" + slot.MarkMask, "lookup", "100003", "priority", rulePriority},
		{"ip", "route", "flush", "table", "100003"},
		{"ip", "link", "del", slot.Interface},
	}
	tcs := []struct {
		name       string
		observeNew bool
		wantSteps  []string
		wantHeld   []int
	}{
		{
			name:      "acquisition_clears_prior_holder_evidence_and_keeps_held_slot",
			wantSteps: []string{},
			wantHeld:  []int{0},
		},
		{
			name:       "new_holder_observation_after_acquisition_tears_down_held_slot",
			observeNew: true,
			wantSteps:  []string{strings.Join(teardown[0], " "), strings.Join(teardown[1], " "), strings.Join(teardown[2], " ")},
			wantHeld:   []int{},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			rc := dpRuntimeConfig(0)
			d := newDataPlane(rc)
			applyPassWith(t, d, (&runRecorder{}).run, rc, resultsFor([]int{0}))
			d.observeOtherHolder()
			d.startLeading()
			if tc.observeNew {
				d.observeOtherHolder()
			}

			rec := &runRecorder{}
			if err := d.standbyPass(context.Background(), rec.run, rc, func() bool { return false }, testLogger(t)); err != nil {
				t.Fatalf("standbyPass: %v", err)
			}
			if got := stepLines(t, rec.snapshot()); !slices.Equal(got, tc.wantSteps) {
				t.Errorf("standby actions = %v, want %v", got, tc.wantSteps)
			}
			if got := d.heldSlots(); !slices.Equal(got, tc.wantHeld) {
				t.Errorf("held slots = %v, want %v", got, tc.wantHeld)
			}
		})
	}
}
