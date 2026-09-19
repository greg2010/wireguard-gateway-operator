package link

import (
	"slices"
	"strings"
	"testing"
)

// TestTeardownCommandPlan pins the exported teardown plan in both modes, which an out-of-process
// harness replays step by step.
func TestTeardownCommandPlan(t *testing.T) {
	gwIdent := NewGatewayIdentity(3)
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
			name: "local_single_slot",
			rc: RuntimeConfig{
				TrafficPolicy: TrafficPolicyLocal,
				Identity:      &gwIdent,
				WireGuard:     WireGuard{Peers: []Peer{{Slot: 0, PublicKey: "PUB="}}},
			},
			wantPlan: [][]string{
				{"nft", "delete", "table", "inet", "gw3"},
				{"ip", "rule", "del", "fwmark", "0x00030000/0xffff0000", "lookup", "100003", "priority", "10000"},
				{"ip", "route", "flush", "table", "100003"},
				{"ip", "link", "del", "wg-gw3"},
			},
		},
		{
			name: "local_two_slots",
			rc: RuntimeConfig{
				TrafficPolicy: TrafficPolicyLocal,
				Identity:      &gwIdent,
				WireGuard:     WireGuard{Peers: []Peer{{Slot: 0, PublicKey: "PUB0="}, {Slot: 2, PublicKey: "PUB2="}}},
			},
			wantPlan: [][]string{
				{"nft", "delete", "table", "inet", "gw3"},
				{"ip", "rule", "del", "fwmark", "0x00030000/0xffff0000", "lookup", "100003", "priority", "10000"},
				{"ip", "route", "flush", "table", "100003"},
				{"ip", "link", "del", "wg-gw3"},
				{"ip", "rule", "del", "fwmark", "0x02030000/0xffff0000", "lookup", "100515", "priority", "10000"},
				{"ip", "route", "flush", "table", "100515"},
				{"ip", "link", "del", "wg-gw3-2"},
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assertSteps(t, TeardownCommands(tc.rc), tc.wantPlan)
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
