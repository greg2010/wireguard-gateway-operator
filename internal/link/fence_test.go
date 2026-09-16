package link

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// TestTeardownCommandPlan pins the exported fence plan in both modes, which an out-of-process
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

func TestFencingTableNameDistinctFromDataPlaneTable(t *testing.T) {
	gwIdent := NewGatewayIdentity(3)
	rc := RuntimeConfig{TrafficPolicy: TrafficPolicyLocal, Identity: &gwIdent}

	got := fencingTableName(rc)
	if got != "fence-gw3" {
		t.Errorf("fencingTableName = %q, want %q", got, "fence-gw3")
	}
	if got == nftTableName(rc) {
		t.Errorf("fencingTableName %q collides with the data-plane table name %q", got, nftTableName(rc))
	}
}

// TestFencingRuleset admits loopback and applied-slot health traffic.
func TestFencingRuleset(t *testing.T) {
	gwIdent := NewGatewayIdentity(3)
	rc := RuntimeConfig{
		TrafficPolicy: TrafficPolicyLocal,
		Identity:      &gwIdent,
		HealthPort:    gwIdent.HealthPort,
		WireGuard:     WireGuard{Peers: []Peer{{Slot: 0, PublicKey: "PUB0="}, {Slot: 2, PublicKey: "PUB2="}}},
	}
	const (
		head = "add table inet fence-gw3\n" +
			"flush table inet fence-gw3\n" +
			"table inet fence-gw3 {\n" +
			"\tchain input {\n" +
			"\t\ttype filter hook input priority filter; policy accept;\n" +
			"\t\ttcp dport 27003 iifname \"lo\" accept\n"
		tail = "\t\ttcp dport 27003 drop\n\t}\n}\n"
	)

	tcs := []struct {
		name     string
		admitted []int
		want     string
	}{
		{
			name: "no_applied_slot_admits_loopback_alone",
			want: head + tail,
		},
		{
			name:     "one_applied_slot_admits_its_interface",
			admitted: []int{0},
			want:     head + "\t\ttcp dport 27003 iifname \"wg-gw3\" accept\n" + tail,
		},
		{
			name:     "every_applied_slot_is_admitted_in_slot_order",
			admitted: []int{2, 0},
			want: head + "\t\ttcp dport 27003 iifname \"wg-gw3\" accept\n" +
				"\t\ttcp dport 27003 iifname \"wg-gw3-2\" accept\n" + tail,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if got := FencingRuleset(rc, tc.admitted); got != tc.want {
				t.Errorf("fencing ruleset = %q, want %q", got, tc.want)
			}

			rec := &runRecorder{}
			if err := InstallFencing(context.Background(), rec.run, rc, tc.admitted); err != nil {
				t.Fatalf("InstallFencing: %v", err)
			}
			cmds := rec.snapshot()
			if len(cmds) != 1 {
				t.Fatalf("InstallFencing ran %d commands, want 1", len(cmds))
			}
			if cmds[0].name != "nft" || !slices.Equal(cmds[0].args, []string{"-f", "-"}) {
				t.Fatalf("InstallFencing command = %s %v, want nft -f -", cmds[0].name, cmds[0].args)
			}
			if cmds[0].stdin != tc.want {
				t.Errorf("installed ruleset = %q, want %q", cmds[0].stdin, tc.want)
			}
		})
	}
}

// TestRemoveFencingDeletesByName pins that RemoveFencing issues exactly one delete of the
// fencing table, never the data-plane table.
func TestRemoveFencingDeletesByName(t *testing.T) {
	gwIdent := NewGatewayIdentity(3)
	rc := RuntimeConfig{TrafficPolicy: TrafficPolicyLocal, Identity: &gwIdent}

	rec := &runRecorder{}
	if err := RemoveFencing(context.Background(), rec.run, rc); err != nil {
		t.Fatalf("RemoveFencing: %v", err)
	}
	assertRanPlan(t, rec.snapshot(), [][]string{{"nft", "delete", "table", "inet", "fence-gw3"}})
}
