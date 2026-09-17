package link

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestResolveForwards(t *testing.T) {
	forwards := []Forward{
		{Name: "web", PublicPort: 443, Protocol: "tcp", Service: "web.default.svc", TargetPort: 8443},
		{Name: "game", PublicPort: 30000, Protocol: "udp", Service: "game.default.svc", TargetPort: 9000},
	}

	clusterIPs := map[string]string{
		"web.default.svc":  "10.96.1.10",
		"game.default.svc": "10.96.2.20",
	}
	resolve := func(_ context.Context, host string) (string, error) {
		ip, ok := clusterIPs[host]
		if !ok {
			return "", fmt.Errorf("no record for %s", host)
		}
		return ip, nil
	}

	got, err := resolveForwards(context.Background(), forwards, resolve)
	if err != nil {
		t.Fatalf("resolveForwards: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	want := []ResolvedForward{
		{Name: "web", PublicPort: 443, Protocol: "tcp", Target: "10.96.1.10", TargetPort: 8443},
		{Name: "game", PublicPort: 30000, Protocol: "udp", Target: "10.96.2.20", TargetPort: 9000},
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("resolved[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestResolveForwardsError(t *testing.T) {
	resolve := func(_ context.Context, _ string) (string, error) {
		return "", fmt.Errorf("nxdomain")
	}
	_, err := resolveForwards(context.Background(), []Forward{
		{Name: "broken", Service: "missing.svc"},
	}, resolve)
	if err == nil {
		t.Fatal("expected error for unresolvable service")
	}
	if !strings.Contains(err.Error(), "broken") || !strings.Contains(err.Error(), "missing.svc") {
		t.Errorf("error should name the forward and service: %v", err)
	}
}

// testLocalIdentity is the GatewayIdentity every Local RuntimeConfig fixture in this file uses.
func testLocalIdentity() *GatewayIdentity { return new(NewGatewayIdentity(3)) }

func TestBuildApplyCommands(t *testing.T) {
	const nftRuleset = "table inet gateway { }"

	tcs := []struct {
		name          string
		rc            RuntimeConfig
		wgConfPaths   map[int]string
		ifaceExists   map[int]bool
		localForwards []ResolvedForward
		wantPlans     []slotPlan
	}{
		{
			name:        "cluster_with_mtu_absent",
			rc:          RuntimeConfig{WireGuard: WireGuard{Address: "10.99.0.2/32", MTU: 1380}},
			wgConfPaths: map[int]string{0: "/tmp/gateway-wg.conf"},
			ifaceExists: map[int]bool{0: false},
			wantPlans: []slotPlan{{Slot: 0, Cmds: []command{
				{name: "ip", args: []string{"link", "add", "wg0", "type", "wireguard"}},
				{name: "wg", args: []string{"syncconf", "wg0", "/tmp/gateway-wg.conf"}},
				{name: "ip", args: []string{"addr", "replace", "10.99.0.2/32", "dev", "wg0"}},
				{name: "ip", args: []string{"link", "set", "wg0", "mtu", "1380", "up"}},
			}}},
		},
		{
			name:        "cluster_no_mtu_absent",
			rc:          RuntimeConfig{WireGuard: WireGuard{Address: "10.99.0.2/32"}},
			wgConfPaths: map[int]string{0: "/tmp/gateway-wg.conf"},
			ifaceExists: map[int]bool{0: false},
			wantPlans: []slotPlan{{Slot: 0, Cmds: []command{
				{name: "ip", args: []string{"link", "add", "wg0", "type", "wireguard"}},
				{name: "wg", args: []string{"syncconf", "wg0", "/tmp/gateway-wg.conf"}},
				{name: "ip", args: []string{"addr", "replace", "10.99.0.2/32", "dev", "wg0"}},
				{name: "ip", args: []string{"link", "set", "wg0", "up"}},
			}}},
		},
		{
			name:        "cluster_with_mtu_present_no_link_add",
			rc:          RuntimeConfig{WireGuard: WireGuard{Address: "10.99.0.2/32", MTU: 1380}},
			wgConfPaths: map[int]string{0: "/tmp/gateway-wg.conf"},
			ifaceExists: map[int]bool{0: true},
			wantPlans: []slotPlan{{Slot: 0, Cmds: []command{
				{name: "wg", args: []string{"syncconf", "wg0", "/tmp/gateway-wg.conf"}},
				{name: "ip", args: []string{"addr", "replace", "10.99.0.2/32", "dev", "wg0"}},
				{name: "ip", args: []string{"link", "set", "wg0", "mtu", "1380", "up"}},
			}}},
		},
		{
			name: "local_with_mtu_absent",
			rc: RuntimeConfig{
				TrafficPolicy: TrafficPolicyLocal,
				Identity:      testLocalIdentity(),
				WireGuard: WireGuard{
					Address: "10.244.1.7/32", MTU: 1380,
					Peers: []Peer{{Slot: 0, PublicKey: "PUB="}},
				},
			},
			wgConfPaths: map[int]string{0: "/tmp/gateway-wg-0.conf"},
			ifaceExists: map[int]bool{0: false},
			localForwards: []ResolvedForward{
				{Name: "tcp-8443", PublicPort: 8443, Protocol: "tcp", Target: "10.244.1.7", TargetPort: 9080},
				{Name: "udp-8443", PublicPort: 8443, Protocol: "udp", Target: "10.244.1.7", TargetPort: 9080},
			},
			wantPlans: []slotPlan{{Slot: 0, Cmds: []command{
				{name: "ip", args: []string{"link", "add", "wg-gw3", "type", "wireguard"}},
				{name: "wg", args: []string{"syncconf", "wg-gw3", "/tmp/gateway-wg-0.conf"}},
				{name: "ip", args: []string{"addr", "replace", "10.244.1.7/32", "dev", "wg-gw3"}},
				{name: "ip", args: []string{"link", "set", "wg-gw3", "mtu", "1380", "up"}},
				{writePath: HostProcSysNetPath + "/ipv4/conf/wg-gw3/rp_filter", writeValue: "0"},
				{writePath: HostProcSysNetPath + "/ipv4/conf/wg-gw3/forwarding", writeValue: "1"},
				{name: "ip", args: []string{"route", "replace", "default", "dev", "wg-gw3", "table", "100003"}},
				{name: "ip", args: []string{"route", "flush", "table", "100003", "type", "throw"}},
				{name: "ip", args: []string{"route", "replace", "throw", "10.244.1.7/32", "table", "100003"}},
				{name: "ip", args: []string{"rule", "add", "fwmark", "0x00030000/0xffff0000", "lookup", "100003", "priority", "10000"}, tolerateExists: true},
			}}},
		},
		{
			name: "local_zero_slots",
			rc: RuntimeConfig{
				TrafficPolicy: TrafficPolicyLocal,
				Identity:      testLocalIdentity(),
				WireGuard:     WireGuard{Address: "10.244.1.7/32", Peers: []Peer{}},
			},
			wgConfPaths: map[int]string{},
			ifaceExists: map[int]bool{},
			wantPlans:   []slotPlan{},
		},
		{
			name: "local_two_slots",
			rc: RuntimeConfig{
				TrafficPolicy: TrafficPolicyLocal,
				Identity:      testLocalIdentity(),
				WireGuard: WireGuard{
					Address: "10.244.1.7/32",
					Peers:   []Peer{{Slot: 0, PublicKey: "A="}, {Slot: 2, PublicKey: "B="}},
				},
			},
			wgConfPaths: map[int]string{0: "/tmp/gateway-wg-0.conf", 2: "/tmp/gateway-wg-2.conf"},
			ifaceExists: map[int]bool{0: true, 2: false},
			localForwards: []ResolvedForward{
				{Name: "a", PublicPort: 8443, Protocol: "tcp", Target: "10.244.1.9", TargetPort: 9080},
			},
			wantPlans: []slotPlan{
				{Slot: 0, Cmds: []command{
					{name: "wg", args: []string{"syncconf", "wg-gw3", "/tmp/gateway-wg-0.conf"}},
					{name: "ip", args: []string{"addr", "replace", "10.244.1.7/32", "dev", "wg-gw3"}},
					{name: "ip", args: []string{"link", "set", "wg-gw3", "up"}},
					{writePath: HostProcSysNetPath + "/ipv4/conf/wg-gw3/rp_filter", writeValue: "0"},
					{writePath: HostProcSysNetPath + "/ipv4/conf/wg-gw3/forwarding", writeValue: "1"},
					{name: "ip", args: []string{"route", "replace", "default", "dev", "wg-gw3", "table", "100003"}},
					{name: "ip", args: []string{"route", "flush", "table", "100003", "type", "throw"}},
					{name: "ip", args: []string{"route", "replace", "throw", "10.244.1.9/32", "table", "100003"}},
					{name: "ip", args: []string{"rule", "add", "fwmark", "0x00030000/0xffff0000", "lookup", "100003", "priority", "10000"}, tolerateExists: true},
				}},
				{Slot: 2, Cmds: []command{
					{name: "ip", args: []string{"link", "add", "wg-gw3-2", "type", "wireguard"}},
					{name: "wg", args: []string{"syncconf", "wg-gw3-2", "/tmp/gateway-wg-2.conf"}},
					{name: "ip", args: []string{"addr", "replace", "10.244.1.7/32", "dev", "wg-gw3-2"}},
					{name: "ip", args: []string{"link", "set", "wg-gw3-2", "up"}},
					{writePath: HostProcSysNetPath + "/ipv4/conf/wg-gw3-2/rp_filter", writeValue: "0"},
					{writePath: HostProcSysNetPath + "/ipv4/conf/wg-gw3-2/forwarding", writeValue: "1"},
					{name: "ip", args: []string{"route", "replace", "default", "dev", "wg-gw3-2", "table", "100515"}},
					{name: "ip", args: []string{"route", "flush", "table", "100515", "type", "throw"}},
					{name: "ip", args: []string{"route", "replace", "throw", "10.244.1.9/32", "table", "100515"}},
					{name: "ip", args: []string{"rule", "add", "fwmark", "0x02030000/0xffff0000", "lookup", "100515", "priority", "10000"}, tolerateExists: true},
				}},
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			plans, final := buildApplyCommands(tc.rc, tc.wgConfPaths, nftRuleset, tc.ifaceExists, tc.localForwards)
			if len(plans) != len(tc.wantPlans) {
				t.Fatalf("plan count = %d, want %d\ngot: %+v", len(plans), len(tc.wantPlans), plans)
			}
			for i, want := range tc.wantPlans {
				if plans[i].Slot != want.Slot {
					t.Errorf("plan[%d].Slot = %d, want %d", i, plans[i].Slot, want.Slot)
				}
				assertCommandPlan(t, plans[i].Cmds, want.Cmds)
			}
			wantFinal := command{name: "nft", args: []string{"-f", "-"}, stdin: nftRuleset}
			assertCommandPlan(t, []command{final}, []command{wantFinal})
		})
	}
}

func TestLocalThrowTargets(t *testing.T) {
	tcs := []struct {
		name     string
		forwards []ResolvedForward
		want     []string
	}{
		{name: "empty", forwards: nil, want: []string{}},
		{
			name: "duplicates_collapse",
			forwards: []ResolvedForward{
				{Name: "a", Target: "10.244.1.7"},
				{Name: "b", Target: "10.244.1.7"},
			},
			want: []string{"10.244.1.7"},
		},
		{
			name: "unsorted_input_is_sorted",
			forwards: []ResolvedForward{
				{Name: "a", Target: "10.244.1.9"},
				{Name: "b", Target: "10.244.1.7"},
				{Name: "c", Target: "10.244.1.8"},
			},
			want: []string{"10.244.1.7", "10.244.1.8", "10.244.1.9"},
		},
		{
			name: "empty_cluster_ip_skipped",
			forwards: []ResolvedForward{
				{Name: "a", Target: ""},
				{Name: "b", Target: "10.244.1.7"},
			},
			want: []string{"10.244.1.7"},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got := localThrowTargets(tc.forwards)
			if !slices.Equal(got, tc.want) {
				t.Errorf("localThrowTargets = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestApplyIsIdempotent runs Apply twice: the second pass adds no interface, and an ip rule add
// the kernel rejects as an identical rule does not fail the apply.
func TestApplyIsIdempotent(t *testing.T) {
	rec := &runRecorder{}
	linkShowCalls := 0
	ruleAddCalls := 0
	rec.hook = func(c command) error {
		if c.name == "ip" && len(c.args) >= 2 && c.args[0] == "link" && c.args[1] == "show" {
			linkShowCalls++
			if linkShowCalls >= 2 {
				return nil
			}
			return fmt.Errorf("ip %v: exit status 1: Device %q does not exist", c.args, c.args[2])
		}
		if c.name == "ip" && len(c.args) >= 2 && c.args[0] == "rule" && c.args[1] == "add" {
			ruleAddCalls++
			if ruleAddCalls >= 2 {
				return fmt.Errorf("ip %v: exit status 2: RTNETLINK answers: File exists", c.args)
			}
			return nil
		}
		return nil
	}

	rc := RuntimeConfig{
		TrafficPolicy: TrafficPolicyLocal,
		Identity:      testLocalIdentity(),
		WireGuard: WireGuard{
			Address: "10.244.1.7/32",
			Peers: []Peer{{
				Slot:                0,
				PublicKey:           "PUB=",
				Endpoint:            "203.0.113.5:51820",
				AllowedIPs:          []string{"0.0.0.0/0"},
				PersistentKeepalive: 25,
			}},
		},
	}
	resolve := func(_ context.Context, _ string) (string, error) { return "10.96.1.10", nil }

	if _, _, err := Apply(context.Background(), rec.run, rc, "priv", resolve, nil, nil, testLogger(t)); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	if _, _, err := Apply(context.Background(), rec.run, rc, "priv", resolve, nil, nil, testLogger(t)); err != nil {
		t.Fatalf("second Apply: %v", err)
	}

	cmds := rec.snapshot()
	linkAdds := 0
	ruleAdds := 0
	for _, c := range cmds {
		if c.name == "ip" && len(c.args) >= 2 && c.args[0] == "link" && c.args[1] == "add" {
			linkAdds++
		}
		if c.name == "ip" && len(c.args) >= 2 && c.args[0] == "rule" && c.args[1] == "add" {
			ruleAdds++
		}
	}
	if linkAdds != 1 {
		t.Errorf("ip link add count across both applies = %d, want 1 (only the first apply creates the interface)", linkAdds)
	}
	if ruleAdds != 2 {
		t.Errorf("ip rule add count across both applies = %d, want 2 (one per apply)", ruleAdds)
	}
}

// TestConntrackFlushCommands pins the tuple diff conntrackFlushCommands computes: a tuple previous
// carries that current drops gets one flush command, in previous's order, duplicates collapsed.
func TestConntrackFlushCommands(t *testing.T) {
	a := ResolvedForward{Name: "a", PublicPort: 443, Protocol: "tcp", Target: "10.96.1.10", TargetPort: 8443}
	aDup := ResolvedForward{Name: "a-dup", PublicPort: 443, Protocol: "tcp", Target: "10.96.1.10", TargetPort: 8443}
	aRetargeted := ResolvedForward{Name: "a", PublicPort: 443, Protocol: "tcp", Target: "10.96.1.20", TargetPort: 8443}
	aPortChanged := ResolvedForward{Name: "a", PublicPort: 443, Protocol: "tcp", Target: "10.96.1.10", TargetPort: 9443}
	aProtoChanged := ResolvedForward{Name: "a", PublicPort: 443, Protocol: "udp", Target: "10.96.1.10", TargetPort: 8443}
	b := ResolvedForward{Name: "b", PublicPort: 30000, Protocol: "udp", Target: "10.96.2.20", TargetPort: 9000}
	bRetargeted := ResolvedForward{Name: "b", PublicPort: 30000, Protocol: "udp", Target: "10.96.2.30", TargetPort: 9000}

	cmdFor := func(f ResolvedForward) command {
		return command{name: "conntrack", args: ConntrackFlushArgs(f), tolerateNoFlows: true}
	}

	tcs := []struct {
		name     string
		previous []ResolvedForward
		current  []ResolvedForward
		want     []command
	}{
		{name: "nil_previous", current: []ResolvedForward{a}},
		{name: "identical_sets", previous: []ResolvedForward{a, b}, current: []ResolvedForward{a, b}},
		{name: "target_changed", previous: []ResolvedForward{a}, current: []ResolvedForward{aRetargeted}, want: []command{cmdFor(a)}},
		{name: "target_port_changed", previous: []ResolvedForward{a}, current: []ResolvedForward{aPortChanged}, want: []command{cmdFor(a)}},
		{name: "protocol_changed", previous: []ResolvedForward{a}, current: []ResolvedForward{aProtoChanged}, want: []command{cmdFor(a)}},
		{name: "forward_removed", previous: []ResolvedForward{a, b}, current: []ResolvedForward{b}, want: []command{cmdFor(a)}},
		{name: "forward_added", previous: []ResolvedForward{a}, current: []ResolvedForward{a, b}},
		{
			name:     "two_forwards_retargeted",
			previous: []ResolvedForward{a, b},
			current:  []ResolvedForward{aRetargeted, bRetargeted},
			want:     []command{cmdFor(a), cmdFor(b)},
		},
		{
			name:     "same_tuple_twice_in_previous_collapses",
			previous: []ResolvedForward{a, aDup},
			want:     []command{cmdFor(a)},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assertCommandPlan(t, conntrackFlushCommands(tc.previous, tc.current), tc.want)
		})
	}
}

// TestApplyFlushesRetargetedForwards runs Apply twice with a retargeted Cluster forward: the first
// call's exact plan carries no conntrack step; the second's ends with the nft step then one flush.
func TestApplyFlushesRetargetedForwards(t *testing.T) {
	rc := RuntimeConfig{
		WireGuard: WireGuard{Address: "10.99.0.2/32"},
		Forwards:  []Forward{{Name: "web", PublicPort: 443, Protocol: "tcp", Service: "web.default.svc", TargetPort: 8443}},
	}
	targets := []string{"10.96.1.10", "10.96.1.20"}
	call := 0
	resolve := func(_ context.Context, _ string) (string, error) {
		ip := targets[call]
		call++
		return ip, nil
	}
	forwardA := ResolvedForward{Name: "web", PublicPort: 443, Protocol: "tcp", Target: "10.96.1.10", TargetPort: 8443}
	forwardB := ResolvedForward{Name: "web", PublicPort: 443, Protocol: "tcp", Target: "10.96.1.20", TargetPort: 8443}

	first := &runRecorder{}
	_, applied1, err := Apply(context.Background(), first.run, rc, "priv", resolve, nil, nil, testLogger(t))
	if err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	if len(applied1) != 1 || applied1[0] != forwardA {
		t.Fatalf("first applied = %+v, want [%+v]", applied1, forwardA)
	}
	cmds1 := first.snapshot()
	nftA, err := RenderNftables(rc, []ResolvedForward{forwardA})
	if err != nil {
		t.Fatalf("RenderNftables A: %v", err)
	}
	assertCommandPlan(t, cmds1, []command{
		{name: "ip", args: []string{"link", "show", "wg0"}},
		{name: "wg", args: []string{"syncconf", "wg0", syncconfPath(t, cmds1)}},
		{name: "ip", args: []string{"addr", "replace", "10.99.0.2/32", "dev", "wg0"}},
		{name: "ip", args: []string{"link", "set", "wg0", "up"}},
		{name: "nft", args: []string{"-f", "-"}, stdin: nftA},
	})

	second := &runRecorder{}
	_, applied2, err := Apply(context.Background(), second.run, rc, "priv", resolve, applied1, nil, testLogger(t))
	if err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if len(applied2) != 1 || applied2[0] != forwardB {
		t.Fatalf("second applied = %+v, want [%+v]", applied2, forwardB)
	}
	cmds2 := second.snapshot()
	nftB, err := RenderNftables(rc, []ResolvedForward{forwardB})
	if err != nil {
		t.Fatalf("RenderNftables B: %v", err)
	}
	assertCommandPlan(t, cmds2, []command{
		{name: "ip", args: []string{"link", "show", "wg0"}},
		{name: "wg", args: []string{"syncconf", "wg0", syncconfPath(t, cmds2)}},
		{name: "ip", args: []string{"addr", "replace", "10.99.0.2/32", "dev", "wg0"}},
		{name: "ip", args: []string{"link", "set", "wg0", "up"}},
		{name: "nft", args: []string{"-f", "-"}, stdin: nftB},
		{name: "conntrack", args: ConntrackFlushArgs(forwardA), tolerateNoFlows: true},
	})
}

// syncconfPath returns the wg conf path a recorded wg syncconf step ran with, since
// os.CreateTemp generates the path fresh on every Apply call.
func syncconfPath(t *testing.T, cmds []command) string {
	t.Helper()
	for _, c := range cmds {
		if c.name == "wg" && len(c.args) == 3 && c.args[0] == "syncconf" {
			return c.args[2]
		}
	}
	t.Fatal("no wg syncconf step found")
	return ""
}

// TestApplyToleratesEmptyFlush pins that a zero-match conntrack deletion succeeds the apply, the
// way EEXIST does for an ip rule add, and that any other conntrack failure fails it.
func TestApplyToleratesEmptyFlush(t *testing.T) {
	rc := RuntimeConfig{
		WireGuard: WireGuard{Address: "10.99.0.2/32"},
		Forwards:  []Forward{{Name: "web", PublicPort: 443, Protocol: "tcp", Service: "web.default.svc", TargetPort: 8443}},
	}
	forwardA := ResolvedForward{Name: "web", PublicPort: 443, Protocol: "tcp", Target: "10.96.1.10", TargetPort: 8443}
	forwardB := ResolvedForward{Name: "web", PublicPort: 443, Protocol: "tcp", Target: "10.96.1.20", TargetPort: 8443}
	resolveB := func(_ context.Context, _ string) (string, error) { return "10.96.1.20", nil }

	tcs := []struct {
		name         string
		conntrackErr error
		wantErr      bool
		wantErrSub   string
	}{
		{
			name:         "zero_matches_is_success",
			conntrackErr: fmt.Errorf("conntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted"),
		},
		{
			name:         "other_failure_fails_the_apply",
			conntrackErr: fmt.Errorf("conntrack v1.4.8 (conntrack-tools): permission denied"),
			wantErr:      true,
			wantErrSub:   "flush conntrack",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			rec := &runRecorder{hook: func(c command) error {
				if c.name == "conntrack" {
					return tc.conntrackErr
				}
				return nil
			}}
			_, applied, err := Apply(context.Background(), rec.run, rc, "priv", resolveB, []ResolvedForward{forwardA}, nil, testLogger(t))
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrSub) {
					t.Fatalf("Apply error = %v, want one containing %q", err, tc.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if len(applied) != 1 || applied[0] != forwardB {
				t.Errorf("applied = %+v, want [%+v]", applied, forwardB)
			}
		})
	}
}

// TestIfaceExists pins that only ip(8)'s ENODEV wording means an absent interface and
// that every other probe failure reaches the caller.
func TestIfaceExists(t *testing.T) {
	notFound := errors.New(`ip [link show wg-gw1]: exec: "ip": executable file not found in $PATH`)

	tcs := []struct {
		name       string
		runErr     error
		want       bool
		wantErrIs  error
		wantErrNil bool
	}{
		{name: "present", wantErrNil: true, want: true},
		{name: "absent", runErr: errors.New(`ip [link show wg-gw1]: exit status 1: Device "wg-gw1" does not exist`), wantErrNil: true},
		{name: "probe_failure_is_returned", runErr: notFound, wantErrIs: notFound},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			rec := &runRecorder{hook: func(command) error { return tc.runErr }}
			got, err := ifaceExists(context.Background(), rec.run, "wg-gw1")
			if got != tc.want {
				t.Errorf("ifaceExists = %v, want %v", got, tc.want)
			}
			switch {
			case tc.wantErrNil && err != nil:
				t.Errorf("error = %v, want nil", err)
			case !tc.wantErrNil && !errors.Is(err, tc.wantErrIs):
				t.Errorf("error = %v, want one wrapping %v", err, tc.wantErrIs)
			}
		})
	}
}

// TestApplyFailsOnProbeError pins that a probe failure with no ENODEV wording fails the
// whole apply instead of being read as an absent interface.
func TestApplyFailsOnProbeError(t *testing.T) {
	probeErr := errors.New(`ip [link show wg-gw3]: exec: "ip": executable file not found in $PATH`)
	rec := &runRecorder{hook: func(c command) error {
		if c.name == "ip" && len(c.args) >= 2 && c.args[0] == "link" && c.args[1] == "show" {
			return probeErr
		}
		return nil
	}}

	rc := RuntimeConfig{
		TrafficPolicy: TrafficPolicyLocal,
		Identity:      testLocalIdentity(),
		WireGuard: WireGuard{
			Address: "10.244.1.7/32",
			Peers: []Peer{{
				Slot:                0,
				PublicKey:           "PUB=",
				Endpoint:            "203.0.113.5:51820",
				AllowedIPs:          []string{"0.0.0.0/0"},
				PersistentKeepalive: 25,
			}},
		},
	}
	resolve := func(_ context.Context, _ string) (string, error) { return "10.96.1.10", nil }

	_, _, err := Apply(context.Background(), rec.run, rc, "priv", resolve, nil, nil, testLogger(t))
	if !errors.Is(err, probeErr) {
		t.Fatalf("Apply = %v, want one wrapping %v", err, probeErr)
	}
}

// TestApplyOneFailingSlotOthersContinue keeps healthy slots running after one fails.
func TestApplyOneFailingSlotOthersContinue(t *testing.T) {
	rec := &runRecorder{hook: func(c command) error {
		if c.writePath != "" && strings.Contains(c.writePath, "wg-gw3-1") {
			return fmt.Errorf("write %s: permission denied", c.writePath)
		}
		return nil
	}}

	rc := RuntimeConfig{
		TrafficPolicy: TrafficPolicyLocal,
		Identity:      testLocalIdentity(),
		WireGuard: WireGuard{
			Address: "10.244.1.7/32",
			Peers: []Peer{
				{Slot: 0, PublicKey: "A=", Endpoint: "203.0.113.5:51820", AllowedIPs: []string{"0.0.0.0/0"}},
				{Slot: 1, PublicKey: "B=", Endpoint: "203.0.113.6:51820", AllowedIPs: []string{"0.0.0.0/0"}},
			},
		},
	}
	resolve := func(_ context.Context, _ string) (string, error) { return "", nil }

	results, _, err := Apply(context.Background(), rec.run, rc, "priv", resolve, nil, nil, testLogger(t))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %+v, want 2 entries", results)
	}
	var slot0, slot1 SlotResult
	for _, r := range results {
		switch r.Slot {
		case 0:
			slot0 = r
		case 1:
			slot1 = r
		}
	}
	if !slot0.Applied || slot0.Err != nil {
		t.Errorf("slot 0 = %+v, want Applied=true Err=nil", slot0)
	}
	if slot1.Applied || slot1.Err == nil {
		t.Errorf("slot 1 = %+v, want Applied=false with a non-nil Err", slot1)
	}

	wantSteps := []string{
		"ip link show wg-gw3",
		"ip link show wg-gw3-1",
		"wg syncconf wg-gw3 " + wgConfArg,
		"ip addr replace 10.244.1.7/32 dev wg-gw3",
		"ip link set wg-gw3 up",
		"write " + HostProcSysNetPath + "/ipv4/conf/wg-gw3/rp_filter=0",
		"write " + HostProcSysNetPath + "/ipv4/conf/wg-gw3/forwarding=1",
		"ip route replace default dev wg-gw3 table 100003",
		"ip route flush table 100003 type throw",
		"ip rule add fwmark 0x00030000/0xffff0000 lookup 100003 priority 10000",
		"wg syncconf wg-gw3-1 " + wgConfArg,
		"ip addr replace 10.244.1.7/32 dev wg-gw3-1",
		"ip link set wg-gw3-1 up",
		"write " + HostProcSysNetPath + "/ipv4/conf/wg-gw3-1/rp_filter=0",
		"nft -f -",
	}
	if steps := stepLines(t, rec.snapshot()); !slices.Equal(steps, wantSteps) {
		t.Errorf("executed steps =\n%s\nwant\n%s", strings.Join(steps, "\n"), strings.Join(wantSteps, "\n"))
	}
}

// wgConfArg stands for the per-slot wg(8) config path in a compared step list: os.CreateTemp
// names it afresh every run.
const wgConfArg = "<wg.conf>"

// stepLines renders every recorded step as one comparable line, a process as its argv and a
// sysctl as "write <path>=<value>", with each slot's wg config path replaced by wgConfArg.
func stepLines(t *testing.T, cmds []command) []string {
	t.Helper()
	pattern := filepath.Join(os.TempDir(), "gateway-wg-*.conf")
	lines := make([]string, 0, len(cmds))
	for _, c := range cmds {
		if c.writePath != "" {
			lines = append(lines, fmt.Sprintf("write %s=%s", c.writePath, c.writeValue))
			continue
		}
		args := slices.Clone(c.args)
		for i, a := range args {
			match, err := filepath.Match(pattern, a)
			if err != nil {
				t.Fatalf("match %q against %q: %v", a, pattern, err)
			}
			if match {
				args[i] = wgConfArg
			}
		}
		lines = append(lines, strings.Join(append([]string{c.name}, args...), " "))
	}
	return lines
}

// TestApplyRulesetFailureHoldsEveryAttemptedSlot pins the final nft -f failing: a Gateway-wide
// error and one unapplied result per attempted slot, so the caller holds the state they created.
func TestApplyRulesetFailureHoldsEveryAttemptedSlot(t *testing.T) {
	nftErr := fmt.Errorf("nft -f -: exit status 1: Error: syntax error")
	slotErr := fmt.Errorf("ip [link set wg-gw3-2 up]: exit status 2: Operation not permitted")

	tcs := []struct {
		name string
		// failSlotStep fails slot 2's link set step, the per-slot failure the ruleset failure
		// must not overwrite.
		failSlotStep bool
		wantErrs     []error
	}{
		{
			name:     "both_slots_carry_the_ruleset_error",
			wantErrs: []error{nftErr, nftErr},
		},
		{
			name:         "a_slot_that_failed_its_own_step_keeps_its_error",
			failSlotStep: true,
			wantErrs:     []error{nftErr, slotErr},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			rec := &runRecorder{hook: func(c command) error {
				if c.name == "nft" {
					return nftErr
				}
				if tc.failSlotStep && c.name == "ip" && slices.Equal(c.args, []string{"link", "set", "wg-gw3-2", "up"}) {
					return slotErr
				}
				return nil
			}}

			rc := RuntimeConfig{
				TrafficPolicy: TrafficPolicyLocal,
				Identity:      testLocalIdentity(),
				WireGuard: WireGuard{
					Address: "10.244.1.7/32",
					Peers: []Peer{
						{Slot: 0, PublicKey: "A=", Endpoint: "203.0.113.5:51820", AllowedIPs: []string{"0.0.0.0/0"}},
						{Slot: 2, PublicKey: "B=", Endpoint: "203.0.113.6:51820", AllowedIPs: []string{"0.0.0.0/0"}},
					},
				},
			}
			resolve := func(_ context.Context, _ string) (string, error) { return "", nil }

			results, _, err := Apply(context.Background(), rec.run, rc, "priv", resolve, nil, nil, testLogger(t))
			if err == nil || !errors.Is(err, nftErr) {
				t.Fatalf("Apply error = %v, want one wrapping %v", err, nftErr)
			}
			wantSlots := []int{0, 2}
			if len(results) != len(wantSlots) {
				t.Fatalf("results = %+v, want one entry per attempted slot %v", results, wantSlots)
			}
			for i, want := range wantSlots {
				if results[i].Slot != want || results[i].Applied {
					t.Errorf("results[%d] = {slot %d applied %t}, want {slot %d applied false}",
						i, results[i].Slot, results[i].Applied, want)
				}
				if !errors.Is(results[i].Err, tc.wantErrs[i]) {
					t.Errorf("results[%d].Err = %v, want one wrapping %v", i, results[i].Err, tc.wantErrs[i])
				}
			}

			d := newDataPlane(rc)
			d.mu.Lock()
			d.record(results)
			d.mu.Unlock()
			if held := d.heldSlots(); !slices.Equal(held, wantSlots) {
				t.Errorf("held slots after the failed pass = %v, want %v", held, wantSlots)
			}
		})
	}
}

// TestRunStep pins the EEXIST tolerance: only a step that asks for it survives a
// "File exists" failure, and no step survives any other failure.
func TestRunStep(t *testing.T) {
	exists := fmt.Errorf("ip [rule add]: exit status 2: RTNETLINK answers: File exists")
	other := fmt.Errorf("ip [rule add]: exit status 1: Invalid argument")

	tcs := []struct {
		name    string
		cmd     command
		runErr  error
		wantErr error
	}{
		{name: "success", cmd: command{name: "ip"}},
		{name: "tolerated_exists", cmd: command{name: "ip", tolerateExists: true}, runErr: exists},
		{name: "tolerating_step_other_failure", cmd: command{name: "ip", tolerateExists: true}, runErr: other, wantErr: other},
		{name: "untolerating_step_exists", cmd: command{name: "ip"}, runErr: exists, wantErr: exists},
		{name: "untolerating_step_other_failure", cmd: command{name: "ip"}, runErr: other, wantErr: other},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			run := func(_ context.Context, _ command) error {
				calls++
				return tc.runErr
			}
			err := runStep(context.Background(), run, tc.cmd, testLogger(t))
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("runStep = %v, want %v", err, tc.wantErr)
			}
			if calls != 1 {
				t.Errorf("run calls = %d, want 1", calls)
			}
		})
	}
}

// TestRulePlanShape pins one tolerant fwmark rule add, no apply-time delete, and exactly one
// delete in the fence: an apply-time delete leaves the rule missing until the add re-runs.
func TestRulePlanShape(t *testing.T) {
	rc := RuntimeConfig{
		TrafficPolicy: TrafficPolicyLocal,
		Identity:      testLocalIdentity(),
		WireGuard: WireGuard{
			Address: "10.244.1.7/32",
			Peers:   []Peer{{Slot: 0, PublicKey: "PUB="}},
		},
	}

	plans, _ := buildApplyCommands(rc, map[int]string{0: "/tmp/wg.conf"}, "table inet gw3 { }", map[int]bool{0: true}, nil)
	if len(plans) != 1 {
		t.Fatalf("plan count = %d, want 1", len(plans))
	}
	adds, dels := countRuleSteps(plans[0].Cmds)
	if adds != 1 || dels != 0 {
		t.Errorf("apply plan has %d rule add and %d rule del steps, want 1 and 0", adds, dels)
	}
	for _, c := range plans[0].Cmds {
		if isRuleStep(c, "add") && !c.tolerateExists {
			t.Error("the apply plan's rule add does not tolerate an already-present rule")
		}
	}
}

func countRuleSteps(cmds []command) (adds, dels int) {
	for _, c := range cmds {
		if isRuleStep(c, "add") {
			adds++
		}
		if isRuleStep(c, "del") {
			dels++
		}
	}
	return adds, dels
}

func isRuleStep(c command, verb string) bool {
	return c.name == "ip" && len(c.args) >= 2 && c.args[0] == "rule" && c.args[1] == verb
}

func TestPreCheckLocal(t *testing.T) {
	tcs := []struct {
		name        string
		ipForward   *string
		rpFilterAll *string
		wantReason  string
		// wantMessageSub is a substring the fault message must carry, used where the
		// message names the file the pre-check could not read.
		wantMessageSub string
	}{
		{
			name:        "ip_forward_1_all_0_no_fault",
			ipForward:   new("1"),
			rpFilterAll: new("0"),
		},
		{
			name:       "ip_forward_0_apply_failed",
			ipForward:  new("0"),
			wantReason: FaultApplyFailed,
		},
		{
			name:        "all_1_rp_filter_strict",
			ipForward:   new("1"),
			rpFilterAll: new("1"),
			wantReason:  FaultRPFilterStrict,
		},
		{
			name:        "all_2_no_fault",
			ipForward:   new("1"),
			rpFilterAll: new("2"),
		},
		{
			name:           "missing_file_is_an_apply_failed_fault",
			wantReason:     FaultApplyFailed,
			wantMessageSub: "ipv4/ip_forward",
		},
		{
			name:           "unparseable_value_is_an_apply_failed_fault",
			ipForward:      new("not-a-number"),
			wantReason:     FaultApplyFailed,
			wantMessageSub: "parse",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			prefix := t.TempDir()
			if tc.ipForward != nil {
				writeSysctl(t, prefix, "ipv4/ip_forward", *tc.ipForward)
			}
			if tc.rpFilterAll != nil {
				writeSysctl(t, prefix, "ipv4/conf/all/rp_filter", *tc.rpFilterAll)
			}

			fault := preCheckLocalAt(prefix, "node-a")
			if fault.Reason != tc.wantReason {
				t.Errorf("fault.Reason = %q, want %q (message: %q)", fault.Reason, tc.wantReason, fault.Message)
			}
			if tc.wantMessageSub != "" && !strings.Contains(fault.Message, tc.wantMessageSub) {
				t.Errorf("fault.Message = %q, want substring %q", fault.Message, tc.wantMessageSub)
			}
		})
	}
}

func writeSysctl(t *testing.T, prefix, rel, value string) {
	t.Helper()
	path := filepath.Join(prefix, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestFirstIPv4 pins that the first IPv4 wins regardless of position and that a slice without one
// reports not-ok rather than handing an IPv6 address to the IPv4-only DNAT.
func TestFirstIPv4(t *testing.T) {
	tests := []struct {
		name   string
		addrs  []net.IP
		want   string
		wantOK bool
	}{
		{
			name:   "ipv4 first",
			addrs:  []net.IP{net.ParseIP("10.96.1.10"), net.ParseIP("fd00::1")},
			want:   "10.96.1.10",
			wantOK: true,
		},
		{
			name:   "ipv6 then ipv4",
			addrs:  []net.IP{net.ParseIP("fd00::1"), net.ParseIP("10.96.2.20")},
			want:   "10.96.2.20",
			wantOK: true,
		},
		{
			name:   "ipv6 only",
			addrs:  []net.IP{net.ParseIP("fd00::1"), net.ParseIP("2001:db8::2")},
			want:   "",
			wantOK: false,
		},
		{
			name:   "empty",
			addrs:  nil,
			want:   "",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := firstIPv4(tt.addrs)
			if ok != tt.wantOK {
				t.Fatalf("firstIPv4 ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Errorf("firstIPv4 = %q, want %q", got, tt.want)
			}
		})
	}
}

func assertCommandPlan(t *testing.T, got, want []command) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("plan length = %d, want %d\ngot: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].name != want[i].name {
			t.Errorf("cmd[%d] name = %q, want %q", i, got[i].name, want[i].name)
		}
		if strings.Join(got[i].args, " ") != strings.Join(want[i].args, " ") {
			t.Errorf("cmd[%d] args = %v, want %v", i, got[i].args, want[i].args)
		}
		if got[i].stdin != want[i].stdin {
			t.Errorf("cmd[%d] stdin = %q, want %q", i, got[i].stdin, want[i].stdin)
		}
		if got[i].writePath != want[i].writePath {
			t.Errorf("cmd[%d] writePath = %q, want %q", i, got[i].writePath, want[i].writePath)
		}
		if got[i].writeValue != want[i].writeValue {
			t.Errorf("cmd[%d] writeValue = %q, want %q", i, got[i].writeValue, want[i].writeValue)
		}
		if got[i].tolerateExists != want[i].tolerateExists {
			t.Errorf("cmd[%d] tolerateExists = %v, want %v", i, got[i].tolerateExists, want[i].tolerateExists)
		}
		if got[i].tolerateNoFlows != want[i].tolerateNoFlows {
			t.Errorf("cmd[%d] tolerateNoFlows = %v, want %v", i, got[i].tolerateNoFlows, want[i].tolerateNoFlows)
		}
	}
}

// runRecorder records every command and fails the call whose name matches failOn, to drive a
// mid-plan failure without shelling out. hook, when set, overrides the failOn behaviour.
type runRecorder struct {
	mu     sync.Mutex
	cmds   []command
	failOn string
	hook   func(c command) error
}

func (r *runRecorder) run(_ context.Context, c command) error {
	r.mu.Lock()
	r.cmds = append(r.cmds, c)
	r.mu.Unlock()
	if r.hook != nil {
		return r.hook(c)
	}
	if c.name == r.failOn {
		return fmt.Errorf("injected failure for %s %v", c.name, c.args)
	}
	return nil
}

func (r *runRecorder) snapshot() []command {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]command(nil), r.cmds...)
}

// lookupCall records the address family and host of one injected lookup call, so
// a test can assert the query is A-only and absolute.
type lookupCall struct {
	network string
	host    string
}

// lookupResult is one scripted return from the injected lookup function.
type lookupResult struct {
	addrs []net.IP
	err   error
}

// scriptedLookup records every call into rec and returns results[i] on the i-th call, reusing the
// last entry past the script so a fully-failing script keeps failing.
func scriptedLookup(rec *[]lookupCall, results []lookupResult) func(context.Context, string, string) ([]net.IP, error) {
	return func(_ context.Context, network, host string) ([]net.IP, error) {
		*rec = append(*rec, lookupCall{network: network, host: host})
		i := len(*rec) - 1
		if i >= len(results) {
			i = len(results) - 1
		}
		return results[i].addrs, results[i].err
	}
}

// TestDefaultResolve pins the resolver contract that keeps a retarget from blackholing the DNAT:
// queries are A-only and absolute, a transient failure or empty result is retried, exhaustion fails
func TestDefaultResolve(t *testing.T) {
	ok := lookupResult{addrs: []net.IP{net.ParseIP("10.96.1.10")}}
	ipv6Only := lookupResult{addrs: []net.IP{net.ParseIP("fd00::1")}}
	failed := lookupResult{err: fmt.Errorf("nxdomain")}
	empty := lookupResult{}

	tests := []struct {
		name      string
		host      string
		results   []lookupResult
		wantIP    string
		wantErr   bool
		wantCalls int
		wantHost  string
	}{
		{
			name:      "absolute_and_a_only_on_first_success",
			host:      "web.default.svc.cluster.local",
			results:   []lookupResult{ok},
			wantIP:    "10.96.1.10",
			wantCalls: 1,
			wantHost:  "web.default.svc.cluster.local.",
		},
		{
			name:      "already_absolute_host_not_double_dotted",
			host:      "web.default.svc.cluster.local.",
			results:   []lookupResult{ok},
			wantIP:    "10.96.1.10",
			wantCalls: 1,
			wantHost:  "web.default.svc.cluster.local.",
		},
		{
			name:      "retries_then_succeeds",
			host:      "web.default.svc.cluster.local",
			results:   []lookupResult{failed, empty, ok},
			wantIP:    "10.96.1.10",
			wantCalls: 3,
			wantHost:  "web.default.svc.cluster.local.",
		},
		{
			name:      "empty_result_is_retryable",
			host:      "web.default.svc.cluster.local",
			results:   []lookupResult{empty, ok},
			wantIP:    "10.96.1.10",
			wantCalls: 2,
			wantHost:  "web.default.svc.cluster.local.",
		},
		{
			name:      "ipv6_only_is_retryable_then_fails",
			host:      "web.default.svc.cluster.local",
			results:   []lookupResult{ipv6Only},
			wantErr:   true,
			wantCalls: resolveAttempts,
			wantHost:  "web.default.svc.cluster.local.",
		},
		{
			name:      "exhausts_attempts_then_errors",
			host:      "web.default.svc.cluster.local",
			results:   []lookupResult{failed},
			wantErr:   true,
			wantCalls: resolveAttempts,
			wantHost:  "web.default.svc.cluster.local.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls []lookupCall
			resolve := newResolver(scriptedLookup(&calls, tt.results))

			ip, err := resolve(context.Background(), tt.host)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("resolve(%q) = %q, want error", tt.host, ip)
				}
			} else {
				if err != nil {
					t.Fatalf("resolve(%q): %v", tt.host, err)
				}
				if ip != tt.wantIP {
					t.Errorf("ip = %q, want %q", ip, tt.wantIP)
				}
			}

			if len(calls) != tt.wantCalls {
				t.Fatalf("lookup call count = %d, want %d", len(calls), tt.wantCalls)
			}
			for i, c := range calls {
				if c.network != "ip4" {
					t.Errorf("call[%d] network = %q, want ip4", i, c.network)
				}
				if c.host != tt.wantHost {
					t.Errorf("call[%d] host = %q, want %q", i, c.host, tt.wantHost)
				}
			}
		})
	}
}

// TestDefaultResolveContextCancellationAborts pins that a cancelled context breaks the retry wait:
// the call returns the context error well inside one retry delay.
func TestDefaultResolveContextCancellationAborts(t *testing.T) {
	var calls int
	resolve := newResolver(func(_ context.Context, _, _ string) ([]net.IP, error) {
		calls++
		return nil, fmt.Errorf("nxdomain")
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, err := resolve(ctx, "web.default.svc.cluster.local")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("resolve should error when context is cancelled")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled in chain", err)
	}
	if calls != 1 {
		t.Errorf("lookup call count = %d, want 1 (one attempt before the aborted wait)", calls)
	}
	if elapsed >= resolveRetryDelay {
		t.Errorf("resolve took %v, want well under the %v retry delay", elapsed, resolveRetryDelay)
	}
}

// TestRenderConfigModeBranch pins which forward set each mode renders: Local renders the supplied
// localForwards and never resolves, its targets being pod IPs; Cluster renders what resolve says.
func TestRenderConfigModeBranch(t *testing.T) {
	clusterIPs := map[string]string{
		"web.default.svc":  "10.96.1.10",
		"game.default.svc": "10.96.2.20",
	}

	// Both Cluster rows drive the same resolver; the rows differ only in whether the
	// mode is the default or spelled out.
	clusterResolve := func(t *testing.T, calls *[]string) func(context.Context, string) (string, error) {
		return func(_ context.Context, host string) (string, error) {
			*calls = append(*calls, host)
			ip, ok := clusterIPs[host]
			if !ok {
				t.Errorf("resolver asked for unexpected host %q", host)
				return "", fmt.Errorf("no record for %s", host)
			}
			return ip, nil
		}
	}

	tcs := []struct {
		name          string
		rc            RuntimeConfig
		localForwards []ResolvedForward
		// resolve is built per case so the Local case can fail the test from inside it.
		resolve   func(t *testing.T, calls *[]string) func(ctx context.Context, host string) (string, error)
		wantDNAT  []string
		wantCalls []string
	}{
		{
			name: "local_renders_supplied_forwards_without_resolving",
			rc: RuntimeConfig{
				TrafficPolicy: TrafficPolicyLocal,
				Identity:      testLocalIdentity(),
				WireGuard:     WireGuard{Address: "10.99.0.2/32", Peers: []Peer{{Slot: 0, PublicKey: "PUB="}}},
				Forwards: []Forward{
					{Name: "web", PublicPort: 443, Protocol: "tcp", Service: "web.default.svc", TargetPort: 8443},
				},
			},
			localForwards: []ResolvedForward{
				{Name: "web", PublicPort: 443, Protocol: "tcp", Target: "10.244.1.7", TargetPort: 8443},
				{Name: "game", PublicPort: 30000, Protocol: "udp", Target: "10.244.1.8", TargetPort: 9000},
			},
			resolve: func(t *testing.T, _ *[]string) func(context.Context, string) (string, error) {
				return func(_ context.Context, host string) (string, error) {
					t.Errorf("resolver called for %q in Local mode; the endpoint watcher already picked the target", host)
					return "10.96.9.9", nil
				}
			},
			wantDNAT: []string{"10.244.1.7 : 8443", "10.244.1.8 : 9000"},
		},
		{
			name: "cluster_by_default_renders_resolved_targets",
			rc: RuntimeConfig{
				WireGuard: WireGuard{Address: "10.99.0.2/32", Peers: []Peer{{Slot: 0, PublicKey: "PUB="}}},
				Forwards: []Forward{
					{Name: "web", PublicPort: 443, Protocol: "tcp", Service: "web.default.svc", TargetPort: 8443},
					{Name: "game", PublicPort: 30000, Protocol: "udp", Service: "game.default.svc", TargetPort: 9000},
				},
			},
			localForwards: []ResolvedForward{
				{Name: "ignored", PublicPort: 443, Protocol: "tcp", Target: "10.244.1.7", TargetPort: 8443},
			},
			resolve:   clusterResolve,
			wantDNAT:  []string{"10.96.1.10 : 8443", "10.96.2.20 : 9000"},
			wantCalls: []string{"web.default.svc", "game.default.svc"},
		},
		{
			name: "cluster_explicit_policy_renders_resolved_targets",
			rc: RuntimeConfig{
				TrafficPolicy: TrafficPolicyCluster,
				WireGuard:     WireGuard{Address: "10.99.0.2/32", Peers: []Peer{{Slot: 0, PublicKey: "PUB="}}},
				Forwards: []Forward{
					{Name: "web", PublicPort: 443, Protocol: "tcp", Service: "web.default.svc", TargetPort: 8443},
					{Name: "game", PublicPort: 30000, Protocol: "udp", Service: "game.default.svc", TargetPort: 9000},
				},
			},
			localForwards: []ResolvedForward{
				{Name: "ignored", PublicPort: 443, Protocol: "tcp", Target: "10.244.1.7", TargetPort: 8443},
			},
			resolve:   clusterResolve,
			wantDNAT:  []string{"10.96.1.10 : 8443", "10.96.2.20 : 9000"},
			wantCalls: []string{"web.default.svc", "game.default.svc"},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			_, ruleset, _, cleanup, err := renderConfig(context.Background(), tc.rc, "priv", tc.resolve(t, &calls), tc.localForwards, testLogger(t))
			if err != nil {
				t.Fatalf("renderConfig: %v", err)
			}
			defer func() {
				if err := cleanup(false); err != nil {
					t.Errorf("cleanup: %v", err)
				}
			}()

			if got := dnatTargets(ruleset); !slices.Equal(got, tc.wantDNAT) {
				t.Errorf("rendered DNAT targets = %v, want %v\n--- ruleset ---\n%s", got, tc.wantDNAT, ruleset)
			}
			if !slices.Equal(calls, tc.wantCalls) {
				t.Errorf("resolver calls = %v, want %v", calls, tc.wantCalls)
			}
		})
	}
}

// dnatTargets returns the "<address> : <port>" of every DNAT rule in a rendered ruleset,
// in rule order.
func dnatTargets(ruleset string) []string {
	var targets []string
	for line := range strings.SplitSeq(ruleset, "\n") {
		if _, after, ok := strings.Cut(line, "dnat ip to "); ok {
			targets = append(targets, strings.TrimSpace(after))
		}
	}
	return targets
}
