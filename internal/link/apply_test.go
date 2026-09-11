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

func TestBuildApplyCommands(t *testing.T) {
	const wgConfPath = "/tmp/gateway-wg.conf"
	const nftRuleset = "table inet gateway { }"

	localRC := RuntimeConfig{
		TrafficPolicy: TrafficPolicyLocal,
		Identity:      new(NewIdentity(3)),
		WireGuard:     WireGuard{Address: "10.244.1.7/32"},
	}

	tcs := []struct {
		name          string
		rc            RuntimeConfig
		ifaceExists   bool
		localForwards []ResolvedForward
		want          []command
	}{
		{
			name: "cluster_with_mtu_absent",
			rc: RuntimeConfig{
				WireGuard: WireGuard{Address: "10.99.0.2/32", MTU: 1380},
			},
			ifaceExists: false,
			want: []command{
				{name: "ip", args: []string{"link", "add", "wg0", "type", "wireguard"}},
				{name: "wg", args: []string{"syncconf", "wg0", wgConfPath}},
				{name: "ip", args: []string{"addr", "replace", "10.99.0.2/32", "dev", "wg0"}},
				{name: "ip", args: []string{"link", "set", "wg0", "mtu", "1380", "up"}},
				{name: "nft", args: []string{"-f", "-"}, stdin: nftRuleset},
			},
		},
		{
			name: "cluster_no_mtu_absent",
			rc: RuntimeConfig{
				WireGuard: WireGuard{Address: "10.99.0.2/32"},
			},
			ifaceExists: false,
			want: []command{
				{name: "ip", args: []string{"link", "add", "wg0", "type", "wireguard"}},
				{name: "wg", args: []string{"syncconf", "wg0", wgConfPath}},
				{name: "ip", args: []string{"addr", "replace", "10.99.0.2/32", "dev", "wg0"}},
				{name: "ip", args: []string{"link", "set", "wg0", "up"}},
				{name: "nft", args: []string{"-f", "-"}, stdin: nftRuleset},
			},
		},
		{
			name: "cluster_with_mtu_present_no_link_add",
			rc: RuntimeConfig{
				WireGuard: WireGuard{Address: "10.99.0.2/32", MTU: 1380},
			},
			ifaceExists: true,
			want: []command{
				{name: "wg", args: []string{"syncconf", "wg0", wgConfPath}},
				{name: "ip", args: []string{"addr", "replace", "10.99.0.2/32", "dev", "wg0"}},
				{name: "ip", args: []string{"link", "set", "wg0", "mtu", "1380", "up"}},
				{name: "nft", args: []string{"-f", "-"}, stdin: nftRuleset},
			},
		},
		{
			name:        "local_with_mtu_absent",
			rc:          RuntimeConfig{TrafficPolicy: TrafficPolicyLocal, Identity: new(NewIdentity(3)), WireGuard: WireGuard{Address: "10.244.1.7/32", MTU: 1380}},
			ifaceExists: false,
			localForwards: []ResolvedForward{
				{Name: "tcp-8443", PublicPort: 8443, Protocol: "tcp", Target: "10.244.1.7", TargetPort: 9080},
				{Name: "udp-8443", PublicPort: 8443, Protocol: "udp", Target: "10.244.1.7", TargetPort: 9080},
			},
			want: []command{
				{name: "ip", args: []string{"link", "add", "wg-gw3", "type", "wireguard"}},
				{name: "wg", args: []string{"syncconf", "wg-gw3", wgConfPath}},
				{name: "ip", args: []string{"addr", "replace", "10.244.1.7/32", "dev", "wg-gw3"}},
				{name: "ip", args: []string{"link", "set", "wg-gw3", "mtu", "1380", "up"}},
				{writePath: HostProcSysNetPath + "/ipv4/conf/wg-gw3/rp_filter", writeValue: "0"},
				{writePath: HostProcSysNetPath + "/ipv4/conf/wg-gw3/forwarding", writeValue: "1"},
				{name: "ip", args: []string{"route", "replace", "default", "dev", "wg-gw3", "table", "100003"}},
				{name: "ip", args: []string{"route", "flush", "table", "100003", "type", "throw"}},
				{name: "ip", args: []string{"route", "replace", "throw", "10.244.1.7/32", "table", "100003"}},
				{name: "ip", args: []string{"rule", "add", "fwmark", "0x00030000/0xffff0000", "lookup", "100003", "priority", "10000"}, tolerateExists: true},
				{name: "nft", args: []string{"-f", "-"}, stdin: nftRuleset},
			},
		},
		{
			name:        "local_with_mtu_present",
			rc:          localRC,
			ifaceExists: true,
			localForwards: []ResolvedForward{
				{Name: "b", PublicPort: 8444, Protocol: "tcp", Target: "10.244.1.9", TargetPort: 9081},
				{Name: "a", PublicPort: 8443, Protocol: "tcp", Target: "10.244.1.7", TargetPort: 9080},
			},
			want: []command{
				{name: "wg", args: []string{"syncconf", "wg-gw3", wgConfPath}},
				{name: "ip", args: []string{"addr", "replace", "10.244.1.7/32", "dev", "wg-gw3"}},
				{name: "ip", args: []string{"link", "set", "wg-gw3", "up"}},
				{writePath: HostProcSysNetPath + "/ipv4/conf/wg-gw3/rp_filter", writeValue: "0"},
				{writePath: HostProcSysNetPath + "/ipv4/conf/wg-gw3/forwarding", writeValue: "1"},
				{name: "ip", args: []string{"route", "replace", "default", "dev", "wg-gw3", "table", "100003"}},
				{name: "ip", args: []string{"route", "flush", "table", "100003", "type", "throw"}},
				{name: "ip", args: []string{"route", "replace", "throw", "10.244.1.7/32", "table", "100003"}},
				{name: "ip", args: []string{"route", "replace", "throw", "10.244.1.9/32", "table", "100003"}},
				{name: "ip", args: []string{"rule", "add", "fwmark", "0x00030000/0xffff0000", "lookup", "100003", "priority", "10000"}, tolerateExists: true},
				{name: "nft", args: []string{"-f", "-"}, stdin: nftRuleset},
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			cmds := buildApplyCommands(tc.rc, wgConfPath, nftRuleset, tc.ifaceExists, tc.localForwards)
			assertCommandPlan(t, cmds, tc.want)
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
		Identity:      new(NewIdentity(3)),
		WireGuard: WireGuard{
			Address: "10.244.1.7/32",
			Peer: Peer{
				Endpoint:            "203.0.113.5:51820",
				AllowedIPs:          []string{"0.0.0.0/0"},
				PersistentKeepalive: 25,
			},
		},
	}
	resolve := func(_ context.Context, _ string) (string, error) { return "10.96.1.10", nil }

	if err := Apply(context.Background(), rec.run, rc, "priv", "pub", resolve, nil, testLogger(t)); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	if err := Apply(context.Background(), rec.run, rc, "priv", "pub", resolve, nil, testLogger(t)); err != nil {
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
		Identity:      new(NewIdentity(3)),
		WireGuard: WireGuard{
			Address: "10.244.1.7/32",
			Peer: Peer{
				Endpoint:            "203.0.113.5:51820",
				AllowedIPs:          []string{"0.0.0.0/0"},
				PersistentKeepalive: 25,
			},
		},
	}
	resolve := func(_ context.Context, _ string) (string, error) { return "10.96.1.10", nil }

	err := Apply(context.Background(), rec.run, rc, "priv", "pub", resolve, nil, testLogger(t))
	if !errors.Is(err, probeErr) {
		t.Fatalf("Apply = %v, want one wrapping %v", err, probeErr)
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
		Identity:      new(NewIdentity(3)),
		WireGuard:     WireGuard{Address: "10.244.1.7/32"},
	}

	apply := buildApplyCommands(rc, "/tmp/wg.conf", "table inet gw3 { }", true, nil)
	adds, dels := countRuleSteps(apply)
	if adds != 1 || dels != 0 {
		t.Errorf("apply plan has %d rule add and %d rule del steps, want 1 and 0", adds, dels)
	}
	for _, c := range apply {
		if isRuleStep(c, "add") && !c.tolerateExists {
			t.Error("the apply plan's rule add does not tolerate an already-present rule")
		}
	}

	rec := &runRecorder{}
	if err := Teardown(context.Background(), rec.run, rc); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	adds, dels = countRuleSteps(rec.snapshot())
	if adds != 0 || dels != 1 {
		t.Errorf("teardown plan has %d rule add and %d rule del steps, want 0 and 1", adds, dels)
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
				Identity:      new(NewIdentity(3)),
				WireGuard:     WireGuard{Address: "10.99.0.2/32"},
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
				WireGuard: WireGuard{Address: "10.99.0.2/32"},
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
				WireGuard:     WireGuard{Address: "10.99.0.2/32"},
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
			_, ruleset, cleanup, err := renderConfig(context.Background(), tc.rc, "priv", "pub", tc.resolve(t, &calls), tc.localForwards)
			if err != nil {
				t.Fatalf("renderConfig: %v", err)
			}
			defer cleanup()

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
