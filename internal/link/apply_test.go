package link

import (
	"context"
	"errors"
	"fmt"
	"net"
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
		{Name: "web", PublicPort: 443, Protocol: "tcp", ClusterIP: "10.96.1.10", TargetPort: 8443},
		{Name: "game", PublicPort: 30000, Protocol: "udp", ClusterIP: "10.96.2.20", TargetPort: 9000},
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

func TestBuildApplyCommandsWithMTU(t *testing.T) {
	rc := RuntimeConfig{
		WireGuard: WireGuard{Address: "10.99.0.2/32", MTU: 1380},
	}
	const wgConfPath = "/tmp/gateway-wg.conf"
	const nftRuleset = "table inet gateway { }"

	cmds := buildApplyCommands(rc, wgConfPath, nftRuleset)

	want := []command{
		{name: "ip", args: []string{"link", "add", "wg0", "type", "wireguard"}},
		{name: "wg", args: []string{"setconf", "wg0", wgConfPath}},
		{name: "ip", args: []string{"addr", "add", "10.99.0.2/32", "dev", "wg0"}},
		{name: "ip", args: []string{"link", "set", "wg0", "mtu", "1380", "up"}},
		{name: "nft", args: []string{"-f", "-"}, stdin: nftRuleset},
	}

	assertCommandPlan(t, cmds, want)
}

func TestBuildApplyCommandsNoMTU(t *testing.T) {
	rc := RuntimeConfig{
		WireGuard: WireGuard{Address: "10.99.0.2/32", MTU: 0},
	}
	cmds := buildApplyCommands(rc, "/tmp/wg.conf", "ruleset")

	want := []command{
		{name: "ip", args: []string{"link", "add", "wg0", "type", "wireguard"}},
		{name: "wg", args: []string{"setconf", "wg0", "/tmp/wg.conf"}},
		{name: "ip", args: []string{"addr", "add", "10.99.0.2/32", "dev", "wg0"}},
		{name: "ip", args: []string{"link", "set", "wg0", "up"}},
		{name: "nft", args: []string{"-f", "-"}, stdin: "ruleset"},
	}

	assertCommandPlan(t, cmds, want)
}

// TestBuildReloadCommands pins the non-disruptive reload contract: the plan uses
// wg syncconf and nft -f and issues no ip link del or add, so an established
// tunnel survives a config change.
func TestBuildReloadCommands(t *testing.T) {
	const (
		wgConfPath = "/tmp/gateway-wg.conf"
		nftRuleset = "table inet gateway { }"
	)

	cmds := buildReloadCommands(wgConfPath, nftRuleset)

	want := []command{
		{name: "wg", args: []string{"syncconf", "wg0", wgConfPath}},
		{name: "nft", args: []string{"-f", "-"}, stdin: nftRuleset},
	}
	assertCommandPlan(t, cmds, want)

	for _, c := range cmds {
		if c.name == "ip" {
			t.Errorf("reload plan must not touch the interface, found ip command: %v", c.args)
		}
	}
}

// TestFirstIPv4 pins the resolver's IPv4-selection rule: the first IPv4 wins
// regardless of position, and a slice with no IPv4 reports not-ok rather than
// handing an IPv6 address to the IPv4-only DNAT.
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
	}
}

// runRecorder is an injectable runner that records every command and fails the
// call whose name matches failOn, to drive a mid-plan failure without shelling
// out.
type runRecorder struct {
	mu     sync.Mutex
	cmds   []command
	failOn string
}

func (r *runRecorder) run(_ context.Context, c command) error {
	r.mu.Lock()
	r.cmds = append(r.cmds, c)
	r.mu.Unlock()
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

// TestApplyTearsDownInterfaceOnMidPlanFailure pins the self-heal contract: a step
// failing after wg0 is created makes Apply issue a teardown ip link del wg0 (following
// the add, not the leading idempotency delete) so the next reload rebuilds.
func TestApplyTearsDownInterfaceOnMidPlanFailure(t *testing.T) {
	rec := &runRecorder{failOn: "wg"}

	rc := RuntimeConfig{
		WireGuard: WireGuard{
			Address: "10.99.0.2/32",
			Peer: Peer{
				Endpoint:            "203.0.113.5:51820",
				AllowedIPs:          []string{"10.99.0.1/32"},
				PersistentKeepalive: 25,
			},
		},
		Forwards: []Forward{{Name: "web", PublicPort: 443, Protocol: "tcp", Service: "web.default.svc", TargetPort: 8443}},
	}
	resolve := func(_ context.Context, _ string) (string, error) { return "10.96.1.10", nil }

	if err := Apply(context.Background(), rec.run, rc, "priv", "pub", resolve); err == nil {
		t.Fatal("Apply should propagate the injected mid-plan failure")
	}

	cmds := rec.snapshot()
	addIdx := indexOfCommand(cmds, "ip", "link", "add", "wg0", "type", "wireguard")
	if addIdx < 0 {
		t.Fatalf("expected wg0 to be created; recorded: %+v", cmds)
	}
	delIdx := indexOfCommand(cmds[addIdx+1:], "ip", "link", "del", "wg0")
	if delIdx < 0 {
		t.Fatalf("expected teardown ip link del wg0 after the add; recorded: %+v", cmds)
	}
}

// indexOfCommand returns the index of the first command in cmds whose name and
// args exactly match name and args, or -1 if none match.
func indexOfCommand(cmds []command, name string, args ...string) int {
	want := strings.Join(args, " ")
	for i, c := range cmds {
		if c.name == name && strings.Join(c.args, " ") == want {
			return i
		}
	}
	return -1
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

// scriptedLookup returns a lookup stub that records every call into rec and
// returns results[i] on the i-th call, reusing the last entry past the script so
// a fully-failing script keeps failing.
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

// TestDefaultResolve pins the resolver contract that keeps a retarget from
// blackholing the DNAT: queries are A-only and absolute, a transient failure or
// empty result is retried, and exhausting the retries fails loud.
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

// TestDefaultResolveContextCancellationAborts pins that a cancelled context breaks the
// retry wait promptly: one lookup fails to enter the wait, then the call returns the
// context error well inside one retry delay.
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
