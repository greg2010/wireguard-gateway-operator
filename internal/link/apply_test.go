package link

import (
	"context"
	"fmt"
	"strings"
	"testing"
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
	resolve := func(_ context.Context, host string) (string, error) {
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
	const wgConfPath = "/tmp/cyno-wg.conf"
	const nftRuleset = "table inet cyno { }"

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
