package link

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
)

// command is a single shell-out step in the apply plan. stdin, when non-empty,
// is piped to the process's standard input.
type command struct {
	name  string
	args  []string
	stdin string
}

// buildApplyCommands returns the ordered list of ip/wg/nft invocations that
// bring up wg0 and load the nftables ruleset. The mtu argument is included only
// when rc.WireGuard.MTU is greater than zero. Removing any stale wg0 is handled
// by Apply, not here, because it tolerates failure and so is not part of the
// must-succeed plan.
func buildApplyCommands(rc RuntimeConfig, wgConfPath, nftRuleset string) []command {
	linkSet := []string{"link", "set", "wg0"}
	if rc.WireGuard.MTU > 0 {
		linkSet = append(linkSet, "mtu", strconv.Itoa(rc.WireGuard.MTU))
	}
	linkSet = append(linkSet, "up")

	return []command{
		{name: "ip", args: []string{"link", "add", "wg0", "type", "wireguard"}},
		{name: "wg", args: []string{"setconf", "wg0", wgConfPath}},
		{name: "ip", args: []string{"addr", "add", rc.WireGuard.Address, "dev", "wg0"}},
		{name: "ip", args: linkSet},
		{name: "nft", args: []string{"-f", "-"}, stdin: nftRuleset},
	}
}

// Apply brings up the WireGuard tunnel and programs nftables from rc.
//
// It assumes a kube-proxy data plane (iptables or ipvs) so that masqueraded
// traffic to a Service ClusterIP is load-balanced to a backend pod. Cilium's
// kube-proxy replacement bypasses the ClusterIP DNAT that this design relies on
// and is out of scope for v1.
//
// resolve maps a Service DNS name to a single address; pass defaultResolve in
// production. privKey and peerPubKey are base64 WireGuard keys read from mounted
// Secret files. The rendered config (which embeds the private key) is written to
// a 0600 temp file for the duration of the call and removed before return. A
// best-effort delete of any pre-existing wg0 runs first so Apply is idempotent
// across restarts.
func Apply(ctx context.Context, rc RuntimeConfig, privKey, peerPubKey string, resolve func(ctx context.Context, host string) (string, error)) error {
	_ = run(ctx, command{name: "ip", args: []string{"link", "del", "wg0"}})

	wgConf, err := os.CreateTemp("", "cyno-wg-*.conf")
	if err != nil {
		return fmt.Errorf("create wg conf temp file: %w", err)
	}
	wgConfPath := wgConf.Name()
	defer os.Remove(wgConfPath)

	if err := wgConf.Chmod(0o600); err != nil {
		wgConf.Close()
		return fmt.Errorf("chmod wg conf %s: %w", wgConfPath, err)
	}
	wgConfText, err := RenderWGConf(rc, privKey, peerPubKey)
	if err != nil {
		wgConf.Close()
		return fmt.Errorf("render wg conf %s: %w", wgConfPath, err)
	}
	if _, err := wgConf.WriteString(wgConfText); err != nil {
		wgConf.Close()
		return fmt.Errorf("write wg conf %s: %w", wgConfPath, err)
	}
	if err := wgConf.Close(); err != nil {
		return fmt.Errorf("close wg conf %s: %w", wgConfPath, err)
	}

	resolved, err := resolveForwards(ctx, rc.Forwards, resolve)
	if err != nil {
		return fmt.Errorf("resolve forwards: %w", err)
	}

	nftRuleset, err := RenderNftables(resolved)
	if err != nil {
		return fmt.Errorf("render nftables ruleset: %w", err)
	}
	for _, c := range buildApplyCommands(rc, wgConfPath, nftRuleset) {
		if err := run(ctx, c); err != nil {
			return err
		}
	}
	return nil
}

// resolveForwards resolves each forward's Service to a ClusterIP using resolve,
// preserving order. An empty result from resolve is treated as a failure.
func resolveForwards(ctx context.Context, forwards []Forward, resolve func(ctx context.Context, host string) (string, error)) ([]ResolvedForward, error) {
	out := make([]ResolvedForward, 0, len(forwards))
	for _, f := range forwards {
		ip, err := resolve(ctx, f.Service)
		if err != nil {
			return nil, fmt.Errorf("forward %q: resolve %s: %w", f.Name, f.Service, err)
		}
		out = append(out, ResolvedForward{
			Name:       f.Name,
			PublicPort: f.PublicPort,
			Protocol:   f.Protocol,
			ClusterIP:  ip,
			TargetPort: f.TargetPort,
		})
	}
	return out, nil
}

// defaultResolve returns the first address for host from the default resolver.
func defaultResolve(ctx context.Context, host string) (string, error) {
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return "", fmt.Errorf("lookup %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("lookup %s: no addresses", host)
	}
	return addrs[0], nil
}

// run executes c, piping stdin when set and folding captured stderr into the
// returned error so failures are diagnosable from logs alone.
func run(ctx context.Context, c command) error {
	cmd := exec.CommandContext(ctx, c.name, c.args...)
	if c.stdin != "" {
		cmd.Stdin = bytes.NewReader([]byte(c.stdin))
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %v: %w: %s", c.name, c.args, err, stderr.String())
	}
	return nil
}
