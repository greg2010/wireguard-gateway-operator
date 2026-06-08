package link

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// command is a single shell-out step in the apply plan; stdin, when non-empty, is
// piped to the process's standard input.
type command struct {
	name  string
	args  []string
	stdin string
}

// runner executes a single command. Tests inject a recorder to exercise the
// command plan without shelling out.
type runner func(ctx context.Context, c command) error

// buildApplyCommands returns the ordered ip/wg/nft invocations that bring up wg0 and
// load the nftables ruleset. The mtu argument is included only when MTU is positive.
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

// buildReloadCommands reconciles an already-up wg0 onto the new config without
// tearing the interface down, so the tunnel and its handshake survive. Address and
// MTU are creation-time properties Apply owns and are left untouched here.
func buildReloadCommands(wgConfPath, nftRuleset string) []command {
	return []command{
		{name: "wg", args: []string{"syncconf", "wg0", wgConfPath}},
		{name: "nft", args: []string{"-f", "-"}, stdin: nftRuleset},
	}
}

// Apply builds wg0 from scratch and programs nftables from rc, deleting any stale wg0
// first for idempotency. It mutates host network state, must not run concurrently, and
// assumes kube-proxy DNAT; Cilium kube-proxy-replacement is unsupported.
func Apply(ctx context.Context, run runner, rc RuntimeConfig, privKey, peerPubKey string, resolve func(ctx context.Context, host string) (string, error)) error {
	_ = run(ctx, command{name: "ip", args: []string{"link", "del", "wg0"}})

	wgConfPath, nftRuleset, cleanup, err := renderConfig(ctx, rc, privKey, peerPubKey, resolve)
	if err != nil {
		return err
	}
	defer cleanup()

	cmds := buildApplyCommands(rc, wgConfPath, nftRuleset)
	for i, c := range cmds {
		if err := run(ctx, c); err != nil {
			// Tear down a half-configured wg0 so the next reload retries a full Apply.
			if i > 0 {
				_ = run(ctx, command{name: "ip", args: []string{"link", "del", "wg0"}})
			}
			return err
		}
	}
	return nil
}

// Reconcile applies rc onto an already-up wg0 without tearing it down, so an
// established handshake and in-flight connections survive a config change.
func Reconcile(ctx context.Context, run runner, rc RuntimeConfig, privKey, peerPubKey string, resolve func(ctx context.Context, host string) (string, error)) error {
	wgConfPath, nftRuleset, cleanup, err := renderConfig(ctx, rc, privKey, peerPubKey, resolve)
	if err != nil {
		return err
	}
	defer cleanup()

	for _, c := range buildReloadCommands(wgConfPath, nftRuleset) {
		if err := run(ctx, c); err != nil {
			return err
		}
	}
	return nil
}

// renderConfig writes the wg(8) config to a 0600 temp file (it holds the private key)
// and renders the nftables ruleset, resolving each forward to a ClusterIP. The caller
// must defer cleanup to remove the temp file.
func renderConfig(ctx context.Context, rc RuntimeConfig, privKey, peerPubKey string, resolve func(ctx context.Context, host string) (string, error)) (wgConfPath, nftRuleset string, cleanup func(), err error) {
	wgConf, err := os.CreateTemp("", "gateway-wg-*.conf")
	if err != nil {
		return "", "", nil, fmt.Errorf("create wg conf temp file: %w", err)
	}
	wgConfPath = wgConf.Name()
	cleanup = func() { _ = os.Remove(wgConfPath) }

	if err := wgConf.Chmod(0o600); err != nil {
		wgConf.Close()
		cleanup()
		return "", "", nil, fmt.Errorf("chmod wg conf %s: %w", wgConfPath, err)
	}
	wgConfText, err := RenderWGConf(rc, privKey, peerPubKey)
	if err != nil {
		wgConf.Close()
		cleanup()
		return "", "", nil, fmt.Errorf("render wg conf %s: %w", wgConfPath, err)
	}
	if _, err := wgConf.WriteString(wgConfText); err != nil {
		wgConf.Close()
		cleanup()
		return "", "", nil, fmt.Errorf("write wg conf %s: %w", wgConfPath, err)
	}
	if err := wgConf.Close(); err != nil {
		cleanup()
		return "", "", nil, fmt.Errorf("close wg conf %s: %w", wgConfPath, err)
	}

	resolved, err := resolveForwards(ctx, rc.Forwards, resolve)
	if err != nil {
		cleanup()
		return "", "", nil, fmt.Errorf("resolve forwards: %w", err)
	}
	nftRuleset, err = RenderNftables(resolved)
	if err != nil {
		cleanup()
		return "", "", nil, fmt.Errorf("render nftables ruleset: %w", err)
	}
	return wgConfPath, nftRuleset, cleanup, nil
}

// wg0Exists reports whether the wg0 interface is present. Any error from ip link
// show is reported as absent, so the caller falls back to a full Apply.
func wg0Exists(ctx context.Context, run runner) bool {
	return run(ctx, command{name: "ip", args: []string{"link", "show", "wg0"}}) == nil
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

// resolveAttempts and resolveRetryDelay bound and space the resolver's retries, to
// ride out the window where CoreDNS serves a stale or missing record after a
// retarget rather than baking a wrong address into the DNAT.
const (
	resolveAttempts   = 4
	resolveRetryDelay = 750 * time.Millisecond
)

// newResolver returns a resolver mapping a host to one IPv4 address (the DNAT is
// IPv4-only). host is forced absolute so an ndots:5 search-list query cannot race the
// CoreDNS negative-cache; errors and empty results retry resolveAttempts times.
func newResolver(lookup func(ctx context.Context, network, host string) ([]net.IP, error)) func(ctx context.Context, host string) (string, error) {
	return func(ctx context.Context, host string) (string, error) {
		fqdn := host
		if !strings.HasSuffix(fqdn, ".") {
			fqdn += "."
		}

		var lastErr error
		for attempt := range resolveAttempts {
			if attempt > 0 {
				select {
				case <-ctx.Done():
					return "", fmt.Errorf("lookup %s: %w", fqdn, ctx.Err())
				case <-time.After(resolveRetryDelay):
				}
			}

			addrs, err := lookup(ctx, "ip4", fqdn)
			if err != nil {
				lastErr = fmt.Errorf("lookup %s: %w", fqdn, err)
				continue
			}
			ip, ok := firstIPv4(addrs)
			if !ok {
				lastErr = fmt.Errorf("service %s resolved to no IPv4 address (nftables DNAT is IPv4-only)", fqdn)
				continue
			}
			return ip, nil
		}
		return "", fmt.Errorf("resolve %s after %d attempts: %w", fqdn, resolveAttempts, lastErr)
	}
}

// firstIPv4 returns the first IPv4 address in addrs and whether one was found; the
// DNAT target must be IPv4.
func firstIPv4(addrs []net.IP) (string, bool) {
	for _, addr := range addrs {
		if addr.To4() != nil {
			return addr.String(), true
		}
	}
	return "", false
}

// execCommand runs c, piping stdin when set and folding captured stderr into the
// returned error so failures are diagnosable from logs alone.
func execCommand(ctx context.Context, c command) error {
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
