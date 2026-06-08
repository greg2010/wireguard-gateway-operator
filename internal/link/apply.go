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

// command is a single shell-out step in the apply plan. stdin, when non-empty,
// is piped to the process's standard input.
type command struct {
	name  string
	args  []string
	stdin string
}

// runner executes a single command. The production implementation is
// execCommand; tests inject a recorder to exercise the command plan without
// shelling out.
type runner func(ctx context.Context, c command) error

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

// buildReloadCommands returns the ordered list of invocations that reconcile an
// already-up wg0 onto the new config without tearing the interface down. wg
// syncconf diffs the running peer set against the conf and applies only the
// delta, so the existing tunnel and its handshake survive; nft -f atomically
// swaps the ruleset. The interface address and MTU are interface-creation
// properties Apply sets, so the reload path leaves them untouched.
func buildReloadCommands(wgConfPath, nftRuleset string) []command {
	return []command{
		{name: "wg", args: []string{"syncconf", "wg0", wgConfPath}},
		{name: "nft", args: []string{"-f", "-"}, stdin: nftRuleset},
	}
}

// Apply brings up the WireGuard tunnel and programs nftables from rc.
//
// It mutates host network state (wg0 and the nftables ruleset) and must not be
// called concurrently; it relies on the single reconcile-goroutine caller.
//
// It assumes a kube-proxy data plane (iptables or ipvs) so that masqueraded
// traffic to a Service ClusterIP is load-balanced to a backend pod. Cilium's
// kube-proxy replacement bypasses the ClusterIP DNAT that this design relies on
// and is out of scope for v1.
//
// resolve maps a Service DNS name to a single address; pass a resolver built by
// newResolver in production. privKey and peerPubKey are base64 WireGuard keys
// read from mounted Secret files. The rendered config (which embeds the private
// key) is written to a 0600 temp file for the duration of the call and removed
// before return. A best-effort delete of any pre-existing wg0 runs first so Apply
// is idempotent across restarts; it is used for first-time setup, not for the
// live reload path, which is Reconcile. If a step after the interface is created
// fails, wg0 is torn down best-effort before returning, so a partial Apply never
// leaves a half-configured interface that a later Reconcile would patch instead
// of rebuilding.
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
			// The first command creates wg0; a failure past it leaves a
			// half-configured interface. Tear it down so the next reload sees
			// wg0Exists false and retries a full Apply rather than a Reconcile
			// against a broken interface.
			if i > 0 {
				_ = run(ctx, command{name: "ip", args: []string{"link", "del", "wg0"}})
			}
			return err
		}
	}
	return nil
}

// Reconcile applies rc onto an already-up wg0 without tearing the interface
// down: wg syncconf reconciles the peer endpoint and key against the running
// interface, and nft -f atomically swaps the ruleset. Unlike Apply it issues no
// ip link del or ip link add, so an established handshake and in-flight
// connections survive a config change. The caller chooses Apply versus Reconcile
// from wg0Exists.
//
// Concurrency, resolve, and key handling match Apply: a single reconcile
// goroutine, and the rendered config (which embeds the private key) lives in a
// 0600 temp file only for the duration of the call.
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

// renderConfig writes the wg(8) configuration to a 0600 temp file and renders
// the nftables ruleset, resolving each forward's Service to a ClusterIP. It
// returns the temp file path, the ruleset text, and a cleanup func the caller
// must defer to remove the temp file. The file holds the WireGuard private key,
// so it is created 0600 and never left behind.
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

// wg0Exists reports whether the wg0 interface is already present, so the caller
// picks first-time Apply versus non-disruptive Reconcile. Any non-nil error from
// ip link show is reported as absent, so the caller falls back to a full Apply.
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

// resolveAttempts bounds how many times the resolver queries DNS before giving
// up, and resolveRetryDelay spaces those attempts. A retarget points the Service
// FQDN at a new ClusterIP, and CoreDNS may briefly serve the stale or no record
// while that propagates; a few spaced retries ride out that window instead of
// baking a wrong or missing address into the nftables DNAT.
const (
	resolveAttempts   = 4
	resolveRetryDelay = 750 * time.Millisecond
)

// newResolver returns a resolver that maps a forward's host to a single IPv4
// address using lookup. In production lookup is net.DefaultResolver.LookupIP;
// tests inject a stub so the retry loop runs without real DNS. lookup carries
// the net.Resolver.LookupIP contract: network is an address family selector
// ("ip4" here).
//
// The nftables ruleset DNATs to an IPv4 ClusterIP, so the resolver queries A
// records only ("ip4"); an AAAA result could never match the DNAT and only adds
// a parallel query that races the A leg.
//
// host is forced absolute (a trailing dot is appended when absent) so the
// resolver issues one direct query rather than walking the ndots search list.
// The operator already hands the resolver a cluster FQDN; under the link pod's
// ClusterFirst ndots:5 policy a 4-label FQDN is still below the threshold, so
// without the dot the resolver tries every search-list suffix first, and a
// search-list query racing CoreDNS negative-cache can return a successful but
// wrong address that then durably blackholes the DNAT.
//
// The lookup is retried up to resolveAttempts times, spaced by
// resolveRetryDelay; both a lookup error and an empty or IPv4-less result are
// retryable. Exhausting all attempts returns an error so resolveForwards fails
// the whole apply, keeping fail-loud semantics: the reconcile warns and retries
// rather than logging false success against a bad DNAT. ctx cancellation aborts
// the retry wait promptly.
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

// firstIPv4 returns the string form of the first IPv4 address in addrs, skipping
// IPv6 entries, and reports whether one was found. The DNAT target must be IPv4,
// so an addrs slice with no IPv4 entry yields ok=false.
func firstIPv4(addrs []net.IP) (string, bool) {
	for _, addr := range addrs {
		if addr.To4() != nil {
			return addr.String(), true
		}
	}
	return "", false
}

// execCommand runs c, piping stdin when set and folding captured stderr into
// the returned error so failures are diagnosable from logs alone.
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
