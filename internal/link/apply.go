package link

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// HostProcSysNetPath is where the DaemonSet bind-mounts the node's /proc/sys/net read-write. The
// container's own /proc/sys is read-only for a non-privileged container, so writes go through it.
const HostProcSysNetPath = "/host/proc/sys/net"

// command is one step of the apply or teardown plan. Exactly one of name and writePath is set;
// stdin, when non-empty, is piped to the process.
type command struct {
	name  string
	args  []string
	stdin string

	// writePath and writeValue name a file the step writes instead of a process it runs. The Local
	// sysctls are file writes, through HostProcSysNetPath.
	writePath  string
	writeValue string

	// tolerateExists marks a step whose object may already be installed, where the
	// kernel's EEXIST is the idempotent outcome and not a failure.
	tolerateExists bool
}

// existsMarker is ip(8)'s wording for the kernel's EEXIST. execCommand folds stderr into the
// error, so a tolerateExists step is matched on the returned error's text.
const existsMarker = "File exists"

// absentMarker is ip(8)'s wording for the kernel's ENODEV. execCommand sets LC_ALL=C, so the
// wording is stable and is matched on the returned error's text.
const absentMarker = "does not exist"

// runner executes a single command. Tests inject a recorder to exercise the
// command plan without shelling out.
type runner func(ctx context.Context, c command) error

// clusterInterface and clusterNftTable are the fixed names Cluster mode programs. Its
// netns is private, so per-Gateway names would buy nothing.
const (
	clusterInterface = "wg0"
	clusterNftTable  = "gateway"
)

// rulePriority places the per-Gateway ip rule ahead of the main table (32766).
const rulePriority = "10000"

// nftTableName is the inet table the mode programs.
func nftTableName(rc RuntimeConfig) string {
	if rc.isLocal() {
		return rc.Identity.NftTable
	}
	return clusterNftTable
}

// slotPlan is one slot's ordered command list. Cluster mode always has exactly one, keyed by
// slot 0, for its single wg0 interface; Local mode has one per configured peer's slot.
type slotPlan struct {
	Slot int
	Cmds []command
}

// buildApplyCommands builds per-slot plans and their shared final nft step.
func buildApplyCommands(rc RuntimeConfig, wgConfPaths map[int]string, nftRuleset string, ifaceExists map[int]bool, localForwards []ResolvedForward) ([]slotPlan, command) {
	final := command{name: "nft", args: []string{"-f", "-"}, stdin: nftRuleset}

	linkSetFor := func(iface string) []string {
		linkSet := []string{"link", "set", iface}
		if rc.WireGuard.MTU > 0 {
			linkSet = append(linkSet, "mtu", strconv.Itoa(rc.WireGuard.MTU))
		}
		return append(linkSet, "up")
	}

	if !rc.isLocal() {
		iface := clusterInterface
		var cmds []command
		if !ifaceExists[0] {
			cmds = append(cmds, command{name: "ip", args: []string{"link", "add", iface, "type", "wireguard"}})
		}
		cmds = append(cmds,
			command{name: "wg", args: []string{"syncconf", iface, wgConfPaths[0]}},
			command{name: "ip", args: []string{"addr", "replace", rc.WireGuard.Address, "dev", iface}},
			command{name: "ip", args: linkSetFor(iface)},
		)
		return []slotPlan{{Slot: 0, Cmds: cmds}}, final
	}

	targets := localThrowTargets(localForwards)
	plans := make([]slotPlan, 0, len(rc.WireGuard.Peers))
	for _, p := range rc.WireGuard.Peers {
		id := NewSlotIdentity(rc.Identity.ID, p.Slot)

		var cmds []command
		if !ifaceExists[p.Slot] {
			cmds = append(cmds, command{name: "ip", args: []string{"link", "add", id.Interface, "type", "wireguard"}})
		}
		cmds = append(cmds,
			command{name: "wg", args: []string{"syncconf", id.Interface, wgConfPaths[p.Slot]}},
			command{name: "ip", args: []string{"addr", "replace", rc.WireGuard.Address, "dev", id.Interface}},
			command{name: "ip", args: linkSetFor(id.Interface)},
			command{writePath: HostProcSysNetPath + "/ipv4/conf/" + id.Interface + "/rp_filter", writeValue: "0"},
			command{writePath: HostProcSysNetPath + "/ipv4/conf/" + id.Interface + "/forwarding", writeValue: "1"},
		)
		cmds = append(cmds, localRouteCommands(id, targets)...)
		plans = append(plans, slotPlan{Slot: p.Slot, Cmds: cmds})
	}
	return plans, final
}

// localRouteCommands builds the Local route plan from sorted, unique targets: default route, throw
// routes re-added each apply so stale ones are pruned, and the fwmark rule with EEXIST tolerated.
func localRouteCommands(id SlotIdentity, targets []string) []command {
	table := strconv.Itoa(id.RouteTable)
	fwmark := id.Mark + "/" + id.MarkMask

	cmds := make([]command, 0, len(targets)+3)
	cmds = append(cmds,
		command{name: "ip", args: []string{"route", "replace", "default", "dev", id.Interface, "table", table}},
		command{name: "ip", args: []string{"route", "flush", "table", table, "type", "throw"}},
	)
	for _, target := range targets {
		cmds = append(cmds, command{name: "ip", args: []string{"route", "replace", "throw", target + "/32", "table", table}})
	}
	return append(cmds,
		command{name: "ip", args: []string{"rule", "add", "fwmark", fwmark, "lookup", table, "priority", rulePriority}, tolerateExists: true},
	)
}

// RouteStep is one step of the Local route plan as an out-of-process caller sees it.
type RouteStep struct {
	// Args is the ip(8) argument list, without the leading "ip".
	Args []string
	// TolerateExists marks a step the kernel may reject with EEXIST because the object is already
	// installed. That outcome is the step's success, and a caller running the plan must treat it so.
	TolerateExists bool
}

// LocalRouteCommands returns the ip(8) steps a Local apply programs for id's route table and rule,
// in order, given sorted and deduplicated DNAT targets. It lets an out-of-process harness install
// the product's own route plan instead of restating it.
func LocalRouteCommands(id SlotIdentity, targets []string) []RouteStep {
	cmds := localRouteCommands(id, targets)
	steps := make([]RouteStep, 0, len(cmds))
	for _, c := range cmds {
		steps = append(steps, RouteStep{Args: c.args, TolerateExists: c.tolerateExists})
	}
	return steps
}

// localThrowTargets returns the sorted, unique backend addresses the Local forwards
// point at. Empty values are skipped.
func localThrowTargets(forwards []ResolvedForward) []string {
	targets := make(map[string]struct{}, len(forwards))
	for _, f := range forwards {
		if f.Target != "" {
			targets[f.Target] = struct{}{}
		}
	}
	return slices.Sorted(maps.Keys(targets))
}

// ResolveFunc resolves a Cluster-mode forward's backend Service to a concrete address.
type ResolveFunc func(ctx context.Context, host string) (string, error)

// SlotResult is one slot's apply outcome.
type SlotResult struct {
	Slot    int
	Applied bool
	Err     error // nil when Applied
}

// Apply programs network state without concurrent calls. Local slot failures return in SlotResult.
func Apply(ctx context.Context, run runner, rc RuntimeConfig, privKey string, resolve ResolveFunc, localForwards []ResolvedForward, log *zap.SugaredLogger) (results []SlotResult, err error) {
	wgConfPaths, nftRuleset, cleanup, err := renderConfig(ctx, rc, privKey, resolve, localForwards, log)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cleanupErr := cleanup(err != nil); cleanupErr != nil {
			err = fmt.Errorf("remove wg conf temp files: %w", cleanupErr)
		}
	}()

	exists := map[int]bool{}
	if !rc.isLocal() {
		ok, err := ifaceExists(ctx, run, clusterInterface)
		if err != nil {
			return nil, err
		}
		exists[0] = ok
	} else {
		for _, p := range rc.WireGuard.Peers {
			ok, err := ifaceExists(ctx, run, NewSlotIdentity(rc.Identity.ID, p.Slot).Interface)
			if err != nil {
				return nil, err
			}
			exists[p.Slot] = ok
		}
	}

	plans, final := buildApplyCommands(rc, wgConfPaths, nftRuleset, exists, localForwards)

	if !rc.isLocal() {
		for _, c := range plans[0].Cmds {
			if err := runStep(ctx, run, c, log); err != nil {
				return nil, err
			}
		}
		if err := runStep(ctx, run, final, log); err != nil {
			return nil, fmt.Errorf("apply nftables ruleset: %w", err)
		}
		return nil, nil
	}

	results = make([]SlotResult, 0, len(plans))
	for _, sp := range plans {
		var stepErr error
		for _, c := range sp.Cmds {
			if stepErr = runStep(ctx, run, c, log); stepErr != nil {
				break
			}
		}
		results = append(results, SlotResult{Slot: sp.Slot, Applied: stepErr == nil, Err: stepErr})
	}
	if err := runStep(ctx, run, final, log); err != nil {
		err = fmt.Errorf("apply nftables ruleset: %w", err)
		return unapplied(results, err), err
	}
	return results, nil
}

// unapplied marks a pass whose final ruleset failed: no slot is admitted, though each created
// node state its holder tears down on departure. A slot that already failed keeps its error.
func unapplied(results []SlotResult, err error) []SlotResult {
	for i := range results {
		results[i].Applied = false
		if results[i].Err == nil {
			results[i].Err = err
		}
	}
	return results
}

// runStep executes one plan step. A tolerateExists step failing with EEXIST found its object
// already installed, the expected re-apply outcome; that is logged at Debug rather than failed.
func runStep(ctx context.Context, run runner, c command, log *zap.SugaredLogger) error {
	err := run(ctx, c)
	if err != nil && c.tolerateExists && strings.Contains(err.Error(), existsMarker) {
		log.Debugw("step's object already exists, leaving it in place",
			"command", strings.Join(append([]string{c.name}, c.args...), " "), "error", err)
		return nil
	}
	return err
}

// renderConfig writes 0600 per-slot configs and renders the shared ruleset.
func renderConfig(ctx context.Context, rc RuntimeConfig, privKey string, resolve ResolveFunc, localForwards []ResolvedForward, log *zap.SugaredLogger) (wgConfPaths map[int]string, nftRuleset string, cleanup func(logFailures bool) error, err error) {
	wgConfPaths = map[int]string{}
	var paths []string
	cleanup = func(logFailures bool) error {
		var errs []error
		for _, p := range paths {
			if removeErr := os.Remove(p); removeErr != nil {
				if logFailures {
					log.Warnw("remove wg conf temp file", "path", p, "error", removeErr)
				} else {
					errs = append(errs, fmt.Errorf("remove %s: %w", p, removeErr))
				}
			}
		}
		return errors.Join(errs...)
	}

	writeWGConf := func(slot int, rcForSlot RuntimeConfig) error {
		text, err := RenderWGConf(rcForSlot, privKey)
		if err != nil {
			return fmt.Errorf("render wg conf for slot %d: %w", slot, err)
		}
		f, err := os.CreateTemp("", "gateway-wg-*.conf")
		if err != nil {
			return fmt.Errorf("create wg conf temp file: %w", err)
		}
		path := f.Name()
		paths = append(paths, path)
		if err := f.Chmod(0o600); err != nil {
			if closeErr := f.Close(); closeErr != nil {
				log.Warnw("close wg conf temp file", "path", path, "error", closeErr)
			}
			return fmt.Errorf("chmod wg conf %s: %w", path, err)
		}
		if _, err := f.WriteString(text); err != nil {
			if closeErr := f.Close(); closeErr != nil {
				log.Warnw("close wg conf temp file", "path", path, "error", closeErr)
			}
			return fmt.Errorf("write wg conf %s: %w", path, err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("close wg conf %s: %w", path, err)
		}
		wgConfPaths[slot] = path
		return nil
	}

	if rc.isLocal() {
		for _, p := range rc.WireGuard.Peers {
			slotRC := rc
			slotRC.WireGuard.Peers = []Peer{p}
			if err := writeWGConf(p.Slot, slotRC); err != nil {
				if cleanupErr := cleanup(true); cleanupErr != nil {
					log.Warnw("remove wg conf temp files", "error", cleanupErr)
				}
				return nil, "", nil, err
			}
		}
	} else if err := writeWGConf(0, rc); err != nil {
		if cleanupErr := cleanup(true); cleanupErr != nil {
			log.Warnw("remove wg conf temp files", "error", cleanupErr)
		}
		return nil, "", nil, err
	}

	resolved := localForwards
	if !rc.isLocal() {
		resolved, err = resolveForwards(ctx, rc.Forwards, resolve)
		if err != nil {
			if cleanupErr := cleanup(true); cleanupErr != nil {
				log.Warnw("remove wg conf temp files", "error", cleanupErr)
			}
			return nil, "", nil, fmt.Errorf("resolve forwards: %w", err)
		}
	}
	nftRuleset, err = RenderNftables(rc, resolved)
	if err != nil {
		if cleanupErr := cleanup(true); cleanupErr != nil {
			log.Warnw("remove wg conf temp files", "error", cleanupErr)
		}
		return nil, "", nil, fmt.Errorf("render nftables ruleset: %w", err)
	}
	return wgConfPaths, nftRuleset, cleanup, nil
}

// ifaceExists reports whether iface is present. Only ip(8)'s "does not exist" answer means absent;
// any other failure is returned, so a broken netlink socket is never read as an absent interface.
func ifaceExists(ctx context.Context, run runner, iface string) (bool, error) {
	err := run(ctx, command{name: "ip", args: []string{"link", "show", iface}})
	switch {
	case err == nil:
		return true, nil
	case strings.Contains(err.Error(), absentMarker):
		return false, nil
	default:
		return false, fmt.Errorf("probe interface %s: %w", iface, err)
	}
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
			Target:     ip,
			TargetPort: f.TargetPort,
		})
	}
	return out, nil
}

// resolveAttempts and resolveRetryDelay bound and space the resolver's retries, to ride out a stale
// CoreDNS record after a retarget rather than baking a wrong address into the DNAT.
const (
	resolveAttempts   = 4
	resolveRetryDelay = 750 * time.Millisecond
)

// newResolver maps a host to one IPv4 address (the DNAT is IPv4-only). host is forced absolute so
// an ndots:5 search-list query cannot race the CoreDNS negative cache; failures retry.
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

// execCommand runs c: a file write when writePath is set, otherwise a process. Captured stderr is
// folded into the returned error so failures are diagnosable from logs alone.
func execCommand(ctx context.Context, c command) error {
	if c.writePath != "" {
		if err := os.WriteFile(c.writePath, []byte(c.writeValue), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", c.writePath, err)
		}
		return nil
	}
	cmd := exec.CommandContext(ctx, c.name, c.args...)
	// runStep matches iproute2's EEXIST wording, which is localised.
	cmd.Env = append(os.Environ(), "LC_ALL=C")
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

// preCheckFault is the fault a Local pre-check found, empty when the node is fit to program the
// data plane. The link publishes it on its Lease; it never lowers a node-wide sysctl to clear one.
type preCheckFault struct {
	Reason  string
	Message string
}

// preCheckLocal asserts, via the host /proc/sys/net mount, that ip_forward is 1 and rp_filter on
// all is 0 or 2, the kernel taking the maximum with the per-interface value. Unreadable is a fault.
func preCheckLocal(node string) preCheckFault {
	return preCheckLocalAt(HostProcSysNetPath, node)
}

// preCheckLocalAt is preCheckLocal parameterised on the /proc/sys/net prefix, so
// tests can inject a temp-dir fixture instead of the real host mount.
func preCheckLocalAt(prefix, node string) preCheckFault {
	ipForward, err := readSysctlInt(prefix + "/ipv4/ip_forward")
	if err != nil {
		return unreadableSysctlFault(node, err)
	}
	if ipForward == 0 {
		return preCheckFault{
			Reason:  FaultApplyFailed,
			Message: fmt.Sprintf("%s: net.ipv4.ip_forward is 0; the node does not forward", node),
		}
	}

	rpFilter, err := readSysctlInt(prefix + "/ipv4/conf/all/rp_filter")
	if err != nil {
		return unreadableSysctlFault(node, err)
	}
	if rpFilter != 0 && rpFilter != 2 {
		return preCheckFault{
			Reason: FaultRPFilterStrict,
			Message: fmt.Sprintf("%s: net.ipv4.conf.all.rp_filter is %d; Local mode needs an effective value of 0 or 2 on the tunnel interface",
				node, rpFilter),
		}
	}

	return preCheckFault{}
}

// unreadableSysctlFault reports an unreadable or unparseable sysctl as a fault, not a fatal error,
// so the Gateway is told why the node cannot be programmed instead of the pod crash-looping.
func unreadableSysctlFault(node string, err error) preCheckFault {
	return preCheckFault{Reason: FaultApplyFailed, Message: fmt.Sprintf("%s: %v", node, err)}
}

// readSysctlInt reads and parses a single-integer sysctl file. A missing, unreadable or
// unparseable file is an error naming the path; the caller cannot distinguish the cases.
func readSysctlInt(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", path, err)
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", path, err)
	}
	return v, nil
}
