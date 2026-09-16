package link

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"go.uber.org/zap"
)

// TeardownStep is one command of the teardown plan as an out-of-process caller sees it.
type TeardownStep struct {
	// Name is the executable the step runs, without a path.
	Name string
	// Args is the argument list, excluding Name.
	Args []string
}

// TeardownCommands returns the teardown plan for rc in execution order, so an out-of-process
// harness runs the product's own fence. The nftables table goes first so no new connection is
// DNAT'd while the rest unwinds; in Local mode every slot's steps follow, in the config's order.
func TeardownCommands(rc RuntimeConfig) []TeardownStep {
	steps := []TeardownStep{{Name: "nft", Args: []string{"delete", "table", "inet", nftTableName(rc)}}}
	if !rc.isLocal() {
		return append(steps, TeardownStep{Name: "ip", Args: []string{"link", "del", clusterInterface}})
	}
	for _, p := range rc.WireGuard.Peers {
		steps = append(steps, slotTeardownSteps(rc.Identity.ID, p.Slot)...)
	}
	return steps
}

// slotTeardownSteps removes the rule before its route table and interface.
func slotTeardownSteps(gatewayID, slot int) []TeardownStep {
	id := NewSlotIdentity(gatewayID, slot)
	table := strconv.Itoa(id.RouteTable)
	return []TeardownStep{
		{Name: "ip", Args: []string{"rule", "del", "fwmark", id.Mark + "/" + id.MarkMask, "lookup", table, "priority", rulePriority}},
		{Name: "ip", Args: []string{"route", "flush", "table", table}},
		{Name: "ip", Args: []string{"link", "del", id.Interface}},
	}
}

// absentObjectMarkers are ip(8)'s and nft(8)'s wordings for an object that is already gone: an
// absent link, an absent rule, an absent table. execCommand pins LC_ALL=C, so they are stable.
var absentObjectMarkers = []string{absentMarker, "Cannot find device", "No such file or directory"}

// runTeardownStep treats already-absent objects as complete.
func runTeardownStep(ctx context.Context, run runner, step TeardownStep, log *zap.SugaredLogger, kv ...any) error {
	err := run(ctx, command{name: step.Name, args: step.Args})
	if err == nil {
		return nil
	}
	text := err.Error()
	if !slices.ContainsFunc(absentObjectMarkers, func(m string) bool { return strings.Contains(text, m) }) {
		return err
	}
	log.Warnw("teardown step's object is already absent, treating the step as done",
		append(kv, "step", strings.Join(append([]string{step.Name}, step.Args...), " "), "error", err)...)
	return nil
}

// teardownCluster removes Cluster mode's single table and interface. It runs every step
// regardless of failures and joins the per-command errors.
func teardownCluster(ctx context.Context, run runner, rc RuntimeConfig, log *zap.SugaredLogger) error {
	var errs []error
	for _, step := range TeardownCommands(rc) {
		if err := runTeardownStep(ctx, run, step, log); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// fencingTableName is the per-Gateway fencing table's name, distinct from the holder's
// data-plane table (rc's NftTable) so the two are never flushed together.
func fencingTableName(rc RuntimeConfig) string { return "fence-" + nftTableName(rc) }

// FencingRuleset renders health-port admission for applied Local slots.
func FencingRuleset(rc RuntimeConfig, admitted []int) string {
	table := fencingTableName(rc)
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s\n", table)
	fmt.Fprintf(&b, "flush table inet %s\n", table)
	fmt.Fprintf(&b, "table inet %s {\n", table)
	b.WriteString("\tchain input {\n")
	b.WriteString("\t\ttype filter hook input priority filter; policy accept;\n")
	fmt.Fprintf(&b, "\t\ttcp dport %d iifname \"lo\" accept\n", rc.Identity.HealthPort)
	for _, slot := range slices.Sorted(slices.Values(admitted)) {
		iface := NewSlotIdentity(rc.Identity.ID, slot).Interface
		fmt.Fprintf(&b, "\t\ttcp dport %d iifname %q accept\n", rc.Identity.HealthPort, iface)
	}
	fmt.Fprintf(&b, "\t\ttcp dport %d drop\n", rc.Identity.HealthPort)
	b.WriteString("\t}\n}\n")
	return b.String()
}

// InstallFencing renders and applies the standalone fencing table for the slots in admitted.
// Idempotent (add+flush, like the data-plane table): every replica installs it once at process
// start with no slot admitted, and re-renders it from its applied set whenever that set can have
// changed — never gated on leadership.
func InstallFencing(ctx context.Context, run runner, rc RuntimeConfig, admitted []int) error {
	if err := run(ctx, command{name: "nft", args: []string{"-f", "-"}, stdin: FencingRuleset(rc, admitted)}); err != nil {
		return fmt.Errorf("install fencing table %s: %w", fencingTableName(rc), err)
	}
	return nil
}

// RemoveFencing deletes the fencing table by name. Called once at process exit, after
// the health listener has closed never by the holder's flush-and-recreate of
// the data-plane table, and never by the step-down fence.
func RemoveFencing(ctx context.Context, run runner, rc RuntimeConfig) error {
	if err := run(ctx, command{name: "nft", args: []string{"delete", "table", "inet", fencingTableName(rc)}}); err != nil {
		return fmt.Errorf("remove fencing table %s: %w", fencingTableName(rc), err)
	}
	return nil
}
