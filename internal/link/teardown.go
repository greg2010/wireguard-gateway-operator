package link

import (
	"context"
	"errors"
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

func deleteTableCommand(table string) command {
	return command{name: "nft", args: []string{"delete", "table", "inet", table}}
}

// TeardownCommands returns the teardown plan for rc in execution order, so an out-of-process
// harness runs the product's own teardown. The nftables table goes first so no new connection is
// DNAT'd while the rest unwinds; in Local mode every slot's steps follow, in the config's order.
func TeardownCommands(rc RuntimeConfig) []TeardownStep {
	table := deleteTableCommand(nftTableName(rc))
	steps := []TeardownStep{{Name: table.name, Args: table.args}}
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
