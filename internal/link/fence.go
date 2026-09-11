package link

import (
	"context"
	"errors"
	"strconv"
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
// DNAT'd while the rest unwinds; in Local mode the ip rule precedes the route flush so no packet
// is routed into an emptying table, and both go by name because deleting the interface keeps them.
func TeardownCommands(rc RuntimeConfig) []TeardownStep {
	steps := []TeardownStep{{Name: "nft", Args: []string{"delete", "table", "inet", nftTableName(rc)}}}
	if rc.isLocal() {
		rt := strconv.Itoa(rc.Identity.RouteTable)
		steps = append(steps,
			TeardownStep{Name: "ip", Args: []string{"rule", "del", "fwmark", rc.Identity.Mark + "/" + rc.Identity.MarkMask, "lookup", rt, "priority", rulePriority}},
			TeardownStep{Name: "ip", Args: []string{"route", "flush", "table", rt}},
		)
	}
	return append(steps, TeardownStep{Name: "ip", Args: []string{"link", "del", interfaceName(rc)}})
}

// Teardown best-effort removes the link's data plane so a demoted standby stops
// carrying traffic. It runs every step of TeardownCommands regardless of failures and
// joins the per-command errors.
func Teardown(ctx context.Context, run runner, rc RuntimeConfig) error {
	var errs []error
	for _, step := range TeardownCommands(rc) {
		if err := run(ctx, command{name: step.Name, args: step.Args}); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
