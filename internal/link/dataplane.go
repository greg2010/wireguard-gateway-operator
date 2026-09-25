package link

import (
	"context"
	"errors"
	"maps"
	"slices"
	"sync"

	"go.uber.org/zap"
)

// dataPlane serializes this replica's node-global state.
type dataPlane struct {
	mu sync.Mutex
	rc RuntimeConfig
	// slots maps a slot this replica holds to whether its last pass ended applied. A slot enters
	// on a successful apply and leaves once its teardown has completed.
	slots       map[int]bool
	otherHolder bool
	// forwards is the forward set the last successful apply programmed, read by the next apply so
	// it can flush the conntrack entries of whatever tuple no longer appears.
	forwards []ResolvedForward
	// publicAddress is the PublicAddress of the last successful apply this leadership cycle, read by
	// the next apply so it can delete the flows that predate a newly installed hairpin rule.
	publicAddress string
	probeLatch    responderProbeLatch
}

func newDataPlane(rc RuntimeConfig) *dataPlane {
	return &dataPlane{rc: rc, slots: map[int]bool{}}
}

// hold records a slot this replica found already programmed at start. It is not admitted — this
// process applied nothing yet — and the first pass tears it down unless the config still lists it.
func (d *dataPlane) hold(slot int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.slots[slot] = false
}

// observeOtherHolder records the election's evidence that another replica holds the Lease.
func (d *dataPlane) observeOtherHolder() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.otherHolder = true
}

// startLeading resets the per-term state at the start of each leadership cycle: the other-holder
// evidence and the remembered public address, so the cycle's first apply installs the hairpin anew.
func (d *dataPlane) startLeading() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.otherHolder = false
	d.publicAddress = ""
}

// applyPass records outcomes under the node lock, threading the last successfully applied forward
// set and public address into apply and storing the new ones only on success.
func (d *dataPlane) applyPass(ctx context.Context, run runner, current RuntimeConfig,
	apply func(context.Context, []ResolvedForward, string) ([]SlotResult, []ResolvedForward, error), log *zap.SugaredLogger) ([]SlotResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !current.isLocal() {
		results, applied, err := apply(ctx, d.forwards, d.publicAddress)
		if err == nil {
			d.forwards, d.publicAddress = applied, current.PublicAddress
		}
		return results, err
	}

	d.rc = current
	departed := d.teardownSlots(ctx, run, configuredSlots(current), log)
	results, applied, err := apply(ctx, d.forwards, d.publicAddress)
	if err == nil {
		d.forwards, d.publicAddress = applied, current.PublicAddress
	}
	d.record(results)
	return append(slices.Clone(results), departed...), err
}

// standbyPass tears held slots down once another replica is observed holding the Lease,
// preserving inherited or self-applied data until a late leadership acquisition can claim it.
func (d *dataPlane) standbyPass(ctx context.Context, run runner, current RuntimeConfig, leader func() bool, log *zap.SugaredLogger) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if leader() {
		return nil
	}
	d.rc = current
	if !d.otherHolder {
		return nil
	}
	return errors.Join(slotErrors(d.teardownSlots(ctx, run, nil, log))...)
}

// stepDown removes the data plane before tearing down held slots.
func (d *dataPlane) stepDown(ctx context.Context, run runner, log *zap.SugaredLogger) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.rc.isLocal() {
		return teardownCluster(ctx, run, d.rc, log)
	}

	var errs []error
	table := deleteTableCommand(nftTableName(d.rc))
	if err := runTeardownStep(ctx, run, TeardownStep{Name: table.name, Args: table.args}, log); err != nil {
		errs = append(errs, err)
	}
	errs = append(errs, slotErrors(d.teardownSlots(ctx, run, nil, log))...)
	return errors.Join(errs...)
}

// teardownSlots retains failed teardowns for a later retry.
func (d *dataPlane) teardownSlots(ctx context.Context, run runner, keep map[int]bool, log *zap.SugaredLogger) []SlotResult {
	var down []SlotResult
	for _, slot := range slices.Sorted(maps.Keys(d.slots)) {
		if keep[slot] {
			continue
		}
		var errs []error
		for _, step := range slotTeardownSteps(d.rc.Identity.ID, slot) {
			if err := runTeardownStep(ctx, run, step, log, "slot", slot); err != nil {
				errs = append(errs, err)
			}
		}
		if err := errors.Join(errs...); err != nil {
			d.slots[slot] = false
			down = append(down, SlotResult{Slot: slot, Err: err})
			continue
		}
		delete(d.slots, slot)
	}
	return down
}

// record retains every attempted slot so departure tears down partial state.
func (d *dataPlane) record(results []SlotResult) {
	for _, r := range results {
		d.slots[r.Slot] = r.Applied
	}
}

// heldSlots is every slot this replica still holds, applied or not, sorted.
func (d *dataPlane) heldSlots() []int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Sorted(maps.Keys(d.slots))
}

// configuredSlots is the set of slots rc carries a peer for.
func configuredSlots(rc RuntimeConfig) map[int]bool {
	slots := make(map[int]bool, len(rc.WireGuard.Peers))
	for _, p := range rc.WireGuard.Peers {
		slots[p.Slot] = true
	}
	return slots
}

// slotErrors is the errors carried by a teardown's down slots.
func slotErrors(down []SlotResult) []error {
	errs := make([]error, 0, len(down))
	for _, r := range down {
		errs = append(errs, r.Err)
	}
	return errs
}
