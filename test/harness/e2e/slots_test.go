package e2e

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestStackAddressWeight(t *testing.T) {
	tests := []struct {
		name string
		opts []StartOption
		want int64
	}{
		{name: "single instance", want: 1},
		{name: "load-balanced fleet with default replicas", opts: []StartOption{WithLoadBalancer("NONE")}, want: 2},
		{name: "fleet one replica", opts: []StartOption{WithGCPReplicas(1), WithLoadBalancer("NONE")}, want: 2},
		{name: "fleet two replicas", opts: []StartOption{WithGCPReplicas(2), WithLoadBalancer("NONE")}, want: 3},
		{name: "fleet four replicas", opts: []StartOption{WithGCPReplicas(4), WithLoadBalancer("NONE")}, want: 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg startConfig
			for _, opt := range tt.opts {
				opt(&cfg)
			}
			if got := stackAddressWeight(cfg); got != tt.want {
				t.Errorf("stack address weight = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestMaxAddresses(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    int64
		wantErr bool
	}{
		{name: "unset defaults", want: 8},
		{name: "sixteen", raw: "16", want: 16},
		{name: "non integer rejected", raw: "sixteen", wantErr: true},
		{name: "under one rejected", raw: "0", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := maxAddresses(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("max addresses(%q) = %d, nil, want an error", tt.raw, got)
				}
				if !strings.Contains(err.Error(), EnvMaxAddresses) || !strings.Contains(err.Error(), tt.raw) {
					t.Errorf("max addresses(%q) error = %q, want %s and %q", tt.raw, err, EnvMaxAddresses, tt.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("max addresses(%q): %v", tt.raw, err)
			}
			if got != tt.want {
				t.Errorf("max addresses(%q) = %d, want %d", tt.raw, got, tt.want)
			}
		})
	}
}

func TestAddressSlotsAcquisitionBlocksUntilRelease(t *testing.T) {
	tests := []struct {
		name      string
		capacity  int64
		held      int64
		requested int64
		wantErr   string
	}{
		{name: "remaining capacity is too small", capacity: 4, held: 3, requested: 2},
		{name: "request exceeds capacity", capacity: 1, requested: 2, wantErr: "stack needs 2 external addresses, E2E_MAX_ADDRESSES allows 1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slots := newAddressSlots(tt.capacity)
			if tt.wantErr != "" {
				ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
				defer cancel()
				if err := slots.acquire(ctx, tt.requested); err == nil || err.Error() != tt.wantErr {
					t.Fatalf("acquire %d addresses = %v, want %q", tt.requested, err, tt.wantErr)
				}
				return
			}
			acquireAddressesWithin(t, slots, tt.held)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			acquired := make(chan error, 1)
			go func() {
				acquired <- slots.acquire(ctx, tt.requested)
			}()

			select {
			case err := <-acquired:
				t.Fatalf("acquire %d addresses while %d are held: %v", tt.requested, tt.held, err)
			case <-time.After(200 * time.Millisecond):
			}

			slots.release(tt.held)
			select {
			case err := <-acquired:
				if err != nil {
					t.Fatalf("acquire %d addresses after release: %v", tt.requested, err)
				}
			case <-ctx.Done():
				t.Fatalf("acquire %d addresses after release: %v", tt.requested, ctx.Err())
			}
		})
	}
}

func acquireAddressesWithin(t *testing.T, slots *addressSlots, weight int64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := slots.acquire(ctx, weight); err != nil {
		t.Fatalf("acquire %d addresses: %v", weight, err)
	}
}

func TestStackReleaseAddressPermitFor(t *testing.T) {
	tests := []struct {
		name     string
		outcomes []gatewayOutcome
		wantFree int64
	}{
		{name: "gateway deleted releases", outcomes: []gatewayOutcome{gatewayConfirmedGone}, wantFree: 2},
		{name: "gateway preserved holds", outcomes: []gatewayOutcome{gatewayStillLive}, wantFree: 0},
		{name: "gateway creation failed releases", outcomes: []gatewayOutcome{gatewayConfirmedGone}, wantFree: 2},
		{name: "second release returns no second permit", outcomes: []gatewayOutcome{gatewayConfirmedGone, gatewayConfirmedGone}, wantFree: 2},
		{name: "preserved then confirmed gone releases once", outcomes: []gatewayOutcome{gatewayStillLive, gatewayConfirmedGone}, wantFree: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slots := newAddressSlots(2)
			stack := &Stack{addresses: slots, addressWeight: 2}
			acquireAddressesWithin(t, slots, 2)

			for _, outcome := range tt.outcomes {
				stack.releaseAddressPermitFor(outcome)
			}

			if got := availableAddresses(t, slots, 2); got != tt.wantFree {
				t.Errorf("available addresses after %v = %d, want %d", tt.outcomes, got, tt.wantFree)
			}
		})
	}
}

func availableAddresses(t *testing.T, slots *addressSlots, limit int64) int64 {
	t.Helper()
	var available int64
	for range limit {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		err := slots.acquire(ctx, 1)
		cancel()
		if err != nil {
			return available
		}
		available++
	}
	return available
}
