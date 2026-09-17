package e2e

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"

	"golang.org/x/sync/semaphore"
)

// EnvMaxAddresses caps the GCP external addresses used by this test binary.
const EnvMaxAddresses = "E2E_MAX_ADDRESSES"

const defaultMaxAddresses = 8

var liveAddresses = sync.OnceValues(func() (*addressSlots, error) {
	n, err := maxAddresses(os.Getenv(EnvMaxAddresses))
	if err != nil {
		return nil, err
	}
	return newAddressSlots(n), nil
})

type addressSlots struct {
	capacity int64
	sem      *semaphore.Weighted
}

func newAddressSlots(n int64) *addressSlots {
	return &addressSlots{capacity: n, sem: semaphore.NewWeighted(n)}
}

func (s *addressSlots) acquire(ctx context.Context, weight int64) error {
	if weight > s.capacity {
		return fmt.Errorf("stack needs %d external addresses, %s allows %d", weight, EnvMaxAddresses, s.capacity)
	}
	if err := s.sem.Acquire(ctx, weight); err != nil {
		return fmt.Errorf("acquire %d of the %s address permits: %w", weight, EnvMaxAddresses, err)
	}
	return nil
}

func (s *addressSlots) release(weight int64) {
	s.sem.Release(weight)
}

func maxAddresses(raw string) (int64, error) {
	if raw == "" {
		return defaultMaxAddresses, nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%s=%q is not a positive integer", EnvMaxAddresses, raw)
	}
	return n, nil
}
