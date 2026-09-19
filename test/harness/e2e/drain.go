package e2e

import (
	"context"
	"fmt"
	"time"
)

// WaitDrained polls immediately and then every interval until poll reports an empty residual.
// A poll error is logged and retried; it ends the wait only by outliving ctx, whose expiry
// returns an error carrying the last residual or poll error and the elapsed time.
func WaitDrained(
	ctx context.Context,
	interval time.Duration,
	poll func(context.Context) (string, error),
	logf func(string, ...any),
) error {
	start := time.Now()
	var lastResidual string
	var lastErr error
	for {
		residual, err := poll(ctx)
		elapsed := time.Since(start).Round(time.Second)
		switch {
		case err != nil:
			lastResidual, lastErr = "", err
			logf("drain poll failed after %s: %v", elapsed, err)
		case residual == "":
			return nil
		default:
			lastResidual, lastErr = residual, nil
			logf("still draining after %s: %s", elapsed, residual)
		}
		select {
		case <-ctx.Done():
			return drainTimeout(time.Since(start).Round(time.Second), lastResidual, lastErr, ctx.Err())
		case <-time.After(interval):
		}
	}
}

func drainTimeout(elapsed time.Duration, residual string, pollErr error, ctxErr error) error {
	if residual != "" {
		return fmt.Errorf("not drained after %s, last residual: %s: %w", elapsed, residual, ctxErr)
	}
	return fmt.Errorf("not drained after %s, last poll failed: %v: %w", elapsed, pollErr, ctxErr)
}
