package e2e

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// RetryNotReady runs run immediately and re-runs it every interval while it fails with a
// "is not ready" error, which GCP returns for a resource whose prerequisites are still
// settling; ctx bounds the retrying. Any other error is returned unchanged, unless ctx ended
// during that attempt after a not-ready one: then the error reports the budget running out.
func RetryNotReady(ctx context.Context, interval time.Duration, logf func(string, ...any), run func() error) error {
	start := time.Now()
	elapsed := func() time.Duration { return time.Since(start).Round(time.Second) }
	var lastNotReady error
	for {
		err := run()
		switch {
		case err == nil:
			return nil
		case !strings.Contains(err.Error(), "is not ready"):
			if lastNotReady != nil && ctx.Err() != nil {
				return fmt.Errorf("still not ready after %s: %w; last attempt: %v", elapsed(), lastNotReady, err)
			}
			return err
		}
		lastNotReady = err
		logf("not ready after %s, retrying: %v", elapsed(), err)
		select {
		case <-ctx.Done():
			return fmt.Errorf("still not ready after %s: %w", elapsed(), err)
		case <-time.After(interval):
		}
	}
}
