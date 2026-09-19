package e2e

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestRetryNotReady(t *testing.T) {
	notReady := errors.New("ERROR: (gcloud.compute.firewall-rules.create) Could not fetch resource: - " +
		"The resource 'projects/p/global/networks/n' is not ready")
	otherErr := errors.New("gcloud boom")

	tests := []struct {
		name string
		// script drives one run per entry; repeatLast keeps the last entry answering forever.
		script     []error
		repeatLast bool
		// cancelBeforeRun cancels the row's context just before that 1-based run returns.
		cancelBeforeRun int
		wantErr         error
		wantErrIs       []string
		wantErrEq       string
		wantRuns        int
		wantLogHas      string
	}{
		{
			name:     "succeeds on the first call",
			script:   []error{nil},
			wantRuns: 1,
		},
		{
			name:       "not ready twice then succeeds",
			script:     []error{notReady, notReady, nil},
			wantRuns:   3,
			wantLogHas: "is not ready",
		},
		{
			name:      "other error on the first call",
			script:    []error{otherErr},
			wantErr:   otherErr,
			wantErrEq: otherErr.Error(),
			wantRuns:  1,
		},
		{
			name:       "not ready until the deadline",
			script:     []error{notReady},
			repeatLast: true,
			wantErr:    notReady,
			wantErrIs:  []string{"still not ready after", "is not ready"},
			wantLogHas: "is not ready",
		},
		{
			name:            "deadline expires during an attempt after a not-ready one",
			script:          []error{notReady, errors.New("signal: killed")},
			cancelBeforeRun: 2,
			wantErr:         notReady,
			wantErrIs:       []string{"still not ready after", "is not ready", "signal: killed"},
			wantRuns:        2,
			wantLogHas:      "is not ready",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()

			runs := 0
			run := func() error {
				runs++
				i := runs - 1
				if i >= len(tt.script) {
					if !tt.repeatLast {
						t.Fatalf("run called %d times, script has %d entries", runs, len(tt.script))
					}
					i = len(tt.script) - 1
				}
				if tt.cancelBeforeRun == runs {
					cancel()
				}
				return tt.script[i]
			}
			var logged strings.Builder
			logf := func(format string, args ...any) {
				fmt.Fprintf(&logged, format+"\n", args...)
			}

			err := RetryNotReady(ctx, time.Millisecond, logf, run)

			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("RetryNotReady() = %v, want nil", err)
				}
			} else {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("RetryNotReady() = %v, want an error matching %v", err, tt.wantErr)
				}
				if tt.wantErrEq != "" && err.Error() != tt.wantErrEq {
					t.Fatalf("RetryNotReady() error = %q, want %q", err, tt.wantErrEq)
				}
				for _, want := range tt.wantErrIs {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("RetryNotReady() error = %q, want it to contain %q", err, want)
					}
				}
			}
			if tt.wantRuns != 0 && runs != tt.wantRuns {
				t.Fatalf("run count = %d, want %d", runs, tt.wantRuns)
			}
			if tt.wantLogHas != "" && !strings.Contains(logged.String(), tt.wantLogHas) {
				t.Fatalf("log = %q, want it to contain %q", logged.String(), tt.wantLogHas)
			}
		})
	}
}
