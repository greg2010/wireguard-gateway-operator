package e2e

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

type pollResult struct {
	residual string
	err      error
}

func TestWaitDrained(t *testing.T) {
	const residual = "network x present, subnetworks=3"
	pollErr := errors.New("gcloud boom")

	tests := []struct {
		name string
		// script drives one poll per entry; repeatLast keeps the last entry answering forever.
		script     []pollResult
		repeatLast bool
		wantErr    bool
		wantPolls  int
		wantErrHas string
		wantLogHas string
	}{
		{
			name:      "drained on first poll",
			script:    []pollResult{{}},
			wantPolls: 1,
		},
		{
			name:       "drained on third poll",
			script:     []pollResult{{residual: residual}, {residual: residual}, {}},
			wantPolls:  3,
			wantLogHas: residual,
		},
		{
			name:       "never drained",
			script:     []pollResult{{residual: residual}},
			repeatLast: true,
			wantErr:    true,
			wantErrHas: residual,
			wantLogHas: residual,
		},
		{
			name:       "poll errors until the deadline",
			script:     []pollResult{{err: pollErr}},
			repeatLast: true,
			wantErr:    true,
			wantErrHas: pollErr.Error(),
			wantLogHas: pollErr.Error(),
		},
		{
			name:       "poll error twice then drained",
			script:     []pollResult{{err: pollErr}, {err: pollErr}, {}},
			wantPolls:  3,
			wantLogHas: pollErr.Error(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()

			polls := 0
			poll := func(context.Context) (string, error) {
				polls++
				i := polls - 1
				if i >= len(tt.script) {
					if !tt.repeatLast {
						t.Fatalf("poll called %d times, script has %d entries", polls, len(tt.script))
					}
					i = len(tt.script) - 1
				}
				return tt.script[i].residual, tt.script[i].err
			}
			var logged strings.Builder
			logf := func(format string, args ...any) {
				fmt.Fprintf(&logged, format+"\n", args...)
			}

			err := WaitDrained(ctx, time.Millisecond, poll, logf)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("WaitDrained() = nil, want an error containing %q", tt.wantErrHas)
				}
				if !strings.Contains(err.Error(), tt.wantErrHas) {
					t.Fatalf("WaitDrained() error = %q, want it to contain %q", err, tt.wantErrHas)
				}
			} else {
				if err != nil {
					t.Fatalf("WaitDrained() = %v, want nil", err)
				}
				if polls != tt.wantPolls {
					t.Fatalf("poll count = %d, want %d", polls, tt.wantPolls)
				}
			}
			if tt.wantLogHas != "" && !strings.Contains(logged.String(), tt.wantLogHas) {
				t.Fatalf("log = %q, want it to contain %q", logged.String(), tt.wantLogHas)
			}
		})
	}
}
