package link

import (
	"context"
	"errors"
)

// Teardown best-effort removes the link's data plane (wg0 and the inet gateway nft
// table) so a demoted standby stops carrying traffic. Every step runs regardless of
// failures and the per-command errors are joined.
func Teardown(ctx context.Context, run runner) error {
	cmds := []command{
		{name: "ip", args: []string{"link", "del", "wg0"}},
		{name: "nft", args: []string{"delete", "table", "inet", "gateway"}},
	}

	var errs []error
	for _, c := range cmds {
		if err := run(ctx, c); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
