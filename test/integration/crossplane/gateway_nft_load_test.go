package crossplane

import (
	"context"
	"testing"
	"time"

	"github.com/greg2010/wireguard-gateway-operator/test/harness/netns"
	"github.com/testcontainers/testcontainers-go"
)

// TestGatewayNftLoadsIntoKernel feeds the rendered VM ruleset to a real nft and
// reads the result back, so a syntax error or a construct this kernel rejects
// fails here instead of bricking a booting gateway. The kernel's own dump of the
// gateway table is then re-checked for the IAP-accept-before-DNAT ordering, which
// the file-level assertion cannot prove survives nft's parse and normalisation.
// The container's own eth0 satisfies the ruleset's `iif "eth0"`, which nft resolves
// to an interface index at load time.
func TestGatewayNftLoadsIntoKernel(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	ctr := netns.Start(ctx, t)
	ruleset := renderGatewayNft(t)

	netns.Apply(ctx, t, ctr, ruleset)

	t.Logf("kernel ruleset after load:\n%s", netns.List(ctx, t, ctr, "ruleset"))

	// Scoped to the gateway table so the assertion cannot latch onto a prerouting
	// chain some other table in the container's netns happens to own.
	table := netns.List(ctx, t, ctr, "table", "inet", "gateway")
	assertPreroutingOrder(t, preroutingChain(t, table))
}
