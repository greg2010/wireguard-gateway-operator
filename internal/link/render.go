package link

import (
	_ "embed"
	"fmt"
	"slices"
	"strings"
	"text/template"
)

// ResolvedForward is a Forward with its Service resolved to a concrete
// ClusterIP, ready to be rendered into nftables DNAT rules.
type ResolvedForward struct {
	Name       string
	PublicPort int
	Protocol   string
	ClusterIP  string
	TargetPort int
}

//go:embed wgconf.tmpl
var wgConfTemplateText string

var wgConfTemplate = template.Must(template.New("wgconf").Parse(wgConfTemplateText))

// RenderWGConf renders a wg(8) setconf-compatible configuration for wg0. The
// output is suitable for `wg setconf`, which understands only [Interface]
// PrivateKey/ListenPort and [Peer] keys: Address and MTU are interface
// properties applied via ip(8) and are deliberately omitted here. ListenPort is
// emitted only when greater than zero. PersistentKeepalive is always emitted,
// including the value 0, so that `wg syncconf` clears a previously-set keepalive
// when the config drops it. privKey and peerPubKey are base64 WireGuard keys
// read from mounted Secret files, not from rc. It returns an error only if
// template execution fails.
func RenderWGConf(rc RuntimeConfig, privKey, peerPubKey string) (string, error) {
	p := rc.WireGuard.Peer
	data := struct {
		PrivKey             string
		ListenPort          int
		PeerPubKey          string
		Endpoint            string
		AllowedIPs          string
		PersistentKeepalive int
	}{
		PrivKey:             privKey,
		ListenPort:          rc.WireGuard.ListenPort,
		PeerPubKey:          peerPubKey,
		Endpoint:            p.Endpoint,
		AllowedIPs:          strings.Join(p.AllowedIPs, ", "),
		PersistentKeepalive: p.PersistentKeepalive,
	}

	var b strings.Builder
	if err := wgConfTemplate.Execute(&b, data); err != nil {
		return "", fmt.Errorf("render wireguard config: %w", err)
	}
	return b.String(), nil
}

//go:embed nftables.tmpl
var nftablesTemplateText string

var nftablesTemplate = template.Must(template.New("nftables").Parse(nftablesTemplateText))

// RenderNftables renders the inet "gateway" table that DNATs configured public
// ports arriving on wg0 to in-cluster ClusterIPs and masquerades the forwarded
// traffic toward the cluster so backends reply to the link pod.
//
// The document is self-replacing: it opens with `add table inet gateway` then
// `flush table inet gateway`, so a single `nft -f` ensures the table exists,
// empties it, and repopulates it in one atomic transaction. Re-applying the same
// or a changed ruleset is therefore idempotent and never accumulates stale rules.
//
// The forward filter chain defaults to drop and accepts forwarded packets by
// their post-DNAT destination (ClusterIP and target port): the prerouting nat
// hook rewrites the destination before the forward hook runs, so matching the
// public port there would never hit. The established/related rule covers the
// return path. The output is deterministic: forwards are sorted by public port
// then protocol on a copy before rendering. It returns an error only if
// template execution fails.
func RenderNftables(forwards []ResolvedForward) (string, error) {
	sorted := slices.Clone(forwards)
	slices.SortFunc(sorted, func(a, b ResolvedForward) int {
		if a.PublicPort != b.PublicPort {
			return a.PublicPort - b.PublicPort
		}
		return strings.Compare(a.Protocol, b.Protocol)
	})

	var b strings.Builder
	if err := nftablesTemplate.Execute(&b, sorted); err != nil {
		return "", fmt.Errorf("render nftables config: %w", err)
	}
	return b.String(), nil
}
