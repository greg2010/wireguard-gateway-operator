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

// RenderWGConf renders a wg(8) setconf config for wg0; Address and MTU are omitted
// because ip(8) applies those. PersistentKeepalive is always emitted, including 0, so
// wg syncconf clears it when the config drops it.
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

// RenderNftables renders the inet "gateway" table that DNATs public wg0 ports to
// ClusterIPs and masquerades the traffic. The forward chain defaults to drop; output
// is deterministic, sorted by public port then protocol.
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
