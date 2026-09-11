package link

import (
	_ "embed"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"text/template"
)

// ResolvedForward is a Forward whose backend has been resolved to a concrete address,
// ready to be rendered into nftables DNAT rules.
type ResolvedForward struct {
	Name       string
	PublicPort int
	Protocol   string
	// Target is the DNAT target address: the Service ClusterIP in Cluster mode, the
	// backend pod IP on this node in Local mode.
	Target     string
	TargetPort int
}

//go:embed wgconf.tmpl
var wgConfTemplateText string

var wgConfTemplate = template.Must(template.New("wgconf").Parse(wgConfTemplateText))

// RenderWGConf renders a wg(8) setconf config; Address and MTU are omitted because ip(8) applies
// those. PersistentKeepalive is always emitted, including 0, so wg syncconf clears a dropped value.
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

//go:embed nftables_cluster.tmpl
var nftablesTemplateText string

var nftablesTemplate = template.Must(template.New("nftables").Parse(nftablesTemplateText))

//go:embed nftables_local.tmpl
var nftablesLocalTemplateText string

var nftablesLocalTemplate = template.Must(template.New("nftables_local").Parse(nftablesLocalTemplateText))

// keepMask returns the complement of a mark mask, spelled as nftables and ip(8) spell it. The
// premark chain writes mask and preserves keep-mask, so the two must be exact complements.
func keepMask(markMask string) (string, error) {
	v, err := strconv.ParseUint(markMask, 0, 32)
	if err != nil {
		return "", fmt.Errorf("parse mark mask %q: %w", markMask, err)
	}
	return fmt.Sprintf("0x%08x", ^uint32(v)), nil
}

// nftablesData is the render input both rulesets share. Mark, MarkMask and KeepMask are empty in
// Cluster mode, which programs no connmark; KeepMask is MarkMask's complement.
type nftablesData struct {
	Interface string
	Table     string
	Mark      string
	MarkMask  string
	KeepMask  string
	Forwards  []ResolvedForward
}

// RenderNftables renders the ruleset for rc's mode: the Cluster inet table DNATing public ports to
// ClusterIPs and masquerading tunnel egress, or the per-Gateway Local table DNATing to pod IPs and
// marking tunnel-ingress connections for the return route, masquerading nothing. Output is sorted
// by public port then protocol. A mark mask that cannot be parsed into a keep-mask is an error.
func RenderNftables(rc RuntimeConfig, forwards []ResolvedForward) (string, error) {
	sorted := slices.Clone(forwards)
	slices.SortFunc(sorted, func(a, b ResolvedForward) int {
		if a.PublicPort != b.PublicPort {
			return a.PublicPort - b.PublicPort
		}
		return strings.Compare(a.Protocol, b.Protocol)
	})

	data := nftablesData{
		Interface: interfaceName(rc),
		Table:     nftTableName(rc),
		Forwards:  sorted,
	}
	tmpl := nftablesTemplate
	if rc.isLocal() {
		data.Mark = rc.Identity.Mark
		data.MarkMask = rc.Identity.MarkMask
		keep, err := keepMask(rc.Identity.MarkMask)
		if err != nil {
			return "", err
		}
		data.KeepMask = keep
		tmpl = nftablesLocalTemplate
	}

	var b strings.Builder
	if err := tmpl.Execute(&b, data); err != nil {
		return "", fmt.Errorf("render nftables config: %w", err)
	}
	return b.String(), nil
}
