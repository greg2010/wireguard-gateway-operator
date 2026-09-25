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

// wgConfPeerData is one [Peer] stanza's render input.
type wgConfPeerData struct {
	PublicKey           string
	Endpoint            string
	AllowedIPs          string
	PersistentKeepalive int
}

// RenderWGConf renders a wg(8) setconf config: one [Interface] block and one [Peer] block per
// entry in rc.WireGuard.Peers, in order. Address and MTU are omitted because ip(8) applies those.
// PersistentKeepalive is always emitted, including 0, so wg syncconf clears a dropped value.
func RenderWGConf(rc RuntimeConfig, privKey string) (string, error) {
	peers := make([]wgConfPeerData, 0, len(rc.WireGuard.Peers))
	for _, p := range rc.WireGuard.Peers {
		peers = append(peers, wgConfPeerData{
			PublicKey:           p.PublicKey,
			Endpoint:            p.Endpoint,
			AllowedIPs:          strings.Join(p.AllowedIPs, ", "),
			PersistentKeepalive: p.PersistentKeepalive,
		})
	}

	data := struct {
		PrivKey    string
		ListenPort int
		Peers      []wgConfPeerData
	}{
		PrivKey:    privKey,
		ListenPort: rc.WireGuard.ListenPort,
		Peers:      peers,
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

// nftablesData is the render input for Cluster's single-interface ruleset. An empty
// ResponderTarget omits the health DNAT and its forward-chain accept.
type nftablesData struct {
	Interface       string
	Table           string
	HealthPort      int
	ResponderTarget string
	ResponderPort   int
	Forwards        []ResolvedForward
}

// localSlotData is one Local slot's connmark identity, feeding its own premark/prerouting/forward
// block in the rendered ruleset.
type localSlotData struct {
	Interface string
	Mark      string
	MarkMask  string
	KeepMask  string
}

// nftablesLocalData is the render input for Local's per-Gateway table. An empty ResponderIP
// omits the health DNAT and its forward-chain accept; an empty PublicAddress omits the hairpin.
type nftablesLocalData struct {
	Table         string
	HealthPort    int
	ResponderIP   string
	ResponderPort int
	PublicAddress string
	Slots         []localSlotData
	Forwards      []ResolvedForward
}

// RenderNftables renders the nftables document for the runtime configuration. nodeName selects
// this replica's entry from rc.Responders in Local mode; Cluster mode ignores it.
func RenderNftables(rc RuntimeConfig, forwards []ResolvedForward, nodeName string) (string, error) {
	sorted := slices.Clone(forwards)
	slices.SortFunc(sorted, func(a, b ResolvedForward) int {
		if a.PublicPort != b.PublicPort {
			return a.PublicPort - b.PublicPort
		}
		return strings.Compare(a.Protocol, b.Protocol)
	})

	if rc.isLocal() {
		slots := make([]localSlotData, 0, len(rc.WireGuard.Peers))
		for _, p := range rc.WireGuard.Peers {
			id := NewSlotIdentity(rc.Identity.ID, p.Slot)
			keep, err := keepMask(id.MarkMask)
			if err != nil {
				return "", err
			}
			slots = append(slots, localSlotData{
				Interface: id.Interface,
				Mark:      id.Mark,
				MarkMask:  id.MarkMask,
				KeepMask:  keep,
			})
		}
		data := nftablesLocalData{
			Table:         rc.Identity.NftTable,
			HealthPort:    rc.HealthPort,
			ResponderIP:   rc.Responders[nodeName],
			ResponderPort: rc.ResponderPort,
			PublicAddress: rc.PublicAddress,
			Slots:         slots,
			Forwards:      sorted,
		}
		var b strings.Builder
		if err := nftablesLocalTemplate.Execute(&b, data); err != nil {
			return "", fmt.Errorf("render nftables config: %w", err)
		}
		return b.String(), nil
	}

	responderTarget := ""
	if rc.HealthPort > 0 {
		responderTarget = rc.ResponderTarget
	}
	data := nftablesData{
		Interface:       clusterInterface,
		Table:           clusterNftTable,
		HealthPort:      rc.HealthPort,
		ResponderTarget: responderTarget,
		ResponderPort:   rc.ResponderPort,
		Forwards:        sorted,
	}
	var b strings.Builder
	if err := nftablesTemplate.Execute(&b, data); err != nil {
		return "", fmt.Errorf("render nftables config: %w", err)
	}
	return b.String(), nil
}
