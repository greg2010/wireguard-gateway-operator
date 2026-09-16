package link

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// chainRules returns chain's rules in render order, each trimmed of the template's indentation,
// so a test can pin the exact set of rules a chain carries.
func chainRules(t *testing.T, ruleset, chain string) []string {
	t.Helper()
	rules := []string{}
	inChain := false
	for line := range strings.SplitSeq(ruleset, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "chain "+chain+" {":
			inChain = true
		case inChain && trimmed == "}":
			return rules
		case inChain && trimmed != "":
			rules = append(rules, trimmed)
		}
	}
	t.Fatalf("ruleset carries no chain %q:\n%s", chain, ruleset)
	return nil
}

// chainHeader matches a chain's opening line, whose name group names the chain.
var chainHeader = regexp.MustCompile(`(?m)^\s*chain (\S+) \{$`)

// renderedChains returns the ruleset's chain names in render order.
func renderedChains(ruleset string) []string {
	names := []string{}
	for _, m := range chainHeader.FindAllStringSubmatch(ruleset, -1) {
		names = append(names, m[1])
	}
	return names
}

// interfaceMatch matches every interface name a rule selects on, in either mode's spelling.
var interfaceMatch = regexp.MustCompile(`(?:iifname|oifname|iif) "([^"]+)"`)

// renderedInterfaces returns the unique interface names the ruleset matches on, sorted.
func renderedInterfaces(ruleset string) []string {
	names := []string{}
	for _, m := range interfaceMatch.FindAllStringSubmatch(ruleset, -1) {
		if !slices.Contains(names, m[1]) {
			names = append(names, m[1])
		}
	}
	slices.Sort(names)
	return names
}

// renderedLines returns text's non-blank lines in order, so a whole rendered document can be
// compared against the exact lines it must carry.
func renderedLines(text string) []string {
	lines := []string{}
	for line := range strings.SplitSeq(text, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	return lines
}

// clusterRC is a minimal Cluster-mode RuntimeConfig, one peer, used by tests that only exercise
// the Cluster nftables template.
func clusterRC() RuntimeConfig {
	return RuntimeConfig{
		WireGuard: WireGuard{
			Peers: []Peer{{Slot: 0, PublicKey: "PUB=", Endpoint: "gateway.example:51820", AllowedIPs: []string{"10.99.0.1/32"}}},
		},
	}
}

func TestRenderNftables(t *testing.T) {
	forwards := []ResolvedForward{
		{Name: "udp-svc", PublicPort: 30000, Protocol: "udp", Target: "10.96.2.2", TargetPort: 9000},
		{Name: "tcp-svc", PublicPort: 8443, Protocol: "tcp", Target: "10.96.1.1", TargetPort: 443},
	}

	out, err := RenderNftables(clusterRC(), forwards)
	if err != nil {
		t.Fatalf("RenderNftables: %v", err)
	}

	wantContains := []string{
		"add table inet gateway",
		"flush table inet gateway",
		"table inet gateway {",
		"type nat hook prerouting priority dstnat; policy accept;",
		`iif "wg0" tcp dport 8443 dnat ip to 10.96.1.1 : 443`,
		`iif "wg0" udp dport 30000 dnat ip to 10.96.2.2 : 9000`,
		"type nat hook postrouting priority srcnat; policy accept;",
		`oifname != "wg0" masquerade`,
		"type filter hook forward priority filter; policy drop;",
		"ct state established,related accept",
		`iif "wg0" ip daddr 10.96.1.1 tcp dport 443 accept`,
		`iif "wg0" ip daddr 10.96.2.2 udp dport 9000 accept`,
		`oifname "wg0" tcp flags syn tcp option maxseg size set rt mtu`,
		"type filter hook input priority filter; policy accept;",
		`iif "wg0" drop`,
	}
	for _, frag := range wantContains {
		if !strings.Contains(out, frag) {
			t.Errorf("rendered nftables missing %q\n---\n%s", frag, out)
		}
	}
}

// TestRenderNftablesClusterInputAdmission verifies the admission rule: a
// configured health port is accepted ahead of the drop that ends the input chain.
func TestRenderNftablesClusterInputAdmission(t *testing.T) {
	rc := clusterRC()
	rc.HealthPort = 8080

	out, err := RenderNftables(rc, nil)
	if err != nil {
		t.Fatalf("RenderNftables: %v", err)
	}

	admitIdx := strings.Index(out, `iif "wg0" tcp dport 8080 accept`)
	dropIdx := strings.Index(out, `iif "wg0" drop`)
	if admitIdx < 0 {
		t.Fatalf("missing health port admission rule:\n%s", out)
	}
	if dropIdx < 0 {
		t.Fatalf("missing input drop rule:\n%s", out)
	}
	if admitIdx >= dropIdx {
		t.Errorf("admission rule must precede drop: admit=%d drop=%d\n%s", admitIdx, dropIdx, out)
	}
}

// TestRenderNftablesClusterNoHealthPortOmitsAdmission pins that an unset health port renders no
// admission rule, keeping a config from an older operator or a test fixture unchanged.
func TestRenderNftablesClusterNoHealthPortOmitsAdmission(t *testing.T) {
	out, err := RenderNftables(clusterRC(), nil)
	if err != nil {
		t.Fatalf("RenderNftables: %v", err)
	}
	want := []string{"type filter hook input priority filter; policy accept;", `iif "wg0" drop`}
	if got := chainRules(t, out, "input"); !slices.Equal(got, want) {
		t.Errorf("input chain rules = %v, want %v", got, want)
	}
}

func TestRenderNftablesDeterministicAndSorted(t *testing.T) {
	forwards := []ResolvedForward{
		{Name: "c", PublicPort: 9000, Protocol: "tcp", Target: "10.0.0.3", TargetPort: 80},
		{Name: "a", PublicPort: 80, Protocol: "udp", Target: "10.0.0.1", TargetPort: 80},
		{Name: "b", PublicPort: 80, Protocol: "tcp", Target: "10.0.0.2", TargetPort: 80},
	}

	first, err := RenderNftables(clusterRC(), forwards)
	if err != nil {
		t.Fatalf("RenderNftables (first): %v", err)
	}
	second, err := RenderNftables(clusterRC(), forwards)
	if err != nil {
		t.Fatalf("RenderNftables (second): %v", err)
	}
	if first != second {
		t.Fatalf("RenderNftables not deterministic:\nfirst:\n%s\nsecond:\n%s", first, second)
	}

	// (80,tcp) must precede (80,udp) must precede (9000,tcp) in the prerouting
	// DNAT lines.
	idxTCP80 := strings.Index(first, "tcp dport 80 dnat ip to 10.0.0.2")
	idxUDP80 := strings.Index(first, "udp dport 80 dnat ip to 10.0.0.1")
	idx9000 := strings.Index(first, "tcp dport 9000 dnat ip to 10.0.0.3")
	if idxTCP80 < 0 || idxUDP80 < 0 || idx9000 < 0 {
		t.Fatalf("missing expected DNAT lines:\n%s", first)
	}
	if idxTCP80 >= idxUDP80 || idxUDP80 >= idx9000 {
		t.Errorf("DNAT lines not sorted by (port, proto): tcp80=%d udp80=%d t9000=%d\n%s",
			idxTCP80, idxUDP80, idx9000, first)
	}
}

// TestRenderNftablesRetargetReferencesOnlyNewClusterIP pins that repointing a forward moves both
// the DNAT and its companion accept rule, leaving no reference to the old ClusterIP.
func TestRenderNftablesRetargetReferencesOnlyNewClusterIP(t *testing.T) {
	const (
		port    = 8453
		proto   = "tcp"
		target  = 443
		oldIP   = "10.96.0.10"
		newIP   = "10.96.0.20"
		svcName = "retarget"
	)

	before, err := RenderNftables(clusterRC(), []ResolvedForward{
		{Name: svcName, PublicPort: port, Protocol: proto, Target: oldIP, TargetPort: target},
	})
	if err != nil {
		t.Fatalf("RenderNftables (before): %v", err)
	}
	if !strings.Contains(before, oldIP) {
		t.Fatalf("before retarget: rendered ruleset should reference old ClusterIP %q\n%s", oldIP, before)
	}

	after, err := RenderNftables(clusterRC(), []ResolvedForward{
		{Name: svcName, PublicPort: port, Protocol: proto, Target: newIP, TargetPort: target},
	})
	if err != nil {
		t.Fatalf("RenderNftables (after): %v", err)
	}

	wantPrerouting := []string{
		"type nat hook prerouting priority dstnat; policy accept;",
		`iif "wg0" tcp dport 8453 dnat ip to 10.96.0.20 : 443`,
	}
	if got := chainRules(t, after, "prerouting"); !slices.Equal(got, wantPrerouting) {
		t.Errorf("after retarget: prerouting rules = %v, want %v", got, wantPrerouting)
	}
	wantForward := []string{
		"type filter hook forward priority filter; policy drop;",
		`oifname "wg0" tcp flags syn tcp option maxseg size set rt mtu`,
		"ct state established,related accept",
		`iif "wg0" ip daddr 10.96.0.20 tcp dport 443 accept`,
	}
	if got := chainRules(t, after, "forward"); !slices.Equal(got, wantForward) {
		t.Errorf("after retarget: forward rules = %v, want %v", got, wantForward)
	}
}

func TestRenderNftablesEmpty(t *testing.T) {
	out, err := RenderNftables(clusterRC(), nil)
	if err != nil {
		t.Fatalf("RenderNftables: %v", err)
	}
	for _, frag := range []string{
		"add table inet gateway",
		"flush table inet gateway",
		"table inet gateway {",
		`oifname != "wg0" masquerade`,
		"policy drop;",
		`iif "wg0" drop`,
	} {
		if !strings.Contains(out, frag) {
			t.Errorf("empty ruleset missing structural fragment %q\n%s", frag, out)
		}
	}
	wantPrerouting := []string{"type nat hook prerouting priority dstnat; policy accept;"}
	if got := chainRules(t, out, "prerouting"); !slices.Equal(got, wantPrerouting) {
		t.Errorf("empty ruleset prerouting rules = %v, want %v", got, wantPrerouting)
	}
}

// TestRenderNftablesClusterClampFirst pins that the MSS clamp precedes every accept rule in the
// Cluster forward chain, since accept is terminal and a clamp behind an accept never runs.
func TestRenderNftablesClusterClampFirst(t *testing.T) {
	forwards := []ResolvedForward{
		{Name: "web", PublicPort: 443, Protocol: "tcp", Target: "10.96.1.1", TargetPort: 8443},
		{Name: "game", PublicPort: 30000, Protocol: "udp", Target: "10.96.2.2", TargetPort: 9000},
	}

	out, err := RenderNftables(clusterRC(), forwards)
	if err != nil {
		t.Fatalf("RenderNftables: %v", err)
	}

	clampIdx := strings.Index(out, `oifname "wg0" tcp flags syn tcp option maxseg size set rt mtu`)
	if clampIdx < 0 {
		t.Fatalf("missing MSS clamp line:\n%s", out)
	}
	establishedIdx := strings.Index(out, "ct state established,related accept")
	if establishedIdx < 0 || clampIdx >= establishedIdx {
		t.Errorf("clamp must precede the established,related accept: clamp=%d established=%d\n%s", clampIdx, establishedIdx, out)
	}
	for _, frag := range []string{
		`iif "wg0" ip daddr 10.96.1.1 tcp dport 8443 accept`,
		`iif "wg0" ip daddr 10.96.2.2 udp dport 9000 accept`,
	} {
		idx := strings.Index(out, frag)
		if idx < 0 {
			t.Fatalf("missing accept line %q:\n%s", frag, out)
		}
		if clampIdx >= idx {
			t.Errorf("clamp must precede accept line %q: clamp=%d accept=%d\n%s", frag, clampIdx, idx, out)
		}
	}
}

// localRC builds a Local-mode RuntimeConfig with one peer per (slot) given.
func localRC(id int, slots ...int) RuntimeConfig {
	peers := make([]Peer, 0, len(slots))
	for _, s := range slots {
		peers = append(peers, Peer{Slot: s, PublicKey: "PUB=", Endpoint: "gateway.example:51820", AllowedIPs: []string{"0.0.0.0/0"}})
	}
	ident := NewGatewayIdentity(id)
	return RuntimeConfig{
		TrafficPolicy: TrafficPolicyLocal,
		Identity:      &ident,
		HealthPort:    ident.HealthPort,
		WireGuard:     WireGuard{Peers: peers},
	}
}

// TestRenderNftablesLocal pins the exact fragment set of the Local ruleset: no masquerade, the
// premark rules, both DNATs, the clamp, the forward and input rules, clamp before every accept.
func TestRenderNftablesLocal(t *testing.T) {
	rc := localRC(3, 0)
	forwards := []ResolvedForward{
		{Name: "web", PublicPort: 443, Protocol: "tcp", Target: "10.244.1.7", TargetPort: 9080},
		{Name: "game", PublicPort: 8081, Protocol: "udp", Target: "10.244.1.8", TargetPort: 8081},
	}

	out, err := RenderNftables(rc, forwards)
	if err != nil {
		t.Fatalf("RenderNftables: %v", err)
	}

	wantContains := []string{
		"add table inet gw3",
		"flush table inet gw3",
		`iifname "wg-gw3" ct state new counter ct mark set ct mark and 0x0000ffff or 0x00030000`,
		`ct direction reply ct mark and 0xffff0000 == 0x00030000 counter meta mark set meta mark and 0x0000ffff or 0x00030000`,
		"chain output {",
		"type route hook output priority mangle; policy accept;",
		`tcp sport 27003 ct direction reply ct mark and 0xffff0000 == 0x00030000 counter meta mark set meta mark and 0x0000ffff or 0x00030000`,
		`iifname "wg-gw3" tcp dport 27003 counter accept`,
		`iifname "wg-gw3" tcp dport 443 counter dnat ip to 10.244.1.7 : 9080`,
		`iifname "wg-gw3" udp dport 8081 counter dnat ip to 10.244.1.8 : 8081`,
		`oifname "wg-gw3" tcp flags syn counter tcp option maxseg size set rt mtu`,
		`iifname "wg-gw3" ct state established,related counter accept`,
		`iifname "wg-gw3" ip daddr 10.244.1.7 tcp dport 9080 ct state new counter accept`,
		`iifname "wg-gw3" ip daddr 10.244.1.8 udp dport 8081 ct state new counter accept`,
		`iifname "wg-gw3" counter drop`,
		`oifname "wg-gw3" ct state established,related counter accept`,
		`oifname "wg-gw3" counter drop`,
	}
	for _, frag := range wantContains {
		if !strings.Contains(out, frag) {
			t.Errorf("rendered local nftables missing %q\n---\n%s", frag, out)
		}
	}
	wantChains := []string{"premark", "output", "prerouting", "forward", "input"}
	if got := renderedChains(out); !slices.Equal(got, wantChains) {
		t.Errorf("local ruleset chains = %v, want %v", got, wantChains)
	}

	clampIdx := strings.Index(out, `oifname "wg-gw3" tcp flags syn counter tcp option maxseg size set rt mtu`)
	for _, frag := range []string{
		`iifname "wg-gw3" ct state established,related counter accept`,
		`iifname "wg-gw3" ip daddr 10.244.1.7 tcp dport 9080 ct state new counter accept`,
		`iifname "wg-gw3" ip daddr 10.244.1.8 udp dport 8081 ct state new counter accept`,
		`oifname "wg-gw3" ct state established,related counter accept`,
	} {
		idx := strings.LastIndex(out, frag)
		if clampIdx >= idx {
			t.Errorf("clamp must precede %q: clamp=%d idx=%d\n%s", frag, clampIdx, idx, out)
		}
	}
}

// TestRenderNftablesLocalMultiSlot covers the Local-mode multi-slot render invariants.
func TestRenderNftablesLocalMultiSlot(t *testing.T) {
	t.Run("local_peer_list_gap_keeps_remaining_identity", func(t *testing.T) {
		out, err := RenderNftables(localRC(7, 0, 2), nil)
		if err != nil {
			t.Fatalf("RenderNftables: %v", err)
		}
		want := []string{"wg-gw7", "wg-gw7-2"}
		if got := renderedInterfaces(out); !slices.Equal(got, want) {
			t.Errorf("rendered local nftables interfaces = %v, want %v", got, want)
		}
	})

	// local_two_slots_disjoint_marks_tables: slot 0 and slot 2's marks/tables/interfaces are
	// pairwise distinct, and slot 0 matches identity_test.go's pinned single-slot values exactly.
	t.Run("local_two_slots_disjoint_marks_tables", func(t *testing.T) {
		out, err := RenderNftables(localRC(3, 0, 2), nil)
		if err != nil {
			t.Fatalf("RenderNftables: %v", err)
		}

		slot0 := NewSlotIdentity(3, 0)
		slot2 := NewSlotIdentity(3, 2)
		if slot0.Interface == slot2.Interface || slot0.Mark == slot2.Mark || slot0.RouteTable == slot2.RouteTable {
			t.Fatalf("slot identities must be pairwise distinct: slot0=%+v slot2=%+v", slot0, slot2)
		}
		if want := NewSlotIdentity(3, 0); slot0 != want {
			t.Errorf("slot 0 = %+v, want %+v (identity_test.go's pinned single-slot values)", slot0, want)
		}
		for _, slot := range []SlotIdentity{slot0, slot2} {
			want := `tcp sport 27003 ct direction reply ct mark and ` + slot.MarkMask + ` == ` + slot.Mark + ` counter meta mark set meta mark and 0x0000ffff or ` + slot.Mark
			if strings.Count(out, want) != 1 {
				t.Errorf("rendered local nftables output chain has %d rules matching %q, want exactly 1\n---\n%s", strings.Count(out, want), want, out)
			}
		}
		for _, frag := range []string{
			`iifname "` + slot0.Interface + `" ct state new counter ct mark set ct mark and 0x0000ffff or ` + slot0.Mark,
			`iifname "` + slot2.Interface + `" ct state new counter ct mark set ct mark and 0x0000ffff or ` + slot2.Mark,
		} {
			if !strings.Contains(out, frag) {
				t.Errorf("rendered local nftables missing %q\n---\n%s", frag, out)
			}
		}
	})
}

// TestRenderNftablesZeroPeers pins the ruleset a pending fleet renders in each mode: the Local
// table with no slot block, and the Cluster ruleset for a peerless interface.
func TestRenderNftablesZeroPeers(t *testing.T) {
	tcs := []struct {
		name string
		rc   RuntimeConfig
		want string
	}{
		{
			name: "local_zero_slots",
			rc:   localRC(5),
			want: `add table inet gw5
flush table inet gw5
table inet gw5 {
	chain premark {
		type filter hook prerouting priority mangle; policy accept;
	}

	chain output {
		type route hook output priority mangle; policy accept;
	}

	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
	}

	chain forward {
		type filter hook forward priority filter; policy accept;
	}

	chain input {
		type filter hook input priority filter; policy accept;
	}
}
`,
		},
		{
			name: "cluster_zero_peers",
			rc:   RuntimeConfig{WireGuard: WireGuard{Address: "10.99.0.2/32", Peers: []Peer{}}},
			want: `add table inet gateway
flush table inet gateway
table inet gateway {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
	}

	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname != "wg0" masquerade
	}

	chain forward {
		type filter hook forward priority filter; policy drop;
		oifname "wg0" tcp flags syn tcp option maxseg size set rt mtu
		ct state established,related accept
	}

	chain input {
		type filter hook input priority filter; policy accept;
		iif "wg0" drop
	}
}
`,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			out, err := RenderNftables(tc.rc, nil)
			if err != nil {
				t.Fatalf("RenderNftables: %v", err)
			}
			if out != tc.want {
				t.Errorf("rendered ruleset =\n%s\nwant\n%s", out, tc.want)
			}
		})
	}
}

// TestRenderNftablesKeepMaskComplementsMarkMask pins that the premark keep-mask complements the
// slot's own mark mask, not the package default, so another mask preserves exactly the other bits.
func TestRenderNftablesKeepMaskComplementsMarkMask(t *testing.T) {
	if want := "0xffff0000"; markMask != want {
		t.Fatalf("markMask = %q, want %q (this test pins keepMask against the identity-derived mask)", markMask, want)
	}
	out, err := RenderNftables(localRC(3, 0), nil)
	if err != nil {
		t.Fatalf("RenderNftables: %v", err)
	}
	wantLine := `iifname "wg-gw3" ct state new counter ct mark set ct mark and 0x0000ffff or 0x00030000`
	if !strings.Contains(out, wantLine) {
		t.Errorf("rendered local nftables missing %q\n---\n%s", wantLine, out)
	}
	if !strings.Contains(out, "ct mark and 0xffff0000 == 0x00030000") {
		t.Errorf("rendered local nftables does not match on mask 0xffff0000\n---\n%s", out)
	}
}

// TestRenderNftablesLocalDeterministic mirrors TestRenderNftablesDeterministicAndSorted
// for the Local template.
func TestRenderNftablesLocalDeterministic(t *testing.T) {
	rc := localRC(3, 0)
	forwards := []ResolvedForward{
		{Name: "c", PublicPort: 9000, Protocol: "tcp", Target: "10.244.1.3", TargetPort: 80},
		{Name: "a", PublicPort: 80, Protocol: "udp", Target: "10.244.1.1", TargetPort: 80},
		{Name: "b", PublicPort: 80, Protocol: "tcp", Target: "10.244.1.2", TargetPort: 80},
	}

	first, err := RenderNftables(rc, forwards)
	if err != nil {
		t.Fatalf("RenderNftables (first): %v", err)
	}
	second, err := RenderNftables(rc, forwards)
	if err != nil {
		t.Fatalf("RenderNftables (second): %v", err)
	}
	if first != second {
		t.Fatalf("RenderNftables not deterministic:\nfirst:\n%s\nsecond:\n%s", first, second)
	}

	idxTCP80 := strings.Index(first, "tcp dport 80 counter dnat ip to 10.244.1.2")
	idxUDP80 := strings.Index(first, "udp dport 80 counter dnat ip to 10.244.1.1")
	idx9000 := strings.Index(first, "tcp dport 9000 counter dnat ip to 10.244.1.3")
	if idxTCP80 < 0 || idxUDP80 < 0 || idx9000 < 0 {
		t.Fatalf("missing expected DNAT lines:\n%s", first)
	}
	if idxTCP80 >= idxUDP80 || idxUDP80 >= idx9000 {
		t.Errorf("DNAT lines not sorted by (port, proto): tcp80=%d udp80=%d t9000=%d\n%s",
			idxTCP80, idxUDP80, idx9000, first)
	}
}

// TestRenderWGConfAllowedIPs pins that the operator's chosen AllowedIPs value passes
// through the template unchanged in both modes.
func TestRenderWGConfAllowedIPs(t *testing.T) {
	tcs := []struct {
		name     string
		rc       RuntimeConfig
		wantLine string
	}{
		{
			name: "cluster_narrow_allowed_ips",
			rc: RuntimeConfig{
				WireGuard: WireGuard{
					Address: "10.99.0.2/32",
					Peers:   []Peer{{Slot: 0, PublicKey: "PEERPUBKEY=", Endpoint: "gateway.example:51820", AllowedIPs: []string{"10.99.0.0/29"}}},
				},
			},
			wantLine: "AllowedIPs = 10.99.0.0/29",
		},
		{
			name:     "local_default_route_allowed_ips",
			rc:       localRC(3, 0),
			wantLine: "AllowedIPs = 0.0.0.0/0",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			out, err := RenderWGConf(tc.rc, "priv")
			if err != nil {
				t.Fatalf("RenderWGConf: %v", err)
			}
			if !strings.Contains(out, tc.wantLine) {
				t.Errorf("wg conf missing %q\n---\n%s", tc.wantLine, out)
			}
		})
	}
}

func TestRenderWGConf(t *testing.T) {
	tcs := []struct {
		name      string
		rc        RuntimeConfig
		privKey   string
		wantLines []string
	}{
		{
			name: "full_peer_with_listenport_and_keepalive",
			rc: RuntimeConfig{
				WireGuard: WireGuard{
					Address:    "10.99.0.2/32",
					ListenPort: 51820,
					MTU:        1380,
					Peers: []Peer{{
						Slot:                0,
						PublicKey:           "PEERPUBKEY=",
						Endpoint:            "gateway.example:51820",
						AllowedIPs:          []string{"10.99.0.1/32", "10.99.0.0/24"},
						PersistentKeepalive: 25,
					}},
				},
			},
			privKey: "MYPRIVKEY=",
			wantLines: []string{
				"[Interface]",
				"PrivateKey = MYPRIVKEY=",
				"ListenPort = 51820",
				"[Peer]",
				"PublicKey = PEERPUBKEY=",
				"Endpoint = gateway.example:51820",
				"AllowedIPs = 10.99.0.1/32, 10.99.0.0/24",
				"PersistentKeepalive = 25",
			},
		},
		{
			name: "listenport_zero_omitted",
			rc: RuntimeConfig{
				WireGuard: WireGuard{
					Address:    "10.99.0.2/32",
					ListenPort: 0,
					Peers: []Peer{{
						Slot:                0,
						PublicKey:           "PK=",
						Endpoint:            "host:1",
						AllowedIPs:          []string{"10.99.0.1/32"},
						PersistentKeepalive: 0,
					}},
				},
			},
			privKey: "PRIV=",
			wantLines: []string{
				"[Interface]",
				"PrivateKey = PRIV=",
				"[Peer]",
				"PublicKey = PK=",
				"Endpoint = host:1",
				"AllowedIPs = 10.99.0.1/32",
				"PersistentKeepalive = 0",
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			out, err := RenderWGConf(tc.rc, tc.privKey)
			if err != nil {
				t.Fatalf("RenderWGConf: %v", err)
			}
			if got := renderedLines(out); !slices.Equal(got, tc.wantLines) {
				t.Errorf("wg conf lines = %v, want %v", got, tc.wantLines)
			}
		})
	}
}

// TestRenderWGConfZeroPeers covers a pending fleet's peerless interface config.
func TestRenderWGConfZeroPeers(t *testing.T) {
	out, err := RenderWGConf(RuntimeConfig{WireGuard: WireGuard{Address: "10.99.0.2/32", ListenPort: 51820, Peers: []Peer{}}}, "PRIV=")
	if err != nil {
		t.Fatalf("RenderWGConf: %v", err)
	}
	want := []string{"[Interface]", "PrivateKey = PRIV=", "ListenPort = 51820"}
	if got := renderedLines(out); !slices.Equal(got, want) {
		t.Errorf("wg conf lines = %v, want %v", got, want)
	}
}

func TestRenderWGConfClusterPeerSet(t *testing.T) {
	rc := RuntimeConfig{
		WireGuard: WireGuard{
			Address: "10.99.0.2/32",
			Peers: []Peer{
				{Slot: 0, PublicKey: "PUBA=", Endpoint: "203.0.113.1:51820", AllowedIPs: []string{"10.99.0.2/32"}, PersistentKeepalive: 25},
				{Slot: 1, PublicKey: "PUBB=", Endpoint: "203.0.113.2:51820", AllowedIPs: []string{"10.99.0.3/32"}, PersistentKeepalive: 25},
			},
		},
	}

	out, err := RenderWGConf(rc, "priv")
	if err != nil {
		t.Fatalf("RenderWGConf: %v", err)
	}

	if n := strings.Count(out, "[Interface]"); n != 1 {
		t.Errorf("[Interface] should appear exactly once, got %d\n---\n%s", n, out)
	}
	if n := strings.Count(out, "[Peer]"); n != 2 {
		t.Errorf("[Peer] should appear exactly twice, got %d\n---\n%s", n, out)
	}
	for _, frag := range []string{
		"PublicKey = PUBA=",
		"Endpoint = 203.0.113.1:51820",
		"AllowedIPs = 10.99.0.2/32",
		"PublicKey = PUBB=",
		"Endpoint = 203.0.113.2:51820",
		"AllowedIPs = 10.99.0.3/32",
	} {
		if !strings.Contains(out, frag) {
			t.Errorf("wg conf missing %q\n---\n%s", frag, out)
		}
	}
}
