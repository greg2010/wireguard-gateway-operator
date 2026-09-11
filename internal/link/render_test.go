package link

import (
	"strings"
	"testing"
)

func TestRenderNftables(t *testing.T) {
	forwards := []ResolvedForward{
		{Name: "udp-svc", PublicPort: 30000, Protocol: "udp", Target: "10.96.2.2", TargetPort: 9000},
		{Name: "tcp-svc", PublicPort: 8443, Protocol: "tcp", Target: "10.96.1.1", TargetPort: 443},
	}

	out, err := RenderNftables(RuntimeConfig{}, forwards)
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

func TestRenderNftablesDeterministicAndSorted(t *testing.T) {
	forwards := []ResolvedForward{
		{Name: "c", PublicPort: 9000, Protocol: "tcp", Target: "10.0.0.3", TargetPort: 80},
		{Name: "a", PublicPort: 80, Protocol: "udp", Target: "10.0.0.1", TargetPort: 80},
		{Name: "b", PublicPort: 80, Protocol: "tcp", Target: "10.0.0.2", TargetPort: 80},
	}

	first, err := RenderNftables(RuntimeConfig{}, forwards)
	if err != nil {
		t.Fatalf("RenderNftables (first): %v", err)
	}
	second, err := RenderNftables(RuntimeConfig{}, forwards)
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

	before, err := RenderNftables(RuntimeConfig{}, []ResolvedForward{
		{Name: svcName, PublicPort: port, Protocol: proto, Target: oldIP, TargetPort: target},
	})
	if err != nil {
		t.Fatalf("RenderNftables (before): %v", err)
	}
	if !strings.Contains(before, oldIP) {
		t.Fatalf("before retarget: rendered ruleset should reference old ClusterIP %q\n%s", oldIP, before)
	}

	after, err := RenderNftables(RuntimeConfig{}, []ResolvedForward{
		{Name: svcName, PublicPort: port, Protocol: proto, Target: newIP, TargetPort: target},
	})
	if err != nil {
		t.Fatalf("RenderNftables (after): %v", err)
	}

	wantContains := []string{
		"iif \"wg0\" tcp dport 8453 dnat ip to 10.96.0.20 : 443",
		"iif \"wg0\" ip daddr 10.96.0.20 tcp dport 443 accept",
	}
	for _, frag := range wantContains {
		if !strings.Contains(after, frag) {
			t.Errorf("after retarget: rendered ruleset missing %q\n%s", frag, after)
		}
	}
	if strings.Contains(after, oldIP) {
		t.Errorf("after retarget: rendered ruleset still references old ClusterIP %q; DNAT and accept must move to the new IP and leave nothing behind\n%s", oldIP, after)
	}
}

func TestRenderNftablesEmpty(t *testing.T) {
	out, err := RenderNftables(RuntimeConfig{}, nil)
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
	if strings.Contains(out, "dnat ip to") {
		t.Errorf("empty ruleset should have no DNAT rules:\n%s", out)
	}
}

// TestRenderNftablesClusterClampFirst pins that the MSS clamp precedes every accept rule in the
// Cluster forward chain, since accept is terminal and a clamp behind an accept never runs.
func TestRenderNftablesClusterClampFirst(t *testing.T) {
	forwards := []ResolvedForward{
		{Name: "web", PublicPort: 443, Protocol: "tcp", Target: "10.96.1.1", TargetPort: 8443},
		{Name: "game", PublicPort: 30000, Protocol: "udp", Target: "10.96.2.2", TargetPort: 9000},
	}

	out, err := RenderNftables(RuntimeConfig{}, forwards)
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

// TestRenderNftablesLocal pins the exact fragment set of the Local ruleset: no masquerade, the
// premark rules, both DNATs, the clamp, the forward and input rules, clamp before every accept.
func TestRenderNftablesLocal(t *testing.T) {
	rc := RuntimeConfig{
		TrafficPolicy: TrafficPolicyLocal,
		Identity:      new(NewIdentity(3)),
	}
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
	if strings.Contains(out, "masquerade") {
		t.Errorf("local ruleset must not masquerade:\n%s", out)
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

// TestRenderNftablesKeepMaskComplementsMarkMask pins that the premark keep-mask complements the
// config's mark mask, not the package default, so another mask preserves exactly the other bits.
func TestRenderNftablesKeepMaskComplementsMarkMask(t *testing.T) {
	tcs := []struct {
		name     string
		markMask string
		wantLine string
		wantErr  bool
	}{
		{
			name:     "default_mask",
			markMask: "0xffff0000",
			wantLine: `iifname "wg-gw3" ct state new counter ct mark set ct mark and 0x0000ffff or 0x00030000`,
		},
		{
			name:     "non_default_mask",
			markMask: "0xff000000",
			wantLine: `iifname "wg-gw3" ct state new counter ct mark set ct mark and 0x00ffffff or 0x00030000`,
		},
		{name: "unparseable_mask", markMask: "not-a-mask", wantErr: true},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			id := NewIdentity(3)
			id.MarkMask = tc.markMask
			rc := RuntimeConfig{TrafficPolicy: TrafficPolicyLocal, Identity: &id}

			out, err := RenderNftables(rc, nil)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("RenderNftables with mask %q = %q, want an error", tc.markMask, out)
				}
				return
			}
			if err != nil {
				t.Fatalf("RenderNftables: %v", err)
			}
			if !strings.Contains(out, tc.wantLine) {
				t.Errorf("rendered local nftables missing %q\n---\n%s", tc.wantLine, out)
			}
			if !strings.Contains(out, "ct mark and "+tc.markMask+" == 0x00030000") {
				t.Errorf("rendered local nftables does not match on mask %q\n---\n%s", tc.markMask, out)
			}
		})
	}
}

// TestRenderNftablesLocalDeterministic mirrors TestRenderNftablesDeterministicAndSorted
// for the Local template.
func TestRenderNftablesLocalDeterministic(t *testing.T) {
	rc := RuntimeConfig{
		TrafficPolicy: TrafficPolicyLocal,
		Identity:      new(NewIdentity(3)),
	}
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
					Peer:    Peer{Endpoint: "gateway.example:51820", AllowedIPs: []string{"10.99.0.0/29"}},
				},
			},
			wantLine: "AllowedIPs = 10.99.0.0/29",
		},
		{
			name: "local_default_route_allowed_ips",
			rc: RuntimeConfig{
				TrafficPolicy: TrafficPolicyLocal,
				Identity:      new(NewIdentity(3)),
				WireGuard: WireGuard{
					Address: "10.99.0.2/32",
					Peer:    Peer{Endpoint: "gateway.example:51820", AllowedIPs: []string{"0.0.0.0/0"}},
				},
			},
			wantLine: "AllowedIPs = 0.0.0.0/0",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			out, err := RenderWGConf(tc.rc, "priv", "peerpub")
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
		name            string
		rc              RuntimeConfig
		privKey         string
		peerPubKey      string
		wantContains    []string
		wantNotContains []string
	}{
		{
			name: "full_peer_with_listenport_and_keepalive",
			rc: RuntimeConfig{
				WireGuard: WireGuard{
					Address:    "10.99.0.2/32",
					ListenPort: 51820,
					MTU:        1380,
					Peer: Peer{
						Endpoint:            "gateway.example:51820",
						AllowedIPs:          []string{"10.99.0.1/32", "10.99.0.0/24"},
						PersistentKeepalive: 25,
					},
				},
			},
			privKey:    "MYPRIVKEY=",
			peerPubKey: "PEERPUBKEY=",
			wantContains: []string{
				"[Interface]",
				"PrivateKey = MYPRIVKEY=",
				"ListenPort = 51820",
				"[Peer]",
				"PublicKey = PEERPUBKEY=",
				"Endpoint = gateway.example:51820",
				"AllowedIPs = 10.99.0.1/32, 10.99.0.0/24",
				"PersistentKeepalive = 25",
			},
			wantNotContains: []string{
				"Address",
				"MTU",
			},
		},
		{
			name: "listenport_zero_omitted",
			rc: RuntimeConfig{
				WireGuard: WireGuard{
					Address:    "10.99.0.2/32",
					ListenPort: 0,
					Peer: Peer{
						Endpoint:            "host:1",
						AllowedIPs:          []string{"10.99.0.1/32"},
						PersistentKeepalive: 0,
					},
				},
			},
			privKey:    "PRIV=",
			peerPubKey: "PK=",
			wantContains: []string{
				"PrivateKey = PRIV=",
				"PublicKey = PK=",
				"AllowedIPs = 10.99.0.1/32",
				"PersistentKeepalive = 0",
			},
			wantNotContains: []string{
				"ListenPort",
				"Address",
				"MTU",
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			out, err := RenderWGConf(tc.rc, tc.privKey, tc.peerPubKey)
			if err != nil {
				t.Fatalf("RenderWGConf: %v", err)
			}
			for _, frag := range tc.wantContains {
				if !strings.Contains(out, frag) {
					t.Errorf("wg conf missing %q\n---\n%s", frag, out)
				}
			}
			for _, frag := range tc.wantNotContains {
				if strings.Contains(out, frag) {
					t.Errorf("wg conf should not contain %q\n---\n%s", frag, out)
				}
			}
			if n := strings.Count(out, "PrivateKey"); n != 1 {
				t.Errorf("PrivateKey should appear exactly once, got %d\n---\n%s", n, out)
			}
		})
	}
}
