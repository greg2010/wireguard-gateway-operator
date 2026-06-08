package link

import (
	"strings"
	"testing"
)

func TestRenderNftables(t *testing.T) {
	forwards := []ResolvedForward{
		{Name: "udp-svc", PublicPort: 30000, Protocol: "udp", ClusterIP: "10.96.2.2", TargetPort: 9000},
		{Name: "tcp-svc", PublicPort: 8443, Protocol: "tcp", ClusterIP: "10.96.1.1", TargetPort: 443},
	}

	out, err := RenderNftables(forwards)
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
		{Name: "c", PublicPort: 9000, Protocol: "tcp", ClusterIP: "10.0.0.3", TargetPort: 80},
		{Name: "a", PublicPort: 80, Protocol: "udp", ClusterIP: "10.0.0.1", TargetPort: 80},
		{Name: "b", PublicPort: 80, Protocol: "tcp", ClusterIP: "10.0.0.2", TargetPort: 80},
	}

	first, err := RenderNftables(forwards)
	if err != nil {
		t.Fatalf("RenderNftables (first): %v", err)
	}
	second, err := RenderNftables(forwards)
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

// TestRenderNftablesRetargetReferencesOnlyNewClusterIP pins that repointing a forward
// moves both the DNAT and its companion accept rule to the new ClusterIP and leaves no
// reference to the old one.
func TestRenderNftablesRetargetReferencesOnlyNewClusterIP(t *testing.T) {
	const (
		port    = 8453
		proto   = "tcp"
		target  = 443
		oldIP   = "10.96.0.10"
		newIP   = "10.96.0.20"
		svcName = "retarget"
	)

	before, err := RenderNftables([]ResolvedForward{
		{Name: svcName, PublicPort: port, Protocol: proto, ClusterIP: oldIP, TargetPort: target},
	})
	if err != nil {
		t.Fatalf("RenderNftables (before): %v", err)
	}
	if !strings.Contains(before, oldIP) {
		t.Fatalf("before retarget: rendered ruleset should reference old ClusterIP %q\n%s", oldIP, before)
	}

	after, err := RenderNftables([]ResolvedForward{
		{Name: svcName, PublicPort: port, Protocol: proto, ClusterIP: newIP, TargetPort: target},
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
	out, err := RenderNftables(nil)
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
