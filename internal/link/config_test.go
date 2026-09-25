package link

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const validRuntimeJSON = `{
  "wireguard": {
    "address": "10.99.0.2/32",
    "listenPort": 51820,
    "mtu": 1380,
    "peers": [
      {"slot": 0, "publicKey": "PEERPUB=", "endpoint": "gateway.example:51820", "allowedIPs": ["10.99.0.1/32"], "persistentKeepalive": 25}
    ]
  },
  "forwards": [
    {"name": "web", "publicPort": 443, "protocol": "TCP", "service": "web.default.svc", "targetPort": 8443},
    {"name": "game", "publicPort": 30000, "protocol": "udp", "service": "game.default.svc", "targetPort": 9000}
  ]
}`

func writeRuntimeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write runtime config: %v", err)
	}
	return path
}

func TestLoadRuntimeConfigHappyPath(t *testing.T) {
	path := writeRuntimeConfig(t, validRuntimeJSON)

	rc, err := LoadRuntimeConfig(path)
	if err != nil {
		t.Fatalf("LoadRuntimeConfig: %v", err)
	}

	if rc.WireGuard.Address != "10.99.0.2/32" {
		t.Errorf("address = %q, want 10.99.0.2/32", rc.WireGuard.Address)
	}
	if len(rc.WireGuard.Peers) != 1 {
		t.Fatalf("peers len = %d, want 1", len(rc.WireGuard.Peers))
	}
	if rc.WireGuard.Peers[0].PersistentKeepalive != 25 {
		t.Errorf("keepalive = %d, want 25", rc.WireGuard.Peers[0].PersistentKeepalive)
	}
	if len(rc.Forwards) != 2 {
		t.Fatalf("forwards len = %d, want 2", len(rc.Forwards))
	}
	if rc.Forwards[0].Protocol != "tcp" {
		t.Errorf("forward[0] protocol = %q, want lowercased tcp", rc.Forwards[0].Protocol)
	}
	if rc.Forwards[1].Protocol != "udp" {
		t.Errorf("forward[1] protocol = %q, want udp", rc.Forwards[1].Protocol)
	}
}

func TestLoadRuntimeConfigValidation(t *testing.T) {
	const onePeer = `"peers":[{"slot":0,"publicKey":"PUB=","endpoint":"h:1"}]`
	tcs := []struct {
		name    string
		body    string
		wantErr string
	}{
		{
			name:    "missing_file",
			body:    "",
			wantErr: "read runtime config",
		},
		{
			name:    "malformed_json",
			body:    `{"wireguard": `,
			wantErr: "unmarshal runtime config",
		},
		{
			name:    "empty_address",
			body:    `{"wireguard":{"address":"",` + onePeer + `}}`,
			wantErr: "wireguard address is required",
		},
		{
			name: "bad_protocol",
			body: `{"wireguard":{"address":"10.0.0.2/32",` + onePeer + `},
			        "forwards":[{"name":"x","publicPort":80,"protocol":"sctp","service":"s","targetPort":80}]}`,
			wantErr: "protocol must be tcp or udp",
		},
		{
			name: "public_port_out_of_range",
			body: `{"wireguard":{"address":"10.0.0.2/32",` + onePeer + `},
			        "forwards":[{"name":"x","publicPort":70000,"protocol":"tcp","service":"s","targetPort":80}]}`,
			wantErr: "public port must be in 1..65535",
		},
		{
			name: "target_port_out_of_range",
			body: `{"wireguard":{"address":"10.0.0.2/32",` + onePeer + `},
			        "forwards":[{"name":"x","publicPort":80,"protocol":"tcp","service":"s","targetPort":0}]}`,
			wantErr: "target port must be in 1..65535",
		},
		{
			name: "empty_service",
			body: `{"wireguard":{"address":"10.0.0.2/32",` + onePeer + `},
			        "forwards":[{"name":"x","publicPort":80,"protocol":"tcp","service":"","targetPort":80}]}`,
			wantErr: "service is required",
		},
		{
			name: "duplicate_port_protocol",
			body: `{"wireguard":{"address":"10.0.0.2/32",` + onePeer + `},
			        "forwards":[
			          {"name":"a","publicPort":80,"protocol":"TCP","service":"s1","targetPort":80},
			          {"name":"b","publicPort":80,"protocol":"tcp","service":"s2","targetPort":81}
			        ]}`,
			wantErr: "collides with",
		},
		{
			name: "local_identity_with_namespace_and_service_name_valid",
			body: `{"trafficPolicy":"Local","healthPort":27003,"identity":{"id":3,"healthPort":27003,"nftTable":"gw3"},"podSelector":{"app":"gateway-link"},
			        "wireguard":{"address":"10.0.0.2/32",` + onePeer + `},
			        "forwards":[{"name":"x","publicPort":80,"protocol":"tcp","namespace":"default","serviceName":"web"}]}`,
			wantErr: "",
		},
		{
			name: "local_health_port_omitted_invalid",
			body: `{"trafficPolicy":"Local","identity":{"id":3,"healthPort":27003,"nftTable":"gw3"},"podSelector":{"app":"gateway-link"},
			        "wireguard":{"address":"10.0.0.2/32",` + onePeer + `}}`,
			wantErr: "healthPort 0 must equal this gateway identity's health port 27003",
		},
		{
			name: "local_health_port_mismatched_invalid",
			body: `{"trafficPolicy":"Local","healthPort":8080,"identity":{"id":3,"healthPort":27003,"nftTable":"gw3"},"podSelector":{"app":"gateway-link"},
			        "wireguard":{"address":"10.0.0.2/32",` + onePeer + `}}`,
			wantErr: "healthPort 8080 must equal this gateway identity's health port 27003",
		},
		{
			name: "local_health_port_equal_to_identity_valid",
			body: `{"trafficPolicy":"Local","healthPort":27003,"identity":{"id":3,"healthPort":27003,"nftTable":"gw3"},"podSelector":{"app":"gateway-link"},
			        "wireguard":{"address":"10.0.0.2/32",` + onePeer + `}}`,
			wantErr: "",
		},
		{
			name: "unknown_traffic_policy_invalid",
			body: `{"trafficPolicy":"Regional",
			        "wireguard":{"address":"10.0.0.2/32",` + onePeer + `}}`,
			wantErr: `unknown traffic policy "Regional"`,
		},
		{
			name: "cluster_traffic_policy_valid",
			body: `{"trafficPolicy":"Cluster",
			        "wireguard":{"address":"10.0.0.2/32",` + onePeer + `}}`,
			wantErr: "",
		},
		{
			name: "local_policy_without_identity_invalid",
			body: `{"trafficPolicy":"Local",
			        "wireguard":{"address":"10.0.0.2/32",` + onePeer + `}}`,
			wantErr: "carries no identity block",
		},
		{
			name: "identity_with_cluster_policy_invalid",
			body: `{"identity":{"id":3,"healthPort":27003,"nftTable":"gw3"},"podSelector":{"app":"gateway-link"},
			        "wireguard":{"address":"10.0.0.2/32",` + onePeer + `}}`,
			wantErr: "Local-only",
		},
		{
			name: "local_identity_without_pod_selector_invalid",
			body: `{"trafficPolicy":"Local","healthPort":27003,"identity":{"id":3,"healthPort":27003,"nftTable":"gw3"},
			        "wireguard":{"address":"10.0.0.2/32",` + onePeer + `},
			        "forwards":[{"name":"x","publicPort":80,"protocol":"tcp","namespace":"default","serviceName":"web"}]}`,
			wantErr: "requires a non-empty podSelector",
		},
		{
			name: "local_forward_missing_service_name_invalid",
			body: `{"trafficPolicy":"Local","healthPort":27003,"identity":{"id":3,"healthPort":27003,"nftTable":"gw3"},"podSelector":{"app":"gateway-link"},
			        "wireguard":{"address":"10.0.0.2/32",` + onePeer + `},
			        "forwards":[{"name":"x","publicPort":80,"protocol":"tcp","namespace":"default"}]}`,
			wantErr: "serviceName is required",
		},
		{
			name: "local_forward_empty_service_port_name_valid",
			body: `{"trafficPolicy":"Local","healthPort":27003,"identity":{"id":3,"healthPort":27003,"nftTable":"gw3"},"podSelector":{"app":"gateway-link"},
			        "wireguard":{"address":"10.0.0.2/32",` + onePeer + `},
			        "forwards":[{"name":"x","publicPort":80,"protocol":"tcp","namespace":"default","serviceName":"web","servicePortName":""}]}`,
			wantErr: "",
		},
		{
			name:    "peer_missing_public_key_invalid",
			body:    `{"wireguard":{"address":"10.0.0.2/32","peers":[{"slot":0,"endpoint":"h:1"}]}}`,
			wantErr: "publicKey is required",
		},
		{
			name:    "peer_slot_below_range_invalid",
			body:    `{"wireguard":{"address":"10.0.0.2/32","peers":[{"slot":-1,"publicKey":"A=","endpoint":"h:1"}]}}`,
			wantErr: "must be in 0..255",
		},
		{
			name:    "peer_slot_zero_valid",
			body:    `{"wireguard":{"address":"10.0.0.2/32","peers":[{"slot":0,"publicKey":"A=","endpoint":"h:1"}]}}`,
			wantErr: "",
		},
		{
			name:    "peer_slot_255_valid",
			body:    `{"wireguard":{"address":"10.0.0.2/32","peers":[{"slot":255,"publicKey":"A=","endpoint":"h:1"}]}}`,
			wantErr: "",
		},
		{
			name:    "peer_slot_above_range_invalid",
			body:    `{"wireguard":{"address":"10.0.0.2/32","peers":[{"slot":256,"publicKey":"A=","endpoint":"h:1"}]}}`,
			wantErr: "must be in 0..255",
		},
		{
			name:    "duplicate_peer_slot_invalid",
			body:    `{"wireguard":{"address":"10.0.0.2/32","peers":[{"slot":1,"publicKey":"A=","endpoint":"h:1"},{"slot":1,"publicKey":"B=","endpoint":"h:2"}]}}`,
			wantErr: "duplicate slot",
		},
		{
			name:    "peer_list_gap_valid",
			body:    `{"wireguard":{"address":"10.0.0.2/32","peers":[{"slot":0,"publicKey":"A=","endpoint":"h:1"},{"slot":2,"publicKey":"B=","endpoint":"h:2"}]}}`,
			wantErr: "",
		},
		{
			name: "local_responders_set_zero_port_invalid",
			body: `{"trafficPolicy":"Local","healthPort":27003,"identity":{"id":3,"healthPort":27003,"nftTable":"gw3"},"podSelector":{"app":"gateway-link"},
			        "responders":{"node-a":"10.244.2.9"},"responderPort":0,
			        "wireguard":{"address":"10.0.0.2/32",` + onePeer + `}}`,
			wantErr: "responderPort must be nonzero when responders is set",
		},
		{
			name: "cluster_responder_target_zero_port_invalid",
			body: `{"responderTarget":"10.96.5.5","responderPort":0,
			        "wireguard":{"address":"10.0.0.2/32",` + onePeer + `}}`,
			wantErr: "responderPort must be nonzero when responderTarget is set",
		},
		{
			name: "cluster_responder_target_nonzero_port_valid",
			body: `{"responderTarget":"10.96.5.5","responderPort":8000,
			        "wireguard":{"address":"10.0.0.2/32",` + onePeer + `}}`,
			wantErr: "",
		},
		{
			name:    "public_address_empty_valid",
			body:    `{"publicAddress":"","wireguard":{"address":"10.0.0.2/32",` + onePeer + `}}`,
			wantErr: "",
		},
		{
			name:    "public_address_ipv4_valid",
			body:    `{"publicAddress":"203.0.113.10","wireguard":{"address":"10.0.0.2/32",` + onePeer + `}}`,
			wantErr: "",
		},
		{
			name:    "public_address_hostname_unparsable",
			body:    `{"publicAddress":"gateway.example","wireguard":{"address":"10.0.0.2/32",` + onePeer + `}}`,
			wantErr: `publicAddress: ParseAddr("gateway.example"): unexpected character (at "gateway.example")`,
		},
		{
			name:    "public_address_ipv6_invalid",
			body:    `{"publicAddress":"2001:db8::1","wireguard":{"address":"10.0.0.2/32",` + onePeer + `}}`,
			wantErr: `publicAddress must be an IPv4 address, got "2001:db8::1"`,
		},
		{
			name:    "public_address_unspecified_invalid",
			body:    `{"publicAddress":"0.0.0.0","wireguard":{"address":"10.0.0.2/32",` + onePeer + `}}`,
			wantErr: `publicAddress must not be the unspecified address, got "0.0.0.0"`,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var path string
			if tc.name == "missing_file" {
				path = filepath.Join(t.TempDir(), "does-not-exist.json")
			} else {
				path = writeRuntimeConfig(t, tc.body)
			}

			_, err := LoadRuntimeConfig(path)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestLoadRuntimeConfigZeroPeers pins that a pending fleet — a load-balanced Gateway whose
// members' VMs do not exist yet — loads in both modes, as the one-peer config minus the peer.
func TestLoadRuntimeConfigZeroPeers(t *testing.T) {
	tcs := []struct {
		name string
		body string
		want RuntimeConfig
	}{
		{
			name: "cluster_zero_peers",
			body: `{"wireguard":{"address":"10.99.0.2/32","listenPort":51820,"mtu":1380,"peers":[]},
			        "forwards":[{"name":"web","publicPort":443,"protocol":"TCP","service":"web.default.svc","targetPort":8443}]}`,
			want: RuntimeConfig{
				WireGuard: WireGuard{Address: "10.99.0.2/32", ListenPort: 51820, MTU: 1380, Peers: []Peer{}},
				Forwards:  []Forward{{Name: "web", PublicPort: 443, Protocol: "tcp", Service: "web.default.svc", TargetPort: 8443}},
			},
		},
		{
			name: "local_zero_peers",
			body: `{"trafficPolicy":"Local","healthPort":27003,"identity":{"id":3,"healthPort":27003,"nftTable":"gw3"},
			        "podSelector":{"app":"gateway-link"},
			        "wireguard":{"address":"10.99.0.2/32","peers":[]},
			        "forwards":[{"name":"web","publicPort":443,"protocol":"TCP","namespace":"default","serviceName":"web"}]}`,
			want: RuntimeConfig{
				TrafficPolicy: TrafficPolicyLocal,
				Identity:      new(NewGatewayIdentity(3)),
				HealthPort:    27003,
				PodSelector:   map[string]string{"app": "gateway-link"},
				WireGuard:     WireGuard{Address: "10.99.0.2/32", Peers: []Peer{}},
				Forwards:      []Forward{{Name: "web", PublicPort: 443, Protocol: "tcp", Namespace: "default", ServiceName: "web"}},
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			rc, err := LoadRuntimeConfig(writeRuntimeConfig(t, tc.body))
			if err != nil {
				t.Fatalf("LoadRuntimeConfig: %v", err)
			}
			if !reflect.DeepEqual(rc, tc.want) {
				t.Errorf("loaded config = %+v, want %+v", rc, tc.want)
			}
		})
	}
}

func TestEmptyPeerEndpointAllowed(t *testing.T) {
	// The operator writes the endpoint once it observes the member's promoted address, so an
	// absent endpoint must still validate; the wg0 address and each peer's public key are not.
	body := `{"wireguard":{"address":"10.0.0.2/32","peers":[{"slot":0,"publicKey":"PUB=","allowedIPs":["10.99.0.1/32"]}]}}`
	path := writeRuntimeConfig(t, body)
	rc, err := LoadRuntimeConfig(path)
	if err != nil {
		t.Fatalf("empty peer endpoint should validate: %v", err)
	}
	if rc.WireGuard.Peers[0].Endpoint != "" {
		t.Errorf("endpoint = %q, want empty", rc.WireGuard.Peers[0].Endpoint)
	}
}

const validLocalRuntimeJSON = `{
  "trafficPolicy": "Local",
  "healthPort": 27003,
  "identity": {"id":3,"healthPort":27003,"nftTable":"gw3"},
  "podSelector": {"app": "gateway-link", "gateway": "gw1"},
  "wireguard": {
    "address": "10.99.0.2/32",
    "peers": [
      {"slot": 0, "publicKey": "PUB=", "endpoint": "gateway.example:51820", "allowedIPs": ["0.0.0.0/0"]}
    ]
  },
  "forwards": [
    {"name": "web", "publicPort": 443, "protocol": "TCP", "namespace": "default", "serviceName": "web"}
  ]
}`

func TestLoadRuntimeConfigLocalHappyPath(t *testing.T) {
	path := writeRuntimeConfig(t, validLocalRuntimeJSON)

	rc, err := LoadRuntimeConfig(path)
	if err != nil {
		t.Fatalf("LoadRuntimeConfig: %v", err)
	}

	if rc.TrafficPolicy != TrafficPolicyLocal {
		t.Errorf("trafficPolicy = %q, want %q", rc.TrafficPolicy, TrafficPolicyLocal)
	}
	if rc.Identity == nil {
		t.Fatalf("identity = nil, want non-nil")
	}
	if want := NewGatewayIdentity(3); *rc.Identity != want {
		t.Errorf("identity = %+v, want %+v", *rc.Identity, want)
	}
	wantSelector := map[string]string{"app": "gateway-link", "gateway": "gw1"}
	if len(rc.PodSelector) != len(wantSelector) {
		t.Fatalf("podSelector = %v, want %v", rc.PodSelector, wantSelector)
	}
	for k, v := range wantSelector {
		if rc.PodSelector[k] != v {
			t.Errorf("podSelector[%q] = %q, want %q", k, rc.PodSelector[k], v)
		}
	}
}

func TestDuplicatePortDifferentProtocolAllowed(t *testing.T) {
	body := `{"wireguard":{"address":"10.0.0.2/32","peers":[{"slot":0,"publicKey":"PUB=","endpoint":"h:1"}]},
	          "forwards":[
	            {"name":"a","publicPort":80,"protocol":"tcp","service":"s1","targetPort":80},
	            {"name":"b","publicPort":80,"protocol":"udp","service":"s2","targetPort":81}
	          ]}`
	path := writeRuntimeConfig(t, body)
	if _, err := LoadRuntimeConfig(path); err != nil {
		t.Fatalf("same port across tcp/udp should be allowed: %v", err)
	}
}
