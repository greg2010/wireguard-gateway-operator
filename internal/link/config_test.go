package link

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validRuntimeJSON = `{
  "wireguard": {
    "address": "10.99.0.2/32",
    "listenPort": 51820,
    "mtu": 1380,
    "peer": {
      "endpoint": "gateway.example:51820",
      "allowedIPs": ["10.99.0.1/32"],
      "persistentKeepalive": 25
    }
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
	if rc.WireGuard.Peer.PersistentKeepalive != 25 {
		t.Errorf("keepalive = %d, want 25", rc.WireGuard.Peer.PersistentKeepalive)
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
			body:    `{"wireguard":{"address":"","peer":{"endpoint":"h:1"}}}`,
			wantErr: "wireguard address is required",
		},
		{
			name: "bad_protocol",
			body: `{"wireguard":{"address":"10.0.0.2/32","peer":{"endpoint":"h:1"}},
			        "forwards":[{"name":"x","publicPort":80,"protocol":"sctp","service":"s","targetPort":80}]}`,
			wantErr: "protocol must be tcp or udp",
		},
		{
			name: "public_port_out_of_range",
			body: `{"wireguard":{"address":"10.0.0.2/32","peer":{"endpoint":"h:1"}},
			        "forwards":[{"name":"x","publicPort":70000,"protocol":"tcp","service":"s","targetPort":80}]}`,
			wantErr: "public port must be in 1..65535",
		},
		{
			name: "target_port_out_of_range",
			body: `{"wireguard":{"address":"10.0.0.2/32","peer":{"endpoint":"h:1"}},
			        "forwards":[{"name":"x","publicPort":80,"protocol":"tcp","service":"s","targetPort":0}]}`,
			wantErr: "target port must be in 1..65535",
		},
		{
			name: "empty_service",
			body: `{"wireguard":{"address":"10.0.0.2/32","peer":{"endpoint":"h:1"}},
			        "forwards":[{"name":"x","publicPort":80,"protocol":"tcp","service":"","targetPort":80}]}`,
			wantErr: "service is required",
		},
		{
			name: "duplicate_port_protocol",
			body: `{"wireguard":{"address":"10.0.0.2/32","peer":{"endpoint":"h:1"}},
			        "forwards":[
			          {"name":"a","publicPort":80,"protocol":"TCP","service":"s1","targetPort":80},
			          {"name":"b","publicPort":80,"protocol":"tcp","service":"s2","targetPort":81}
			        ]}`,
			wantErr: "collides with",
		},
		{
			name: "local_identity_with_namespace_and_service_name_valid",
			body: `{"trafficPolicy":"Local","identity":{"id":3,"interface":"wg-gw3","nftTable":"gw3","mark":"0x00030000","markMask":"0xffff0000","routeTable":100003,"healthPort":27003},"podSelector":{"app":"gateway-link"},
			        "wireguard":{"address":"10.0.0.2/32","peer":{"endpoint":"h:1"}},
			        "forwards":[{"name":"x","publicPort":80,"protocol":"tcp","namespace":"default","serviceName":"web"}]}`,
			wantErr: "",
		},
		{
			name: "unknown_traffic_policy_invalid",
			body: `{"trafficPolicy":"Regional",
			        "wireguard":{"address":"10.0.0.2/32","peer":{"endpoint":"h:1"}}}`,
			wantErr: `unknown traffic policy "Regional"`,
		},
		{
			name: "cluster_traffic_policy_valid",
			body: `{"trafficPolicy":"Cluster",
			        "wireguard":{"address":"10.0.0.2/32","peer":{"endpoint":"h:1"}}}`,
			wantErr: "",
		},
		{
			name: "local_policy_without_identity_invalid",
			body: `{"trafficPolicy":"Local",
			        "wireguard":{"address":"10.0.0.2/32","peer":{"endpoint":"h:1"}}}`,
			wantErr: "carries no identity block",
		},
		{
			name: "identity_with_cluster_policy_invalid",
			body: `{"identity":{"id":3,"interface":"wg-gw3","nftTable":"gw3","mark":"0x00030000","markMask":"0xffff0000","routeTable":100003,"healthPort":27003},"podSelector":{"app":"gateway-link"},
			        "wireguard":{"address":"10.0.0.2/32","peer":{"endpoint":"h:1"}}}`,
			wantErr: "Local-only",
		},
		{
			name: "local_identity_without_pod_selector_invalid",
			body: `{"trafficPolicy":"Local","identity":{"id":3,"interface":"wg-gw3","nftTable":"gw3","mark":"0x00030000","markMask":"0xffff0000","routeTable":100003,"healthPort":27003},
			        "wireguard":{"address":"10.0.0.2/32","peer":{"endpoint":"h:1"}},
			        "forwards":[{"name":"x","publicPort":80,"protocol":"tcp","namespace":"default","serviceName":"web"}]}`,
			wantErr: "requires a non-empty podSelector",
		},
		{
			name: "local_forward_missing_service_name_invalid",
			body: `{"trafficPolicy":"Local","identity":{"id":3,"interface":"wg-gw3","nftTable":"gw3","mark":"0x00030000","markMask":"0xffff0000","routeTable":100003,"healthPort":27003},"podSelector":{"app":"gateway-link"},
			        "wireguard":{"address":"10.0.0.2/32","peer":{"endpoint":"h:1"}},
			        "forwards":[{"name":"x","publicPort":80,"protocol":"tcp","namespace":"default"}]}`,
			wantErr: "serviceName is required",
		},
		{
			name: "local_forward_empty_service_port_name_valid",
			body: `{"trafficPolicy":"Local","identity":{"id":3,"interface":"wg-gw3","nftTable":"gw3","mark":"0x00030000","markMask":"0xffff0000","routeTable":100003,"healthPort":27003},"podSelector":{"app":"gateway-link"},
			        "wireguard":{"address":"10.0.0.2/32","peer":{"endpoint":"h:1"}},
			        "forwards":[{"name":"x","publicPort":80,"protocol":"tcp","namespace":"default","serviceName":"web","servicePortName":""}]}`,
			wantErr: "",
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

func TestEmptyPeerEndpointAllowed(t *testing.T) {
	// The operator writes the endpoint once it observes the gateway address, so an absent
	// endpoint must still validate; the wg0 address is required regardless.
	body := `{"wireguard":{"address":"10.0.0.2/32","peer":{"allowedIPs":["10.99.0.1/32"]}}}`
	path := writeRuntimeConfig(t, body)
	rc, err := LoadRuntimeConfig(path)
	if err != nil {
		t.Fatalf("empty peer endpoint should validate: %v", err)
	}
	if rc.WireGuard.Peer.Endpoint != "" {
		t.Errorf("endpoint = %q, want empty", rc.WireGuard.Peer.Endpoint)
	}
}

const validLocalRuntimeJSON = `{
  "trafficPolicy": "Local",
  "identity": {"id":3,"interface":"wg-gw3","nftTable":"gw3","mark":"0x00030000","markMask":"0xffff0000","routeTable":100003,"healthPort":27003},
  "podSelector": {"app": "gateway-link", "gateway": "gw1"},
  "wireguard": {
    "address": "10.99.0.2/32",
    "peer": {
      "endpoint": "gateway.example:51820",
      "allowedIPs": ["0.0.0.0/0"]
    }
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
	if want := NewIdentity(3); *rc.Identity != want {
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
	body := `{"wireguard":{"address":"10.0.0.2/32","peer":{"endpoint":"h:1"}},
	          "forwards":[
	            {"name":"a","publicPort":80,"protocol":"tcp","service":"s1","targetPort":80},
	            {"name":"b","publicPort":80,"protocol":"udp","service":"s2","targetPort":81}
	          ]}`
	path := writeRuntimeConfig(t, body)
	if _, err := LoadRuntimeConfig(path); err != nil {
		t.Fatalf("same port across tcp/udp should be allowed: %v", err)
	}
}
