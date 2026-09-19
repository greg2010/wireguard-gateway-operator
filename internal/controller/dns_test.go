package controller

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestBuildDNSEndpoint(t *testing.T) {
	tests := []struct {
		name      string
		hostnames []string
		address   string
		wantNil   bool
		wantHosts []string
	}{
		{"no hostnames", nil, "203.0.113.5", true, nil},
		{"no address", []string{"a.example.com"}, "", true, nil},
		{"two hostnames", []string{"a.example.com", "*.example.com"}, "203.0.113.5", false, []string{"a.example.com", "*.example.com"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system", nil, tt.hostnames)
			u := buildDNSEndpoint(gw, tt.address)

			if tt.wantNil {
				if u != nil {
					t.Fatalf("buildDNSEndpoint = %v, want nil", u.Object)
				}
				return
			}
			if u == nil {
				t.Fatal("buildDNSEndpoint = nil, want object")
			}

			if got := u.GetAPIVersion(); got != dnsEndpointAPIVersion {
				t.Errorf("apiVersion = %q, want %q", got, dnsEndpointAPIVersion)
			}
			if got := u.GetKind(); got != dnsEndpointKind {
				t.Errorf("kind = %q, want %q", got, dnsEndpointKind)
			}
			if got := u.GetAnnotations()[cloudflareProxiedAnnotation]; got != "false" {
				t.Errorf("%s = %q, want false", cloudflareProxiedAnnotation, got)
			}

			endpoints, _, err := unstructured.NestedSlice(u.Object, "spec", "endpoints")
			if err != nil {
				t.Fatalf("read endpoints: %v", err)
			}
			gotHosts := map[string]bool{}
			for _, raw := range endpoints {
				ep, ok := raw.(map[string]any)
				if !ok {
					t.Fatalf("endpoint is %T, want map", raw)
				}
				if ep["recordType"] != "A" {
					t.Errorf("recordType = %v, want A", ep["recordType"])
				}
				targets, ok := ep["targets"].([]any)
				if !ok || len(targets) != 1 || targets[0] != tt.address {
					t.Errorf("targets = %v, want [%s]", ep["targets"], tt.address)
				}
				dnsName, ok := ep["dnsName"].(string)
				if !ok {
					t.Fatalf("dnsName is %T, want string", ep["dnsName"])
				}
				gotHosts[dnsName] = true
			}
			for _, h := range tt.wantHosts {
				if !gotHosts[h] {
					t.Errorf("missing endpoint for %q; got %v", h, gotHosts)
				}
			}
		})
	}
}
