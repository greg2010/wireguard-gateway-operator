package controller

import (
	"encoding/base32"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/greg2010/wireguard-gateway-operator/internal/gcpmembers"
	"github.com/greg2010/wireguard-gateway-operator/internal/link"
	"github.com/greg2010/wireguard-gateway-operator/internal/wg"
	wgnetv1alpha1 "github.com/greg2010/wireguard-gateway-operator/pkg/api/v1alpha1"
	hk8s "github.com/greg2010/wireguard-gateway-operator/test/harness/k8s"
)

// testConfig is the operator-level config the builder tests fold into Gateways.
func testConfig() Config {
	return Config{
		LinkImage:           "registry.example.com/gateway-link:test",
		LinkImagePullPolicy: "IfNotPresent",
		UserData:            "#ignition\n",
		EnableOSLogin:       true,
		RequeueInterval:     0,
		SharedNetworkName:   "wgnet-test",
		ProviderConfigName:  "test-provider-config",
		PodNamespace:        "gateway-operator",
	}
}

// testGatewayUID is a stable UID for builder assertions.
const testGatewayUID = types.UID("11112222-3333-4444-5555-666677778888")

func newGateway(name, namespace string, forwards []wgnetv1alpha1.Forward, hostnames []string) *wgnetv1alpha1.Gateway {
	return &wgnetv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, UID: testGatewayUID},
		Spec: wgnetv1alpha1.GatewaySpec{
			GCP: wgnetv1alpha1.GatewayGCPSpec{
				ProjectID:   "test-project",
				Region:      "us-central1",
				Zone:        "us-central1-a",
				MachineType: "e2-small",
			},
			Forwards:     forwards,
			DNSHostnames: hostnames,
		},
	}
}

// clusterBackends is the shape classifyForwards produces for a Cluster-mode Gateway whose
// Services publish numeric targetPorts: a resolved backend port and an unnamed Service port.
func clusterBackends(forwards []wgnetv1alpha1.Forward) []forwardBackend {
	backends := make([]forwardBackend, 0, len(forwards))
	for _, f := range forwards {
		backends = append(backends, forwardBackend{Forward: f, BackendPort: effectiveServicePort(f)})
	}
	return backends
}

func assertNestedString(t *testing.T, u *unstructured.Unstructured, want string, path ...string) {
	t.Helper()
	got, found, err := unstructured.NestedString(u.Object, path...)
	if err != nil {
		t.Fatalf("read %v: %v", path, err)
	}
	if !found {
		t.Fatalf("%v not found, want %q", path, want)
	}
	if got != want {
		t.Errorf("%v = %q, want %q", path, got, want)
	}
}

func decodeJSON(t *testing.T, raw string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(raw), v); err != nil {
		t.Fatalf("unmarshal %q: %v", raw, err)
	}
}

func TestGCPID(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		objName   string
	}{
		{"short", "default", "gw1"},
		{"long names", "a-very-long-namespace-name", "an-equally-long-gateway-resource-name"},
		{"unicode-ish", "ns", "gateway-with-dashes-and-123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := gcpID(tt.namespace, tt.objName)

			if len(got) > gcpIDMaxLen {
				t.Fatalf("gcpID length = %d, want <= %d (%q)", len(got), gcpIDMaxLen, got)
			}
			if !strings.HasPrefix(got, gcpIDPrefix) {
				t.Fatalf("gcpID = %q, want prefix %q", got, gcpIDPrefix)
			}
			if got[0] < 'a' || got[0] > 'z' {
				t.Fatalf("gcpID = %q, want leading letter", got)
			}
			body := strings.TrimPrefix(got, gcpIDPrefix)
			for _, r := range body {
				isLower := r >= 'a' && r <= 'z'
				isB32Digit := r >= '2' && r <= '7'
				if !isLower && !isB32Digit {
					t.Fatalf("gcpID body %q has out-of-charset rune %q (want [a-z2-7])", body, r)
				}
			}

			if again := gcpID(tt.namespace, tt.objName); again != got {
				t.Fatalf("gcpID not deterministic: %q then %q", got, again)
			}
		})
	}

	t.Run("namespace qualified", func(t *testing.T) {
		a := gcpID("ns-a", "gw")
		b := gcpID("ns-b", "gw")
		if a == b {
			t.Fatalf("gcpID collides across namespaces: %q", a)
		}
	})
}

// TestHashedNamesArePinned fixes the exact bytes both hashedName callers produce, so a
// prefix, digest, encoding or truncation change cannot silently rename live objects.
func TestHashedNamesArePinned(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"gcp id", gcpID("default", "gw1"), "gw-aggomndtxrzb5qrg4d7sunz5muq"},
		{
			"clusterrolebinding",
			linkClusterRoleBindingName(newGateway("edge", "wg-system", nil, nil)),
			"gateway-link-cnvcej5geqr66udgtvezbh73rsj",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("name = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestBuildXGatewayGCP(t *testing.T) {
	cfg := testConfig()
	gw := newGateway("edge", "wg-system",
		[]wgnetv1alpha1.Forward{
			{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP},
			{Port: 1194, Protocol: wgnetv1alpha1.ProtocolUDP},
		},
		[]string{"edge.example.com"},
	)

	u, err := buildXGatewayGCP(gw, cfg, gw.Spec.Forwards, false, nil, clusterHealthPort)
	if err != nil {
		t.Fatalf("buildXGatewayGCP: %v", err)
	}

	if got := u.GetAPIVersion(); got != xgatewayGCPAPIVersion {
		t.Errorf("apiVersion = %q, want %q", got, xgatewayGCPAPIVersion)
	}
	if got := u.GetKind(); got != xgatewayGCPKind {
		t.Errorf("kind = %q, want %q", got, xgatewayGCPKind)
	}
	if got := u.GetName(); got != "edge" {
		t.Errorf("name = %q, want edge", got)
	}
	if got := u.GetNamespace(); got != "wg-system" {
		t.Errorf("namespace = %q, want wg-system", got)
	}

	assertNestedString(t, u, "us-central1", "spec", "region")
	assertNestedString(t, u, "us-central1-a", "spec", "zone")
	assertNestedString(t, u, "e2-small", "spec", "machineType")
	assertNestedString(t, u, cfg.UserData, "spec", "userData")

	// sharedNetworkName flows from operator config; every other input flows from
	// gw.Spec (here all defaulted).
	assertNestedString(t, u, cfg.SharedNetworkName, "spec", "sharedNetworkName")
	assertNestedString(t, u, cfg.ProviderConfigName, "spec", "providerConfigName")

	assertNestedString(t, u, "test-project", "spec", "projectID")
	assertNestedString(t, u, effectiveGCPImage(gw), "spec", "image")
	assertNestedString(t, u, effectiveWGGatewayAddress(gw), "spec", "wgGatewayAddress")
	assertNestedString(t, u, effectiveWGLinkAddress(gw), "spec", "wgLinkAddress")
	assertNestedString(t, u, effectiveWGSubnet(gw), "spec", "wgSubnet")

	wantWGPort := int64(effectiveWireguardPort(gw))
	if got, _, _ := unstructured.NestedInt64(u.Object, "spec", "wgListenPort"); got != wantWGPort {
		t.Errorf("wgListenPort = %d, want %d", got, wantWGPort)
	}
	wantWGMTU := int64(effectiveWGMTU(gw))
	if got, _, _ := unstructured.NestedInt64(u.Object, "spec", "wgMTU"); got != wantWGMTU {
		t.Errorf("wgMTU = %d, want %d", got, wantWGMTU)
	}
	if got, _, _ := unstructured.NestedInt64(u.Object, "spec", "diskSizeGB"); got != int64(effectiveGCPDiskSizeGB(gw)) {
		t.Errorf("diskSizeGB = %d, want %d", got, effectiveGCPDiskSizeGB(gw))
	}
	wantAddr := map[string]any{"type": "Reserved"}
	gotAddr, found, err := unstructured.NestedMap(u.Object, "spec", "address")
	if err != nil || !found {
		t.Fatalf("read spec.address: found=%v err=%v", found, err)
	}
	if !reflect.DeepEqual(gotAddr, wantAddr) {
		t.Errorf("spec.address = %#v, want %#v", gotAddr, wantAddr)
	}
	if got, _, _ := unstructured.NestedBool(u.Object, "spec", "enableOsLogin"); got != cfg.EnableOSLogin {
		t.Errorf("enableOsLogin = %v, want %v", got, cfg.EnableOSLogin)
	}

	assertNestedString(t, u, gcpID(gw.Namespace, gw.Name), "spec", "serviceAccountId")
	assertNestedString(t, u, testRecordNameBase(t, gw), "spec", "secretId")

	ports, _, err := unstructured.NestedSlice(u.Object, "spec", "allowedPorts")
	if err != nil {
		t.Fatalf("read allowedPorts: %v", err)
	}
	if len(ports) != 2 {
		t.Fatalf("allowedPorts len = %d, want 2", len(ports))
	}
	byPort := map[int64]string{}
	for _, raw := range ports {
		p, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("allowedPort entry is %T, want map", raw)
		}
		port, ok := p["port"].(int64)
		if !ok {
			t.Fatalf("allowedPort port is %T, want int64", p["port"])
		}
		proto, _ := p["protocol"].(string)
		byPort[port] = proto
	}
	if byPort[443] != "tcp" {
		t.Errorf("allowedPort 443 protocol = %q, want tcp (lowercased)", byPort[443])
	}
	if byPort[1194] != "udp" {
		t.Errorf("allowedPort 1194 protocol = %q, want udp (lowercased)", byPort[1194])
	}

	if _, found, _ := unstructured.NestedFieldNoCopy(u.Object, "status"); found {
		t.Errorf("buildXGatewayGCP must not set status; serviceAccountEmail is GCP-observed")
	}
}

// TestBuildXGatewayGCPAddress pins the 1:1 mapping from spec.gcp.address to the composite's
// spec.address for each form, including the zero block's Reserved default.
func TestBuildXGatewayGCPAddress(t *testing.T) {
	cfg := testConfig()
	tests := []struct {
		name string
		addr wgnetv1alpha1.GatewayGCPAddressSpec
		want map[string]any
	}{
		{
			name: "zero block defaults to Reserved",
			addr: wgnetv1alpha1.GatewayGCPAddressSpec{},
			want: map[string]any{"type": "Reserved"},
		},
		{
			name: "explicit reserved",
			addr: wgnetv1alpha1.GatewayGCPAddressSpec{Type: wgnetv1alpha1.GatewayGCPAddressReserved},
			want: map[string]any{"type": "Reserved"},
		},
		{
			name: "ephemeral",
			addr: wgnetv1alpha1.GatewayGCPAddressSpec{Type: wgnetv1alpha1.GatewayGCPAddressEphemeral},
			want: map[string]any{"type": "Ephemeral"},
		},
		{
			name: "external by name",
			addr: wgnetv1alpha1.GatewayGCPAddressSpec{
				Type:     wgnetv1alpha1.GatewayGCPAddressExternal,
				External: &wgnetv1alpha1.GatewayGCPExternalAddress{Name: "prod-edge-ip"},
			},
			want: map[string]any{"type": "External", "external": map[string]any{"name": "prod-edge-ip"}},
		},
		{
			name: "external by ip",
			addr: wgnetv1alpha1.GatewayGCPAddressSpec{
				Type:     wgnetv1alpha1.GatewayGCPAddressExternal,
				External: &wgnetv1alpha1.GatewayGCPExternalAddress{IP: "34.76.10.20"},
			},
			want: map[string]any{"type": "External", "external": map[string]any{"ip": "34.76.10.20"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system", nil, nil)
			gw.Spec.GCP.Address = tt.addr

			u, err := buildXGatewayGCP(gw, cfg, gw.Spec.Forwards, false, nil, clusterHealthPort)
			if err != nil {
				t.Fatalf("buildXGatewayGCP: %v", err)
			}
			got, found, err := unstructured.NestedMap(u.Object, "spec", "address")
			if err != nil || !found {
				t.Fatalf("read spec.address: found=%v err=%v", found, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("spec.address = %#v, want %#v", got, tt.want)
			}
		})
	}
}

// TestTemplateRevision verifies template-affecting inputs change the revision.
func TestTemplateRevision(t *testing.T) {
	cfg := testConfig()
	base := func(t *testing.T, gw *wgnetv1alpha1.Gateway) string {
		t.Helper()
		return testRecordNameBase(t, gw)
	}

	tests := []struct {
		name          string
		mutate        func(gw *wgnetv1alpha1.Gateway)
		wantIdentical bool
	}{
		{name: "unchanged inputs", mutate: func(*wgnetv1alpha1.Gateway) {}, wantIdentical: true},
		{name: "same name, new uid", mutate: func(gw *wgnetv1alpha1.Gateway) {
			gw.UID = types.UID("99998888-7777-6666-5555-444433332222")
		}},
		{name: "new project", mutate: func(gw *wgnetv1alpha1.Gateway) { gw.Spec.GCP.ProjectID = "other-project" }},
		{name: "new machine type", mutate: func(gw *wgnetv1alpha1.Gateway) { gw.Spec.GCP.MachineType = "e2-medium" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system", nil, nil)
			first := templateRevision(gw, cfg, base(t, gw))

			other := newGateway("edge", "wg-system", nil, nil)
			tt.mutate(other)
			second := templateRevision(other, cfg, base(t, other))

			if identical := first == second; identical != tt.wantIdentical {
				t.Errorf("templateRevision = %q and %q, identical=%v, want identical=%v",
					first, second, identical, tt.wantIdentical)
			}
		})
	}
}

// testRecordNameBase is the record naming base the VM reads as its "secret-id" metadata
// value and suffixes with its own name to derive its bundle id.
func testRecordNameBase(t *testing.T, gw *wgnetv1alpha1.Gateway) string {
	t.Helper()
	base, err := gcpmembers.NameBase(string(gw.UID), gw.Spec.GCP.ProjectID)
	if err != nil {
		t.Fatalf("gcpmembers.NameBase(...) returned unexpected error: %v", err)
	}
	return base
}

// TestBuildXGatewayGCPBranches verifies the composite for both provisioning branches.
func TestBuildXGatewayGCPBranches(t *testing.T) {
	cfg := testConfig()
	singleInstanceKeys := []string{
		"address", "crossplane", "diskSizeGB", "enableOsLogin", "image", "machineType",
		"projectID", "providerConfigName", "region", "secretId", "serviceAccountId",
		"sharedNetworkName", "spot", "trafficPolicy", "userData", "wgGatewayAddress",
		"wgLinkAddress", "wgListenPort", "wgMTU", "wgSubnet", "zone",
	}
	loadBalancedKeys := append(append([]string{}, singleInstanceKeys...),
		"healthPort", "loadBalanced", "members", "sessionAffinity", "targetSize",
		"templateRevision", "zones")
	slices.Sort(loadBalancedKeys)

	roster := func(t *testing.T, gw *wgnetv1alpha1.Gateway, name string) []gcpmembers.RosterEntry {
		t.Helper()
		names, err := gcpmembers.NameResourceNames(string(gw.UID), gw.Spec.GCP.ProjectID, name)
		if err != nil {
			t.Fatalf("gcpmembers.NameResourceNames(...) returned unexpected error: %v", err)
		}
		return []gcpmembers.RosterEntry{{Name: name, Slot: 0, TunnelAddress: "10.99.0.1", ManagedResourceNames: names}}
	}

	tests := []struct {
		name           string
		loadBalanced   bool
		replicas       int32
		result         func(t *testing.T, gw *wgnetv1alpha1.Gateway) *gcpmembers.Result
		wantKeys       []string
		wantTargetSize int64
		wantMembers    []any
	}{
		{
			name:     "single instance without an observed name renders no roster",
			wantKeys: singleInstanceKeys,
		},
		{
			name: "single instance with an observed name renders one member",
			result: func(t *testing.T, gw *wgnetv1alpha1.Gateway) *gcpmembers.Result {
				return &gcpmembers.Result{Roster: roster(t, gw, "gw-edge-9x2k")}
			},
			wantKeys:    slices.Sorted(slices.Values(append(append([]string{}, singleInstanceKeys...), "members"))),
			wantMembers: []any{memberEntry("gw-edge-9x2k")},
		},
		{
			name:           "load balanced without a result renders an empty roster",
			loadBalanced:   true,
			replicas:       2,
			wantKeys:       loadBalancedKeys,
			wantTargetSize: 2,
			wantMembers:    []any{},
		},
		{
			name:         "load balanced with a result renders its roster",
			loadBalanced: true,
			replicas:     2,
			result: func(t *testing.T, gw *wgnetv1alpha1.Gateway) *gcpmembers.Result {
				return &gcpmembers.Result{TargetSize: 1, Roster: roster(t, gw, "gw-edge-7f31")}
			},
			wantKeys:       loadBalancedKeys,
			wantTargetSize: 1,
			wantMembers:    []any{memberEntry("gw-edge-7f31")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system", nil, nil)
			gw.Spec.GCP.Replicas = tt.replicas
			if tt.loadBalanced {
				gw.Spec.GCP.LoadBalancer = &wgnetv1alpha1.GatewayGCPLoadBalancerSpec{SessionAffinity: "NONE"}
			}
			var result *gcpmembers.Result
			if tt.result != nil {
				result = tt.result(t, gw)
			}

			u, err := buildXGatewayGCP(gw, cfg, nil, tt.loadBalanced, result, clusterHealthPort)
			if err != nil {
				t.Fatalf("buildXGatewayGCP: %v", err)
			}
			specMap, found, err := unstructured.NestedMap(u.Object, "spec")
			if err != nil || !found {
				t.Fatalf("read spec: found=%v err=%v", found, err)
			}
			if got := slices.Sorted(maps.Keys(specMap)); !slices.Equal(got, tt.wantKeys) {
				t.Errorf("spec keys = %v, want %v", got, tt.wantKeys)
			}
			if tt.loadBalanced {
				if got, _, _ := unstructured.NestedInt64(u.Object, "spec", "targetSize"); got != tt.wantTargetSize {
					t.Errorf("spec.targetSize = %d, want %d", got, tt.wantTargetSize)
				}
				if got, _, _ := unstructured.NestedBool(u.Object, "spec", "loadBalanced"); !got {
					t.Errorf("spec.loadBalanced = %v, want true", got)
				}
			}
			if tt.wantMembers != nil {
				got, _, err := unstructured.NestedSlice(u.Object, "spec", "members")
				if err != nil {
					t.Fatalf("read spec.members: %v", err)
				}
				if !reflect.DeepEqual(got, tt.wantMembers) {
					t.Errorf("spec.members = %#v, want %#v", got, tt.wantMembers)
				}
			}
		})
	}
}

// memberEntry is the exact roster entry the composite carries for instanceName on the
// fixture Gateway: names derived from the base plus the instance's own name.
func memberEntry(instanceName string) map[string]any {
	base := "gw-" + string(testGatewayUID) + "-test-project-" + instanceName
	return map[string]any{
		"name":                     instanceName,
		"slot":                     int64(0),
		"tunnelAddress":            "10.99.0.1",
		"kubernetesSecretName":     base,
		"cloudSecretName":          base,
		"cloudSecretVersionName":   base + "-version",
		"cloudSecretIamMemberName": base + "-iam",
	}
}

// TestBuildXGatewayGCPKeySet pins the composite's exact spec key set: a stray or
// dropped field fails here even when no other test reads it.
func TestBuildXGatewayGCPKeySet(t *testing.T) {
	cfg := testConfig()
	gw := newGateway("edge", "wg-system",
		[]wgnetv1alpha1.Forward{{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP}},
		nil,
	)

	u, err := buildXGatewayGCP(gw, cfg, gw.Spec.Forwards, false, nil, clusterHealthPort)
	if err != nil {
		t.Fatalf("buildXGatewayGCP: %v", err)
	}
	specMap, found, err := unstructured.NestedMap(u.Object, "spec")
	if err != nil || !found {
		t.Fatalf("read spec: found=%v err=%v", found, err)
	}
	got := slices.Sorted(maps.Keys(specMap))
	want := []string{
		"address", "allowedPorts", "crossplane", "diskSizeGB", "enableOsLogin", "image",
		"machineType", "projectID", "providerConfigName", "region", "secretId",
		"serviceAccountId", "sharedNetworkName", "spot", "trafficPolicy", "userData",
		"wgGatewayAddress", "wgLinkAddress", "wgListenPort", "wgMTU",
		"wgSubnet", "zone",
	}
	if !slices.Equal(got, want) {
		t.Errorf("spec keys = %v, want %v", got, want)
	}
}

// TestBuildXGatewayGCPOptionalFields pins the fields the builder omits when unconfigured
// against image and diskSizeGB, which carry CRD defaults and are always set.
func TestBuildXGatewayGCPOptionalFields(t *testing.T) {
	cfg := testConfig()
	cfg.UserData = ""
	cfg.EnableOSLogin = false

	gw := newGateway("edge", "wg-system", nil, nil)

	u, err := buildXGatewayGCP(gw, cfg, gw.Spec.Forwards, false, nil, clusterHealthPort)
	if err != nil {
		t.Fatalf("buildXGatewayGCP: %v", err)
	}

	// enableOsLogin is set unconditionally from config, so a false config value
	// surfaces as an explicit false rather than an omitted field.
	if got, _, _ := unstructured.NestedBool(u.Object, "spec", "enableOsLogin"); got != false {
		t.Errorf("enableOsLogin = %v, want false", got)
	}

	for _, field := range []string{"userData", "allowedPorts"} {
		if _, found, _ := unstructured.NestedFieldNoCopy(u.Object, "spec", field); found {
			t.Errorf("spec.%s set, want omitted when unconfigured/empty", field)
		}
	}

	// image and diskSizeGB are always present once defaulting is applied.
	for _, field := range []string{"image", "diskSizeGB"} {
		if _, found, _ := unstructured.NestedFieldNoCopy(u.Object, "spec", field); !found {
			t.Errorf("spec.%s absent, want always set from defaulted gw.Spec", field)
		}
	}
}

// TestBuildXGatewayGCPWireguardListenPort pins that a non-default listen port flows
// verbatim onto wgListenPort, so the gateway VM boots on the port the link dials.
func TestBuildXGatewayGCPWireguardListenPort(t *testing.T) {
	cfg := testConfig()
	gw := newGateway("edge", "wg-system", nil, nil)
	gw.Spec.Wireguard.ListenPort = 51999

	u, err := buildXGatewayGCP(gw, cfg, gw.Spec.Forwards, false, nil, clusterHealthPort)
	if err != nil {
		t.Fatalf("buildXGatewayGCP: %v", err)
	}

	if got, _, _ := unstructured.NestedInt64(u.Object, "spec", "wgListenPort"); got != 51999 {
		t.Errorf("wgListenPort = %d, want 51999 (non-default spec.wireguard.listenPort)", got)
	}
}

// TestBuildXGatewayGCPWireguardMTU pins that a non-default mtu flows verbatim onto wgMTU, so
// the VM sets wg0 to the same MTU the link uses rather than leaving it at the kernel default.
func TestBuildXGatewayGCPWireguardMTU(t *testing.T) {
	cfg := testConfig()
	gw := newGateway("edge", "wg-system", nil, nil)
	gw.Spec.Wireguard.MTU = 1280

	u, err := buildXGatewayGCP(gw, cfg, gw.Spec.Forwards, false, nil, clusterHealthPort)
	if err != nil {
		t.Fatalf("buildXGatewayGCP: %v", err)
	}

	if got, _, _ := unstructured.NestedInt64(u.Object, "spec", "wgMTU"); got != 1280 {
		t.Errorf("wgMTU = %d, want 1280 (non-default spec.wireguard.mtu)", got)
	}
}

func TestBuildBundleSecret(t *testing.T) {
	gw := newGateway("edge", "wg-system", nil, nil)
	sec := buildBundleSecret(gw, "GATEWAY_PRIV", "LINK_PUB")

	if sec.Name != "edge-bundle" {
		t.Errorf("bundle secret name = %q, want edge-bundle", sec.Name)
	}
	if sec.Namespace != "wg-system" {
		t.Errorf("bundle secret namespace = %q, want wg-system", sec.Namespace)
	}
	if sec.Type != corev1.SecretTypeOpaque {
		t.Errorf("bundle secret type = %q, want Opaque", sec.Type)
	}
	got := string(sec.Data[wg.BundleKey])
	want := "GATEWAY_PRIV\nLINK_PUB\n"
	if got != want {
		t.Errorf("bundle data[%q] = %q, want %q", wg.BundleKey, got, want)
	}
	if len(sec.Data) != 1 {
		t.Errorf("bundle data keys = %d, want 1", len(sec.Data))
	}
}

func TestBuildLinkSecret(t *testing.T) {
	gw := newGateway("edge", "wg-system", nil, nil)
	sec := buildLinkSecret(gw, "LINK_PRIV", "GATEWAY_PUB")

	if sec.Name != "edge-link" {
		t.Errorf("link secret name = %q, want edge-link", sec.Name)
	}
	if got := string(sec.Data[wg.LinkPrivateKey]); got != "LINK_PRIV" {
		t.Errorf("link data[%q] = %q, want LINK_PRIV", wg.LinkPrivateKey, got)
	}
	if got := string(sec.Data[wg.LinkPeerPublicKey]); got != "GATEWAY_PUB" {
		t.Errorf("link data[%q] = %q, want GATEWAY_PUB", wg.LinkPeerPublicKey, got)
	}
}

func TestBuildLinkConfigMap(t *testing.T) {
	gw := newGateway("edge", "wg-system",
		[]wgnetv1alpha1.Forward{
			{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web", TargetPort: 8443},
			{Port: 1194, Protocol: wgnetv1alpha1.ProtocolUDP, Service: "vpn"},
		}, nil)

	cm, err := buildLinkConfigMap(gw, "", clusterBackends(gw.Spec.Forwards), nil, "GATEWAY_PUB_TEST", nil, clusterHealthPort)
	if err != nil {
		t.Fatalf("buildLinkConfigMap: %v", err)
	}
	if cm.Name != "edge-link" {
		t.Errorf("link configmap name = %q, want edge-link", cm.Name)
	}

	raw, ok := cm.Data[linkConfigKey]
	if !ok {
		t.Fatalf("configmap missing %q", linkConfigKey)
	}
	var rc link.RuntimeConfig
	decodeJSON(t, raw, &rc)

	if rc.WireGuard.Address != "10.99.0.2/29" {
		t.Errorf("wireguard.address = %q, want 10.99.0.2/29", rc.WireGuard.Address)
	}
	wantMTU := int(effectiveWGMTU(gw))
	if rc.WireGuard.MTU != wantMTU {
		t.Errorf("wireguard.mtu = %d, want %d", rc.WireGuard.MTU, wantMTU)
	}
	wantKeepalive := int(effectiveWGKeepalive(gw))
	if rc.WireGuard.Peers[0].PersistentKeepalive != wantKeepalive {
		t.Errorf("peer.persistentKeepalive = %d, want %d", rc.WireGuard.Peers[0].PersistentKeepalive, wantKeepalive)
	}
	wantSubnet := effectiveWGSubnet(gw)
	if len(rc.WireGuard.Peers[0].AllowedIPs) != 1 || rc.WireGuard.Peers[0].AllowedIPs[0] != wantSubnet {
		t.Errorf("peer.allowedIPs = %v, want [%s]", rc.WireGuard.Peers[0].AllowedIPs, wantSubnet)
	}

	if rc.WireGuard.Peers[0].Endpoint != "" {
		t.Errorf("peer.endpoint = %q, want empty when address is unknown", rc.WireGuard.Peers[0].Endpoint)
	}

	wantForwards := []link.Forward{
		{Name: "tcp-443", PublicPort: 443, Protocol: "tcp", Service: "web.wg-system.svc.cluster.local", TargetPort: 8443},
		{Name: "udp-1194", PublicPort: 1194, Protocol: "udp", Service: "vpn.wg-system.svc.cluster.local", TargetPort: 1194},
	}
	if !slices.Equal(rc.Forwards, wantForwards) {
		t.Errorf("forwards = %+v, want %+v", rc.Forwards, wantForwards)
	}
}

// TestBuildLinkConfigMapEndpoint pins that an empty address leaves the peer endpoint unset,
// so the link waits and reloads in place once the gateway IP appears.
func TestBuildLinkConfigMapEndpoint(t *testing.T) {
	tests := []struct {
		name         string
		address      string
		wantEndpoint string
	}{
		{"address set renders host:port", "203.0.113.5", "203.0.113.5:51820"},
		{"empty address leaves endpoint unset", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system",
				[]wgnetv1alpha1.Forward{{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}}, nil)

			cm, err := buildLinkConfigMap(gw, tt.address, clusterBackends(gw.Spec.Forwards), nil, "GATEWAY_PUB_TEST", nil, clusterHealthPort)
			if err != nil {
				t.Fatalf("buildLinkConfigMap: %v", err)
			}
			var rc link.RuntimeConfig
			decodeJSON(t, cm.Data[linkConfigKey], &rc)

			if rc.WireGuard.Peers[0].Endpoint != tt.wantEndpoint {
				t.Errorf("peer.endpoint = %q, want %q", rc.WireGuard.Peers[0].Endpoint, tt.wantEndpoint)
			}
		})
	}
}

// TestBuildLinkConfigMapTargetPortDefault covers the target-port defaulting rule:
// an unset TargetPort mirrors Port, while a set one is preserved verbatim.
func TestBuildLinkConfigMapTargetPortDefault(t *testing.T) {
	tests := []struct {
		name           string
		targetPort     int32
		wantTargetPort int
	}{
		{"zero defaults to port", 0, 443},
		{"set distinct from port preserved", 8443, 8443},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system",
				[]wgnetv1alpha1.Forward{
					{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web", TargetPort: tt.targetPort},
				}, nil)

			cm, err := buildLinkConfigMap(gw, "", clusterBackends(gw.Spec.Forwards), nil, "GATEWAY_PUB_TEST", nil, clusterHealthPort)
			if err != nil {
				t.Fatalf("buildLinkConfigMap: %v", err)
			}
			var rc link.RuntimeConfig
			decodeJSON(t, cm.Data[linkConfigKey], &rc)

			if len(rc.Forwards) != 1 {
				t.Fatalf("forwards = %d, want 1", len(rc.Forwards))
			}
			if got := rc.Forwards[0].TargetPort; got != tt.wantTargetPort {
				t.Errorf("targetPort = %d, want %d", got, tt.wantTargetPort)
			}
		})
	}
}

// TestBuildLinkConfigMapRoundTrip guards that the ConfigMap the operator writes is one the
// link daemon accepts, by loading the emitted JSON through the real parse-and-validate path.
func TestBuildLinkConfigMapRoundTrip(t *testing.T) {
	gw := newGateway("edge", "wg-system",
		[]wgnetv1alpha1.Forward{
			{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web", TargetPort: 8443},
			{Port: 1194, Protocol: wgnetv1alpha1.ProtocolUDP, Service: "vpn"},
		}, nil)

	cm, err := buildLinkConfigMap(gw, "", clusterBackends(gw.Spec.Forwards), nil, "GATEWAY_PUB_TEST", nil, clusterHealthPort)
	if err != nil {
		t.Fatalf("buildLinkConfigMap: %v", err)
	}

	path := filepath.Join(t.TempDir(), linkConfigKey)
	if err := os.WriteFile(path, []byte(cm.Data[linkConfigKey]), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	rc, err := link.LoadRuntimeConfig(path)
	if err != nil {
		t.Fatalf("link.LoadRuntimeConfig: %v", err)
	}

	wantForwards := []link.Forward{
		{Name: "tcp-443", PublicPort: 443, Protocol: "tcp", Service: "web.wg-system.svc.cluster.local", TargetPort: 8443},
		{Name: "udp-1194", PublicPort: 1194, Protocol: "udp", Service: "vpn.wg-system.svc.cluster.local", TargetPort: 1194},
	}
	if !slices.Equal(rc.Forwards, wantForwards) {
		t.Errorf("loaded forwards = %+v, want %+v", rc.Forwards, wantForwards)
	}
}

// TestEffectiveForwardNamespace pins the namespace-defaulting rule the FQDN builder and the
// cross-namespace gate both depend on.
func TestEffectiveForwardNamespace(t *testing.T) {
	gw := newGateway("edge", "wg-system", nil, nil)
	tests := []struct {
		name    string
		forward wgnetv1alpha1.Forward
		want    string
	}{
		{"unset defaults to gateway namespace", wgnetv1alpha1.Forward{Service: "web"}, "wg-system"},
		{"explicit namespace honored", wgnetv1alpha1.Forward{Service: "web", Namespace: "prod"}, "prod"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := effectiveForwardNamespace(tt.forward, gw); got != tt.want {
				t.Errorf("effectiveForwardNamespace = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestBuildLinkConfigMapServiceFQDN pins that the runtime config carries a fully-qualified
// Service name, so resolution does not depend on the pod's resolv.conf ndots.
func TestBuildLinkConfigMapServiceFQDN(t *testing.T) {
	tests := []struct {
		name        string
		forward     wgnetv1alpha1.Forward
		wantService string
	}{
		{
			name:        "same namespace defaults to gateway namespace",
			forward:     wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
			wantService: "web.wg-system.svc.cluster.local",
		},
		{
			name:        "explicit cross namespace",
			forward:     wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "db", Namespace: "prod"},
			wantService: "db.prod.svc.cluster.local",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system", []wgnetv1alpha1.Forward{tt.forward}, nil)
			cm, err := buildLinkConfigMap(gw, "", clusterBackends(gw.Spec.Forwards), nil, "GATEWAY_PUB_TEST", nil, clusterHealthPort)
			if err != nil {
				t.Fatalf("buildLinkConfigMap: %v", err)
			}
			var rc link.RuntimeConfig
			decodeJSON(t, cm.Data[linkConfigKey], &rc)
			if len(rc.Forwards) != 1 {
				t.Fatalf("forwards = %d, want 1", len(rc.Forwards))
			}
			if got := rc.Forwards[0].Service; got != tt.wantService {
				t.Errorf("forward service = %q, want %q", got, tt.wantService)
			}
		})
	}
}

// hasOpenEgressPort matches the 0.0.0.0/0 peer the link's forward and WireGuard rules use,
// so the policy holds whether the CNI matches on ClusterIP or on pod IP.
func hasOpenEgressPort(rules []networkingv1.NetworkPolicyEgressRule, proto corev1.Protocol, port int32) bool {
	for _, r := range rules {
		open := false
		for _, peer := range r.To {
			if peer.IPBlock != nil && peer.IPBlock.CIDR == "0.0.0.0/0" {
				open = true
				break
			}
		}
		if !open {
			continue
		}
		for _, p := range r.Ports {
			if p.Protocol != nil && *p.Protocol == proto && p.Port != nil && p.Port.IntVal == port {
				return true
			}
		}
	}
	return false
}

// hasProtocolOnlyEgress reports whether any egress rule permits the whole of proto to a
// 0.0.0.0/0 peer, the port-less shape an unresolved (named) backend port renders.
func hasProtocolOnlyEgress(rules []networkingv1.NetworkPolicyEgressRule, proto corev1.Protocol) bool {
	for _, r := range rules {
		open := false
		for _, peer := range r.To {
			if peer.IPBlock != nil && peer.IPBlock.CIDR == "0.0.0.0/0" {
				open = true
				break
			}
		}
		if !open {
			continue
		}
		for _, p := range r.Ports {
			if p.Protocol != nil && *p.Protocol == proto && p.Port == nil {
				return true
			}
		}
	}
	return false
}

// hasNoPeerEgressPort matches a rule with no `to` peer, as the apiserver rule is, since
// in-cluster apiserver addressing varies by environment.
func hasNoPeerEgressPort(rules []networkingv1.NetworkPolicyEgressRule, proto corev1.Protocol, port int32) bool {
	for _, r := range rules {
		if len(r.To) != 0 {
			continue
		}
		for _, p := range r.Ports {
			if p.Protocol != nil && *p.Protocol == proto && p.Port != nil && p.Port.IntVal == port {
				return true
			}
		}
	}
	return false
}

func hasDNSEgress(rules []networkingv1.NetworkPolicyEgressRule, proto corev1.Protocol) bool {
	for _, r := range rules {
		dns := false
		for _, peer := range r.To {
			if peer.NamespaceSelector == nil || peer.PodSelector == nil {
				continue
			}
			if peer.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] == "kube-system" &&
				peer.PodSelector.MatchLabels["k8s-app"] == "kube-dns" {
				dns = true
				break
			}
		}
		if !dns {
			continue
		}
		for _, p := range r.Ports {
			if p.Protocol != nil && *p.Protocol == proto && p.Port != nil && p.Port.IntVal == 53 {
				return true
			}
		}
	}
	return false
}

// fixedEgressRules is the count of egress rules buildLinkNetworkPolicy emits before the
// per-forward ones: kube-dns, the WireGuard underlay, and the apiserver.
const fixedEgressRules = 3

// TestBuildLinkNetworkPolicy pins each forward's rule to the Service port plus the pod-side
// port it DNATs to, since CNIs evaluate egress before or after kube-proxy rewrites it.
func TestBuildLinkNetworkPolicy(t *testing.T) {
	// port 0 means the entry must carry no port at all, allowing the whole protocol.
	type wantPort struct {
		proto corev1.Protocol
		port  int32
	}

	tests := []struct {
		name     string
		backends []forwardBackend
		// wantRules are the per-forward egress rules, in order, each holding the
		// exact port entries that rule must carry.
		wantRules [][]wantPort
	}{
		{
			name: "tcp and udp forwards whose service port is the pod port",
			backends: []forwardBackend{
				{Forward: wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web", TargetPort: 8443}, BackendPort: 8443},
				{Forward: wgnetv1alpha1.Forward{Port: 1194, Protocol: wgnetv1alpha1.ProtocolUDP, Service: "vpn"}, BackendPort: 1194},
			},
			wantRules: [][]wantPort{
				{{corev1.ProtocolTCP, 8443}},
				{{corev1.ProtocolUDP, 1194}},
			},
		},
		{
			name: "service target ports differing from the service port are allowed too",
			backends: []forwardBackend{
				{Forward: wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}, BackendPort: 10443},
				{Forward: wgnetv1alpha1.Forward{Port: 80, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}, BackendPort: 10080},
			},
			wantRules: [][]wantPort{
				{{corev1.ProtocolTCP, 443}, {corev1.ProtocolTCP, 10443}},
				{{corev1.ProtocolTCP, 80}, {corev1.ProtocolTCP, 10080}},
			},
		},
		{
			// A named Service targetPort resolves to 0: the pod port is unknown, so the rule
			// drops its ports rather than name one the pod never listens on; nftables remains.
			name: "unresolved backend port allows the whole protocol",
			backends: []forwardBackend{
				{Forward: wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}},
			},
			wantRules: [][]wantPort{{{corev1.ProtocolTCP, 0}}},
		},
		{
			name:     "no forwards still permits control-plane egress",
			backends: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system", forwardSpecs(tt.backends), nil)

			np := buildLinkNetworkPolicy(gw, tt.backends)

			if np.Name != "edge-link" {
				t.Errorf("networkpolicy name = %q, want edge-link", np.Name)
			}
			if !slices.Equal(np.Spec.PolicyTypes, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}) {
				t.Errorf("policyTypes = %v, want [Egress]", np.Spec.PolicyTypes)
			}

			egress := np.Spec.Egress
			if !hasDNSEgress(egress, corev1.ProtocolUDP) || !hasDNSEgress(egress, corev1.ProtocolTCP) {
				t.Errorf("egress missing kube-dns UDP/TCP 53 rules: %+v", egress)
			}
			wgPort := effectiveWireguardPort(gw)
			if !hasOpenEgressPort(egress, corev1.ProtocolUDP, wgPort) {
				t.Errorf("egress missing WireGuard UDP %d rule: %+v", wgPort, egress)
			}
			if !hasNoPeerEgressPort(egress, corev1.ProtocolTCP, 443) {
				t.Errorf("egress missing apiserver TCP 443 rule (Lease leader election): %+v", egress)
			}
			if !hasNoPeerEgressPort(egress, corev1.ProtocolTCP, 6443) {
				t.Errorf("egress missing apiserver TCP 6443 rule (Lease leader election): %+v", egress)
			}

			if len(egress) != fixedEgressRules+len(tt.wantRules) {
				t.Fatalf("egress rules = %d, want %d: %+v", len(egress), fixedEgressRules+len(tt.wantRules), egress)
			}
			for i, want := range tt.wantRules {
				rule := egress[fixedEgressRules+i]
				if len(rule.To) != 1 || rule.To[0].IPBlock == nil || rule.To[0].IPBlock.CIDR != "0.0.0.0/0" {
					t.Errorf("forward rule %d peer = %+v, want a single 0.0.0.0/0 IPBlock", i, rule.To)
				}
				if len(rule.Ports) != len(want) {
					t.Errorf("forward rule %d ports = %+v, want %d entries", i, rule.Ports, len(want))
					continue
				}
				for j, w := range want {
					got := rule.Ports[j]
					if got.Protocol == nil || *got.Protocol != w.proto {
						t.Errorf("forward rule %d port %d protocol = %v, want %s", i, j, got.Protocol, w.proto)
					}
					switch {
					case w.port == 0 && got.Port != nil:
						t.Errorf("forward rule %d port %d = %v, want no port", i, j, got.Port)
					case w.port != 0 && (got.Port == nil || got.Port.IntVal != w.port):
						t.Errorf("forward rule %d port %d = %v, want %d", i, j, got.Port, w.port)
					}
				}
			}
		})
	}
}

func TestBuildLinkDeployment(t *testing.T) {
	cfg := testConfig()
	gw := newGateway("edge", "wg-system", nil, nil)
	gw.Spec.Wireguard.ReconcileInterval = "10s"

	dep := buildLinkDeployment(gw, cfg)

	if dep.Name != "edge-link" {
		t.Errorf("deployment name = %q, want edge-link", dep.Name)
	}
	if got := *dep.Spec.Replicas; got != 1 {
		t.Errorf("replicas = %d, want 1 (default)", got)
	}

	// The link is leader-elected, so it rolls (maxSurge=1, maxUnavailable=0) rather
	// than using Recreate: the lease, not the rollout, keeps a single pod active.
	if dep.Spec.Strategy.Type != appsv1.RollingUpdateDeploymentStrategyType {
		t.Errorf("strategy = %q, want RollingUpdate", dep.Spec.Strategy.Type)
	}
	if ru := dep.Spec.Strategy.RollingUpdate; ru == nil {
		t.Error("strategy.rollingUpdate = nil, want maxSurge=1/maxUnavailable=0")
	} else {
		if ru.MaxSurge == nil || ru.MaxSurge.IntVal != 1 {
			t.Errorf("strategy.rollingUpdate.maxSurge = %+v, want 1", ru.MaxSurge)
		}
		if ru.MaxUnavailable == nil || ru.MaxUnavailable.IntVal != 0 {
			t.Errorf("strategy.rollingUpdate.maxUnavailable = %+v, want 0", ru.MaxUnavailable)
		}
	}

	podSpec := dep.Spec.Template.Spec

	// IP forwarding is enabled by a privileged init container writing the shared pod
	// netns, not a kubelet-allowlisted pod sysctl.
	if len(podSpec.InitContainers) != 1 {
		t.Fatalf("init containers = %d, want 1", len(podSpec.InitContainers))
	}
	ic := podSpec.InitContainers[0]
	if ic.Image != cfg.LinkImage {
		t.Errorf("init container image = %q, want %q", ic.Image, cfg.LinkImage)
	}
	if !strings.Contains(strings.Join(ic.Command, " "), "echo 1 > /proc/sys/net/ipv4/ip_forward") {
		t.Errorf("init container command = %v, want it to enable forwarding via echo 1 > /proc/sys/net/ipv4/ip_forward", ic.Command)
	}
	if ic.SecurityContext == nil || ic.SecurityContext.Privileged == nil || !*ic.SecurityContext.Privileged {
		t.Errorf("init container privileged = %+v, want true", ic.SecurityContext)
	}
	if ic.SecurityContext == nil || ic.SecurityContext.RunAsUser == nil || *ic.SecurityContext.RunAsUser != 0 {
		t.Errorf("init container runAsUser = %+v, want 0", ic.SecurityContext)
	}

	if podSpec.SecurityContext != nil && len(podSpec.SecurityContext.Sysctls) != 0 {
		t.Errorf("pod sysctls = %+v, want none", podSpec.SecurityContext.Sysctls)
	}

	for _, ctr := range podSpec.Containers {
		if ctr.SecurityContext != nil && ctr.SecurityContext.Privileged != nil && *ctr.SecurityContext.Privileged {
			t.Errorf("main container %q is privileged, want not privileged", ctr.Name)
		}
	}

	containers := podSpec.Containers
	if len(containers) != 1 {
		t.Fatalf("containers = %d, want 1", len(containers))
	}
	c := containers[0]
	if c.Image != cfg.LinkImage {
		t.Errorf("image = %q, want %q", c.Image, cfg.LinkImage)
	}
	if len(c.Command) != 1 || c.Command[0] != "gateway-link" {
		t.Errorf("command = %v, want [gateway-link]", c.Command)
	}
	if c.SecurityContext == nil || c.SecurityContext.RunAsUser == nil || *c.SecurityContext.RunAsUser != 0 {
		t.Errorf("securityContext.runAsUser = %+v, want 0", c.SecurityContext)
	}
	if c.SecurityContext == nil || c.SecurityContext.AllowPrivilegeEscalation == nil || *c.SecurityContext.AllowPrivilegeEscalation {
		t.Errorf("securityContext.allowPrivilegeEscalation = %+v, want false", c.SecurityContext)
	}
	if c.SecurityContext == nil || len(c.SecurityContext.Capabilities.Add) != 1 || c.SecurityContext.Capabilities.Add[0] != "NET_ADMIN" {
		t.Errorf("capabilities = %+v, want add NET_ADMIN", c.SecurityContext)
	}

	env := map[string]string{}
	for _, e := range c.Env {
		env[e.Name] = e.Value
	}
	wantEnv := map[string]string{
		"GATEWAY_RECONCILE_INTERVAL":  "10s",
		"GATEWAY_CONFIG_PATH":         "/etc/gateway/config/config.json",
		"GATEWAY_WG_KEY_PATH":         "/etc/gateway/wg/" + wg.LinkPrivateKey,
		"GATEWAY_WG_PEER_PUBKEY_PATH": "/etc/gateway/wg/" + wg.LinkPeerPublicKey,
	}
	for k, want := range wantEnv {
		if env[k] != want {
			t.Errorf("env[%q] = %q, want %q", k, env[k], want)
		}
	}

	// The config ConfigMap must mount as a live directory, never a subPath: a subPath mount
	// is copied once at start and never refreshed, defeating the link's in-place reload.
	mounts := map[string]corev1.VolumeMount{}
	for _, m := range c.VolumeMounts {
		mounts[m.Name] = m
	}
	configMount, ok := mounts["config"]
	if !ok {
		t.Fatal("config volume mount missing")
	}
	if configMount.MountPath != "/etc/gateway/config" {
		t.Errorf("config mount path = %q, want /etc/gateway/config", configMount.MountPath)
	}
	if configMount.SubPath != "" {
		t.Errorf("config mount has subPath %q, want none (subPath defeats in-place reload)", configMount.SubPath)
	}
	if env["GATEWAY_CONFIG_PATH"] != "/etc/gateway/config/config.json" {
		t.Errorf("GATEWAY_CONFIG_PATH = %q, want /etc/gateway/config/config.json", env["GATEWAY_CONFIG_PATH"])
	}

	// The link does not read the XGatewayGCP, so it carries no cluster-lookup env.
	for _, gone := range []string{"GATEWAY_NAME", "GATEWAY_NAMESPACE", "GATEWAY_WG_LISTEN_PORT"} {
		if _, present := env[gone]; present {
			t.Errorf("env[%q] present, want removed", gone)
		}
	}

	// Leader election needs the projected ServiceAccount token, so the pod runs
	// under the link SA and automounts its token.
	if podSpec.ServiceAccountName != linkComponentName(gw) {
		t.Errorf("serviceAccountName = %q, want %q", podSpec.ServiceAccountName, linkComponentName(gw))
	}
	if podSpec.AutomountServiceAccountToken == nil || !*podSpec.AutomountServiceAccountToken {
		t.Errorf("automountServiceAccountToken = %v, want true (leader election needs the token)", podSpec.AutomountServiceAccountToken)
	}

	if podSpec.TerminationGracePeriodSeconds == nil || *podSpec.TerminationGracePeriodSeconds != 30 {
		t.Errorf("terminationGracePeriodSeconds = %v, want 30", podSpec.TerminationGracePeriodSeconds)
	}

	// GATEWAY_LEASE_NAME is the literal lease name; POD_NAMESPACE and POD_NAME come
	// from the downward API so each pod elects under its own identity.
	if env["GATEWAY_LEASE_NAME"] != linkComponentName(gw) {
		t.Errorf("env[GATEWAY_LEASE_NAME] = %q, want %q", env["GATEWAY_LEASE_NAME"], linkComponentName(gw))
	}
	assertFieldRefEnv(t, c.Env, "POD_NAMESPACE", "metadata.namespace")
	assertFieldRefEnv(t, c.Env, "POD_NAME", "metadata.name")

	assertHostnameAntiAffinity(t, podSpec.Affinity, linkSelectorLabels(gw))

	// The link container carries no CYNO_*-prefixed env.
	for _, e := range c.Env {
		if strings.HasPrefix(e.Name, "CYNO_") {
			t.Errorf("unexpected legacy env %q on link container", e.Name)
		}
	}

	// In-place reload means no config-checksum roll trigger.
	if _, ok := dep.Spec.Template.Annotations["checksum/config"]; ok {
		t.Error("pod template carries checksum/config; in-place reload needs no roll trigger")
	}
}

func assertFieldRefEnv(t *testing.T, env []corev1.EnvVar, name, fieldPath string) {
	t.Helper()
	for _, e := range env {
		if e.Name != name {
			continue
		}
		if e.Value != "" {
			t.Errorf("env[%q] has literal value %q, want valueFrom fieldRef %q", name, e.Value, fieldPath)
		}
		if e.ValueFrom == nil || e.ValueFrom.FieldRef == nil {
			t.Fatalf("env[%q] = %+v, want valueFrom fieldRef %q", name, e, fieldPath)
		}
		if got := e.ValueFrom.FieldRef.FieldPath; got != fieldPath {
			t.Errorf("env[%q] fieldRef = %q, want %q", name, got, fieldPath)
		}
		return
	}
	t.Errorf("env missing %q (valueFrom fieldRef %q)", name, fieldPath)
}

// assertHostnameAntiAffinity checks the soft anti-affinity term keyed on node hostname,
// which is what spreads the link replicas across nodes.
func assertHostnameAntiAffinity(t *testing.T, affinity *corev1.Affinity, wantSelector map[string]string) {
	t.Helper()
	if affinity == nil || affinity.PodAntiAffinity == nil {
		t.Fatalf("affinity = %+v, want podAntiAffinity", affinity)
	}
	terms := affinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution
	if len(terms) != 1 {
		t.Fatalf("preferred anti-affinity terms = %d, want 1", len(terms))
	}
	term := terms[0]
	if term.Weight != 100 {
		t.Errorf("anti-affinity weight = %d, want 100", term.Weight)
	}
	if term.PodAffinityTerm.TopologyKey != "kubernetes.io/hostname" {
		t.Errorf("anti-affinity topologyKey = %q, want kubernetes.io/hostname", term.PodAffinityTerm.TopologyKey)
	}
	sel := term.PodAffinityTerm.LabelSelector
	if sel == nil {
		t.Fatal("anti-affinity labelSelector = nil, want link selector")
	}
	if !maps.Equal(sel.MatchLabels, wantSelector) {
		t.Errorf("anti-affinity labelSelector = %v, want %v", sel.MatchLabels, wantSelector)
	}
}

// TestBuildLinkDeploymentReplicas pins that replicas default to 1 and honor an explicit
// value, which is what enables a hot-standby Gateway.
func TestBuildLinkDeploymentReplicas(t *testing.T) {
	cfg := testConfig()
	tests := []struct {
		name     string
		replicas int32
		want     int32
	}{
		{"unset defaults to 1", 0, 1},
		{"explicit 3 honored", 3, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system", nil, nil)
			gw.Spec.Link.Replicas = tt.replicas

			dep := buildLinkDeployment(gw, cfg)
			if dep.Spec.Replicas == nil || *dep.Spec.Replicas != tt.want {
				t.Errorf("replicas = %v, want %d", dep.Spec.Replicas, tt.want)
			}
		})
	}
}

// TestEffectiveLinkReplicas pins the replica-defaulting accessor: an unset value
// resolves to the CRD default of 1 and an explicit value passes through.
func TestEffectiveLinkReplicas(t *testing.T) {
	tests := []struct {
		name     string
		replicas int32
		want     int32
	}{
		{"zero defaults to 1", 0, 1},
		{"explicit 1", 1, 1},
		{"explicit 3", 3, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system", nil, nil)
			gw.Spec.Link.Replicas = tt.replicas
			if got := effectiveLinkReplicas(gw); got != tt.want {
				t.Errorf("effectiveLinkReplicas = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestBuildLinkServiceAccount pins the link ServiceAccount's name, namespace, and
// labels; its token is the credential the link presents for leader election.
func TestBuildLinkServiceAccount(t *testing.T) {
	gw := newGateway("edge", "wg-system", nil, nil)
	sa := buildLinkServiceAccount(gw)

	if sa.Name != "edge-link" {
		t.Errorf("serviceaccount name = %q, want edge-link", sa.Name)
	}
	if sa.Namespace != "wg-system" {
		t.Errorf("serviceaccount namespace = %q, want wg-system", sa.Namespace)
	}
	if got := sa.Labels["app.kubernetes.io/component"]; got != componentLink {
		t.Errorf("serviceaccount component label = %q, want %q", got, componentLink)
	}
}

// TestBuildLinkRole pins the Cluster-mode Role to exactly the verbs leader election needs
// on leases and nothing else, because a Cluster link never watches pods.
func TestBuildLinkRole(t *testing.T) {
	gw := newGateway("edge", "wg-system", nil, nil)
	role := buildLinkRole(gw)

	if role.Name != "edge-link" {
		t.Errorf("role name = %q, want edge-link", role.Name)
	}
	if role.Namespace != "wg-system" {
		t.Errorf("role namespace = %q, want wg-system", role.Namespace)
	}
	if len(role.Rules) != 1 {
		t.Fatalf("role rules = %d, want 1", len(role.Rules))
	}
	rule := role.Rules[0]
	if !slices.Equal(rule.APIGroups, []string{"coordination.k8s.io"}) {
		t.Errorf("rule apiGroups = %v, want [coordination.k8s.io]", rule.APIGroups)
	}
	if !slices.Equal(rule.Resources, []string{"leases"}) {
		t.Errorf("rule resources = %v, want [leases]", rule.Resources)
	}
	wantVerbs := []string{"get", "list", "watch", "create", "update"}
	if !slices.Equal(rule.Verbs, wantVerbs) {
		t.Errorf("rule verbs = %v, want %v", rule.Verbs, wantVerbs)
	}
}

// TestBuildLinkRoleBinding pins the binding of the link Role to the link ServiceAccount,
// the grant that lets the link pods elect.
func TestBuildLinkRoleBinding(t *testing.T) {
	gw := newGateway("edge", "wg-system", nil, nil)
	rb := buildLinkRoleBinding(gw)

	if rb.Name != "edge-link" {
		t.Errorf("rolebinding name = %q, want edge-link", rb.Name)
	}
	if rb.Namespace != "wg-system" {
		t.Errorf("rolebinding namespace = %q, want wg-system", rb.Namespace)
	}
	if rb.RoleRef.APIGroup != rbacv1.GroupName || rb.RoleRef.Kind != "Role" || rb.RoleRef.Name != "edge-link" {
		t.Errorf("roleRef = %+v, want rbac.authorization.k8s.io/Role/edge-link", rb.RoleRef)
	}
	if len(rb.Subjects) != 1 {
		t.Fatalf("rolebinding subjects = %d, want 1", len(rb.Subjects))
	}
	sub := rb.Subjects[0]
	if sub.Kind != rbacv1.ServiceAccountKind || sub.Name != "edge-link" || sub.Namespace != "wg-system" {
		t.Errorf("subject = %+v, want ServiceAccount edge-link in wg-system", sub)
	}
}

// TestBuildLinkPodDisruptionBudget pins minAvailable 1 so a drain cannot take the active and
// the standby at once, and AlwaysAllow so an unhealthy pod is still evictable at the limit.
func TestBuildLinkPodDisruptionBudget(t *testing.T) {
	gw := newGateway("edge", "wg-system", nil, nil)
	pdb := buildLinkPodDisruptionBudget(gw)

	if pdb.Name != "edge-link" {
		t.Errorf("pdb name = %q, want edge-link", pdb.Name)
	}
	if pdb.Namespace != "wg-system" {
		t.Errorf("pdb namespace = %q, want wg-system", pdb.Namespace)
	}
	if pdb.Spec.MinAvailable == nil || pdb.Spec.MinAvailable.IntVal != 1 {
		t.Errorf("pdb minAvailable = %+v, want 1", pdb.Spec.MinAvailable)
	}
	if pdb.Spec.Selector == nil || !maps.Equal(pdb.Spec.Selector.MatchLabels, linkSelectorLabels(gw)) {
		t.Errorf("pdb selector = %+v, want link selector %v", pdb.Spec.Selector, linkSelectorLabels(gw))
	}
	if pdb.Spec.UnhealthyPodEvictionPolicy == nil || *pdb.Spec.UnhealthyPodEvictionPolicy != policyv1.AlwaysAllow {
		t.Errorf("pdb unhealthyPodEvictionPolicy = %v, want AlwaysAllow", pdb.Spec.UnhealthyPodEvictionPolicy)
	}
}

// TestBuildXGatewayGCPProviderSelector pins the compositionSelector provider label, so a
// second provider's Composition cannot collide with the gcp one.
func TestBuildXGatewayGCPProviderSelector(t *testing.T) {
	cfg := testConfig()
	tests := []struct {
		name     string
		provider wgnetv1alpha1.CloudProvider
		want     string
	}{
		{"defaults to gcp when empty", "", "gcp"},
		{"honors explicit provider", wgnetv1alpha1.ProviderGCP, "gcp"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system", nil, nil)
			gw.Spec.Provider = tt.provider

			u, err := buildXGatewayGCP(gw, cfg, gw.Spec.Forwards, false, nil, clusterHealthPort)
			if err != nil {
				t.Fatalf("buildXGatewayGCP: %v", err)
			}
			assertNestedString(t, u, tt.want, "spec", "crossplane", "compositionSelector", "matchLabels", "provider")
		})
	}
}

// TestBuildXGatewayNetwork pins the singleton shared-VPC composite, which carries no
// ownerReference so deleting a Gateway never GCs the shared network.
func TestBuildXGatewayNetwork(t *testing.T) {
	cfg := testConfig()

	u := buildXGatewayNetwork(cfg)

	if got := u.GetAPIVersion(); got != xgatewayGCPAPIVersion {
		t.Errorf("apiVersion = %q, want %q", got, xgatewayGCPAPIVersion)
	}
	if got := u.GetKind(); got != xgatewayNetworkKind {
		t.Errorf("kind = %q, want %q", got, xgatewayNetworkKind)
	}
	if got := u.GetName(); got != cfg.SharedNetworkName {
		t.Errorf("name = %q, want %q", got, cfg.SharedNetworkName)
	}
	if got := u.GetNamespace(); got != cfg.PodNamespace {
		t.Errorf("namespace = %q, want %q", got, cfg.PodNamespace)
	}

	assertNestedString(t, u, cfg.SharedNetworkName, "spec", "name")
	assertNestedString(t, u, cfg.ProviderConfigName, "spec", "providerConfigName")
	assertNestedString(t, u, "gcp", "spec", "crossplane", "compositionSelector", "matchLabels", "provider")

	if refs := u.GetOwnerReferences(); len(refs) != 0 {
		t.Errorf("ownerReferences = %d, want 0 (shared network is refcount-managed, not Gateway-owned)", len(refs))
	}
}

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

// TestGCPIDBase32Length documents the bound truncation relies on: sha256 base32-encodes to
// 52 chars, so prefix+hash always exceeds the 30-char cap.
func TestGCPIDBase32Length(t *testing.T) {
	full := base32.StdEncoding.WithPadding(base32.NoPadding).EncodedLen(32)
	if full+len(gcpIDPrefix) <= gcpIDMaxLen {
		t.Fatalf("base32 length %d + prefix does not exceed cap %d; truncation untested", full, gcpIDMaxLen)
	}
}

// TestEffectiveTrafficPolicy pins that an empty value reads as Cluster, so a Gateway that
// bypassed CRD defaulting still builds a Cluster data path.
func TestEffectiveTrafficPolicy(t *testing.T) {
	tests := []struct {
		name   string
		policy wgnetv1alpha1.TrafficPolicy
		want   wgnetv1alpha1.TrafficPolicy
	}{
		{"unset defaults to Cluster", "", wgnetv1alpha1.TrafficPolicyCluster},
		{"explicit Cluster", wgnetv1alpha1.TrafficPolicyCluster, wgnetv1alpha1.TrafficPolicyCluster},
		{"explicit Local", wgnetv1alpha1.TrafficPolicyLocal, wgnetv1alpha1.TrafficPolicyLocal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system", nil, nil)
			gw.Spec.TrafficPolicy = tt.policy
			if got := effectiveTrafficPolicy(gw); got != tt.want {
				t.Errorf("effectiveTrafficPolicy = %q, want %q", got, tt.want)
			}
			if got, want := isLocal(gw), tt.want == wgnetv1alpha1.TrafficPolicyLocal; got != want {
				t.Errorf("isLocal = %v, want %v", got, want)
			}
		})
	}
}

// TestLinkIdentityOf pins that an identity exists only once a Local Gateway's id is
// allocated, so no Local workload is built before that id is persisted.
func TestLinkIdentityOf(t *testing.T) {
	ident3 := link.NewGatewayIdentity(3)
	tests := []struct {
		name   string
		policy wgnetv1alpha1.TrafficPolicy
		id     int32
		want   *link.GatewayIdentity
	}{
		{"cluster has no identity", wgnetv1alpha1.TrafficPolicyCluster, 0, nil},
		{"cluster ignores a stale id", wgnetv1alpha1.TrafficPolicyCluster, 3, nil},
		{"local without an id yet", wgnetv1alpha1.TrafficPolicyLocal, 0, nil},
		{"local with an allocated id", wgnetv1alpha1.TrafficPolicyLocal, 3, &ident3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system", nil, nil)
			gw.Spec.TrafficPolicy = tt.policy
			gw.Status.Link.ID = tt.id

			got := linkIdentityOf(gw)
			switch {
			case tt.want == nil && got != nil:
				t.Fatalf("linkIdentityOf = %+v, want nil", got)
			case tt.want != nil && got == nil:
				t.Fatalf("linkIdentityOf = nil, want %+v", *tt.want)
			case tt.want != nil && *got != *tt.want:
				t.Errorf("linkIdentityOf = %+v, want %+v", *got, *tt.want)
			}
		})
	}
}

// TestBuildXGatewayGCPTrafficPolicy pins that the composite carries the mode lowercased,
// which is the form the composition renders into the VM's traffic-policy metadata key.
func TestBuildXGatewayGCPTrafficPolicy(t *testing.T) {
	tests := []struct {
		name   string
		policy wgnetv1alpha1.TrafficPolicy
		want   string
	}{
		{"unset renders cluster", "", "cluster"},
		{"Cluster renders cluster", wgnetv1alpha1.TrafficPolicyCluster, "cluster"},
		{"Local renders local", wgnetv1alpha1.TrafficPolicyLocal, "local"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system", nil, nil)
			gw.Spec.TrafficPolicy = tt.policy

			u, err := buildXGatewayGCP(gw, testConfig(), nil, false, nil, clusterHealthPort)
			if err != nil {
				t.Fatalf("buildXGatewayGCP: %v", err)
			}
			assertNestedString(t, u, tt.want, "spec", "trafficPolicy")
		})
	}
}

// TestBuildLinkConfigMapLocal pins the Local-mode RuntimeConfig: the derived identity, the
// widened allowed IPs and EndpointSlice-resolvable forwards instead of Service FQDNs.
func TestBuildLinkConfigMapLocal(t *testing.T) {
	gw := newGateway("edge", "wg-system",
		[]wgnetv1alpha1.Forward{
			{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
			{Port: 5432, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "db", Namespace: "prod"},
		}, nil)
	gw.Spec.TrafficPolicy = wgnetv1alpha1.TrafficPolicyLocal
	gw.Status.Link.ID = 3

	backends := []forwardBackend{
		{Forward: gw.Spec.Forwards[0], BackendPort: 8443},
		{Forward: gw.Spec.Forwards[1], BackendPort: 5432, ServicePortName: "postgres"},
	}

	cm, err := buildLinkConfigMap(gw, "203.0.113.5", backends, linkIdentityOf(gw), "GATEWAY_PUB_TEST", nil, effectiveHealthPort(gw))
	if err != nil {
		t.Fatalf("buildLinkConfigMap: %v", err)
	}

	path := filepath.Join(t.TempDir(), linkConfigKey)
	if err := os.WriteFile(path, []byte(cm.Data[linkConfigKey]), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	rc, err := link.LoadRuntimeConfig(path)
	if err != nil {
		t.Fatalf("link.LoadRuntimeConfig: %v", err)
	}

	if rc.TrafficPolicy != link.TrafficPolicyLocal {
		t.Errorf("trafficPolicy = %q, want %q", rc.TrafficPolicy, link.TrafficPolicyLocal)
	}
	if rc.Identity == nil {
		t.Fatal("identity = nil, want the identity derived from id 3")
	}
	if want := link.NewGatewayIdentity(3); *rc.Identity != want {
		t.Errorf("identity = %+v, want %+v", *rc.Identity, want)
	}
	if !slices.Equal(rc.WireGuard.Peers[0].AllowedIPs, []string{"0.0.0.0/0"}) {
		t.Errorf("peer.allowedIPs = %v, want [0.0.0.0/0]", rc.WireGuard.Peers[0].AllowedIPs)
	}
	if !maps.Equal(rc.PodSelector, linkSelectorLabels(gw)) {
		t.Errorf("podSelector = %v, want %v", rc.PodSelector, linkSelectorLabels(gw))
	}

	wantForwards := []link.Forward{
		{Name: "tcp-443", PublicPort: 443, Protocol: "tcp", Namespace: "wg-system", ServiceName: "web"},
		{Name: "tcp-5432", PublicPort: 5432, Protocol: "tcp", Namespace: "prod", ServiceName: "db", ServicePortName: "postgres"},
	}
	if !slices.Equal(rc.Forwards, wantForwards) {
		t.Errorf("forwards = %+v, want %+v", rc.Forwards, wantForwards)
	}
}

// TestBuildLinkConfigMapPodSelector pins that the pod selector is Local-only: the
// Cluster-mode link runs no pod watch, so the rendered config omits the key.
func TestBuildLinkConfigMapPodSelector(t *testing.T) {
	tests := []struct {
		name   string
		local  bool
		want   map[string]string
		wantID bool
	}{
		{name: "renders no pod selector or identity for cluster traffic"},
		{name: "renders the pod selector and identity for local traffic", local: true, wantID: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system",
				[]wgnetv1alpha1.Forward{{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}}, nil)
			endpoint := ""
			if tt.local {
				gw.Spec.TrafficPolicy = wgnetv1alpha1.TrafficPolicyLocal
				gw.Status.Link.ID = 3
				endpoint = "203.0.113.5"
			}

			cm, err := buildLinkConfigMap(gw, endpoint, clusterBackends(gw.Spec.Forwards), linkIdentityOf(gw), "GATEWAY_PUB_TEST", nil, effectiveHealthPort(gw))
			if err != nil {
				t.Fatalf("buildLinkConfigMap: %v", err)
			}

			var rc link.RuntimeConfig
			decodeJSON(t, cm.Data[linkConfigKey], &rc)
			want := map[string]string(nil)
			if tt.local {
				want = linkSelectorLabels(gw)
			}
			if !maps.Equal(rc.PodSelector, want) {
				t.Errorf("podSelector = %v, want %v", rc.PodSelector, want)
			}
			if (rc.Identity != nil) != tt.wantID {
				t.Errorf("identity = %+v, want non-nil %t", rc.Identity, tt.wantID)
			}

			var raw map[string]any
			decodeJSON(t, cm.Data[linkConfigKey], &raw)
			if _, ok := raw["podSelector"]; ok != tt.local {
				t.Errorf("rendered podSelector key present = %t, want %t", ok, tt.local)
			}
		})
	}
}

// TestBuildLinkDaemonSet pins the Local-mode host-network shape: no init container or
// anti-affinity, a loopback probe on the id-derived port, a writable host /proc/sys/net.
func TestBuildLinkDaemonSet(t *testing.T) {
	gw := newGateway("edge", "wg-system", nil, nil)
	gw.Spec.TrafficPolicy = wgnetv1alpha1.TrafficPolicyLocal
	gw.Status.Link.ID = 3

	ds := buildLinkDaemonSet(gw, testConfig(), linkIdentityOf(gw))
	if ds.Name != "edge-link" || ds.Namespace != "wg-system" {
		t.Errorf("daemonset = %s/%s, want wg-system/edge-link", ds.Namespace, ds.Name)
	}

	podSpec := ds.Spec.Template.Spec
	c := podSpec.Containers[0]
	env := map[string]string{}
	for _, e := range c.Env {
		env[e.Name] = e.Value
	}
	mounts := map[string]corev1.VolumeMount{}
	for _, m := range c.VolumeMounts {
		mounts[m.Name] = m
	}
	volumes := map[string]corev1.Volume{}
	for _, v := range podSpec.Volumes {
		volumes[v.Name] = v
	}

	tests := []struct {
		name string
		got  any
		want any
	}{
		{"hostNetwork", podSpec.HostNetwork, true},
		{"dnsPolicy", podSpec.DNSPolicy, corev1.DNSClusterFirstWithHostNet},
		{"init containers", len(podSpec.InitContainers), 0},
		{"container ports", len(c.Ports), 0},
		{"probe host", c.ReadinessProbe.HTTPGet.Host, "127.0.0.1"},
		{"probe port", c.ReadinessProbe.HTTPGet.Port, intstr.FromInt32(27003)},
		{"health addr", env["GATEWAY_HEALTH_ADDR"], ":27003"},
		{"host proc mount path", mounts["host-proc-sys-net"].MountPath, link.HostProcSysNetPath},
		{"host proc mount writable", mounts["host-proc-sys-net"].ReadOnly, false},
		{"host proc hostPath", volumes["host-proc-sys-net"].HostPath.Path, "/proc/sys/net"},
		{"termination grace period", *podSpec.TerminationGracePeriodSeconds, int64(30)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.want)
			}
		})
	}

	if podSpec.Affinity != nil {
		t.Errorf("affinity = %+v, want nil (a DaemonSet is already one pod per node)", podSpec.Affinity)
	}
	if hp := volumes["host-proc-sys-net"].HostPath; hp == nil || hp.Type == nil || *hp.Type != corev1.HostPathDirectory {
		t.Errorf("host-proc-sys-net hostPath = %+v, want type Directory", hp)
	}
	assertFieldRefEnv(t, c.Env, "NODE_NAME", "spec.nodeName")

	sc := c.SecurityContext
	if sc == nil || sc.RunAsUser == nil || *sc.RunAsUser != 0 {
		t.Errorf("securityContext.runAsUser = %+v, want 0", sc)
	}
	if sc == nil || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
		t.Errorf("securityContext.allowPrivilegeEscalation = %+v, want false", sc)
	}
	if sc == nil || !slices.Equal(sc.Capabilities.Add, []corev1.Capability{"NET_ADMIN"}) {
		t.Errorf("capabilities = %+v, want add NET_ADMIN", sc)
	}
}

// TestBuildLinkDeploymentUnchangedInClusterMode guards that sharing a pod spec with the
// DaemonSet did not leak any Local-mode shape into the Cluster workload.
func TestBuildLinkDeploymentUnchangedInClusterMode(t *testing.T) {
	gw := newGateway("edge", "wg-system", nil, nil)
	dep := buildLinkDeployment(gw, testConfig())

	podSpec := dep.Spec.Template.Spec
	c := podSpec.Containers[0]
	env := map[string]string{}
	for _, e := range c.Env {
		env[e.Name] = e.Value
	}

	if podSpec.HostNetwork {
		t.Error("hostNetwork = true, want false in Cluster mode")
	}
	if podSpec.DNSPolicy != "" {
		t.Errorf("dnsPolicy = %q, want unset in Cluster mode", podSpec.DNSPolicy)
	}
	if len(podSpec.InitContainers) != 1 {
		t.Errorf("init containers = %d, want 1", len(podSpec.InitContainers))
	}
	assertHostnameAntiAffinity(t, podSpec.Affinity, linkSelectorLabels(gw))
	if len(c.Ports) != 1 || c.Ports[0].Name != "health" || c.Ports[0].ContainerPort != 8080 {
		t.Errorf("container ports = %+v, want a single health port 8080", c.Ports)
	}
	if got := c.ReadinessProbe.HTTPGet; got.Host != "" || got.Port != intstr.FromString("health") {
		t.Errorf("readiness probe = %+v, want the named health port with no host", got)
	}
	if env["GATEWAY_HEALTH_ADDR"] != ":8080" {
		t.Errorf("GATEWAY_HEALTH_ADDR = %q, want :8080", env["GATEWAY_HEALTH_ADDR"])
	}
	if _, present := env["NODE_NAME"]; present {
		t.Error("NODE_NAME present, want it only in Local mode")
	}
	for _, v := range podSpec.Volumes {
		if v.Name == "host-proc-sys-net" {
			t.Error("host-proc-sys-net volume present, want it only in Local mode")
		}
	}
}

// TestLinkPodSpecNodeSelector pins that spec.link.nodeSelector reaches both workloads'
// pod templates, which is how an operator confines the link to a node pool.
func TestLinkPodSpecNodeSelector(t *testing.T) {
	selector := map[string]string{"wgnet.dev/pool": "edge"}

	gw := newGateway("edge", "wg-system", nil, nil)
	gw.Spec.Link.NodeSelector = selector
	dep := buildLinkDeployment(gw, testConfig())

	local := newGateway("edge", "wg-system", nil, nil)
	local.Spec.TrafficPolicy = wgnetv1alpha1.TrafficPolicyLocal
	local.Spec.Link.NodeSelector = selector
	local.Status.Link.ID = 3
	ds := buildLinkDaemonSet(local, testConfig(), linkIdentityOf(local))

	tests := []struct {
		name string
		got  map[string]string
	}{
		{"deployment", dep.Spec.Template.Spec.NodeSelector},
		{"daemonset", ds.Spec.Template.Spec.NodeSelector},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !maps.Equal(tt.got, selector) {
				t.Errorf("nodeSelector = %v, want %v", tt.got, selector)
			}
		})
	}
}

// TestBuildLinkRolePods pins the Local-mode link Role's pod rule, the liveness input of
// the election, on top of the Lease rule both modes get.
func TestBuildLinkRolePods(t *testing.T) {
	gw := newGateway("edge", "wg-system", nil, nil)
	gw.Spec.TrafficPolicy = wgnetv1alpha1.TrafficPolicyLocal
	role := buildLinkRole(gw)
	if len(role.Rules) != 2 {
		t.Fatalf("role rules = %d, want 2", len(role.Rules))
	}
	if got := role.Rules[0].Resources; !slices.Equal(got, []string{"leases"}) {
		t.Errorf("first rule resources = %v, want [leases]", got)
	}
	rule := role.Rules[1]
	if !slices.Equal(rule.APIGroups, []string{""}) {
		t.Errorf("rule apiGroups = %v, want [\"\"]", rule.APIGroups)
	}
	if !slices.Equal(rule.Resources, []string{"pods"}) {
		t.Errorf("rule resources = %v, want [pods]", rule.Resources)
	}
	if want := []string{"get", "list", "watch"}; !slices.Equal(rule.Verbs, want) {
		t.Errorf("rule verbs = %v, want %v", rule.Verbs, want)
	}
}

// TestBuildLinkClusterRoleBinding pins the EndpointSlice grant a Local link needs, with the
// owner labels the delete path has to find it by, having no ownerReference.
func TestBuildLinkClusterRoleBinding(t *testing.T) {
	gw := newGateway("edge", "wg-system", nil, nil)
	crb := buildLinkClusterRoleBinding(gw)

	if want := linkClusterRoleBindingName(gw); crb.Name != want {
		t.Errorf("clusterrolebinding name = %q, want %q", crb.Name, want)
	}
	if crb.Namespace != "" {
		t.Errorf("clusterrolebinding namespace = %q, want cluster-scoped", crb.Namespace)
	}
	if crb.RoleRef.APIGroup != rbacv1.GroupName || crb.RoleRef.Kind != "ClusterRole" || crb.RoleRef.Name != linkEndpointSliceClusterRole {
		t.Errorf("roleRef = %+v, want ClusterRole/%s", crb.RoleRef, linkEndpointSliceClusterRole)
	}
	if len(crb.Subjects) != 1 {
		t.Fatalf("subjects = %d, want 1", len(crb.Subjects))
	}
	sub := crb.Subjects[0]
	if sub.Kind != rbacv1.ServiceAccountKind || sub.Name != "edge-link" || sub.Namespace != "wg-system" {
		t.Errorf("subject = %+v, want ServiceAccount edge-link in wg-system", sub)
	}

	want := commonLabels(gw, componentLink)
	want[ownerNamespaceLabel] = "wg-system"
	want[ownerNameLabel] = "edge"
	if !maps.Equal(crb.Labels, want) {
		t.Errorf("labels = %v, want %v", crb.Labels, want)
	}
}

// TestLinkClusterRoleBindingNameDistinctAcrossNamespaces pins that the hash separates a pair
// "<namespace>-<name>" would collide, and is stable so the apply targets one object.
func TestLinkClusterRoleBindingNameDistinctAcrossNamespaces(t *testing.T) {
	a := newGateway("c", "a-b", nil, nil)
	b := newGateway("b-c", "a", nil, nil)

	nameA := linkClusterRoleBindingName(a)
	nameB := linkClusterRoleBindingName(b)

	if nameA == nameB {
		t.Errorf("clusterrolebinding names collide: both %q", nameA)
	}
	if got := linkClusterRoleBindingName(a); got != nameA {
		t.Errorf("clusterrolebinding name = %q on the second call, want the stable %q", got, nameA)
	}
	for _, name := range []string{nameA, nameB} {
		if !strings.HasPrefix(name, linkClusterRoleBindingPrefix) {
			t.Errorf("clusterrolebinding name = %q, want the %q prefix", name, linkClusterRoleBindingPrefix)
		}
	}
}

// TestLinkPodSpecHealthAddr pins GATEWAY_HEALTH_ADDR per mode, looked up by env name so
// a reordered env slice cannot silently move the override onto another variable.
func TestLinkPodSpecHealthAddr(t *testing.T) {
	tests := []struct {
		name   string
		policy wgnetv1alpha1.TrafficPolicy
		id     int32
		want   string
	}{
		{"cluster", wgnetv1alpha1.TrafficPolicyCluster, 0, ":8080"},
		{"local id 1", wgnetv1alpha1.TrafficPolicyLocal, 1, ":27001"},
		{"local id 7", wgnetv1alpha1.TrafficPolicyLocal, 7, ":27007"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system", nil, nil)
			gw.Spec.TrafficPolicy = tt.policy
			gw.Status.Link.ID = tt.id

			spec := linkPodSpec(gw, testConfig(), linkIdentityOf(gw))
			var got string
			var found bool
			for _, e := range spec.Containers[0].Env {
				if e.Name == "GATEWAY_HEALTH_ADDR" {
					got, found = e.Value, true
				}
			}
			if !found {
				t.Fatal("GATEWAY_HEALTH_ADDR absent from container env")
			}
			if got != tt.want {
				t.Errorf("GATEWAY_HEALTH_ADDR = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestMaxLinkIDMatchesCRDBound pins link.MaxLinkID to the kubebuilder Maximum marker on
// GatewayLinkStatus.ID, which the CRD bound comes from and cannot reference the constant.
func TestMaxLinkIDMatchesCRDBound(t *testing.T) {
	const crdMaximum = 250
	if link.MaxLinkID != crdMaximum {
		t.Errorf("link.MaxLinkID = %d, want %d to match the CRD Maximum marker", link.MaxLinkID, crdMaximum)
	}
}

// TestLinkShutdownBudgetFitsGracePeriod guards two independent exit deadlines: a grace
// period at or below link.ShutdownBudget kills the link mid-release, stranding the Lease.
func TestLinkShutdownBudgetFitsGracePeriod(t *testing.T) {
	cluster := newGateway("edge", "wg-system", nil, nil)

	local := newGateway("edge", "wg-system", nil, nil)
	local.Spec.TrafficPolicy = wgnetv1alpha1.TrafficPolicyLocal
	local.Status.Link.ID = 3

	tests := []struct {
		name  string
		grace *int64
	}{
		{"deployment", buildLinkDeployment(cluster, testConfig()).Spec.Template.Spec.TerminationGracePeriodSeconds},
		{"daemonset", buildLinkDaemonSet(local, testConfig(), linkIdentityOf(local)).Spec.Template.Spec.TerminationGracePeriodSeconds},
	}
	budget := int64(link.ShutdownBudget / time.Second)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.grace == nil {
				t.Fatalf("terminationGracePeriodSeconds unset, want more than the %ds shutdown budget", budget)
			}
			if *tt.grace <= budget {
				t.Errorf("terminationGracePeriodSeconds = %ds, want more than link.ShutdownBudget (%ds)", *tt.grace, budget)
			}
		})
	}
}

// TestTrafficPolicyConstantsMatch guards three independent declarations of the policy
// values: operator, link RuntimeConfig, e2e harness. Drift breaks the data path or the suite.
func TestTrafficPolicyConstantsMatch(t *testing.T) {
	tests := []struct {
		name    string
		api     wgnetv1alpha1.TrafficPolicy
		link    string
		harness string
	}{
		{"cluster", wgnetv1alpha1.TrafficPolicyCluster, link.TrafficPolicyCluster, hk8s.TrafficPolicyCluster},
		{"local", wgnetv1alpha1.TrafficPolicyLocal, link.TrafficPolicyLocal, hk8s.TrafficPolicyLocal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.api) != tt.link {
				t.Errorf("api value %q != link value %q", tt.api, tt.link)
			}
			if string(tt.api) != tt.harness {
				t.Errorf("api value %q != harness value %q", tt.api, tt.harness)
			}
		})
	}
}

// TestClusterHealthPortMatchesLinkDefault guards clusterHealthPort against the link's own
// envconfig default, which applies when GATEWAY_HEALTH_ADDR is absent; drift breaks the probe.
func TestClusterHealthPortMatchesLinkDefault(t *testing.T) {
	field, ok := reflect.TypeFor[link.Config]().FieldByName("HealthAddr")
	if !ok {
		t.Fatal("link.Config has no HealthAddr field")
	}
	def := field.Tag.Get("default")
	wantPort, err := strconv.Atoi(strings.TrimPrefix(def, ":"))
	if err != nil {
		t.Fatalf("parse link HealthAddr default %q: %v", def, err)
	}
	if clusterHealthPort != wantPort {
		t.Errorf("clusterHealthPort = %d, want %d from link.Config's HealthAddr default", clusterHealthPort, wantPort)
	}
}
