package controller

import (
	"encoding/base32"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/greg2010/wireguard-gateway-operator/internal/link"
	"github.com/greg2010/wireguard-gateway-operator/internal/wg"
	wgnetv1alpha1 "github.com/greg2010/wireguard-gateway-operator/pkg/api/v1alpha1"
)

// testConfig is the operator-level config the builder tests fold into Gateways.
func testConfig() Config {
	return Config{
		LinkImage:           "registry.example.com/gateway-link:test",
		LinkImagePullPolicy: "IfNotPresent",
		UserData:            "#ignition\n",
		RequeueInterval:     0,
		SharedNetworkName:   "wgnet-test",
		PodNamespace:        "gateway-operator",
	}
}

// newGateway builds a Gateway fixture with the given forwards and hostnames. It
// sets the required spec.gcp.ProjectID and leaves every defaulted spec.gcp and
// spec.wireguard field unset so the builders exercise their defaulting accessors.
func newGateway(name, namespace string, forwards []wgnetv1alpha1.Forward, hostnames []string) *wgnetv1alpha1.Gateway {
	return &wgnetv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
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

// assertNestedString fails unless the unstructured object's value at path equals
// want.
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

// decodeJSON unmarshals raw into v, failing the test on error.
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

func TestBuildXGatewayGCP(t *testing.T) {
	cfg := testConfig()
	gw := newGateway("edge", "wg-system",
		[]wgnetv1alpha1.Forward{
			{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP},
			{Port: 1194, Protocol: wgnetv1alpha1.ProtocolUDP},
		},
		[]string{"edge.example.com"},
	)

	u, err := buildXGatewayGCP(gw, cfg, gw.Spec.Forwards)
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

	// sharedNetworkName flows from operator config: every Gateway attaches to the
	// one shared VPC the operator provisions.
	assertNestedString(t, u, cfg.SharedNetworkName, "spec", "sharedNetworkName")

	// The GCP and WireGuard composite inputs now flow from gw.Spec (here all
	// defaulted) rather than the operator config.
	assertNestedString(t, u, "test-project", "spec", "projectID")
	assertNestedString(t, u, effectiveGCPImage(gw), "spec", "image")
	assertNestedString(t, u, effectiveWGGatewayAddress(gw), "spec", "wgGatewayAddress")
	assertNestedString(t, u, effectiveWGLinkAddress(gw), "spec", "wgLinkAddress")
	assertNestedString(t, u, effectiveWGSubnet(gw), "spec", "wgSubnet")

	wantWGPort := int64(effectiveWireguardPort(gw))
	if got, _, _ := unstructured.NestedInt64(u.Object, "spec", "wgListenPort"); got != wantWGPort {
		t.Errorf("wgListenPort = %d, want %d", got, wantWGPort)
	}
	if got, _, _ := unstructured.NestedInt64(u.Object, "spec", "diskSizeGB"); got != int64(effectiveGCPDiskSizeGB(gw)) {
		t.Errorf("diskSizeGB = %d, want %d", got, effectiveGCPDiskSizeGB(gw))
	}
	if got, _, _ := unstructured.NestedBool(u.Object, "spec", "reservedIP"); got != effectiveGCPReservedIP(gw) {
		t.Errorf("reservedIP = %v, want %v", got, effectiveGCPReservedIP(gw))
	}

	id := gcpID(gw.Namespace, gw.Name)
	assertNestedString(t, u, id, "spec", "serviceAccountId")
	assertNestedString(t, u, id, "spec", "secretId")
	assertNestedString(t, u, wg.BundleKey, "spec", "wgKeySecretRef", "key")
	assertNestedString(t, u, bundleSecretName(gw), "spec", "wgKeySecretRef", "name")

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

// TestBuildXGatewayGCPOptionalFields pins the fields the builder omits when
// unconfigured: the operator-level userData (empty config) and allowedPorts (no
// forwards). image and diskSizeGB are no longer omittable: they carry CRD
// defaults and the builder always sets them from gw.Spec via the defaulting
// accessors.
func TestBuildXGatewayGCPOptionalFields(t *testing.T) {
	cfg := testConfig()
	cfg.UserData = ""

	gw := newGateway("edge", "wg-system", nil, nil)

	u, err := buildXGatewayGCP(gw, cfg, gw.Spec.Forwards)
	if err != nil {
		t.Fatalf("buildXGatewayGCP: %v", err)
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

// TestBuildXGatewayGCPWireguardListenPort pins the split-brain fix at the
// operator boundary: a non-default spec.wireguard.listenPort flows verbatim onto
// the composite's wgListenPort, so the single per-Gateway value reaches the
// instance metadata and the gateway VM boots on the port the link dials.
func TestBuildXGatewayGCPWireguardListenPort(t *testing.T) {
	cfg := testConfig()
	gw := newGateway("edge", "wg-system", nil, nil)
	gw.Spec.Wireguard.ListenPort = 51999

	u, err := buildXGatewayGCP(gw, cfg, gw.Spec.Forwards)
	if err != nil {
		t.Fatalf("buildXGatewayGCP: %v", err)
	}

	if got, _, _ := unstructured.NestedInt64(u.Object, "spec", "wgListenPort"); got != 51999 {
		t.Errorf("wgListenPort = %d, want 51999 (non-default spec.wireguard.listenPort)", got)
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

	cm, err := buildLinkConfigMap(gw, "", gw.Spec.Forwards)
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
	if rc.WireGuard.Peer.PersistentKeepalive != wantKeepalive {
		t.Errorf("peer.persistentKeepalive = %d, want %d", rc.WireGuard.Peer.PersistentKeepalive, wantKeepalive)
	}
	wantSubnet := effectiveWGSubnet(gw)
	if len(rc.WireGuard.Peer.AllowedIPs) != 1 || rc.WireGuard.Peer.AllowedIPs[0] != wantSubnet {
		t.Errorf("peer.allowedIPs = %v, want [%s]", rc.WireGuard.Peer.AllowedIPs, wantSubnet)
	}

	if rc.WireGuard.Peer.Endpoint != "" {
		t.Errorf("peer.endpoint = %q, want empty when address is unknown", rc.WireGuard.Peer.Endpoint)
	}

	wantForwards := []link.Forward{
		{Name: "tcp-443", PublicPort: 443, Protocol: "tcp", Service: "web.wg-system.svc.cluster.local", TargetPort: 8443},
		{Name: "udp-1194", PublicPort: 1194, Protocol: "udp", Service: "vpn.wg-system.svc.cluster.local", TargetPort: 1194},
	}
	if !slices.Equal(rc.Forwards, wantForwards) {
		t.Errorf("forwards = %+v, want %+v", rc.Forwards, wantForwards)
	}
}

// TestBuildLinkConfigMapEndpoint pins the operator-supplied peer endpoint: a
// known gateway address is rendered as address:wireguardPort, and an empty
// address leaves the endpoint unset so the link waits for the operator to observe
// the IP and reload in place.
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

			cm, err := buildLinkConfigMap(gw, tt.address, gw.Spec.Forwards)
			if err != nil {
				t.Fatalf("buildLinkConfigMap: %v", err)
			}
			var rc link.RuntimeConfig
			decodeJSON(t, cm.Data[linkConfigKey], &rc)

			if rc.WireGuard.Peer.Endpoint != tt.wantEndpoint {
				t.Errorf("peer.endpoint = %q, want %q", rc.WireGuard.Peer.Endpoint, tt.wantEndpoint)
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

			cm, err := buildLinkConfigMap(gw, "", gw.Spec.Forwards)
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

// TestBuildLinkConfigMapRoundTrip is the regression guard that the ConfigMap the
// operator writes is one the link daemon actually accepts: it loads the emitted
// JSON through link.LoadRuntimeConfig (the real parse-and-validate path) and
// confirms the forwards survive the round trip. validate lowercases protocols
// and requires service plus an in-range target port, so this also pins the
// defaulting and casing the builder must satisfy.
func TestBuildLinkConfigMapRoundTrip(t *testing.T) {
	gw := newGateway("edge", "wg-system",
		[]wgnetv1alpha1.Forward{
			{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web", TargetPort: 8443},
			{Port: 1194, Protocol: wgnetv1alpha1.ProtocolUDP, Service: "vpn"},
		}, nil)

	cm, err := buildLinkConfigMap(gw, "", gw.Spec.Forwards)
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

// TestEffectiveForwardNamespace pins the namespace-defaulting rule the FQDN
// builder and the cross-namespace gate both depend on: an unset Forward.Namespace
// resolves to the Gateway's namespace, while an explicit one is honored verbatim.
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

// TestBuildLinkConfigMapServiceFQDN pins that the link's runtime config carries a
// fully-qualified Service name, defaulting to the Gateway namespace and honoring an
// explicit cross-namespace target. Building the FQDN in the operator makes backend
// resolution explicit and identical for same- and cross-namespace forwards.
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
			cm, err := buildLinkConfigMap(gw, "", gw.Spec.Forwards)
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

// hasOpenEgressPort reports whether any egress rule permits proto/port to a
// 0.0.0.0/0 peer. The link's forward and WireGuard rules use that open CIDR so
// the policy holds whether the CNI matches on the Service ClusterIP or the
// resolved pod IP.
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

// hasDNSEgress reports whether any egress rule targets the kube-dns pods in
// kube-system on the given protocol at port 53.
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

// TestBuildLinkNetworkPolicy pins the egress allowlist kindnet enforces: DNS, the
// WireGuard underlay, and one rule per forward at its effective target port. The
// unset-TargetPort case must default to the public port so the policy tracks the
// DNAT target the link actually dials. The link holds no cluster credentials, so
// there must be no apiserver (TCP/443) egress.
func TestBuildLinkNetworkPolicy(t *testing.T) {
	tests := []struct {
		name      string
		forwards  []wgnetv1alpha1.Forward
		wantPorts []struct {
			proto corev1.Protocol
			port  int32
		}
	}{
		{
			name: "tcp and udp forwards with explicit and defaulted target ports",
			forwards: []wgnetv1alpha1.Forward{
				{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web", TargetPort: 8443},
				{Port: 1194, Protocol: wgnetv1alpha1.ProtocolUDP, Service: "vpn"},
			},
			wantPorts: []struct {
				proto corev1.Protocol
				port  int32
			}{
				{corev1.ProtocolTCP, 8443},
				{corev1.ProtocolUDP, 1194},
			},
		},
		{
			name:     "no forwards still permits control-plane egress",
			forwards: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system", tt.forwards, nil)

			np := buildLinkNetworkPolicy(gw, gw.Spec.Forwards)

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
			if hasOpenEgressPort(egress, corev1.ProtocolTCP, 443) {
				t.Errorf("egress permits apiserver TCP 443; link holds no cluster credentials: %+v", egress)
			}
			for _, w := range tt.wantPorts {
				if !hasOpenEgressPort(egress, w.proto, w.port) {
					t.Errorf("egress missing forward %s %d rule: %+v", w.proto, w.port, egress)
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
		t.Errorf("replicas = %d, want 1", got)
	}
	if dep.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType {
		t.Errorf("strategy = %q, want Recreate", dep.Spec.Strategy.Type)
	}

	podSpec := dep.Spec.Template.Spec
	if len(podSpec.InitContainers) != 0 {
		t.Errorf("init containers = %d, want 0", len(podSpec.InitContainers))
	}

	// IP forwarding is enabled by the kubelet via the pod-level sysctl, not a
	// privileged init container or a /proc write.
	if podSpec.SecurityContext == nil {
		t.Fatal("pod securityContext = nil, want sysctls")
	}
	wantSysctl := corev1.Sysctl{Name: "net.ipv4.ip_forward", Value: "1"}
	if !slices.Contains(podSpec.SecurityContext.Sysctls, wantSysctl) {
		t.Errorf("pod sysctls = %+v, want to contain %+v", podSpec.SecurityContext.Sysctls, wantSysctl)
	}

	// No container, init or main, may be privileged.
	privilegeChecks := []struct {
		group      string
		containers []corev1.Container
	}{
		{"init", podSpec.InitContainers},
		{"main", podSpec.Containers},
	}
	for _, pc := range privilegeChecks {
		for _, ctr := range pc.containers {
			if ctr.SecurityContext != nil && ctr.SecurityContext.Privileged != nil && *ctr.SecurityContext.Privileged {
				t.Errorf("%s container %q is privileged, want not privileged", pc.group, ctr.Name)
			}
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

	// The config ConfigMap must be mounted as a live directory, never with a
	// subPath: a subPath mount is copied once at container start and never
	// refreshed by the kubelet, which defeats the link's in-place reload of the
	// operator-injected gateway endpoint. GATEWAY_CONFIG_PATH must point at the
	// file inside that directory.
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

	// The link no longer reads the XGatewayGCP, so the cluster-lookup env is gone and
	// no ServiceAccount token is projected into the pod.
	for _, gone := range []string{"GATEWAY_NAME", "GATEWAY_NAMESPACE", "GATEWAY_WG_LISTEN_PORT"} {
		if _, present := env[gone]; present {
			t.Errorf("env[%q] present, want removed (link holds no cluster credentials)", gone)
		}
	}
	if podSpec.ServiceAccountName != "" {
		t.Errorf("serviceAccountName = %q, want empty (no link RBAC)", podSpec.ServiceAccountName)
	}
	if podSpec.AutomountServiceAccountToken == nil || *podSpec.AutomountServiceAccountToken {
		t.Errorf("automountServiceAccountToken = %v, want false", podSpec.AutomountServiceAccountToken)
	}

	// The link must not receive the stale CYNO_* env the deleted chart used.
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

// TestBuildXGatewayGCPProviderSelector pins the multi-cloud scoping contract: the
// composite carries a spec.crossplane.compositionSelector matchLabels provider
// that defaults to gcp and honors an explicitly set provider, so a second
// provider's Composition can be dropped in without collision. The selector lives
// under spec.crossplane because the XRD is apiextensions.crossplane.io/v2, which
// nests the composition-machinery fields there rather than at the v1 spec root.
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

			u, err := buildXGatewayGCP(gw, cfg, gw.Spec.Forwards)
			if err != nil {
				t.Fatalf("buildXGatewayGCP: %v", err)
			}
			assertNestedString(t, u, tt.want, "spec", "crossplane", "compositionSelector", "matchLabels", "provider")
		})
	}
}

// TestBuildXGatewayNetwork pins the singleton shared-VPC composite: it is named
// and spec'd from cfg.SharedNetworkName, lives in cfg.PodNamespace alongside the
// operator pod, pins the gcp Composition via compositionSelector, and carries no
// ownerReference so deleting any one Gateway never garbage-collects the shared
// network.
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

// TestGCPIDBase32Length documents the encoding bound the truncation relies on:
// sha256 (32 bytes) base32-encodes to 52 chars, so the prefix+hash always
// exceeds the 30-char cap and truncation is exercised.
func TestGCPIDBase32Length(t *testing.T) {
	full := base32.StdEncoding.WithPadding(base32.NoPadding).EncodedLen(32)
	if full+len(gcpIDPrefix) <= gcpIDMaxLen {
		t.Fatalf("base32 length %d + prefix does not exceed cap %d; truncation untested", full, gcpIDMaxLen)
	}
}
