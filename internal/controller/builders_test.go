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

	wgnetv1alpha1 "github.com/greg2010/wireguard-gateway-operator/api/v1alpha1"
	"github.com/greg2010/wireguard-gateway-operator/internal/link"
	"github.com/greg2010/wireguard-gateway-operator/internal/wg"
)

// testConfig is the operator-global config the builder tests fold into Gateways.
func testConfig() Config {
	return Config{
		Namespace:           "wg-system",
		LinkImage:           "registry.example.com/gateway-link:test",
		LinkImagePullPolicy: "IfNotPresent",
		WGSubnet:            "10.99.0.0/29",
		WGLinkAddress:       "10.99.0.2",
		WGListenPort:        51820,
		WGKeepalive:         25,
		WGMTU:               1380,
		WGReconcileInterval: 0,
		GCPSubnetCIDR:       "10.200.0.0/24",
		GCPImage:            "projects/test/global/images/flatcar",
		GCPDiskSizeGB:       20,
		GCPReservedIP:       true,
		GCPSpot:             false,
		UserData:            "#ignition\n",
		RequeueInterval:     0,
	}
}

// newGateway builds a Gateway fixture with the given forwards and hostnames.
func newGateway(name, namespace string, forwards []wgnetv1alpha1.Forward, hostnames []string) *wgnetv1alpha1.Gateway {
	return &wgnetv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: wgnetv1alpha1.GatewaySpec{
			GCP: wgnetv1alpha1.GatewayGCPSpec{
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

// assertSameStringSet fails unless got and want hold the same elements ignoring
// order.
func assertSameStringSet(t *testing.T, label string, got, want []string) {
	t.Helper()
	g := append([]string(nil), got...)
	w := append([]string(nil), want...)
	slices.Sort(g)
	slices.Sort(w)
	if !slices.Equal(g, w) {
		t.Errorf("%s = %v, want %v", label, got, want)
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

func TestBuildXGateway(t *testing.T) {
	cfg := testConfig()
	gw := newGateway("edge", "wg-system",
		[]wgnetv1alpha1.Forward{
			{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP},
			{Port: 1194, Protocol: wgnetv1alpha1.ProtocolUDP},
		},
		[]string{"edge.example.com"},
	)

	u, err := buildXGateway(gw, cfg)
	if err != nil {
		t.Fatalf("buildXGateway: %v", err)
	}

	if got := u.GetAPIVersion(); got != xgatewayAPIVersion {
		t.Errorf("apiVersion = %q, want %q", got, xgatewayAPIVersion)
	}
	if got := u.GetKind(); got != xgatewayKind {
		t.Errorf("kind = %q, want %q", got, xgatewayKind)
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
	assertNestedString(t, u, cfg.GCPSubnetCIDR, "spec", "subnetCIDR")
	assertNestedString(t, u, cfg.UserData, "spec", "userData")
	assertNestedString(t, u, cfg.GCPImage, "spec", "image")

	if got, _, _ := unstructured.NestedInt64(u.Object, "spec", "wgListenPort"); got != int64(cfg.WGListenPort) {
		t.Errorf("wgListenPort = %d, want %d", got, cfg.WGListenPort)
	}
	if got, _, _ := unstructured.NestedBool(u.Object, "spec", "reservedIP"); got != cfg.GCPReservedIP {
		t.Errorf("reservedIP = %v, want %v", got, cfg.GCPReservedIP)
	}

	id := gcpID(gw.Namespace, gw.Name)
	assertNestedString(t, u, id, "spec", "serviceAccountId")
	assertNestedString(t, u, id, "spec", "secretId")
	assertNestedString(t, u, wg.BundleKey, "spec", "wgKeySecretRef", "key")
	assertNestedString(t, u, bundleSecretName(gw), "spec", "wgKeySecretRef", "name")

	hostnames, _, err := unstructured.NestedStringSlice(u.Object, "spec", "dnsHostnames")
	if err != nil {
		t.Fatalf("read dnsHostnames: %v", err)
	}
	if len(hostnames) != 1 || hostnames[0] != "edge.example.com" {
		t.Errorf("dnsHostnames = %v, want [edge.example.com]", hostnames)
	}

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
		t.Errorf("buildXGateway must not set status; serviceAccountEmail is GCP-observed")
	}
}

func TestBuildXGatewayOptionalFields(t *testing.T) {
	cfg := testConfig()
	cfg.GCPImage = ""
	cfg.GCPDiskSizeGB = 0
	cfg.UserData = ""

	gw := newGateway("edge", "wg-system", nil, nil)

	u, err := buildXGateway(gw, cfg)
	if err != nil {
		t.Fatalf("buildXGateway: %v", err)
	}

	for _, field := range []string{"image", "diskSizeGB", "userData", "dnsHostnames", "allowedPorts"} {
		if _, found, _ := unstructured.NestedFieldNoCopy(u.Object, "spec", field); found {
			t.Errorf("spec.%s set, want omitted when unconfigured/empty", field)
		}
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
	cfg := testConfig()
	gw := newGateway("edge", "wg-system",
		[]wgnetv1alpha1.Forward{
			{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web", TargetPort: 8443},
			{Port: 1194, Protocol: wgnetv1alpha1.ProtocolUDP, Service: "vpn"},
		}, nil)

	cm, err := buildLinkConfigMap(gw, cfg)
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
	var rc linkRuntimeConfig
	decodeJSON(t, raw, &rc)

	if rc.WireGuard.Address != "10.99.0.2/29" {
		t.Errorf("wireguard.address = %q, want 10.99.0.2/29", rc.WireGuard.Address)
	}
	if rc.WireGuard.MTU != cfg.WGMTU {
		t.Errorf("wireguard.mtu = %d, want %d", rc.WireGuard.MTU, cfg.WGMTU)
	}
	if rc.WireGuard.Peer.PersistentKeepalive != cfg.WGKeepalive {
		t.Errorf("peer.persistentKeepalive = %d, want %d", rc.WireGuard.Peer.PersistentKeepalive, cfg.WGKeepalive)
	}
	if len(rc.WireGuard.Peer.AllowedIPs) != 1 || rc.WireGuard.Peer.AllowedIPs[0] != cfg.WGSubnet {
		t.Errorf("peer.allowedIPs = %v, want [%s]", rc.WireGuard.Peer.AllowedIPs, cfg.WGSubnet)
	}

	wantForwards := []linkForward{
		{Name: "tcp-443", PublicPort: 443, Protocol: "tcp", Service: "web", TargetPort: 8443},
		{Name: "udp-1194", PublicPort: 1194, Protocol: "udp", Service: "vpn", TargetPort: 1194},
	}
	if !slices.Equal(rc.Forwards, wantForwards) {
		t.Errorf("forwards = %+v, want %+v", rc.Forwards, wantForwards)
	}
}

// TestBuildLinkConfigMapTargetPortDefault covers the target-port defaulting rule:
// an unset TargetPort mirrors Port, while a set one is preserved verbatim.
func TestBuildLinkConfigMapTargetPortDefault(t *testing.T) {
	cfg := testConfig()
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

			cm, err := buildLinkConfigMap(gw, cfg)
			if err != nil {
				t.Fatalf("buildLinkConfigMap: %v", err)
			}
			var rc linkRuntimeConfig
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
	cfg := testConfig()
	gw := newGateway("edge", "wg-system",
		[]wgnetv1alpha1.Forward{
			{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web", TargetPort: 8443},
			{Port: 1194, Protocol: wgnetv1alpha1.ProtocolUDP, Service: "vpn"},
		}, nil)

	cm, err := buildLinkConfigMap(gw, cfg)
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
		{Name: "tcp-443", PublicPort: 443, Protocol: "tcp", Service: "web", TargetPort: 8443},
		{Name: "udp-1194", PublicPort: 1194, Protocol: "udp", Service: "vpn", TargetPort: 1194},
	}
	if !slices.Equal(rc.Forwards, wantForwards) {
		t.Errorf("loaded forwards = %+v, want %+v", rc.Forwards, wantForwards)
	}
}

// hasOpenEgressPort reports whether any egress rule permits proto/port to a
// 0.0.0.0/0 peer. The link's forward and apiserver rules use that open CIDR so
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
// WireGuard underlay, the apiserver on 443, and one rule per forward at its
// effective target port. The unset-TargetPort case must default to the public
// port so the policy tracks the DNAT target the link actually dials.
func TestBuildLinkNetworkPolicy(t *testing.T) {
	cfg := testConfig()
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

			np := buildLinkNetworkPolicy(gw, cfg)

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
			if !hasOpenEgressPort(egress, corev1.ProtocolUDP, int32(cfg.WGListenPort)) {
				t.Errorf("egress missing WireGuard UDP %d rule: %+v", cfg.WGListenPort, egress)
			}
			if !hasOpenEgressPort(egress, corev1.ProtocolTCP, 443) {
				t.Errorf("egress missing apiserver TCP 443 rule: %+v", egress)
			}
			for _, w := range tt.wantPorts {
				if !hasOpenEgressPort(egress, w.proto, w.port) {
					t.Errorf("egress missing forward %s %d rule: %+v", w.proto, w.port, egress)
				}
			}
		})
	}
}

func TestBuildLinkRole(t *testing.T) {
	gw := newGateway("edge", "wg-system", nil, nil)
	role := buildLinkRole(gw)

	if len(role.Rules) != 1 {
		t.Fatalf("role rules = %d, want 1", len(role.Rules))
	}
	rule := role.Rules[0]
	assertSameStringSet(t, "apiGroups", rule.APIGroups, []string{"infra.wgnet.dev"})
	assertSameStringSet(t, "resources", rule.Resources, []string{"xgateways"})
	assertSameStringSet(t, "verbs", rule.Verbs, []string{"get", "list", "watch"})
}

func TestBuildLinkRoleBinding(t *testing.T) {
	gw := newGateway("edge", "wg-system", nil, nil)
	rb := buildLinkRoleBinding(gw)

	if rb.RoleRef.Name != "edge-link" || rb.RoleRef.Kind != "Role" {
		t.Errorf("roleRef = %+v, want Role/edge-link", rb.RoleRef)
	}
	if len(rb.Subjects) != 1 {
		t.Fatalf("subjects = %d, want 1", len(rb.Subjects))
	}
	s := rb.Subjects[0]
	if s.Kind != "ServiceAccount" || s.Name != "edge-link" || s.Namespace != "wg-system" {
		t.Errorf("subject = %+v, want ServiceAccount edge-link/wg-system", s)
	}
}

func TestBuildLinkDeployment(t *testing.T) {
	cfg := testConfig()
	cfg.WGReconcileInterval = 10_000_000_000 // 10s
	gw := newGateway("edge", "wg-system", nil, nil)

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
		"GATEWAY_NAME":                "edge",
		"GATEWAY_NAMESPACE":           "wg-system",
		"GATEWAY_WG_LISTEN_PORT":      "51820",
		"GATEWAY_RECONCILE_INTERVAL":  "10s",
		"GATEWAY_CONFIG_PATH":         "/etc/cyno/config.json",
		"GATEWAY_WG_KEY_PATH":         "/etc/cyno/wg/" + wg.LinkPrivateKey,
		"GATEWAY_WG_PEER_PUBKEY_PATH": "/etc/cyno/wg/" + wg.LinkPeerPublicKey,
	}
	for k, want := range wantEnv {
		if env[k] != want {
			t.Errorf("env[%q] = %q, want %q", k, env[k], want)
		}
	}

	// The link must not receive the stale CYNO_* env the deleted chart used.
	for _, e := range c.Env {
		if strings.HasPrefix(e.Name, "CYNO_") {
			t.Errorf("unexpected legacy env %q on link container", e.Name)
		}
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
