package controller

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"

	gcp "github.com/greg2010/wireguard-gateway-operator/internal/crossplane/gcp"
	"github.com/greg2010/wireguard-gateway-operator/internal/link"
	"github.com/greg2010/wireguard-gateway-operator/internal/wg"
	wgnetv1alpha1 "github.com/greg2010/wireguard-gateway-operator/pkg/api/v1alpha1"
)

const (
	// gcpIDPrefix prefixes the hash-derived GCP service-account and secret IDs.
	// It guarantees the leading letter GCP requires and namespaces the operator's
	// IDs apart from any other tenant in the project.
	gcpIDPrefix = "gw-"
	// gcpIDMaxLen is GCP's service-account-ID length cap; secret IDs are looser
	// but share the derived value so both fit this bound.
	gcpIDMaxLen = 30

	// linkConfigKey is the data key under which the link Deployment's RuntimeConfig
	// JSON is stored in its ConfigMap and mounted into the container.
	linkConfigKey = "config.json"

	// componentLink labels and names the in-cluster link objects.
	componentLink = "link"

	// xgatewayGCPAPIVersion and xgatewayGCPKind identify the Crossplane composite the
	// operator builds; it is handled unstructured because the typed view models
	// only the spec/status, not the full Kubernetes object.
	xgatewayGCPAPIVersion = "infra.wgnet.dev/v1alpha1"
	xgatewayGCPKind       = "XGatewayGCP"

	// xgatewayNetworkKind is the singleton composite that provisions the shared
	// VPC. It shares xgatewayGCPAPIVersion: both composites live in the same
	// infra.wgnet.dev group/version.
	xgatewayNetworkKind = "XGatewayNetwork"

	// providerLabelKey is the matchLabels key under spec.crossplane.compositionSelector
	// that pins the provider-specific Composition. The per-provider Composition carries
	// the matching provider label so a second provider's Composition can coexist
	// without collision.
	providerLabelKey = "provider"

	// dnsEndpointAPIVersion and dnsEndpointKind identify the external-dns
	// DNSEndpoint the operator publishes; handled unstructured because its CRD is
	// an optional install prerequisite, not a compiled-in type.
	dnsEndpointAPIVersion = "externaldns.k8s.io/v1alpha1"
	dnsEndpointKind       = "DNSEndpoint"
	// cloudflareProxiedAnnotation keeps published records DNS-only: gateway
	// traffic is raw WireGuard/TCP and must never sit behind a proxy.
	cloudflareProxiedAnnotation = "external-dns.alpha.kubernetes.io/cloudflare-proxied"
)

// gcpID derives a project-global-unique, GCP-valid service-account/secret ID for
// a Gateway. The input is namespace-qualified so the same Gateway name in two
// namespaces does not collide. The output is gw-<lowercase-base32(sha256)>
// truncated to GCP's 30-char limit: the gw- prefix supplies the required leading
// letter and base32's [a-z2-7] alphabet is wholly GCP-valid, including the
// truncation boundary, so no trailing-character fixup is needed.
func gcpID(namespace, name string) string {
	sum := sha256.Sum256([]byte(namespace + "/" + name))
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])
	id := gcpIDPrefix + strings.ToLower(enc)
	if len(id) > gcpIDMaxLen {
		id = id[:gcpIDMaxLen]
	}
	return id
}

// bundleSecretName and linkSecretName name the two WireGuard key Secrets a
// Gateway owns. They are per-Gateway so two Gateways in a namespace do not share
// key material.
func bundleSecretName(gw *wgnetv1alpha1.Gateway) string { return gw.Name + "-bundle" }
func linkSecretName(gw *wgnetv1alpha1.Gateway) string   { return gw.Name + "-link" }

// linkComponentName names the link Deployment, ConfigMap, and NetworkPolicy for a
// Gateway.
func linkComponentName(gw *wgnetv1alpha1.Gateway) string { return gw.Name + "-link" }

// commonLabels are the identifying labels stamped on every child object.
func commonLabels(gw *wgnetv1alpha1.Gateway, component string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       "wireguard-gateway-operator",
		"app.kubernetes.io/instance":   gw.Name,
		"app.kubernetes.io/component":  component,
		"app.kubernetes.io/managed-by": "gateway-operator",
	}
}

// buildXGatewayGCP builds the Crossplane composite that provisions the gateway VM.
// It maps the Gateway's GCP placement and WireGuard tunnel parameters from
// gw.Spec (defaulting in-memory Gateways that bypassed CRD defaulting), points
// wgKeySecretRef at the bundle Secret, derives the per-Gateway
// serviceAccountId/secretId, and sets the operator-level VM userData. The
// per-Gateway WireGuard values (listen port, gateway/link address, subnet) and
// the GCP projectID flow onto the composite so the composition can stamp them
// into the instance metadata the boot keyfetch reads, keeping the userData
// byte-identical across every Gateway. The typed spec is marshalled into the
// unstructured object so the composite carries the exact field shape the XRD and
// composition consume. DNS publication is not on the composite: the operator
// emits the DNSEndpoint directly from gw.Spec.DNSHostnames. serviceAccountEmail
// is intentionally absent: it is GCP-observed and surfaced through the composite
// status.
//
// forwards is the validated subset the caller chose to expose, not gw.Spec.Forwards
// verbatim: each becomes an entry in the firewall's AllowedPorts. An empty slice
// leaves AllowedPorts unset, closing the GCP firewall to the WireGuard underlay
// only, which is the correct posture when no forward currently resolves.
func buildXGatewayGCP(gw *wgnetv1alpha1.Gateway, cfg Config, forwards []wgnetv1alpha1.Forward) (*unstructured.Unstructured, error) {
	id := gcpID(gw.Namespace, gw.Name)
	image := effectiveGCPImage(gw)
	diskSizeGB := int(effectiveGCPDiskSizeGB(gw))
	reservedIP := effectiveGCPReservedIP(gw)
	spot := effectiveGCPSpot(gw)
	projectID := gw.Spec.GCP.ProjectID
	wgGatewayAddress := effectiveWGGatewayAddress(gw)
	wgLinkAddress := effectiveWGLinkAddress(gw)
	wgSubnet := effectiveWGSubnet(gw)

	spec := gcp.XGatewayGCPSpec{
		Region:            gw.Spec.GCP.Region,
		Zone:              gw.Spec.GCP.Zone,
		MachineType:       gw.Spec.GCP.MachineType,
		SharedNetworkName: cfg.SharedNetworkName,
		Image:             &image,
		DiskSizeGB:        &diskSizeGB,
		WgListenPort:      int(effectiveWireguardPort(gw)),
		WgGatewayAddress:  &wgGatewayAddress,
		WgLinkAddress:     &wgLinkAddress,
		WgSubnet:          &wgSubnet,
		ProjectID:         &projectID,
		ReservedIP:        &reservedIP,
		Spot:              &spot,
		ServiceAccountId:  &id,
		SecretId:          &id,
		WgKeySecretRef: &struct {
			Key  string `json:"key"`
			Name string `json:"name"`
		}{Key: wg.BundleKey, Name: bundleSecretName(gw)},
	}

	if cfg.UserData != "" {
		spec.UserData = &cfg.UserData
	}
	if len(forwards) > 0 {
		ports := make([]struct {
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
		}, 0, len(forwards))
		for _, f := range forwards {
			ports = append(ports, struct {
				Port     int    `json:"port"`
				Protocol string `json:"protocol"`
			}{Port: int(f.Port), Protocol: strings.ToLower(string(f.Protocol))})
		}
		spec.AllowedPorts = &ports
	}

	specMap, err := toUnstructuredMap(&spec)
	if err != nil {
		return nil, fmt.Errorf("encode xgatewaygcp spec: %w", err)
	}

	specMap["crossplane"] = map[string]any{
		"compositionSelector": map[string]any{
			"matchLabels": map[string]any{providerLabelKey: string(gatewayProvider(gw))},
		},
	}

	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": xgatewayGCPAPIVersion,
		"kind":       xgatewayGCPKind,
		"spec":       specMap,
	}}
	u.SetName(gw.Name)
	u.SetNamespace(gw.Namespace)
	u.SetLabels(commonLabels(gw, "gateway"))
	return u, nil
}

// buildXGatewayNetwork builds the singleton shared-VPC composite. It is named
// cfg.SharedNetworkName and placed in cfg.PodNamespace alongside the operator
// pod, not in any Gateway's namespace, because it has no owning Gateway: its
// lifecycle is refcount-managed by the controller across every Gateway that
// attaches to the shared VPC. It carries no ownerReference for the same reason,
// so it is not garbage-collected when any single Gateway is deleted. The
// compositionSelector pins the gcp Composition; the shared network is GCP-only
// today, so the provider label is fixed rather than derived from a Gateway.
func buildXGatewayNetwork(cfg Config) *unstructured.Unstructured {
	spec := map[string]any{
		"name": cfg.SharedNetworkName,
		"crossplane": map[string]any{
			"compositionSelector": map[string]any{
				"matchLabels": map[string]any{providerLabelKey: string(wgnetv1alpha1.ProviderGCP)},
			},
		},
	}

	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": xgatewayGCPAPIVersion,
		"kind":       xgatewayNetworkKind,
		"spec":       spec,
	}}
	u.SetName(cfg.SharedNetworkName)
	u.SetNamespace(cfg.PodNamespace)
	u.SetLabels(map[string]string{
		"app.kubernetes.io/name":       "wireguard-gateway-operator",
		"app.kubernetes.io/component":  "shared-network",
		"app.kubernetes.io/managed-by": "gateway-operator",
	})
	return u
}

// gatewayProvider returns the Gateway's provider, defaulting an empty value to
// gcp. The CRD default normally populates it, so this guards only objects that
// bypassed defaulting (e.g. a directly-constructed in-memory Gateway).
func gatewayProvider(gw *wgnetv1alpha1.Gateway) wgnetv1alpha1.CloudProvider {
	if gw.Spec.Provider == "" {
		return wgnetv1alpha1.ProviderGCP
	}
	return gw.Spec.Provider
}

// The default consts mirror the CRD defaults on GatewayGCPSpec and
// GatewayWireguardSpec. They are the single source the effective* accessors apply
// when a field is unset, which happens only for in-memory Gateways that bypassed
// CRD defaulting (the API server populates them for any applied Gateway).
const (
	gcpDefaultImage            = "projects/kinvolk-public/global/images/family/flatcar-stable"
	gcpDefaultDiskSizeGB int32 = 20

	wgDefaultListenPort        int32 = 51820
	wgDefaultSubnet                  = "10.99.0.0/29"
	wgDefaultGatewayAddress          = "10.99.0.1"
	wgDefaultLinkAddress             = "10.99.0.2"
	wgDefaultKeepalive         int32 = 25
	wgDefaultMTU               int32 = 1380
	wgDefaultReconcileInterval       = "10s"
)

// effectiveGCPImage returns the gateway VM boot image, defaulting an unset value.
func effectiveGCPImage(gw *wgnetv1alpha1.Gateway) string {
	if gw.Spec.GCP.Image == "" {
		return gcpDefaultImage
	}
	return gw.Spec.GCP.Image
}

// effectiveGCPDiskSizeGB returns the gateway VM boot disk size, defaulting an
// unset value.
func effectiveGCPDiskSizeGB(gw *wgnetv1alpha1.Gateway) int32 {
	if gw.Spec.GCP.DiskSizeGB == 0 {
		return gcpDefaultDiskSizeGB
	}
	return gw.Spec.GCP.DiskSizeGB
}

// effectiveGCPReservedIP returns whether a static external IP is allocated,
// defaulting a nil pointer to true to mirror the CRD default.
func effectiveGCPReservedIP(gw *wgnetv1alpha1.Gateway) bool {
	if gw.Spec.GCP.ReservedIP == nil {
		return true
	}
	return *gw.Spec.GCP.ReservedIP
}

// effectiveGCPSpot returns whether the gateway VM runs as a spot instance.
func effectiveGCPSpot(gw *wgnetv1alpha1.Gateway) bool {
	return gw.Spec.GCP.Spot
}

// effectiveWireguardPort returns the Gateway's WireGuard listen port, defaulting an
// unset value to wgDefaultListenPort for in-memory Gateways that bypassed CRD defaulting.
func effectiveWireguardPort(gw *wgnetv1alpha1.Gateway) int32 {
	if gw.Spec.Wireguard.ListenPort == 0 {
		return wgDefaultListenPort
	}
	return gw.Spec.Wireguard.ListenPort
}

// effectiveWGSubnet returns the WireGuard tunnel CIDR, defaulting an unset value.
func effectiveWGSubnet(gw *wgnetv1alpha1.Gateway) string {
	if gw.Spec.Wireguard.Subnet == "" {
		return wgDefaultSubnet
	}
	return gw.Spec.Wireguard.Subnet
}

// effectiveWGGatewayAddress returns the gateway VM's wg0 address, defaulting an
// unset value.
func effectiveWGGatewayAddress(gw *wgnetv1alpha1.Gateway) string {
	if gw.Spec.Wireguard.GatewayAddress == "" {
		return wgDefaultGatewayAddress
	}
	return gw.Spec.Wireguard.GatewayAddress
}

// effectiveWGLinkAddress returns the link end's wg0 address, defaulting an unset
// value.
func effectiveWGLinkAddress(gw *wgnetv1alpha1.Gateway) string {
	if gw.Spec.Wireguard.LinkAddress == "" {
		return wgDefaultLinkAddress
	}
	return gw.Spec.Wireguard.LinkAddress
}

// effectiveWGKeepalive returns the link's persistent-keepalive interval in
// seconds, defaulting an unset value.
func effectiveWGKeepalive(gw *wgnetv1alpha1.Gateway) int32 {
	if gw.Spec.Wireguard.Keepalive == 0 {
		return wgDefaultKeepalive
	}
	return gw.Spec.Wireguard.Keepalive
}

// effectiveWGMTU returns the link's wg0 MTU, defaulting an unset value.
func effectiveWGMTU(gw *wgnetv1alpha1.Gateway) int32 {
	if gw.Spec.Wireguard.MTU == 0 {
		return wgDefaultMTU
	}
	return gw.Spec.Wireguard.MTU
}

// effectiveWGReconcileInterval returns how often the link re-reads the
// XGatewayGCP address, defaulting an unset value.
func effectiveWGReconcileInterval(gw *wgnetv1alpha1.Gateway) string {
	if gw.Spec.Wireguard.ReconcileInterval == "" {
		return wgDefaultReconcileInterval
	}
	return gw.Spec.Wireguard.ReconcileInterval
}

// XGatewayGCPGVK is the composite's GroupVersionKind, exported so the manager can
// register an unstructured Owns watch on it.
var XGatewayGCPGVK = schema.GroupVersionKind{Group: "infra.wgnet.dev", Version: "v1alpha1", Kind: "XGatewayGCP"}

// newXGatewayGCP returns an empty unstructured XGatewayGCP with its GVK set, for Get,
// CreateOrUpdate, and the Owns watch.
func newXGatewayGCP() *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(XGatewayGCPGVK)
	return u
}

// XGatewayNetworkGVK is the shared-VPC composite's GroupVersionKind, exported so
// the manager can register an unstructured watch on it.
var XGatewayNetworkGVK = schema.GroupVersionKind{Group: "infra.wgnet.dev", Version: "v1alpha1", Kind: "XGatewayNetwork"}

// newXGatewayNetwork returns an empty unstructured XGatewayNetwork with its GVK
// set, for Get, CreateOrUpdate, and the watch.
func newXGatewayNetwork() *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(XGatewayNetworkGVK)
	return u
}

// buildBundleSecret builds the gateway-bundle Secret read by the XGatewayGCP's
// SecretVersion. Its single data key holds "<gatewayPriv>\n<linkPub>\n", the
// payload the VM boot script splits. The caller supplies both keypairs so the
// link Secret can be built from the same material.
func buildBundleSecret(gw *wgnetv1alpha1.Gateway, gatewayPriv, linkPub string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bundleSecretName(gw),
			Namespace: gw.Namespace,
			Labels:    commonLabels(gw, "bundle"),
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			wg.BundleKey: []byte(gatewayPriv + "\n" + linkPub + "\n"),
		},
	}
}

// buildLinkSecret builds the Secret the link mounts: its own private key and the
// gateway's public key (its sole peer).
func buildLinkSecret(gw *wgnetv1alpha1.Gateway, linkPriv, gatewayPub string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      linkSecretName(gw),
			Namespace: gw.Namespace,
			Labels:    commonLabels(gw, componentLink),
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			wg.LinkPrivateKey:    []byte(linkPriv),
			wg.LinkPeerPublicKey: []byte(gatewayPub),
		},
	}
}

// buildLinkConfigMap builds the link's RuntimeConfig ConfigMap. The wg0 address
// reuses the tunnel CIDR suffix; the private key is supplied out-of-band via the
// mounted Secret, so it is absent here. The peer endpoint is set to
// address:wireguardPort when address is non-empty (the operator has observed the
// gateway IP) and left empty otherwise, so the link reloads in place once the
// address appears. Each forward's target port defaults to its public port when
// the Gateway leaves it unset.
//
// forwards is the validated subset the caller chose to expose, not gw.Spec.Forwards
// verbatim: only these become link runtime forwards, so the link's nftables serves
// exactly the resolvable backends. An empty slice yields a ConfigMap with no
// forwards, which makes the link stop serving them in place.
func buildLinkConfigMap(gw *wgnetv1alpha1.Gateway, address string, forwards []wgnetv1alpha1.Forward) (*corev1.ConfigMap, error) {
	wgSubnet := effectiveWGSubnet(gw)
	suffix := wgSubnet
	if i := strings.LastIndex(suffix, "/"); i >= 0 {
		suffix = suffix[i+1:]
	}

	linkForwards := make([]link.Forward, 0, len(forwards))
	for _, f := range forwards {
		proto := strings.ToLower(string(f.Protocol))
		linkForwards = append(linkForwards, link.Forward{
			Name:       fmt.Sprintf("%s-%d", proto, f.Port),
			PublicPort: int(f.Port),
			Protocol:   proto,
			Service:    forwardServiceFQDN(f, gw),
			TargetPort: int(effectiveTargetPort(f)),
		})
	}

	var endpoint string
	if address != "" {
		endpoint = net.JoinHostPort(address, strconv.Itoa(int(effectiveWireguardPort(gw))))
	}

	rc := link.RuntimeConfig{
		WireGuard: link.WireGuard{
			Address:    fmt.Sprintf("%s/%s", effectiveWGLinkAddress(gw), suffix),
			ListenPort: 0,
			MTU:        int(effectiveWGMTU(gw)),
			Peer: link.Peer{
				Endpoint:            endpoint,
				AllowedIPs:          []string{wgSubnet},
				PersistentKeepalive: int(effectiveWGKeepalive(gw)),
			},
		},
		Forwards: linkForwards,
	}

	data, err := json.Marshal(rc)
	if err != nil {
		return nil, fmt.Errorf("encode link runtime config: %w", err)
	}

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      linkComponentName(gw),
			Namespace: gw.Namespace,
			Labels:    commonLabels(gw, componentLink),
		},
		Data: map[string]string{linkConfigKey: string(data)},
	}, nil
}

// buildLinkNetworkPolicy builds the egress allowlist for the link pod. kindnet
// enforces NetworkPolicies, so every destination the link needs must be listed:
// cluster DNS, the WireGuard underlay to the gateway, and each forward's backend
// target port (the link DNATs tunnel traffic to these). The link holds no cluster
// credentials and never reaches the apiserver. The link's own nftables
// default-DROP is the inner containment layer.
//
// forwards is the validated subset the caller chose to expose, not gw.Spec.Forwards
// verbatim: only these get a backend egress rule, matching the forwards the link
// ConfigMap actually serves. An empty slice yields a policy with only the DNS and
// WireGuard egress rules.
func buildLinkNetworkPolicy(gw *wgnetv1alpha1.Gateway, forwards []wgnetv1alpha1.Forward) *networkingv1.NetworkPolicy {
	dnsPort53UDP := corev1.ProtocolUDP
	dnsPort53TCP := corev1.ProtocolTCP
	wgProto := corev1.ProtocolUDP
	port53 := intstr.FromInt32(53)
	wgPort := intstr.FromInt32(effectiveWireguardPort(gw))

	egress := []networkingv1.NetworkPolicyEgressRule{
		{
			To: []networkingv1.NetworkPolicyPeer{{
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"},
				},
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"k8s-app": "kube-dns"},
				},
			}},
			Ports: []networkingv1.NetworkPolicyPort{
				{Protocol: &dnsPort53UDP, Port: &port53},
				{Protocol: &dnsPort53TCP, Port: &port53},
			},
		},
		{
			To: []networkingv1.NetworkPolicyPeer{{
				IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0"},
			}},
			Ports: []networkingv1.NetworkPolicyPort{
				{Protocol: &wgProto, Port: &wgPort},
			},
		},
	}

	// The backend peer is 0.0.0.0/0 rather than the Service CIDR for CNI
	// portability: NetworkPolicy egress is evaluated against the Service ClusterIP
	// on some CNIs and the resolved pod IP on others, so a narrower peer risks
	// breaking the data path. Containment is the link's own nftables default-DROP
	// with DNAT only to the resolved ClusterIP; the link holds NET_ADMIN, so a
	// tighter NP egress would be moot against a link compromise anyway.
	for _, f := range forwards {
		proto := corev1ProtocolOf(f.Protocol)
		targetPort := intstr.FromInt32(effectiveTargetPort(f))
		egress = append(egress, networkingv1.NetworkPolicyEgressRule{
			To: []networkingv1.NetworkPolicyPeer{{
				IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0"},
			}},
			Ports: []networkingv1.NetworkPolicyPort{
				{Protocol: &proto, Port: &targetPort},
			},
		})
	}

	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      linkComponentName(gw),
			Namespace: gw.Namespace,
			Labels:    commonLabels(gw, componentLink),
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: linkSelectorLabels(gw)},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress:      egress,
		},
	}
}

// corev1ProtocolOf maps a Gateway L4 protocol to its corev1 equivalent for use
// in NetworkPolicy ports. The Gateway enum is constrained to TCP and UDP, so an
// unrecognized value falls back to TCP rather than producing an empty protocol
// that the API would reject.
func corev1ProtocolOf(p wgnetv1alpha1.Protocol) corev1.Protocol {
	if p == wgnetv1alpha1.ProtocolUDP {
		return corev1.ProtocolUDP
	}
	return corev1.ProtocolTCP
}

// effectiveForwardNamespace is the namespace a forward's Service lives in: its
// explicit Namespace, or the Gateway's own namespace when left unset.
func effectiveForwardNamespace(f wgnetv1alpha1.Forward, gw *wgnetv1alpha1.Gateway) string {
	if f.Namespace != "" {
		return f.Namespace
	}
	return gw.Namespace
}

// forwardServiceFQDN is the fully-qualified cluster DNS name the link resolves
// for a forward's backend. Building it here, rather than passing the bare Service
// name, makes resolution explicit and identical for same- and cross-namespace
// targets. The link forces this name absolute before lookup, so it does not
// depend on the pod's resolv.conf ndots search path.
func forwardServiceFQDN(f wgnetv1alpha1.Forward, gw *wgnetv1alpha1.Gateway) string {
	return fmt.Sprintf("%s.%s.svc.cluster.local", f.Service, effectiveForwardNamespace(f, gw))
}

// effectiveTargetPort is the backend port a forward DNATs to: its TargetPort, or
// its public Port when TargetPort is unset.
func effectiveTargetPort(f wgnetv1alpha1.Forward) int32 {
	if f.TargetPort == 0 {
		return f.Port
	}
	return f.TargetPort
}

// linkSelectorLabels are the pod-template and selector labels for the link
// Deployment; a stable subset of the common labels.
func linkSelectorLabels(gw *wgnetv1alpha1.Gateway) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":      "wireguard-gateway-operator",
		"app.kubernetes.io/instance":  gw.Name,
		"app.kubernetes.io/component": componentLink,
	}
}

// buildLinkDeployment builds the single-replica link Deployment. It runs as root
// with NET_ADMIN to own wg0 and the nftables ruleset and uses the Recreate
// strategy so two pods never race for the tunnel. The explicit runAsUser:0
// overrides the image's numeric non-root default, so the pod needs no
// runAsNonRoot relaxation; allowPrivilegeEscalation stays false because the
// process starts root and inherits NET_ADMIN directly.
//
// The pod sets net.ipv4.ip_forward via the pod-level securityContext sysctl,
// applied by the kubelet before any container starts: the link DNATs wg0 traffic
// to a backend ClusterIP and re-emits on eth0, which the kernel drops after
// prerouting unless forwarding is on. The container cannot set it itself because
// its /proc/sys is mounted read-only and NET_ADMIN does not lift that. This is an
// unsafe sysctl, so nodes hosting link pods must run their kubelet with
// net.ipv4.ip_forward allowlisted (--allowed-unsafe-sysctls); otherwise the
// kubelet refuses to admit the pod.
//
// The link reloads its config in place on a ConfigMap change, so the Deployment
// carries no config-checksum roll trigger. It holds no cluster credentials:
// AutomountServiceAccountToken is false so no token is projected into the pod.
func buildLinkDeployment(gw *wgnetv1alpha1.Gateway, cfg Config) *appsv1.Deployment {
	var replicas int32 = 1
	var runAsUser int64
	allowPrivilegeEscalation := false
	selector := linkSelectorLabels(gw)

	const (
		// configMountDir is the directory the config ConfigMap is mounted into. It
		// is a whole-volume mount (no subPath) so the kubelet keeps it live via the
		// "..data" symlink swap, which is what lets the link's fsnotify dir-watch
		// observe the operator's endpoint update and reload in place. A subPath mount
		// would be copied once at container start and never refreshed.
		configMountDir  = "/etc/gateway/config"
		configFilePath  = configMountDir + "/" + linkConfigKey
		wgKeysMountPath = "/etc/gateway/wg"
		wgKeyPath       = "/etc/gateway/wg/" + wg.LinkPrivateKey
		wgPeerPubPath   = "/etc/gateway/wg/" + wg.LinkPeerPublicKey
		healthAddr      = ":8080"
	)

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      linkComponentName(gw),
			Namespace: gw.Namespace,
			Labels:    commonLabels(gw, componentLink),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: selector},
			Strategy: appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: selector,
				},
				Spec: corev1.PodSpec{
					AutomountServiceAccountToken: new(false),
					SecurityContext: &corev1.PodSecurityContext{
						Sysctls: []corev1.Sysctl{{Name: "net.ipv4.ip_forward", Value: "1"}},
					},
					Containers: []corev1.Container{{
						Name:            componentLink,
						Image:           cfg.LinkImage,
						ImagePullPolicy: corev1.PullPolicy(cfg.LinkImagePullPolicy),
						Command:         []string{"gateway-link"},
						SecurityContext: &corev1.SecurityContext{
							RunAsUser:                &runAsUser,
							AllowPrivilegeEscalation: &allowPrivilegeEscalation,
							Capabilities:             &corev1.Capabilities{Add: []corev1.Capability{"NET_ADMIN"}},
						},
						Env: []corev1.EnvVar{
							{Name: "GATEWAY_CONFIG_PATH", Value: configFilePath},
							{Name: "GATEWAY_WG_KEY_PATH", Value: wgKeyPath},
							{Name: "GATEWAY_WG_PEER_PUBKEY_PATH", Value: wgPeerPubPath},
							{Name: "GATEWAY_HEALTH_ADDR", Value: healthAddr},
							{Name: "GATEWAY_RECONCILE_INTERVAL", Value: effectiveWGReconcileInterval(gw)},
						},
						Ports: []corev1.ContainerPort{{
							Name:          "health",
							ContainerPort: 8080,
							Protocol:      corev1.ProtocolTCP,
						}},
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path: "/healthz",
									Port: intstr.FromString("health"),
								},
							},
							// The link reports healthy only once a fresh WireGuard
							// handshake exists, which trails the VM boot, so probe
							// readiness only. No liveness probe: a restart while the
							// tunnel is still converging would just reset progress.
							InitialDelaySeconds: 3,
							PeriodSeconds:       5,
							TimeoutSeconds:      2,
						},
						VolumeMounts: []corev1.VolumeMount{
							{Name: "config", MountPath: configMountDir, ReadOnly: true},
							{Name: "wg-keys", MountPath: wgKeysMountPath, ReadOnly: true},
						},
					}},
					Volumes: []corev1.Volume{
						{
							Name: "config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{Name: linkComponentName(gw)},
								},
							},
						},
						{
							Name: "wg-keys",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{SecretName: linkSecretName(gw)},
							},
						},
					},
				},
			},
		},
	}
}

// buildDNSEndpoint builds the external-dns DNSEndpoint mapping each hostname to
// the gateway address as an A record. It returns nil when there are no hostnames
// or the address is not yet known; the caller skips creation in that case.
func buildDNSEndpoint(gw *wgnetv1alpha1.Gateway, address string) *unstructured.Unstructured {
	if len(gw.Spec.DNSHostnames) == 0 || address == "" {
		return nil
	}

	endpoints := make([]any, 0, len(gw.Spec.DNSHostnames))
	for _, host := range gw.Spec.DNSHostnames {
		endpoints = append(endpoints, map[string]any{
			"dnsName":    host,
			"recordType": "A",
			"targets":    []any{address},
		})
	}

	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": dnsEndpointAPIVersion,
		"kind":       dnsEndpointKind,
		"spec":       map[string]any{"endpoints": endpoints},
	}}
	u.SetName(gw.Name)
	u.SetNamespace(gw.Namespace)
	u.SetLabels(commonLabels(gw, "dns"))
	u.SetAnnotations(map[string]string{cloudflareProxiedAnnotation: "false"})
	return u
}

// toUnstructuredMap converts a typed value into the map form an unstructured
// object stores, using the runtime converter so integers become int64 (a plain
// JSON round-trip would yield float64, which NestedInt64 and the API server's
// typed coercion reject).
func toUnstructuredMap(v any) (map[string]any, error) {
	return runtime.DefaultUnstructuredConverter.ToUnstructured(v)
}
