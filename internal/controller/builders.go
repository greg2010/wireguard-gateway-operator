package controller

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"

	gcp "github.com/greg2010/wireguard-gateway-operator/internal/crossplane/gcp"
	"github.com/greg2010/wireguard-gateway-operator/internal/gcpmembers"
	"github.com/greg2010/wireguard-gateway-operator/internal/link"
	"github.com/greg2010/wireguard-gateway-operator/internal/wg"
	wgnetv1alpha1 "github.com/greg2010/wireguard-gateway-operator/pkg/api/v1alpha1"
)

const (
	// gcpIDPrefix supplies the leading letter GCP requires on hash-derived
	// service-account and secret IDs and namespaces them apart from other tenants.
	gcpIDPrefix = "gw-"
	// gcpIDMaxLen is GCP's service-account-ID length cap; secret IDs share the
	// derived value so both fit this bound.
	gcpIDMaxLen = 30

	// linkConfigKey is the data key under which the link Deployment's RuntimeConfig
	// JSON is stored in its ConfigMap and mounted into the container.
	linkConfigKey = "config.json"

	// componentLink labels and names the in-cluster link objects.
	componentLink = "link"

	// xgatewayGCPAPIVersion and xgatewayGCPKind identify the Crossplane composite the
	// operator builds; it is unstructured because the typed view models only spec/status.
	xgatewayGCPAPIVersion = "infra.wgnet.dev/v1alpha1"
	xgatewayGCPKind       = "XGatewayGCP"

	// xgatewayNetworkKind is the singleton composite that provisions the shared VPC. It
	// shares xgatewayGCPAPIVersion: both composites live in the same group/version.
	xgatewayNetworkKind = "XGatewayNetwork"

	// providerLabelKey is the matchLabels key under spec.crossplane.compositionSelector
	// pinning the provider-specific Composition, so two providers can coexist.
	providerLabelKey = "provider"

	// dnsEndpointAPIVersion and dnsEndpointKind identify the published external-dns
	// DNSEndpoint; unstructured because its CRD is an optional install prerequisite.
	dnsEndpointAPIVersion = "externaldns.k8s.io/v1alpha1"
	dnsEndpointKind       = "DNSEndpoint"
	// cloudflareProxiedAnnotation keeps published records DNS-only: gateway
	// traffic is raw WireGuard/TCP and must never sit behind a proxy.
	cloudflareProxiedAnnotation = "external-dns.alpha.kubernetes.io/cloudflare-proxied"

	// linkEndpointSliceClusterRole is the chart-shipped ClusterRole granting EndpointSlice
	// reads; a fixed cluster-scoped name, the resourceName of the operator's bind grant.
	linkEndpointSliceClusterRole = "gateway-link-endpointslice-reader"

	// linkClusterRoleBindingPrefix leads every per-Gateway ClusterRoleBinding name so
	// the objects are identifiable in a cluster-wide listing.
	linkClusterRoleBindingPrefix = "gateway-link-"
	// linkClusterRoleBindingMaxLen caps the hashed ClusterRoleBinding name, leaving 27
	// base32 digest characters, far more than collision resistance needs here.
	linkClusterRoleBindingMaxLen = len(linkClusterRoleBindingPrefix) + 27

	// ownerNamespaceLabel and ownerNameLabel name the owning Gateway on a cluster-scoped
	// child, which cannot carry an ownerReference to a namespaced owner.
	ownerNamespaceLabel = "wgnet.dev/gateway-namespace"
	ownerNameLabel      = "wgnet.dev/gateway-name"

	// clusterHealthPort is the Cluster-mode readiness port; it must match the
	// GATEWAY_HEALTH_ADDR default in internal/link/config.go. Local mode binds loopback.
	clusterHealthPort = 8080

	// bootstrapScriptRevision is bumped whenever files/gcp/keyfetch.sh's contract changes,
	// folding that change into templateRevision's hash.
	bootstrapScriptRevision = "v1"
)

// templateRevision hashes only inputs that affect the instance template.
func templateRevision(gw *wgnetv1alpha1.Gateway, cfg Config, secretID string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00%d\x00%t\x00%t\x00%s\x00%s\x00%d\x00%d\x00%s\x00%s\x00%s\x00%s",
		bootstrapScriptRevision, effectiveGCPImage(gw), gw.Spec.GCP.MachineType,
		effectiveGCPDiskSizeGB(gw), effectiveGCPSpot(gw), cfg.EnableOSLogin, cfg.UserData,
		cfg.SharedNetworkName, effectiveWireguardPort(gw), effectiveWGMTU(gw),
		effectiveWGLinkAddress(gw), strings.ToLower(string(effectiveTrafficPolicy(gw))),
		gw.Spec.GCP.ProjectID, secretID)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// hashedName derives prefix + lowercase base32 of SHA-256 over "<namespace>/<name>",
// truncated to maxLen. The input is namespace-qualified so equal names do not collide.
func hashedName(prefix, namespace, name string, maxLen int) string {
	sum := sha256.Sum256([]byte(namespace + "/" + name))
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])
	id := prefix + strings.ToLower(enc)
	if len(id) > maxLen {
		id = id[:maxLen]
	}
	return id
}

// gcpID derives a project-unique, GCP-valid service-account/secret ID.
func gcpID(namespace, name string) string {
	return hashedName(gcpIDPrefix, namespace, name, gcpIDMaxLen)
}

// bundleSecretName and linkSecretName name the two WireGuard key Secrets a Gateway
// owns, per-Gateway so two Gateways in a namespace do not share key material.
func bundleSecretName(gw *wgnetv1alpha1.Gateway) string { return gw.Name + "-bundle" }
func linkSecretName(gw *wgnetv1alpha1.Gateway) string   { return gw.Name + "-link" }

// linkComponentName names every namespaced link object of a Gateway: the workload,
// ConfigMap, NetworkPolicy, PDB, ServiceAccount, Role, RoleBinding and Lease.
func linkComponentName(gw *wgnetv1alpha1.Gateway) string { return gw.Name + "-link" }

// linkClusterRoleBindingName hashes namespace and name into the cluster-scoped binding
// name; "<namespace>-<name>" is ambiguous when either contains a dash.
func linkClusterRoleBindingName(gw *wgnetv1alpha1.Gateway) string {
	return hashedName(linkClusterRoleBindingPrefix, gw.Namespace, gw.Name, linkClusterRoleBindingMaxLen)
}

// rosterOf is result's roster, empty when no pass has produced one yet.
func rosterOf(result *gcpmembers.Result) []gcpmembers.RosterEntry {
	if result == nil {
		return nil
	}
	return result.Roster
}

// commonLabels are the identifying labels stamped on every child object.
func commonLabels(gw *wgnetv1alpha1.Gateway, component string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       "wireguard-gateway-operator",
		"app.kubernetes.io/instance":   gw.Name,
		"app.kubernetes.io/component":  component,
		"app.kubernetes.io/managed-by": "gateway-operator",
	}
}

// xgatewayMember aliases the generated composite's roster entry, so both branches render the
// roster through one helper.
type xgatewayMember = struct {
	CloudSecretIamMemberName string `json:"cloudSecretIamMemberName"`
	CloudSecretName          string `json:"cloudSecretName"`
	CloudSecretVersionName   string `json:"cloudSecretVersionName"`
	KubernetesSecretName     string `json:"kubernetesSecretName"`
	Name                     string `json:"name"`
	Slot                     int    `json:"slot"`
	TunnelAddress            string `json:"tunnelAddress"`
}

func rosterMembers(roster []gcpmembers.RosterEntry) []xgatewayMember {
	members := make([]xgatewayMember, 0, len(roster))
	for _, e := range roster {
		members = append(members, xgatewayMember{
			CloudSecretIamMemberName: e.CloudSecretIAMMemberName,
			CloudSecretName:          e.CloudSecretName,
			CloudSecretVersionName:   e.CloudSecretVersionName,
			KubernetesSecretName:     e.KubernetesSecretName,
			Name:                     e.Name,
			Slot:                     e.Slot,
			TunnelAddress:            e.TunnelAddress,
		})
	}
	return members
}

// buildXGatewayGCP builds the composite for either gateway provisioning branch.
func buildXGatewayGCP(gw *wgnetv1alpha1.Gateway, cfg Config, forwards []wgnetv1alpha1.Forward, loadBalanced bool, result *gcpmembers.Result, healthPort int) (*unstructured.Unstructured, error) {
	id := gcpID(gw.Namespace, gw.Name)
	secretID, err := gcpmembers.NameBase(string(gw.UID), gw.Spec.GCP.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("derive bundle secret id: %w", err)
	}
	image := effectiveGCPImage(gw)
	diskSizeGB := int(effectiveGCPDiskSizeGB(gw))
	addr := effectiveGCPAddress(gw)
	addrType := string(addr.Type)
	xgAddress := &struct {
		External *struct {
			Ip   *string `json:"ip,omitempty"` //nolint:revive // name fixed by the generated composite schema
			Name *string `json:"name,omitempty"`
		} `json:"external,omitempty"`
		Type *string `json:"type,omitempty"`
	}{Type: &addrType}
	if addr.External != nil {
		extName := addr.External.Name
		extIP := addr.External.IP
		ext := &struct {
			Ip   *string `json:"ip,omitempty"` //nolint:revive // name fixed by the generated composite schema
			Name *string `json:"name,omitempty"`
		}{}
		if extName != "" {
			ext.Name = &extName
		}
		if extIP != "" {
			ext.Ip = &extIP
		}
		xgAddress.External = ext
	}
	spot := effectiveGCPSpot(gw)
	projectID := gw.Spec.GCP.ProjectID
	wgGatewayAddress := effectiveWGGatewayAddress(gw)
	wgLinkAddress := effectiveWGLinkAddress(gw)
	wgSubnet := effectiveWGSubnet(gw)

	spec := gcp.XGatewayGCPSpec{
		Address:            xgAddress,
		Region:             gw.Spec.GCP.Region,
		Zone:               gw.Spec.GCP.Zone,
		MachineType:        gw.Spec.GCP.MachineType,
		SharedNetworkName:  cfg.SharedNetworkName,
		ProviderConfigName: &cfg.ProviderConfigName,
		Image:              &image,
		DiskSizeGB:         &diskSizeGB,
		WgListenPort:       int(effectiveWireguardPort(gw)),
		WgMTU:              int(effectiveWGMTU(gw)),
		WgGatewayAddress:   &wgGatewayAddress,
		WgLinkAddress:      &wgLinkAddress,
		WgSubnet:           &wgSubnet,
		ProjectID:          &projectID,
		TrafficPolicy:      new(strings.ToLower(string(effectiveTrafficPolicy(gw)))),
		Spot:               &spot,
		EnableOsLogin:      new(cfg.EnableOSLogin),
		ServiceAccountId:   &id,
		SecretId:           secretID,
	}

	if cfg.UserData != "" {
		spec.UserData = &cfg.UserData
	}

	if loadBalanced {
		enabled := true
		sessionAffinity := gw.Spec.GCP.LoadBalancer.SessionAffinity
		targetSize := int(gw.Spec.GCP.Replicas)
		if result != nil {
			targetSize = int(result.TargetSize)
		}
		zones := effectiveZones(gw)
		revision := templateRevision(gw, cfg, secretID)
		hp := healthPort

		spec.LoadBalanced = &enabled
		spec.SessionAffinity = &sessionAffinity
		spec.TargetSize = &targetSize
		spec.Zones = &zones
		spec.TemplateRevision = &revision
		spec.HealthPort = &hp

		members := rosterMembers(rosterOf(result))
		spec.Members = &members
	} else if roster := rosterOf(result); len(roster) > 0 {
		members := rosterMembers(roster)
		spec.Members = &members
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

// buildXGatewayNetwork builds the singleton shared-VPC composite in cfg.PodNamespace.
// It carries no ownerReference: its lifecycle is refcount-managed across Gateways.
func buildXGatewayNetwork(cfg Config) *unstructured.Unstructured {
	spec := map[string]any{
		"name":               cfg.SharedNetworkName,
		"providerConfigName": cfg.ProviderConfigName,
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

// gatewayProvider defaults an empty provider to gcp, guarding in-memory Gateways
// that bypassed CRD defaulting.
func gatewayProvider(gw *wgnetv1alpha1.Gateway) wgnetv1alpha1.CloudProvider {
	if gw.Spec.Provider == "" {
		return wgnetv1alpha1.ProviderGCP
	}
	return gw.Spec.Provider
}

// The default consts mirror the CRD defaults; the effective* accessors apply them only
// to in-memory Gateways that bypassed CRD defaulting.
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

	linkDefaultReplicas int32 = 1
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

// effectiveGCPAddress returns the address block, defaulting an unset Type to Reserved
// for in-memory Gateways that bypassed CRD defaulting.
func effectiveGCPAddress(gw *wgnetv1alpha1.Gateway) wgnetv1alpha1.GatewayGCPAddressSpec {
	addr := gw.Spec.GCP.Address
	if addr.Type == "" {
		addr.Type = wgnetv1alpha1.GatewayGCPAddressReserved
	}
	return addr
}

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

// effectiveLinkReplicas returns the link Deployment's replica count, defaulting
// an unset value.
func effectiveLinkReplicas(gw *wgnetv1alpha1.Gateway) int32 {
	if gw.Spec.Link.Replicas == 0 {
		return linkDefaultReplicas
	}
	return gw.Spec.Link.Replicas
}

// effectiveTrafficPolicy defaults an empty data-path mode to Cluster, guarding
// in-memory Gateways that bypassed CRD defaulting.
func effectiveTrafficPolicy(gw *wgnetv1alpha1.Gateway) wgnetv1alpha1.TrafficPolicy {
	if gw.Spec.TrafficPolicy == "" {
		return wgnetv1alpha1.TrafficPolicyCluster
	}
	return gw.Spec.TrafficPolicy
}

func isLocal(gw *wgnetv1alpha1.Gateway) bool {
	return effectiveTrafficPolicy(gw) == wgnetv1alpha1.TrafficPolicyLocal
}

// linkIdentityOf returns the Gateway-level identity derived from the allocated id, nil in
// Cluster mode and before allocation. Local workload builders require a non-nil result.
func linkIdentityOf(gw *wgnetv1alpha1.Gateway) *link.GatewayIdentity {
	if !isLocal(gw) || gw.Status.Link.ID <= 0 {
		return nil
	}
	ident := link.NewGatewayIdentity(int(gw.Status.Link.ID))
	return &ident
}

// effectiveHealthPort returns the local identity port or the cluster default.
func effectiveHealthPort(gw *wgnetv1alpha1.Gateway) int {
	if ident := linkIdentityOf(gw); ident != nil {
		return ident.HealthPort
	}
	return clusterHealthPort
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

// buildBundleSecret builds the Secret read by the XGatewayGCP's SecretVersion; its
// single key holds "<gatewayPriv>\n<linkPub>\n", the payload the VM boot script splits.
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

// fleetLinkPeers renders one link peer per fleet member. Local mode overrides every peer's
// AllowedIPs with the wildcard so cryptokey routing selects a peer for an arbitrary client.
func fleetLinkPeers(gw *wgnetv1alpha1.Gateway, fleetPeers []gcpmembers.Peer) []link.Peer {
	keepalive := int(effectiveWGKeepalive(gw))
	peers := make([]link.Peer, 0, len(fleetPeers))
	for _, p := range fleetPeers {
		var endpoint string
		if p.ExternalAddress != "" {
			endpoint = net.JoinHostPort(p.ExternalAddress, strconv.Itoa(p.ListenPort))
		}
		allowedIPs := []string{p.TunnelAddress + "/32"}
		if isLocal(gw) {
			allowedIPs = []string{"0.0.0.0/0"}
		}
		peers = append(peers, link.Peer{
			Slot:                p.Slot,
			PublicKey:           p.PublicKey,
			Endpoint:            endpoint,
			AllowedIPs:          allowedIPs,
			PersistentKeepalive: keepalive,
		})
	}
	return peers
}

// buildLinkConfigMap renders the link configuration for either gateway branch.
func buildLinkConfigMap(gw *wgnetv1alpha1.Gateway, address string, backends []forwardBackend, ident *link.GatewayIdentity, gatewayPublicKey string, fleetPeers []link.Peer, healthPort int) (*corev1.ConfigMap, error) {
	wgSubnet := effectiveWGSubnet(gw)
	suffix := wgSubnet
	if i := strings.LastIndex(suffix, "/"); i >= 0 {
		suffix = suffix[i+1:]
	}

	local := isLocal(gw)
	linkForwards := make([]link.Forward, 0, len(backends))
	for _, b := range backends {
		f := b.Forward
		proto := strings.ToLower(string(f.Protocol))
		lf := link.Forward{
			Name:       fmt.Sprintf("%s-%d", proto, f.Port),
			PublicPort: int(f.Port),
			Protocol:   proto,
		}
		if local {
			lf.Namespace = effectiveForwardNamespace(f, gw)
			lf.ServiceName = f.Service
			lf.ServicePortName = b.ServicePortName
		} else {
			lf.Service = forwardServiceFQDN(f, gw)
			lf.TargetPort = int(effectiveServicePort(f))
		}
		linkForwards = append(linkForwards, lf)
	}

	keepalive := int(effectiveWGKeepalive(gw))

	// Local mode needs wildcard routes for arbitrary client traffic.
	wildcardAllowedIPs := []string{"0.0.0.0/0"}

	peers := fleetPeers
	if gw.Spec.GCP.LoadBalancer != nil && peers == nil {
		peers = []link.Peer{}
	}
	if gw.Spec.GCP.LoadBalancer == nil {
		var endpoint string
		if address != "" {
			endpoint = net.JoinHostPort(address, strconv.Itoa(int(effectiveWireguardPort(gw))))
		}
		allowedIPs := []string{wgSubnet}
		if local {
			allowedIPs = wildcardAllowedIPs
		}
		peers = []link.Peer{{
			Slot:                0,
			PublicKey:           gatewayPublicKey,
			Endpoint:            endpoint,
			AllowedIPs:          allowedIPs,
			PersistentKeepalive: keepalive,
		}}
	}

	rc := link.RuntimeConfig{
		TrafficPolicy: string(effectiveTrafficPolicy(gw)),
		Identity:      ident,
		HealthPort:    healthPort,
		WireGuard: link.WireGuard{
			Address:    fmt.Sprintf("%s/%s", effectiveWGLinkAddress(gw), suffix),
			ListenPort: 0,
			MTU:        int(effectiveWGMTU(gw)),
			Peers:      peers,
		},
		Forwards: linkForwards,
	}
	if local {
		rc.PodSelector = linkSelectorLabels(gw)
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

// buildLinkNetworkPolicy allows egress to cluster DNS, the apiserver, the WireGuard
// underlay and each forward's backend ports; nftables default-DROP contains the rest.
func buildLinkNetworkPolicy(gw *wgnetv1alpha1.Gateway, backends []forwardBackend) *networkingv1.NetworkPolicy {
	dnsPort53UDP := corev1.ProtocolUDP
	dnsPort53TCP := corev1.ProtocolTCP
	wgProto := corev1.ProtocolUDP
	apiserverProto := corev1.ProtocolTCP
	port53 := intstr.FromInt32(53)
	port443 := intstr.FromInt32(443)
	port6443 := intstr.FromInt32(6443)
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
		// The apiserver's in-cluster addressing varies by environment, so the rule is
		// peer-less: 443 covers the Service, 6443 the direct apiserver port.
		{
			Ports: []networkingv1.NetworkPolicyPort{
				{Protocol: &apiserverProto, Port: &port443},
				{Protocol: &apiserverProto, Port: &port6443},
			},
		},
	}

	// The peer is 0.0.0.0/0 and both ports are allowed because a CNI may evaluate egress
	// against the ClusterIP and Service port or against the pod IP and DNAT'd port.
	for _, b := range backends {
		egress = append(egress, networkingv1.NetworkPolicyEgressRule{
			To: []networkingv1.NetworkPolicyPeer{{
				IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0"},
			}},
			Ports: backendEgressPorts(b),
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

// backendEgressPorts allows the Service port and the pod-side port it is remapped to. A named
// backend port cannot be enumerated, so the rule goes port-less and classifyForwards warns.
func backendEgressPorts(b forwardBackend) []networkingv1.NetworkPolicyPort {
	proto := corev1ProtocolOf(b.Forward.Protocol)
	if b.BackendPort == 0 {
		return []networkingv1.NetworkPolicyPort{{Protocol: &proto}}
	}
	svcPort := effectiveServicePort(b.Forward)
	ports := []networkingv1.NetworkPolicyPort{{Protocol: &proto, Port: new(intstr.FromInt32(svcPort))}}
	if b.BackendPort != svcPort {
		ports = append(ports, networkingv1.NetworkPolicyPort{Protocol: &proto, Port: new(intstr.FromInt32(b.BackendPort))})
	}
	return ports
}

// corev1ProtocolOf maps a Gateway L4 protocol to its corev1 equivalent, falling back to
// TCP rather than the empty protocol the API would reject.
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

// forwardServiceFQDN is the fully-qualified cluster DNS name of a forward's backend,
// built here so resolution does not depend on the pod's resolv.conf ndots.
func forwardServiceFQDN(f wgnetv1alpha1.Forward, gw *wgnetv1alpha1.Gateway) string {
	return fmt.Sprintf("%s.%s.svc.cluster.local", f.Service, effectiveForwardNamespace(f, gw))
}

// effectiveServicePort is the forward's TargetPort, or its public Port when unset. It is
// the Service's published port, not the pod-side port the Service may remap it to.
func effectiveServicePort(f wgnetv1alpha1.Forward) int32 {
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

// linkPodSpec builds the pod spec both link workloads share. A nil ident selects Cluster
// mode (own netns, init container enables ip_forward); non-nil selects host-netns Local.
func linkPodSpec(gw *wgnetv1alpha1.Gateway, cfg Config, ident *link.GatewayIdentity) corev1.PodSpec {
	var runAsUser int64
	allowPrivilegeEscalation := false
	terminationGracePeriod := int64(30)

	const (
		// Whole-volume mount (no subPath) so the kubelet's "..data" symlink swap keeps it
		// live and the link's fsnotify watch reloads; a subPath mount never refreshes.
		configMountDir       = "/etc/gateway/config"
		configFilePath       = configMountDir + "/" + linkConfigKey
		wgKeysMountPath      = "/etc/gateway/wg"
		wgKeyPath            = "/etc/gateway/wg/" + wg.LinkPrivateKey
		wgPeerPubPath        = "/etc/gateway/wg/" + wg.LinkPeerPublicKey
		hostProcSysNetVolume = "host-proc-sys-net"
	)

	healthAddr := ":" + strconv.Itoa(clusterHealthPort)
	if ident != nil {
		// Wildcard, not loopback: a load-balanced Local Gateway's health check can arrive
		// over the tunnel interface, not just from the local node.
		healthAddr = ":" + strconv.Itoa(ident.HealthPort)
	}

	env := []corev1.EnvVar{
		{Name: "GATEWAY_CONFIG_PATH", Value: configFilePath},
		{Name: "GATEWAY_WG_KEY_PATH", Value: wgKeyPath},
		{Name: "GATEWAY_WG_PEER_PUBKEY_PATH", Value: wgPeerPubPath},
		{Name: "GATEWAY_HEALTH_ADDR", Value: healthAddr},
		{Name: "GATEWAY_RECONCILE_INTERVAL", Value: effectiveWGReconcileInterval(gw)},
		{
			Name: "POD_NAMESPACE",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
			},
		},
		{
			Name: "POD_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"},
			},
		},
		{Name: "GATEWAY_LEASE_NAME", Value: linkComponentName(gw)},
	}

	mounts := []corev1.VolumeMount{
		{Name: "config", MountPath: configMountDir, ReadOnly: true},
		{Name: "wg-keys", MountPath: wgKeysMountPath, ReadOnly: true},
	}
	volumes := []corev1.Volume{
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
	}

	var (
		hostNetwork    bool
		dnsPolicy      corev1.DNSPolicy
		initContainers []corev1.Container
		affinity       *corev1.Affinity
		ports          []corev1.ContainerPort
		probeHandler   corev1.HTTPGetAction
	)

	if ident != nil {
		hostNetwork = true
		dnsPolicy = corev1.DNSClusterFirstWithHostNet
		probeHandler = corev1.HTTPGetAction{
			Path: "/healthz",
			Host: "127.0.0.1",
			Port: intstr.FromInt32(int32(ident.HealthPort)),
		}
		env = append(env, corev1.EnvVar{
			Name: "NODE_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
			},
		})
		hostPathDir := corev1.HostPathDirectory
		volumes = append(volumes, corev1.Volume{
			Name: hostProcSysNetVolume,
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{Path: "/proc/sys/net", Type: &hostPathDir},
			},
		})
		mounts = append(mounts, corev1.VolumeMount{
			Name:      hostProcSysNetVolume,
			MountPath: link.HostProcSysNetPath,
			ReadOnly:  false,
		})
	} else {
		privileged := true
		initContainers = []corev1.Container{{
			Name:            "enable-ip-forward",
			Image:           cfg.LinkImage,
			ImagePullPolicy: corev1.PullPolicy(cfg.LinkImagePullPolicy),
			Command:         []string{"sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"},
			SecurityContext: &corev1.SecurityContext{
				RunAsUser:  &runAsUser,
				Privileged: &privileged,
			},
		}}
		affinity = &corev1.Affinity{
			PodAntiAffinity: &corev1.PodAntiAffinity{
				PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{{
					Weight: 100,
					PodAffinityTerm: corev1.PodAffinityTerm{
						TopologyKey:   "kubernetes.io/hostname",
						LabelSelector: &metav1.LabelSelector{MatchLabels: linkSelectorLabels(gw)},
					},
				}},
			},
		}
		ports = []corev1.ContainerPort{{
			Name:          "health",
			ContainerPort: clusterHealthPort,
			Protocol:      corev1.ProtocolTCP,
		}}
		probeHandler = corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromString("health")}
	}

	return corev1.PodSpec{
		ServiceAccountName:            linkComponentName(gw),
		AutomountServiceAccountToken:  new(true),
		TerminationGracePeriodSeconds: &terminationGracePeriod,
		NodeSelector:                  gw.Spec.Link.NodeSelector,
		HostNetwork:                   hostNetwork,
		DNSPolicy:                     dnsPolicy,
		Affinity:                      affinity,
		InitContainers:                initContainers,
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
			Env:   env,
			Ports: ports,
			ReadinessProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{HTTPGet: &probeHandler},
				// Readiness only: the link reports healthy once a fresh handshake
				// exists, and a liveness restart mid-converge would just reset progress.
				InitialDelaySeconds: 3,
				PeriodSeconds:       5,
				TimeoutSeconds:      2,
			},
			VolumeMounts: mounts,
		}},
		Volumes: volumes,
	}
}

// buildLinkDeployment builds the Cluster-mode link Deployment, leader-elected
// active-passive. maxUnavailable=0 with maxSurge=1 keeps a programmed pod through a roll.
func buildLinkDeployment(gw *wgnetv1alpha1.Gateway, cfg Config) *appsv1.Deployment {
	replicas := effectiveLinkReplicas(gw)
	selector := linkSelectorLabels(gw)
	maxSurge := intstr.FromInt32(1)
	maxUnavailable := intstr.FromInt32(0)

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      linkComponentName(gw),
			Namespace: gw.Namespace,
			Labels:    commonLabels(gw, componentLink),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: selector},
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxSurge:       &maxSurge,
					MaxUnavailable: &maxUnavailable,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: selector},
				Spec:       linkPodSpec(gw, cfg, nil),
			},
		},
	}
}

// buildLinkDaemonSet builds the Local-mode link DaemonSet, one host-network pod per node.
// ident must be non-nil: every name, mark, route table and health port derives from it.
func buildLinkDaemonSet(gw *wgnetv1alpha1.Gateway, cfg Config, ident *link.GatewayIdentity) *appsv1.DaemonSet {
	selector := linkSelectorLabels(gw)

	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      linkComponentName(gw),
			Namespace: gw.Namespace,
			Labels:    commonLabels(gw, componentLink),
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: selector},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: selector},
				Spec:       linkPodSpec(gw, cfg, ident),
			},
		},
	}
}

// buildLinkServiceAccount builds the ServiceAccount the link pods run under; its token
// is the only cluster credential they mount.
func buildLinkServiceAccount(gw *wgnetv1alpha1.Gateway) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      linkComponentName(gw),
			Namespace: gw.Namespace,
			Labels:    commonLabels(gw, componentLink),
		},
	}
}

// buildLinkRole grants the Lease verbs leader election needs, plus in Local mode the
// pod reads the election's liveness input needs.
func buildLinkRole(gw *wgnetv1alpha1.Gateway) *rbacv1.Role {
	rules := []rbacv1.PolicyRule{{
		APIGroups: []string{"coordination.k8s.io"},
		Resources: []string{"leases"},
		Verbs:     []string{"get", "list", "watch", "create", "update"},
	}}
	if isLocal(gw) {
		// Only a Local link watches pods: it reads this Gateway's link pods to learn
		// which nodes carry a ready peer, the election's liveness input.
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get", "list", "watch"},
		})
	}
	return &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      linkComponentName(gw),
			Namespace: gw.Namespace,
			Labels:    commonLabels(gw, componentLink),
		},
		Rules: rules,
	}
}

// buildLinkRoleBinding binds the link Role to the link ServiceAccount, granting
// the link pods the Lease verbs in the Gateway's namespace.
func buildLinkRoleBinding(gw *wgnetv1alpha1.Gateway) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      linkComponentName(gw),
			Namespace: gw.Namespace,
			Labels:    commonLabels(gw, componentLink),
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     linkComponentName(gw),
		},
		Subjects: []rbacv1.Subject{{
			Kind:      rbacv1.ServiceAccountKind,
			Name:      linkComponentName(gw),
			Namespace: gw.Namespace,
		}},
	}
}

// buildLinkClusterRoleBinding lets a Local Gateway's link resolve backend pods. Being
// cluster-scoped it has no ownerReference, so the delete path reaps it explicitly.
func buildLinkClusterRoleBinding(gw *wgnetv1alpha1.Gateway) *rbacv1.ClusterRoleBinding {
	labels := commonLabels(gw, componentLink)
	labels[ownerNamespaceLabel] = gw.Namespace
	labels[ownerNameLabel] = gw.Name

	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   linkClusterRoleBindingName(gw),
			Labels: labels,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     linkEndpointSliceClusterRole,
		},
		Subjects: []rbacv1.Subject{{
			Kind:      rbacv1.ServiceAccountKind,
			Name:      linkComponentName(gw),
			Namespace: gw.Namespace,
		}},
	}
}

// buildLinkPodDisruptionBudget keeps one pod available through a voluntary disruption,
// so a drain cannot take the active and the standby at once. Meaningful only at replicas>1.
func buildLinkPodDisruptionBudget(gw *wgnetv1alpha1.Gateway) *policyv1.PodDisruptionBudget {
	minAvailable := intstr.FromInt32(1)
	// AlwaysAllow evicts an unhealthy pod even at the budget limit, so an unready
	// replica cannot block a node drain.
	unhealthyPolicy := policyv1.AlwaysAllow
	return &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      linkComponentName(gw),
			Namespace: gw.Namespace,
			Labels:    commonLabels(gw, componentLink),
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MinAvailable:               &minAvailable,
			Selector:                   &metav1.LabelSelector{MatchLabels: linkSelectorLabels(gw)},
			UnhealthyPodEvictionPolicy: &unhealthyPolicy,
		},
	}
}

// buildDNSEndpoint maps each hostname to the gateway address as an A record, returning
// nil when there are no hostnames or the address is not yet known.
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

// toUnstructuredMap converts via the runtime converter, so integers become int64 rather
// than the float64 a JSON round-trip yields (which NestedInt64 and the API server reject).
func toUnstructuredMap(v any) (map[string]any, error) {
	return runtime.DefaultUnstructuredConverter.ToUnstructured(v)
}
