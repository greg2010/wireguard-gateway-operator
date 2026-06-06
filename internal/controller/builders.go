package controller

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"

	wgnetv1alpha1 "github.com/greg2010/wireguard-gateway-operator/api/v1alpha1"
	"github.com/greg2010/wireguard-gateway-operator/internal/wg"
	gcp "github.com/greg2010/wireguard-gateway-operator/pkg/crossplane/gcp"
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

	// xgatewayAPIVersion and xgatewayKind identify the Crossplane composite the
	// operator builds; it is handled unstructured because the typed view models
	// only the spec/status, not the full Kubernetes object.
	xgatewayAPIVersion = "infra.wgnet.dev/v1alpha1"
	xgatewayKind       = "XGateway"

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

// linkComponentName names the link Deployment, ConfigMap, ServiceAccount, Role,
// RoleBinding, and NetworkPolicy for a Gateway.
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

// buildXGateway builds the Crossplane composite that provisions the gateway VM.
// It maps the Gateway's region/zone/machineType/forwards/dnsHostnames, folds in
// the operator-global GCP and WireGuard fields from cfg, points wgKeySecretRef at
// the bundle Secret, derives the per-Gateway serviceAccountId/secretId, and sets
// the static Ignition userData. The typed spec is marshalled into the
// unstructured object so the composite carries the exact field shape the XRD and
// composition consume. serviceAccountEmail is intentionally absent: it is
// GCP-observed and surfaced through the composite status.
func buildXGateway(gw *wgnetv1alpha1.Gateway, cfg Config) (*unstructured.Unstructured, error) {
	id := gcpID(gw.Namespace, gw.Name)

	spec := gcp.XGatewaySpec{
		Region:           gw.Spec.GCP.Region,
		Zone:             gw.Spec.GCP.Zone,
		MachineType:      gw.Spec.GCP.MachineType,
		SubnetCIDR:       cfg.GCPSubnetCIDR,
		WgListenPort:     cfg.WGListenPort,
		ReservedIP:       &cfg.GCPReservedIP,
		Spot:             &cfg.GCPSpot,
		ServiceAccountId: &id,
		SecretId:         &id,
		WgKeySecretRef: &struct {
			Key  string `json:"key"`
			Name string `json:"name"`
		}{Key: wg.BundleKey, Name: bundleSecretName(gw)},
	}

	if cfg.GCPImage != "" {
		spec.Image = &cfg.GCPImage
	}
	if cfg.GCPDiskSizeGB != 0 {
		spec.DiskSizeGB = &cfg.GCPDiskSizeGB
	}
	if cfg.UserData != "" {
		spec.UserData = &cfg.UserData
	}
	if len(gw.Spec.DNSHostnames) > 0 {
		hostnames := append([]string(nil), gw.Spec.DNSHostnames...)
		spec.DnsHostnames = &hostnames
	}
	if len(gw.Spec.Forwards) > 0 {
		ports := make([]struct {
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
		}, 0, len(gw.Spec.Forwards))
		for _, f := range gw.Spec.Forwards {
			ports = append(ports, struct {
				Port     int    `json:"port"`
				Protocol string `json:"protocol"`
			}{Port: int(f.Port), Protocol: strings.ToLower(string(f.Protocol))})
		}
		spec.AllowedPorts = &ports
	}

	specMap, err := toUnstructuredMap(&spec)
	if err != nil {
		return nil, fmt.Errorf("encode xgateway spec: %w", err)
	}

	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": xgatewayAPIVersion,
		"kind":       xgatewayKind,
		"spec":       specMap,
	}}
	u.SetName(gw.Name)
	u.SetNamespace(gw.Namespace)
	u.SetLabels(commonLabels(gw, "gateway"))
	return u, nil
}

// XGatewayGVK is the composite's GroupVersionKind, exported so the manager can
// register an unstructured Owns watch on it.
var XGatewayGVK = schema.GroupVersionKind{Group: "infra.wgnet.dev", Version: "v1alpha1", Kind: "XGateway"}

// newXGateway returns an empty unstructured XGateway with its GVK set, for Get,
// CreateOrUpdate, and the Owns watch.
func newXGateway() *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(XGatewayGVK)
	return u
}

// buildBundleSecret builds the gateway-bundle Secret read by the XGateway's
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

// linkRuntimeConfig is the on-disk JSON the link reads. It mirrors
// link.RuntimeConfig structurally; it is defined locally to avoid importing the
// link daemon package into the operator.
type linkRuntimeConfig struct {
	WireGuard linkWireGuard `json:"wireguard"`
	Forwards  []linkForward `json:"forwards"`
}

// linkForward mirrors link.Forward. The JSON keys must match that contract
// exactly so LoadRuntimeConfig accepts the marshalled output.
type linkForward struct {
	Name       string `json:"name"`
	PublicPort int    `json:"publicPort"`
	Protocol   string `json:"protocol"`
	Service    string `json:"service"`
	TargetPort int    `json:"targetPort"`
}

type linkWireGuard struct {
	Address    string   `json:"address"`
	ListenPort int      `json:"listenPort"`
	MTU        int      `json:"mtu"`
	Peer       linkPeer `json:"peer"`
}

type linkPeer struct {
	AllowedIPs          []string `json:"allowedIPs"`
	PersistentKeepalive int      `json:"persistentKeepalive"`
}

// buildLinkConfigMap builds the link's RuntimeConfig ConfigMap. The wg0 address
// reuses the tunnel CIDR suffix; the peer endpoint and private key are supplied
// to the link out-of-band (status address and mounted Secret), so they are
// absent here. Each forward's target port defaults to its public port when the
// Gateway leaves it unset.
func buildLinkConfigMap(gw *wgnetv1alpha1.Gateway, cfg Config) (*corev1.ConfigMap, error) {
	suffix := cfg.WGSubnet
	if i := strings.LastIndex(suffix, "/"); i >= 0 {
		suffix = suffix[i+1:]
	}

	forwards := make([]linkForward, 0, len(gw.Spec.Forwards))
	for _, f := range gw.Spec.Forwards {
		proto := strings.ToLower(string(f.Protocol))
		forwards = append(forwards, linkForward{
			Name:       fmt.Sprintf("%s-%d", proto, f.Port),
			PublicPort: int(f.Port),
			Protocol:   proto,
			Service:    f.Service,
			TargetPort: int(effectiveTargetPort(f)),
		})
	}

	rc := linkRuntimeConfig{
		WireGuard: linkWireGuard{
			Address:    fmt.Sprintf("%s/%s", cfg.WGLinkAddress, suffix),
			ListenPort: 0,
			MTU:        cfg.WGMTU,
			Peer: linkPeer{
				AllowedIPs:          []string{cfg.WGSubnet},
				PersistentKeepalive: cfg.WGKeepalive,
			},
		},
		Forwards: forwards,
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

// buildLinkServiceAccount builds the ServiceAccount the link pod runs as.
func buildLinkServiceAccount(gw *wgnetv1alpha1.Gateway) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      linkComponentName(gw),
			Namespace: gw.Namespace,
			Labels:    commonLabels(gw, componentLink),
		},
	}
}

// buildLinkRole builds the namespaced Role granting the link read access to the
// XGateway composite whose status.address it polls for the gateway endpoint.
func buildLinkRole(gw *wgnetv1alpha1.Gateway) *rbacv1.Role {
	return &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      linkComponentName(gw),
			Namespace: gw.Namespace,
			Labels:    commonLabels(gw, componentLink),
		},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"infra.wgnet.dev"},
			Resources: []string{"xgateways"},
			Verbs:     []string{"get", "list", "watch"},
		}},
	}
}

// buildLinkRoleBinding binds the link Role to the link ServiceAccount.
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
			Kind:      "ServiceAccount",
			Name:      linkComponentName(gw),
			Namespace: gw.Namespace,
		}},
	}
}

// buildLinkNetworkPolicy builds the egress allowlist for the link pod. kindnet
// enforces NetworkPolicies, so every destination the link needs must be listed:
// cluster DNS, the WireGuard underlay to the gateway, each forward's backend
// target port (the link DNATs tunnel traffic to these), and the apiserver on 443
// (the link polls the XGateway status for the gateway endpoint). The link's own
// nftables default-DROP is the inner containment layer.
func buildLinkNetworkPolicy(gw *wgnetv1alpha1.Gateway, cfg Config) *networkingv1.NetworkPolicy {
	dnsPort53UDP := corev1.ProtocolUDP
	dnsPort53TCP := corev1.ProtocolTCP
	wgProto := corev1.ProtocolUDP
	apiProto := corev1.ProtocolTCP
	port53 := intstr.FromInt32(53)
	wgPort := intstr.FromInt32(int32(cfg.WGListenPort))
	apiPort := intstr.FromInt32(443)

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
		{
			To: []networkingv1.NetworkPolicyPeer{{
				IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0"},
			}},
			Ports: []networkingv1.NetworkPolicyPort{
				{Protocol: &apiProto, Port: &apiPort},
			},
		},
	}

	for _, f := range gw.Spec.Forwards {
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
// with NET_ADMIN to own wg0 and the nftables ruleset, uses the Recreate strategy
// so two pods never race for the tunnel, and learns the gateway endpoint from the
// XGateway named by the GATEWAY_NAME/GATEWAY_NAMESPACE env. The explicit
// runAsUser:0 overrides the image's numeric non-root default, so the pod needs no
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
func buildLinkDeployment(gw *wgnetv1alpha1.Gateway, cfg Config) *appsv1.Deployment {
	var replicas int32 = 1
	var runAsUser int64
	allowPrivilegeEscalation := false
	selector := linkSelectorLabels(gw)

	const (
		configMountPath = "/etc/cyno/config.json"
		wgKeysMountPath = "/etc/cyno/wg"
		wgKeyPath       = "/etc/cyno/wg/" + wg.LinkPrivateKey
		wgPeerPubPath   = "/etc/cyno/wg/" + wg.LinkPeerPublicKey
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
				ObjectMeta: metav1.ObjectMeta{Labels: selector},
				Spec: corev1.PodSpec{
					ServiceAccountName: linkComponentName(gw),
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
							{Name: "GATEWAY_CONFIG_PATH", Value: configMountPath},
							{Name: "GATEWAY_WG_KEY_PATH", Value: wgKeyPath},
							{Name: "GATEWAY_WG_PEER_PUBKEY_PATH", Value: wgPeerPubPath},
							{Name: "GATEWAY_HEALTH_ADDR", Value: healthAddr},
							{Name: "GATEWAY_NAME", Value: gw.Name},
							{Name: "GATEWAY_NAMESPACE", Value: gw.Namespace},
							{Name: "GATEWAY_WG_LISTEN_PORT", Value: fmt.Sprintf("%d", cfg.WGListenPort)},
							{Name: "GATEWAY_RECONCILE_INTERVAL", Value: cfg.WGReconcileInterval.String()},
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
							{Name: "config", MountPath: configMountPath, SubPath: linkConfigKey, ReadOnly: true},
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
