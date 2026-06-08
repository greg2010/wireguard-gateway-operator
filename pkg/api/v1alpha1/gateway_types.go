package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Protocol is an L4 transport protocol for a forwarded port.
type Protocol string

const (
	ProtocolTCP Protocol = "TCP"
	ProtocolUDP Protocol = "UDP"
)

// CloudProvider selects the cloud the gateway VM is provisioned on.
type CloudProvider string

// ProviderGCP is the only provider supported today.
const ProviderGCP CloudProvider = "gcp"

// +kubebuilder:validation:XValidation:rule="!has(self.forwards) || self.forwards.all(f1, self.forwards.exists_one(f2, f2.port == f1.port && f2.protocol == f1.protocol))",message="each forward must use a unique port and protocol combination"
// +kubebuilder:validation:XValidation:rule="!has(self.forwards) || self.forwards.all(f, !(f.protocol == 'UDP' && f.port == self.wireguard.listenPort))",message="a UDP forward must not use the WireGuard listen port (spec.wireguard.listenPort)"
type GatewaySpec struct {
	GCP GatewayGCPSpec `json:"gcp"`

	// Wireguard carries the provider-agnostic WireGuard tunnel parameters. Every
	// value defaults via the CRD, so the block may be omitted to get the standard
	// tunnel.
	// +optional
	// +kubebuilder:default={}
	Wireguard GatewayWireguardSpec `json:"wireguard,omitempty"`

	// Link configures the in-cluster link Deployment. Every value defaults via the
	// CRD, so the block may be omitted to get a single-replica link.
	// +optional
	// +kubebuilder:default={}
	Link GatewayLinkSpec `json:"link,omitempty"`

	// Provider selects the provider-specific Crossplane Composition that
	// provisions the gateway VM, matched by the composite's compositionSelector.
	// Only gcp is supported today.
	// +kubebuilder:validation:Enum=gcp
	// +kubebuilder:default=gcp
	Provider CloudProvider `json:"provider,omitempty"`

	// Forwards are the public ports DNAT'd through the gateway to in-cluster pods.
	// +kubebuilder:validation:MaxItems=64
	Forwards []Forward `json:"forwards,omitempty"`

	// DNSHostnames are FQDNs the operator publishes via a DNSEndpoint.
	DNSHostnames []string `json:"dnsHostnames,omitempty"`
}

type GatewayGCPSpec struct {
	// ProjectID is the GCP project that owns the gateway VM and its Secret Manager
	// secret. The boot keyfetch reads it from instance metadata to resolve the
	// secret URL.
	// +kubebuilder:validation:MinLength=1
	ProjectID string `json:"projectID"`

	// +kubebuilder:validation:MinLength=1
	Region string `json:"region"`

	// +kubebuilder:validation:MinLength=1
	Zone string `json:"zone"`

	// +kubebuilder:default="e2-small"
	MachineType string `json:"machineType,omitempty"`

	// Image is the gateway VM boot image. The gateway boots Flatcar because its
	// userData is Flatcar Ignition; this defaults to the GCP Flatcar stable family.
	// +kubebuilder:default="projects/kinvolk-public/global/images/family/flatcar-stable"
	Image string `json:"image,omitempty"`

	// DiskSizeGB is the gateway VM boot disk size in GB.
	// +kubebuilder:default=20
	// +kubebuilder:validation:Minimum=1
	DiskSizeGB int32 `json:"diskSizeGB,omitempty"`

	// ReservedIP allocates a static external IP so the address survives an
	// instance replace.
	// +kubebuilder:default=true
	ReservedIP *bool `json:"reservedIP,omitempty"`

	// Spot runs the gateway VM as a preemptible spot instance.
	// +kubebuilder:default=false
	Spot bool `json:"spot,omitempty"`
}

// GatewayWireguardSpec is the WireGuard tunnel configuration shared by the
// gateway VM and the in-cluster link. It is provider-agnostic.
type GatewayWireguardSpec struct {
	// ListenPort is the gateway VM's WireGuard UDP listen port.
	// +kubebuilder:default=51820
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	ListenPort int32 `json:"listenPort,omitempty"`

	// Subnet is the tunnel CIDR; its suffix sizes both interface addresses and it
	// is the peer's sole allowed IP range.
	// +kubebuilder:default="10.99.0.0/29"
	// +kubebuilder:validation:Pattern=`^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])/(3[0-2]|[12]?[0-9])$`
	Subnet string `json:"subnet,omitempty"`

	// GatewayAddress is the gateway VM's wg0 address (without CIDR suffix).
	// +kubebuilder:default="10.99.0.1"
	// +kubebuilder:validation:Pattern=`^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$`
	GatewayAddress string `json:"gatewayAddress,omitempty"`

	// LinkAddress is the link end's wg0 address (without CIDR suffix).
	// +kubebuilder:default="10.99.0.2"
	// +kubebuilder:validation:Pattern=`^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$`
	LinkAddress string `json:"linkAddress,omitempty"`

	// Keepalive is the link's persistent-keepalive interval in seconds.
	// +kubebuilder:default=25
	Keepalive int32 `json:"keepalive,omitempty"`

	// MTU is the link's wg0 MTU.
	// +kubebuilder:default=1380
	MTU int32 `json:"mtu,omitempty"`

	// ReconcileInterval is how often the link re-reads the XGatewayGCP address.
	// +kubebuilder:default="10s"
	ReconcileInterval string `json:"reconcileInterval,omitempty"`
}

// GatewayLinkSpec configures the in-cluster link Deployment.
type GatewayLinkSpec struct {
	// Replicas is the number of link pods. Values >1 enable hot-standby
	// failover and safe rolling updates via leader election.
	// +optional
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1
	Replicas int32 `json:"replicas,omitempty"`
}

type Forward struct {
	// Port is the public port opened on the gateway VM and DNAT'd through the
	// tunnel.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`

	// +kubebuilder:validation:Enum=TCP;UDP
	Protocol Protocol `json:"protocol"`

	// Service is the bare in-cluster Service name, constrained to a single
	// DNS-1035 label so a dotted FQDN cannot bypass the Namespace gate.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=^[a-z]([-a-z0-9]*[a-z0-9])?$
	Service string `json:"service"`

	// Namespace of the target Service. Defaults to the Gateway's namespace.
	// Cross-namespace forwards require the target namespace to carry the opt-in
	// label.
	// +kubebuilder:validation:Pattern=^[a-z0-9]([-a-z0-9]*[a-z0-9])?$
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// TargetPort is the port on Service; it defaults to Port when unset.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +optional
	TargetPort int32 `json:"targetPort,omitempty"`
}

type GatewayStatus struct {
	// Address is the gateway VM's public ingress IP, mirrored from the XGatewayGCP.
	Address string `json:"address,omitempty"`

	ServiceAccountEmail string `json:"serviceAccountEmail,omitempty"`

	// +listType=map
	// +listMapKey=type
	// +patchStrategy=merge
	// +patchMergeKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=gw
// +kubebuilder:printcolumn:name="Address",type=string,JSONPath=`.status.address`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`

type Gateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GatewaySpec   `json:"spec,omitempty"`
	Status GatewayStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

type GatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Gateway `json:"items"`
}
