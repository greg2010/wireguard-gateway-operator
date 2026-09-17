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

// TrafficPolicy selects a Gateway's data-path mode.
type TrafficPolicy string

const (
	TrafficPolicyCluster TrafficPolicy = "Cluster"
	TrafficPolicyLocal   TrafficPolicy = "Local"
)

// +kubebuilder:validation:XValidation:rule="!has(self.forwards) || self.forwards.all(f1, self.forwards.exists_one(f2, f2.port == f1.port && f2.protocol == f1.protocol))",message="each forward must use a unique port and protocol combination"
// +kubebuilder:validation:XValidation:rule="!has(self.forwards) || self.forwards.all(f, !(f.protocol == 'UDP' && f.port == self.wireguard.listenPort))",message="a UDP forward must not use the WireGuard listen port (spec.wireguard.listenPort)"
// +kubebuilder:validation:XValidation:rule="self.trafficPolicy != 'Local' || self.link.replicas == 1",message="spec.link.replicas applies only to trafficPolicy Cluster; Local runs a DaemonSet on every eligible node"
// +kubebuilder:validation:XValidation:rule="!has(self.gcp.loadBalancer) || (self.wireguard.subnet == oldSelf.wireguard.subnet && self.wireguard.gatewayAddress == oldSelf.wireguard.gatewayAddress && self.wireguard.linkAddress == oldSelf.wireguard.linkAddress)",message="spec.wireguard.subnet, gatewayAddress and linkAddress are immutable on a load-balanced Gateway"
// +kubebuilder:validation:XValidation:rule="self.trafficPolicy == 'Local' || !has(self.forwards) || self.forwards.all(f, !(f.protocol == 'TCP' && f.port == 8080))",message="a TCP forward on port 8080 is rejected under trafficPolicy Cluster: it is the link's health port"
type GatewaySpec struct {
	GCP GatewayGCPSpec `json:"gcp"`

	// Wireguard carries the WireGuard tunnel parameters. Every value has a default, so
	// the block may be omitted.
	// +optional
	// +kubebuilder:default={}
	Wireguard GatewayWireguardSpec `json:"wireguard"`

	// Link configures the in-cluster link workload: a Deployment in Cluster mode, a
	// DaemonSet in Local mode. Every value has a default, so the block may be omitted.
	// +optional
	// +kubebuilder:default={}
	Link GatewayLinkSpec `json:"link"`

	// Provider selects the Composition that provisions the gateway VM. The only
	// supported value is gcp.
	// +kubebuilder:validation:Enum=gcp
	// +kubebuilder:default=gcp
	Provider CloudProvider `json:"provider,omitempty"`

	// Cluster masquerades tunnel egress at the VM and DNATs to a Service ClusterIP; Local keeps the
	// client source address and DNATs to a ready pod on the link Lease holder's node. Immutable.
	// +optional
	// +kubebuilder:validation:Enum=Cluster;Local
	// +kubebuilder:default=Cluster
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="spec.trafficPolicy is immutable"
	TrafficPolicy TrafficPolicy `json:"trafficPolicy,omitempty"`

	// Forwards are the public ports DNAT'd through the gateway to in-cluster pods.
	// +kubebuilder:validation:MaxItems=64
	Forwards []Forward `json:"forwards,omitempty"`

	// DNSHostnames are FQDNs the operator publishes via a DNSEndpoint.
	DNSHostnames []string `json:"dnsHostnames,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="!has(self.zones) || self.zones.all(z, z.startsWith(self.region + '-'))",message="spec.gcp.zones entries must be inside spec.gcp.region"
// +kubebuilder:validation:XValidation:rule="has(self.loadBalancer) || (self.replicas <= 1 && (!has(self.zones) || (self.zones.size() == 1 && self.zones[0] == self.zone)))",message="without spec.gcp.loadBalancer, replicas must be 1 and zones, if set, must equal [zone]"
// +kubebuilder:validation:XValidation:rule="has(self.loadBalancer) == has(oldSelf.loadBalancer)",message="spec.gcp.loadBalancer presence is immutable"
// +kubebuilder:validation:XValidation:rule="!has(self.loadBalancer) || ((has(self.zones) ? self.zones : [self.zone]).size() == (has(oldSelf.zones) ? oldSelf.zones : [oldSelf.zone]).size() && (has(self.zones) ? self.zones : [self.zone]).all(z, z in (has(oldSelf.zones) ? oldSelf.zones : [oldSelf.zone])))",message="a load-balanced Gateway's effective zone set is immutable"
// +kubebuilder:validation:XValidation:rule="has(self.loadBalancer) || self.diskSizeGB == oldSelf.diskSizeGB",message="spec.gcp.diskSizeGB is immutable on a single-instance Gateway"
type GatewayGCPSpec struct {
	// ProjectID is the GCP project owning the gateway VM and its Secret Manager secret;
	// the boot keyfetch resolves the secret URL through it.
	// +kubebuilder:validation:MinLength=1
	ProjectID string `json:"projectID"`

	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Region string `json:"region"`

	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
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

	// Address selects the gateway VM's public ingress address. Every value has a
	// default, so the block may be omitted.
	// +optional
	// +kubebuilder:default={}
	Address GatewayGCPAddressSpec `json:"address"`

	// Spot runs the gateway VM as a preemptible spot instance.
	// +kubebuilder:default=false
	Spot bool `json:"spot,omitempty"`

	// Replicas is the desired member count, at most the usable hosts of Wireguard.Subnet less
	// the link's own address, and never more than 256.
	// +optional
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1
	Replicas int32 `json:"replicas,omitempty"`

	// Zones spreads a load-balanced Gateway's regional MIG. Absent means the effective
	// list [Zone]; the effective list is computed at reconcile, never persisted.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=63
	Zones []string `json:"zones,omitempty"`

	// LoadBalancer opts a Gateway into the regional-MIG-behind-passthrough-NLB path.
	// Absent keeps the single-Instance path. Presence is fixed at creation.
	// +optional
	LoadBalancer *GatewayGCPLoadBalancerSpec `json:"loadBalancer,omitempty"`
}

// GatewayGCPLoadBalancerSpec configures the regional load balancer and managed instance group.
// Its presence selects this provisioning path and is immutable after creation.
type GatewayGCPLoadBalancerSpec struct {
	// SessionAffinity is the regional backend service's affinity mode.
	// +optional
	// +kubebuilder:validation:Enum=NONE;CLIENT_IP_PORT_PROTO;CLIENT_IP_PROTO;CLIENT_IP
	// +kubebuilder:default=NONE
	SessionAffinity string `json:"sessionAffinity,omitempty"`
}

// GatewayGCPAddressType selects where the gateway VM's public ingress address comes from.
type GatewayGCPAddressType string

const (
	GatewayGCPAddressEphemeral GatewayGCPAddressType = "Ephemeral"
	GatewayGCPAddressReserved  GatewayGCPAddressType = "Reserved"
	GatewayGCPAddressExternal  GatewayGCPAddressType = "External"
)

// GatewayGCPAddressSpec selects the gateway VM's public ingress address.
// +kubebuilder:validation:XValidation:rule="(has(self.type) && self.type == 'External') == has(self.external)",message="spec.gcp.address.external is required when type is External and forbidden otherwise"
type GatewayGCPAddressSpec struct {
	// Ephemeral takes whatever address the instance is assigned; Reserved allocates a static regional
	// address alongside the VM; External binds an address reserved outside the operator.
	// +optional
	// +kubebuilder:validation:Enum=Ephemeral;Reserved;External
	// +kubebuilder:default=Reserved
	Type GatewayGCPAddressType `json:"type,omitempty"`

	// External identifies the pre-existing regional external address to bind. It must
	// live in spec.gcp.projectID and spec.gcp.region.
	// +optional
	External *GatewayGCPExternalAddress `json:"external,omitempty"`
}

// GatewayGCPExternalAddress identifies an address the operator neither creates nor deletes.
// +kubebuilder:validation:XValidation:rule="has(self.name) != has(self.ip)",message="spec.gcp.address.external must set exactly one of name and ip"
type GatewayGCPExternalAddress struct {
	// Name is the GCP regional Address resource name.
	// +optional
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name,omitempty"`

	// IP is the literal IPv4 address of a reserved regional external address.
	// +optional
	// +kubebuilder:validation:Pattern=`^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$`
	IP string `json:"ip,omitempty"`
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

// GatewayLinkSpec configures the in-cluster link workload: a Deployment in Cluster
// mode, a DaemonSet in Local mode.
type GatewayLinkSpec struct {
	// Replicas is the number of link pods. Values >1 enable hot-standby
	// failover and safe rolling updates via leader election.
	// +optional
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1
	Replicas int32 `json:"replicas,omitempty"`

	// NodeSelector is applied to the link pod template: the Deployment's in Cluster
	// mode, the DaemonSet's in Local mode.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
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

	// Namespace of the target Service, defaulting to the Gateway's namespace. Another
	// namespace must carry the wgnet.dev/allow-gateway-ingress=true label.
	// +kubebuilder:validation:Pattern=^[a-z0-9]([-a-z0-9]*[a-z0-9])?$
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// TargetPort is the port on Service; it defaults to Port when unset.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +optional
	TargetPort int32 `json:"targetPort,omitempty"`
}

// GatewayLinkStatus is the observed state of a Gateway's link workload.
type GatewayLinkStatus struct {
	// Link id allocated in Local mode, 0 in Cluster mode. Never reassigned once written: interface
	// name, nftables table, firewall mark, route table and health port all derive from it.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=250
	// +optional
	ID int32 `json:"id,omitempty"`

	// ActiveNode is the node running the pod that holds the link Lease, in either
	// mode. Empty until a holder pod is observed.
	// +optional
	ActiveNode string `json:"activeNode,omitempty"`
}

// GatewayGCPStatus reports the observed fleet for a load-balanced Gateway.
// It is empty for the single-instance provisioning path.
type GatewayGCPStatus struct {
	// Members lists the instance group members seen by read-only discovery, keyed and ordered by name
	// and refreshed on every reconcile of a load-balanced Gateway; empty until a member is observed.
	// +optional
	// +listType=map
	// +listMapKey=name
	Members []GatewayGCPMemberStatus `json:"members,omitempty"`
}

// GatewayGCPMemberStatus is one fleet member's public-only observed state, keyed by
// instance name. No key material or bundle contents ever appear here.
type GatewayGCPMemberStatus struct {
	// Name is the GCP managed instance name.
	Name string `json:"name"`
	// Zone is the last observed GCP zone and is empty until discovery reports it.
	Zone string `json:"zone,omitempty"`
	// Slot is the persistent allocation slot; zero also represents an unallocated pending member.
	Slot int32 `json:"slot,omitempty"`
	// TunnelAddress is the assigned tunnel host address and is empty for pending members.
	TunnelAddress string `json:"tunnelAddress,omitempty"`
	// ExternalAddress is the last observed public address and is empty until GCP reports one.
	ExternalAddress string `json:"externalAddress,omitempty"`
	// InstanceID is the last observed GCP instance ID and is empty until GCP reports one.
	InstanceID string `json:"instanceID,omitempty"`
	// Revision is the last path segment of the MIG version's instance template, empty until known.
	Revision string `json:"revision,omitempty"`
	// State is derived from the current discovery snapshot and durable member record.
	State GatewayGCPMemberState `json:"state"`
	// Message is empty when there is nothing to report.
	Message string `json:"message,omitempty"`
}

// GatewayGCPMemberState classifies a member from discovery and its durable record.
type GatewayGCPMemberState string

const (
	// GatewayGCPMemberPending is listed without a record, slot, key, or peer.
	GatewayGCPMemberPending GatewayGCPMemberState = "Pending"
	// GatewayGCPMemberActive has an allocated record, whether or not it is currently listed.
	GatewayGCPMemberActive GatewayGCPMemberState = "Active"
	// GatewayGCPMemberRecreating is listed recreating while its record and peer remain retained.
	GatewayGCPMemberRecreating GatewayGCPMemberState = "Recreating"
	// GatewayGCPMemberDeparting is absent from one or two usable snapshots and remains retained.
	GatewayGCPMemberDeparting GatewayGCPMemberState = "Departing"
	// GatewayGCPMemberDeparted has its peer removed while its record awaits release confirmation.
	GatewayGCPMemberDeparted GatewayGCPMemberState = "Departed"
)

type GatewayStatus struct {
	// Address is the gateway VM's public ingress IP, mirrored from the XGatewayGCP.
	Address string `json:"address,omitempty"`

	ServiceAccountEmail string `json:"serviceAccountEmail,omitempty"`

	// Link is the observed state of this Gateway's link workload.
	// +optional
	Link GatewayLinkStatus `json:"link"`

	// GCP is the observed state of a Gateway's GCP fleet. Empty on the single-Instance path.
	// +optional
	GCP GatewayGCPStatus `json:"gcp"`

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
// +kubebuilder:printcolumn:name="Policy",type=string,JSONPath=`.spec.trafficPolicy`
// +kubebuilder:printcolumn:name="Node",type=string,JSONPath=`.status.link.activeNode`,priority=1
// +kubebuilder:validation:XValidation:rule="!has(self.spec) || !has(self.spec.gcp) || !has(self.spec.gcp.loadBalancer) || size(self.metadata.name) <= 37",message="a load-balanced Gateway name is at most 37 characters: the instance template name prefix appends a 17-character revision suffix and GCP caps the prefix at 54"

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
