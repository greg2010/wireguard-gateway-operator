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

type GatewaySpec struct {
	GCP GatewayGCPSpec `json:"gcp"`

	// Forwards are the public ports DNAT'd through the gateway to in-cluster pods.
	Forwards []Forward `json:"forwards,omitempty"`

	// DNSHostnames are FQDNs the operator publishes via a DNSEndpoint.
	DNSHostnames []string `json:"dnsHostnames,omitempty"`
}

type GatewayGCPSpec struct {
	// +kubebuilder:validation:MinLength=1
	Region string `json:"region"`

	// +kubebuilder:validation:MinLength=1
	Zone string `json:"zone"`

	// +kubebuilder:default="e2-small"
	MachineType string `json:"machineType,omitempty"`
}

type Forward struct {
	// Port is the public port opened on the gateway VM and DNAT'd through the
	// tunnel.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`

	// +kubebuilder:validation:Enum=TCP;UDP
	Protocol Protocol `json:"protocol"`

	// Service is the in-cluster Service DNS name the link DNATs the public port
	// to.
	// +kubebuilder:validation:MinLength=1
	Service string `json:"service"`

	// TargetPort is the port on Service; it defaults to Port when unset.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +optional
	TargetPort int32 `json:"targetPort,omitempty"`
}

type GatewayStatus struct {
	// Address is the gateway VM's public ingress IP, mirrored from the XGateway.
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

func init() {
	SchemeBuilder.Register(&Gateway{}, &GatewayList{})
}
