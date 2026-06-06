// Package controller reconciles the user-facing Gateway CR into a Crossplane
// XGateway composite, the WireGuard key Secrets, the in-cluster link Deployment
// and its RBAC, and an optional DNSEndpoint.
package controller

import "time"

// Config carries the operator-global inputs the reconciler folds into each
// Gateway's children: the values that are identical across every Gateway
// (WireGuard tunnel parameters, the link image, the GCP fields not expressed on
// the Gateway CR, and the static Flatcar Ignition) rather than per-Gateway spec.
//
// Populated from the process environment via config.Load. The empty envconfig
// prefix means tags are read verbatim.
type Config struct {
	// Namespace is the single namespace the operator watches and creates
	// children in. Empty means all namespaces.
	Namespace string `envconfig:"GATEWAY_OPERATOR_NAMESPACE"`

	// LinkImage is the container image for the gateway-link Deployment.
	LinkImage string `envconfig:"GATEWAY_LINK_IMAGE" required:"true"`
	// LinkImagePullPolicy is the imagePullPolicy for the link container.
	LinkImagePullPolicy string `envconfig:"GATEWAY_LINK_IMAGE_PULL_POLICY" default:"IfNotPresent"`

	// WGSubnet is the WireGuard tunnel CIDR; its suffix is reused for the link
	// interface address and it is the peer's sole allowed IP range.
	WGSubnet string `envconfig:"GATEWAY_WG_SUBNET" default:"10.99.0.0/29"`
	// WGLinkAddress is the link end's wg0 address (without CIDR suffix).
	WGLinkAddress string `envconfig:"GATEWAY_WG_LINK_ADDRESS" default:"10.99.0.2"`
	// WGListenPort is the gateway VM's WireGuard UDP port. It is both written to
	// the XGateway (driving the GCP firewall) and handed to the link to form the
	// peer endpoint.
	WGListenPort int `envconfig:"GATEWAY_WG_LISTEN_PORT" default:"51820"`
	// WGKeepalive is the link's persistent-keepalive interval in seconds.
	WGKeepalive int `envconfig:"GATEWAY_WG_KEEPALIVE" default:"25"`
	// WGMTU is the link's wg0 MTU.
	WGMTU int `envconfig:"GATEWAY_WG_MTU" default:"1380"`
	// WGReconcileInterval is how often the link re-reads the XGateway address.
	WGReconcileInterval time.Duration `envconfig:"GATEWAY_WG_RECONCILE_INTERVAL" default:"10s"`

	// GCPSubnetCIDR is the subnet CIDR the XGateway provisions on GCP.
	GCPSubnetCIDR string `envconfig:"GATEWAY_GCP_SUBNET_CIDR" default:"10.200.0.0/24"`
	// GCPImage is the boot image for the gateway VM; empty leaves the composition
	// default.
	GCPImage string `envconfig:"GATEWAY_GCP_IMAGE"`
	// GCPDiskSizeGB is the gateway VM boot disk size in GB; 0 leaves the
	// composition default.
	GCPDiskSizeGB int `envconfig:"GATEWAY_GCP_DISK_SIZE_GB"`
	// GCPReservedIP allocates a static external IP so the address survives an
	// instance replace.
	GCPReservedIP bool `envconfig:"GATEWAY_GCP_RESERVED_IP" default:"true"`
	// GCPSpot runs the gateway VM as a preemptible spot instance.
	GCPSpot bool `envconfig:"GATEWAY_GCP_SPOT" default:"false"`

	// UserData is the static Flatcar Ignition the XGateway sets as the VM
	// user-data. It is operator-global: no per-Gateway value is baked in, so the
	// rendered Ignition is identical across every Gateway. Phase F mounts it from
	// a ConfigMap.
	UserData string `envconfig:"GATEWAY_USER_DATA"`

	// RequeueInterval is how often the reconciler re-polls the XGateway status,
	// since the composite's status is not watched in realtime.
	RequeueInterval time.Duration `envconfig:"GATEWAY_REQUEUE_INTERVAL" default:"30s"`
}
