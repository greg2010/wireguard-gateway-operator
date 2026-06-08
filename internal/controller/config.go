// Package controller reconciles the user-facing Gateway CR into a Crossplane
// XGatewayGCP composite, the WireGuard key Secrets, the in-cluster link Deployment
// and its RBAC, and an optional DNSEndpoint.
package controller

import "time"

// Config carries the operator-level inputs the reconciler folds into every
// Gateway's children. These are the values that are identical across the whole
// operator install rather than per-Gateway: the link image, the VM userData, and
// the reconcile cadence. Every per-Gateway value (the GCP placement and the
// WireGuard tunnel parameters) lives on the Gateway CR's spec, not here.
//
// Populated from the process environment via config.Load. The empty envconfig
// prefix means tags are read verbatim.
type Config struct {
	// LinkImage is the container image for the gateway-link Deployment.
	LinkImage string `envconfig:"GATEWAY_LINK_IMAGE" required:"true"`
	// LinkImagePullPolicy is the imagePullPolicy for the link container.
	LinkImagePullPolicy string `envconfig:"GATEWAY_LINK_IMAGE_PULL_POLICY" default:"IfNotPresent"`

	// UserData is the VM user-data the XGatewayGCP sets on the gateway instance. It is
	// operator-level: every per-Gateway value is read from instance metadata at
	// boot, so the rendered Ignition is byte-identical across every Gateway. Empty
	// omits the field from the composite.
	UserData string `envconfig:"GATEWAY_USER_DATA"`

	// RequeueInterval is how often the reconciler re-polls the XGatewayGCP status,
	// since the composite's status is not watched in realtime.
	RequeueInterval time.Duration `envconfig:"GATEWAY_REQUEUE_INTERVAL" default:"30s"`

	// SharedNetworkName is the GCP VPC every Gateway this operator manages attaches
	// to. Required so a misconfigured install fails fast rather than silently using
	// the wrong VPC: the chart always supplies the release-derived name (wgnet-<release>),
	// and operators serving separate tenants each get a distinct value so they do not
	// contend for one VPC.
	SharedNetworkName string `envconfig:"GATEWAY_SHARED_NETWORK_NAME" required:"true"`

	// PodNamespace is where the operator pod itself runs, used to place the
	// singleton shared-network composite alongside the operator. Supplied via the
	// downward API.
	PodNamespace string `envconfig:"POD_NAMESPACE" required:"true"`
}
