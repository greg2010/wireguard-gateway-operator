// Package controller reconciles the user-facing Gateway CR into a Crossplane
// XGatewayGCP composite, the WireGuard key Secrets, the in-cluster link Deployment
// and its RBAC, and an optional DNSEndpoint.
package controller

import "time"

// Config carries the operator-level inputs the reconciler folds into every Gateway's
// children: the values identical across the whole install, not the per-Gateway ones
// that live on the Gateway spec. It is populated from the process environment.
type Config struct {
	// LinkImage is the container image for the gateway-link Deployment.
	LinkImage string `envconfig:"GATEWAY_LINK_IMAGE" required:"true"`
	// LinkImagePullPolicy is the imagePullPolicy for the link container.
	LinkImagePullPolicy string `envconfig:"GATEWAY_LINK_IMAGE_PULL_POLICY" default:"IfNotPresent"`

	// UserData is the VM user-data the XGatewayGCP sets on the gateway instance.
	// It is operator-level and byte-identical across Gateways because every
	// per-Gateway value is read from instance metadata at boot. Empty omits the field.
	UserData string `envconfig:"GATEWAY_USER_DATA"`

	// EnableOSLogin turns GCP OS Login on for every gateway VM, gating SSH access
	// through IAM rather than instance metadata keys. Defaults on.
	EnableOSLogin bool `envconfig:"GATEWAY_ENABLE_OSLOGIN" default:"true"`

	// RequeueInterval is how often the reconciler re-polls the XGatewayGCP status,
	// since the composite's status is not watched in realtime.
	RequeueInterval time.Duration `envconfig:"GATEWAY_REQUEUE_INTERVAL" default:"30s"`

	// SharedNetworkName is the GCP VPC every Gateway this operator manages attaches to.
	// Required so a misconfigured install fails fast; separate tenants get distinct
	// values so they never contend for one VPC.
	SharedNetworkName string `envconfig:"GATEWAY_SHARED_NETWORK_NAME" required:"true"`

	// ProviderConfigName is the Crossplane ClusterProviderConfig every composed GCP
	// resource references. Defaults to "default"; set a distinct value to bind an
	// install to its own provider credentials and project.
	ProviderConfigName string `envconfig:"GATEWAY_PROVIDER_CONFIG_NAME" default:"default"`

	// PodNamespace is where the operator pod itself runs, used to place the
	// singleton shared-network composite alongside the operator. Supplied via the
	// downward API.
	PodNamespace string `envconfig:"POD_NAMESPACE" required:"true"`
}
