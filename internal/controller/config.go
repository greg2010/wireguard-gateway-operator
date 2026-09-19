// Package controller reconciles Gateways into Crossplane XGatewayGCP composites, WireGuard
// key Secrets, link Deployments and RBAC, and optional DNSEndpoints.
package controller

import (
	"time"
)

// Config carries install-wide inputs folded into every Gateway's children, not Gateway spec values.
// It is populated from the process environment.
type Config struct {
	// LinkImage is the container image for the gateway-link Deployment.
	LinkImage string `envconfig:"GATEWAY_LINK_IMAGE" required:"true"`
	// LinkImagePullPolicy is the imagePullPolicy for the link container.
	LinkImagePullPolicy string `envconfig:"GATEWAY_LINK_IMAGE_PULL_POLICY" default:"IfNotPresent"`

	// UserData is identical across Gateways; per-Gateway values come from VM metadata.
	// Empty omits the field.
	UserData string `envconfig:"GATEWAY_USER_DATA"`

	// EnableOSLogin turns GCP OS Login on for every gateway VM, gating SSH access
	// through IAM rather than instance metadata keys. Defaults on.
	EnableOSLogin bool `envconfig:"GATEWAY_ENABLE_OSLOGIN" default:"true"`

	// RequeueInterval is how often the reconciler re-polls the XGatewayGCP status,
	// since the composite's status is not watched in realtime.
	RequeueInterval time.Duration `envconfig:"GATEWAY_REQUEUE_INTERVAL" default:"30s"`

	// SharedNetworkName is the GCP VPC every Gateway attaches to; required so a bad install
	// fails fast, and distinct per tenant so tenants never share a VPC.
	SharedNetworkName string `envconfig:"GATEWAY_SHARED_NETWORK_NAME" required:"true"`

	// ProviderConfigName is the Crossplane ClusterProviderConfig all composed GCP resources use.
	// A distinct value binds an install to its own credentials.
	ProviderConfigName string `envconfig:"GATEWAY_PROVIDER_CONFIG_NAME" default:"default"`

	// PodNamespace hosts the singleton shared-network composite.
	PodNamespace string `envconfig:"POD_NAMESPACE" required:"true"`

	// GCPCredentialsSecret is the "<namespace>/<name>" of the Secret holding the service-account
	// key gcpdiscovery.Client authenticates with.
	GCPCredentialsSecret string `envconfig:"GATEWAY_GCP_CREDENTIALS_SECRET" default:"crossplane-system/gcp-creds"`
	// GCPCredentialsKey is the data key inside GCPCredentialsSecret holding the raw key bytes.
	GCPCredentialsKey string `envconfig:"GATEWAY_GCP_CREDENTIALS_KEY" default:"credentials.json"`
	// GCPDiscoveryInterval paces how often a load-balanced Gateway's fleet membership is re-listed.
	GCPDiscoveryInterval time.Duration `envconfig:"GATEWAY_GCP_DISCOVERY_INTERVAL" default:"30s"`
	// GCPAddressRefreshInterval paces the periodic instance-detail refresh, an order of
	// magnitude slower than GCPDiscoveryInterval; it only catches a missed address change.
	GCPAddressRefreshInterval time.Duration `envconfig:"GATEWAY_GCP_ADDRESS_REFRESH_INTERVAL" default:"10m"`

	// ResponderImage is the default container image for a Gateway's responder workload,
	// used when the Gateway's own spec.responder.image is unset.
	ResponderImage string `envconfig:"GATEWAY_RESPONDER_IMAGE" required:"true"`
}
