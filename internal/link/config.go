package link

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Config is the process-level configuration for gateway-link, populated from the
// environment via config.Load.
type Config struct {
	// ConfigPath is the on-disk path to the JSON RuntimeConfig. Its parent dir is
	// watched so in-place updates are picked up without a restart.
	ConfigPath string `envconfig:"GATEWAY_CONFIG_PATH" default:"/etc/gateway/config/config.json"`
	// WGKeyPath is the WireGuard private key path, kept out of the RuntimeConfig so
	// the key Secret and the config ConfigMap rotate independently.
	WGKeyPath string `envconfig:"GATEWAY_WG_KEY_PATH" default:"/etc/gateway/wg/private"`
	// PeerPubKeyPath is the path to the gateway's WireGuard public key.
	PeerPubKeyPath string `envconfig:"GATEWAY_WG_PEER_PUBKEY_PATH" default:"/etc/gateway/wg/peerPublicKey"`
	// HealthAddr is the listen address for the readiness HTTP server.
	HealthAddr string `envconfig:"GATEWAY_HEALTH_ADDR" default:":8080"`
	// ReconcileInterval backstops the fsnotify-driven reload loop in case a
	// filesystem event is missed.
	ReconcileInterval time.Duration `envconfig:"GATEWAY_RECONCILE_INTERVAL" default:"10s"`
	// PodNamespace is the namespace the leader-election Lease lives in. Required: the Lease lock is
	// namespaced and the in-cluster client has no implicit namespace.
	PodNamespace string `envconfig:"POD_NAMESPACE" required:"true"`
	// PodName is this replica's leader-election identity, recorded as the Lease
	// holder. Required and unique per pod.
	PodName string `envconfig:"POD_NAME" required:"true"`
	// LeaseName is the coordination.k8s.io Lease the replicas contend for. Shared
	// across a gateway's replicas so exactly one holds it at a time.
	LeaseName string `envconfig:"GATEWAY_LEASE_NAME" required:"true"`
	// NodeName is the node this pod runs on, from the downward API. Required in Local mode as the
	// endpoint-selection filter and this link's election identity; Cluster mode leaves it empty.
	NodeName string `envconfig:"NODE_NAME"`
}

// Traffic-policy values carried in RuntimeConfig.TrafficPolicy, mirroring the wgnet.dev/v1alpha1
// values verbatim so the operator copies the CR value without translating it.
const (
	TrafficPolicyCluster = "Cluster"
	TrafficPolicyLocal   = "Local"
)

// RuntimeConfig is the on-disk JSON config describing the WireGuard tunnel and the port forwards
// the link programs. The WireGuard private key is absent; it is read from Config.WGKeyPath.
type RuntimeConfig struct {
	// TrafficPolicy is TrafficPolicyCluster or TrafficPolicyLocal. Empty means
	// Cluster, so a config written by an older operator keeps its meaning.
	TrafficPolicy string `json:"trafficPolicy,omitempty"`

	// Identity is present in Local mode only. Its absence tells the link it is a Cluster-mode
	// replica, and makes Forward.Service and Forward.TargetPort required instead of the Local set.
	Identity *Identity `json:"identity,omitempty"`

	// PodSelector matches this Gateway's link pods, and is what the election's liveness table
	// watches by. Local mode only, and required there.
	PodSelector map[string]string `json:"podSelector,omitempty"`

	WireGuard WireGuard `json:"wireguard"`
	Forwards  []Forward `json:"forwards"`
}

// WireGuard describes the local wg0 interface and the single gateway peer the
// link dials out to.
type WireGuard struct {
	// Address is the wg0 address in CIDR form (e.g. 10.99.0.2/32).
	Address string `json:"address"`
	// ListenPort is the optional local UDP listen port; 0 picks an ephemeral port.
	ListenPort int `json:"listenPort"`
	// MTU is the optional wg0 MTU; 0 leaves the kernel default.
	MTU  int  `json:"mtu"`
	Peer Peer `json:"peer"`
}

// Peer is the gateway endpoint the link connects to. The peer's public key is
// read from Config.PeerPubKeyPath at apply time, not carried here.
type Peer struct {
	// Endpoint is the gateway's public host:port. Optional on disk: the operator's
	// observation of the gateway address may trail the link's start; the reload loop waits.
	Endpoint string `json:"endpoint"`
	// AllowedIPs is the set of source ranges accepted from and routed to the peer,
	// typically the wg0 subnet.
	AllowedIPs []string `json:"allowedIPs"`
	// PersistentKeepalive in seconds keeps the NAT pinhole open; 0 disables it.
	PersistentKeepalive int `json:"persistentKeepalive"`
}

// Forward maps a public port arriving on the tunnel interface to an in-cluster backend. Cluster
// mode DNATs to a Service's ClusterIP; Local mode DNATs to a ready pod IP on this node.
type Forward struct {
	Name       string `json:"name"`
	PublicPort int    `json:"publicPort"`
	// Protocol is tcp or udp; it is lowercased during validation.
	Protocol string `json:"protocol"`

	// Service is the backend Service FQDN. Cluster mode only.
	Service string `json:"service,omitempty"`
	// TargetPort is the Service port the DNAT targets. Cluster mode only.
	TargetPort int `json:"targetPort,omitempty"`

	// Namespace is the backend Service's namespace. Local mode only.
	Namespace string `json:"namespace,omitempty"`
	// ServiceName is the bare backend Service name, the value of the
	// kubernetes.io/service-name selector the link watches. Local mode only.
	ServiceName string `json:"serviceName,omitempty"`
	// ServicePortName is matched against the EndpointSlice ports entry; empty selects the entry
	// carrying no name, which a single unnamed Service port produces. Local mode only.
	ServicePortName string `json:"servicePortName,omitempty"`
}

// LoadRuntimeConfig reads and validates the JSON RuntimeConfig at path. Unknown
// fields are tolerated so older daemons can run against newer config schemas.
func LoadRuntimeConfig(path string) (RuntimeConfig, error) {
	var rc RuntimeConfig
	data, err := os.ReadFile(path)
	if err != nil {
		return rc, fmt.Errorf("read runtime config %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &rc); err != nil {
		return rc, fmt.Errorf("unmarshal runtime config %s: %w", path, err)
	}
	if err := rc.validate(); err != nil {
		return rc, fmt.Errorf("validate runtime config %s: %w", path, err)
	}
	return rc, nil
}

// isLocal reports whether rc is a Local-mode config. validate rejects a config whose identity
// block and traffic policy disagree, so the identity block alone decides the mode.
func (rc RuntimeConfig) isLocal() bool {
	return rc.Identity != nil
}

// validate lowercases forward protocols in place and rejects configs the apply step cannot
// program. The peer endpoint is not required; the reload loop waits for the operator to fill it in.
func (rc *RuntimeConfig) validate() error {
	if rc.WireGuard.Address == "" {
		return fmt.Errorf("wireguard address is required")
	}
	if rc.TrafficPolicy != "" && rc.TrafficPolicy != TrafficPolicyCluster && rc.TrafficPolicy != TrafficPolicyLocal {
		return fmt.Errorf("unknown traffic policy %q", rc.TrafficPolicy)
	}
	if rc.TrafficPolicy == TrafficPolicyLocal && rc.Identity == nil {
		return fmt.Errorf("traffic policy %s carries no identity block", rc.TrafficPolicy)
	}
	if rc.Identity != nil && rc.TrafficPolicy != TrafficPolicyLocal {
		return fmt.Errorf("identity block is Local-only, got traffic policy %q", rc.TrafficPolicy)
	}
	if rc.Identity != nil && len(rc.PodSelector) == 0 {
		return fmt.Errorf("traffic policy %s requires a non-empty podSelector", rc.TrafficPolicy)
	}

	type key struct {
		port  int
		proto string
	}
	seen := make(map[key]string, len(rc.Forwards))
	for i := range rc.Forwards {
		f := &rc.Forwards[i]
		proto := strings.ToLower(f.Protocol)
		f.Protocol = proto
		if proto != "tcp" && proto != "udp" {
			return fmt.Errorf("forward %q: protocol must be tcp or udp, got %q", f.Name, f.Protocol)
		}
		if f.PublicPort < 1 || f.PublicPort > 65535 {
			return fmt.Errorf("forward %q: public port must be in 1..65535, got %d", f.Name, f.PublicPort)
		}

		if !rc.isLocal() {
			if f.Service == "" {
				return fmt.Errorf("forward %q: service is required", f.Name)
			}
			if f.TargetPort < 1 || f.TargetPort > 65535 {
				return fmt.Errorf("forward %q: target port must be in 1..65535, got %d", f.Name, f.TargetPort)
			}
		} else {
			if f.Namespace == "" {
				return fmt.Errorf("forward %q: namespace is required", f.Name)
			}
			if f.ServiceName == "" {
				return fmt.Errorf("forward %q: serviceName is required", f.Name)
			}
		}

		k := key{port: f.PublicPort, proto: proto}
		if prev, ok := seen[k]; ok {
			return fmt.Errorf("forward %q collides with %q on %s/%d", f.Name, prev, proto, f.PublicPort)
		}
		seen[k] = f.Name
	}
	return nil
}
