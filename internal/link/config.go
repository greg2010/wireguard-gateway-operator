// Package link implements the in-cluster gateway-link daemon: it brings up wg0 to the
// gateway VM and DNATs public ports to Service ClusterIPs, reloading from a watched
// ConfigMap. Leader election over a Lease lets only the holder program the data plane.
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
	// PodNamespace is the namespace the leader-election Lease lives in. Required
	// because the Lease lock is namespaced and the in-cluster client has no
	// implicit namespace.
	PodNamespace string `envconfig:"POD_NAMESPACE" required:"true"`
	// PodName is this replica's leader-election identity, recorded as the Lease
	// holder. Required and unique per pod.
	PodName string `envconfig:"POD_NAME" required:"true"`
	// LeaseName is the coordination.k8s.io Lease the replicas contend for. Shared
	// across a gateway's replicas so exactly one holds it at a time.
	LeaseName string `envconfig:"GATEWAY_LEASE_NAME" required:"true"`
}

// RuntimeConfig is the on-disk JSON config describing the WireGuard tunnel and
// the port forwards the link programs into nftables. The WireGuard private key
// is deliberately absent; it is read separately from Config.WGKeyPath.
type RuntimeConfig struct {
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
	// Endpoint is the gateway's public host:port. Optional on disk because the
	// operator's observation of the gateway address may trail the link's start, in
	// which case the reload loop waits for it.
	Endpoint string `json:"endpoint"`
	// AllowedIPs is the set of source ranges accepted from and routed to the peer,
	// typically the wg0 subnet.
	AllowedIPs []string `json:"allowedIPs"`
	// PersistentKeepalive in seconds keeps the NAT pinhole open; 0 disables it.
	PersistentKeepalive int `json:"persistentKeepalive"`
}

// Forward maps a public port arriving on wg0 to an in-cluster Service, resolved
// to a ClusterIP at apply time.
type Forward struct {
	Name       string `json:"name"`
	PublicPort int    `json:"publicPort"`
	// Protocol is tcp or udp; it is lowercased during validation.
	Protocol   string `json:"protocol"`
	Service    string `json:"service"`
	TargetPort int    `json:"targetPort"`
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

// validate lowercases forward protocols in place and rejects configs the apply
// step cannot program. The peer endpoint is intentionally not required here; the
// reload loop waits for the operator to fill it in before applying.
func (rc *RuntimeConfig) validate() error {
	if rc.WireGuard.Address == "" {
		return fmt.Errorf("wireguard address is required")
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
		if f.TargetPort < 1 || f.TargetPort > 65535 {
			return fmt.Errorf("forward %q: target port must be in 1..65535, got %d", f.Name, f.TargetPort)
		}
		if f.Service == "" {
			return fmt.Errorf("forward %q: service is required", f.Name)
		}
		k := key{port: f.PublicPort, proto: proto}
		if prev, ok := seen[k]; ok {
			return fmt.Errorf("forward %q collides with %q on %s/%d", f.Name, prev, proto, f.PublicPort)
		}
		seen[k] = f.Name
	}
	return nil
}
