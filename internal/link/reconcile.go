package link

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// xgatewayGVR is the XGateway composite resource that publishes the gateway's
// public IP at status.address. The link reads it via the dynamic client.
var xgatewayGVR = schema.GroupVersionResource{Group: "infra.wgnet.dev", Version: "v1alpha1", Resource: "xgateways"}

// applyFunc programs the tunnel and nftables from rc, given the WireGuard
// private and peer public keys. It matches Apply once defaultResolve is bound,
// and is injected so the reconcile loop can be tested without shelling out.
type applyFunc func(ctx context.Context, rc RuntimeConfig, privKey, peerPubKey string) error

// readGatewayIP returns the gateway's public IP from the XGateway's
// status.address. A missing XGateway or an unset address is reported as
// ("", nil) rather than an error: both mean the provision Job has not populated
// it yet, so the caller waits rather than failing. A genuine API error is
// returned wrapped.
func readGatewayIP(ctx context.Context, dyn dynamic.Interface, name, namespace string) (string, error) {
	u, err := dyn.Resource(xgatewayGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get xgateway %s/%s: %w", namespace, name, err)
	}
	ip, _, err := unstructured.NestedString(u.Object, "status", "address")
	if err != nil {
		return "", fmt.Errorf("read status.address of xgateway %s/%s: %w", namespace, name, err)
	}
	return ip, nil
}

// reconcile keeps the WireGuard peer endpoint in sync with the gateway's observed
// IP. It calls readIP every interval; when the IP first appears or changes it
// sets rc.WireGuard.Peer.Endpoint to <ip>:<wgListenPort> and calls apply. The
// last successfully-applied IP is remembered so an unchanged IP is a no-op and a
// failed apply is retried on the next tick (last-applied is updated only on
// success). An unobserved IP (readIP returning "") is not fatal: the loop logs
// and waits. It returns nil when ctx is cancelled; the only error paths are
// genuine failures from readIP, which are logged and retried, so in practice
// reconcile returns nil.
func reconcile(
	ctx context.Context,
	rc RuntimeConfig,
	privKey, peerPubKey string,
	readIP func(context.Context) (string, error),
	wgListenPort int,
	interval time.Duration,
	apply applyFunc,
	log *zap.SugaredLogger,
) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lastApplied string
	for {
		ip, err := readIP(ctx)
		switch {
		case err != nil:
			log.Warnw("read gateway ip", "error", err)
		case ip == "":
			log.Debugw("waiting for gateway ip")
		case ip != lastApplied:
			rc.WireGuard.Peer.Endpoint = net.JoinHostPort(ip, strconv.Itoa(wgListenPort))
			if aerr := apply(ctx, rc, privKey, peerPubKey); aerr != nil {
				log.Warnw("apply tunnel config", "endpoint", rc.WireGuard.Peer.Endpoint, "error", aerr)
			} else {
				lastApplied = ip
				log.Infow("applied gateway endpoint", "endpoint", rc.WireGuard.Peer.Endpoint)
			}
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
