// Package wg provides WireGuard key material helpers shared across the gateway
// control plane.
package wg

import (
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// GenerateKeypair generates a Curve25519 WireGuard keypair. Both returned keys
// are standard base64-encoded 32-byte WireGuard keys (the same encoding `wg`
// emits and accepts); publicKey is deterministically derived from privateKey.
func GenerateKeypair() (privateKey, publicKey string, err error) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", "", fmt.Errorf("generate wireguard private key: %w", err)
	}
	return priv.String(), priv.PublicKey().String(), nil
}
