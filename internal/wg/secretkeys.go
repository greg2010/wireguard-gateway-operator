package wg

// Secret data keys shared between the key generator and the consumers of the
// WireGuard key material. The gateway VM fetches its bundle from GCP Secret
// Manager, so both ends must agree on these constants.
const (
	// BundleKey is the single data key in the gateway-bundle Secret. Its value is
	// "<gateway_private_key>\n<link_public_key>\n".
	BundleKey = "bundle"
	// LinkPrivateKey is the link Secret data key holding the link's WireGuard
	// private key.
	LinkPrivateKey = "private"
	// LinkPeerPublicKey is the link Secret data key holding the gateway's
	// WireGuard public key (the link's sole peer).
	LinkPeerPublicKey = "peerPublicKey"
)
