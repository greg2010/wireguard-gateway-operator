#!/usr/bin/env sh
# Per-Gateway values are read from instance metadata, not baked in. The secret fetch
# loops because the instance may boot before the operator has populated the secret.
set -eu

# The OAuth token and secret bundle land in /tmp before removal and must not be
# world-readable in the interim.
umask 077

NETDEV_PATH=/etc/systemd/network/10-wg0.netdev
NETWORK_PATH=/etc/systemd/network/20-wg0.network
NFT_PATH=/etc/nftables/gateway.nft
METADATA_BASE="http://metadata.google.internal/computeMetadata/v1/instance"
METADATA_TOKEN_URL="$METADATA_BASE/service-accounts/default/token"
METADATA_ATTR_BASE="$METADATA_BASE/attributes"

modprobe wireguard 2>&1 || echo "gateway-keyfetch: modprobe wireguard returned nonzero (may be builtin)"

extract_json_string() {
	# Sufficient for the flat metadata token and Secret Manager responses, which
	# carry no nested quotes in these fields.
	sed -n 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
}

fetch_metadata_attr() {
	# Loops because the operator may populate the metadata after the VM starts.
	# Presence is decided by the status code, not the body: the server returns a
	# non-empty error body on 404 that body-only gating would accept as a value.
	attr="$1"
	body_file="/tmp/gateway-attr.json"
	attempt=0
	while true; do
		attempt=$((attempt + 1))
		http="$(curl -s --connect-timeout 5 --max-time 10 -o "$body_file" -w '%{http_code}' -H "Metadata-Flavor: Google" "$METADATA_ATTR_BASE/$attr" || echo 000)"
		# Diagnostics go to stderr so the caller's command substitution captures
		# only the value printf emits.
		echo "gateway-keyfetch: attr=$attr attempt=$attempt http=$http" >&2
		if [ "$http" = "200" ]; then
			value="$(cat "$body_file")"
			rm -f "$body_file" 2>/dev/null || true
			printf '%s' "$value"
			return 0
		fi
		rm -f "$body_file" 2>/dev/null || true
		sleep 5
	done
}

write_netdev() {
	priv="$1"
	peer_pub="$2"
	cat > "$NETDEV_PATH.tmp" <<EOF
[NetDev]
Name=wg0
Kind=wireguard
MTUBytes=$wg_mtu

[WireGuard]
PrivateKey=$priv
ListenPort=$wg_listen_port

[WireGuardPeer]
PublicKey=$peer_pub
AllowedIPs=$wg_link_address/32
EOF
	chmod 0640 "$NETDEV_PATH.tmp"
	chown root:systemd-network "$NETDEV_PATH.tmp"
	mv "$NETDEV_PATH.tmp" "$NETDEV_PATH"
}

write_network() {
	# The wg0 address reuses the tunnel subnet's prefix length. A subnet without a
	# '/' would make "${var##*/}" yield the whole string and emit a malformed
	# Address= line, so reject it.
	case "$wg_subnet" in
		*/*) ;;
		*)
			echo "gateway-keyfetch: ERROR wg-subnet '$wg_subnet' has no '/' prefix length" >&2
			exit 1
			;;
	esac
	suffix="${wg_subnet##*/}"
	cat > "$NETWORK_PATH.tmp" <<EOF
[Match]
Name=wg0

[Network]
Address=$wg_gateway_address/$suffix
EOF
	chmod 0644 "$NETWORK_PATH.tmp"
	mv "$NETWORK_PATH.tmp" "$NETWORK_PATH"
}

render_nft() {
	# The sed delimiter is '|' so a value containing '/' (a CIDR) does not
	# terminate the s command and brick boot under set -eu.
	sed -e "s|__WG_LISTEN_PORT__|$wg_listen_port|g" \
		-e "s|__WG_LINK_ADDRESS__|$wg_link_address|g" \
		"$NFT_PATH" > "$NFT_PATH.tmp"
	chmod 0644 "$NFT_PATH.tmp"
	mv "$NFT_PATH.tmp" "$NFT_PATH"
}

wg_listen_port="$(fetch_metadata_attr wg-listen-port)"
wg_mtu="$(fetch_metadata_attr wg-mtu)"
wg_gateway_address="$(fetch_metadata_attr wg-gateway-address)"
wg_link_address="$(fetch_metadata_attr wg-link-address)"
wg_subnet="$(fetch_metadata_attr wg-subnet)"
project_id="$(fetch_metadata_attr project-id)"
secret_id="$(fetch_metadata_attr secret-id)"

write_network
render_nft

secret_url="https://secretmanager.googleapis.com/v1/projects/$project_id/secrets/$secret_id/versions/latest:access"

attempt=0
while true; do
	attempt=$((attempt + 1))
	tok_http="$(curl -s --connect-timeout 5 --max-time 10 -o /tmp/gateway-token.json -w '%{http_code}' -H "Metadata-Flavor: Google" "$METADATA_TOKEN_URL" || echo 000)"
	token="$(extract_json_string access_token < /tmp/gateway-token.json)"
	echo "gateway-keyfetch: attempt=$attempt token_http=$tok_http token_empty=$([ -z "$token" ] && echo yes || echo no)"
	if [ -z "$token" ]; then
		sleep 5
		continue
	fi

	sm_http="$(curl -s --connect-timeout 5 --max-time 10 -o /tmp/gateway-sm.json -w '%{http_code}' -H "Authorization: Bearer $token" "$secret_url" || echo 000)"
	echo "gateway-keyfetch: attempt=$attempt sm_url=$secret_url sm_http=$sm_http"
	payload="$(extract_json_string data < /tmp/gateway-sm.json)"
	if [ -z "$payload" ]; then
		sleep 5
		continue
	fi

	bundle="$(printf '%s' "$payload" | base64 -d 2>/dev/null)" || { echo "gateway-keyfetch: base64 decode failed"; sleep 5; continue; }
	gateway_priv="$(printf '%s\n' "$bundle" | sed -n '1p')"
	link_pub="$(printf '%s\n' "$bundle" | sed -n '2p')"
	if [ -z "$gateway_priv" ] || [ -z "$link_pub" ]; then
		echo "gateway-keyfetch: bundle parse empty (priv_empty=$([ -z "$gateway_priv" ] && echo yes || echo no) pub_empty=$([ -z "$link_pub" ] && echo yes || echo no))"
		sleep 5
		continue
	fi

	echo "gateway-keyfetch: bundle obtained on attempt=$attempt"
	write_netdev "$gateway_priv" "$link_pub"
	break
done
rm -f /tmp/gateway-token.json /tmp/gateway-sm.json 2>/dev/null || true

echo "gateway-keyfetch: bundle fetched, wrote netdev"
systemctl restart systemd-networkd

echo "gateway-keyfetch: restarted systemd-networkd, waiting for wg0"
i=0
while [ "$i" -lt 15 ]; do
	if ip link show wg0 >/dev/null 2>&1; then
		echo "gateway-keyfetch: wg0 is up"
		break
	fi
	i=$((i+1)); sleep 1
done
if [ "$i" -ge 15 ]; then
	echo "gateway-keyfetch: ERROR wg0 did not appear after networkd restart"
	networkctl status wg0 2>&1 | head -20 || true
	journalctl -u systemd-networkd --no-pager 2>&1 | tail -30 || true
	echo "gateway-keyfetch: netdev=$(sed 's/PrivateKey=.*/PrivateKey=REDACTED/' "$NETDEV_PATH" 2>&1 | tr '\n' '|')"
fi
