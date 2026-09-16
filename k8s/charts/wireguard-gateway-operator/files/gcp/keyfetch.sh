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
# Overridable only so the integration proof can point at a controlled HTTP double;
# unset in production, where these resolve to the values below.
METADATA_BASE="${GATEWAY_KEYFETCH_METADATA_BASE:-http://metadata.google.internal/computeMetadata/v1/instance}"
SECRETMANAGER_BASE="${GATEWAY_KEYFETCH_SECRETMANAGER_BASE:-https://secretmanager.googleapis.com}"
METADATA_TOKEN_URL="$METADATA_BASE/service-accounts/default/token"
METADATA_ATTR_BASE="$METADATA_BASE/attributes"

modprobe wireguard 2>&1 || echo "gateway-keyfetch: modprobe wireguard returned nonzero (may be builtin)"

extract_json_string() {
	# Sufficient for the flat metadata token, Secret Manager and bundle responses,
	# which carry no nested quotes in these fields.
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

fetch_instance_attr() {
	# Same polling shape as fetch_metadata_attr, but queries the instance resource
	# directly ($METADATA_BASE/<attr>) rather than under attributes/.
	attr="$1"
	body_file="/tmp/gateway-instance-attr.json"
	attempt=0
	while true; do
		attempt=$((attempt + 1))
		http="$(curl -s --connect-timeout 5 --max-time 10 -o "$body_file" -w '%{http_code}' -H "Metadata-Flavor: Google" "$METADATA_BASE/$attr" || echo 000)"
		echo "gateway-keyfetch: instance_attr=$attr attempt=$attempt http=$http" >&2
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
	peer_allowed_ips="$3"
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
AllowedIPs=$peer_allowed_ips
EOF
	chmod 0640 "$NETDEV_PATH.tmp"
	chown root:systemd-network "$NETDEV_PATH.tmp"
	mv "$NETDEV_PATH.tmp" "$NETDEV_PATH"
}

write_network() {
	# member_address is already CIDR (the bundle's "address" field), so no suffix
	# computation is needed here.
	member_address="$1"
	cat > "$NETWORK_PATH.tmp" <<EOF
[Match]
Name=wg0

[Network]
Address=$member_address
EOF
	chmod 0644 "$NETWORK_PATH.tmp"
	mv "$NETWORK_PATH.tmp" "$NETWORK_PATH"
}

postrouting_verdict() {
	# Local preserves the client's source address end to end, so tunnel egress must
	# not be masqueraded; "return" falls through to the chain policy and keeps the
	# rendered ruleset syntactically complete. An unrecognised value falls back to
	# masquerade, which forwards traffic without preserving the source rather than
	# rendering a ruleset the VM cannot serve from.
	case "$1" in
		local) printf '%s' "return" ;;
		*) printf '%s' "masquerade" ;;
	esac
}

render_nft() {
	# The sed delimiter is '|' so a value containing '/' (a CIDR) does not
	# terminate the s command and brick boot under set -eu.
	sed -e "s|__WG_LISTEN_PORT__|$wg_listen_port|g" \
		-e "s|__WG_LINK_ADDRESS__|$wg_link_address|g" \
		-e "s|__WG_POSTROUTING_VERDICT__|$wg_postrouting_verdict|g" \
		"$NFT_PATH" > "$NFT_PATH.tmp"
	chmod 0644 "$NFT_PATH.tmp"
	mv "$NFT_PATH.tmp" "$NFT_PATH"
}

wg_listen_port="$(fetch_metadata_attr wg-listen-port)"
wg_mtu="$(fetch_metadata_attr wg-mtu)"
wg_link_address="$(fetch_metadata_attr wg-link-address)"
traffic_policy="$(fetch_metadata_attr traffic-policy)"
project_id="$(fetch_metadata_attr project-id)"
secret_id_base="$(fetch_metadata_attr secret-id)"
own_name="$(fetch_instance_attr name)"
secret_id="${secret_id_base}-${own_name}"

wg_postrouting_verdict="$(postrouting_verdict "$traffic_policy")"

render_nft

secret_url="$SECRETMANAGER_BASE/v1/projects/$project_id/secrets/$secret_id/versions/latest:access"

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
	member_priv="$(printf '%s' "$bundle" | extract_json_string privateKey)"
	member_address="$(printf '%s' "$bundle" | extract_json_string address)"
	member_slot="$(printf '%s' "$bundle" | extract_json_string slot)"
	member_peer_pub="$(printf '%s' "$bundle" | extract_json_string peerPublicKey)"
	member_peer_allowed_ips="$(printf '%s' "$bundle" | extract_json_string peerAllowedIPs)"
	if [ -z "$member_priv" ] || [ -z "$member_address" ] || [ -z "$member_peer_pub" ] || [ -z "$member_peer_allowed_ips" ]; then
		echo "gateway-keyfetch: bundle parse empty (priv_empty=$([ -z "$member_priv" ] && echo yes || echo no) address_empty=$([ -z "$member_address" ] && echo yes || echo no) peer_pub_empty=$([ -z "$member_peer_pub" ] && echo yes || echo no) peer_allowed_ips_empty=$([ -z "$member_peer_allowed_ips" ] && echo yes || echo no))"
		sleep 5
		continue
	fi

	echo "gateway-keyfetch: bundle obtained on attempt=$attempt slot=${member_slot:-unknown}"
	write_network "$member_address"
	write_netdev "$member_priv" "$member_peer_pub" "$member_peer_allowed_ips"
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
