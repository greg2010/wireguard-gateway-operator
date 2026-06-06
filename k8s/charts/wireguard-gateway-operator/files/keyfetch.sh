#!/usr/bin/env sh
# Fetches the gateway WireGuard key bundle from GCP Secret Manager, writes the
# wg0 netdev unit, and restarts systemd-networkd to bring the interface up. The
# bundle is a two-line payload: line 1 is the gateway private key, line 2 is the
# link peer public key. Loops until the secret version exists and decodes
# cleanly, so the instance may boot before the operator has populated the secret.
# Runs after network-online.target, since the metadata server and Secret Manager
# are reachable only over the primary NIC.
#
# The per-Gateway secret ID is read from the instance metadata server, not baked
# into this script: the operator sets XGateway.spec.secretId, the composition
# writes it into the Instance metadata "secret-id" attribute, and this script
# resolves it at boot. The WireGuard listen port and link address it templates
# are operator-global, so the rendered Ignition is identical across every Gateway.
set -eu

NETDEV_PATH=/etc/systemd/network/10-wg0.netdev
METADATA_BASE="http://metadata.google.internal/computeMetadata/v1/instance"
METADATA_TOKEN_URL="$METADATA_BASE/service-accounts/default/token"
SECRET_ID_URL="$METADATA_BASE/attributes/secret-id"

modprobe wireguard 2>&1 || echo "gateway-keyfetch: modprobe wireguard returned nonzero (may be builtin)"

extract_json_string() {
	# Pulls the value of a flat JSON string field ("<field>":"<value>") from
	# stdin. Sufficient for the metadata token and Secret Manager access
	# responses, which are flat objects with no nested quotes in these fields.
	sed -n 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
}

write_netdev() {
	priv="$1"
	peer_pub="$2"
	umask 077
	cat > "$NETDEV_PATH.tmp" <<EOF
[NetDev]
Name=wg0
Kind=wireguard

[WireGuard]
PrivateKey=$priv
ListenPort={{ .Values.wireguard.listenPort }}

[WireGuardPeer]
PublicKey=$peer_pub
AllowedIPs={{ .Values.wireguard.linkAddress }}/32
EOF
	chmod 0640 "$NETDEV_PATH.tmp"
	chown root:systemd-network "$NETDEV_PATH.tmp"
	mv "$NETDEV_PATH.tmp" "$NETDEV_PATH"
}

secret_id=""
attempt=0
while [ -z "$secret_id" ]; do
	attempt=$((attempt + 1))
	secret_id="$(curl -s --connect-timeout 5 --max-time 10 -H "Metadata-Flavor: Google" "$SECRET_ID_URL" || true)"
	echo "gateway-keyfetch: attempt=$attempt secret_id_empty=$([ -z "$secret_id" ] && echo yes || echo no)"
	if [ -z "$secret_id" ]; then
		sleep 5
	fi
done

secret_url="https://secretmanager.googleapis.com/v1/projects/{{ .Values.gcp.projectID }}/secrets/$secret_id/versions/latest:access"

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
