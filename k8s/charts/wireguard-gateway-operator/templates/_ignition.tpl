{{/*
wireguard-gateway-operator.ignition renders the gateway VM's Ignition v3.4.0
config as a JSON string.

The config is assembled directly as nested dict/list values and serialised with
toJson, which keeps the chart self-contained (no Butane toolchain). Each file in
files/ is run through tpl, then embedded as a base64 data URL.

The rendered output is fully value-free and byte-identical across every Gateway:
no per-Gateway value is baked in. The keyfetch unit reads every per-Gateway value
(WireGuard listen port, gateway/link addresses, tunnel subnet, project ID, secret
ID) from the instance metadata server at boot and renders the wg0 netdev, the wg0
.network address, and the nftables ruleset from it. The netdev and .network are
therefore not shipped as static files, and gateway.nft ships as a value-free
template the keyfetch unit fills before gateway-nftables.service loads it. The
operator stamps this one static userData ConfigMap onto every XGatewayGCP.
*/}}
{{- define "wireguard-gateway-operator.ignition" -}}
{{- $keyfetchUnit := `[Unit]
Description=Fetch gateway WireGuard bundle and write wg0 netdev
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/opt/gateway/keyfetch.sh
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
` -}}
{{- $nftablesUnit := `[Unit]
Description=Apply gateway nftables ruleset
After=network-pre.target gateway-keyfetch.service
Wants=network-pre.target gateway-keyfetch.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/nftables/gateway.nft
ExecReload=/usr/sbin/nft -f /etc/nftables/gateway.nft

[Install]
WantedBy=multi-user.target
` -}}
{{- $files := list
  (dict "path" "/opt/gateway/keyfetch.sh" "mode" 493 "src" "files/keyfetch.sh")
  (dict "path" "/etc/nftables/gateway.nft" "mode" 420 "src" "files/gateway.nft")
  (dict "path" "/etc/sysctl.d/50-gateway-forward.conf" "mode" 420 "src" "files/50-gateway-forward.conf")
-}}
{{- $storageFiles := list -}}
{{- range $files -}}
  {{- $rendered := tpl ($.Files.Get .src) $ -}}
  {{- $storageFiles = append $storageFiles (dict
      "path" .path
      "mode" .mode
      "contents" (dict "source" (printf "data:;base64,%s" ($rendered | b64enc)))
  ) -}}
{{- end -}}
{{- $config := dict
  "ignition" (dict "version" "3.4.0")
  "storage" (dict "files" $storageFiles)
  "systemd" (dict "units" (list
    (dict "name" "systemd-networkd.service" "enabled" true)
    (dict "name" "gateway-keyfetch.service" "enabled" true "contents" $keyfetchUnit)
    (dict "name" "gateway-nftables.service" "enabled" true "contents" $nftablesUnit)
  ))
-}}
{{- $config | toJson -}}
{{- end }}
