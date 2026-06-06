{{/*
wireguard-gateway-operator.ignition renders the gateway VM's Ignition v3.4.0
config as a JSON string.

The config is assembled directly as nested dict/list values and serialised with
toJson, which keeps the chart self-contained (no Butane toolchain). Each file in
files/ is run through tpl so its {{ .Values }} references resolve, then embedded
as a base64 data URL. The keyfetch unit writes the wg0 netdev from the Secret
Manager bundle at boot; the netdev is therefore not shipped as a static file.

The rendered output is operator-global: no per-Gateway value is baked in (the
per-Gateway secret ID is read from the instance metadata server at boot), so the
chart renders one static userData ConfigMap the operator stamps onto every
XGateway.
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
After=network-pre.target
Wants=network-pre.target

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
  (dict "path" "/etc/systemd/network/20-wg0.network" "mode" 420 "src" "files/wg0.network")
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
