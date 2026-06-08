{{- define "wireguard-gateway-operator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "wireguard-gateway-operator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Call with (dict "ctx" . "component" "<component>"). */}}
{{- define "wireguard-gateway-operator.labels" -}}
helm.sh/chart: {{ include "wireguard-gateway-operator.chart" .ctx }}
{{ include "wireguard-gateway-operator.selectorLabels" . }}
{{- if .ctx.Chart.AppVersion }}
app.kubernetes.io/version: {{ .ctx.Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .ctx.Release.Service }}
app.kubernetes.io/part-of: wireguard-gateway-operator
{{- end }}

{{/* Call with (dict "ctx" . "component" "<component>"). */}}
{{- define "wireguard-gateway-operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "wireguard-gateway-operator.name" .ctx }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/* Chart-name based, not release-name based: one release per namespace. Call with (dict "ctx" . "component" "<component>"). */}}
{{- define "wireguard-gateway-operator.componentName" -}}
{{- printf "%s-%s" (include "wireguard-gateway-operator.name" .ctx) .component | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{/* Release-derived, not chart-name based: the VPC is GCP-global, so clusters sharing a project must not collide. */}}
{{- define "wireguard-gateway-operator.sharedNetworkName" -}}
{{- .Values.operator.sharedNetworkName | default (printf "wgnet-%s" .Release.Name) | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{- define "wireguard-gateway-operator.operatorImage" -}}
{{- printf "%s:%s" .Values.operator.image.repository .Values.operator.image.tag -}}
{{- end }}

{{/* The operator stamps this onto each per-Gateway link Deployment via the GATEWAY_LINK_IMAGE env. */}}
{{- define "wireguard-gateway-operator.linkImage" -}}
{{- printf "%s:%s" .Values.link.image.repository .Values.link.image.tag -}}
{{- end }}
