{{/*
Expand the name of the chart.
*/}}
{{- define "wireguard-gateway-operator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Chart label value (chart-version).
*/}}
{{- define "wireguard-gateway-operator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels. Call with (dict "ctx" . "component" "<component>").
*/}}
{{- define "wireguard-gateway-operator.labels" -}}
helm.sh/chart: {{ include "wireguard-gateway-operator.chart" .ctx }}
{{ include "wireguard-gateway-operator.selectorLabels" . }}
{{- if .ctx.Chart.AppVersion }}
app.kubernetes.io/version: {{ .ctx.Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .ctx.Release.Service }}
app.kubernetes.io/part-of: wireguard-gateway-operator
{{- end }}

{{/*
Selector labels. Call with (dict "ctx" . "component" "<component>").
*/}}
{{- define "wireguard-gateway-operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "wireguard-gateway-operator.name" .ctx }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/*
Object name for a chart-rendered component: <chart-name>-<component>.
Chart-name based (NOT release-name based) — one release per namespace makes
the release prefix redundant.
Call with (dict "ctx" . "component" "<component>").
*/}}
{{- define "wireguard-gateway-operator.componentName" -}}
{{- printf "%s-%s" (include "wireguard-gateway-operator.name" .ctx) .component | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{/*
Shared GCP VPC name. Release-derived (unlike the chart-name-based component
names) because the VPC is a GCP-global resource: clusters sharing one project
must not collide. An explicit operator.sharedNetworkName pins it.
*/}}
{{- define "wireguard-gateway-operator.sharedNetworkName" -}}
{{- .Values.operator.sharedNetworkName | default (printf "wgnet-%s" .Release.Name) | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{/*
Operator container image reference (repository:tag). Runs the manager.
*/}}
{{- define "wireguard-gateway-operator.operatorImage" -}}
{{- printf "%s:%s" .Values.operator.image.repository .Values.operator.image.tag -}}
{{- end }}

{{/*
Link container image reference (repository:tag). The operator stamps it onto each
per-Gateway link Deployment via the GATEWAY_LINK_IMAGE env.
*/}}
{{- define "wireguard-gateway-operator.linkImage" -}}
{{- printf "%s:%s" .Values.link.image.repository .Values.link.image.tag -}}
{{- end }}
