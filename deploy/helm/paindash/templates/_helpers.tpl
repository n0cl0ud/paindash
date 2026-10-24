{{/* Chart name, truncated to the 63 characters of a DNS label. */}}
{{- define "paindash.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Resource name: the release name, prefixed with the chart name unless it contains it. */}}
{{- define "paindash.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "paindash.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "paindash.labels" -}}
helm.sh/chart: {{ include "paindash.chart" . }}
{{ include "paindash.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "paindash.selectorLabels" -}}
app.kubernetes.io/name: {{ include "paindash.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "paindash.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "paindash.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "paindash.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion | toString }}
{{- if .Values.image.digest }}
{{- printf "%s:%s@%s" .Values.image.repository $tag .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository $tag }}
{{- end }}
{{- end }}

{{/* Secret and key holding PAINDASH_DATABASE_URL, empty when the database comes from extraEnv/envFrom. */}}
{{- define "paindash.databaseSecret" -}}
{{- if .Values.database.existingSecret }}
{{- .Values.database.existingSecret }}
{{- else if .Values.database.url }}
{{- printf "%s-db" (include "paindash.fullname" .) }}
{{- end }}
{{- end }}

{{- define "paindash.databaseSecretKey" -}}
{{- if .Values.database.existingSecret }}
{{- .Values.database.existingSecretKey | default "url" }}
{{- else }}
{{- "url" }}
{{- end }}
{{- end }}

{{/* Fails rendering on configurations the binary would reject at startup. */}}
{{- define "paindash.validate" -}}
{{- $pgEnv := false }}
{{- $promEnv := false }}
{{- range .Values.extraEnv }}
{{- if has .name (list "PAINDASH_DATABASE_URL" "PGHOST") }}
{{- $pgEnv = true }}
{{- end }}
{{- if eq .name "PAINDASH_PROMETHEUS_URL" }}
{{- $promEnv = true }}
{{- end }}
{{- end }}
{{- if not (or .Values.database.url .Values.database.existingSecret $pgEnv .Values.envFrom) }}
{{- fail "paindash needs PostgreSQL 14+ (none is bundled, demo mode included): set database.url, database.existingSecret, or PG* variables through extraEnv or envFrom" }}
{{- end }}
{{- if not (or .Values.prometheus.url $promEnv .Values.envFrom .Values.demo.enabled) }}
{{- fail "set prometheus.url, or PAINDASH_PROMETHEUS_URL through extraEnv or envFrom: a Prometheus-compatible API with the kube-state-metrics series (or demo.enabled=true)" }}
{{- end }}
{{- if and .Values.prometheus.url $promEnv }}
{{- fail "prometheus.url and PAINDASH_PROMETHEUS_URL in extraEnv are both set: keep one" }}
{{- end }}
{{- if not (has .Values.auth.mode (list "pomerium" "disabled")) }}
{{- fail (printf "auth.mode: %q, want \"pomerium\" or \"disabled\"" (toString .Values.auth.mode)) }}
{{- end }}
{{- range $class, $level := .Values.exposure.ingressClasses }}
{{- if not (has $level (list "internet" "internal")) }}
{{- fail (printf "exposure.ingressClasses.%s: %q, want \"internet\" or \"internal\"" $class (toString $level)) }}
{{- end }}
{{- end }}
{{- end }}
