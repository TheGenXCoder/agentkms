{{- define "agentkms.fullname" -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "agentkms.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{ include "agentkms.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "agentkms.selectorLabels" -}}
app.kubernetes.io/name: agentkms
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
