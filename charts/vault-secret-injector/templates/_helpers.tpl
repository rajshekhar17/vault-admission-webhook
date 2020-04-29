
{{/* vim: set filetype=mustache: */}}
{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}

{{- define "vault-secret-injector.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "vault-secret-injector.fullname" -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "vault-secret-injector.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "vault-secret-injector.metaLabels" -}}
app.kubernetes.io/name: {{ template "vault-secret-injector.name" . }}
helm.sh/chart: {{ template "vault-secret-injector.chart" . }}
app.kubernetes.io/instance: "{{ .Release.Name }}"
app.kubernetes.io/managed-by: "{{ .Release.Service }}"
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}

{{- define "vault-secret-injector.selectorLabels" -}}
app.kubernetes.io/name: {{ template "vault-secret-injector.name" . }}
app.kubernetes.io/component: app
app.kubernetes.io/instance: "{{ .Release.Name }}"
{{- end -}}

{{/*
Create the name of the service account to use
*/}}

{{- define "vault-secret-injector.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
    {{ default (include "vault-secret-injector.fullname" .) .Values.serviceAccount.name }}
{{- else -}}
    {{ default "default" .Values.serviceAccount.name }}
{{- end -}}
{{- end -}}

{{- define "vault-secret-injector.service.validationWebhook" -}}
{{ include "vault-secret-injector.fullname" . }}-validation-webhook
{{- end -}}