{{- define "qm.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "qm.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "qm.selectorLabels" -}}
app.kubernetes.io/name: {{ include "qm.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "qm.hasSecretEnv" -}}
{{- $found := "" -}}
{{- range $k, $v := .Values.secretEnv -}}
{{- if $v }}{{ $found = "1" }}{{ end -}}
{{- end -}}
{{- $found -}}
{{- end -}}

{{- define "qm.image" -}}
{{- $root := .root -}}
{{- $name := .name -}}
{{- $service := .service -}}
{{- $repository := printf "%s%s%s" $root.Values.image.repository ($root.Values.image.separator | default "/") $service.image -}}
{{- $digest := "" -}}
{{- with $root.Values.image.digests -}}
{{- $digest = index . $name | default "" -}}
{{- end -}}
{{- $tag := $service.tag | default $root.Values.image.tag -}}
{{- if $digest -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" $digest) -}}
{{- fail (printf "image.digests.%s must be a sha256 digest" $name) -}}
{{- end -}}
{{- printf "%s@%s" $repository $digest -}}
{{- else if $tag -}}
{{- printf "%s:%s" $repository $tag -}}
{{- else -}}
{{- fail (printf "image.digests.%s or an explicit image tag is required" $name) -}}
{{- end -}}
{{- end -}}

{{- define "qm.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "qm.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
{{- end -}}
