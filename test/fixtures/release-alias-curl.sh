#!/usr/bin/env bash
set -euo pipefail

method=GET
headers=
if_none_match=false
output=
scope=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --request) method="$2"; shift 2 ;;
    --dump-header) headers="$2"; shift 2 ;;
    --output) output="$2"; shift 2 ;;
    --data-urlencode) if [[ "$2" == scope=* ]]; then scope="${2#scope=}"; fi; shift 2 ;;
    --header) if [ "$2" = "If-None-Match: *" ]; then if_none_match=true; fi; shift 2 ;;
    --user | --write-out | --retry | --data-binary) shift 2 ;;
    --get | --fail-with-body | --silent | --show-error) shift ;;
    https://*) url="$1"; shift ;;
    *) echo "unexpected curl argument: $1" >&2; exit 99 ;;
  esac
done

if [ "$url" = https://ghcr.io/token ]; then
  if [ -n "${TOKEN_SCOPE_LOG:-}" ]; then printf '%s\n' "$scope" >> "$TOKEN_SCOPE_LOG"; fi
  printf '{"token":"test-token"}'
  exit 0
fi

repository="${url#https://ghcr.io/v2/}"
repository="${repository%/manifests/*}"
reference="${url##*/}"
state_file="$STATE_DIR/${repository//\//_}"

write_headers() {
  printf 'HTTP/1.1 200 OK\r\nDocker-Content-Digest: %s\r\nContent-Type: application/vnd.oci.image.index.v1+json\r\n\r\n' "$1" > "$headers"
}

write_exact() {
  write_headers "$SOURCE_DIGEST"
  printf '%s' "$SOURCE_BODY" > "$output"
  printf '200'
}

if [ "$method" = PUT ] && [[ "$reference" == sha256:* ]] && [ "$if_none_match" = true ]; then
  printf '{}' > "$output"
  if [ "${PRECONDITION_SUPPORTED:-true}" = true ]; then printf '412'; else printf '201'; fi
elif [ "$method" = PUT ]; then
  touch "$state_file"
  printf '%s\n' "$repository" >> "$PUT_LOG"
  printf '{}' > "$output"
  printf '201'
elif [[ "$reference" == sha256:* ]]; then
  write_exact
elif [ -e "$state_file" ] || [ "$ALIAS_STATE" = exact ]; then
  write_exact
elif [ "$ALIAS_STATE" = conflict ]; then
  write_headers "$CONFLICT_DIGEST"
  printf '%s' "$CONFLICT_BODY" > "$output"
  printf '200'
else
  printf 'HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n\r\n' > "$headers"
  printf '{"errors":[{"code":"MANIFEST_UNKNOWN"}]}' > "$output"
  printf '404'
fi
