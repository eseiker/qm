#!/usr/bin/env bash
set -euo pipefail

MODE="${1:?usage: scripts/release-image-aliases.sh <check|publish|verify> <manifest> <version>}"
MANIFEST="${2:?usage: scripts/release-image-aliases.sh <check|publish|verify> <manifest> <version>}"
VERSION="${3:?usage: scripts/release-image-aliases.sh <check|publish|verify> <manifest> <version>}"
GH_TOKEN="${GH_TOKEN:?GH_TOKEN is required}"
GITHUB_ACTOR="${GITHUB_ACTOR:?GITHUB_ACTOR is required}"

case "$MODE" in
  check | publish | verify) ;;
  *) echo "mode must be check, publish, or verify" >&2; exit 1 ;;
esac

if [[ ! "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "version must be stable semver, got $VERSION" >&2
  exit 1
fi

jq -e -s '
  def service_name:
    type == "string" and test("^[a-z0-9]+(?:-[a-z0-9]+)*$");
  def digest:
    type == "string"
    and test("^sha256:[0-9a-f]{64}$")
    and (test("^sha256:(.)\\1{63}$") | not);
  def image_ref($service):
    type == "string"
    and (split("@") as $parts
      | ($parts | length) == 2
      and $parts[0] == ("ghcr.io/yc-software/qm/" + $service)
      and ($parts[1] | digest));
  length == 1
  and (.[0]
    | type == "object"
    and keys == ["sandboxBase", "services"]
    and (.sandboxBase | image_ref("sandbox-base"))
    and (.services | type == "object" and length > 0 and (has("sandbox-base") | not))
    and all(.services | to_entries[];
      . as $entry
      | ($entry.key | service_name)
        and ($entry.value | image_ref($entry.key))))' \
  "$MANIFEST" > /dev/null

TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT
ACCEPT='application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json'
SERVICES=()
while IFS= read -r service; do
  SERVICES+=("$service")
done < <(jq -r '["sandbox-base"] + (.services | keys) | .[]' "$MANIFEST")

registry_token() {
  local repository_path="$1"
  local actions=pull
  if [ "$MODE" = publish ]; then actions=pull,push; fi
  curl --fail-with-body --silent --show-error --retry 0 \
    --user "$GITHUB_ACTOR:$GH_TOKEN" \
    --get \
    --data-urlencode service=ghcr.io \
    --data-urlencode "scope=repository:$repository_path:$actions" \
    https://ghcr.io/token | jq -er '.token | strings'
}

request_manifest() {
  local repository_path="$1"
  local reference="$2"
  local token="$3"
  local prefix="$4"
  if HTTP_STATUS=$(curl --silent --show-error --retry 0 \
      --request GET \
      --header "Authorization: Bearer $token" \
      --header "Accept: $ACCEPT" \
      --dump-header "$prefix.headers" \
      --output "$prefix.body" \
      --write-out '%{http_code}' \
      "https://ghcr.io/v2/$repository_path/manifests/$reference"); then
    CURL_STATUS=0
  else
    CURL_STATUS=$?
  fi
}

header_value() {
  local name="$1"
  local file="$2"
  awk -v expected="$name:" '
    tolower($1) == tolower(expected) { gsub("\r", "", $2); value=$2 }
    END { print value }
  ' "$file"
}

verify_manifest() {
  local prefix="$1"
  local expected_digest="$2"
  local header_digest
  local body_digest
  local media_type
  header_digest=$(header_value Docker-Content-Digest "$prefix.headers")
  body_digest="sha256:$(sha256sum "$prefix.body" | cut -d ' ' -f 1)"
  media_type=$(header_value Content-Type "$prefix.headers")
  if [ "$header_digest" != "$expected_digest" ] || [ "$body_digest" != "$expected_digest" ]; then
    echo "registry manifest digest is $header_digest/$body_digest, expected $expected_digest" >&2
    return 1
  fi
  case "$media_type" in
    application/vnd.oci.image.index.v1+json | application/vnd.docker.distribution.manifest.list.v2+json) ;;
    *) echo "registry returned unsupported manifest type $media_type" >&2; return 1 ;;
  esac
}

require_create_precondition() {
  local repository_path="$1"
  local token="$2"
  local digest="$3"
  local source_prefix="$4"
  local probe_prefix="$5"
  local media_type
  local probe_status
  local probe_curl_status
  media_type=$(header_value Content-Type "$source_prefix.headers")
  if probe_status=$(curl --silent --show-error --retry 0 \
      --request PUT \
      --header "Authorization: Bearer $token" \
      --header "Content-Type: $media_type" \
      --header 'If-None-Match: *' \
      --data-binary "@$source_prefix.body" \
      --output "$probe_prefix.body" \
      --write-out '%{http_code}' \
      "https://ghcr.io/v2/$repository_path/manifests/$digest"); then
    probe_curl_status=0
  else
    probe_curl_status=$?
  fi
  if [ "$probe_curl_status" -ne 0 ] || [ "$probe_status" != 412 ]; then
    echo "registry does not enforce create-only manifest writes for $repository_path: curl $probe_curl_status, HTTP $probe_status" >&2
    cat "$probe_prefix.body" >&2
    return 1
  fi
}

alias_state() {
  local repository_path="$1"
  local token="$2"
  local expected_digest="$3"
  local prefix="$4"
  request_manifest "$repository_path" "$VERSION" "$token" "$prefix"
  if [ "$CURL_STATUS" -ne 0 ]; then return 30; fi
  if [ "$HTTP_STATUS" = 200 ]; then
    if verify_manifest "$prefix" "$expected_digest"; then return 0; fi
    return 20
  fi
  if [ "$HTTP_STATUS" = 404 ] &&
    jq -e '(.errors | type == "array") and any(.errors[]; .code == "MANIFEST_UNKNOWN")' \
      "$prefix.body" > /dev/null; then
    return 10
  fi
  echo "registry returned HTTP $HTTP_STATUS for $repository_path:$VERSION" >&2
  cat "$prefix.body" >&2
  return 30
}

for service in "${SERVICES[@]}"; do
  if [ "$service" = sandbox-base ]; then
    ref=$(jq -er '.sandboxBase | strings' "$MANIFEST")
  else
    ref=$(jq -er --arg service "$service" '.services[$service] | strings' "$MANIFEST")
  fi
  repository="${ref%@*}"
  repository_path="${repository#ghcr.io/}"
  digest="${ref##*@}"
  version_alias="$repository:$VERSION"
  token=$(registry_token "$repository_path")
  source_prefix="$TEMP_DIR/$service-source"
  request_manifest "$repository_path" "$digest" "$token" "$source_prefix"
  if [ "$CURL_STATUS" -ne 0 ] || [ "$HTTP_STATUS" != 200 ]; then
    echo "could not read released image $ref: curl $CURL_STATUS, HTTP $HTTP_STATUS" >&2
    cat "$source_prefix.body" >&2
    exit 1
  fi
  verify_manifest "$source_prefix" "$digest"

  alias_prefix="$TEMP_DIR/$service-alias"
  if alias_state "$repository_path" "$token" "$digest" "$alias_prefix"; then
    state=0
  else
    state=$?
  fi
  if [ "$state" -eq 0 ]; then continue; fi
  if [ "$state" -ne 10 ]; then
    echo "$version_alias is not safely publishable" >&2
    exit 1
  fi
  if [ "$MODE" = check ]; then continue; fi
  if [ "$MODE" = verify ]; then
    echo "$version_alias does not exist at the released digest" >&2
    exit 1
  fi

  require_create_precondition "$repository_path" "$token" "$digest" "$source_prefix" \
    "$TEMP_DIR/$service-precondition"
  media_type=$(header_value Content-Type "$source_prefix.headers")
  put_prefix="$TEMP_DIR/$service-put"
  if put_status=$(curl --silent --show-error --retry 0 \
      --request PUT \
      --header "Authorization: Bearer $token" \
      --header "Content-Type: $media_type" \
      --header 'If-None-Match: *' \
      --data-binary "@$source_prefix.body" \
      --output "$put_prefix.body" \
      --write-out '%{http_code}' \
      "https://ghcr.io/v2/$repository_path/manifests/$VERSION"); then
    put_curl_status=0
  else
    put_curl_status=$?
  fi

  verified=false
  for delay in 0 1 2; do
    if [ "$delay" -ne 0 ]; then sleep "$delay"; fi
    if alias_state "$repository_path" "$token" "$digest" "$alias_prefix"; then
      state=0
    else
      state=$?
    fi
    if [ "$state" -eq 0 ]; then
      verified=true
      break
    fi
    if [ "$state" -eq 20 ]; then break; fi
  done
  if [ "$verified" != true ]; then
    echo "could not publish exact alias $version_alias: curl $put_curl_status, HTTP $put_status" >&2
    cat "$put_prefix.body" >&2
    exit 1
  fi
done
