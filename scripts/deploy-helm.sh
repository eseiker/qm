#!/usr/bin/env bash
set -euo pipefail

REPO="${1:?usage: scripts/deploy-helm.sh <image-repo-prefix> [tag]   e.g. scripts/deploy-helm.sh ghcr.io/<org>/qm}"
RELEASE="${QM_RELEASE:-qm}"
NAMESPACE="${QM_NAMESPACE:-qm}"
PLATFORM="${QM_PLATFORM:-linux/amd64}"
DEPLOY="${QM_DEPLOY:-1}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAG="${2:-}"
CHART_NS="${REPO%/*}"
GIT_SHA=""
SOURCE_CLEAN=false

if git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git_status="$(git -C "$ROOT" status --porcelain)"
  if [ -z "$git_status" ]; then
    SOURCE_CLEAN=true
    GIT_SHA="$(git -C "$ROOT" rev-parse HEAD)"
  fi
fi

if [ -z "$TAG" ]; then
  if [ "$SOURCE_CLEAN" != true ]; then
    echo "an explicit development image tag is required for modified or non-git QM source" >&2
    exit 1
  fi
  TAG="$GIT_SHA"
elif [ "$SOURCE_CLEAN" != true ]; then
  if [[ "$TAG" =~ ^[0-9A-Fa-f]{7,40}$ ]] \
    || [[ "$TAG" =~ ^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$ ]]; then
    echo "modified or non-git QM source requires a clearly non-commit development image tag" >&2
    exit 1
  fi
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
SOURCE_ROOT="$ROOT"
if [ "$SOURCE_CLEAN" = true ]; then
  SOURCE_ROOT="$WORK_DIR/source"
  mkdir -p "$SOURCE_ROOT"
  git -C "$ROOT" archive --format=tar HEAD | tar -xf - -C "$SOURCE_ROOT"
fi
CHART="$SOURCE_ROOT/deploy/helm"
VERSION="$(node -p 'require(process.argv[1]).version' "$SOURCE_ROOT/cli/package.json")"

if [[ ! "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "cli/package.json must contain a stable version, got $VERSION" >&2
  exit 1
fi

if [ -n "$GIT_SHA" ] && [[ ! "$GIT_SHA" =~ ^[a-f0-9]{40}$ ]]; then
  echo "git HEAD must be a full lowercase commit SHA, got $GIT_SHA" >&2
  exit 1
fi

PUBLISH_CHART="$SOURCE_CLEAN"
if [ "$SOURCE_CLEAN" = true ] && [ "$TAG" = "$VERSION" ]; then
  CHART_VERSION="$VERSION"
elif [ "$SOURCE_CLEAN" = true ]; then
  tag_id="$(node -p 'require("node:crypto").createHash("sha256").update(process.argv[1]).digest("hex").slice(0, 16)' "$TAG")"
  CHART_VERSION="$VERSION-build.git-$GIT_SHA.tag-$tag_id"
else
  build_id="$(node -p 'require("node:crypto").randomBytes(16).toString("hex")')"
  CHART_VERSION="$VERSION-dev.build-$build_id"
fi

SERVICES=(core auth web-ui admin portal egress-proxy)

for svc in "${SERVICES[@]}"; do
  image="$REPO/$svc:$TAG"
  build_options=(--platform "$PLATFORM")
  if [[ "$svc" == core && -n "$GIT_SHA" ]]; then build_options+=(--build-arg "GIT_SHA=$GIT_SHA"); fi
  echo ">> building $image from deploy/$svc/Dockerfile"
  docker build \
    "${build_options[@]}" \
    -t "$image" \
    -f "$SOURCE_ROOT/deploy/$svc/Dockerfile" \
    "$SOURCE_ROOT"
  echo ">> pushing $image"
  docker push "$image"
done

echo ">> packaging chart"
PKG_DIR="$WORK_DIR/package"
mkdir -p "$PKG_DIR"
helm package "$CHART" --version "$CHART_VERSION" --app-version "$TAG" --destination "$PKG_DIR" >/dev/null
packages=("$PKG_DIR"/*.tgz)
if [ "${#packages[@]}" -ne 1 ] || [ ! -f "${packages[0]}" ]; then
  echo "helm package must produce exactly one chart archive" >&2
  exit 1
fi
PACKAGE="${packages[0]}"
EXPECTED_PACKAGE="$PKG_DIR/qm-$CHART_VERSION.tgz"
if [ "$PACKAGE" != "$EXPECTED_PACKAGE" ]; then
  echo "helm package produced $PACKAGE, expected $EXPECTED_PACKAGE" >&2
  exit 1
fi
if [ "$PUBLISH_CHART" = true ]; then
  echo ">> pushing chart to oci://$CHART_NS"
  helm push "$PACKAGE" "oci://$CHART_NS"
  chart_destination="oci://$CHART_NS"
else
  echo ">> modified or non-git source: not publishing the prerelease chart"
  chart_destination="local deployment only"
fi

if [ "$DEPLOY" = "1" ]; then
  echo ">> deploying release '$RELEASE' to namespace '$NAMESPACE'"
  helm upgrade --install "$RELEASE" "$PACKAGE" \
    --namespace "$NAMESPACE" \
    --create-namespace \
    --set image.repository="$REPO" \
    --set image.tag="$TAG"
else
  echo ">> QM_DEPLOY=0, skipping in-cluster deploy"
fi

echo ">> done: chart $chart_destination @ chart $(helm show chart "$PACKAGE" | awk '/^version:/{print $2}'), images @ $TAG"
