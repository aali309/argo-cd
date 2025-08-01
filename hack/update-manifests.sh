#! /usr/bin/env bash
set -x
set -o errexit
set -o nounset
set -o pipefail

SRCROOT="$( CDPATH='' cd -- "$(dirname "$0")/.." && pwd -P )"
AUTOGENMSG="# This is an auto-generated file. DO NOT EDIT"

KUSTOMIZE=kustomize
[ -f "$SRCROOT/dist/kustomize" ] && KUSTOMIZE="$SRCROOT/dist/kustomize"

cd "${SRCROOT}/manifests/ha/base/redis-ha" && ./generate.sh

IMAGE_NAMESPACE="${IMAGE_NAMESPACE:-quay.io/argoproj}"
IMAGE_TAG="${IMAGE_TAG:-}"

# if the tag has not been declared, and we are on a release branch, use the VERSION file.
if [ "$IMAGE_TAG" = "" ]; then
  branch=$(git rev-parse --abbrev-ref HEAD)
  if [[ $branch = release-* ]]; then
    pwd
    IMAGE_TAG=v$(cat "$SRCROOT/VERSION")
  fi
fi
# otherwise, use latest
if [ "$IMAGE_TAG" = "" ]; then
  IMAGE_TAG=latest
fi

$KUSTOMIZE version
which "$KUSTOMIZE"

cd "${SRCROOT}/manifests/base" && $KUSTOMIZE edit set image "quay.io/argoproj/argocd=${IMAGE_NAMESPACE}/argocd:${IMAGE_TAG}"
cd "${SRCROOT}/manifests/ha/base" && $KUSTOMIZE edit set image "quay.io/argoproj/argocd=${IMAGE_NAMESPACE}/argocd:${IMAGE_TAG}"
cd "${SRCROOT}/manifests/core-install" && $KUSTOMIZE edit set image "quay.io/argoproj/argocd=${IMAGE_NAMESPACE}/argocd:${IMAGE_TAG}"

# Because commit-server is added as a resource outside the base, we have to explicitly set the image override here.
# If/when commit-server is added to the base, this can be removed.
cd "${SRCROOT}/manifests/base/commit-server" && $KUSTOMIZE edit set image "quay.io/argoproj/argocd=${IMAGE_NAMESPACE}/argocd:${IMAGE_TAG}"

echo "${AUTOGENMSG}" > "${SRCROOT}/manifests/install.yaml"
$KUSTOMIZE build "${SRCROOT}/manifests/cluster-install" >> "${SRCROOT}/manifests/install.yaml"

echo "${AUTOGENMSG}" > "${SRCROOT}/manifests/namespace-install.yaml"
$KUSTOMIZE build "${SRCROOT}/manifests/namespace-install" >> "${SRCROOT}/manifests/namespace-install.yaml"

echo "${AUTOGENMSG}" > "${SRCROOT}/manifests/ha/install.yaml"
$KUSTOMIZE build "${SRCROOT}/manifests/ha/cluster-install" >> "${SRCROOT}/manifests/ha/install.yaml"

echo "${AUTOGENMSG}" > "${SRCROOT}/manifests/ha/namespace-install.yaml"
$KUSTOMIZE build "${SRCROOT}/manifests/ha/namespace-install" >> "${SRCROOT}/manifests/ha/namespace-install.yaml"

echo "${AUTOGENMSG}" > "${SRCROOT}/manifests/core-install.yaml"
$KUSTOMIZE build "${SRCROOT}/manifests/core-install" >> "${SRCROOT}/manifests/core-install.yaml"

# Copies enabling manifest hydrator. These can be removed once the manifest hydrator is either removed or enabled by
# default.

echo "${AUTOGENMSG}" > "${SRCROOT}/manifests/install-with-hydrator.yaml"
$KUSTOMIZE build "${SRCROOT}/manifests/cluster-install-with-hydrator" >> "${SRCROOT}/manifests/install-with-hydrator.yaml"

echo "${AUTOGENMSG}" > "${SRCROOT}/manifests/namespace-install-with-hydrator.yaml"
$KUSTOMIZE build "${SRCROOT}/manifests/namespace-install-with-hydrator" >> "${SRCROOT}/manifests/namespace-install-with-hydrator.yaml"

echo "${AUTOGENMSG}" > "${SRCROOT}/manifests/ha/install-with-hydrator.yaml"
$KUSTOMIZE build "${SRCROOT}/manifests/ha/cluster-install-with-hydrator" >> "${SRCROOT}/manifests/ha/install-with-hydrator.yaml"

echo "${AUTOGENMSG}" > "${SRCROOT}/manifests/ha/namespace-install-with-hydrator.yaml"
$KUSTOMIZE build "${SRCROOT}/manifests/ha/namespace-install-with-hydrator" >> "${SRCROOT}/manifests/ha/namespace-install-with-hydrator.yaml"

echo "${AUTOGENMSG}" > "${SRCROOT}/manifests/core-install-with-hydrator.yaml"
$KUSTOMIZE build "${SRCROOT}/manifests/core-install-with-hydrator" >> "${SRCROOT}/manifests/core-install-with-hydrator.yaml"
