# pkinative — the ClusterFuzzLite build image.
#
# Jazzer.js is installed HERE and never in package.json. That is the whole
# reason this directory exists in this shape: the zero-dependency promise is
# a property of what `npm install pkinative` puts in a consumer's tree, and
# an engine that lives only inside a build image cannot reach it. The
# `no runtime, peer, optional or bundled dependency` assertion in
# tests/tools/workflows.test.ts keeps that true from the other side.
#
# The base image is pinned by digest, like every action in .github/workflows.
# Nothing bumps it automatically — Dependabot does not watch gcr.io — so it
# is a deliberate, reviewed edit. Resolve a new one with:
#   curl -sI -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
#     https://gcr.io/v2/oss-fuzz-base/base-builder-javascript/manifests/latest \
#     | grep -i docker-content-digest
FROM gcr.io/oss-fuzz-base/base-builder-javascript@sha256:abb373b596ba4238718641c6006f77f3281d66914c55ebf51ae4d57f52af9942

COPY . $SRC/pkinative
COPY .clusterfuzzlite/build.sh $SRC/build.sh
WORKDIR $SRC/pkinative
