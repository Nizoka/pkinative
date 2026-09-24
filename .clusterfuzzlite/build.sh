#!/bin/bash -eu
# pkinative — the ClusterFuzzLite build step.
#
# What the targets fuzz is `dist/`, the bytes a consumer installs, reached by
# the package's own name through the `exports` map (Node self-reference).
# `tests/fuzzing/targets.test.ts` runs the same three files against `src/`
# through vitest's alias, so the targets are proved callable and proved to
# rethrow a non-PkiError before they ever reach a container. One file, two
# engines, and the half that can be checked anywhere is checked everywhere.

cd "$SRC/pkinative"

# --ignore-scripts, the same rule as every runner and every contributor
# machine (.npmrc): no dependency's lifecycle script runs while building a
# fuzzing image either.
npm ci --ignore-scripts
npm run build

# The engine, installed into the image and never into the manifest. It is the
# only npm install in this repository that is not `npm ci` from the lockfile,
# which is exactly why it must not touch package.json: --no-save.
npm install --no-save --ignore-scripts @jazzer.js/core

# Seed corpus: the committed certificates, which are real CA roots and
# intermediates of foreign provenance (tests/fixtures/PROVENANCE.md). Starting
# a DER fuzzer from random bytes wastes days rediscovering the tag-length
# header; starting it from a structure that parses puts it inside the grammar
# on the first mutation.
for target in asn1 x509 pem; do
  zip -j "$OUT/${target}_seed_corpus.zip" tests/fixtures/certs/*.der >/dev/null
done

compile_javascript_fuzzer pkinative fuzz/asn1.js --sync
compile_javascript_fuzzer pkinative fuzz/x509.js --sync
compile_javascript_fuzzer pkinative fuzz/pem.js --sync
