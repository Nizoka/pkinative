#!/bin/bash -eu
# pkinative — the ClusterFuzzLite build step.
#
# What the targets fuzz is `dist/`, the bytes a consumer installs, reached by
# the package's own name through the `exports` map (Node self-reference).
# `tests/fuzzing/targets.test.ts` runs the same files against `src/` through
# vitest's alias, so the targets are proved callable and proved to rethrow a
# non-PkiError before they ever reach a container. One file, two engines,
# and the half that can be checked anywhere is checked everywhere.

cd "$SRC/pkinative"

# --ignore-scripts, the same rule as every runner and every contributor
# machine (.npmrc): no dependency's lifecycle script runs while building a
# fuzzing image either.
npm ci --ignore-scripts
npm run build

# Seed corpora. The committed certificates (real CA roots and intermediates
# of foreign provenance, tests/fixtures/PROVENANCE.md) plus the structures
# tests/fuzzing/_fuzz-seeds.ts builds — a CRL, an OCSP response, a
# SignedData, a timestamp, a PFX — because the committed fixtures are all
# certificates, and an OCSP response is a long way from one in mutation
# distance. Starting a DER fuzzer from random bytes wastes days rediscovering
# the tag-length header; starting it from a structure that parses puts it
# inside the grammar on the first mutation. targets.test.ts proves every
# seed parses, on every gate run.
seeds="$(mktemp -d)"
npx tsx tests/fuzzing/_fuzz-seeds.ts "$seeds"
for target in asn1 cms crl ocsp pem pkcs12 tsp x509; do
  zip -j "$OUT/${target}_seed_corpus.zip" tests/fixtures/certs/*.der "$seeds/$target"/*.der >/dev/null
done

# The engine, never in the manifest. .clusterfuzzlite/engine/package.json
# names one exact version, and its package-lock.json pins every package of
# the engine's tree to a version and a sha512 integrity that `npm ci` checks
# before it unpacks anything — no range, no resolution at build time, the
# same supply-chain rule as the project's own lockfile. The project's
# node_modules is then replaced by the engine's: the targets import only
# `dist/`, which has no dependency, and the OSS-Fuzz wrapper runs
# `<project>/node_modules/@jazzer.js/core/dist/cli.js`.
(cd .clusterfuzzlite/engine && npm ci --ignore-scripts)
rm -rf node_modules
mv .clusterfuzzlite/engine/node_modules node_modules

compile_javascript_fuzzer pkinative fuzz/asn1.js --sync
compile_javascript_fuzzer pkinative fuzz/cms.js --sync
compile_javascript_fuzzer pkinative fuzz/crl.js --sync
compile_javascript_fuzzer pkinative fuzz/ocsp.js --sync
compile_javascript_fuzzer pkinative fuzz/pem.js --sync
compile_javascript_fuzzer pkinative fuzz/pkcs12.js --sync
compile_javascript_fuzzer pkinative fuzz/tsp.js --sync
compile_javascript_fuzzer pkinative fuzz/x509.js --sync
