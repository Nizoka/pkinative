/**
 * The public certificates the recipes read — the committed fixtures of
 * tests/fixtures/ (PROVENANCE.md), so every recipe runs on real
 * certificates without the network.
 */
import { readFileSync } from 'node:fs';

/** The DER bytes of a fixture, e.g. `fixture('letsencrypt-org-leaf')`. */
export function fixture(name: string): Uint8Array {
    return new Uint8Array(readFileSync(new URL(`../tests/fixtures/certs/${name}.der`, import.meta.url)));
}

export const FIXTURE_NAMES = ['isrg-root-x1', 'isrg-root-x2', 'lets-encrypt-e7', 'lets-encrypt-r12', 'letsencrypt-org-leaf', 'rfc8410-x25519'] as const;
