/**
 * pkinative — OID name lookup
 * ===========================
 * A `Map` over the registry, built once when the module loads. The map is
 * fixed-size data, never a cache that grows with input.
 *
 * @module oid/oid-names
 */

import { OID_REGISTRY, type OidRegistryEntry } from './oid-registry.js';

function indexByOid(entries: readonly OidRegistryEntry[]): ReadonlyMap<string, string> {
    const map = new Map<string, string>();
    for (const entry of entries) map.set(entry.oid, entry.name);
    return map;
}

const NAME_BY_OID: ReadonlyMap<string, string> = /*#__PURE__*/ indexByOid(OID_REGISTRY);

/**
 * The display name of a registered object identifier.
 *
 * @param oid A dotted-decimal OID, e.g. `2.5.29.17`.
 * @returns The registered name (`subjectAltName`), or `undefined` for an OID
 *   the registry does not list and for any argument that is not a string.
 * @throws Never — an unknown or malformed OID is simply not registered.
 */
export function getOidName(oid: string): string | undefined {
    return typeof oid === 'string' ? NAME_BY_OID.get(oid) : undefined;
}
