/**
 * pkinative — URI grammar
 * =======================
 * RFC 3986 and RFC 4516, read by their ABNF rather than by a URL library that
 * normalises. Two layers ask the same questions of the same strings: `x509/`
 * reports a uniformResourceIdentifier that breaks RFC 5280 §4.2.1.6, and
 * `path/` evaluates a §4.2.1.10 name constraint against the host of one.
 * Both read the grammar here, so a URI cannot be well formed for one and
 * malformed for the other.
 *
 * Nothing here decodes a percent-encoding or folds case: every answer is
 * about the characters as written, which is what is signed.
 *
 * @module core/uri
 */

// ── RFC 3986 character classes ──────────────────────────────────────

/** §2.2 sub-delims and §2.3 unreserved, as the inside of a character class. */
const UNRESERVED_SUB_DELIMS = "A-Za-z0-9\\-._~!$&'()*+,;=";
/** §3.3 `pchar = unreserved / pct-encoded / sub-delims / ":" / "@"`, and `/`. */
const PATH = /*#__PURE__*/ new RegExp(`^(?:[${UNRESERVED_SUB_DELIMS}:@/]|%[0-9A-Fa-f]{2})*$`);
/** §3.4 and §3.5: `query = fragment = *( pchar / "/" / "?" )`. */
const QUERY = /*#__PURE__*/ new RegExp(`^(?:[${UNRESERVED_SUB_DELIMS}:@/?]|%[0-9A-Fa-f]{2})*$`);
/** §3.2.1 `userinfo = *( unreserved / pct-encoded / sub-delims / ":" )`. */
const USERINFO = /*#__PURE__*/ new RegExp(`^(?:[${UNRESERVED_SUB_DELIMS}:]|%[0-9A-Fa-f]{2})*$`);
/** §3.2.2 `reg-name = *( unreserved / pct-encoded / sub-delims )`. */
const REG_NAME = /*#__PURE__*/ new RegExp(`^(?:[${UNRESERVED_SUB_DELIMS}]|%[0-9A-Fa-f]{2})*$`);
/** §3.2.2 `IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )`. */
const IP_FUTURE = /*#__PURE__*/ new RegExp(`^[vV][0-9A-Fa-f]+\\.[${UNRESERVED_SUB_DELIMS}:]+$`);
/** §3.1 `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`, with its colon. */
const SCHEME = /^([A-Za-z][A-Za-z0-9+.-]*):/;
/** §3.2.3 `port = *DIGIT`. */
const PORT = /^[0-9]*$/;
/** §3.2.2 `dec-octet`, four of them. */
const IPV4 = /^(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$/;
const H16 = /^[0-9A-Fa-f]{1,4}$/;

/** Whether `text` is an RFC 3986 §3.2.2 `IPv4address`. */
function _isIpv4(text: string): boolean {
    return IPV4.test(text);
}

/**
 * Whether `text` is an RFC 3986 §3.2.2 `IPv6address`: eight 16-bit groups, or
 * fewer around exactly one `::`, the last two of which may be written as an
 * IPv4 address.
 */
function _isIpv6(text: string): boolean {
    let groups = text;
    const tail = text.slice(text.lastIndexOf(':') + 1);
    if (tail.includes('.')) {
        // ls32 as an IPv4address stands for the last two groups. Without a
        // colon at all the result has two groups, which no form accepts.
        if (!_isIpv4(tail)) return false;
        groups = text.replace(/[^:]*$/, '0:0');
    }
    const halves = groups.split('::');
    if (halves.length > 2) return false;
    const fields = halves.flatMap((half) => (half === '' ? [] : half.split(':')));
    if (!fields.every((field) => H16.test(field))) return false;
    return halves.length === 2 ? fields.length <= 7 : fields.length === 8;
}

// ── The parts of a URI ───────────────────────────────────────────────

/** A URI cut at its RFC 3986 §3 delimiters, before any of the parts is judged. */
interface _UriParts {
    /** The authority after `//`, or null when the hier-part has none. */
    readonly authority: string | null;
    readonly path: string;
    /** Everything after the first `?`, a later `?` included, which the query alphabet allows. */
    readonly query: string;
    /** Everything after the first `#`, a later `#` included, which the fragment alphabet then refuses. */
    readonly fragment: string;
}

function _split(uri: string): _UriParts | null {
    const scheme = SCHEME.exec(uri);
    if (scheme === null) return null;
    const [beforeFragment, ...fragment] = uri.slice(scheme[0].length).split('#') as [string, ...string[]];
    const [hierPart, ...query] = beforeFragment.split('?') as [string, ...string[]];
    const hier = /^\/\/([^/]*)(.*)$/s.exec(hierPart);
    return {
        authority: hier === null ? null : hier[1] as string,
        path: hier === null ? hierPart : hier[2] as string,
        query: query.join('?'),
        fragment: fragment.join('#'),
    };
}

/**
 * The userinfo, host and port of an authority: the userinfo ends at the
 * first `@`, the port starts at the first `:` after the host. An IP literal
 * keeps its brackets; one that does not close, or is followed by anything
 * but a port, is returned whole as the host, which no host rule accepts.
 */
function _authorityHost(authority: string): { readonly userinfo: string; readonly host: string; readonly port: string } {
    const parts = /^(?:([^@]*)@)?(.*)$/s.exec(authority) as RegExpExecArray;
    const userinfo = parts[1] ?? '';
    const hostAndPort = parts[2] as string;
    const literal = /^(\[[^\]]*\])(?::(.*))?$/s.exec(hostAndPort);
    if (literal !== null) return { userinfo, host: literal[1] as string, port: literal[2] ?? '' };
    if (hostAndPort.startsWith('[')) return { userinfo, host: hostAndPort, port: '' };
    const plain = /^([^:]*)(?::(.*))?$/s.exec(hostAndPort) as RegExpExecArray;
    return { userinfo, host: plain[1] as string, port: plain[2] ?? '' };
}

/**
 * Whether `text` is an RFC 3986 §3 `URI`: a scheme, a hier-part, an optional
 * query and an optional fragment, every character one the grammar allows in
 * its place and every `%` the start of a `pct-encoded`.
 *
 * A relative reference (§4.2) has no scheme and is not a URI, which is what
 * RFC 5280 §4.2.1.6 refuses when it says *"The name MUST NOT be a relative
 * URI"*. An empty hier-part (`urn:`) is a URI by this grammar.
 *
 * @param text The string to read.
 * @returns True when the whole string matches the `URI` production.
 */
export function isUri(text: string): boolean {
    const parts = _split(text);
    if (parts === null || !PATH.test(parts.path) || !QUERY.test(parts.query) || !QUERY.test(parts.fragment)) return false;
    if (parts.authority === null) return true;
    const { userinfo, host, port } = _authorityHost(parts.authority);
    if (!USERINFO.test(userinfo) || !PORT.test(port)) return false;
    if (host.startsWith('[')) {
        const literal = host.slice(1, -1);
        return host.endsWith(']') && (_isIpv6(literal) || IP_FUTURE.test(literal));
    }
    return REG_NAME.test(host);
}

/**
 * The scheme of `text` and what follows its colon, or null when it has no
 * scheme: RFC 5280 §4.2.1.6 asks for *"both a scheme … and a
 * scheme-specific-part"*.
 *
 * @param text The string to read.
 * @returns The scheme as written and the rest of the string.
 */
export function uriScheme(text: string): { readonly scheme: string; readonly specific: string } | null {
    const scheme = SCHEME.exec(text);
    return scheme === null ? null : { scheme: scheme[1] as string, specific: text.slice(scheme[0].length) };
}

/**
 * Whether `host` is a fully qualified domain name in RFC 1034 §3.5 preferred
 * name syntax, as RFC 1123 §2.1 relaxes it: labels of letters, digits and
 * hyphens, 1 to 63 octets, none beginning or ending with a hyphen, at most
 * 253 octets in all, written without the trailing dot.
 *
 * @param host The host to judge.
 * @returns True for a name such as `crl.example.com`.
 */
export function isFqdn(host: string): boolean {
    // The empty name is one empty label, which the label rule refuses.
    if (host.length > 253) return false;
    return host.split('.').every((label) => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label));
}

/**
 * The host of a URI that has an authority (RFC 3986 §3.2), as written, or
 * null when it has none — `mailto:`, `urn:`, or no scheme at all.
 *
 * Lenient on purpose: it cuts the authority at its delimiters without
 * judging the rest of the URI, so that the host can be judged on its own
 * (RFC 5280 §4.2.1.6: *"URIs that include an authority … MUST include a
 * fully qualified domain name or IP address as the host"*).
 *
 * @param uri The URI to read.
 * @returns The host, brackets kept on an IP literal.
 */
export function uriAuthorityHost(uri: string): string | null {
    const authority = _split(uri)?.authority;
    return authority === undefined || authority === null ? null : _authorityHost(authority).host;
}

/**
 * Whether `host` is a fully qualified domain name or an IP address: an
 * `IPv4address`, or an `IPv6address` inside the brackets of an IP literal.
 *
 * @param host A host as `uriAuthorityHost` returns it.
 * @returns True when RFC 5280 §4.2.1.6 accepts it as the host of a URI.
 */
export function isFqdnOrIpHost(host: string): boolean {
    if (host.startsWith('[') && host.endsWith(']')) return _isIpv6(host.slice(1, -1));
    return _isIpv4(host) || isFqdn(host);
}

// ── The host a name constraint is checked against ────────────────────

/** RFC 3986 §3.1 `scheme ":"`, followed by the `"//"` that opens an authority (§3.2). */
const URI_SCHEME_AND_AUTHORITY = /^[A-Za-z][A-Za-z0-9+.-]*:\/\//;
/** Every character RFC 3986 §2 lets a URI hold — reserved, unreserved, and `%` only as `pct-encoded`. */
const URI_CHARACTERS = /^(?:[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=]|%[0-9A-Fa-f]{2})*$/;
/** RFC 3986 §3.2.1 `userinfo = *( unreserved / pct-encoded / sub-delims / ":" )` — no `@`. */
const URI_USERINFO = /^(?:[A-Za-z0-9\-._~!$&'()*+,;=:]|%[0-9A-Fa-f]{2})*$/;
/**
 * RFC 3986 §3.2.2 `reg-name`, **without** `pct-encoded`: RFC 5280 §4.2.1.6 asks
 * for a fully qualified domain name as the host, and a percent in a host is a
 * name that each decoder reads differently.
 */
const URI_REG_NAME = /^[A-Za-z0-9\-._~!$&'()*+,;=]+$/;
/** RFC 3986 §3.2.2 `IP-literal` as an IPv6 address: hex digits, colons and dots — no zone, no `IPvFuture`. */
const URI_IP_LITERAL = /^\[[0-9A-Fa-f:.]+\]$/;
/** RFC 3986 §3.2.3 `":" port`, or nothing. */
const URI_PORT = /^(?::[0-9]*)?$/;

/**
 * The host of a URI, or null when there is no authority to constrain or the
 * authority is not RFC 3986's.
 *
 * Read by the grammar, not cut at the last `@`: `https://evil.test\@good.example.com/`
 * is not a URI (a backslash is no URI character), and a WHATWG parser reads its
 * host as `evil.test` where cutting reads `good.example.com` — a constraint
 * checked against a host the client never connects to (CWE-436). So every
 * character must be one RFC 3986 allows, the userinfo holds no `@`, the host is
 * a `reg-name` without percent-encoding or an IPv6 literal, and anything after
 * the host is a port. Anything else has no host both sides agree on, and a
 * constrained URI form refuses it.
 *
 * @param uri The URI to read.
 * @returns The host as written, or null.
 */
export function uriHost(uri: string): string | null {
    const scheme = URI_SCHEME_AND_AUTHORITY.exec(uri);
    if (scheme === null || !URI_CHARACTERS.test(uri)) return null;
    // The authority runs to the first "/", "?" or "#", or to the end.
    const authority = uri.slice(scheme[0].length).split(/[/?#]/, 1)[0] as string;
    // Userinfo is everything before the first "@", and holds no "@" itself:
    // a second one lands in the host, which refuses it.
    const at = authority.indexOf('@');
    if (!URI_USERINFO.test(authority.slice(0, Math.max(at, 0)))) return null;
    const hostAndPort = authority.slice(at + 1);
    if (hostAndPort.startsWith('[')) {
        // An IPv6 literal keeps its brackets, which never match a
        // dNSName-style constraint, and is not split on its own colons.
        const close = hostAndPort.indexOf(']') + 1;
        const literal = hostAndPort.slice(0, close);
        return URI_IP_LITERAL.test(literal) && URI_PORT.test(hostAndPort.slice(close)) ? literal : null;
    }
    const host = hostAndPort.split(':', 1)[0] as string;
    return URI_REG_NAME.test(host) && URI_PORT.test(hostAndPort.slice(host.length)) ? host : null;
}

// ── RFC 4516 LDAP URLs ───────────────────────────────────────────────

/**
 * The `<dn>` and `<attributes>` of an RFC 4516 §2 LDAP URL, or null when
 * `text` is not one — when its scheme is not `ldap`.
 *
 * `ldapurl = scheme COLON SLASH SLASH [host [COLON port]] [SLASH dn
 * [QUESTION [attributes] [QUESTION …]]]`. A field that is not there is
 * `undefined`; one that is there and empty is `''`. Neither is decoded:
 * RFC 5280 §4.2.1.13 and §4.2.2.1 ask whether the fields are present, not
 * what their percent-encoding spells.
 *
 * @param text The URI to read.
 * @returns The two fields, as written, or null.
 */
export function ldapUrlFields(text: string): { readonly dn: string | undefined; readonly attributes: string | undefined } | null {
    const scheme = uriScheme(text);
    if (scheme?.scheme.toLowerCase() !== 'ldap') return null;
    // The hostport runs to the first "/", after which come the dn and the "?"-separated fields.
    const url = /^\/\/[^/]*(?:\/(.*))?$/s.exec(scheme.specific);
    if (url === null) return null;
    if (url[1] === undefined) return { dn: undefined, attributes: undefined };
    const [dn, attributes] = url[1].split('?');
    return { dn, attributes };
}

/**
 * Whether `text` is an `http` or `ldap` URI — the two RFC 5280 §4.2.1.13,
 * §4.2.2.1 and §4.2.2.2 ask a CA to offer at least one of. The scheme is
 * compared without case (RFC 3986 §3.1); `https` and `ldaps` are other
 * schemes.
 *
 * @param text The URI to read.
 * @returns True for `http:` and `ldap:` URIs.
 */
export function isHttpOrLdapUri(text: string): boolean {
    const scheme = uriScheme(text)?.scheme.toLowerCase();
    return scheme === 'http' || scheme === 'ldap';
}
