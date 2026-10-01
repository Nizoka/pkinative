"""pkinative — the python-cryptography reader (pyca/cryptography, Rust lineage).

Two modes, one program, so the reader the interoperability matrix trusts is
the reader conformance level L4 confronts:

  python python-cryptography.py l4 <blob> <out.ndjson>
      Conformance level L4: read the PKIBLOB1 file scripts/lib/validators.ts
      writes and answer in its NDJSON contract (schema 1).

  python python-cryptography.py interop <manifest.json> <out.ndjson>
      The interoperability matrix, write direction: read every artefact the
      manifest lists (scripts/lib/interop-artefacts.ts) and report what this
      library makes of it, one record per check. Nothing is compared here —
      scripts/run-interop.ts compares, so the comparison is written once.

pyca/cryptography parses X.509 with rust-asn1 and its own cryptography-x509
crate: an implementation lineage that shares no code with OpenSSL's ASN.1
reader, with Go's, or with CryptoAPI's. Only the standard library and
`cryptography` are imported; the conformance workflow installs it from
scripts/data/interop-python-requirements.txt, pinned by version and SHA-256.
"""

import hashlib
import json
import struct
import sys

import cryptography
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509 import ocsp
from cryptography.x509.verification import PolicyBuilder, Store
from cryptography.x509.oid import ExtensionOID, NameOID


def fp(data):
    return hashlib.sha256(data).hexdigest()


def write(path, lines):
    with open(path, 'w', encoding='utf-8', newline='\n') as out:
        out.write('\n'.join(json.dumps(line, ensure_ascii=False) for line in lines) + '\n')


# ── L4 ───────────────────────────────────────────────────────────────

def l4(blob_path, out_path):
    with open(blob_path, 'rb') as f:
        blob = f.read()
    if blob[:8] != b'PKIBLOB1':
        raise SystemExit('not a pkinative blob')
    (count,) = struct.unpack('>I', blob[8:12])
    at = 12
    # No spkiKeyFp256: pyca exposes no slice of the SubjectPublicKeyInfo it
    # read, and a re-serialised key would be a fingerprint of pyca's encoder.
    # subject and issuer are re-encoded from the parsed Name, which keeps
    # every string type and every RDN as read — a difference there is a
    # difference in reading.
    fields = ['subjectFp256', 'issuerFp256', 'tbsFp256', 'keyAlgOid', 'version']
    lines = [{'t': 'header', 'schema': 1, 'tool': 'python-cryptography', 'version': cryptography.__version__, 'fields': fields}]
    for i in range(count):
        (n,) = struct.unpack('>I', blob[at:at + 4])
        der = blob[at + 4:at + 4 + n]
        at += 4 + n
        record = {'t': 'cert', 'i': i, 'ok': False}
        try:
            c = x509.load_der_x509_certificate(der)
            values = {
                'subjectFp256': fp(c.subject.public_bytes()),
                'issuerFp256': fp(c.issuer.public_bytes()),
                'tbsFp256': fp(c.tbs_certificate_bytes),
                'keyAlgOid': c.public_key_algorithm_oid.dotted_string,
                'version': c.version.value + 1,
            }
            # ok last, once every field was read.
            record.update(values)
            record['ok'] = True
        except Exception as e:  # noqa: BLE001 — the refusal is the answer
            record['error'] = f'{type(e).__name__}: {e}'[:200]
        lines.append(record)
    lines.append({'t': 'footer', 'count': count})
    write(out_path, lines)


# ── The interoperability matrix ──────────────────────────────────────

def name_value(name, oid):
    values = name.get_attributes_for_oid(oid)
    return values[0].value if values else ''


def cert_facts(c):
    facts = {
        'serial': format(c.serial_number, 'x'),
        'commonName': name_value(c.subject, NameOID.COMMON_NAME),
        'signatureOid': c.signature_algorithm_oid.dotted_string,
    }
    try:
        san = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        facts['dnsNames'] = ','.join(sorted(san.get_values_for_type(x509.DNSName)))
    except x509.ExtensionNotFound:
        facts['dnsNames'] = ''
    for key, oid in (('organization', NameOID.ORGANIZATION_NAME), ('organizationalUnit', NameOID.ORGANIZATIONAL_UNIT_NAME), ('locality', NameOID.LOCALITY_NAME)):
        value = name_value(c.subject, oid)
        if value:
            facts[key] = value
    return facts


def interop(manifest_path, out_path):
    with open(manifest_path, encoding='utf-8') as f:
        artefacts = json.load(f)['artefacts']
    by_id = {a['id']: a for a in artefacts}
    lines = [{'t': 'header', 'tool': 'python-cryptography', 'version': cryptography.__version__}]

    def check(artefact, name, fn):
        record = {'id': artefact['id'], 'check': name, 'ok': False}
        try:
            result = fn()
            if isinstance(result, dict):
                record['facts'] = result
                record['ok'] = True
            else:
                record['ok'] = bool(result)
        except Exception as e:  # noqa: BLE001
            record['error'] = f'{type(e).__name__}: {e}'[:300]
        lines.append(record)

    def load(path):
        with open(path, 'rb') as f:
            return f.read()

    for a in artefacts:
        kind = a['kind']
        if kind == 'cert':
            check(a, 'cert.read', lambda a=a: cert_facts(x509.load_der_x509_certificate(load(a['der']))))
            check(a, 'cert.pem', lambda a=a: cert_facts(x509.load_pem_x509_certificate(load(a['pem']))))
            if a.get('shape') != 'ca':
                issuer = by_id[a['issuer']]

                def directly(a=a, issuer=issuer):
                    leaf = x509.load_der_x509_certificate(load(a['der']))
                    leaf.verify_directly_issued_by(x509.load_der_x509_certificate(load(issuer['der'])))
                    return True
                check(a, 'chain.verify', directly)
            if a.get('shape') == 'br' and a.get('webpki'):
                issuer = by_id[a['issuer']]

                def webpki(a=a, issuer=issuer):
                    # The CA/Browser Forum profile pyca enforces for a TLS
                    # server: algorithms, key sizes, extensions, the name.
                    store = Store([x509.load_der_x509_certificate(load(issuer['der']))])
                    verifier = PolicyBuilder().store(store).build_server_verifier(x509.DNSName(a['serverName']))
                    verifier.verify(x509.load_der_x509_certificate(load(a['der'])), [])
                    return True
                check(a, 'chain.webpki', webpki)
        elif kind == 'csr':
            def csr(a=a):
                r = x509.load_der_x509_csr(load(a['der']))
                if not r.is_signature_valid:
                    raise ValueError('is_signature_valid is False')
                return {'commonName': name_value(r.subject, NameOID.COMMON_NAME), 'signatureOid': r.signature_algorithm_oid.dotted_string}
            check(a, 'csr.verify', csr)
            check(a, 'csr.pem', lambda a=a: {'commonName': name_value(x509.load_pem_x509_csr(load(a['pem'])).subject, NameOID.COMMON_NAME)})
        elif kind == 'cms':
            check(a, 'cms.certificates', lambda a=a: {'certificateCount': str(len(pkcs7.load_der_pkcs7_certificates(load(a['der']))))})
        elif kind == 'ocsp-request':
            def request(a=a):
                r = ocsp.load_der_ocsp_request(load(a['der']))
                facts = {
                    'serial': format(r.serial_number, 'x'),
                    'issuerNameHash': r.issuer_name_hash.hex(),
                    'issuerKeyHash': r.issuer_key_hash.hex(),
                }
                try:
                    facts['nonce'] = r.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce.hex()
                except x509.ExtensionNotFound:
                    facts['nonce'] = ''
                return facts
            check(a, 'ocsp.request', request)
    lines.append({'t': 'footer', 'count': len(lines) - 1})
    write(out_path, lines)


if __name__ == '__main__':
    if len(sys.argv) != 4 or sys.argv[1] not in ('l4', 'interop'):
        raise SystemExit('usage: python-cryptography.py l4|interop <input> <out.ndjson>')
    (l4 if sys.argv[1] == 'l4' else interop)(sys.argv[2], sys.argv[3])
