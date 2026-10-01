// pkinative — the Go crypto/x509 reader.
//
// Two modes, one program, so the reader the interoperability matrix trusts is
// the reader conformance level L4 confronts:
//
//	go run main.go l4 <blob> <out.ndjson>
//	    Conformance level L4: read the PKIBLOB1 file scripts/lib/validators.ts
//	    writes and answer in its NDJSON contract (schema 1), all six fields.
//
//	go run main.go interop <manifest.json> <out.ndjson>
//	    The interoperability matrix, write direction: read every certificate
//	    and certification request the manifest lists
//	    (scripts/lib/interop-artefacts.ts) and report what crypto/x509 makes of
//	    it, one record per check. scripts/run-interop.ts compares.
//
// Go's crypto/x509 is written in Go on Go's own encoding/asn1 and
// golang.org/x/crypto/cryptobyte: a lineage that shares no code with OpenSSL,
// CryptoAPI or pyca. Standard library only — no go.mod, nothing downloaded.
package main

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"
)

func fp(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

type subjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func clip(err error) string {
	s := err.Error()
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// ── L4 ───────────────────────────────────────────────────────────────

func l4(blobPath, outPath string) error {
	blob, err := os.ReadFile(blobPath)
	if err != nil {
		return err
	}
	if len(blob) < 12 || string(blob[:8]) != "PKIBLOB1" {
		return fmt.Errorf("not a pkinative blob")
	}
	count := binary.BigEndian.Uint32(blob[8:12])
	at := uint32(12)
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()
	enc := json.NewEncoder(out)
	_ = enc.Encode(map[string]any{"t": "header", "schema": 1, "tool": "go-x509", "version": runtime.Version(),
		"fields": []string{"subjectFp256", "issuerFp256", "spkiKeyFp256", "tbsFp256", "keyAlgOid", "version"}})
	for i := uint32(0); i < count; i++ {
		n := binary.BigEndian.Uint32(blob[at : at+4])
		der := blob[at+4 : at+4+n]
		at += 4 + n
		rec := map[string]any{"t": "cert", "i": i, "ok": false}
		c, err := x509.ParseCertificate(der)
		if err == nil {
			var k subjectPublicKeyInfo
			rest, e := asn1.Unmarshal(c.RawSubjectPublicKeyInfo, &k)
			if e != nil || len(rest) != 0 {
				err = fmt.Errorf("subjectPublicKeyInfo: %v", e)
			} else {
				// RawSubject, RawIssuer and RawTBSCertificate are the slices
				// Go read, byte for byte; ok is set once every field is in.
				rec["subjectFp256"] = fp(c.RawSubject)
				rec["issuerFp256"] = fp(c.RawIssuer)
				rec["spkiKeyFp256"] = fp(k.PublicKey.Bytes)
				rec["tbsFp256"] = fp(c.RawTBSCertificate)
				rec["keyAlgOid"] = k.Algorithm.Algorithm.String()
				rec["version"] = c.Version
				rec["ok"] = true
			}
		}
		if err != nil {
			rec["error"] = clip(err)
		}
		_ = enc.Encode(rec)
	}
	return enc.Encode(map[string]any{"t": "footer", "count": count})
}

// ── The interoperability matrix ──────────────────────────────────────

type artefact struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Shape  string `json:"shape"`
	Der    string `json:"der"`
	Pem    string `json:"pem"`
	Issuer string `json:"issuer"`
	// The name a leaf is verified for, and the instant (epoch ms; now when 0).
	ServerName string `json:"serverName"`
	VerifyAt   int64  `json:"verifyAt"`
}

func certFacts(c *x509.Certificate) map[string]string {
	dns := append([]string(nil), c.DNSNames...)
	sort.Strings(dns)
	facts := map[string]string{
		"serial":       c.SerialNumber.Text(16),
		"commonName":   c.Subject.CommonName,
		"dnsNames":     strings.Join(dns, ","),
		"signatureOid": signatureOid(c.Raw),
	}
	if len(c.Subject.Organization) > 0 {
		facts["organization"] = c.Subject.Organization[0]
	}
	if len(c.Subject.OrganizationalUnit) > 0 {
		facts["organizationalUnit"] = c.Subject.OrganizationalUnit[0]
	}
	if len(c.Subject.Locality) > 0 {
		facts["locality"] = c.Subject.Locality[0]
	}
	return facts
}

// signatureOid reads the outer signatureAlgorithm, which crypto/x509 maps to
// an enum and does not expose as an OID.
func signatureOid(raw []byte) string {
	var c struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	if _, err := asn1.Unmarshal(raw, &c); err != nil {
		return ""
	}
	return c.Algorithm.Algorithm.String()
}

func interop(manifestPath, outPath string) error {
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var manifest struct{ Artefacts []artefact }
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return err
	}
	byID := map[string]artefact{}
	for _, a := range manifest.Artefacts {
		byID[a.ID] = a
	}
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(map[string]any{"t": "header", "tool": "go-x509", "version": runtime.Version()})
	records := 0
	emit := func(id, check string, facts map[string]string, err error) {
		rec := map[string]any{"id": id, "check": check, "ok": err == nil}
		if err != nil {
			rec["error"] = clip(err)
		} else if facts != nil {
			rec["facts"] = facts
		}
		_ = enc.Encode(rec)
		records++
	}
	load := func(path string) (*x509.Certificate, error) {
		der, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return x509.ParseCertificate(der)
	}
	for _, a := range manifest.Artefacts {
		switch a.Kind {
		case "cert":
			c, err := load(a.Der)
			if err != nil {
				emit(a.ID, "cert.read", nil, err)
				continue
			}
			emit(a.ID, "cert.read", certFacts(c), nil)
			if a.Shape == "ca" {
				continue
			}
			ca, err := load(byID[a.Issuer].Der)
			if err != nil {
				emit(a.ID, "chain.verify", nil, err)
				continue
			}
			// The signature alone, then the whole path as a TLS client
			// builds it: the name, serverAuth, the CA's name constraints.
			if err := c.CheckSignatureFrom(ca); err != nil {
				emit(a.ID, "chain.verify", nil, err)
				continue
			}
			roots := x509.NewCertPool()
			roots.AddCert(ca)
			opts := x509.VerifyOptions{Roots: roots, DNSName: a.ServerName, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			if a.VerifyAt != 0 {
				opts.CurrentTime = time.UnixMilli(a.VerifyAt)
			}
			_, err = c.Verify(opts)
			emit(a.ID, "chain.verify", nil, err)
		case "csr":
			der, err := os.ReadFile(a.Der)
			if err == nil {
				var r *x509.CertificateRequest
				r, err = x509.ParseCertificateRequest(der)
				if err == nil {
					if err = r.CheckSignature(); err == nil {
						emit(a.ID, "csr.verify", map[string]string{"commonName": r.Subject.CommonName}, nil)
						continue
					}
				}
			}
			emit(a.ID, "csr.verify", nil, err)
		}
	}
	return enc.Encode(map[string]any{"t": "footer", "count": records})
}

func main() {
	if len(os.Args) != 4 || (os.Args[1] != "l4" && os.Args[1] != "interop") {
		fmt.Fprintln(os.Stderr, "usage: main.go l4|interop <input> <out.ndjson>")
		os.Exit(2)
	}
	run := l4
	if os.Args[1] == "interop" {
		run = interop
	}
	if err := run(os.Args[2], os.Args[3]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
