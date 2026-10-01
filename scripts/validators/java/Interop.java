// pkinative — the Java reader of the interoperability matrix (write direction).
//
//   java Interop.java <manifest.json> <out.ndjson>
//
// Reads every certificate the manifest lists (scripts/lib/interop-artefacts.ts)
// through the JDK's own CertificateFactory and PKIX CertPathValidator — the
// reader every Java service, keytool included, uses — and reports what it
// makes of each, one NDJSON record per check. Certification requests are read
// by `keytool -printcertreq` from scripts/lib/interop-tools.ts, because the
// JDK exposes no public PKCS#10 reader. scripts/run-interop.ts compares.
//
// A single-file source program (JEP 330, JDK 11+): no build, no dependency,
// and no JSON library — the manifest is read with the few patterns its writer
// guarantees. On a JDK without EdDSA (before 15, JEP 339) an Ed25519 artefact
// is answered `unsupported`, which the runner accepts only where
// TOOL_LIMITATIONS of scripts/lib/interop.ts declares it.
import java.io.FileInputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.naming.directory.Attribute;

public class Interop {
    static final CertificateFactory CF;
    static {
        try { CF = CertificateFactory.getInstance("X.509"); } catch (Exception e) { throw new RuntimeException(e); }
    }

    static String json(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
            else b.append(c);
        }
        return b.append('"').toString();
    }

    static String record(String id, String check, boolean ok, Map<String, String> facts, String error, String unsupported) {
        StringBuilder b = new StringBuilder("{\"id\":").append(json(id)).append(",\"check\":").append(json(check)).append(",\"ok\":").append(ok);
        if (facts != null) {
            b.append(",\"facts\":{");
            boolean first = true;
            for (Map.Entry<String, String> e : facts.entrySet()) {
                if (!first) b.append(',');
                b.append(json(e.getKey())).append(':').append(json(e.getValue()));
                first = false;
            }
            b.append('}');
        }
        if (error != null) b.append(",\"error\":").append(json(error.length() > 300 ? error.substring(0, 300) : error));
        if (unsupported != null) b.append(",\"unsupported\":").append(json(unsupported));
        return b.append('}').toString();
    }

    static X509Certificate load(String path) throws Exception {
        try (FileInputStream in = new FileInputStream(path)) { return (X509Certificate) CF.generateCertificate(in); }
    }

    static Map<String, String> facts(X509Certificate c) throws Exception {
        Map<String, String> f = new LinkedHashMap<>();
        f.put("serial", c.getSerialNumber().toString(16));
        f.put("signatureOid", c.getSigAlgOID());
        Map<String, String> names = new HashMap<>();
        // toString(), not getName(RFC2253): on JDK 13 the RFC 2253 rendering
        // decodes a BMPString's UTF-16 octets as ISO 8859-1, while the
        // keyword form keytool prints decodes it as UTF-16. Both are JDK
        // renderings of the same parsed value; the one keytool shows is the
        // one a Java user sees.
        for (Rdn rdn : new LdapName(c.getSubjectX500Principal().toString()).getRdns()) {
            // A multi-valued RDN arrives as one Rdn with several attributes.
            var all = rdn.toAttributes().getAll();
            while (all.hasMore()) {
                Attribute a = all.next();
                names.putIfAbsent(a.getID().toUpperCase(), String.valueOf(a.get()));
            }
        }
        f.put("commonName", names.getOrDefault("CN", ""));
        if (names.containsKey("O")) f.put("organization", names.get("O"));
        if (names.containsKey("OU")) f.put("organizationalUnit", names.get("OU"));
        if (names.containsKey("L")) f.put("locality", names.get("L"));
        List<String> dns = new ArrayList<>();
        if (c.getSubjectAlternativeNames() != null) {
            for (List<?> gn : c.getSubjectAlternativeNames()) if (((Integer) gn.get(0)) == 2) dns.add((String) gn.get(1));
        }
        Collections.sort(dns);
        f.put("dnsNames", String.join(",", dns));
        return f;
    }

    public static void main(String[] args) throws Exception {
        String manifest = Files.readString(Path.of(args[0]), StandardCharsets.UTF_8);
        boolean eddsa;
        try { KeyFactory.getInstance("Ed25519"); eddsa = true; } catch (Exception e) { eddsa = false; }
        // One object per artefact, flat: "id", "kind", "shape", "der", "pem", "issuer".
        Pattern object = Pattern.compile("\\{[^{}]*\"kind\"[^{}]*\\}");
        Map<String, Map<String, String>> byId = new LinkedHashMap<>();
        Matcher m = object.matcher(manifest.replaceAll("\"expect\"\\s*:\\s*\\{[^{}]*\\}", "\"expect\":null"));
        while (m.find()) {
            Map<String, String> a = new HashMap<>();
            Matcher kv = Pattern.compile("\"(\\w+)\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"").matcher(m.group());
            while (kv.find()) a.put(kv.group(1), kv.group(2).replace("\\\\", "\\"));
            Matcher at = Pattern.compile("\"verifyAt\"\\s*:\\s*(\\d+)").matcher(m.group());
            if (at.find()) a.put("verifyAt", at.group(1));
            byId.put(a.get("id"), a);
        }
        List<String> out = new ArrayList<>();
        out.add("{\"t\":\"header\",\"tool\":\"java-keytool\",\"version\":" + json("Java " + System.getProperty("java.version") + " (" + System.getProperty("java.vendor") + ")") + ",\"eddsa\":" + eddsa + "}");
        for (Map<String, String> a : byId.values()) {
            if (!"cert".equals(a.get("kind"))) continue;
            String id = a.get("id");
            // The frozen samples (sample/...) are Ed25519 too.
            String unsupported = !eddsa && (id.startsWith("ed25519/") || id.startsWith("sample/")) ?"this JDK has no EdDSA (JEP 339 arrived in JDK 15)" : null;
            for (String check : new String[] { "cert.read", "cert.pem" }) {
                try {
                    X509Certificate c = load(a.get(check.equals("cert.read") ? "der" : "pem"));
                    out.add(record(id, check, true, facts(c), null, null));
                } catch (Exception e) {
                    out.add(record(id, check, false, null, e.toString(), unsupported));
                }
            }
            if ("ca".equals(a.get("shape"))) continue;
            try {
                X509Certificate leaf = load(a.get("der"));
                X509Certificate ca = load(byId.get(a.get("issuer")).get("der"));
                leaf.verify(ca.getPublicKey());
                // PKIX as a Java client runs it: the CA as anchor, its name
                // constraints and key usage enforced, revocation off.
                PKIXParameters params = new PKIXParameters(Collections.singleton(new TrustAnchor(ca, null)));
                params.setRevocationEnabled(false);
                if (a.containsKey("verifyAt")) params.setDate(new java.util.Date(Long.parseLong(a.get("verifyAt"))));
                CertPathValidator.getInstance("PKIX").validate(CF.generateCertPath(List.of(leaf)), params);
                out.add(record(id, "chain.verify", true, null, null, null));
            } catch (Exception e) {
                out.add(record(id, "chain.verify", false, null, e.toString(), unsupported));
            }
        }
        out.add("{\"t\":\"footer\",\"count\":" + (out.size() - 1) + "}");
        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(Path.of(args[1]), StandardCharsets.UTF_8))) {
            for (String line : out) w.print(line + "\n");
        }
    }
}
