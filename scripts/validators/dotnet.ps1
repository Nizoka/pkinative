# pkinative — the .NET reader of the interoperability matrix (write direction).
#
#   pwsh -NoProfile -File dotnet.ps1 <manifest.json> <out.ndjson>
#
# Reads every artefact the manifest lists (scripts/lib/interop-artefacts.ts)
# through .NET's own managed readers — X509Certificate2, CertificateRequest,
# SignedCms, Rfc3161TimestampRequest — and reports what .NET makes of each,
# one NDJSON record per check. Nothing is compared here: scripts/run-interop.ts
# compares, so the comparison is written once for every tool.
#
# Every value is an API value, never rendered text: X509Certificate2.Subject
# is formatted and, on Windows, partly localised, so a name is read attribute
# by attribute and a DNS name through X509SubjectAlternativeNameExtension.
#
# Needs PowerShell 7 on .NET 7 or later (LoadSigningRequest,
# EnumerateDnsNames, EnumerateRelativeDistinguishedNames), which every GitHub
# runner image carries. Nothing is downloaded, vendored or pinned.

param(
    [Parameter(Mandatory = $true)][string]$ManifestPath,
    [Parameter(Mandatory = $true)][string]$OutPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Security.Cryptography.Pkcs -ErrorAction SilentlyContinue

$X = 'System.Security.Cryptography.X509Certificates'
$manifest = Get-Content -Raw -Encoding UTF8 $ManifestPath | ConvertFrom-Json
$byId = @{}
foreach ($a in $manifest.artefacts) { $byId[$a.id] = $a }
$sha = [System.Security.Cryptography.SHA256]::Create()
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add((ConvertTo-Json -Compress ([ordered]@{ t = 'header'; tool = 'dotnet'; version = "PowerShell $($PSVersionTable.PSVersion) on $([System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription)" })))

function Hex([byte[]]$bytes) { return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '') }
# An INTEGER's hex as every tool is compared on it: lowercase, no leading zeros.
function IntHex([string]$text) { $t = $text.ToLowerInvariant().TrimStart('0'); if ($t -eq '') { return '0' } return $t }

function Load([string]$path) {
    return New-Object "$X.X509Certificate2" (, [System.IO.File]::ReadAllBytes($path))
}

# The value of a single-valued RDN of type $oid, or '' — a multi-valued RDN
# is left to the readers that expose its elements.
function NameValue($name, [string]$oid) {
    foreach ($rdn in $name.EnumerateRelativeDistinguishedNames()) {
        if (-not $rdn.HasMultipleElements -and $rdn.GetSingleElementType().Value -eq $oid) { return $rdn.GetSingleElementValue() }
    }
    return ''
}

function CertFacts($c) {
    $facts = [ordered]@{
        serial       = IntHex $c.SerialNumber
        commonName   = NameValue $c.SubjectName '2.5.4.3'
        signatureOid = $c.SignatureAlgorithm.Value
        dnsNames     = ''
    }
    foreach ($e in $c.Extensions) {
        if ($e -is [System.Security.Cryptography.X509Certificates.X509SubjectAlternativeNameExtension]) {
            $facts.dnsNames = (@($e.EnumerateDnsNames()) | Sort-Object -CaseSensitive) -join ','
        }
    }
    $o = NameValue $c.SubjectName '2.5.4.10'
    if ($o -ne '') { $facts.organization = $o }
    return $facts
}

function Check($artefact, [string]$check, [scriptblock]$body) {
    $record = [ordered]@{ id = $artefact.id; check = $check; ok = $false }
    try {
        $result = & $body
        if ($result -is [System.Collections.IDictionary]) { $record.facts = $result; $record.ok = $true }
        else { $record.ok = [bool]$result }
    } catch {
        $record.error = ($_.Exception.GetBaseException().Message -replace '\s+', ' ')
    }
    $lines.Add((ConvertTo-Json -Compress -Depth 4 $record))
}

foreach ($a in $manifest.artefacts) {
    switch ($a.kind) {
        'cert' {
            Check $a 'cert.read' { CertFacts (Load $a.der) }
            Check $a 'cert.pem' { CertFacts ([System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem([System.IO.File]::ReadAllText($a.pem))) }
            if ($a.shape -ne 'ca') {
                Check $a 'chain.verify' {
                    $chain = New-Object "$X.X509Chain"
                    $chain.ChainPolicy.TrustMode = [System.Security.Cryptography.X509Certificates.X509ChainTrustMode]::CustomRootTrust
                    [void]$chain.ChainPolicy.CustomTrustStore.Add((Load $byId[$a.issuer].der))
                    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                    [void]$chain.ChainPolicy.ApplicationPolicy.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1'))
                    if ($a.PSObject.Properties['verifyAt']) { $chain.ChainPolicy.VerificationTime = [DateTimeOffset]::FromUnixTimeMilliseconds([long]$a.verifyAt).UtcDateTime }
                    if (-not $chain.Build((Load $a.der))) {
                        throw ('X509Chain: ' + (($chain.ChainStatus | ForEach-Object { $_.Status.ToString() }) -join ','))
                    }
                    $true
                }
            }
        }
        'csr' {
            Check $a 'csr.verify' {
                # LoadSigningRequest verifies the self-signature unless told not to.
                $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::LoadSigningRequest(
                    [System.IO.File]::ReadAllBytes($a.der), [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                    [System.Security.Cryptography.X509Certificates.CertificateRequestLoadOptions]::Default)
                [ordered]@{ commonName = NameValue $req.SubjectName '2.5.4.3' }
            }
            Check $a 'csr.pem' {
                $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::LoadSigningRequestPem(
                    [System.IO.File]::ReadAllText($a.pem), [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                    [System.Security.Cryptography.X509Certificates.CertificateRequestLoadOptions]::Default)
                [ordered]@{ commonName = NameValue $req.SubjectName '2.5.4.3' }
            }
        }
        'cms' {
            Check $a 'cms.verify' {
                $content = [System.IO.File]::ReadAllBytes($a.content)
                if ($a.detached) {
                    $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms((New-Object System.Security.Cryptography.Pkcs.ContentInfo(, $content)), $true)
                } else {
                    $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
                }
                $cms.Decode([System.IO.File]::ReadAllBytes($a.der))
                # The signature and the signed attributes; the chain is the
                # certificates' business, judged above.
                $cms.CheckSignature($true)
                $signer = $cms.SignerInfos[0]
                [ordered]@{
                    contentSha256    = Hex $sha.ComputeHash($cms.ContentInfo.Content)
                    signerSerial     = IntHex $signer.Certificate.SerialNumber
                    version          = [string]$cms.Version
                    certificateCount = [string]$cms.Certificates.Count
                }
            }
        }
        'tsq' {
            Check $a 'tsq.read' {
                $req = $null
                $read = 0
                $bytes = [System.IO.File]::ReadAllBytes($a.der)
                if (-not [System.Security.Cryptography.Pkcs.Rfc3161TimestampRequest]::TryDecode($bytes, [ref]$req, [ref]$read) -or $read -ne $bytes.Length) {
                    throw "Rfc3161TimestampRequest.TryDecode read $read of $($bytes.Length) octets"
                }
                $nonce = $req.GetNonce()
                [ordered]@{
                    hashOid = $req.HashAlgorithmId.Value
                    imprint = Hex $req.GetMessageHash().ToArray()
                    nonce   = if ($null -eq $nonce) { '' } else { IntHex (Hex $nonce.ToArray()) }
                    policy  = if ($null -eq $req.RequestedPolicyId) { '' } else { $req.RequestedPolicyId.Value }
                    certReq = ([string]$req.RequestSignerCertificate).ToLowerInvariant()
                }
            }
        }
    }
}

$lines.Add((ConvertTo-Json -Compress ([ordered]@{ t = 'footer'; count = $lines.Count - 1 })))
[System.IO.File]::WriteAllLines($OutPath, $lines, (New-Object System.Text.UTF8Encoding($false)))
