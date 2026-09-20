# pkinative — conformance level L4, the Windows CryptoAPI validator.
#
# Reads the blob scripts/lib/validators.ts writes and answers in the NDJSON
# contract that module defines. X509Certificate2 on Windows PowerShell is
# backed by CryptoAPI: an implementation lineage with nothing in common with
# OpenSSL, which is the whole point of confronting it.
#
# It reports only what it can reach without interpreting anything: SHA-256 of
# the encoded subject and issuer, SHA-256 of the public key octets, the key
# algorithm OID and the version. No rendered name, no formatted date — those
# differ between implementations for reasons that are nobody's defect.
#
# Windows PowerShell 5.1 is present on every Windows runner and needs no
# install. Nothing here is downloaded, vendored or pinned.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File windows-cryptoapi.ps1 <blob> <out>

param(
    [Parameter(Mandatory = $true)][string]$BlobPath,
    [Parameter(Mandatory = $true)][string]$OutPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$blob = [System.IO.File]::ReadAllBytes($BlobPath)
$magic = [System.Text.Encoding]::ASCII.GetString($blob, 0, 8)
if ($magic -ne 'PKIBLOB1') { throw "not a pkinative blob: $magic" }

function Read-UInt32BE([byte[]]$buffer, [int]$at) {
    return ([uint32]$buffer[$at] -shl 24) -bor ([uint32]$buffer[$at + 1] -shl 16) -bor ([uint32]$buffer[$at + 2] -shl 8) -bor [uint32]$buffer[$at + 3]
}

$count = Read-UInt32BE $blob 8
$at = 12

$sha = [System.Security.Cryptography.SHA256]::Create()
function Get-Fp([byte[]]$bytes) {
    if ($null -eq $bytes -or $bytes.Length -eq 0) { return $null }
    return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
}

$lines = New-Object System.Collections.Generic.List[string]
$version = "PowerShell $($PSVersionTable.PSVersion) / .NET $([System.Environment]::Version)"
$header = [ordered]@{
    t       = 'header'
    schema  = 1
    tool    = 'windows-cryptoapi'
    version = $version
    fields  = @('subjectFp256', 'issuerFp256', 'spkiKeyFp256', 'keyAlgOid', 'version')
}
$lines.Add((ConvertTo-Json $header -Compress))

for ($i = 0; $i -lt $count; $i++) {
    $length = Read-UInt32BE $blob $at
    $at += 4
    $der = New-Object byte[] $length
    if ($length -gt 0) { [System.Array]::Copy($blob, $at, $der, 0, $length) }
    $at += $length

    $record = [ordered]@{ t = 'cert'; i = $i; ok = $false }
    try {
        # The constructor is the acceptance decision: it throws on anything
        # CryptoAPI will not read as a certificate.
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, $der)
        $subject = Get-Fp $cert.SubjectName.RawData
        $issuer = Get-Fp $cert.IssuerName.RawData
        $key = Get-Fp $cert.PublicKey.EncodedKeyValue.RawData
        $oid = $cert.PublicKey.Oid.Value
        $ver = $cert.Version
        $cert.Dispose()
        # `ok` is set last, and only once every field has been read: an empty
        # input builds an object whose properties then throw, and a record
        # that says ok with half its fields missing would be worse than a
        # refusal.
        $record.ok = $true
        $record.subjectFp256 = $subject
        $record.issuerFp256 = $issuer
        $record.spkiKeyFp256 = $key
        $record.keyAlgOid = $oid
        $record.version = $ver
    } catch {
        $record.ok = $false
        $record.error = ($_.Exception.Message -replace '\s+', ' ')
    }
    $lines.Add((ConvertTo-Json $record -Compress))
}

# The footer is what proves the run reached the end: a validator that stops
# halfway and exits 0 is indistinguishable from a complete one without it.
$lines.Add((ConvertTo-Json ([ordered]@{ t = 'footer'; count = $count }) -Compress))

[System.IO.File]::WriteAllLines($OutPath, $lines, (New-Object System.Text.UTF8Encoding($false)))
