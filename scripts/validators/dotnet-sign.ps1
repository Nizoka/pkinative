# pkinative — the .NET writer of the interoperability matrix (read direction).
#
#   pwsh -NoProfile -File dotnet-sign.ps1 <dir>
#
# .NET makes a root CA and two signers in memory (CertificateRequest — no
# certificate store is touched), then signs one content four ways with
# SignedCms.ComputeSignature, which is what every .NET S/MIME, Authenticode-
# adjacent and document-signing stack calls. pkinative must verify each file
# against the root (scripts/lib/interop-reads.ts, the `dotnet:cms-*` cases).
#
# Writes into <dir>: root.cer, content.bin, and cms-rsa.p7s, cms-rsa-ski.p7m,
# cms-rsa-pss.p7s, cms-ecdsa.p7s; prints WROTE and the runtime on success.

param([Parameter(Mandatory = $true)][string]$Dir)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Security.Cryptography.Pkcs -ErrorAction SilentlyContinue

$X = 'System.Security.Cryptography.X509Certificates'
$sha256 = [System.Security.Cryptography.HashAlgorithmName]::SHA256
$now = [DateTimeOffset]::UtcNow

function Extensions($request, [bool]$ca) {
    $request.CertificateExtensions.Add((New-Object "$X.X509BasicConstraintsExtension" $ca, $false, 0, $true))
    $usage = if ($ca) { [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]'KeyCertSign, CrlSign' } else { [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]'DigitalSignature, NonRepudiation' }
    $request.CertificateExtensions.Add((New-Object "$X.X509KeyUsageExtension" $usage, $true))
    $request.CertificateExtensions.Add((New-Object "$X.X509SubjectKeyIdentifierExtension" $request.PublicKey, $false))
}

$rootKey = [System.Security.Cryptography.RSA]::Create(2048)
$rootRequest = New-Object "$X.CertificateRequest" 'CN=pkinative interop dotnet root', $rootKey, $sha256, ([System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
Extensions $rootRequest $true
$root = $rootRequest.CreateSelfSigned($now.AddMinutes(-5), $now.AddDays(30))

function Issue([string]$name, $key, [bool]$rsa) {
    $request = if ($rsa) {
        New-Object "$X.CertificateRequest" "CN=$name", $key, $sha256, ([System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    } else {
        New-Object "$X.CertificateRequest" "CN=$name", $key, $sha256
    }
    Extensions $request $false
    $request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509AuthorityKeyIdentifierExtension]::CreateFromCertificate($root, $true, $false))
    $serial = [byte[]](1..16 | ForEach-Object { Get-Random -Minimum 1 -Maximum 255 })
    $serial[0] = $serial[0] -band 0x7f
    # The X509SignatureGenerator overload: the root is RSA, the signer may not be.
    $generator = [System.Security.Cryptography.X509Certificates.X509SignatureGenerator]::CreateForRSA($rootKey, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $cert = $request.Create($root.SubjectName, $generator, $now.AddMinutes(-5), $now.AddDays(29), $serial)
    if ($rsa) { return [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($cert, $key) }
    return [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::CopyWithPrivateKey($cert, $key)
}

$rsaSigner = Issue 'pkinative interop dotnet rsa' ([System.Security.Cryptography.RSA]::Create(2048)) $true
$ecSigner = Issue 'pkinative interop dotnet ecdsa' ([System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)) $false

$content = [System.Text.Encoding]::UTF8.GetBytes("pkinative interop, signed by .NET`n")
[System.IO.File]::WriteAllBytes((Join-Path $Dir 'root.cer'), $root.RawData)
[System.IO.File]::WriteAllBytes((Join-Path $Dir 'content.bin'), $content)

function Sign([string]$file, $cert, [bool]$detached, [string]$sid, $padding, [string]$digest) {
    $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms((New-Object System.Security.Cryptography.Pkcs.ContentInfo(, $content)), $detached)
    $type = [System.Security.Cryptography.Pkcs.SubjectIdentifierType]$sid
    $signer = if ($null -ne $padding) {
        New-Object System.Security.Cryptography.Pkcs.CmsSigner($type, $cert, [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert), $padding)
    } else {
        New-Object System.Security.Cryptography.Pkcs.CmsSigner($type, $cert)
    }
    $signer.DigestAlgorithm = New-Object System.Security.Cryptography.Oid($digest)
    $signer.IncludeOption = [System.Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
    [void]$signer.SignedAttributes.Add((New-Object System.Security.Cryptography.Pkcs.Pkcs9SigningTime))
    $cms.ComputeSignature($signer, $true)
    [System.IO.File]::WriteAllBytes((Join-Path $Dir $file), $cms.Encode())
}

$pkcs1 = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
Sign 'cms-rsa.p7s' $rsaSigner $true 'IssuerAndSerialNumber' $pkcs1 '2.16.840.1.101.3.4.2.1'
Sign 'cms-rsa-ski.p7m' $rsaSigner $false 'SubjectKeyIdentifier' $pkcs1 '2.16.840.1.101.3.4.2.3'
Sign 'cms-rsa-pss.p7s' $rsaSigner $true 'IssuerAndSerialNumber' ([System.Security.Cryptography.RSASignaturePadding]::Pss) '2.16.840.1.101.3.4.2.1'
Sign 'cms-ecdsa.p7s' $ecSigner $true 'IssuerAndSerialNumber' $null '2.16.840.1.101.3.4.2.1'

'WROTE ' + [System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription
