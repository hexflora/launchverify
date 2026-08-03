<#
Regenerates Authenticode test fixtures under tests/fixtures/.
Requires: gcc on PATH, PowerShell with New-SelfSignedCertificate + Set-AuthenticodeSignature.
Run from the repo root:  pwsh -File scripts/make-fixtures.ps1
#>
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

$outDir = Join-Path (Get-Location) 'tests\fixtures'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$tmp = Join-Path $env:TEMP 'lv-fixtures'
if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

# 1. Unsigned base executable.
$src = Join-Path $tmp 'hello.c'
Set-Content -Path $src -Value 'int main(void){return 0;}' -Encoding ascii
$unsigned = Join-Path $tmp 'unsigned.exe'
& gcc -O0 -o $unsigned $src
if ($LASTEXITCODE -ne 0) { throw 'gcc failed to build unsigned.exe' }
Copy-Item $unsigned (Join-Path $outDir 'unsigned.exe') -Force

# 2. Self-signed cert (current), used for the self-signed fixture.
$selfSigned = New-SelfSignedCertificate -Subject 'CN=LaunchVerify Test Signer' `
    -CertStoreLocation Cert:\CurrentUser\My -Type CodeSigningCert `
    -KeyExportPolicy Exportable -KeyUsage DigitalSignature `
    -NotAfter (Get-Date).AddYears(5) -TextExtension @('2.5.29.19={critical}{text}ca=0') `
    -ErrorAction Stop

# 3. Expired cert. Set-AuthenticodeSignature refuses certs that are already
#    expired, so we sign with a cert that is valid for a short window now, then
#    expires. The committed fixture is permanently expired within a couple of
#    minutes (signing happens immediately below; tests run later).
$expired = New-SelfSignedCertificate -Subject 'CN=LaunchVerify Test Signer' `
    -CertStoreLocation Cert:\CurrentUser\My -Type CodeSigningCert `
    -KeyExportPolicy Exportable -KeyUsage DigitalSignature `
    -NotBefore (Get-Date).AddDays(-1) -NotAfter (Get-Date).AddSeconds(20) `
    -TextExtension @('2.5.29.19={critical}{text}ca=0') `
    -ErrorAction Stop

function Sign-File([string]$Path, [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert) {
    $sig = Set-AuthenticodeSignature -FilePath $Path -Certificate $Cert -HashAlgorithm SHA256
    # Self-signed certs legitimately report UnknownError ("root not trusted");
    # that still produces a validly-applied signature. Only fail on statuses
    # that mean the signature was not applied.
    $bad = @('NotSigned', 'HashMismatch', 'NotSupported', 'NoSignature')
    if ($bad -contains [string]$sig.Status) {
        throw "Set-AuthenticodeSignature failed for $Path : $($sig.StatusMessage)"
    }
}

Copy-Item $unsigned (Join-Path $tmp 'selfsigned.exe') -Force
Sign-File (Join-Path $tmp 'selfsigned.exe') $selfSigned
Copy-Item (Join-Path $tmp 'selfsigned.exe') (Join-Path $outDir 'signed-selfsigned.exe') -Force

Copy-Item $unsigned (Join-Path $tmp 'expired.exe') -Force
Sign-File (Join-Path $tmp 'expired.exe') $expired
Copy-Item (Join-Path $tmp 'expired.exe') (Join-Path $outDir 'signed-expired.exe') -Force

# 4. Tampered: sign a copy, then flip a byte in the middle of the file.
Copy-Item $unsigned (Join-Path $tmp 'tampered.exe') -Force
Sign-File (Join-Path $tmp 'tampered.exe') $selfSigned
$bytes = [System.IO.File]::ReadAllBytes((Join-Path $tmp 'tampered.exe'))
$mid = [int]($bytes.Length / 2)
$bytes[$mid] = $bytes[$mid] -bxor 0xFF
[System.IO.File]::WriteAllBytes((Join-Path $outDir 'signed-tampered.exe'), $bytes)

# Cleanup temp certs from the personal store.
Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq 'CN=LaunchVerify Test Signer' } | Remove-Item
Write-Host 'Fixtures written to tests/fixtures/'