# Writes the hosted service's public trust anchors from CI variables into a
# directory for `build-msi.ps1 -TrustDir`. Only public values are used.
#
#   TRAPD_HOSTED_BACKEND_URL      https URL of the hosted backend
#   TRAPD_HOSTED_CA_PEM           PEM certificate(s) that pin the backend TLS
#   TRAPD_HOSTED_COMMAND_PUBKEY   base64 of the raw 32-byte Ed25519 command-signing key
#
# Optional:
#   TRAPD_HOSTED_RELEASE_PUBKEY   base64 of the raw 32-byte Ed25519 release-signing key;
#                                 enables signed self-update on the installed agent
#
# Nothing is staged unless all three required values are set. Values are validated by
# build-msi.ps1, which fails the build on malformed input.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutDir)
$ErrorActionPreference = 'Stop'

function Set-BakedFlag([bool]$Baked) {
    if ($env:GITHUB_OUTPUT) { "baked=$($Baked.ToString().ToLower())" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8 }
}

$values = [ordered]@{
    TRAPD_HOSTED_BACKEND_URL    = $env:TRAPD_HOSTED_BACKEND_URL
    TRAPD_HOSTED_CA_PEM         = $env:TRAPD_HOSTED_CA_PEM
    TRAPD_HOSTED_COMMAND_PUBKEY = $env:TRAPD_HOSTED_COMMAND_PUBKEY
}
$missing = @($values.Keys | Where-Object { [string]::IsNullOrWhiteSpace($values[$_]) })
if ($missing.Count -eq $values.Count) {
    Write-Host '::notice::No hosted trust variables set - building a generic MSI without baked trust anchors.'
    Set-BakedFlag $false
    return
}
if ($missing.Count -gt 0) {
    Write-Host "::warning::Hosted trust variables incomplete (missing: $($missing -join ', ')) - building a generic MSI without baked trust anchors."
    Set-BakedFlag $false
    return
}

New-Item -ItemType Directory -Force $OutDir | Out-Null
$utf8 = [Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText((Join-Path $OutDir 'backend_url'), $values.TRAPD_HOSTED_BACKEND_URL.Trim(), $utf8)
[IO.File]::WriteAllText((Join-Path $OutDir 'ca.crt'), ($values.TRAPD_HOSTED_CA_PEM.Trim() + "`n"), $utf8)
try {
    $key = [Convert]::FromBase64String($values.TRAPD_HOSTED_COMMAND_PUBKEY.Trim())
} catch {
    throw 'TRAPD_HOSTED_COMMAND_PUBKEY is not valid base64.'
}
[IO.File]::WriteAllBytes((Join-Path $OutDir 'command_signing.pub'), $key)
if (-not [string]::IsNullOrWhiteSpace($env:TRAPD_HOSTED_RELEASE_PUBKEY)) {
    try {
        $releaseKey = [Convert]::FromBase64String($env:TRAPD_HOSTED_RELEASE_PUBKEY.Trim())
    } catch {
        throw 'TRAPD_HOSTED_RELEASE_PUBKEY is not valid base64.'
    }
    [IO.File]::WriteAllBytes((Join-Path $OutDir 'release_signing.pub'), $releaseKey)
}
Write-Host 'Staged hosted trust anchors (public values only).'
Set-BakedFlag $true
