[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$AgentExe,
    [string]$Version,
    [string]$Output = 'dist\trapd-agent-windows-x86_64.msi',
    # Optional: bake the public trust anchors and default backend of the hosted
    # service into the MSI. Directory with ca.crt, command_signing.pub (raw 32
    # bytes) and backend_url (see stage-trust.ps1). Without it the MSI is generic.
    [string]$TrustDir
)
$ErrorActionPreference = 'Stop'
if (-not $Version) {
    $manifest = Get-Content -Raw (Join-Path $PSScriptRoot '..\..\agent\Cargo.toml')
    $Version = [regex]::Match($manifest, '(?m)^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"').Groups[1].Value
}
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw 'MSI Version must be major.minor.patch.' }
$AgentExe = (Resolve-Path $AgentExe).Path
$Output = [IO.Path]::GetFullPath($Output)
New-Item -ItemType Directory -Force (Split-Path $Output) | Out-Null

$wixArgs = @(
    'build', (Join-Path $PSScriptRoot 'Package.wxs'), '-arch', 'x64', '-ext', 'WixToolset.Util.wixext',
    '-d', "AgentExe=$AgentExe", '-d', "Version=$Version", '-d', "SourceDir=$PSScriptRoot", '-o', $Output
)

if ($TrustDir) {
    $TrustDir = (Resolve-Path $TrustDir).Path
    $caPath = Join-Path $TrustDir 'ca.crt'
    $keyPath = Join-Path $TrustDir 'command_signing.pub'
    $urlPath = Join-Path $TrustDir 'backend_url'
    foreach ($p in @($caPath, $keyPath, $urlPath)) {
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { throw "TrustDir is missing $(Split-Path $p -Leaf)." }
    }

    # The URL ends up in an MSI property and a registry value. Accept only a plain
    # https URL: no quotes, brackets (MSI formatted-text syntax), spaces or
    # control characters that could alter the package or the build command line.
    $url = (Get-Content -Raw -LiteralPath $urlPath).Trim()
    if ($url -notmatch '^https://[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$') {
        throw 'backend_url must be a plain https URL (letters, digits, . - _ ~ / and an optional port).'
    }

    # ca.crt: only certificates, each of which must parse. Reject anything else
    # (a pasted private key, stray text) instead of shipping it to every machine.
    $pem = Get-Content -Raw -LiteralPath $caPath
    $blockPattern = '-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----'
    $blocks = [regex]::Matches($pem, $blockPattern)
    if ($blocks.Count -lt 1) { throw 'ca.crt contains no PEM certificate.' }
    if (([regex]::Replace($pem, $blockPattern, '')).Trim().Length -ne 0) { throw 'ca.crt contains data other than PEM certificates.' }
    foreach ($b in $blocks) {
        $der = [Convert]::FromBase64String(($b.Value -replace '-----[A-Z ]+-----', '' -replace '\s', ''))
        [void][Security.Cryptography.X509Certificates.X509Certificate2]::new($der)
    }

    if ((Get-Item -LiteralPath $keyPath).Length -ne 32) { throw 'command_signing.pub must be exactly 32 raw bytes (Ed25519).' }

    $wixArgs += @('-d', "TrustDir=$TrustDir", '-d', "DefaultBackendUrl=$url")
    Write-Host "Baking hosted trust anchors for $url ($($blocks.Count) CA certificate(s))."
}

# Pin the toolchain and add WixToolset.Util.wixext/4.0.6 to the extension cache.
& wix @wixArgs
if ($LASTEXITCODE -ne 0) { throw "WiX MSI build failed ($LASTEXITCODE)." }
Write-Host "Built $Output"
