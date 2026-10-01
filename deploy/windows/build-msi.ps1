[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$AgentExe,
    [string]$Version,
    [string]$Output = 'dist\trapd-agent-windows-x86_64.msi'
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
# Pin the toolchain and add WixToolset.Util.wixext/4.0.6 to the extension cache.
& wix build (Join-Path $PSScriptRoot 'Package.wxs') -arch x64 -ext WixToolset.Util.wixext -d "AgentExe=$AgentExe" -d "Version=$Version" -d "SourceDir=$PSScriptRoot" -o $Output
if ($LASTEXITCODE -ne 0) { throw "WiX MSI build failed ($LASTEXITCODE)." }
Write-Host "Built $Output"
