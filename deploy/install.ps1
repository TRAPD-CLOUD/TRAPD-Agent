# Optional release selector for the MSI. Windows Installer owns the service,
# file replacement, upgrade rollback, repair and uninstall lifecycle.
[CmdletBinding()]
param(
    [ValidateSet('stable', 'beta')][string]$Channel = 'stable',
    [string]$BackendUrl = $env:TRAPD_BACKEND_URL,
    [string]$EnrollToken = $env:TRAPD_ENROLL_TOKEN
)
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this installer from an elevated PowerShell prompt.'
}
if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -ne 'X64') { throw 'Only x64 Windows is supported.' }
if ($BackendUrl -match '["\r\n]' -or $EnrollToken -match '["\r\n\s]') { throw 'Invalid MSI configuration value.' }
$repo = 'trapd-cloud/trapd-agent'
$headers = @{ Accept = 'application/vnd.github+json'; 'X-GitHub-Api-Version' = '2022-11-28' }
if ($Channel -eq 'stable') {
    $release = Invoke-RestMethod -Headers $headers -Uri "https://api.github.com/repos/$repo/releases/latest"
} else {
    $releases = Invoke-RestMethod -Headers $headers -Uri "https://api.github.com/repos/$repo/releases?per_page=100"
    $release = $releases | Where-Object { $_.prerelease -and -not $_.draft } | Select-Object -First 1
}
if (-not $release) { throw "No published $Channel release is available." }
$name = 'trapd-agent-windows-x86_64.msi'
$asset = $release.assets | Where-Object name -eq $name | Select-Object -First 1
$sum = $release.assets | Where-Object name -eq "$name.sha256" | Select-Object -First 1
if (-not $asset -or -not $sum) { throw 'Release has no Windows x64 MSI and checksum.' }
$temp = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
New-Item -ItemType Directory $temp | Out-Null
try {
    $msi = Join-Path $temp $name
    $checksum = Join-Path $temp "$name.sha256"
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $msi
    Invoke-WebRequest -Uri $sum.browser_download_url -OutFile $checksum
    $expected = ((Get-Content -Raw $checksum).Trim() -split '\s+')[0]
    if ($expected -notmatch '^[0-9a-fA-F]{64}$' -or (Get-FileHash -Algorithm SHA256 $msi).Hash -ne $expected) { throw 'MSI checksum mismatch.' }
    $arguments = @('/i', "`"$msi`"", '/qn', '/norestart')
    if ($BackendUrl) { $arguments += "BACKENDURL=`"$BackendUrl`"" }
    if ($EnrollToken) { $arguments += "ENROLLTOKEN=`"$EnrollToken`"" }
    $process = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -ArgumentList $arguments -Wait -PassThru
    if ($process.ExitCode -notin @(0, 3010)) { throw "MSI installation failed ($($process.ExitCode))." }
    Write-Host "Installed TRAPD Agent $($release.tag_name) ($Channel)."
} finally { Remove-Item -Recurse -Force $temp -ErrorAction SilentlyContinue }
