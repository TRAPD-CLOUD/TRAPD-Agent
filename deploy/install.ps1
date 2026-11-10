# Optional release selector for the MSI. Windows Installer owns the service,
# file replacement, upgrade rollback, repair and uninstall lifecycle.
#
# Preferred enrollment is device pairing (no token at all). When a one-time
# token is used it is NEVER placed on the msiexec command line (visible to all
# local users and to process telemetry): it is staged in the SYSTEM/Administrators
# only HKLM\SOFTWARE\TRAPD\Agent key, and the agent deletes it after enrolling.
#
# The MSI must carry a valid Authenticode signature of the expected signer.
[CmdletBinding()]
param(
    [ValidateSet('stable', 'beta')][string]$Channel = 'stable',
    [string]$BackendUrl = $env:TRAPD_BACKEND_URL,
    [string]$EnrollTokenFile,
    [string]$EnrollToken = $env:TRAPD_ENROLL_TOKEN,
    # Expected MSI signer. At least one is required unless -AllowUnsigned is given.
    [string]$ExpectedThumbprint = $env:TRAPD_SIGNER_THUMBPRINT,
    [string]$ExpectedPublisher = $env:TRAPD_SIGNER_SUBJECT,
    # Explicit, loud opt-out for self-built or pre-signing packages.
    [switch]$AllowUnsigned
)
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this installer from an elevated PowerShell prompt.'
}
if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -ne 'X64') { throw 'Only x64 Windows is supported.' }
if ($EnrollTokenFile) {
    if ($EnrollToken) { throw 'Use either -EnrollTokenFile or -EnrollToken, not both.' }
    $EnrollToken = ([string](Get-Content -LiteralPath $EnrollTokenFile -TotalCount 1)).Trim()
}
if (-not $AllowUnsigned -and -not $ExpectedThumbprint -and -not $ExpectedPublisher) {
    throw 'Specify -ExpectedThumbprint or -ExpectedPublisher (the signer of the TRAPD MSI), or -AllowUnsigned to accept an unsigned package explicitly.'
}
if ($BackendUrl -match '["\r\n]' -or $EnrollToken -match '["\r\n\s]') { throw 'Invalid MSI configuration value.' }

function Set-StagedEnrollToken([string]$Token) {
    $hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Registry64')
    $key = $hklm.CreateSubKey('SOFTWARE\TRAPD\Agent')
    try {
        $acl = New-Object Security.AccessControl.RegistrySecurity
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
            $identity = New-Object Security.Principal.SecurityIdentifier $sid
            $acl.AddAccessRule((New-Object Security.AccessControl.RegistryAccessRule($identity, 'FullControl', 'ContainerInherit', 'None', 'Allow')))
        }
        $key.SetAccessControl($acl)
        $key.SetValue('EnrollToken', $Token, 'String')
    } finally { $key.Dispose(); $hklm.Dispose() }
}
function Remove-StagedEnrollToken {
    $hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Registry64')
    try {
        $key = $hklm.OpenSubKey('SOFTWARE\TRAPD\Agent', $true)
        if ($key) { $key.DeleteValue('EnrollToken', $false); $key.Dispose() }
    } finally { $hklm.Dispose() }
}

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
$tokenStaged = $false
try {
    $msi = Join-Path $temp $name
    $checksum = Join-Path $temp "$name.sha256"
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $msi
    Invoke-WebRequest -Uri $sum.browser_download_url -OutFile $checksum
    $expected = ((Get-Content -Raw $checksum).Trim() -split '\s+')[0]
    if ($expected -notmatch '^[0-9a-fA-F]{64}$' -or (Get-FileHash -Algorithm SHA256 $msi).Hash -ne $expected) { throw 'MSI checksum mismatch.' }
    # The checksum comes from the same release, so it proves integrity only.
    # Authenticity requires a valid signature by the expected signer (fail closed).
    if ($AllowUnsigned) {
        Write-Warning 'MSI signature verification skipped (-AllowUnsigned).'
    } else {
        $sig = Get-AuthenticodeSignature -LiteralPath $msi
        if ($sig.Status -ne 'Valid' -or -not $sig.SignerCertificate) { throw "MSI Authenticode signature is not valid ($($sig.Status))." }
        $cert = $sig.SignerCertificate
        if ($ExpectedThumbprint -and $cert.Thumbprint -ne ($ExpectedThumbprint -replace '\s', '').ToUpperInvariant()) { throw 'MSI signer thumbprint does not match -ExpectedThumbprint.' }
        if ($ExpectedPublisher -and $cert.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -ne $ExpectedPublisher) { throw 'MSI publisher does not match -ExpectedPublisher.' }
    }
    $arguments = @('/i', "`"$msi`"", '/qn', '/norestart')
    if ($BackendUrl) { $arguments += "BACKENDURL=`"$BackendUrl`"" }
    if ($EnrollToken) {
        Set-StagedEnrollToken $EnrollToken
        $tokenStaged = $true
    }
    $process = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -ArgumentList $arguments -Wait -PassThru
    if ($process.ExitCode -notin @(0, 3010)) { throw "MSI installation failed ($($process.ExitCode))." }
    Write-Host "Installed TRAPD Agent $($release.tag_name) ($Channel)."
    $tokenStaged = $false
} finally {
    # A failed install must not leave a staged one-time token behind.
    if ($tokenStaged) { Remove-StagedEnrollToken }
    Remove-Item -Recurse -Force $temp -ErrorAction SilentlyContinue
}
