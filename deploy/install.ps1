# Optional release selector for the MSI. Windows Installer owns the service,
# file replacement, upgrade rollback, repair and uninstall lifecycle.
#
# Preferred enrollment is device pairing (no token at all). When a one-time
# token is used it is NEVER placed on the msiexec command line (visible to all
# local users and to process telemetry): the script writes it to a temporary
# file readable only by the current administrator and SYSTEM and passes only
# the file PATH (ENROLLTOKENFILE). A deferred SYSTEM custom action of the MSI
# reads it into the protected HKLM\SOFTWARE\TRAPD\Agent key (an elevated
# administrator cannot write that key on a hardened host), the script deletes
# the file, and the agent deletes the registry value after enrolling.
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
        # Private directory first (inheritance off; SYSTEM + current user), then the file.
        $tokenDir = Join-Path $temp 'enroll'
        New-Item -ItemType Directory $tokenDir | Out-Null
        $dirAcl = New-Object Security.AccessControl.DirectorySecurity
        $dirAcl.SetAccessRuleProtection($true, $false)
        $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $system = New-Object Security.Principal.SecurityIdentifier 'S-1-5-18'
        foreach ($sid in $me, $system) {
            $dirAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        }
        Set-Acl -LiteralPath $tokenDir -AclObject $dirAcl
        $tokenPath = Join-Path $tokenDir 'enroll.token'
        [IO.File]::WriteAllText($tokenPath, $EnrollToken, (New-Object Text.UTF8Encoding $false))
        $arguments += "ENROLLTOKENFILE=`"$tokenPath`""
    }
    $process = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -ArgumentList $arguments -Wait -PassThru
    if ($process.ExitCode -notin @(0, 3010)) { throw "MSI installation failed ($($process.ExitCode))." }
    Write-Host "Installed TRAPD Agent $($release.tag_name) ($Channel)."
} finally {
    # The temp directory holds the staged token file; it is removed on every path.
    Remove-Item -Recurse -Force $temp -ErrorAction SilentlyContinue
}
