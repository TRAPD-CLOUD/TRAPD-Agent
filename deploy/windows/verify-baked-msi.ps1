# Static check of a hosted-flavour MSI without installing it (no service, no
# network): the trust anchors inside the package must be byte-identical to the
# staged inputs, and the default backend must be the staged URL.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Msi, [Parameter(Mandatory)][string]$TrustDir)
$ErrorActionPreference = 'Stop'
$Msi = (Resolve-Path $Msi).Path
$TrustDir = (Resolve-Path $TrustDir).Path
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('trapd-baked-' + [guid]::NewGuid())
New-Item -ItemType Directory -Force $tmp | Out-Null
try {
    # Administrative image: extracts the package files only, runs no actions.
    $p = Start-Process "$env:SystemRoot\System32\msiexec.exe" -ArgumentList @('/a', "`"$Msi`"", '/qn', "TARGETDIR=`"$tmp`"") -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "Administrative extraction failed ($($p.ExitCode))." }

    foreach ($name in @('ca.crt', 'command_signing.pub')) {
        $found = @(Get-ChildItem -Path $tmp -Recurse -File -Filter $name)
        if ($found.Count -ne 1) { throw "Expected exactly one $name in the package, found $($found.Count)." }
        if ((Get-FileHash $found[0].FullName).Hash -ne (Get-FileHash (Join-Path $TrustDir $name)).Hash) {
            throw "$name in the package differs from the staged trust input."
        }
    }

    $expected = (Get-Content -Raw (Join-Path $TrustDir 'backend_url')).Trim()
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $db = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($Msi, 0))
    $view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @('SELECT `Value` FROM `Property` WHERE `Property`=''BACKENDURL'''))
    $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null) | Out-Null
    $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
    if (-not $record) { throw 'The package has no default BACKENDURL.' }
    $actual = $record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, @(1))
    if ($actual -ne $expected) { throw "Default BACKENDURL '$actual' differs from the staged '$expected'." }
    Write-Host "Baked MSI verified: anchors identical, default backend $actual."
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
