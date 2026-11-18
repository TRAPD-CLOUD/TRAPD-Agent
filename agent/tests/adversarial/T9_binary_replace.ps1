# Adversarial row T9 (Windows): replace the installed agent binary with a
# modified copy and restart the service.
#
#   $env:TRAPD_ADVERSARIAL_OK=1; .\T9_binary_replace.ps1      (as SYSTEM)
#
# As an elevated administrator the install-dir DACL (phase 08 WP3) refuses the
# write: that is reported as BLOCKED and is also a pass. As SYSTEM the write
# succeeds and the expected reaction is:
#   * the agent refuses to start (fail-closed binary integrity) and writes
#     selfprotect.binary_tampered to the TRAPD-Agent-Security log (event 122)
#     before any network;
#   * the guard does not restart a tampered agent (selfprotect.peer_binary_tampered,
#     delivered by the next healthy start).
# Safe: the original binary is backed up first and always put back, then the
# service is started again.
$ErrorActionPreference = 'Stop'
if ($env:TRAPD_ADVERSARIAL_OK -ne '1') { Write-Error 'refusing: set $env:TRAPD_ADVERSARIAL_OK=1'; exit 2 }

$svc = Get-CimInstance Win32_Service -Filter "Name='trapd-agent'"
$exe = ($svc.PathName -replace '^"([^"]+)".*$', '$1')
$backup = Join-Path $env:TEMP ("trapd-agent.orig." + [guid]::NewGuid().ToString('N') + '.exe')
Copy-Item $exe $backup
$start = Get-Date
$replaced = $false
try {
    try {
        Stop-Service trapd-agent -Force
    } catch {
        Write-Host "RESULT: BLOCKED (stopping the service was refused: $($_.Exception.Message))"
        return
    }
    $bytes = [IO.File]::ReadAllBytes($backup) + [byte]0
    try {
        [IO.File]::WriteAllBytes($exe, $bytes)
        $replaced = $true
    } catch {
        Write-Host "RESULT: BLOCKED (write to $exe refused: $($_.Exception.Message))"
        return
    }
    Write-Host "T9: replaced $exe with a modified copy at $($start.ToUniversalTime().ToString('T'))"
    Start-Service trapd-agent -ErrorAction SilentlyContinue
    $found = $null
    for ($i = 0; $i -lt 12 -and -not $found; $i++) {
        Start-Sleep 5
        $found = Get-WinEvent -FilterHashtable @{ LogName = 'TRAPD-Agent-Security'; Id = 122; StartTime = $start } -MaxEvents 1 -ErrorAction SilentlyContinue
    }
    if ($found) { Write-Host "RESULT: PASS (event 122 at $($found.TimeCreated))" }
    else { Write-Host 'RESULT: FAIL (no event 122 in TRAPD-Agent-Security within 60 s)' }
} finally {
  if (-not $replaced) {
    Remove-Item $backup -ErrorAction SilentlyContinue
    Start-Service trapd-agent -ErrorAction SilentlyContinue
  } else {
    Stop-Service trapd-guard -Force -ErrorAction SilentlyContinue
    Stop-Service trapd-agent -Force -ErrorAction SilentlyContinue
    Start-Sleep 2
    Copy-Item $backup $exe -Force
    if ((Get-FileHash $exe).Hash -eq (Get-FileHash $backup).Hash) {
        Remove-Item $backup
        Write-Host 'original binary restored'
    } else {
        Write-Host "ERROR: restore failed; the original is at $backup"
    }
    Start-Service trapd-agent -ErrorAction SilentlyContinue
    Start-Service trapd-guard -ErrorAction SilentlyContinue
  }
}
