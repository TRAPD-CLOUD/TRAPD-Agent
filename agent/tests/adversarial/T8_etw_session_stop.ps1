# Adversarial row T8: stop the agent's ETW trace session (what EDR killers do
# with `logman stop <session> -ets` to blind the sensor without touching the
# service).
#
#   $env:TRAPD_ADVERSARIAL_OK=1; .\T8_etw_session_stop.ps1      (elevated)
#
# Expected: selfprotect.etw_session_stopped (agent side), written to the local
# TRAPD-Agent-Security event log as event id 120, delivered to the backend as a
# finding; the agent recreates its session. Verification reads the local log.
#
# Safe: stops only the "TRAPD-Agent" session; the agent restarts it itself, and
# the script restarts the service if the session is still missing at the end.
$ErrorActionPreference = 'Stop'
if ($env:TRAPD_ADVERSARIAL_OK -ne '1') { Write-Error 'refusing: set $env:TRAPD_ADVERSARIAL_OK=1'; exit 2 }
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'must run elevated'; exit 2
}

$session = 'TRAPD-Agent'
$start = Get-Date
& logman query $session -ets *> $null
if ($LASTEXITCODE -ne 0) { Write-Error "ETW session '$session' is not running; is the agent up?"; exit 2 }

& logman stop $session -ets
if ($LASTEXITCODE -ne 0) {
    Write-Host 'RESULT: BLOCKED (stopping the session was refused; also acceptable)'
    exit 0
}
Write-Host "T8: stopped ETW session '$session' at $($start.ToUniversalTime().ToString('T'))"

$found = $null
for ($i = 0; $i -lt 24 -and -not $found; $i++) {
    Start-Sleep -Seconds 5
    try {
        $found = Get-WinEvent -FilterHashtable @{ LogName = 'TRAPD-Agent-Security'; Id = 120; StartTime = $start } -MaxEvents 1 -ErrorAction Stop
    } catch { $found = $null }
}

& logman query $session -ets *> $null
$recreated = ($LASTEXITCODE -eq 0)
if (-not $recreated) {
    Write-Host 'session not recreated by the agent; restarting the service to restore it'
    Restart-Service trapd-agent -ErrorAction SilentlyContinue
}

if ($found) {
    Write-Host "RESULT: PASS (event 120 at $($found.TimeCreated); session recreated: $recreated)"
} else {
    Write-Host 'RESULT: FAIL (no event 120 in TRAPD-Agent-Security within 2 minutes)'
    exit 1
}
