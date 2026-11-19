<#
Adversarial rows T2 (kill) and T3 (suspend) against the guard pair on Windows.

  $env:TRAPD_ADVERSARIAL_OK = '1'
  .\T2_T3_guard_pair.ps1 -Mode kill|suspend -Target agent|guard

Run as SYSTEM (for example `psexec -s -i powershell`) to see the pair react: an
elevated administrator without SeDebugPrivilege is refused by the process DACL
and the service DACL, which is itself the expected result and is reported as
BLOCKED. kill ends the target process; suspend calls NtSuspendProcess on it
(the "alive but mute" case). The peer must notice (death at once, suspension
within about 10 s), terminate a hung process, restart the service and emit
selfprotect.peer_lost.

Safe: touches only the two TRAPD services, resumes a suspended process in
`finally`, and leaves both services running.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('kill', 'suspend')][string]$Mode,
    [ValidateSet('agent', 'guard')][string]$Target = 'agent'
)
$ErrorActionPreference = 'Stop'
if ($env:TRAPD_ADVERSARIAL_OK -ne '1') { Write-Error 'refusing: set TRAPD_ADVERSARIAL_OK=1'; exit 2 }

Add-Type -Namespace Trapd -Name Nt -MemberDefinition @'
[DllImport("ntdll.dll")] public static extern int NtSuspendProcess(IntPtr h);
[DllImport("ntdll.dll")] public static extern int NtResumeProcess(IntPtr h);
'@
$service = "trapd-$Target"
$events = Join-Path $env:ProgramData 'TRAPD\logs\events.ndjson'
function Get-ServicePid([string]$name) { (Get-CimInstance Win32_Service -Filter "Name='$name'").ProcessId }
$oldPid = Get-ServicePid $service
if (-not $oldPid) { throw "$service is not running" }
$before = if (Test-Path $events) { @(Get-Content $events).Count } else { 0 }
$proc = [Diagnostics.Process]::GetProcessById($oldPid)
$handle = $null
try {
    try { $handle = $proc.Handle } catch { Write-Host "BLOCKED: cannot open $service (pid $oldPid): $($_.Exception.Message)"; exit 0 }
    if ($Mode -eq 'kill') { $proc.Kill() } else {
        $rc = [Trapd.Nt]::NtSuspendProcess($handle)
        if ($rc -ne 0) { Write-Host "BLOCKED: NtSuspendProcess returned 0x$('{0:X}' -f $rc)"; exit 0 }
    }
    Write-Host "T2/T3 $Mode $Target (pid $oldPid) at $([DateTime]::UtcNow.ToString('HH:mm:ss'))"
    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    $newPid = $null
    while ([DateTime]::UtcNow -lt $deadline) {
        $cur = Get-ServicePid $service
        if ($cur -and $cur -ne $oldPid -and (Get-Service $service).Status -eq 'Running') { $newPid = $cur; break }
        Start-Sleep -Seconds 1
    }
    if (-not $newPid) { Write-Host "FAIL: $service was not restarted within 90 s"; exit 1 }
    Write-Host "ok: $service restarted (pid $newPid)"
    $reason = if ($Mode -eq 'kill') { 'died' } else { 'hung' }
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Test-Path $events) {
            $hit = @(Get-Content $events | Select-Object -Skip $before | Where-Object {
                $_ -like '*selfprotect.peer_lost*' -and $_ -like "*`"peer`":`"$Target`"*" -and $_ -like "*`"reason`":`"$reason`"*" })
            if ($hit.Count -gt 0) { Write-Host "PASS: selfprotect.peer_lost (peer=$Target reason=$reason) was emitted"; exit 0 }
        }
        Start-Sleep -Seconds 1
    }
    Write-Host "FAIL: no selfprotect.peer_lost event in $events (needs file output; otherwise check the backend)"
    exit 1
} finally {
    if ($Mode -eq 'suspend' -and $handle) { [void][Trapd.Nt]::NtResumeProcess($handle) }
}
