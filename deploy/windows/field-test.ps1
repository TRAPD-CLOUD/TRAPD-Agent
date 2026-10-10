<#
.SYNOPSIS
  Repeatable manual field test for the TRAPD Windows agent
  (docs/windows-v0.7.2-field-test.md, tests 1-9).

.DESCRIPTION
  Generates the activity of the field test and prints, per test, the marker to
  look for plus a ClickHouse query that verifies the telemetry. It does NOT
  talk to ClickHouse or the backend itself: no credentials are read, stored or
  sent, and nothing leaves this host.

  Safety properties:
    * Every artifact carries the run marker ("trapdtest<random>") and is
      removed again in `finally`, also after Ctrl+C.
    * No payloads, no network scanning, no credential access. The ransomware
      test only renames files this script created itself.
    * Tests that change system state (hosts file, honeytoken access) are opt-in
      switches and need an elevated shell where noted. The hosts test restores
      the original bytes and verifies the SHA-256.
    * The script refuses to run against a path it did not create.

  Run it only on a host you own, for which the TRAPD agent is paired to a
  backend you control.

.PARAMETER RansomDir
  Directory the agent watches for ransomware heuristics (NOT %TEMP%, which is
  ignored by design). Created below it: a "<marker>" folder, removed afterwards.

.PARAMETER HostsTest
  Also append and remove a marker comment in drivers\etc\hosts (needs admin).

.PARAMETER HoneytokenPath
  Path of a deployed decoy file to open once (for example the decoy shown in
  the TRAPD console). Skipped if omitted.

.EXAMPLE
  .\field-test.ps1 -RansomDir "$env:USERPROFILE\Documents" -HostsTest
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string]$RansomDir,
    [switch]$HostsTest,
    [string]$HoneytokenPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$marker = 'trapdtest' + ([guid]::NewGuid().ToString('N').Substring(0, 8))
$started = (Get-Date).ToUniversalTime()
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($HostsTest -and -not $isAdmin) {
    throw '-HostsTest needs an elevated shell.'
}

$results = New-Object System.Collections.Generic.List[object]
function Add-Step([string]$Id, [string]$Name, [string]$EventType, [string]$Expect) {
    $results.Add([pscustomobject]@{ Id = $Id; Name = $Name; EventType = $EventType; Expect = $Expect })
}

# ClickHouse query printed for every step; the operator runs it.
function Get-Query([string]$needle, [string]$extra = '') {
    $safe = $needle -replace "'", ''
    return "SELECT ts, event_type, substring(payload_json, 1, 300) FROM trapd_events " +
    "WHERE ts >= toDateTime('$($started.ToString('yyyy-MM-dd HH:mm:ss'))') " +
    "AND positionCaseInsensitive(payload_json, '$safe') > 0 $extra ORDER BY ts"
}

$work = Join-Path -Path $RansomDir -ChildPath $marker
$hostsFile = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$hostsLine = "# $marker"
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$hostsOriginal = $null
$hostsOriginalHash = $null

# Write the saved bytes back and verify the hash; retry because the agent or
# an AV scanner may hold the file briefly.
function Restore-Hosts {
    if ($null -eq $hostsOriginal) { return }
    for ($i = 0; $i -lt 10; $i++) {
        try {
            [IO.File]::WriteAllBytes($hostsFile, $hostsOriginal)
            if ((Get-FileHash -LiteralPath $hostsFile -Algorithm SHA256).Hash -eq $hostsOriginalHash) { return }
        } catch { Start-Sleep -Seconds 1 }
    }
    Write-Warning "hosts file could NOT be restored; original bytes are in memory only. Restore it from a backup now."
}

try {
    Write-Host "Run marker: $marker  (start $($started.ToString('o')) UTC)" -ForegroundColor Cyan

    # 1 + 2: short- and long-lived processes. Acceptance: full command line + user.
    & cmd.exe /c "echo $marker" | Out-Null
    Add-Step '1' 'short-lived cmd' 'process.create' "cmdline contains $marker, username is set"
    Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile', '-Command', "Start-Sleep 5 # $marker" -Wait
    Add-Step '2' 'long-lived powershell' 'process.create' "exe_sha256 is 'sha256:' + 64 hex (71 chars)"

    # 3: DNS + connection. Acceptance: pid/process present, rcode is NXDOMAIN.
    try { Resolve-DnsName "$marker.invalid" -ErrorAction Stop | Out-Null } catch { }
    Add-Step '3' 'DNS NXDOMAIN' 'network' "dns query for $marker.invalid carries process and rcode NXDOMAIN"

    # 4b: hosts file (opt-in).
    if ($HostsTest) {
        # Exact original bytes are restored at the end (never rewrite the file
        # from parsed text: a failed Set-Content once left hosts empty).
        $hostsOriginal = [IO.File]::ReadAllBytes($hostsFile)
        $hostsOriginalHash = (Get-FileHash -LiteralPath $hostsFile -Algorithm SHA256).Hash
        Add-Content -LiteralPath $hostsFile -Value $hostsLine
        Start-Sleep -Seconds 3
        Restore-Hosts
        Add-Step '4b' 'hosts file append/remove' 'filesystem.modify' 'modify with hash/diff, alert raised'
    }

    # 5: failed logon. A nonexistent local account; nothing is guessed or brute-forced.
    try {
        $sec = ConvertTo-SecureString 'x' -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential("$marker", $sec)
        Start-Process -FilePath cmd.exe -ArgumentList '/c', 'exit' -Credential $cred -ErrorAction Stop | Out-Null
    } catch { }
    Add-Step '5' 'failed logon' 'user.logon_failed' "reason and logon type are structured; no spurious SYSTEM success"

    # 6: persistence, HKCU Run value. Removed in finally.
    New-ItemProperty -Path $runKey -Name $marker -Value 'C:\Windows\System32\notepad.exe' -PropertyType String -Force | Out-Null
    Start-Sleep -Seconds 12   # the registry watcher diffs every 10 s
    Remove-ItemProperty -Path $runKey -Name $marker -ErrorAction SilentlyContinue
    Add-Step '6' 'HKCU Run value' 'registry' "registry create+delete for $marker, detection persistence.registry_run_*"

    # 7: ransomware burst on files created here (30 files -> *.docx.locked).
    New-Item -ItemType Directory -Path $work | Out-Null
    1..30 | ForEach-Object { Set-Content -LiteralPath (Join-Path $work "$marker-$_.docx") -Value "x$_" }
    Get-ChildItem -LiteralPath $work -Filter "$marker-*.docx" |
    ForEach-Object { Rename-Item -LiteralPath $_.FullName -NewName ($_.Name + '.locked') }
    Add-Step '7' 'ransomware burst (30 renames)' 'filesystem.ransomware_indicator' 'burst alert, severity critical at 30 files in 10 s'

    # 8: honeytoken (opt-in; opens the decoy read-only).
    if ($HoneytokenPath) {
        if (-not (Test-Path -LiteralPath $HoneytokenPath -PathType Leaf)) { throw "HoneytokenPath not found: $HoneytokenPath" }
        Get-Content -LiteralPath $HoneytokenPath -TotalCount 1 | Out-Null
        Add-Step '8' 'honeytoken read' 'detection.honeytoken_access' 'accessor names powershell.exe + user, severity high, < 5 s'
    }

    Write-Host "`nActivity done. Wait ~60 s, then run the queries below in ClickHouse." -ForegroundColor Green
    foreach ($r in $results) {
        Write-Host ("`n[{0}] {1}  ({2})" -f $r.Id, $r.Name, $r.EventType) -ForegroundColor Yellow
        Write-Host "  expect: $($r.Expect)"
        Write-Host ("  query : " + (Get-Query $marker))
    }
    Write-Host "`nTest 9 (offline buffer) is manual: block the gateway in the firewall, generate activity, restart the service, unblock, then compare event counts." -ForegroundColor DarkGray
    Write-Host "Fill in the PASS/PARTIAL/FAIL column of docs/windows-v0.7.2-field-test.md from the results." -ForegroundColor DarkGray
}
finally {
    Remove-ItemProperty -Path $runKey -Name $marker -ErrorAction SilentlyContinue
    if ($HostsTest -and $isAdmin) {
        if ((Get-FileHash -LiteralPath $hostsFile -Algorithm SHA256).Hash -ne $hostsOriginalHash) { Restore-Hosts }
    }
    # Only ever delete the folder this run created, identified by the marker.
    if ((Test-Path -LiteralPath $work) -and ((Split-Path $work -Leaf) -eq $marker)) {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}
