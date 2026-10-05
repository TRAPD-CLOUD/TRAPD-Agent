# Shows this computer's TRAPD pairing code and opens the pairing page.
#
# The agent writes the code to %ProgramData%\TRAPD\state\pairing.txt. That
# directory is restricted to SYSTEM and Administrators on purpose: whoever sees
# the code can approve this computer into their own TRAPD workspace. This helper
# therefore re-launches itself elevated (UAC) before reading the file.
[CmdletBinding()]
param(
    # Automation/tests: no UAC relaunch, no browser, no "press Enter" pause.
    [switch]$NonInteractive,
    [int]$WaitSeconds = 60
)
$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    if ($NonInteractive) { throw 'Administrator rights are required to read the pairing code.' }
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    Start-Process -FilePath $ps -Verb RunAs -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath))
    return
}

function Exit-Helper([int]$Code) {
    if (-not $NonInteractive) { Read-Host 'Press Enter to close' | Out-Null }
    exit $Code
}

$file = Join-Path $env:ProgramData 'TRAPD\state\pairing.txt'
Write-Output 'Looking for the pairing code of this computer...'
$deadline = (Get-Date).AddSeconds($WaitSeconds)
while (-not (Test-Path -LiteralPath $file) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 1 }
if (-not (Test-Path -LiteralPath $file)) {
    Write-Output 'No pairing is pending. This computer is either already paired (check Agents in the TRAPD web app) or the "TRAPD Agent" service is not running.'
    Exit-Helper 1
}

# Parse defensively: only values of the expected shape are shown or opened.
$text = Get-Content -LiteralPath $file -Raw
$code = [regex]::Match($text, '(?m)^2\. Code:\s+([A-Z0-9-]{1,32})\s*$').Groups[1].Value
$page = [regex]::Match($text, '(?m)^1\. Open:\s+(https?://[^\s\x00-\x1f]{1,2000})\s*$').Groups[1].Value
$link = [regex]::Match($text, '(?m)^Direct link:\s+(https?://[^\s\x00-\x1f]{1,2000})\s*$').Groups[1].Value
$until = [regex]::Match($text, '(?m)^Valid until:\s+([0-9TZ:+.-]{10,40})\s*$').Groups[1].Value
if (-not $code) {
    Write-Output 'The pairing file has an unexpected format. Restart the "TRAPD Agent" service and try again.'
    Exit-Helper 1
}

Write-Output ''
Write-Output "  Pairing code:  $code"
if ($page) { Write-Output "  Pairing page:  $page" }
if ($until) { Write-Output "  Valid until:   $until" }
Write-Output ''
Write-Output 'Sign in to TRAPD, enter the code and confirm only if you are installing this computer yourself.'

if ($link -and -not $NonInteractive) {
    Write-Output 'Opening the pairing page in your browser...'
    Start-Process $link
}
Exit-Helper 0
