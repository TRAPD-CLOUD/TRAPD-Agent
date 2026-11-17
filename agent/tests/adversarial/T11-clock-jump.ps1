# T11 (Windows): move the wall clock back one hour and restore it.
# Expected: selfprotect.time_jump (medium) within ~30 s (backward), another on restore (forward).
if ($env:TRAPD_ADVERSARIAL_OK -ne '1') { Write-Error 'refusing: set TRAPD_ADVERSARIAL_OK=1'; exit 1 }
$start = Get-Date
$sw = [Diagnostics.Stopwatch]::StartNew()
try {
  Stop-Service w32time -ErrorAction SilentlyContinue
  Set-Date -Date $start.AddHours(-1) | Out-Null
  Start-Sleep -Seconds 70
} finally {
  # Restore to start + elapsed real time.
  Set-Date -Date $start.Add($sw.Elapsed) | Out-Null
  Start-Service w32time -ErrorAction SilentlyContinue
}
Write-Host 'done; a second (forward) time_jump is expected on restore'
