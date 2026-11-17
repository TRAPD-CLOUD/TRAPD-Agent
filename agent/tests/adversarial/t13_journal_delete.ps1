# T13 (WP3): deleting the local tamper journal (or restoring an old copy) before
# its entries reached the backend must be detected server-side.
# Run elevated on a bound, enrolled TEST agent. The original journal file is
# always restored at the end (also on error).
if ($env:TRAPD_ADVERSARIAL_OK -ne '1') { Write-Host 'refusing: set TRAPD_ADVERSARIAL_OK=1'; exit 2 }
$state = if ($env:TRAPD_STATE_DIR) { $env:TRAPD_STATE_DIR } else { Join-Path $env:ProgramData 'TRAPD' }
$j = Join-Path $state 'tamper_journal.ndjson'
if (-not (Test-Path $j)) { Write-Host "no journal at $j (agent not bound yet, or journal disabled)"; exit 2 }
$backup = Join-Path ([IO.Path]::GetTempPath()) ("trapd-t13-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $backup | Out-Null
Copy-Item $j (Join-Path $backup 'journal')
try {
  Stop-Service trapd-agent
  Remove-Item $j -Force
  Start-Service trapd-agent
  Write-Host 'journal deleted; waiting 90 s for the agent to upload its new chain ...'
  Start-Sleep -Seconds 90
  Write-Host "RESULT: expected a high finding 'selfprotect.journal_gap' (reason: fork or regression) for this agent."
  Write-Host 'Verify in the console (Findings); the agent log shows: backend rejected the tamper journal.'
} finally {
  Stop-Service trapd-agent -ErrorAction SilentlyContinue
  Copy-Item (Join-Path $backup 'journal') $j -Force
  Start-Service trapd-agent -ErrorAction SilentlyContinue
  Remove-Item $backup -Recurse -Force
}
