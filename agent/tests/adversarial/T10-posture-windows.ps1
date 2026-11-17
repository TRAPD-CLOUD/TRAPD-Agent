# T10 (Windows): weaken registry-visible posture and restore.
# Expected: selfprotect.platform_posture_changed (high) for lsass_ppl and driver_blocklist
# after the next 15-min round (restart the agent service to compare immediately).
# test-signing / Secure Boot / kernel debugger need a reboot and are MANUAL, see README.
if ($env:TRAPD_ADVERSARIAL_OK -ne '1') { Write-Error 'refusing: set TRAPD_ADVERSARIAL_OK=1'; exit 1 }
$ci  = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'
$old = (Get-ItemProperty $ci -ErrorAction SilentlyContinue).VulnerableDriverBlocklistEnable
if ($null -eq $old) { New-Item -Path $ci -Force | Out-Null; Set-ItemProperty $ci VulnerableDriverBlocklistEnable 1 -Type DWord; $old = 1 }
Restart-Service trapd-agent   # records the baseline with the blocklist on
Start-Sleep 20
try {
  Set-ItemProperty $ci VulnerableDriverBlocklistEnable 0 -Type DWord
  Restart-Service trapd-agent
  Start-Sleep 30
  Write-Host 'expect platform_posture_changed (high, driver_blocklist on -> off)'
} finally {
  Set-ItemProperty $ci VulnerableDriverBlocklistEnable $old -Type DWord
  Restart-Service trapd-agent
}
