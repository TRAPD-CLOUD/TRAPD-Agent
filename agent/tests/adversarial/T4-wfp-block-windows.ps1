# T4: EDRSilencer-style silencing. Adds a Windows Firewall outbound block rule
# for the TRAPD agent executable (compiled into a WFP block filter) and removes
# it again. Expected: selfprotect.network_silenced (high) within ~65 s, naming
# the rule, provider "Microsoft Windows Firewall" and the ALE connect layer.
#
# Requires: elevated PowerShell on a test host, TRAPD_ADVERSARIAL_OK=1.
param([string]$AgentExe = 'C:\Program Files\TRAPD Agent\trapd-agent.exe')

if ($env:TRAPD_ADVERSARIAL_OK -ne '1') {
    Write-Error 'Refusing to run: set TRAPD_ADVERSARIAL_OK=1 on a disposable test host.'
    exit 2
}
$name = 'TRAPD-ADVERSARIAL-T4-block-agent'
try {
    New-NetFirewallRule -DisplayName $name -Direction Outbound -Action Block `
        -Program $AgentExe -Profile Any | Out-Null
    Write-Host "Rule '$name' created. Waiting 75 s for the network guard..."
    Start-Sleep -Seconds 75
    Write-Host "Verify: console shows selfprotect.network_silenced with filter name '$name'."
}
finally {
    Remove-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
    Write-Host 'Rule removed. Events queued during the block are delivered now.'
}
