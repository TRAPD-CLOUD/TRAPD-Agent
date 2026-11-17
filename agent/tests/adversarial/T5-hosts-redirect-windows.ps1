# T5: backend redirect through the hosts file. Adds an entry for the backend
# host and removes it again. Expected: selfprotect.backend_redirected (high,
# vector "hosts") within ~65 s.
#
# Requires: elevated PowerShell, TRAPD_ADVERSARIAL_OK=1, -BackendHost <host>.
param([Parameter(Mandatory = $true)][string]$BackendHost)

if ($env:TRAPD_ADVERSARIAL_OK -ne '1') {
    Write-Error 'Refusing to run: set TRAPD_ADVERSARIAL_OK=1 on a disposable test host.'
    exit 2
}
$hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$backup = "$hosts.trapd-adversarial.bak"
Copy-Item $hosts $backup -Force
try {
    Add-Content -Path $hosts -Value "203.0.113.66 $BackendHost # trapd adversarial T5"
    Write-Host 'Hosts entry added. Waiting 75 s for the network guard...'
    Start-Sleep -Seconds 75
    Write-Host 'Verify: selfprotect.backend_redirected, vector hosts, subject "203.0.113.66 <host>".'
}
finally {
    Copy-Item $backup $hosts -Force
    Remove-Item $backup -Force
    Write-Host 'Hosts file restored.'
}
