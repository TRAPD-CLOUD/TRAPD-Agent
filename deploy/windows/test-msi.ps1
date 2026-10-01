# Native Windows acceptance: service, protected state, signed configuration,
# sensors, TLS ingest, inventory, restart, major upgrade and uninstall.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Msi, [Parameter(Mandatory)][string]$AgentExe)
$ErrorActionPreference = 'Stop'
$Msi = (Resolve-Path $Msi).Path
$AgentExe = (Resolve-Path $AgentExe).Path
$root = Join-Path $env:RUNNER_TEMP ('trapd-msi-' + [guid]::NewGuid())
$data = Join-Path $env:ProgramData 'TRAPD'
$config = Join-Path $data 'config'
$state = Join-Path $data 'state'
$eventsPath = Join-Path $data 'logs\events.ndjson'
$watch = Join-Path $env:PUBLIC ('Documents\TRAPD-MSI-Smoke-' + [guid]::NewGuid())
$installedMsi = $Msi
New-Item -ItemType Directory -Force $root, $config, $watch | Out-Null

function Wait-Until([scriptblock]$Predicate, [string]$Message, [int]$Seconds = 120) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        if (& $Predicate) { return }
        Start-Sleep -Milliseconds 1000
    } while ([DateTime]::UtcNow -lt $deadline)
    throw $Message
}
function Invoke-Msi([string[]]$Arguments) {
    $p = Start-Process "$env:SystemRoot\System32\msiexec.exe" -ArgumentList $Arguments -Wait -PassThru
    if ($p.ExitCode -notin @(0, 3010)) { throw "msiexec failed with $($p.ExitCode)." }
}
function Read-Events {
    if (-not (Test-Path $eventsPath)) { return @() }
    @(Get-Content $eventsPath | ForEach-Object { try { $_ | ConvertFrom-Json } catch {} })
}
function Read-Requests {
    $p = Join-Path $root 'requests.ndjson'
    if (-not (Test-Path $p)) { return @() }
    @(Get-Content $p | ForEach-Object { try { $_ | ConvertFrom-Json } catch {} })
}

$defaults = Join-Path $root 'defaults.json'
& $AgentExe diagnostics config | Set-Content -Encoding utf8 $defaults
if ($LASTEXITCODE -ne 0) { throw 'Could not read agent configuration schema.' }
$backend = Start-Process python -ArgumentList @("`"$(Join-Path $PSScriptRoot 'mock-backend.py')`"", '--root', "`"$root`"", '--config-dir', "`"$config`"", '--default-config', "`"$defaults`"", '--watch-dir', "`"$watch`"") -PassThru -RedirectStandardError (Join-Path $root 'backend.err')
try {
    Wait-Until { Test-Path (Join-Path $root 'url.txt') } 'Test backend did not start.'
    $url = Get-Content -Raw (Join-Path $root 'url.txt')
    # First install has no backend properties: local collection must start
    # immediately, with no enrollment requirement.
    Invoke-Msi @('/i', "`"$Msi`"", '/qn', '/norestart', '/L*v', "`"$(Join-Path $root 'offline-install.log')`"")
    Wait-Until { (Get-Service trapd-agent -ErrorAction SilentlyContinue).Status -eq 'Running' } 'Offline service did not start.'
    Wait-Until { @(Read-Events | Where-Object { $_.class -eq 'system' }).Count -gt 0 } 'Offline MSI produced no local telemetry.'
    Wait-Until { Test-Path (Join-Path $state 'inventory.json') } 'Offline inventory was not written.'
    if (@(Read-Requests).Count -ne 0) { throw 'Offline installation contacted the backend.' }
    $offlineDevice = Get-Content -Raw (Join-Path $state 'device_id')
    Invoke-Msi @('/x', "`"$Msi`"", '/qn', '/norestart', '/L*v', "`"$(Join-Path $root 'offline-uninstall.log')`"")
    Wait-Until { $null -eq (Get-Service trapd-agent -ErrorAction SilentlyContinue) } 'Offline uninstall left the service.'
    Invoke-Msi @('/i', "`"$Msi`"", '/qn', '/norestart', "BACKENDURL=$url", 'ENROLLTOKEN=test-enrollment-token', '/L*v', "`"$(Join-Path $root 'install.log')`"")
    Wait-Until { (Get-Service trapd-agent -ErrorAction SilentlyContinue).Status -eq 'Running' } 'MSI service did not start.'
    Wait-Until { Test-Path (Join-Path $state 'config_issued_at.json') } 'Signed configuration was not applied.'
    Wait-Until { @(Read-Events | Where-Object { $_.class -eq 'system' }).Count -gt 0 } 'No system telemetry.'
    $device = Get-Content -Raw (Join-Path $state 'device_id')
    if ($device -ne $offlineDevice) { throw 'Reinstall changed retained identity.' }
    foreach ($dir in @($data, $config, $state, (Join-Path $data 'logs'))) {
        $acl = Get-Acl $dir
        if (-not $acl.AreAccessRulesProtected) { throw "Unprotected ACL: $dir" }
        foreach ($rule in $acl.Access) {
            $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            if ($rule.AccessControlType -eq 'Allow' -and $sid -notin @('S-1-5-18', 'S-1-5-32-544')) { throw "Unexpected ACL on $dir : $sid" }
        }
    }
    foreach ($item in @('HKLM:\SOFTWARE\TRAPD\Agent', (Join-Path $state 'credentials.json'), (Join-Path $config 'agent.env'))) {
        foreach ($rule in (Get-Acl $item).Access) {
            $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            if ($rule.AccessControlType -eq 'Allow' -and $sid -notin @('S-1-5-18', 'S-1-5-32-544')) { throw "Unexpected secret ACL on $item : $sid" }
        }
    }
    # Allow configuration reload to re-arm the file watcher before triggering it.
    Start-Sleep -Seconds 6
    $marker = Join-Path $watch 'sample.txt'
    'initial content' | Set-Content $marker
    $child = Start-Process "$env:SystemRoot\System32\cmd.exe" -ArgumentList '/c ping -n 18 127.0.0.1 > nul & rem TRAPD_MSI_SIGMA_SMOKE' -PassThru
    # Keep an ordinary TCP flow alive for more than one sensor interval.
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $client = [Net.Sockets.TcpClient]::new()
    $client.Connect('127.0.0.1', $listener.LocalEndpoint.Port)
    $peer = $listener.AcceptTcpClient()
    & "$env:SystemRoot\System32\eventcreate.exe" /T INFORMATION /ID 100 /L APPLICATION /SO TRAPD-MSI-Smoke /D TRAPD_MSI_EVENTLOG_SMOKE | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not create native event-log test record.' }
    Wait-Until { @(Read-Events | Where-Object { $_.class -eq 'process' -and $_.data.cmdline -like '*TRAPD_MSI_SIGMA_SMOKE*' }).Count -gt 0 } 'No process telemetry.'
    Wait-Until { @(Read-Events | Where-Object { $_.class -eq 'detection' -and $_.data.title -eq 'TRAPD MSI Sigma smoke' }).Count -gt 0 } 'Windows Sigma rule did not fire.'
    Wait-Until { @(Read-Events | Where-Object { $_.class -eq 'network' -and $_.data.dst_port -eq $listener.LocalEndpoint.Port }).Count -gt 0 } 'No native TCP telemetry.'
    $client.Dispose(); $peer.Dispose(); $listener.Stop()
    Wait-Until { @(Read-Events | Where-Object { $_.class -eq 'filesystem' -and $_.data.path -eq $marker }).Count -gt 0 } 'No file-change telemetry.'
    Start-Sleep -Seconds 12
    'changed content' | Set-Content $marker
    Wait-Until { @(Read-Events | Where-Object { $_.data.path -eq $marker -and $_.data.integrity -eq 'violation' }).Count -gt 0 } 'No SHA256 FIM violation.'
    Wait-Until { @(Read-Events | Where-Object { $_.class -eq 'log' -and $_.data.message -like '*TRAPD_MSI_EVENTLOG_SMOKE*' }).Count -gt 0 } 'No native Windows event-log telemetry.'
    Wait-Until { @(Read-Requests | Where-Object { $_.path -like '*/inventory' -and $_.body.os.family -eq 'windows' }).Count -gt 0 } 'No Windows inventory at backend.'
    Wait-Until { @(Read-Requests | Where-Object { $_.path -like '*/heartbeat' -and $_.status -eq 200 }).Count -gt 0 } 'No authenticated heartbeat.'
    Wait-Until { @(Read-Requests | Where-Object { $_.path -eq '/api/v1/ingest/events' -and $_.status -eq 200 }).Count -gt 0 } 'No authenticated TLS ingest.'

    # Outage across a service restart must replay the durable queue with the
    # same event IDs, then acknowledge it when ingest resumes.
    New-Item -ItemType File (Join-Path $root 'pause-ingest') | Out-Null
    $queuedMarker = Join-Path $watch 'queued.txt'
    'during outage' | Set-Content $queuedMarker
    Wait-Until { @(Read-Events | Where-Object { $_.data.path -eq $queuedMarker }).Count -gt 0 } 'Outage event was not collected.'
    $queuedIds = @(Read-Events | Where-Object { $_.data.path -eq $queuedMarker } | ForEach-Object event_id)
    Restart-Service trapd-agent
    Remove-Item (Join-Path $root 'pause-ingest')
    Wait-Until {
        $accepted = @(Read-Requests | Where-Object { $_.path -eq '/api/v1/ingest/events' -and $_.status -eq 200 } | ForEach-Object { $_.body } | ForEach-Object event_id)
        @($queuedIds | Where-Object { $_ -notin $accepted }).Count -eq 0
    } 'Durable outage events were not replayed with stable IDs.'
    if ((Get-Content -Raw (Join-Path $state 'device_id')) -ne $device) { throw 'Service restart changed device identity.' }

    Invoke-Msi @('/fa', "`"$Msi`"", '/qn', '/norestart', '/L*v', "`"$(Join-Path $root 'repair.log')`"")
    Wait-Until { (Get-Service trapd-agent).Status -eq 'Running' } 'Repair did not restart the service.'
    if ((Get-Content -Raw (Join-Path $state 'device_id')) -ne $device) { throw 'Repair changed device identity.' }

    # A replacement that cannot start must fail its MSI transaction and
    # restore the previous service and executable.
    $currentVersion = ((& $AgentExe --version) -replace '^trapd-agent v', '')
    $v = [version]$currentVersion
    $upgradedVersion = "$($v.Major).$($v.Minor).$($v.Build + 1)"
    $badExe = Join-Path $root 'invalid-agent.exe'
    'Deliberately invalid executable for MSI rollback acceptance' | Set-Content $badExe
    $badMsi = Join-Path $root 'invalid-upgrade.msi'
    & (Join-Path $PSScriptRoot 'build-msi.ps1') -AgentExe $badExe -Version $upgradedVersion -Output $badMsi
    $beforeBinary = (Get-FileHash (Join-Path $env:ProgramFiles 'TRAPD Agent\trapd-agent.exe')).Hash
    $failedUpgrade = Start-Process "$env:SystemRoot\System32\msiexec.exe" -ArgumentList @('/i', "`"$badMsi`"", '/qn', '/norestart', '/L*v', "`"$(Join-Path $root 'rollback.log')`"") -Wait -PassThru
    if ($failedUpgrade.ExitCode -in @(0, 3010)) { throw 'An invalid service executable was accepted.' }
    Wait-Until { (Get-Service trapd-agent -ErrorAction SilentlyContinue).Status -eq 'Running' } 'Rollback did not restore the previous service.'
    if ((Get-FileHash (Join-Path $env:ProgramFiles 'TRAPD Agent\trapd-agent.exe')).Hash -ne $beforeBinary) { throw 'Rollback did not restore the previous executable.' }
    if ((Get-Content -Raw (Join-Path $state 'device_id')) -ne $device) { throw 'Failed upgrade changed device identity.' }

    # Build a distinct product version and exercise the native MSI transaction.
    $upgrade = Join-Path $root 'upgrade.msi'
    & (Join-Path $PSScriptRoot 'build-msi.ps1') -AgentExe $AgentExe -Version $upgradedVersion -Output $upgrade
    $configHash = (Get-FileHash (Join-Path $config 'agent.env')).Hash
    Invoke-Msi @('/i', "`"$upgrade`"", '/qn', '/norestart', '/L*v', "`"$(Join-Path $root 'upgrade.log')`"")
    $installedMsi = $upgrade
    Wait-Until { (Get-Service trapd-agent).Status -eq 'Running' } 'Service did not survive major upgrade.'
    if ((Get-Content -Raw (Join-Path $state 'device_id')) -ne $device) { throw 'Upgrade changed identity.' }
    if ((Get-FileHash (Join-Path $config 'agent.env')).Hash -ne $configHash) { throw 'Upgrade overwrote agent.env.' }
    $downgrade = Start-Process "$env:SystemRoot\System32\msiexec.exe" -ArgumentList @('/i', "`"$Msi`"", '/qn', '/norestart') -Wait -PassThru
    if ($downgrade.ExitCode -in @(0, 3010)) { throw 'MSI downgrade was accepted.' }
    Invoke-Msi @('/x', "`"$installedMsi`"", '/qn', '/norestart', '/L*v', "`"$(Join-Path $root 'uninstall.log')`"")
    Wait-Until { $null -eq (Get-Service trapd-agent -ErrorAction SilentlyContinue) } 'Uninstall left the service registered.'
    if (Test-Path (Join-Path $env:ProgramFiles 'TRAPD Agent\trapd-agent.exe')) { throw 'Uninstall left the executable.' }
    if (-not (Test-Path (Join-Path $state 'device_id'))) { throw 'Uninstall removed retained identity.' }
    Write-Host 'MSI lifecycle and native telemetry acceptance passed.'
} finally {
    $logs = Join-Path (Get-Location) 'msi-test-results'
    New-Item -ItemType Directory -Force $logs | Out-Null
    Get-ChildItem $root -File | Where-Object { $_.Extension -notin @('.exe', '.msi', '.wixpdb', '.key') } | Copy-Item -Destination $logs -Force -ErrorAction SilentlyContinue
    if (Test-Path $eventsPath) { Copy-Item $eventsPath $logs -Force }
    Copy-Item (Join-Path $data 'logs\agent.log') $logs -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $backend.Id -Force -ErrorAction SilentlyContinue
    Stop-Service trapd-agent -Force -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $watch -ErrorAction SilentlyContinue
}
