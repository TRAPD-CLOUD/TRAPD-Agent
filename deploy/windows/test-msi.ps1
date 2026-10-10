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
$eventSource = 'TRAPD-MSI-Smoke-' + [guid]::NewGuid().ToString('N')
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
    @(Get-Content $eventsPath | ForEach-Object {
        try {
            $raw = $_ | ConvertFrom-Json
            if ($raw.metadata.version -eq '1.9.0' -and $raw.unmapped.trapd.schema_version -eq 1) {
                $source = $raw.unmapped.trapd
                [pscustomobject]@{ event_id = $raw.metadata.uid; agent_id = $raw.device.uid;
                    hostname = $raw.device.hostname; timestamp = $source.timestamp;
                    class = $source.class; action = $source.action; severity = $source.severity;
                    data = $source.data; origin = $source.origin }
            } else { $raw }
        } catch {}
    })
}
function Read-Requests {
    $p = Join-Path $root 'requests.ndjson'
    if (-not (Test-Path $p)) { return @() }
    @(Get-Content $p | ForEach-Object { try { $_ | ConvertFrom-Json } catch {} })
}

function Test-BlockExpiryAcrossRestart {
    # Stop before writing the rule so the old service cannot consume its TTL.
    Stop-Service trapd-agent
    $firewall = New-Object -ComObject HNetCfg.FwPolicy2
    $names = @('TRAPD-BLOCK-OUT-203.0.113.80', 'TRAPD-BLOCK-IN-203.0.113.80')
    $deadline = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + 15
    foreach ($name in $names) {
        $rule = New-Object -ComObject HNetCfg.FWRule
        $rule.Name = $name
        $rule.Grouping = 'TRAPD-Containment'
        $rule.Description = 'TRAPD containment: blocked indicator; expiry-v1:' + (@{ deadline = $deadline; command_id = 'expiry-acceptance' } | ConvertTo-Json -Compress)
        $rule.Protocol = 256
        $rule.Direction = if ($name -like '*-IN-*') { 1 } else { 2 }
        $rule.Action = 0
        $rule.RemoteAddresses = '203.0.113.80'
        $rule.Enabled = $true
        $firewall.Rules.Add($rule)
    }
    Start-Service trapd-agent
    Wait-Until { @($firewall.Rules | Where-Object { $_.Name -in $names }).Count -eq 0 } 'Restart lost the persistent firewall TTL.' 60
}

$defaults = Join-Path $root 'defaults.json'
& $AgentExe diagnostics config | Set-Content -Encoding utf8 $defaults
if ($LASTEXITCODE -ne 0) { throw 'Could not read agent configuration schema.' }
$backend = Start-Process python -ArgumentList @("`"$(Join-Path $PSScriptRoot 'mock-backend.py')`"", '--root', "`"$root`"", '--config-dir', "`"$config`"", '--default-config', "`"$defaults`"", '--watch-dir', "`"$watch`"") -PassThru -RedirectStandardError (Join-Path $root 'backend.err')
try {
    Add-Type -AssemblyName System.Diagnostics.EventLog
    # Register before installation so Windows can refresh its source cache.
    # WriteEntry later exercises the real Application log without depending
    # on eventcreate.exe's implicit registration/permission behavior.
    [Diagnostics.EventLog]::CreateEventSource($eventSource, 'Application')
    Wait-Until { Test-Path (Join-Path $root 'url.txt') } 'Test backend did not start.'
    $url = Get-Content -Raw (Join-Path $root 'url.txt')
    # First install has no backend properties: local collection must start
    # immediately, with no enrollment requirement.
    Invoke-Msi @('/i', "`"$Msi`"", '/qn', '/norestart', '/L*v', "`"$(Join-Path $root 'offline-install.log')`"")
    # Check before enrollment too: shortcut bookkeeping must not create the
    # credential key with inherited Users access ahead of RegistryConfig.
    foreach ($rule in (Get-Acl 'HKLM:\SOFTWARE\TRAPD\Agent').Access) {
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($rule.AccessControlType -eq 'Allow' -and $sid -notin @('S-1-5-18', 'S-1-5-32-544')) { throw "Unexpected registry ACL on first install: $sid" }
    }
    Wait-Until { (Get-Service trapd-agent -ErrorAction SilentlyContinue).Status -eq 'Running' } 'Offline service did not start.'
    Wait-Until { @(Read-Events | Where-Object { $_.class -eq 'system' }).Count -gt 0 } 'Offline MSI produced no local telemetry.'
    Wait-Until { Test-Path (Join-Path $state 'inventory.json') } 'Offline inventory was not written.'
    if (@(Read-Requests).Count -ne 0) { throw 'Offline installation contacted the backend.' }
    Test-BlockExpiryAcrossRestart
    $offlineDevice = Get-Content -Raw (Join-Path $state 'device_id')
    Invoke-Msi @('/x', "`"$Msi`"", '/qn', '/norestart', '/L*v', "`"$(Join-Path $root 'offline-uninstall.log')`"")
    Wait-Until { $null -eq (Get-Service trapd-agent -ErrorAction SilentlyContinue) } 'Offline uninstall left the service.'

    # Pairing mode (backend, no token): the agent publishes a code and waits for
    # a person. It must still honour a service stop, otherwise MSI removal or
    # upgrade of an unpaired agent would hang (regression: stop was ignored
    # while enrolling).
    Invoke-Msi @('/i', "`"$Msi`"", '/qn', '/norestart', "BACKENDURL=$url", '/L*v', "`"$(Join-Path $root 'pairing-install.log')`"")
    Wait-Until { (Get-Service trapd-agent -ErrorAction SilentlyContinue).Status -eq 'Running' } 'Pairing-mode service did not start.'
    $pairingFile = Join-Path $state 'pairing.txt'
    Wait-Until { Test-Path $pairingFile } 'Agent did not publish pairing.txt.'
    $pairing = Get-Content -Raw $pairingFile
    if ($pairing -notmatch 'Code:\s+ABCDE-FGHJK') { throw 'pairing.txt does not show the pairing code.' }
    if ($pairing -match 'pair_msi_test_device_code') { throw 'pairing.txt leaked the device code.' }
    # The code is only for administrators (whoever sees it can approve the device).
    foreach ($rule in (Get-Acl $pairingFile).Access) {
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($rule.AccessControlType -eq 'Allow' -and $sid -notin @('S-1-5-18', 'S-1-5-32-544')) { throw "Unexpected ACL on pairing.txt : $sid" }
    }
    $helper = Join-Path $env:ProgramFiles 'TRAPD Agent\pair.ps1'
    $helperOut = (& $helper -NonInteractive -WaitSeconds 10 | Out-String)
    if ($helperOut -notmatch 'ABCDE-FGHJK') { throw 'pair.ps1 did not show the pairing code.' }
    if (-not (Test-Path (Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'TRAPD\Pair this computer with TRAPD.lnk'))) { throw 'Pairing shortcut is missing.' }
    if (@(Read-Requests | Where-Object { $_.path -like '*/agents/pair/start' }).Count -lt 1) { throw 'Agent did not start pairing at the backend.' }
    Test-BlockExpiryAcrossRestart
    Invoke-Msi @('/x', "`"$Msi`"", '/qn', '/norestart', '/L*v', "`"$(Join-Path $root 'pairing-uninstall.log')`"")
    Wait-Until { $null -eq (Get-Service trapd-agent -ErrorAction SilentlyContinue) } 'Uninstall during pending pairing left the service.'
    if (Test-Path $pairingFile) { throw 'pairing.txt survived the service stop.' }
    if (Test-Path (Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'TRAPD')) { throw 'Uninstall left the Start Menu folder.' }

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
    [Diagnostics.EventLog]::WriteEntry($eventSource, 'TRAPD_MSI_EVENTLOG_SMOKE', [Diagnostics.EventLogEntryType]::Information, 100)
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

    # The generic package has no release key, so no updater/helper consumes
    # this synthetic staging marker. Exercise the real heartbeat confirmation.
    $updateDir = Join-Path $state 'update'
    New-Item -ItemType Directory -Force $updateDir | Out-Null
    $stagedOffer = Join-Path $updateDir 'staged.offer.json'
    $healthyMarker = Join-Path $updateDir 'healthy'
    if ((Test-Path $stagedOffer) -or (Test-Path $healthyMarker)) { throw 'Unexpected update state before heartbeat acceptance.' }
    $pauseHeartbeat = Join-Path $root 'pause-heartbeat'
    New-Item -ItemType File $pauseHeartbeat | Out-Null
    $failedBefore = @(Read-Requests | Where-Object { $_.path -like '*/heartbeat' -and $_.status -eq 500 }).Count
    Wait-Until { @(Read-Requests | Where-Object { $_.path -like '*/heartbeat' -and $_.status -eq 500 }).Count -gt $failedBefore } 'Heartbeat outage was not exercised.' 30
    $failedBefore = @(Read-Requests | Where-Object { $_.path -like '*/heartbeat' -and $_.status -eq 500 }).Count
    '{}' | Set-Content $stagedOffer
    Wait-Until { @(Read-Requests | Where-Object { $_.path -like '*/heartbeat' -and $_.status -eq 500 }).Count -gt $failedBefore } 'No rejected heartbeat with staged update.' 30
    if (Test-Path $healthyMarker) { throw 'A failed heartbeat confirmed update health.' }
    Remove-Item $pauseHeartbeat
    Wait-Until { Test-Path $healthyMarker } 'Successful Windows heartbeat did not confirm the update.' 30
    $expectedVersion = ((& $AgentExe --version) -replace '^trapd-agent v', '').Trim()
    if ((Get-Content -Raw $healthyMarker).Trim() -ne $expectedVersion) { throw 'Heartbeat confirmed the wrong update version.' }
    Remove-Item $stagedOffer, $healthyMarker

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

    # Persistent containment must not outlive explicit removal. TEST-NET
    # remote scopes keep the CI host reachable while exercising enabled rules.
    $firewall = New-Object -ComObject HNetCfg.FwPolicy2
    $containmentNames = @('TRAPD-ISOLATE-OUT', 'TRAPD-ISOLATE-IN', 'TRAPD-BLOCK-OUT-203.0.113.79')
    $externalName = 'TRAPD-MSI-EXTERNAL-TEST'
    foreach ($name in ($containmentNames + @($externalName))) {
        $rule = New-Object -ComObject HNetCfg.FWRule
        $rule.Name = $name
        $rule.Grouping = if ($name -eq $externalName) { 'Other-Application' } else { 'TRAPD-Containment' }
        $rule.Protocol = 256
        $rule.Direction = if ($name -eq 'TRAPD-ISOLATE-IN') { 1 } else { 2 }
        $rule.Action = 0
        $rule.RemoteAddresses = '203.0.113.79'
        $rule.Enabled = $true
        $firewall.Rules.Add($rule)
    }

    # A replacement that cannot start must fail its MSI transaction and
    # restore the previous service and executable.
    # Simulate the valid binary signature left by a signed self-update.
    Stop-Service trapd-agent
    $installedExe = Join-Path $env:ProgramFiles 'TRAPD Agent\trapd-agent.exe'
    @'
import hashlib, pathlib, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
key = Ed25519PrivateKey.generate()
config = pathlib.Path(sys.argv[1])
(config / 'release_signing.pub').write_bytes(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
(config / 'binary.sig').write_bytes(key.sign(hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).digest()))
'@ | python - $config $installedExe
    if ($LASTEXITCODE -ne 0) { throw 'Could not provision self-update signature fixture.' }
    $beforeSignature = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $config 'binary.sig')))
    $beforeReleaseKey = (Get-FileHash (Join-Path $config 'release_signing.pub')).Hash
    Start-Service trapd-agent
    $currentVersion = ((& $AgentExe --version) -replace '^trapd-agent v', '')
    $v = [version]$currentVersion
    $upgradedVersion = "$($v.Major).$($v.Minor).$($v.Build + 1)"
    $badExe = Join-Path $root 'invalid-agent.exe'
    'Deliberately invalid executable for MSI rollback acceptance' | Set-Content $badExe
    $badMsi = Join-Path $root 'invalid-upgrade.msi'
    & (Join-Path $PSScriptRoot 'build-msi.ps1') -AgentExe $badExe -Version $upgradedVersion -Output $badMsi
    $beforeBinary = (Get-FileHash (Join-Path $env:ProgramFiles 'TRAPD Agent\trapd-agent.exe')).Hash
    $beforeBaseline = Get-Content -Raw (Join-Path $config 'binary.sha256')
    $failedUpgrade = Start-Process "$env:SystemRoot\System32\msiexec.exe" -ArgumentList @('/i', "`"$badMsi`"", '/qn', '/norestart', '/L*v', "`"$(Join-Path $root 'rollback.log')`"") -Wait -PassThru
    if ($failedUpgrade.ExitCode -in @(0, 3010)) { throw 'An invalid service executable was accepted.' }
    Wait-Until { (Get-Service trapd-agent -ErrorAction SilentlyContinue).Status -eq 'Running' } 'Rollback did not restore the previous service.'
    if ((Get-FileHash (Join-Path $env:ProgramFiles 'TRAPD Agent\trapd-agent.exe')).Hash -ne $beforeBinary) { throw 'Rollback did not restore the previous executable.' }
    if ((Get-Content -Raw (Join-Path $config 'binary.sha256')) -ne $beforeBaseline) { throw 'Rollback did not restore the binary integrity baseline.' }
    if ([Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $config 'binary.sig'))) -ne $beforeSignature) { throw 'Rollback did not restore the previous binary signature.' }
    if ((Get-Content -Raw (Join-Path $state 'device_id')) -ne $device) { throw 'Failed upgrade changed device identity.' }

    # Build a distinct product version and exercise the native MSI transaction.
    $upgrade = Join-Path $root 'upgrade.msi'
    & (Join-Path $PSScriptRoot 'build-msi.ps1') -AgentExe $AgentExe -Version $upgradedVersion -Output $upgrade
    $configHash = (Get-FileHash (Join-Path $config 'agent.env')).Hash
    # A legitimate MSI replacement must reset an obsolete digest itself;
    # the new process may not trust an embedded version to excuse a mismatch.
    ('sha256:' + ('0' * 64)) | Set-Content (Join-Path $config 'binary.sha256')
    # An obsolete signature must be removed by the same trusted transaction,
    # without removing the independently provisioned release trust anchor.
    [IO.File]::WriteAllBytes((Join-Path $config 'binary.sig'), [byte[]]::new(64))
    '0.0.1' | Set-Content (Join-Path $config 'binary.version')
    Invoke-Msi @('/i', "`"$upgrade`"", '/qn', '/norestart', '/L*v', "`"$(Join-Path $root 'upgrade.log')`"")
    $installedMsi = $upgrade
    Wait-Until { (Get-Service trapd-agent).Status -eq 'Running' } 'Service did not survive major upgrade.'
    Wait-Until { ((Get-Content -Raw (Join-Path $config 'binary.sha256')).Trim()) -eq ('sha256:' + $beforeBinary.ToLowerInvariant()) } 'MSI did not establish the installed binary integrity baseline.' 30
    if (Test-Path (Join-Path $config 'binary.sig')) { throw 'Upgrade retained an obsolete binary signature.' }
    if ((Get-FileHash (Join-Path $config 'release_signing.pub')).Hash -ne $beforeReleaseKey) { throw 'Upgrade changed the release trust anchor.' }
    if ((Get-Content -Raw (Join-Path $state 'device_id')) -ne $device) { throw 'Upgrade changed identity.' }
    if ((Get-FileHash (Join-Path $config 'agent.env')).Hash -ne $configHash) { throw 'Upgrade overwrote agent.env.' }
    foreach ($name in $containmentNames) {
        if (@($firewall.Rules | Where-Object { $_.Name -eq $name -and $_.Enabled }).Count -ne 1) { throw "Upgrade did not preserve containment rule $name." }
    }
    $downgrade = Start-Process "$env:SystemRoot\System32\msiexec.exe" -ArgumentList @('/i', "`"$Msi`"", '/qn', '/norestart') -Wait -PassThru
    if ($downgrade.ExitCode -in @(0, 3010)) { throw 'MSI downgrade was accepted.' }
    Invoke-Msi @('/x', "`"$installedMsi`"", '/qn', '/norestart', '/L*v', "`"$(Join-Path $root 'uninstall.log')`"")
    Wait-Until { $null -eq (Get-Service trapd-agent -ErrorAction SilentlyContinue) } 'Uninstall left the service registered.'
    if (Test-Path (Join-Path $env:ProgramFiles 'TRAPD Agent\trapd-agent.exe')) { throw 'Uninstall left the executable.' }
    if (-not (Test-Path (Join-Path $state 'device_id'))) { throw 'Uninstall removed retained identity.' }
    $remaining = @($firewall.Rules | Where-Object { $_.Grouping -eq 'TRAPD-Containment' })
    if ($remaining.Count -ne 0) { throw 'Uninstall left persistent TRAPD containment rules.' }
    if (@($firewall.Rules | Where-Object { $_.Name -eq $externalName }).Count -ne 1) { throw 'Uninstall removed another application firewall rule.' }
    $firewall.Rules.Remove($externalName)
    Write-Host 'MSI lifecycle and native telemetry acceptance passed.'
} finally {
    $logs = Join-Path (Get-Location) 'msi-test-results'
    New-Item -ItemType Directory -Force $logs | Out-Null
    Get-ChildItem $root -File | Where-Object { $_.Extension -notin @('.exe', '.msi', '.wixpdb', '.key') } | Copy-Item -Destination $logs -Force -ErrorAction SilentlyContinue
    if (Test-Path $eventsPath) { Copy-Item $eventsPath $logs -Force }
    Copy-Item (Join-Path $data 'logs\agent.log') $logs -Force -ErrorAction SilentlyContinue
    # Keep failure evidence visible in the job log as well as the artifact.
    Read-Events | Group-Object class, action | Select-Object Name, Count | Format-Table | Out-Host
    if (Test-Path (Join-Path $data 'logs\agent.log')) {
        Get-Content (Join-Path $data 'logs\agent.log') -Tail 30 | Out-Host
    }
    Stop-Process -Id $backend.Id -Force -ErrorAction SilentlyContinue
    Stop-Service trapd-agent -Force -ErrorAction SilentlyContinue
    if ([Diagnostics.EventLog]::SourceExists($eventSource)) {
        [Diagnostics.EventLog]::DeleteEventSource($eventSource)
    }
    Remove-Item -Recurse -Force $watch -ErrorAction SilentlyContinue
}
