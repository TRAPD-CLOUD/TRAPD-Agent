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
# The hardened DACLs (self-protection WP2/WP3) deny administrators stopping the
# service and writing to the install, config and state directories, which is
# what the lifecycle below needs to do. Run exactly those steps as SYSTEM, like
# the MSI itself does, through a one-shot scheduled task.
function Invoke-AsSystem([string]$Command) {
    $id = 'trapd-test-' + [guid]::NewGuid().ToString('N')
    $script = Join-Path $root "$id.ps1"
    $result = Join-Path $root "$id.result"
    @"
`$ErrorActionPreference = 'Stop'
try { $Command; 'ok' | Set-Content -LiteralPath '$result' } catch { `$_.ToString() | Set-Content -LiteralPath '$result' }
"@ | Set-Content -LiteralPath $script
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$script`""
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $id -Action $action -Principal $principal | Out-Null
    try {
        Start-ScheduledTask -TaskName $id
        Wait-Until { Test-Path -LiteralPath $result } "SYSTEM helper did not finish: $Command" 180
        $text = (Get-Content -Raw -LiteralPath $result).Trim()
        if ($text -ne 'ok') { throw "SYSTEM helper failed ($Command): $text" }
    } finally { Unregister-ScheduledTask -TaskName $id -Confirm:$false -ErrorAction SilentlyContinue }
}
function Stop-AgentService { Invoke-AsSystem 'Stop-Service trapd-agent' }
function Start-AgentService { Invoke-AsSystem 'Start-Service trapd-agent' }
function Copy-AsSystem([string]$From, [string]$To) { Invoke-AsSystem "Copy-Item -LiteralPath '$From' -Destination '$To' -Force" }
function Assert-AccessDenied([string]$What, [bool]$Denied) {
    # sc.exe reports ERROR_ACCESS_DENIED as 5; reg.exe exits non-zero.
    if (-not $Denied) { throw "$What was allowed for an administrator." }
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
# Audit baseline (command lines in 4688): the installer enables it, removal puts
# back exactly what it found. Compared against the state before the first
# install, so a runner that already had it on is also a valid case.
function Get-AuditBaseline {
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    $success = {
        param($guid)
        $csv = (& "$env:SystemRoot\System32\auditpol.exe" /get "/subcategory:$guid" /r) -join "`n"
        [bool]($csv -match 'Success')
    }
    [pscustomobject]@{
        Success = (& $success '{0CCE922B-69AE-11D9-BED3-505054503030}')   # Process Creation
        FileSuccess = (& $success '{0CCE921D-69AE-11D9-BED3-505054503030}') # File System (honeytoken accessors)
        CmdLine = (Get-ItemProperty $key -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
    }
}
function Assert-AuditBaseline($Expected, [string]$When) {
    $now = Get-AuditBaseline
    if ($now.Success -ne $Expected.Success -or $now.FileSuccess -ne $Expected.FileSuccess -or $now.CmdLine -ne $Expected.CmdLine) {
        throw "Audit baseline ${When}: expected Success=$($Expected.Success) FileSuccess=$($Expected.FileSuccess) CmdLine=$($Expected.CmdLine), got Success=$($now.Success) FileSuccess=$($now.FileSuccess) CmdLine=$($now.CmdLine)."
    }
}
function Read-Requests {
    $p = Join-Path $root 'requests.ndjson'
    if (-not (Test-Path $p)) { return @() }
    @(Get-Content $p | ForEach-Object { try { $_ | ConvertFrom-Json } catch {} })
}

function Test-BlockExpiryAcrossRestart {
    # Stop before writing the rule so the old service cannot consume its TTL.
    Stop-AgentService
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
    Start-AgentService
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
    $auditBefore = Get-AuditBaseline
    Invoke-Msi @('/i', "`"$Msi`"", '/qn', '/norestart', '/L*v', "`"$(Join-Path $root 'offline-install.log')`"")
    Assert-AuditBaseline ([pscustomobject]@{ Success = $true; FileSuccess = $true; CmdLine = 1 }) 'after install (default AUDITBASELINE=1)'
    # Check before enrollment too: shortcut bookkeeping must not create the
    # credential key with inherited Users access ahead of RegistryConfig.
    foreach ($rule in (Get-Acl 'HKLM:\SOFTWARE\TRAPD\Agent').Access) {
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($rule.AccessControlType -eq 'Allow' -and $sid -notin @('S-1-5-18', 'S-1-5-32-544', 'S-1-3-4')) { throw "Unexpected registry ACL on first install: $sid" }
    }
    Wait-Until { (Get-Service trapd-agent -ErrorAction SilentlyContinue).Status -eq 'Running' } 'Offline service did not start.'
    Wait-Until { @(Read-Events | Where-Object { $_.class -eq 'system' }).Count -gt 0 } 'Offline MSI produced no local telemetry.'
    Wait-Until { Test-Path (Join-Path $state 'inventory.json') } 'Offline inventory was not written.'
    if (@(Read-Requests).Count -ne 0) { throw 'Offline installation contacted the backend.' }
    Test-BlockExpiryAcrossRestart
    $offlineDevice = Get-Content -Raw (Join-Path $state 'device_id')
    Invoke-Msi @('/x', "`"$Msi`"", '/qn', '/norestart', '/L*v', "`"$(Join-Path $root 'offline-uninstall.log')`"")
    Wait-Until { $null -eq (Get-Service trapd-agent -ErrorAction SilentlyContinue) } 'Offline uninstall left the service.'
    Assert-AuditBaseline $auditBefore 'after uninstall (must restore what the installer changed)'

    # Pairing mode (backend, no token): the agent publishes a code and waits for
    # a person. It must still honour a service stop, otherwise MSI removal or
    # upgrade of an unpaired agent would hang (regression: stop was ignored
    # while enrolling).
    Invoke-Msi @('/i', "`"$Msi`"", '/qn', '/norestart', "BACKENDURL=$url", 'AUDITBASELINE=0', '/L*v', "`"$(Join-Path $root 'pairing-install.log')`"")
    Assert-AuditBaseline $auditBefore 'after install with AUDITBASELINE=0 (opt-out must not touch the policy)'
    Wait-Until { (Get-Service trapd-agent -ErrorAction SilentlyContinue).Status -eq 'Running' } 'Pairing-mode service did not start.'
    $pairingFile = Join-Path $state 'pairing.txt'
    Wait-Until { Test-Path $pairingFile } 'Agent did not publish pairing.txt.'
    $pairing = Get-Content -Raw $pairingFile
    if ($pairing -notmatch 'Code:\s+ABCDE-FGHJK') { throw 'pairing.txt does not show the pairing code.' }
    if ($pairing -match 'pair_msi_test_device_code') { throw 'pairing.txt leaked the device code.' }
    # The code is only for administrators (whoever sees it can approve the device).
    foreach ($rule in (Get-Acl $pairingFile).Access) {
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($rule.AccessControlType -eq 'Allow' -and $sid -notin @('S-1-5-18', 'S-1-5-32-544', 'S-1-3-4')) { throw "Unexpected ACL on pairing.txt : $sid" }
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

    # Token goes through a file (ENROLLTOKENFILE): the MSI log and command line must never carry it.
    $tokenFile = Join-Path $root 'enroll.token'
    [IO.File]::WriteAllText($tokenFile, 'test-enrollment-token', (New-Object Text.UTF8Encoding $false))
    Invoke-Msi @('/i', "`"$Msi`"", '/qn', '/norestart', "BACKENDURL=$url", "ENROLLTOKENFILE=`"$tokenFile`"", '/L*v', "`"$(Join-Path $root 'install.log')`"")
    Remove-Item -Force $tokenFile -ErrorAction SilentlyContinue
    if (Select-String -LiteralPath (Join-Path $root 'install.log') -SimpleMatch 'test-enrollment-token' -Quiet) { throw 'The enrollment token appears in the MSI log.' }
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
            if ($rule.AccessControlType -eq 'Allow' -and $sid -notin @('S-1-5-18', 'S-1-5-32-544', 'S-1-3-4')) { throw "Unexpected ACL on $dir : $sid" }
        }
    }
    foreach ($item in @('HKLM:\SOFTWARE\TRAPD\Agent', (Join-Path $state 'credentials.json'), (Join-Path $config 'agent.env'))) {
        foreach ($rule in (Get-Acl $item).Access) {
            $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            if ($rule.AccessControlType -eq 'Allow' -and $sid -notin @('S-1-5-18', 'S-1-5-32-544', 'S-1-3-4')) { throw "Unexpected secret ACL on $item : $sid" }
        }
    }
    # The one-time token must be gone from the registry once enrollment succeeded.
    if ($null -ne (Get-ItemProperty 'HKLM:\SOFTWARE\TRAPD\Agent' -Name EnrollToken -ErrorAction SilentlyContinue)) { throw 'Enrollment token survived enrollment in the registry.' }
    # Hardened service DACL: administrators may start/stop but not rewrite the DACL or owner.
    $serviceSd = (& "$env:SystemRoot\System32\sc.exe" sdshow trapd-agent) -join ''
    if ($serviceSd -notmatch '\(A;;[A-Z]+;;;BA\)') { throw "Service DACL has no Administrators entry: $serviceSd" }
    if ($serviceSd -match '\(A;;[A-Z]*(DC|WP|DT|SD|WD|WO)[A-Z]*;;;BA\)') { throw "Administrators can stop, reconfigure, delete or re-ACL the service: $serviceSd" }
    # Self-protection WP2/WP3: an elevated administrator is refused.
    & "$env:SystemRoot\System32\sc.exe" stop trapd-agent | Out-Null
    Assert-AccessDenied 'sc stop' ($LASTEXITCODE -eq 5)
    & "$env:SystemRoot\System32\sc.exe" config trapd-agent start= disabled | Out-Null
    Assert-AccessDenied 'sc config' ($LASTEXITCODE -eq 5)
    & "$env:SystemRoot\System32\sc.exe" sdset trapd-agent 'D:(A;;GA;;;WD)' | Out-Null
    Assert-AccessDenied 'sc sdset' ($LASTEXITCODE -eq 5)
    & "$env:SystemRoot\System32\reg.exe" add 'HKLM\SYSTEM\CurrentControlSet\Services\trapd-agent' /v Start /t REG_DWORD /d 4 /f 2>$null | Out-Null
    Assert-AccessDenied 'reg add Start' ($LASTEXITCODE -ne 0)
    try { 'x' | Set-Content -LiteralPath (Join-Path $config 'agent.env') -ErrorAction Stop; throw 'An administrator could write agent.env.' } catch { if ($_.Exception.Message -like 'An administrator*') { throw } }
    try { 'x' | Set-Content -LiteralPath (Join-Path $env:ProgramFiles 'TRAPD Agent\planted.txt') -ErrorAction Stop; throw 'An administrator could write to the install directory.' } catch { if ($_.Exception.Message -like 'An administrator*') { throw } }
    if ((Get-Service trapd-agent).Status -ne 'Running') { throw 'The service stopped although the administrator was refused.' }
    # Drift: SYSTEM widens the service DACL; the agent must report it and put it back.
    $legacySd = 'D:P(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)'
    Invoke-AsSystem "& '$env:SystemRoot\System32\sc.exe' sdset trapd-agent '$legacySd'; if (`$LASTEXITCODE -ne 0) { throw 'sdset failed' }"
    Wait-Until { @(Read-Events | Where-Object { $_.data.rule_id -eq 'selfprotect.service_acl_changed' }).Count -gt 0 } 'No selfprotect.service_acl_changed finding after the service DACL was widened.' 120
    Wait-Until { -not ((((& "$env:SystemRoot\System32\sc.exe" sdshow trapd-agent) -join '') -match '\(A;;[A-Z]*WP[A-Z]*;;;BA\)')) } 'The agent did not re-apply the service DACL.' 60
    # Allow configuration reload to re-arm the file watcher before triggering it.
    Start-Sleep -Seconds 6
    $marker = Join-Path $watch 'sample.txt'
    'initial content' | Set-Content $marker
    $child = Start-Process "$env:SystemRoot\System32\cmd.exe" -ArgumentList '/c ping -n 18 127.0.0.1 > nul & rem TRAPD_MSI_PROCESS_SMOKE' -PassThru
    # Keep an ordinary TCP flow alive for more than one sensor interval.
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $client = [Net.Sockets.TcpClient]::new()
    $client.Connect('127.0.0.1', $listener.LocalEndpoint.Port)
    $peer = $listener.AcceptTcpClient()
    [Diagnostics.EventLog]::WriteEntry($eventSource, 'TRAPD_MSI_EVENTLOG_SMOKE', [Diagnostics.EventLogEntryType]::Information, 100)
    Wait-Until { @(Read-Events | Where-Object { $_.class -eq 'process' -and $_.data.cmdline -like '*TRAPD_MSI_PROCESS_SMOKE*' }).Count -gt 0 } 'No process telemetry.'
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
    Invoke-AsSystem "New-Item -ItemType Directory -Force '$updateDir' | Out-Null"
    $stagedOffer = Join-Path $updateDir 'staged.offer.json'
    $healthyMarker = Join-Path $updateDir 'healthy'
    if ((Test-Path $stagedOffer) -or (Test-Path $healthyMarker)) { throw 'Unexpected update state before heartbeat acceptance.' }
    $pauseHeartbeat = Join-Path $root 'pause-heartbeat'
    New-Item -ItemType File $pauseHeartbeat | Out-Null
    $failedBefore = @(Read-Requests | Where-Object { $_.path -like '*/heartbeat' -and $_.status -eq 500 }).Count
    Wait-Until { @(Read-Requests | Where-Object { $_.path -like '*/heartbeat' -and $_.status -eq 500 }).Count -gt $failedBefore } 'Heartbeat outage was not exercised.' 30
    $failedBefore = @(Read-Requests | Where-Object { $_.path -like '*/heartbeat' -and $_.status -eq 500 }).Count
    '{}' | Set-Content (Join-Path $root 'staged.offer.json')
    Copy-AsSystem (Join-Path $root 'staged.offer.json') $stagedOffer
    Wait-Until { @(Read-Requests | Where-Object { $_.path -like '*/heartbeat' -and $_.status -eq 500 }).Count -gt $failedBefore } 'No rejected heartbeat with staged update.' 30
    if (Test-Path $healthyMarker) { throw 'A failed heartbeat confirmed update health.' }
    Remove-Item $pauseHeartbeat
    Wait-Until { Test-Path $healthyMarker } 'Successful Windows heartbeat did not confirm the update.' 30
    $expectedVersion = ((& $AgentExe --version) -replace '^trapd-agent v', '').Trim()
    if ((Get-Content -Raw $healthyMarker).Trim() -ne $expectedVersion) { throw 'Heartbeat confirmed the wrong update version.' }
    Invoke-AsSystem "Remove-Item -LiteralPath '$stagedOffer', '$healthyMarker' -Force"

    # Outage across a service restart must replay the durable queue with the
    # same event IDs, then acknowledge it when ingest resumes.
    New-Item -ItemType File (Join-Path $root 'pause-ingest') | Out-Null
    $queuedMarker = Join-Path $watch 'queued.txt'
    'during outage' | Set-Content $queuedMarker
    Wait-Until { @(Read-Events | Where-Object { $_.data.path -eq $queuedMarker }).Count -gt 0 } 'Outage event was not collected.'
    $queuedIds = @(Read-Events | Where-Object { $_.data.path -eq $queuedMarker } | ForEach-Object event_id)
    Invoke-AsSystem 'Restart-Service trapd-agent'
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
    Stop-AgentService
    $installedExe = Join-Path $env:ProgramFiles 'TRAPD Agent\trapd-agent.exe'
    # Built in a scratch directory (administrators cannot write to config\ any
    # more) and copied into place as SYSTEM.
    $fixture = Join-Path $root 'sigfixture'
    New-Item -ItemType Directory -Force $fixture | Out-Null
    @'
import hashlib, pathlib, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
key = Ed25519PrivateKey.generate()
out = pathlib.Path(sys.argv[1])
(out / 'release_signing.pub').write_bytes(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
(out / 'binary.sig').write_bytes(key.sign(hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).digest()))
'@ | python - $fixture $installedExe
    if ($LASTEXITCODE -ne 0) { throw 'Could not provision self-update signature fixture.' }
    Copy-AsSystem (Join-Path $fixture 'release_signing.pub') (Join-Path $config 'release_signing.pub')
    Copy-AsSystem (Join-Path $fixture 'binary.sig') (Join-Path $config 'binary.sig')
    $beforeSignature = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $config 'binary.sig')))
    $beforeReleaseKey = (Get-FileHash (Join-Path $config 'release_signing.pub')).Hash
    Start-AgentService
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
    ('sha256:' + ('0' * 64)) | Set-Content (Join-Path $root 'stale.sha256')
    Copy-AsSystem (Join-Path $root 'stale.sha256') (Join-Path $config 'binary.sha256')
    # An obsolete signature must be removed by the same trusted transaction,
    # without removing the independently provisioned release trust anchor.
    [IO.File]::WriteAllBytes((Join-Path $root 'stale.sig'), [byte[]]::new(64))
    Copy-AsSystem (Join-Path $root 'stale.sig') (Join-Path $config 'binary.sig')
    '0.0.1' | Set-Content (Join-Path $root 'stale.version')
    Copy-AsSystem (Join-Path $root 'stale.version') (Join-Path $config 'binary.version')
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
    # Removal of an ENROLLED agent is token-gated and fails closed. The generic
    # test MSI ships no maintenance key, so the fixture provisions a throw-away
    # Ed25519 keypair (generated here, never checked in) the way the MSI would
    # lay it down (config\maintenance_signing.pub, raw 32 bytes) and signs
    # tokens bound to the agent id the mock backend enrolled ('windows-smoke').
    $maint = Join-Path $root 'maintenance'
    New-Item -ItemType Directory -Force $maint | Out-Null
    @'
import base64, json, pathlib, secrets, sys, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
out, agent_id = pathlib.Path(sys.argv[1]), sys.argv[2]
key = Ed25519PrivateKey.generate()
(out / 'maintenance_signing.pub').write_bytes(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=').decode()
def token(purpose):
    now = int(time.time())
    payload = json.dumps({'v': 1, 'agent_id': agent_id, 'tenant_id': 'msi-test', 'purpose': purpose,
                          'nonce': secrets.token_hex(16), 'iat': now, 'exp': now + 600}, separators=(',', ':')).encode()
    return b64(payload) + '.' + b64(key.sign(b'trapd-maintenance-token-v1\0' + payload))
(out / 'uninstall.token').write_text(token('uninstall'))
(out / 'stop.token').write_text(token('stop'))
'@ | python - $maint 'windows-smoke'
    if ($LASTEXITCODE -ne 0) { throw 'Could not provision the maintenance token fixture.' }
    Copy-AsSystem (Join-Path $maint 'maintenance_signing.pub') (Join-Path $config 'maintenance_signing.pub')
    $installedExePath = Join-Path $env:ProgramFiles 'TRAPD Agent\trapd-agent.exe'
    # Refusals: no token, a validly signed token of the wrong purpose, and a
    # forged UPGRADINGPRODUCTCODE claim. Each
    # must abort the removal before anything is stopped or deleted.
    $refusals = @(
        @{ Name = 'no token'; Args = @() },
        @{ Name = 'wrong-purpose token'; Args = @("MAINTENANCE_TOKEN_FILE=`"$(Join-Path $maint 'stop.token')`"") },
        # UPGRADINGPRODUCTCODE is a public property: claiming an upgrade on the
        # command line, without the SYSTEM-written upgrade marker, must not skip
        # the gate (a bare value, and a well-formed ProductCode).
        @{ Name = 'bare UPGRADINGPRODUCTCODE'; Args = @('UPGRADINGPRODUCTCODE=1') },
        @{ Name = 'forged UPGRADINGPRODUCTCODE GUID'; Args = @('UPGRADINGPRODUCTCODE={0D18AC24-8CE9-4513-A1E5-889FD2A01D94}') }
    )
    foreach ($refusal in $refusals) {
        $refused = Start-Process "$env:SystemRoot\System32\msiexec.exe" -ArgumentList (@('/x', "`"$installedMsi`"", '/qn', '/norestart', '/L*v', "`"$(Join-Path $root ('refused-uninstall-' + ($refusal.Name -replace '\W', '-') + '.log'))`"") + $refusal.Args) -Wait -PassThru
        if ($refused.ExitCode -in @(0, 3010)) { throw "Uninstall with $($refusal.Name) was accepted." }
        if ($null -eq (Get-Service trapd-agent -ErrorAction SilentlyContinue)) { throw "Refused uninstall ($($refusal.Name)) removed the service." }
        if (-not (Test-Path $installedExePath)) { throw "Refused uninstall ($($refusal.Name)) removed the executable." }
        Wait-Until { (Get-Service trapd-agent).Status -eq 'Running' } "Refused uninstall ($($refusal.Name)) left the service stopped."
    }
    Invoke-Msi @('/x', "`"$installedMsi`"", '/qn', '/norestart', "MAINTENANCE_TOKEN_FILE=`"$(Join-Path $maint 'uninstall.token')`"", '/L*v', "`"$(Join-Path $root 'uninstall.log')`"")
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
    try { Stop-AgentService } catch {}
    if ([Diagnostics.EventLog]::SourceExists($eventSource)) {
        [Diagnostics.EventLog]::DeleteEventSource($eventSource)
    }
    Remove-Item -Recurse -Force $watch -ErrorAction SilentlyContinue
}
