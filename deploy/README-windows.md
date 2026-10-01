# TRAPD Agent MSI for Windows

The release asset `trapd-agent-windows-x86_64.msi` installs the x64 Rust agent
as an automatic LocalSystem service in `C:\Program Files\TRAPD Agent`.
The MSVC release uses a static CRT, so no separate Visual C++ runtime is needed.
Windows Installer controls service stop/start, repair, major upgrade and removal.
Newer product versions replace the old package in a transaction; downgrades are
rejected. Configuration and device identity survive upgrade and uninstall.

## Install

Double-click the MSI or install from an elevated PowerShell prompt:

```powershell
msiexec.exe /i .\trapd-agent-windows-x86_64.msi /qn /norestart
```

This immediately starts local collection and writes
`C:\ProgramData\TRAPD\logs\events.ndjson`. Without a configured backend,
the agent collects in offline mode. To connect it, provision these files in
`C:\ProgramData\TRAPD\config` before installing or restart the service after
provisioning them:

- `ca.crt`: PEM certificate authority that pins the backend TLS connection.
- `command_signing.pub`: raw 32-byte Ed25519 key for signed remote configuration.
- `agent.env`: backend URL and enrollment token (the MSI preserves an existing file).

```ini
TRAPD_BACKEND_URL=https://backend.example.com
TRAPD_ENROLL_TOKEN=enroll_xxxx
TRAPD_OUTPUT=file
RUST_LOG=info
```

For managed deployments, `BACKENDURL` and `ENROLLTOKEN` MSI properties can be
used instead of the corresponding `agent.env` entries. The MSI stores them in
a protected 64-bit `HKLM\SOFTWARE\TRAPD\Agent` key. Environment variables
and then `agent.env` take precedence. `ENROLLTOKEN` is a hidden MSI property;
pre-provision `agent.env` when avoiding a token in process command lines matters.
TLS pinning fails closed unless `TRAPD_TLS_ALLOW_SYSTEM_ROOTS=1` is explicitly
configured. First enrollment needs a reachable backend and a valid token.

An optional `trapd-agent-windows-install.ps1` release selector downloads the MSI
and its checksum, with `-Channel stable` (default) or `-Channel beta`. It invokes
Windows Installer; it does not replace service binaries independently. SHA256
checks integrity. Offline-key manifest signing and Authenticode signing remain
unconfigured, so the checksum alone provides no independent release authenticity.

## Collected data and platform coverage

| Data / path | Windows implementation |
|---|---|
| System snapshots | CPU, RAM, uptime and OS via sysinfo |
| Process create/terminate | 3-second process polling, parent PID, executable, bounded command line, SHA256 and native creation FILETIME; detects observed PID reuse |
| TCP connections and close | Native IPv4/IPv6 IP Helper tables, addresses, ports, owning PID and observed duration |
| File changes | ReadDirectoryChangesW via notify, with live configuration reload |
| File integrity | Periodic SHA256 baseline, content changes and deletion in the shared filesystem schema |
| Authentication | Security events 4624/4625, target user and remote IP/port when the event supplies them; requires Windows audit policy |
| Native logs | Security, System and Application event XML plus structured fields and persisted record cursors |
| Interactive sessions | Session open/close via native Terminal Services API |
| Inventory | OS/hardware, disks, native adapter addresses/MAC/status, machine software from both registry views, local users, TCP listeners, SBOM and CVE correlation |
| Detection | Shared IOC, behaviour, IOA and Sigma engine; Windows process events project to product `windows`; signed config reloads Sigma and anomaly switches |
| Backend | Shared enrollment, signed config, heartbeat, inventory and authenticated event ingest |
| Delivery diagnostics | Persistent queue with restart recovery, telemetry report and `diagnostics telemetry` |
| Honeytokens | Existing file and registry decoys, deployment/health events and cleanup during MSI removal |

Polling can miss short-lived processes and connections. File notifications do
not identify the accessing process or report every file read. Windows has no
eBPF syscall, packet/DNS/TLS sensor, Linux rootkit/memory scanner, Linux CIS audit,
generic Linux file/journal/syslog log-source readers, Linux session forensics,
or Linux prevention/response enforcement in this package. Those capabilities
must not be reported as implemented. The current fallback boot ID changes on
agent restart; native process creation time still distinguishes PID reuse within
a run. No custom kernel driver is installed.

Default file roots are `%SystemRoot%\System32\drivers\etc` and
`%PUBLIC%\Documents`. Explicit Windows `fs_watch_paths` and `fim_paths` in signed
configuration replace those roots. FIM scans cap files (10,000), individual
files (16 MiB), total reading (128 MiB) and scan time (10 s). An incomplete scan
keeps the prior baseline and logs its failure. Event logs begin at their current
tail on first start and resume persisted record IDs on subsequent starts.

## Service, state and removal

```powershell
Get-Service trapd-agent
Restart-Service trapd-agent
& 'C:\Program Files\TRAPD Agent\trapd-agent.exe' diagnostics telemetry
msiexec.exe /x .\trapd-agent-windows-x86_64.msi /qn /norestart
```

The data tree is restricted to SYSTEM and Administrators. State, configuration,
logs and enrollment registry settings are retained after uninstall for a later
reinstall. MSI removal stops/removes the service, removes the executable and
revokes planted decoys. Use MSI removal for an MSI-managed installation.

## Build and verification

On Windows, install WiX 4.0.6 and its utility extension, then build:

```powershell
dotnet tool install --global wix --version 4.0.6
wix extension add -g WixToolset.Util.wixext/4.0.6
cargo build --release --target x86_64-pc-windows-msvc --manifest-path agent/Cargo.toml
.\deploy\windows\build-msi.ps1 -AgentExe target\x86_64-pc-windows-msvc\release\trapd-agent.exe
```

`.github/workflows/windows-package.yml` builds and tests on a native Windows
runner. `deploy/windows/test-msi.ps1` installs the MSI and checks service startup,
offline collection, ACLs, a pinned TLS test backend, signed configuration, process/Sigma/TCP/file/FIM/
event-log telemetry, heartbeat, inventory, durable replay after an outage and
restart, MSI repair, failed-upgrade rollback, major upgrade, downgrade rejection and uninstall. The release job waits
for that acceptance job before publishing the MSI. Test logs are uploaded as CI
artifacts. Running this test requires an isolated Windows machine with admin
rights; it installs a service and generates synthetic security telemetry.

Packaging references: [WiX services](https://docs.firegiant.com/wix/schema/wxs/serviceinstall/),
[utility service recovery](https://docs.firegiant.com/wix/schema/util/serviceconfig/),
[Windows Installer ACLs](https://docs.firegiant.com/wix/schema/wxs/permissionex/).
