# TRAPD Agent MSI for Windows

The release asset `trapd-agent-windows-x86_64.msi` installs the x64 Rust agent
as an automatic LocalSystem service in `C:\Program Files\TRAPD Agent`.
The MSVC release uses a static CRT, so no separate Visual C++ runtime is needed.
Windows Installer controls service stop/start, repair, major upgrade and removal.
Newer product versions replace the old package in a transaction; downgrades are
rejected. Configuration and device identity survive upgrade and uninstall.

## Install

### Home users: double-click, then pair

The release MSI of the hosted TRAPD service is the installer: no separate
bootstrapper `.exe` is needed. It carries the hosted backend URL and its public
trust anchors (`ca.crt`, `command_signing.pub`), so nothing has to be configured.

1. Double-click `trapd-agent-windows-x86_64.msi` and accept the UAC prompt.
2. Open **Start menu → TRAPD → Pair this computer with TRAPD** (accept UAC again).
   It shows the pairing code and opens the pairing page in your browser.
3. Sign in to TRAPD, check that the hostname is this computer, and confirm.
   The agent then enrolls by itself.

The code is only visible to administrators on purpose: whoever sees it can
approve this computer into their own workspace. The helper
(`C:\Program Files\TRAPD Agent\pair.ps1`) elevates itself for that reason. If your
standard account elevates through a different administrator account, the browser
may open for that account; type the displayed code at the pairing page instead.
Until you confirm, the agent waits (and still stops, upgrades and uninstalls
normally); local collection starts after pairing.

A generic MSI (built without trust anchors, e.g. in forks or for self-hosted
setups) has no default backend: provision `ca.crt` and `command_signing.pub` and
pass `BACKENDURL` as described below. Anchors already present in
`C:\ProgramData\TRAPD\config` are never overwritten or removed by the MSI, so a
self-hosted installation can use either flavour. The flip side: a rotated
hosted CA is not replaced by an MSI upgrade.

### Managed or silent install

Install from an elevated PowerShell prompt:

```powershell
msiexec.exe /i .\trapd-agent-windows-x86_64.msi /qn /norestart
```

On a generic MSI this immediately starts local collection and writes
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
checks integrity. The MSI is Authenticode-signed only when SignPath is configured
(see "Signing" below); the unsigned executable inside it and the offline-key
manifest signing are separate. Without a signature, the checksum alone provides
no independent release authenticity, and SmartScreen warns on download.

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
| Honeytokens | File decoys with per-host generated bait, deployment/health events and ownership-verified cleanup during MSI removal (legacy registry decoys are removed, no longer planted) |

Windows honeytoken ownership is persisted in `<state>/windows_honeytoken_deployments.json`.
Cleanup removes only registered, unchanged artifacts; file identity and content are
checked before deletion. Modified files and preexisting registry values are preserved,
and registry container keys remain. Registered paths are considered for cleanup even
after configuration removes them. On upgrade, legacy decoys without ownership records
are preserved with a warning rather than adopted or deleted automatically.

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

To bake the hosted anchors locally, put `ca.crt` (PEM), `command_signing.pub`
(raw 32 bytes) and `backend_url` (plain https URL) into a directory and pass
`-TrustDir <dir>` to `build-msi.ps1`; it rejects anything else (private keys,
stray text, non-https or oddly quoted URLs). `verify-baked-msi.ps1` checks a
built package without installing it. The Windows agent does not use a release
key (the signed self-updater is Linux-only), so none is packaged.

`.github/workflows/windows-package.yml` builds and tests on a native Windows
runner. The acceptance test runs on the generic MSI (it asserts that an install
without a backend never contacts one); the hosted MSI differs only by the two
trust files and the default `BACKENDURL`. It is built when the repository
variables `TRAPD_HOSTED_BACKEND_URL`, `TRAPD_HOSTED_CA_PEM` and
`TRAPD_HOSTED_COMMAND_PUBKEY` (base64 of the raw key) are all set; all values are
public. `deploy/windows/test-msi.ps1` installs the MSI and checks service startup,
offline collection, ACLs, a pinned TLS test backend, signed configuration, process/Sigma/TCP/file/FIM/
event-log telemetry, heartbeat, inventory, durable replay after an outage and
restart, MSI repair, failed-upgrade rollback, major upgrade, downgrade rejection and uninstall. The release job waits
for that acceptance job before publishing the MSI. Test logs are uploaded as CI
artifacts. Running this test requires an isolated Windows machine with admin
rights; it installs a service and generates synthetic security telemetry.

## Signing (SignPath, optional)

The workflow signs the final MSI through the SignPath GitHub action when
`secrets.SIGNPATH_API_TOKEN` and the repository variables
`SIGNPATH_ORGANIZATION_ID`, `SIGNPATH_PROJECT_SLUG` and `SIGNPATH_SIGNING_POLICY_SLUG`
are set (`SIGNPATH_ARTIFACT_CONFIGURATION_SLUG` is optional). Otherwise it logs a
notice and ships the unsigned MSI. The signed package replaces the unsigned one
before the checksum is taken, and the job fails if the signature is not valid.
The calling workflow must pass the secret (`secrets: inherit`) and grant the job
`actions: read` for the SignPath action. SignPath's artifact configuration must
sign `*.msi` inside the uploaded `unsigned-msi` artifact.

Not covered yet: the `trapd-agent.exe` inside the MSI and the standalone
`trapd-agent-windows-x86_64.exe` asset are unsigned (signing the executable
changes its hash, which the signed release statement covers, so it has to happen
before that statement is created), and there is no signed self-update on Windows;
updates ship as a new MSI.

Packaging references: [WiX services](https://docs.firegiant.com/wix/schema/wxs/serviceinstall/),
[utility service recovery](https://docs.firegiant.com/wix/schema/util/serviceconfig/),
[Windows Installer ACLs](https://docs.firegiant.com/wix/schema/wxs/permissionex/).
