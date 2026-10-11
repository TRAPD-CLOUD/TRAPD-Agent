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

Prefer device pairing (no token). For managed deployments, `BACKENDURL` and
`ENROLLTOKEN` MSI properties can be used instead of the corresponding `agent.env`
entries. The MSI stores them in a 64-bit `HKLM\SOFTWARE\TRAPD\Agent` key that is
restricted to SYSTEM and Administrators. Environment variables and then
`agent.env` take precedence. Do not pass `ENROLLTOKEN=` to `msiexec` directly: a
command line is visible to every local user and to process telemetry. Use
`install.ps1 -EnrollTokenFile <file>` (or `-EnrollToken`), which stages the
token in the protected registry key instead of the command line. The agent
deletes the registry `EnrollToken` value as soon as enrollment succeeded (or
persisted credentials exist), so the one-time token does not stay on disk.
TLS pinning fails closed unless `TRAPD_TLS_ALLOW_SYSTEM_ROOTS=1` is explicitly
configured. First enrollment needs a reachable backend and a valid token.

An optional `trapd-agent-windows-install.ps1` release selector downloads the MSI
and its checksum, with `-Channel stable` (default) or `-Channel beta`. It invokes
Windows Installer; it does not replace service binaries independently. The
SHA256 file comes from the same release, so it proves integrity only. The script
therefore also requires a valid Authenticode signature (`Get-AuthenticodeSignature`
status `Valid`) and fails closed unless the signer matches `-ExpectedThumbprint`
(or env `TRAPD_SIGNER_THUMBPRINT`) and/or `-ExpectedPublisher` (or
`TRAPD_SIGNER_SUBJECT`, the certificate's simple name). One of them is mandatory;
`-AllowUnsigned` is an explicit, warned opt-out for self-built packages.
Release builds are signed (see "Signing" below); SmartScreen still warns on a
download until the publisher has reputation.

## Collected data and platform coverage

| Data / path | Windows implementation |
|---|---|
| System snapshots | CPU, RAM, uptime and OS via sysinfo |
| Process create/terminate | Real-time **ETW** (Microsoft-Windows-Kernel-Process): every start and stop with parent PID, image path, native creation time; command line, account and SHA256 enriched from the live process. Catches short-lived processes polling misses. Falls back to 3-second polling when ETW is disabled (`etw_enabled=false`) or the session cannot start. |
| Image / DLL load | ETW image-load events; a protected-process image loaded from a user-writable folder raises a DLL side-load finding |
| TCP connections | Real-time **ETW** (Microsoft-Windows-Kernel-Network) connect/accept with owning PID, or the native IP Helper tables when ETW is off |
| DNS | Real-time **ETW** (Microsoft-Windows-DNS-Client) completed queries with the querying process — feeds IOC-domain and DNS-tunnel detection |
| File changes | ReadDirectoryChangesW via notify, with live configuration reload |
| File integrity | Periodic SHA256 baseline, content changes and deletion in the shared filesystem schema |
| Authentication | Security events 4624/4625, target user and remote IP/port when the event supplies them; requires Windows audit policy |
| Native logs | Security, System and Application event XML plus structured fields and persisted record cursors |
| Interactive sessions | Session open/close via native Terminal Services API |
| Inventory | OS/hardware, disks, native adapter addresses/MAC/status, machine software from both registry views, local users, TCP listeners, SBOM and CVE correlation |
| Detection | Shared IOC, behaviour, IOA and Sigma engine, plus Windows LOLBin / persistence / defense-evasion / credential-access rules (`detection/windows_rules.rs`); Windows process events project to product `windows`; signed config reloads Sigma, anomaly switches, suppressions and per-rule modes |
| Coverage transparency | Heartbeat reports the effective sensor state (ETW session health, events lost, audit-policy state, how decoys are watched) and shadow-mode rule hit counts, so "not seen" is never shown as "did not happen" |
| Backend | Shared enrollment, signed config, heartbeat, inventory and authenticated event ingest |
| Delivery diagnostics | Persistent queue with restart recovery, telemetry report and `diagnostics telemetry` |
| Honeytokens | Operator-listed file decoys **and** operator-approved adaptive decoys that fit each user (role, naming style, a cold directory the user owns but has not touched for weeks — never the desktop or a synced folder). Per-host generated bait, timestamp camouflage, not-content-indexed. Reads attributed to a process/account via a read-audit SACL + 4663 and graded (owner-interactive vs. foreign) to keep false alarms down. Deployment/health events and ownership-verified cleanup during MSI removal; legacy registry decoys removed, no longer planted. Adaptive learning is opt-in (`deception_activity_learning_enabled`), local-only, purged on disable/uninstall. |

Windows honeytoken ownership is persisted in `<state>/windows_honeytoken_deployments.json`.
Cleanup removes only registered, unchanged artifacts; file identity and content are
checked before deletion. Modified files and preexisting registry values are preserved,
and registry container keys remain. Registered paths are considered for cleanup even
after configuration removes them. On upgrade, legacy decoys without ownership records
are preserved with a warning rather than adopted or deleted automatically.

The ETW sensor is user-mode: no kernel driver is installed. It therefore does
**not** see, and must not be reported as seeing, LSASS handle access (that needs
the PPL/ELAM ETW-Ti provider) or an attacker with administrator rights who stops
the `TRAPD-Agent` session itself — that stop *is* detected and reported, but not
prevented. There is also no packet/TLS sensor, no Linux rootkit/memory scanner,
no Linux CIS audit, no generic file/journal/syslog log-source readers, no Linux
session forensics, and no Linux prevention/response enforcement in this package.
When ETW is disabled, process polling falls back to its documented short-event
gaps; cross-view gap detection between ETW and polling is not yet wired (polling
is simply off while ETW runs). The current fallback boot ID changes on agent
restart; native process creation time still distinguishes PID reuse within a run.

ETW process-creation command lines are read from the live process, so a process
that exits within microseconds may yield a start event without its command line
(marked in `enrichment`); 4688 Security-event command lines (requiring the audit
policy) remain a complementary source.

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

If MSI removal fails in the `CleanupDecoys` step, the cause is in
`C:\ProgramData\TRAPD\logs\agent.log`. Decoy removal there is best effort; the
step fails only when TRAPD containment firewall rules cannot be removed
(leftover rules would keep the host isolated once the agent is gone). Restore
the Windows Firewall services (`BFE`, `MpsSvc`) or delete the TRAPD rule group
manually, then repeat the removal.

### Developer-only `install` / `uninstall` verbs

`trapd-agent.exe install` / `uninstall` register and delete the service
directly. They bypass the MSI (no recovery actions, no directory ACLs, and
`uninstall` deletes the binary behind Windows Installer's back), so they are
for development builds only and **refuse to run on a machine the MSI manages**
(`HKLM\SOFTWARE\TRAPD\Agent`, `Installed=1`). That marker survives MSI removal
by design (configuration is retained), so a developer machine that once had the
MSI must set `TRAPD_ALLOW_DEV_INSTALL=1` to use the verbs. Never use them on a
production host. The registered service path is quoted by the service API
whenever it contains spaces, so it is not an unquoted-service-path
(CWE-428) risk.

### Logs and the Windows Event Log

`C:\ProgramData\TRAPD\logs\agent.log` rotates at 10 MiB and keeps three
generations (`agent.log.1` to `agent.log.3`). If the file cannot be opened,
logging falls back to stderr (invisible for a service). Service start, stop and
fatal start-up errors are also written to the **Application** event log under
the source `TRAPD Agent` (event ids 1 started, 2 stopped, 3 fatal). The service
registers that source itself at start-up (the MSI is not involved); the key
`HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\TRAPD Agent`
remains after removal, which is harmless. Messages are short summaries on
purpose, because the Application log is readable by standard users; details stay
in `agent.log`.

### Service status

The service reports `START_PENDING` (with checkpoints and a wait hint) while it
initialises and `RUNNING` only after the binary-integrity check has passed, so a
tampered binary never appears as running. Waiting for pairing/enrollment happens
in `RUNNING` and still honours stop. On stop it reports `STOP_PENDING`; if
background tasks (Event Log reads, firewall calls) do not finish within 10 s
they are abandoned so the stop cannot hang.

### Self-update and the MSI version

A signed self-update (when a release key is provisioned) replaces
`trapd-agent.exe` without changing what Windows Installer recorded: *Apps &
features* keeps showing the version of the MSI that was installed, while
`trapd-agent.exe --version`, the heartbeat and the Event Log entry show the
running version. Editing Windows Installer's own uninstall entry is deliberately
not done (it is owned by the MSI and rewritten on repair). Consequences: use the
reported agent version for inventory; a *repair* or reinstall of an older MSI
puts that MSI's binary back (and resets the integrity baseline), and a newer MSI
upgrades normally. The update helper only runs from a staging directory that is
private to SYSTEM and Administrators and launches a copy whose hash it has
re-verified while holding it write-locked.

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

## Self-protection

- Process death: SCM recovery actions restart the service (configured by the MSI).
- Service DACL: SYSTEM full control; Administrators may query, start, stop and
  delete the service but cannot change its DACL or owner.
- Process mitigation policies (best effort, logged on failure): legacy extension
  points disabled, no images from remote shares or low-integrity locations.
- While running, the agent re-hashes its executable every 15 minutes and raises
  `selfprotect.binary_modified` (Critical) when it no longer matches the
  baseline; coverage reports `binary_integrity`. It does not stop itself: the
  next start fails closed.
- Collectors that exit with an error are restarted with exponential backoff
  (5 s up to 5 min) and listed in coverage `failed_collectors`; a wedged
  pipeline consumer, event-log or ETW loop (no progress for 2-3 minutes) is
  listed in coverage `stalled_components`.

## Signing (SignPath, required for releases)

The workflow signs the final MSI through the SignPath GitHub action. Release
builds (`release.yml`, tag `v*`) pass `require_signing: true`, so the job fails
unless `secrets.SIGNPATH_API_TOKEN` and the repository variables
`SIGNPATH_ORGANIZATION_ID`, `SIGNPATH_PROJECT_SLUG` and `SIGNPATH_SIGNING_POLICY_SLUG`
are configured (`SIGNPATH_ARTIFACT_CONFIGURATION_SLUG` is optional). CI and PR
builds (`ci.yml`) leave it unset and ship an unsigned MSI with a notice. The signed
package replaces the unsigned one before the checksum is taken, and the job fails
if the signature is not valid. The calling workflow must pass the secret
(`secrets: inherit`) and grant the job `actions: read` for the SignPath action.
SignPath's artifact configuration must sign `*.msi` inside the uploaded
`unsigned-msi` artifact. Publish the signing certificate's thumbprint or
subject so users can pass it to `install.ps1`.

Not covered yet: the `trapd-agent.exe` inside the MSI and the standalone
`trapd-agent-windows-x86_64.exe` asset are unsigned (signing the executable
changes its hash, which the signed release statement covers, so it has to happen
before that statement is created), and there is no signed self-update on Windows;
updates ship as a new MSI.

Packaging references: [WiX services](https://docs.firegiant.com/wix/schema/wxs/serviceinstall/),
[utility service recovery](https://docs.firegiant.com/wix/schema/util/serviceconfig/),
[Windows Installer ACLs](https://docs.firegiant.com/wix/schema/wxs/permissionex/).
