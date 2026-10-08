# PR 127 Codex review fixes

Goal: fix the four review findings on commit 16b698f without unrelated changes.

Scope: existing prevention runtime, process target extraction, Windows native firewall and uninstall lifecycle. No additional dependencies. Use reqwest's URL parser and the existing COM API.

- [x] IPv6: demonstrate lost management allowlist with a regression test, parse HTTP(S) URLs and extract unbracketed IP hosts, then rerun runtime tests.
- [x] Process identity: demonstrate an explicit PID with a matching lineage start time clamps kill to alert; reuse only that matching head when an explicit generation is absent. Preserve explicit generations, reject mismatches and invalid identities.
- [x] TTL: persist absolute Unix expiry and signed command ID in each block rule description, within the existing paired rollback operation. Enumerate owned rules at startup and periodically, under the mutation lock. Use the current rule metadata so replacement/permanent blocks cannot be removed by stale timers. Audit expiry; update engine dedup state. Test deadline boundaries, malformed metadata, zero TTL, overflow, restart/reopen, replacement and removal retry.
- [x] Uninstall: enumerate and remove only the TRAPD rule group, fail cleanup if removal fails, run cleanup after StopServices and before DeleteServices. Preserve rules on MSI upgrade. Extend native Windows and MSI acceptance tests to verify owned removal and preservation of unrelated rules.
- [x] Verify: Linux full suite, Clippy, formatting of changed modules, Linux and Windows release builds/cross checks, Windows native and MSI CI. Review diff for unsafe VARIANT handling, ownership checks, partial removals, stale timer races and invalid process generations before pushing to the existing PR branch.

Follow-up review on 344bcbe:

- [x] Relaunch existing Windows staging before the freshness skip and backend poll. Preserve the signed offer, artifact and replay watermark; keep pending-recovery freshness handling. Verify failed launch, early helper exit, empty staging and recovery routing using real staging files and a process-launch boundary double.
- [x] Keep only backend management IPs in EngineConfig; read current signed-config allowances at every isolation action. Reuse one allowlist builder for commands, general automatic response and honeytoken response. Verify additions/removals, management IP preservation, command additions and invalid config IPs through actual firewall command arguments.

Verification of the first fixes: 1074 Linux unit tests and 16 integration tests passed; Linux/Windows Clippy, changed-module formatting and both release builds passed. All five jobs in both CI runs 37781716898 and 37781706934 passed, including native Windows firewall and MSI acceptance. CodeQL run 37781707639 passed for Rust, Python and Actions. Follow-up changes require fresh verification.

Follow-up review on 20dfcb0:

- [x] Confirm update health on successful Windows heartbeats, using the existing shared confirmation hook. Native MSI acceptance stages a synthetic offer while the updater has no release key, checks that rejected heartbeats do not confirm health, then checks that an accepted heartbeat writes exactly the current version. Pause heartbeat responses using the existing mock-backend outage-marker pattern; use the supported five-second cadence in the test fixture.

All CI jobs and CodeQL passed on e5b3909, including the new native heartbeat regression.

Follow-up review on e5b3909:

- [x] Persist a terminal outcome and the exact offer digest in the existing replay state before removing recovery or staging. Both updater polling and helper startup resume fixed-path cleanup without reinstalling or rolling back a completed transaction. Report deletion failures, remove the offer last, preserve the watermark and failed-release block, and reject completion records for a different offer. Test successful/rolled-back cleanup failures, a crash before journal removal, old state compatibility, and resumed backend polling.
- [x] Remove the startup exception based on a self-reported version. Enforce the stored hash on Windows and Linux; verify a provisioned signature before any baseline write. MSI removes the obsolete baseline inside its existing rollback-enabled transaction after stopping the service. Signed updates retain their authenticated baseline transaction. Test a different-version replacement rejection and first-run baseline behavior; extend MSI acceptance to check baseline rollback and installer-driven reset.

Both CI runs and CodeQL passed on a932844, including native MSI baseline reset/rollback acceptance.

Follow-up review on a932844:

- [x] Carry an optional parent generation in process-create telemetry and preserve it in the policy exec view. Windows polling and ETW bind only a parent generation strictly older than the observed child, so a reused PPID observed after child creation remains unknown. Check parent creation time and image on the same owned Windows handle before a policy match. Preserve Linux parent-name behavior and old event decoding. Test generation boundaries, event serialization/conversion, unknown/stale native parent lookups, and actual parent/child block enforcement without false child termination.
- [x] Schedule pending Windows recovery checks when the five-minute journal freshness guard expires, instead of the next hourly backend poll. Keep five minutes between subsequent recovery attempts, also check staging while an asynchronous helper has not yet created its journal, preserve normal polling without pending work and on Linux, and use the same grace constant for launch and scheduling. Test real journal timestamps and both scheduling paths without waiting in real time.

Both CI runs and CodeQL passed on ea9df46, including native generation-bound parent/child policy enforcement.

Follow-up review on ea9df46:

- [x] Retain the backend host instead of startup-resolved IPs. Resolve it asynchronously with a five-second timeout at every command, detection and honeytoken isolation boundary, then read current signed-config allowances without holding a lock across DNS. Do not mutate firewall rules on failed/empty resolution or if prevention was disabled while resolving. Test real localhost/literal resolution, rotated IPv4/IPv6 responses across all three paths, DNS failure/empty answers, and disabled prevention via actual firewall command recording.
- [x] Own fixed detection and tamper watcher handles independently of generic live watches. Watch tamper parents nonrecursively, filter intended root/direct-child events before enqueue, and rearm protected/nested target paths on replacement. Detect root removal/recreation itself as tamper. Native regressions cover rename/recreate, deletion/recreate, nested targets, generic unwatch ownership and sibling queue filtering; portable planner tests verify intended scope.
- [x] Reuse inventory's registry profile discovery for ransomware roots, including relocated local/domain/Entra profiles. Retain the default Users/Public tree, exclude service identities and invalid/drive/network roots, deduplicate overlapping paths, bound additional watches and warn when truncated. Automatic scope remains local endpoint copies; document remote redirected-folder coverage separately. Test registered-profile selection, extension detection in relocated roots and Public, exclusions, duplicate roots and limits.
