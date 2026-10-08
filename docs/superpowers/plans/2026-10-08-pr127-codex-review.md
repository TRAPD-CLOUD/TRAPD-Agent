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

Verification on 9c80ac6: 1092 Linux unit tests and 16 integration tests passed; Linux/Windows Clippy, Linux/GNU Windows release builds, Debian and native Linux acceptance passed. Native Windows exposed an invalid test operation: Windows refuses an ancestor rename with an open descendant directory handle. The nested replacement regression now removes that child, requires its tamper event and handle cleanup, then replaces the ancestor and requires detection on the recreated child. All original assertions remain required; fresh native CI verification follows.

Both full CI runs and CodeQL passed on 8ac8cf9, including all native directory replacement assertions and MSI lifecycle acceptance. Independent final review then found that the reused inventory helper only queried ProfileList for sysinfo accounts/live sessions, missing already-registered logged-off domain/Entra profiles.

- [x] Merge registered ProfileList SID keys into the existing shared discovery helper independently of live-user enumeration. Preserve account metadata enrichment, deduplicate SIDs, ignore backup/non-SID keys, and keep bounded registry reads. A native regression reads a random per-user registry fixture with registered domain/Entra profiles absent from the account list and verifies their actual discovered paths and ransomware scope, without modifying HKLM or real profiles.
- [x] Remove earlier descendant roots when a later ancestor is selected, so recursive watch deduplication is independent of enumeration order. The portable regression failed before the fix and checks both input orders.

Both CI runs and CodeQL passed on aa3c259, including native discovery of registered domain/Entra profiles absent from the account/session list.

Follow-up review on aa3c259:

- [x] Append an optional, omitted-when-absent signed `process_start_time` to memory collection commands. Windows requires a positive observed generation checked on the actual memory-read handle; Linux preserves legacy omission and validates explicit generations around opening its retained memory fd. Refused/empty reads audit the requested identity and return no memory artifact. Tests demonstrated the dropped signed field and successful stale/zero-generation dumps before the fix, then verify signed legacy compatibility, tamper rejection, stale/unknown identities and valid observed-child reads. Windows producers must preserve the exact observed u64 FILETIME when signing.
- [x] Remove the startup tamper exemption and its obsolete uptime parameters: integrity checks complete before collectors start. Report integrity-file creation/modification/deletion from the first notification; only known in-flight-update writes are excused. The portable regression failed before the fix; native coverage includes immediate changes to all three integrity files.
- [x] Use one physical watcher with independent logical telemetry/ransomware/backup/tamper scopes. Build a nonoverlapping native handle union, with nonrecursive fixed parents and ancestor-first recursive targets; only successful ancestors subsume descendants. Install needed fixed children before retiring or downgrading a shared generic ancestor. Filter intended paths and split rename pairs before the bounded queue; preserve repeated real operations without temporal suppression. Rearm replaced roots and retry missing/failed paths periodically. Native regressions cover single alarms under overlapping scopes, repeated file creation, removal of generic scope without losing fixed detection, root replacement including files created before notification consumption, missing-root retry and sibling filtering.

Adversarial review of handle migration additionally requires retaining a working recursive ancestor if its replacement child watch fails; retry narrows physical coverage only after recovery. The native failure regression injects a failed child registration while leaving the real ancestor handle running, requires a tamper event during that failure, then verifies narrowed handles and continued detection after retry.

- [x] Reject Windows quarantine sources unless the retained handle reports exactly one hard link. Reuse the native file-information query and recheck before creating the destination, before deletion, and after setting delete-pending; source changes use the existing rollback/cleanup path. Native regressions require existing hardlinks to be refused with both names, contents and security descriptors intact, and test late-link creation or an explicit sharing-violation guard. The elevated late-link regression is included by the existing native quarantine CI filter.

Follow-up review on f34c977:

- [x] Carry an optional, omitted-when-absent signed `process_start_time` through manual kill/freeze/thaw commands. Remove execution-time Windows identity sampling and reuse the generation-checked action handles; explicit Linux generations use existing pidfd actions and omission retains legacy behavior. Reject failed actions with the requested identity and collect no snapshot on refusal. Regression coverage includes signed field preservation, missing Windows identities, zero/stale identities and actual child freeze/thaw/kill behavior, including Linux legacy commands. Document the required exact observed Windows FILETIME for command producers.

Native quarantine acceptance on 00c6e6e established that Windows excludes the pending-deletion name from `nNumberOfLinks`. Require one link before deletion and zero afterward: accepting one surviving link after delete-pending would leave a concurrently created alias reachable. Existing native copy/cancel/ADS tests rejected the incorrect post-delete count and now validate the full successful transition and rollback behavior.
