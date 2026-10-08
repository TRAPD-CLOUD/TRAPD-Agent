# Windows review fixes implementation plan

**Goal:** Resolve all review findings and replace netsh containment with the native Windows Firewall API.

**Architecture:** Keep shared policy decisions and platform-specific enforcement. Bind process actions and deduplication to observed creation identities. Use typed COM bindings for firewall policy/rules, preserving operator defaults and blocking the complement of the management allowlist.

**Constraints:** Initial snapshot is commit `ca11b7e` in PR #127. All fixes form one second commit, after validation. No changes to the sibling TRAPD repository, no merge or deployment.

## Tasks

- [x] Process safety (`process.rs`, `engine.rs`, `winproc.rs`, generation portions of `response.rs`, schema/producers): preserve observed identity through Honeytoken, network and memory response; reject unknown/stale identity; track successful suspends by generation; fix platform PID tests. Add regression tests for stale/unknown identities, repeated suspend/thaw, and Windows system PIDs.
- [x] Quarantine/recovery (`quarantine.rs`, `winacl.rs`, path portions of `response.rs`, updater): transfer owner to SYSTEM with reversible metadata; validate local resolved paths and refuse protected targets, UNC, traversal and device namespaces; require service stopped before rollback and preserve recovery on failure. Add adversarial path, ACL owner roundtrip and stop/restore failure tests.
- [x] Collectors (`fs_heuristics.rs`, `logs/reader.rs`, `logs/framing.rs`, `windows/memscan.rs`): one last timestamp per distinct file, restore W3C header at checkpoint generation, deduplicate by creation time, wait for disabled-to-enabled config changes. Test duplicate churn, resume/custom fields and rotation, PID reuse and dynamic enablement.
- [x] Native firewall (`firewall.rs`, `winfirewall.rs`, `network.rs`, Cargo dependencies, Windows CI): use INetFwPolicy2/INetFwRule, inspect every active profile and effective policy, preserve rule grouping, typed addresses, idempotent create/delete, and propagate query failures. Replace native CLI acceptance with native API tests using a single Cargo filter. Test profile combinations, rule roundtrip and TEST-NET block/unblock.
- [x] Integration: formatting, full Linux unit/integration suite and Clippy/build; Windows compilation/Clippy plus native Windows CI and MSI acceptance where available; review all diffs against each finding and fix substantive new issues; update PR description, create/push second fix commit and wait for CI results.

## Review focus

- Unknown identities must never fall back to a PID-only destructive action.
- Quarantine rename/copy failures must not leave payloads with permissive ownership.
- Failed stop or restore must retain recovery files and state.
- Firewall queries, disabled active profiles or policy that ignores local rules must not report containment success.
- Resumed log headers must belong to the checkpoint's actual file generation.

## Verified evidence before the final fix commit

- Initial PR snapshot: `ca11b7e`, PR #127.
- Linux: 1065 unit tests and 16 integration tests passed; Clippy all targets passed.
- Windows GNU: cross compilation and Clippy all targets passed.
- Native Windows/MSVC validation snapshot `3e47f4e`: 881 unit tests, native firewall idempotence/rollback, pinned quarantine and ownership, directory trust, audit ACL/4663 and ETW acceptance passed; generic and hosted MSI builds and lifecycle/telemetry acceptance passed.
- Linux CI: release build, telemetry acceptance, Debian install/upgrade/purge and native honeytoken inode/fallback acceptance passed.
- eBPF release build passed, including the appended original-event timestamp.
- Final quarantine hardening: share the fresh protected object path with signed manual actions, preserve all NTFS data streams, and enforce an aggregate 1 GiB copy budget before hashing. Positive retained-handle regressions prove the old object remains distinct from the protected copy; native Windows acceptance passed, including ACL-handle isolation, delete-pending access denial and restore.

Final complete validation run: https://github.com/TRAPD-CLOUD/TRAPD-Agent/actions/runs/37767425966 (all five jobs successful). Formatting passed for the changed security modules and `git diff --check` passed; unrelated pre-existing whole-repository rustfmt differences were not rewritten. The PR receives the single follow-up fix commit after this validation.
