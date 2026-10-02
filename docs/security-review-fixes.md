# Security review remediation — 2026-10-01

Goal: resolve all actionable security and data-loss findings from the code review while preserving intended features, endpoint schemas and operator-configured rule semantics.

## Requirements and work ownership

- [x] Prevention: preserve rule IDs/actions; retain and reconcile kernel blocker for runtime lifetime; respect live prevention_enabled; avoid redundant unbounded executable hashing. Owner: dead_duplicates. Root integrates main startup.
- [x] Containment/output: IPv4+IPv6 parity in iptables fallback; CAP_KILL in both service definitions; private log files/directories and safe rotation. Owner: security_control.
- [x] Honeytokens: authenticated process exemptions; bounded no-follow regular-file reads; exclusive publication; persisted Windows ownership for safe cleanup, preserve existing files. Owner: pipeline_sensors.
- [x] Logs: restart checkpoints retain incomplete physical and logical records; rotation switches only at true EOF. Owner: root.
- [x] SIEM: bounded independent forwarding worker, retain configured sinks/formats while preventing delivery failures from stalling detection. Owner: root.
- [x] Final audit: inspect integrated changes; run Rust tests, clippy, formatting, cross-platform compile where available and meaningful targeted regressions. Record limitations instead of claiming unverified runtime behavior.

## Design constraints

Existing wire schemas and supported commands stay compatible. Alert-only rules do not enforce. Block rules retain intended enforcement. Dynamic config flags take effect without restart. Honeytoken cleanup requires evidence of ownership and cannot delete user files. All resource limits and forwarding losses remain explicit. Tests must not modify the host firewall or signal unrelated processes. No dependency cleanup or unrelated refactoring is included.

## Verification ledger

- `cargo test --manifest-path agent/Cargo.toml`: 778 unit tests and 15 integration tests passed; 10 existing ignored tests were not run.
- Linux and Windows GNU `cargo clippy --all-targets -- -D warnings`: passed after final integration.
- Windows GNU unit-test executable cross-compilation includes native ownership and registry parsing regressions. These regressions have not been executed on native Windows.
- Modified Rust files: individually formatted and checked with `rustfmt --edition 2021 --config skip_children=true`. Repository-wide formatting includes preexisting differences in untouched files; those were left outside this change.
- `bash -n deploy/install.sh`, `git diff --check`, and service/log permission checks passed.
- Red/green regressions reproduced spoofed scanner exemptions, replacement deletion, unsafe token reads/publication, stale executable hashes, lost log checkpoints and rotation records, ignored rule actions, missing IPv6 enforcement, and blocking SIEM delivery before their fixes.

## Changes and operational limits

Prevention preserves exact rule IDs and actions, reconciles block-only kernel rules, and follows live configuration. Both firewall families are handled. Executable hashing streams bounded opened files; cache identity includes inode and change metadata. Optional SIEM forwarding has a bounded queue and reports shedding without blocking the primary pipeline.

Log readers retain incomplete records across restart and drain rotation to actual EOF. Local logs are private regular files opened relative to a pinned directory; symlinks and hard links are refused. Service definitions include the capability required for configured process response.

Honeytoken exemptions require an authenticated trusted executable, rather than a spoofable process name. Linux publication refuses replacement and cleanup verifies content inside private staging. Appended breadcrumbs use one pinned handle for inspection and mutation. Noncooperating writes to the same inode can still race the last metadata check before truncation; detected changes are preserved.

Windows cleanup records file identity/content and registry ownership in `windows_honeytoken_deployments.json`. Legacy unregistered decoys and changed artifacts are conservatively preserved; registry container keys remain. Scanner scripts are not exempted solely because their process name resembles a trusted scanner. Existing protocol schemas and configured sinks remain compatible.

Live eBPF attachment, host firewall enforcement, native Windows/MSI runtime and crash/power-loss scenarios were not exercised. Firewall tests use a fake runner. An isolated Wine attempt could not initialize its runtime, so it provides no Windows execution evidence. A passing review and regression suite are not proof that the codebase contains no other vulnerabilities.
