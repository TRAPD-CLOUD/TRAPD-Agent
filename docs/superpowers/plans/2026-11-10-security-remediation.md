# Agent security remediation plan

**Goal:** Fix audit security findings 1, 2, 3 and 5. HTTPS enforcement (finding 4) is explicitly excluded by the owner.

**Architecture:** Keep the existing command/config verification and signed-update trust model. Harden filesystem operations at the file-descriptor boundary, require independent release authentication, and persist replay state before accepting security-sensitive operations.

**Scope:** Linux quarantine/restore; shell installer/updater and their release artifacts; persistent command nonces and signed-config high-water marks. Preserve Windows behavior and validate shared Rust code for Windows. No unrelated FIM, telemetry, or dead-code changes.

## Tasks

- [x] Quarantine and restore: reproduce symlink traversal and destination overwrite with isolated temporary files; add source/parent identity protection, private quarantine payloads, no-clobber destination publication, and failure recovery. Test symlinks, swapped parents, hardlinks, duplicate payloads, occupied destinations and successful round trips.
- [x] Release authentication: inspect existing release manifests/signing workflow, demonstrate acceptance of tampered artifacts with matching checksums, then require independently provisioned signing trust before executing/installing downloads. Cover installer, updater self-refresh and binary/eBPF artifacts. Test missing/wrong keys, missing/bad signatures, tampering, valid artifacts and migration behavior without touching host services.
- [x] Replay durability: reproduce persistence and corrupted-state failures, then reject command/config acceptance until state is durable. Distinguish absent initial state from invalid existing state. Test restarts, replay, corrupt state, write failure, and legitimate updates.
- [x] Integration: inspect final diff for trust-boundary bypasses and compatibility regressions; run formatting, Linux clippy/build/full tests, shell tests and Windows cross-check where tooling permits. Verify no HTTPS-policy change.

## Review focus

- An attacker may replace a path between validation and mutation; canonicalization alone is insufficient.
- Hardlinks must not allow permission changes to affect another pathname outside quarantine.
- Restore failure must retain recoverable payload/index state and must not overwrite unrelated files.
- An attacker controlling both a release artifact and its checksum must still fail authentication.
- Persistence failures and restarts must not silently reset previously established replay protection.

## Execution

Three independent file ownership groups implement the tasks in the existing checkout; the coordinator reviews and verifies the combined result. Existing untracked user files are preserved. Tests must first demonstrate each regression, then pass with the fix. No deployment or release is part of this task.

Verification results and platform limitations: see `docs/security-remediation-2026-11-10.md`.
