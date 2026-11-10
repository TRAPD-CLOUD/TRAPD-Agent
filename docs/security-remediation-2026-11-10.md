# Security remediation — 2026-11-10

Scope: review findings 1 (quarantine symlinks), 2 (restore redirection/overwrite),
3 (release authentication), and 5 (persistent replay protection). Finding 4
(mandatory HTTPS for the backend) is intentionally unchanged at the owner's
request. FIM, collector configuration and dead-code findings are outside this fix.

## Behavior changes

- Linux quarantine resolves each path component without following symlinks,
  retains source/directory descriptors and copies into a fresh private vault
  inode. Multiply linked files and files larger than 1 GiB are refused. The
  original is retained in private staging until the index commits. Uncertain
  index commits preserve referenced payloads; failed rollback reports the
  recovery location instead of overwriting a replacement file.
- Linux restore verifies the stored digest, sets attributes through the owned
  descriptor and publishes with no-replace semantics. An occupied destination,
  symlink parent or modified payload is an error. Existing quarantine records
  remain readable, including payloads with the old immutable flag. Root and
  non-root round trips are supported; non-root access to mode-000 payloads uses
  a pinned inode rather than a pathname permission change.
- Standalone Linux installation and manual updater self-refresh require an
  independently provisioned Ed25519 release key. Signed statements bind all
  executable artifacts, versions, platform, names, sizes and hashes. Existing
  pinned keys cannot be replaced through the environment. Automatic updates use
  the existing signed agent channel; the legacy daily timer is disabled.
  See [installation and migration](../deploy/README-linux-install.md).
- Commands and configurations are rejected when their replay state cannot be
  durably stored. Invalid existing state is not treated as empty. Signed config
  snapshots and timestamps are committed together; the old separate cache is
  supported only with its legacy timestamp. A cache without its replay timestamp
  is rejected. Explicit or existing state directories are never silently changed
  because they become unavailable. Windows cleanup does not depend on loading
  configuration and remains available if config state is corrupt.

## Operator implications

Back up the complete protected state directory together. Corrupt/inconsistent
config state now causes startup to fail visibly instead of adopting defaults;
restore a coherent trusted backup or use an explicit re-enrollment/recovery
procedure. Do not delete replay files merely to silence an error. A failed
command-state write does not execute the command; retry after repairing storage.

The repository update does not repair already installed legacy updaters by
itself. Disable their timers and migrate through a trusted installation path.
Publish the new signed release assets before distributing the new installer.

## Verification

- Full Linux workspace suite: 1,230 tests passed, 12 intentionally ignored.
- Linux workspace Clippy, all targets, warnings denied: passed.
- Linux optimized release build passed locally and in CI on the 0.7.4 baseline.
- Sixteen executable bootstrap tests: passed, including authentic statements
  from the Rust release signer, forged checksums, bad/missing signatures/keys,
  wrong platform/version, downgrade and unsafe trust-directory refusal.
- Embedded verifier consistency, shell syntax, deployment drop-in tests, workflow
  YAML parsing and changed security-module formatting: passed.
- Windows cross-check attempted but blocked before agent compilation by the
  absent `x86_64-w64-mingw32-gcc` required by bundled SQLite. Native Windows/MSI
  behavior was not exercised locally.
- Repository-wide formatting has existing failures in unrelated files, confirmed
  against the unchanged HEAD; no mass formatting was performed.

The tests exercise controlled filesystem failures and adversarial paths, not an
actual power-loss event. No host installation, fleet rollout or release was run.

## Integration onto current main

Rebased onto `b104656` (0.7.4). The existing `prevention/linuxpin.rs` now owns
the secure Linux transactions; protected OS/agent path checks and newer Windows
response behavior are retained. Strict nonce-store loading supersedes the old
in-memory corruption cutoff, so corrupt state rejects verifier construction.

## PR review follow-up

POSIX access ACLs are retained in the quarantine index separately from the
mode-000 vault object and restored through the held destination descriptor before
publication. A destination default ACL cannot add access absent from the original.
The base Linux units include CAP_CHOWN and CAP_FOWNER so restoration can preserve
non-root ownership; a network-isolated container test runs the real transaction
with only those two capabilities. ACL round-trip and inherited-ACL tests cover the
permission boundary. Debian/Ubuntu package fixtures use authentic Ed25519 releases;
native honeytoken fixtures include the atomic config replay state.
