# PR 127 Codex review fixes

Goal: fix the four review findings on commit 16b698f without unrelated changes.

Scope: existing prevention runtime, process target extraction, Windows native firewall and uninstall lifecycle. No additional dependencies. Use reqwest's URL parser and the existing COM API.

- [x] IPv6: demonstrate lost management allowlist with a regression test, parse HTTP(S) URLs and extract unbracketed IP hosts, then rerun runtime tests.
- [x] Process identity: demonstrate an explicit PID with a matching lineage start time clamps kill to alert; reuse only that matching head when an explicit generation is absent. Preserve explicit generations, reject mismatches and invalid identities.
- [x] TTL: persist absolute Unix expiry and signed command ID in each block rule description, within the existing paired rollback operation. Enumerate owned rules at startup and periodically, under the mutation lock. Use the current rule metadata so replacement/permanent blocks cannot be removed by stale timers. Audit expiry; update engine dedup state. Test deadline boundaries, malformed metadata, zero TTL, overflow, restart/reopen, replacement and removal retry.
- [x] Uninstall: enumerate and remove only the TRAPD rule group, fail cleanup if removal fails, run cleanup after StopServices and before DeleteServices. Preserve rules on MSI upgrade. Extend native Windows and MSI acceptance tests to verify owned removal and preservation of unrelated rules.
- [ ] Verify: Linux full suite, Clippy, formatting of changed modules, Linux and Windows release builds/cross checks, Windows native and MSI CI. Review diff for unsafe VARIANT handling, ownership checks, partial removals, stale timer races and invalid process generations before pushing to the existing PR branch.
