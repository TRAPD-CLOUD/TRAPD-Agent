# SDD ledger — plan: /srv/dev/projects/TRAPD/docs/superpowers/plans/2026-10-07-agent-detection-quality.md
Baseline: f07bb1f6ff98f8f7493370027a3c7eeda38fead7. Agent 951 passed / 11 ignored before changes.
Execution: approved by user, local feature branch feat/agent-detection-quality; platform dirty changes preserved.
Pre-flight: Tasks 1→2/3/7/8 consume optional wire fields and pure assessment; Tasks 2/3→4 share coverage; Tasks 5/6 share injected time and local learning admission.
Ruling: use a clean feature branch in the existing Agent checkout as the approved plan requests; avoid a second checkout with divergent multi-repository paths. No publish/merge.
Ruling: replay record's boolean is named signal: false means alert, not non-alert. Fix misleading spec wording and test BOTH benign demotion and attack retention. Cost if wrong: incorrect evaluation counts; pinned by shared-vector tests.


Implementation and verification are documented in detection-quality-validation.md.
Regression evidence: open flags O_PATH (expected stat, previously open) and mmap
flags (expected stat, previously mmap) each reproduced RED before their fixes.
A real kernel run reproduced missing cat access before BTF resolution.
Independent review found and corrected file-execute/malformed audit masks,
FILETIME decoding, activity/baseline accounting, sweeper directory trust, detached
Linux tasks, failed opens/execs, alias exec, and failed/anonymous mapping evidence.
Native Linux acceptance is available as reviewable source with a failed-exec capacity probe.
Native Windows checks are implemented and CI-wired but not executed on this host.
No production deployment, migration, push, merge, tag or release was performed.

Final independent review: no open substantive findings in reviewed code; native
Windows CI remains a release gate. Both final native Linux modes passed after
MAP_ANONYMOUS exclusion, including failed-exec capacity and successful mmap.
