# Benign telemetry corpus

Replayed in CI (`detection::replay::tests::benign_corpus_stays_within_budget`)
and locally with

    trapd-agent replay <file.ndjson> --budget budgets.json

Every alert-mode finding on this data is a false positive. A rule change that
pushes any rule above its budget (alerts per host and day, `budgets.json`)
fails the build; fix the rule or, with a written justification, raise that
rule's budget.

| File | Origin |
|---|---|
| `linux-dev-workstation.ndjson` | **Recorded**: the agent offline (`TRAPD_OUTPUT=file`, `/proc` polling, no eBPF) on a Linux developer container during git, tar, curl-to-file, ssh-keygen, apt, `tsc` and `cargo check` work. Paths of the recording session were neutralised. |
| `windows-managed-fleet-synthetic.ndjson` | **Synthetic** (`generate_windows_corpus.py`, deterministic): one working day on an office client, an admin workstation and a managed server — Microsoft 365, Defender, Windows Update, SCCM/Intune scripts with `-ExecutionPolicy Bypass`, admin tooling, backup, IIS, SQL Server, periodic Microsoft endpoints. |

Recorded data beats the synthetic model: add recordings from real hosts
whenever available (remove usernames/hostnames you cannot publish).
