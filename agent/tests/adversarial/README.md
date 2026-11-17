# Adversarial test kit (Phase 09)

Each script refuses to run unless `TRAPD_ADVERSARIAL_OK=1` and cleans up what it creates.

| Threat | Script | Command | Expected event / finding | How to verify |
|---|---|---|---|---|
| T1 copied `credentials.json` / cloned VM image | `t1_credentials_copy.sh` | `TRAPD_ADVERSARIAL_OK=1 TRAPD_BACKEND_URL=https://... ./t1_credentials_copy.sh` on a bound agent | file has no `agent_secret`; a leftover secret is rejected with HTTP 401 | script prints `PASS`; console shows the agent with `protection: tpm\|software` |
| T1b second key bound for the same agent | manual (WP1): copy `credentials.json` incl. secret to a host before the first bind, bind on both | second `identity/bind` answers 409 | finding `agent.identity_bind_conflict` (high) | agent logs `identity: backend reports a DIFFERENT key`, stops; finding in console |
| T1c identity key export (Windows, TPM) | `t1_tpm_key_export.ps1` | `$env:TRAPD_ADVERSARIAL_OK=1; .\t1_tpm_key_export.ps1` elevated on a bound Windows agent | no event; every export route fails: `certutil -csp "Microsoft Platform Crypto Provider" -key` / `-exportPFX`, `CngKey.Export(EccPrivateBlob)`; credentials.json has no secret | script prints `RESULT: PASS`; a `FAIL` line means the key is exportable (software provider keys must also refuse: export policy 0) |
