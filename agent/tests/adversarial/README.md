# Adversarial test kit

Every script refuses to run unless `TRAPD_ADVERSARIAL_OK=1` and restores what it changes.

| Threat | Script | Action | Expected | Verify |
|---|---|---|---|---|
| T10 posture (Linux) | `T10-posture-linux.sh` | `ptrace_scope` 1 -> 0 | `selfprotect.platform_posture_changed`, high, key `yama_ptrace_scope`, before=1 after=0; info after restore | Detections list, or agent log "platform posture changed" |
| T10 posture (Windows) | `T10-posture-windows.ps1` | `VulnerableDriverBlocklistEnable` 1 -> 0, service restarts | same rule, high, key `driver_blocklist` | same |
| T10 test-signing (Windows, MANUAL) | none (needs reboot) | `bcdedit /set testsigning on`, reboot. Revert: `bcdedit /set testsigning off`, reboot | high `platform_posture_changed` key `test_signing` off -> on; measured-boot round may add a medium `measured_boot` finding | Revert and confirm the info/strengthened event. Do not do this on a production host; Secure Boot blocks the command when enabled |
| T10 kernel debugger (Windows, MANUAL) | none | `bcdedit /debug on`, reboot. Revert: `bcdedit /debug off`, reboot | high, key `kernel_debugger` | as above |
| T11 clock jump | `T11-clock-jump.sh` / `.ps1` | wall clock -1 h for 70 s, restored | `selfprotect.time_jump`, medium, direction backward (and forward on restore) | Detections list; `evidence.skew_secs` about -3600 |

Not covered by scripts: clock change while the agent is stopped (stop agent, `date -s`, start agent; the persisted anchor reports it at start, `across_reboot=false` on the same boot).
