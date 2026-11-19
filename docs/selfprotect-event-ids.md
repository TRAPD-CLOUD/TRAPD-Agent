# Self-protection event IDs (SIEM contract)

Every `selfprotect.*` finding the agent emits is also written locally. IDs and
journald `MESSAGE_ID`s are fixed and never renumbered. Implementation and
rationale: `agent/src/selfprotect/local_log.rs`.

- Windows: classic log `TRAPD-Agent-Security` (source of the same name; the
  service registers it on first write, no MSI change; message file
  `EventCreate.exe`). A slash in a classic log name is not possible, so the
  dash form is used instead of `TRAPD-Agent/Security`. Severity maps to
  Error (high/critical), Warning (medium/low), Information.
- Linux: journald, `SYSLOG_IDENTIFIER=trapd-agent-security`,
  `MESSAGE_ID=74726170640000000000000000<id as 6 hex digits>`,
  `TRAPD_RULE_ID`, `TRAPD_EVENT_ID`. Query: `journalctl -t trapd-agent-security`.
- Entries carry rule id, severity and event id only (no paths or command lines).
- Optional toast (Windows): signed config `tamper_user_notification`, default
  off, only for the "tamper" rows.

| Event ID | Rule | Toast |
|---|---|---|
| 101 | `selfprotect.peer_lost` | yes |
| 102 | `selfprotect.peer_binary_tampered` | yes |
| 103 | `selfprotect.module_injected` | yes |
| 104 | `selfprotect.code_patched` | yes |
| 105 | `selfprotect.remote_thread` | yes |
| 106 | `selfprotect.debugger_attached` | yes |
| 107 | `selfprotect.handle_access` | yes |
| 108 | `selfprotect.network_silenced` | yes |
| 109 | `selfprotect.tls_pin_mismatch` | yes |
| 110 | `selfprotect.backend_redirected` | yes |
| 111 | `selfprotect.backend_unreachable_selective` | yes |
| 112 | `selfprotect.platform_posture_changed` | no |
| 113 | `selfprotect.time_jump` | no |
| 120 | `selfprotect.etw_session_stopped` | no |
| 121 | `selfprotect.unclean_shutdown` | no |
| 122 | `selfprotect.binary_tampered` | yes |
| 123 | `selfprotect.binary_modified` | yes |
| 199 | any other `selfprotect.*` rule | no |
