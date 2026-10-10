# ATT&CK coverage of the detection rule catalog

Generated from `crates/trapd-detection/src/catalog.rs` by
`TRAPD_UPDATE_CATALOG=1 cargo test -p trapd-detection catalog`. A technique is
listed when a rule exists for it. That says nothing about detection quality:
the per-technique true-positive and false-positive rates still have to be
measured (adversary emulation and a week of idle use per host profile).

113 rules, 73 techniques.

| Tactic | Techniques | Rules | alert | signal | shadow |
|---|---|---|---|---|---|
| TA0001 Initial Access | 2 | 2 | 2 | 0 | 0 |
| TA0002 Execution | 9 | 14 | 7 | 3 | 4 |
| TA0003 Persistence | 16 | 26 | 13 | 5 | 8 |
| TA0004 Privilege Escalation | 5 | 6 | 6 | 0 | 0 |
| TA0005 Defense Evasion | 19 | 29 | 16 | 4 | 9 |
| TA0006 Credential Access | 11 | 14 | 11 | 2 | 1 |
| TA0007 Discovery | 3 | 3 | 1 | 2 | 0 |
| TA0008 Lateral Movement | 1 | 1 | 1 | 0 | 0 |
| TA0009 Collection | 1 | 1 | 0 | 1 | 0 |
| TA0010 Exfiltration | 2 | 2 | 2 | 0 | 0 |
| TA0011 Command and Control | 6 | 8 | 6 | 0 | 2 |
| TA0040 Impact | 3 | 7 | 6 | 1 | 0 |

## TA0001 Initial Access

| Technique | Rules (mode) |
|---|---|
| T1110.001 | `auth.ssh_bruteforce_success` (alert) |
| T1505.003 | `exec.webserver_shell` (alert) |

## TA0002 Execution

| Technique | Rules (mode) |
|---|---|
| (unmapped) | `sigma.` (alert) |
| T1047 | `execution.wmic_process_create` (shadow) |
| T1059 | `anomaly.exec_rate_spike` (signal) |
| T1059.001 | `execution.powershell_encoded` (shadow) |
| T1059.004 | `lolbin.download_pipe_shell` (alert) |
| T1105 | `ioa.download_and_execute` (alert), `execution.powershell_download_exec` (shadow) |
| T1140 | `exec.b64_decode_exec` (alert) |
| T1204 | `ioc.process_hash` (alert), `anomaly.rare_binary_for_user` (signal), `yara.` (alert) |
| T1204.002 | `defense.tmp_exec` (signal), `defense.tmp_exec_chmod` (alert), `execution.office_child_shell` (shadow) |

## TA0003 Persistence

| Technique | Rules (mode) |
|---|---|
| T1053 | `persistence.autostart_write` (alert) |
| T1053.003 | `persistence.cron_write` (alert) |
| T1053.005 | `persistence.schtasks_user_path` (shadow), `persistence.scheduled_task_created` (signal), `persistence.scheduled_task_userpath` (shadow), `persistence.scheduled_task_suspicious` (alert) |
| T1098.004 | `persistence.ssh_authorized_keys` (alert) |
| T1505.003 | `webshell.windows_child_shell` (shadow) |
| T1543.002 | `persistence.systemd_unit` (alert) |
| T1543.003 | `persistence.service_user_path` (shadow), `persistence.service_installed` (signal), `persistence.service_image_userpath` (shadow), `persistence.service_image_suspicious` (alert) |
| T1546.003 | `persistence.wmi_subscription` (signal), `persistence.wmi_command_consumer` (alert) |
| T1546.004 | `persistence.rc_edit` (signal) |
| T1546.010 | `persistence.appinit_dlls` (alert) |
| T1546.012 | `persistence.ifeo_debugger` (alert) |
| T1546.015 | `persistence.com_hijack` (shadow) |
| T1547.001 | `persistence.run_key` (shadow), `persistence.registry_run_key_added` (signal), `persistence.registry_run_userpath` (shadow), `persistence.registry_run_suspicious` (alert) |
| T1547.004 | `persistence.winlogon_modified` (alert) |
| T1547.006 | `defense.kmod_from_tmp` (alert) |
| T1574.006 | `persistence.ld_preload` (alert) |

## TA0004 Privilege Escalation

| Technique | Rules (mode) |
|---|---|
| T1068 | `ioa.privilege_escalation_activity` (alert) |
| T1548 | `privesc.gtfobin` (alert) |
| T1548.001 | `privesc.setuid_root` (alert), `privesc.untracked_suid_exec` (alert) |
| T1548.003 | `privesc.sudoers_modify` (alert) |
| T1611 | `container.escape_indicators` (alert) |

## TA0005 Defense Evasion

| Technique | Rules (mode) |
|---|---|
| T1014 | `rootkit.` (alert) |
| T1055 | `memory.anon_exec` (alert) |
| T1055.001 | `memory.injected_pe` (alert) |
| T1070 | `deception.honeytoken_tamper` (alert) |
| T1070.001 | `defense_evasion.eventlog_clear` (alert) |
| T1070.002 | `evasion.log_or_history_clear` (alert) |
| T1070.003 | `evasion.history_clear` (signal) |
| T1112 | `persistence.registry_object_renamed` (signal) |
| T1218.005 | `lolbin.mshta_remote` (shadow) |
| T1218.010 | `lolbin.regsvr32_remote` (alert) |
| T1218.011 | `lolbin.rundll32_script` (shadow), `lolbin.rundll32_no_args` (shadow), `lolbin.rundll32_remote` (shadow) |
| T1562 | `selfprotect.unclean_shutdown` (signal) |
| T1562.001 | `defense_evasion.amsi_bypass` (shadow), `defense_evasion.defender_tamper` (alert), `defense_evasion.defender_exclusion` (alert), `defense_evasion.defender_disabled` (alert) |
| T1562.002 | `defense_evasion.eventlog_disabled` (shadow), `defense_evasion.audit_policy_disabled` (shadow), `selfprotect.audit_policy_changed` (alert) |
| T1562.006 | `selfprotect.etw_session_stopped` (alert) |
| T1562.009 | `defense_evasion.boot_config_tamper` (shadow) |
| T1574.002 | `defense_evasion.dll_sideload` (shadow) |
| T1574.006 | `injection.ld_preload` (alert), `injection.ld_preload_runtime` (alert) |
| T1620 | `fileless.memfd_exec` (alert), `memory.memfd_exec` (alert), `memory.deleted_exec` (signal) |

## TA0006 Credential Access

| Technique | Rules (mode) |
|---|---|
| T1003.001 | `credential_access.lsass_memory_access` (signal), `credential_access.lsass_dump` (alert), `credential_access.mimikatz` (alert) |
| T1003.002 | `credential_access.sam_hive_save` (alert) |
| T1003.003 | `credential_access.ntds_dump` (shadow) |
| T1003.007 | `creds.proc_mem_access` (alert) |
| T1003.008 | `creds.shadow_read` (alert) |
| T1110.001 | `auth.windows_bruteforce` (alert), `auth.windows_bruteforce_success` (alert) |
| T1110.003 | `auth.windows_password_spray` (alert) |
| T1552.001 | `creds.secret_store_access` (alert) |
| T1552.004 | `creds.private_key_read` (alert) |
| T1552.005 | `cloud.imds_access` (signal) |
| T1555 | `creds.sensitive_file_access` (alert) |

## TA0007 Discovery

| Technique | Rules (mode) |
|---|---|
| T1046 | `recon.port_scan` (alert) |
| T1082 | `discovery.recon_burst` (signal) |
| T1482 | `discovery.ad_trusts` (signal) |

## TA0008 Lateral Movement

| Technique | Rules (mode) |
|---|---|
| T1021 | `lateral.admin_port_sweep` (alert) |

## TA0009 Collection

| Technique | Rules (mode) |
|---|---|
| T1560.001 | `collection.archive_staging` (signal) |

## TA0010 Exfiltration

| Technique | Rules (mode) |
|---|---|
| T1041 | `ioa.credential_access_exfil` (alert) |
| T1048.003 | `exfil.http_upload` (alert) |

## TA0011 Command and Control

| Technique | Rules (mode) |
|---|---|
| T1059.004 | `revshell.dev_tcp_redirect` (alert) |
| T1059.006 | `revshell.interpreter_socket` (alert) |
| T1071 | `ioc.network_ip` (alert), `beaconing.regular_interval` (alert) |
| T1071.004 | `ioc.dns_domain` (alert), `dns_tunnel.anomalous_query_volume` (alert) |
| T1105 | `lolbin.certutil_download` (shadow) |
| T1197 | `lolbin.bitsadmin_download` (shadow) |

## TA0040 Impact

| Technique | Rules (mode) |
|---|---|
| T1486 | `ransomware.mass_modification` (alert), `ransomware.suspicious_extension` (alert), `ransomware.high_entropy` (signal) |
| T1490 | `impact.shadow_copy_delete` (alert), `ransomware.backup_tamper` (alert), `impact.recovery_disabled` (alert) |
| T1496 | `impact.cryptominer` (alert) |

## Tactics without any rule

None.
