# Adversarial test kit

Every script tampers with the local agent on purpose and refuses to run unless
`TRAPD_ADVERSARIAL_OK=1`. Run on a test host only. Scripts create their test
artefacts in a temp dir and remove them.

| Row | Threat | Script | Command | Expected event | How to verify |
|---|---|---|---|---|---|
| T6 | Debugger / DLL injection into the agent | `T6_T7_linux.sh` | `TRAPD_ADVERSARIAL_OK=1 ./T6_T7_linux.sh` | `selfprotect.debugger_attached` (tracer pid, comm, exe) within ~60 s; also the 10 s `AgentTamper` ptrace event | agent log `process integrity finding`, console alert |
| T7 | Memory implant (Linux) | `T6_T7_linux.sh` | same run (gdb maps an rwx page) | `selfprotect.module_injected`, reason `anonymous_rwx` | as above |
| T6 | Remote DLL load (Windows) | `T6_T7_windows.ps1` | `$env:TRAPD_ADVERSARIAL_OK=1; .\T6_T7_windows.ps1` (elevated) | `selfprotect.module_injected` (path outside System32/install dir, sha256), `selfprotect.handle_access` (the PowerShell process with VM_WRITE/CREATE_THREAD) within ~60 s | console alert; agent log |
| T7 | ETW patch (Windows) | `T6_T7_windows.ps1` | same run (writes `ret` over `EtwEventWrite`, restores it) | `selfprotect.code_patched`, subject `ntdll.dll!EtwEventWrite`, expected vs actual bytes | console alert |

False-positive switches: `TRAPD_SELFPROTECT_CHECK_{CODE,MODULES,THREADS,DEBUGGER,HANDLES}=off`,
`TRAPD_SELFPROTECT_MODULE_ALLOW`, `TRAPD_SELFPROTECT_HANDLE_ALLOW`.
