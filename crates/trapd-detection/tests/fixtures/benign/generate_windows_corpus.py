#!/usr/bin/env python3
"""Generate the synthetic Windows benign corpus (deterministic).

    python3 generate_windows_corpus.py > windows-managed-fleet-synthetic.ndjson

SYNTHETIC, not recorded: one working day on three managed Windows hosts,
modelled on what a mid-sized European IT shop runs — Microsoft 365 clients,
Defender, Windows Update, SCCM/ConfigMgr and Intune script execution,
administrator tooling (MMC, RDP, WinSCP, PowerShell with -ExecutionPolicy
Bypass from management agents), backup, IIS and SQL Server. These are exactly
the processes that make naive Windows rules noisy.

Replace or extend it with recorded telemetry (`TRAPD_OUTPUT=file` on real
hosts) whenever available; recorded data always wins over this model.
"""
import json
import random
import uuid
from datetime import datetime, timedelta, timezone

rng = random.Random(20261006)
BASE = datetime(2026, 9, 14, 6, 0, 0, tzinfo=timezone.utc)
seq = 0


def ev(host, ts, cls, action, data):
    global seq
    seq += 1
    return {
        "event_id": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
        "agent_id": f"agent-{host.lower()}",
        "hostname": host,
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "000Z",
        "class": cls,
        "action": action,
        "severity": "info",
        "data": data,
    }


def proc(host, ts, pid, ppid, exe, cmdline, user):
    name = exe.rsplit("\\", 1)[-1]
    return ev(host, ts, "process", "create", {
        "pid": pid, "ppid": ppid, "name": name, "exe": exe, "cmdline": cmdline,
        "uid": 0, "username": user,
        "exe_sha256": format(rng.getrandbits(256), "064x"),
    })


def conn(host, ts, pid, process, dst, port):
    return ev(host, ts, "network", "connection", {
        "protocol": "tcp", "src_addr": "10.20.0.%d" % rng.randint(10, 250),
        "src_port": rng.randint(49152, 65535), "dst_addr": dst, "dst_port": port,
        "state": "established", "pid": pid, "process": process,
    })


def dns(host, ts, qname, ips):
    return ev(host, ts, "network", "dns_query", {
        "qname": qname, "qtype": "A", "resolved_ips": ips,
        "server_addr": "10.20.0.2", "client_addr": "10.20.0.50",
        "transaction_id": rng.randint(0, 65535), "rcode": "NOERROR",
    })


SYS32 = "C:\\Windows\\System32"
PF = "C:\\Program Files"
PF86 = "C:\\Program Files (x86)"

# (exe, cmdline template, user) — {n} is replaced by a random number.
OFFICE = [
    (f"{SYS32}\\svchost.exe", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule", "NT AUTHORITY\\SYSTEM"),
    (f"{SYS32}\\RuntimeBroker.exe", "C:\\Windows\\System32\\RuntimeBroker.exe -Embedding", "CORP\\anna.berg"),
    (f"{SYS32}\\backgroundTaskHost.exe", "\"C:\\Windows\\system32\\backgroundTaskHost.exe\" -ServerName:App.AppXmtcan0h2tfbfy7k9kn8hbxb6dmzz1zh0.mca", "CORP\\anna.berg"),
    (f"{PF}\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "\"C:\\Program Files\\Microsoft Office\\Root\\Office16\\OUTLOOK.EXE\"", "CORP\\anna.berg"),
    (f"{PF}\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "\"C:\\Program Files\\Microsoft Office\\Root\\Office16\\WINWORD.EXE\" /n \"C:\\Users\\anna.berg\\Documents\\Angebot_{n}.docx\" /o \"\"", "CORP\\anna.berg"),
    (f"{PF}\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "\"C:\\Program Files\\Microsoft Office\\Root\\Office16\\EXCEL.EXE\"", "CORP\\anna.berg"),
    (f"{PF86}\\Microsoft\\Edge\\Application\\msedge.exe", "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --type=renderer --lang=de --js-flags=--ms-user-locale= --device-scale-factor=1 --renderer-client-id={n}", "CORP\\anna.berg"),
    ("C:\\Users\\anna.berg\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe", "\"C:\\Users\\anna.berg\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background", "CORP\\anna.berg"),
    (f"{SYS32}\\SearchProtocolHost.exe", "\"C:\\Windows\\system32\\SearchProtocolHost.exe\" Global\\UsGthrFltPipeMssGthrPipe{n}_ Global\\UsGthrCtrlFltPipeMssGthrPipe{n} 1 -2147483646 \"Software\\Microsoft\\Windows Search\" \"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT; MS Search 4.0 Robot)\" \"C:\\ProgramData\\Microsoft\\Search\\Data\\Temp\\usgthrsvc\" \"DownLevelDaemon\"", "NT AUTHORITY\\SYSTEM"),
    ("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MpCmdRun.exe", "\"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MpCmdRun.exe\" SignatureUpdate -ScheduleJob -RestrictPrivileges", "NT AUTHORITY\\SYSTEM"),
    (f"{SYS32}\\taskhostw.exe", "taskhostw.exe Install $(Arg0)", "CORP\\anna.berg"),
    (f"{SYS32}\\conhost.exe", "\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1", "CORP\\anna.berg"),
    ("C:\\Users\\anna.berg\\AppData\\Local\\Microsoft\\WindowsApps\\ms-teams.exe", "\"ms-teams.exe\" msteams:system-initiated", "CORP\\anna.berg"),
]

ADMIN = [
    (f"{SYS32}\\mmc.exe", "\"C:\\Windows\\system32\\mmc.exe\" \"C:\\Windows\\system32\\dsa.msc\"", "CORP\\adm.mueller"),
    (f"{SYS32}\\mstsc.exe", "\"C:\\Windows\\system32\\mstsc.exe\" /v:srv-app{n}.corp.example.eu", "CORP\\adm.mueller"),
    (f"{PF86}\\WinSCP\\WinSCP.exe", "\"C:\\Program Files (x86)\\WinSCP\\WinSCP.exe\"", "CORP\\adm.mueller"),
    (f"{SYS32}\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \\\\fs01\\it$\\scripts\\Get-Inventory.ps1 -ComputerName srv-app{n}", "CORP\\adm.mueller"),
    (f"{SYS32}\\WindowsPowerShell\\v1.0\\powershell.exe", "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoExit -Command Import-Module ActiveDirectory", "CORP\\adm.mueller"),
    (f"{SYS32}\\cmd.exe", "C:\\Windows\\system32\\cmd.exe /c ipconfig /all", "CORP\\adm.mueller"),
    (f"{SYS32}\\ipconfig.exe", "ipconfig  /all", "CORP\\adm.mueller"),
    (f"{SYS32}\\whoami.exe", "whoami  /groups", "CORP\\adm.mueller"),
    (f"{SYS32}\\net.exe", "net  use Z: \\\\fs01\\projekte /persistent:yes", "CORP\\adm.mueller"),
    (f"{SYS32}\\gpupdate.exe", "gpupdate  /force", "CORP\\adm.mueller"),
    (f"{SYS32}\\schtasks.exe", "schtasks  /query /fo LIST /v", "CORP\\adm.mueller"),
    (f"{SYS32}\\sc.exe", "sc  query wuauserv", "CORP\\adm.mueller"),
    (f"{SYS32}\\certutil.exe", "certutil  -hashfile C:\\Install\\setup_{n}.msi SHA256", "CORP\\adm.mueller"),
    (f"{SYS32}\\Robocopy.exe", "robocopy  C:\\Install \\\\fs01\\it$\\install /MIR /R:1 /W:1", "CORP\\adm.mueller"),
    (f"{SYS32}\\nslookup.exe", "nslookup  srv-sql0{n}.corp.example.eu", "CORP\\adm.mueller"),
    (f"{SYS32}\\tasklist.exe", "tasklist  /svc", "CORP\\adm.mueller"),
]

SERVER = [
    ("C:\\Windows\\CCM\\CcmExec.exe", "C:\\Windows\\CCM\\CcmExec.exe", "NT AUTHORITY\\SYSTEM"),
    (f"{SYS32}\\WindowsPowerShell\\v1.0\\powershell.exe", "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoLogo -NonInteractive -ExecutionPolicy Bypass -File \"C:\\Windows\\CCM\\SystemTemp\\{n}.ps1\"", "NT AUTHORITY\\SYSTEM"),
    (f"{PF86}\\Microsoft Intune Management Extension\\AgentExecutor.exe", "\"C:\\Program Files (x86)\\Microsoft Intune Management Extension\\agentexecutor.exe\" -powershell \"C:\\Program Files (x86)\\Microsoft Intune Management Extension\\Policies\\Scripts\\{n}_1.ps1\" \"C:\\Program Files (x86)\\Microsoft Intune Management Extension\\Policies\\Results\\{n}_1.output\" \"C:\\Program Files (x86)\\Microsoft Intune Management Extension\\Policies\\Results\\{n}_1.error\" \"C:\\Program Files (x86)\\Microsoft Intune Management Extension\\Policies\\Results\\{n}_1.timeout\" 60000 \"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\" 0 \"\" \"\" False False False", "NT AUTHORITY\\SYSTEM"),
    (f"{SYS32}\\WindowsPowerShell\\v1.0\\powershell.exe", "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoProfile -executionPolicy bypass -file  \"C:\\Program Files (x86)\\Microsoft Intune Management Extension\\Policies\\Scripts\\{n}_1.ps1\"", "NT AUTHORITY\\SYSTEM"),
    (f"{SYS32}\\msiexec.exe", "C:\\Windows\\system32\\msiexec.exe /i \"C:\\Windows\\ccmcache\\4\\Firefox Setup 128.{n}.msi\" /qn /norestart", "NT AUTHORITY\\SYSTEM"),
    ("C:\\Windows\\WinSxS\\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.20348.2700_none_7c0c8b7b5f6b5a1e\\TiWorker.exe", "C:\\Windows\\winsxs\\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.20348.2700_none_7c0c8b7b5f6b5a1e\\TiWorker.exe -Embedding", "NT AUTHORITY\\SYSTEM"),
    (f"{SYS32}\\wuauclt.exe", "\"C:\\Windows\\system32\\wuauclt.exe\" /RunHandlerComServer", "NT AUTHORITY\\SYSTEM"),
    (f"{PF}\\Veeam\\Endpoint Backup\\Veeam.EndPoint.Service.exe", "\"C:\\Program Files\\Veeam\\Endpoint Backup\\Veeam.EndPoint.Service.exe\"", "NT AUTHORITY\\SYSTEM"),
    (f"{SYS32}\\vssadmin.exe", "vssadmin  list shadows", "NT AUTHORITY\\SYSTEM"),
    (f"{SYS32}\\inetsrv\\w3wp.exe", "c:\\windows\\system32\\inetsrv\\w3wp.exe -ap \"DefaultAppPool\" -v \"v4.0\" -l \"webengine4.dll\" -a \\\\.\\pipe\\iisipm{n} -h \"C:\\inetpub\\temp\\apppools\\DefaultAppPool\\DefaultAppPool.config\" -w \"\" -m 0", "IIS APPPOOL\\DefaultAppPool"),
    (f"{PF}\\Microsoft SQL Server\\MSSQL16.MSSQLSERVER\\MSSQL\\Binn\\sqlservr.exe", "\"C:\\Program Files\\Microsoft SQL Server\\MSSQL16.MSSQLSERVER\\MSSQL\\Binn\\sqlservr.exe\" -sMSSQLSERVER", "NT SERVICE\\MSSQLSERVER"),
    (f"{SYS32}\\wbem\\WmiPrvSE.exe", "C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding", "NT AUTHORITY\\NETWORK SERVICE"),
    (f"{SYS32}\\rundll32.exe", "C:\\Windows\\system32\\rundll32.exe C:\\Windows\\system32\\PcaSvc.dll,PcaPatchSdbTask", "NT AUTHORITY\\SYSTEM"),
    (f"{SYS32}\\bcdedit.exe", "bcdedit  /enum {current}", "NT AUTHORITY\\SYSTEM"),
]

# Recurring outbound endpoints: periodic by design (telemetry, sync, push).
ENDPOINTS = [
    ("MsMpEng.exe", "wdcp.microsoft.com", "20.42.65.85", 443, 900),
    ("OneDrive.exe", "skyapi.live.net", "13.107.42.12", 443, 300),
    ("ms-teams.exe", "teams.microsoft.com", "52.113.194.132", 443, 120),
    ("svchost.exe", "settings-win.data.microsoft.com", "40.127.240.158", 443, 1800),
    ("CcmExec.exe", "sccm01.corp.example.eu", "10.20.0.30", 443, 600),
]

DNS_NAMES = [
    ("login.microsoftonline.com", ["20.190.159.0"]),
    ("outlook.office365.com", ["52.97.146.2"]),
    ("a1887.dscq.akamai.net", ["2.16.106.19"]),
    ("prod-msit-ussc-01.cloudapp.azure.com", ["20.65.0.4"]),
    ("st0contosobackup4f6a2b9c1d.blob.core.windows.net", ["20.60.40.4"]),
    ("v10.events.data.microsoft.com", ["20.42.65.92"]),
    ("_ldap._tcp.dc._msdcs.corp.example.eu", ["10.20.0.2"]),
    ("srv-sql01.corp.example.eu", ["10.20.0.41"]),
    ("wpad.corp.example.eu", ["10.20.0.2"]),
    ("ctldl.windowsupdate.com", ["93.184.221.240"]),
    ("f.c2r.ts.cdn.office.net", ["2.16.106.48"]),
    ("8d6e7f4c2b1a.cdn.cloudflare.net", ["104.16.0.1"]),
]

events = []
for host, catalog, per_hour in (("WS-0142", OFFICE, 16), ("ADM-07", ADMIN, 12), ("SRV-APP02", SERVER, 10)):
    pid = 1000
    for hour in range(0, 12):  # 06:00–18:00
        for _ in range(per_hour):
            exe, cmd, user = rng.choice(catalog)
            ts = BASE + timedelta(hours=hour, seconds=rng.randint(0, 3599))
            pid += rng.randint(4, 40)
            events.append(proc(host, ts, pid, rng.choice([4, 668, 1024, 2048]), exe, cmd.replace("{n}", str(rng.randint(1, 9))), user))
    for process, name, ip, port, period in ENDPOINTS:
        t = BASE + timedelta(seconds=rng.randint(0, period))
        while t < BASE + timedelta(hours=12):
            events.append(dns(host, t, name, [ip]))
            events.append(conn(host, t + timedelta(milliseconds=40), 3000, process, ip, port))
            t += timedelta(seconds=period + rng.randint(-5, 5))
    for _ in range(120):
        name, ips = rng.choice(DNS_NAMES)
        events.append(dns(host, BASE + timedelta(seconds=rng.randint(0, 12 * 3600)), name, ips))

events.sort(key=lambda e: e["timestamp"])
for e in events:
    print(json.dumps(e, separators=(",", ":")))
