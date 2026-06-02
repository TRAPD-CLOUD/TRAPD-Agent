# Telemetry-Tiefe (P1) — Status & Implementierung

Bewertung der P1-Liste „Daten, die noch fehlen“ gegen den TRAPD-Agent und die
in diesem Durchlauf ergänzte Telemetrie. Referenzmaßstab ist CrowdStrike Falcon
(Image-Hash pro Exec, Loaded-Module-Inventory, Netflow-Tiefe, FIM-Baseline …).

Legende: ✅ implementiert · 🟡 teilweise · ⏳ offen (Begründung + Plan)

| # | P1-Punkt | Status | Fundstelle |
|---|----------|--------|------------|
| 1 | **SHA256 beim Exec** (Image-Hash fürs IOC/Reputation-Matching) | ✅ | `collectors/linux/proc_enrich.rs` → `image_sha256` |
| 2 | **Shared-Library-Loads / LD_PRELOAD** | ✅ | LD_PRELOAD (eBPF) + Loaded-Library-Inventory (`proc_enrich::loaded_libraries`); Live-`dlopen`-Tracing optional (eBPF, dokumentiert) |
| 3 | **DNS-Responses (resolved IPs)** | ✅ | `collectors/linux/packet_capture.rs` (AF_PACKET, `parse_dns_response`) |
| 4 | **Netflow-Tiefe** (Bytes/Pakete/Dauer/JA3/SNI) | ✅ | Bytes/Pakete/RTT via INET_DIAG (`inet_diag.rs`), Dauer+Flow-Close (`network.rs`), JA3/SNI (`packet_capture.rs`) |
| 5 | **SHA256-FIM mit Baseline** (`/usr/bin`,`/lib`,`/boot`,`/etc` …) | ✅ | `collectors/linux/filesystem.rs` (SQLite-Baseline, war bereits vorhanden) |
| 6 | **SUID/SGID + Capabilities, Listening-Ports, Kernel-Module + Signatur** | ✅ | `inventory/collect.rs` → `gather_security_posture` |
| 7 | **Container/K8s-Enrichment** (Image/Digest, Pod/Namespace/Labels) | ✅ | `proc_enrich::container_context` + `collectors/linux/container.rs` |
| 8 | **Env-Variablen + Interpreter-Script-Content** | ✅ | `proc_enrich::curated_env` / `interpreter_context` |

Alle acht P1-Punkte sind jetzt im Userspace implementiert und getestet (211
Tests, clippy `-D warnings` clean). Die wenigen verbleibenden Optionalia
(Live-`dlopen`-Events, CRI-Lifecycle-Stream) sind eBPF-/API-gebunden und unten
mit Plan dokumentiert.

---

## Was in diesem Durchlauf implementiert wurde

### 1 · Image-SHA256 bei jedem Exec
`ExecEventData.sha256` (`sha256:<hex>`). Gehasht wird bevorzugt `/proc/<pid>/exe`
(echter Inode, auch bei entlinktem/„self-deleting“ Dropper auflösbar), Fallback
auf den Exec-Pfad. **Cache** nach `(dev, inode, mtime, size)` — ein heißes Binary
(`bash`, `python3`) wird einmal gehasht, nicht pro Exec. Binaries > 512 MiB werden
übersprungen (Kostenschutz), alle übrigen Felder bleiben erhalten.

### 2 · Loaded-Library-Inventory (DLL-Äquivalent)
`ExecEventData.loaded_libraries` aus `/proc/<pid>/maps`: alle distinct file-backed
`*.so` / `*.so.N`, sortiert, dedupliziert, gekappt auf 128. LD_PRELOAD wird
weiterhin im eBPF-`sys_enter_execve` erkannt **und** zusätzlich in `env`
gespiegelt. (Live-`dlopen`-Tracing via uprobe ist als Folgeschritt offen.)

### 6 · Security-Posture-Baseline im Inventory (Schema v3)
Neues `InventorySnapshot.security_posture`:
* **SUID/SGID-Binaries** — ein Filesystem-Walk über die Standard-Exec-Roots
  (`/usr/bin`,`/usr/sbin`,`/bin`,`/sbin`,`/usr/lib`,`/opt`,…) mit Mode, Owner,
  Größe und **SHA256** je Binary; Scan-Budget gekappt (200k Einträge).
* **File-Capabilities** — `security.capability`-xattr via `getxattr(2)`,
  dekodiert (v1/v2/v3 `vfs_cap_data`) in `getcap`-Form
  (`cap_net_raw,cap_net_admin+ep`).
* **Listening-Ports** — TCP `LISTEN` + ungebundene UDP-Sockets (v4/v6), zurück
  aufgelöst auf PID/Prozess über die Socket-Inode-Map.
* **Kernel-Module** — `/proc/modules` mit Größe/State und **Signaturstatus**
  (`signed`/`unsigned`/`unknown`) aus `/sys/module/<name>/taint` bzw. dem
  Taint-Flag `E` (unsigniertes Modul).

Der Snapshot ist die Angriffsflächen-Baseline, gegen die das Backend diffen kann:
ein neues SUID-Binary, ein neuer offener Port oder ein unsigniertes Modul
zwischen zwei Snapshots ist ein hochwertiges Signal.

### 7 · Container/K8s-Enrichment
`ExecEventData.container_runtime` (`docker`/`containerd`/`crio`/`podman`/
`kubepods`), `container_image` + `container_image_digest` sowie `k8s`
(Pod-UID/Name/Namespace + Labels). Container-ID + Runtime + Pod-UID kommen aus
dem cgroup-Pfad (beide Treiber: systemd `_`-kodiert und cgroupfs `-`-kodiert,
`cri-containerd-<hash>`-Segmente korrekt erkannt). **Image-Name/-Digest +
Labels** werden aus den Runtime-State-Files gelesen (kein Daemon-Socket nötig):
Docker `…/containers/<id>/config.v2.json` (`Image`-Digest, `Config.Image`,
`Config.Labels`) bzw. containerd/CRI OCI-`config.json` (`annotations`). Pod-
Name/Namespace stammen aus den `io.kubernetes.pod.*`-Labels, mit Fallback auf
Downward-API/Env (`collectors/linux/container.rs`). **Offen:** Live-
CRI/containerd-Lifecycle-Events (Create/Start/Stop) — erfordern einen CRI-/
containerd-Event-Stream-Client.


### 8 · Env + Interpreter-Script-Content
* **Curated Env** aus `/proc/<pid>/environ`: kuratierte, sicherheitsrelevante
  Allowlist (`LD_*`, Proxies, SSH-/K8s-Kontext, `PATH`, …); Werte mit
  Secret-Markern im Namen (`TOKEN`/`SECRET`/`PASSWORD`/…) werden zu
  `***redacted***` — die Präsenz wird gemeldet, der Klartext nie exfiltriert.
* **Interpreter-Kontext** (`python`/`bash`/`perl`/`node`/…): Inline-Script aus
  `-c`/`-e`, dazu **Base64-Ketten** aus der Cmdline dekodiert (`… | base64 -d |
  sh`, `python -c "...b64decode(...)..."`) inkl. Printable-Heuristik, plus
  Indikator-Tags (`base64_decode`, `pipe_to_shell`, `reverse_shell`,
  `in_memory_exec`, `download_cradle`).

Alle Felder sind additiv und `skip_serializing_if`-geschützt — kein Bruch des
bestehenden Event-Schemas.

---

### 3 · DNS-Responses (resolved IPs) — implementiert
Neuer **passiver AF_PACKET-Sniffer** (`collectors/linux/packet_capture.rs`,
`SOCK_DGRAM`, L3) parst DNS-**Antworten** von Port 53: QNAME (inkl.
Komprimierungs-Pointer, schleifensicher), Antwort-RRs → `resolved_ips` (A/AAAA)
+ `cnames`, `rcode`, `transaction_id` → `DnsResolutionData`. Damit ist die
Domain↔IP-Korrelation für spätere ausgehende Verbindungen möglich. Der eBPF-
`udp_sendmsg`-Pfad (Query-Ziel + Prozess-Attribution) bleibt komplementär
erhalten. Reine Parser sind unit-getestet.

### 4 · Netflow-Tiefe — implementiert
* **Byte-/Paket-Zähler + RTT:** `collectors/linux/inet_diag.rs` fragt
  `INET_DIAG_REQ_V2` (`NETLINK_SOCK_DIAG`) für TCP (v4+v6) ab und joint
  `tcp_info` (`bytes_acked`/`bytes_received`/`segs_out`/`segs_in`/`rtt`) per
  Socket-Inode auf die Flow-Records. **ABI-sicher:** `parse_tcp_info` liest jedes
  Feld nur, wenn das zurückgegebene Blob lang genug ist (ältere Kernel liefern
  ein kürzeres Struct) — diese Offset-Logik ist rein + unit-getestet, der Socket-
  I/O drumherum ist best-effort.
* **Verbindungsdauer + Flow-Close:** `network.rs` (First-Seen-Tracking →
  `state:"closed"` mit `duration_ms` + finalen Zählern).
* **TLS-SNI/JA3:** `packet_capture.rs` parst den ClientHello (erstes TCP-Segment),
  extrahiert SNI/ALPN/`supported_versions` und berechnet JA3 (GREASE gefiltert)
  + dessen MD5-Hash → `TlsHandshakeData`. Parser unit-getestet.

---

## Verbleibende Optionalia (eBPF/API-gebunden) — Plan

Klein und bewusst zurückgestellt (eBPF-Build bzw. Runtime-API, in dieser CI-
Umgebung nicht verifizierbar):

* **Live-`dlopen`/`.so`-mmap-Events** (Punkt 2): das Loaded-Library-*Inventory*
  ist abgedeckt; *Live*-Events pro Nachlade-Vorgang bräuchten einen uprobe auf
  `dlopen` bzw. die Auswertung der bestehenden file-backed `PROT_EXEC`-`mmap`-
  Events.
* **CRI/containerd-Lifecycle-Events** (Punkt 7): Image/Digest/Labels sind über die
  Runtime-State-Files abgedeckt; *Live*-Create/Start/Stop-Events bräuchten einen
  CRI-/containerd-Event-Stream-Client.
* **JA3S** (server-seitiger Hash) und tiefe TCP-Reassembly für ClientHellos, die
  über mehrere Segmente fragmentiert sind — der häufige Single-Segment-Fall ist
  abgedeckt.
