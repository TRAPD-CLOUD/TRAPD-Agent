# Telemetry-Tiefe (P1) — Status & Implementierung

Bewertung der P1-Liste „Daten, die noch fehlen“ gegen den TRAPD-Agent und die
in diesem Durchlauf ergänzte Telemetrie. Referenzmaßstab ist CrowdStrike Falcon
(Image-Hash pro Exec, Loaded-Module-Inventory, Netflow-Tiefe, FIM-Baseline …).

Legende: ✅ implementiert · 🟡 teilweise · ⏳ offen (Begründung + Plan)

| # | P1-Punkt | Status | Fundstelle |
|---|----------|--------|------------|
| 1 | **SHA256 beim Exec** (Image-Hash fürs IOC/Reputation-Matching) | ✅ | `collectors/linux/proc_enrich.rs` → `image_sha256` |
| 2 | **Shared-Library-Loads / LD_PRELOAD** | 🟡 | LD_PRELOAD (eBPF) + Loaded-Library-Inventory (`proc_enrich::loaded_libraries`); dlopen-Live-Tracing offen |
| 3 | **DNS-Responses (resolved IPs)** | ⏳ | nur Query-Ziel (`ebpf/dns.rs`); Response-Parsing offen (eBPF) |
| 4 | **Netflow-Tiefe** (Bytes/Pakete/Dauer/JA3) | 🟡 | **Dauer + Flow-Close ✅** (`network.rs`); Byte-/Paket-Zähler (INET_DIAG) + JA3/SNI (DPI) offen |
| 5 | **SHA256-FIM mit Baseline** (`/usr/bin`,`/lib`,`/boot`,`/etc` …) | ✅ | `collectors/linux/filesystem.rs` (SQLite-Baseline, war bereits vorhanden) |
| 6 | **SUID/SGID + Capabilities, Listening-Ports, Kernel-Module + Signatur** | ✅ | `inventory/collect.rs` → `gather_security_posture` |
| 7 | **Container/K8s-Enrichment** (Image/Digest, Pod/Namespace/Labels) | ✅ | `proc_enrich::container_context` + `collectors/linux/container.rs` |
| 8 | **Env-Variablen + Interpreter-Script-Content** | ✅ | `proc_enrich::curated_env` / `interpreter_context` |

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

### 4 (teilweise) · Netflow-Tiefe — Verbindungsdauer + Flow-Close
Der `NetworkCollector` führt jetzt einen Flow-Lebenszyklus: pro 4-Tupel wird der
First-Seen-Zeitpunkt gehalten, beim Verschwinden einer Verbindung wird ein
`state: "closed"`-Record mit `duration_ms` (gemessene Lebensdauer) emittiert. Der
Flow-Key ist IPv6-sicher (Feld-basiert, kein naives Colon-Split).

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

## Offene Punkte (eBPF-/DPI-gebunden) — Begründung & Plan

Diese Punkte lassen sich nicht sauber im Userspace lösen bzw. erfordern eine
Änderung am eBPF-Programm, die in dieser CI-Umgebung nicht kompiliert/getestet
werden kann (`bpfel-unknown-none` + nightly + `bpf-linker`). Sie sind hier
bewusst dokumentiert statt ungetestet ausgeliefert.

### 3 · DNS-Responses (resolved IPs)
Aktuell erfasst `kprobe__udp_sendmsg` nur das **Query-Ziel** (Resolver-IP/-Port).
Für die **Antworten** (aufgelöste A/AAAA-Records → Korrelation Domain↔IP):
* **Plan:** kretprobe/kprobe auf `udp_recvmsg` (bzw. ein TC/socket-filter eBPF auf
  Port 53), DNS-Payload im Kernel parsen (QNAME + Answer-RRs, bounded Loop für
  den Verifier), Events um `qname` + `resolved_ips[]` erweitern
  (`schema::DnsData`). Korreliert dann ausgehende Connections mit der Domain.

### 4 (Rest) · Netflow-Tiefe — Byte-/Paket-Zähler + TLS-SNI/JA3
Verbindungsdauer + Flow-Close sind implementiert (siehe oben). Offen bleiben:
* **Bytes/Pakete — Plan (Userspace, ohne eBPF):** `INET_DIAG`/`sock_diag`
  über Netlink abfragen → `tcp_info` (`bytes_acked`, `bytes_received`, `segs_in/
  out`, `rtt`). `NetworkConnectionData` um `bytes_sent/recv`, `packets_*`
  erweitern. Bewusst **nicht** per Hand-gerolltem `tcp_info`-Offset-Parsing
  umgesetzt — die ABI ist kernel-versions-/bitfield-abhängig und ohne echten
  Kernel-Host nicht verifizierbar; korrekt wäre eine vetted Netlink-Crate
  (`neli` / `netlink-packet-sock-diag`) als neue Dependency.
* **TLS-SNI/JA3 — Plan (DPI):** ClientHello aus den ersten TX-Bytes der
  Verbindung parsen (TC-eBPF oder AF_PACKET), SNI extrahieren und JA3 über
  Cipher-Suites/Extensions/EC-Kurven hashen.

### 2 (Rest) · Live-dlopen-Tracing
Das Loaded-Library-**Inventory** (maps-Snapshot) ist abgedeckt; **Live**-Events
pro `dlopen`/`.so`-mmap brauchen einen uprobe auf `dlopen` bzw. eine Auswertung
der bestehenden `mmap`-Events (Datei-backed, `PROT_EXEC`) — Folgeschritt.
