# TRAPD-Agent – Falcon Readiness Roadmap

Dieses Dokument listet alle Aufgaben, die notwendig sind, um den TRAPD-Agent auf
CrowdStrike Falcon-Niveau zu bringen. Jede Kategorie entspricht einem GitHub Issue.

---

## 1. Prävention & Aktive Response

**Ziel:** Vom reinen Telemetrie-Agenten zum aktiven EDR-Agenten.

- [ ] **Process Blocking via eBPF/LSM**: Malicious Prozesse via `bpf_send_signal()` oder LSM-Hooks (Linux Security Module) in Echtzeit beenden
- [ ] **Network Containment**: Netzwerk-Isolation infizierter Hosts via iptables/nftables-Regeln aus der Backend-API
- [ ] **File Quarantine**: Automatisches Verschieben/Sperren von als malicious klassifizierten Dateien (`O_NOATIME`, `chattr +i`)
- [ ] **IoC-basiertes Blocking**: Konfigurierbare Block-Rules für Prozess-Hashes, IPs, Domains
- [ ] **Memory Injection Prevention**: LSM-Hooks auf `ptrace`, `process_vm_writev`, `memfd_create` zum Blockieren von Code-Injection
- [ ] **Automated Response Playbooks**: Backend-gesteuerte Aktionen (kill, isolate, quarantine) über Response-Commands in der API

---

## 2. Erweiterte Kernel-Sichtbarkeit via eBPF

**Ziel:** Vollständige Syscall-Abdeckung statt nur `sched_process_exec`.

- [ ] **Syscall Tracing ausdehnen**: eBPF-Programme für `open/openat`, `write`, `connect`, `bind`, `accept`, `execve`, `clone`, `unlink`, `rename`, `chmod`, `chown`, `mmap`, `ptrace`
- [ ] **DNS-Query Monitoring**: Intercepting von DNS-Anfragen via eBPF `kprobe` auf `udp_sendmsg` oder Socket-Filter
- [ ] **Raw Socket & Paketanalyse**: XDP/TC eBPF für Netzwerk-Sichtbarkeit auf Packet-Ebene
- [ ] **Kernel Module Load/Unload Tracking**: `module_load` tracepoint überwachen (Rootkit-Erkennung)
- [ ] **Shared Memory Monitoring**: `shmget`, `shmat` syscall-Tracing
- [ ] **Namespace Monitoring**: PID-, Network-, Mount-Namespace-Wechsel erkennen (Container-Escapes)
- [ ] **eBPF Map-basierter Ringbuffer**: Wechsel auf `BPF_MAP_TYPE_RINGBUF` für alle eBPF-Programme (performance-optimiert)

---

## 3. Verhaltensbasierte Erkennung & ML

**Ziel:** Lokale Anomalie-Erkennung ohne Backend-Abhängigkeit.

- [ ] **Baseline-Profiling**: Normalverhalten von Prozessen, Netzwerk und User-Aktivität über Zeit aufzeichnen
- [ ] **Anomalie-Scoring**: Statistisches Modell (z. B. Isolation Forest) für Prozess-/Netzwerk-Anomalien
- [ ] **YARA Rule Engine**: Integration von `yara-rust` für Datei- und Prozess-Speicher-Scanning
- [ ] **Sigma Rule Support**: Sigma-Regeln in lokale Erkennungslogik übersetzen
- [ ] **MITRE ATT&CK Mapping**: Erkannte Events automatisch ATT&CK-Techniken zuordnen (Tactic, Technique, Sub-Technique)
- [ ] **Heuristische LOLBin-Erkennung**: Whitelist bekannter Binaries mit Verhaltens-Baseline (z. B. `bash` startet `curl` → verdächtig)

---

## 4. Threat Intelligence Integration

**Ziel:** Lokal oder via Feed IOCs erkennen.

- [ ] **Hash-basiertes IOC-Matching**: SHA256-Hashes von Prozessen/Dateien gegen Threat-Feed prüfen
- [ ] **IP/Domain Reputation Lookup**: Ausgehende Verbindungen gegen Threat-Intelligence-Feeds matchen
- [ ] **Lokale IOC-Datenbank**: SQLite-basierte lokale IOC-Datenbank mit regelmäßigem Feed-Update
- [ ] **STIX/TAXII Feed Consumer**: Standardisierte Threat-Intelligence-Feeds konsumieren
- [ ] **CVE/Vulnerability Correlation**: Geladene Bibliotheken und Pakete gegen CVE-Datenbank prüfen

---

## 5. Datei-Integrität & Ransomware-Schutz

**Ziel:** FIM mit Baseline und Ransomware-Frühwarnung.

- [ ] **SHA256-basiertes FIM**: Kryptographische Checksums für alle überwachten Dateien – Baseline erstellen und Abweichungen melden
- [ ] **Erweitertes FIM-Monitoring**: Kritische Pfade ausweiten (`/usr/bin`, `/usr/sbin`, `/lib`, `/boot`, `/etc`, `/root`)
- [ ] **Ransomware-Behavior Detection**: Massenhafte Datei-Verschlüsselungsoperationen via eBPF erkennen (viele `write`-Calls mit Entropie-Änderung)
- [ ] **Datei-Entropie-Analyse**: Entropie-Messung bei `write`-Events zur Erkennung von Verschlüsselung
- [ ] **Shadow Copy / Backup-Schutz**: Erkennen von Löschversuchen auf Backup-Directories
- [ ] **Immutable File Protection**: Kritische Agent-Dateien mit `chattr +i` schützen

---

## 6. Speicher-Sicherheit & Code-Injection-Erkennung

**Ziel:** Erkennung von Process Hollowing, Reflective Loading, Heap Spray.

- [ ] **Process Memory Scanning**: Regelmäßiges Scannen von Prozess-Speicher auf Shellcode-Signaturen (YARA)
- [ ] **ptrace-Missbrauch erkennen**: Alle ptrace-Aufrufe auf fremde Prozesse überwachen und melden
- [ ] **`/proc/PID/maps` Analyse**: Anomale Speicher-Mappings erkennen (ausführbare anonyme Regionen)
- [ ] **`memfd_create` Monitoring**: Dateisystem-lose ausführbare Bereiche erkennen (Fileless Malware)
- [ ] **Shellcode-Entropie-Check**: Hohe Entropie in ausführbaren Speicherbereichen als IOC werten
- [ ] **LD_PRELOAD Hijacking Detection**: Erkennen von `LD_PRELOAD`-Injection in Prozess-Umgebungsvariablen

---

## 7. Identitäts- & Credential-Schutz

**Ziel:** Credential-Diebstahl und Privilegien-Eskalation erkennen.

- [ ] **`/etc/shadow` Access Monitoring**: Zugriffe auf Passwort-Hashes erkennen und alarmieren
- [ ] **Sudo/Su Abuse Detection**: Unerwartete `sudo`/`su`-Verwendung nach Baseline erkennen
- [ ] **SSH Key Access Monitoring**: Zugriffe auf `~/.ssh/` außerhalb legitimier SSH-Dienste
- [ ] **Token/Cookie Theft Detection**: Zugriff auf Browser-Profile, `~/.aws/`, `~/.kube/config` melden
- [ ] **SUID/SGID Binary Monitoring**: Ausführung von SUID-Binaries tracken und gegen Baseline prüfen
- [ ] **Privilege Escalation Detection**: UID-Wechsel (0 → non-0 → 0) via `setuid`-Syscall-Tracing
- [ ] **PAM-Module Monitoring**: Manipulation von `/etc/pam.d/` erkennen

---

## 8. Netzwerk-Sicherheit & C2-Erkennung

**Ziel:** C2-Kommunikation und laterale Bewegung erkennen.

- [ ] **DNS Tunneling Detection**: Ungewöhnlich lange DNS-Queries oder hohe DNS-Frequenz erkennen
- [ ] **Beaconing Detection**: Periodisches Netzwerk-Verbindungsverhalten als C2-Beacon klassifizieren
- [ ] **Reverse Shell Detection**: Shell-Prozesse mit Stdin/Stdout auf Netzwerk-Sockets
- [ ] **Port Scanning Detection**: Ausgehende Verbindungen zu vielen Ports auf demselben Host
- [ ] **Lateral Movement Detection**: SMB/SSH-Verbindungen zu internen Hosts nach initialem Exploit
- [ ] **TLS Certificate Pinning**: Nur validierte Backend-Zertifikate akzeptieren (HPKP-ähnlich)
- [ ] **Encrypted C2 Detection**: Entropie-basierte Erkennung von verschlüsseltem Non-HTTP-Traffic

---

## 9. Container & Cloud Security

**Ziel:** Kubernetes- und Cloud-native Workloads absichern.

- [ ] **Container Escape Detection**: Namespace-Breakouts, privilegierte Mounts, `CAP_SYS_ADMIN`-Missbrauch erkennen
- [ ] **Privileged Container Monitoring**: Alle Prozesse in `--privileged` Containern besonders überwachen
- [ ] **Kubernetes Audit Log Integration**: K8s API-Server Audit-Events konsumieren
- [ ] **Cloud Metadata IMDS Monitoring**: Zugriffe auf `169.254.169.254` (AWS/GCP/Azure IMDS) loggen
- [ ] **CRI-O/containerd Runtime Events**: Container-Lifecycle-Events direkt aus der Runtime zapfen
- [ ] **Kubernetes RBAC Anomalien**: Unerwartete Service-Account-Berechtigungen erkennen
- [ ] **Helm/Operator Tampering**: Änderungen an Kubernetes-Ressourcen durch unbefugte Prozesse

---

## 10. Incident Response (RTR – Real Time Response)

**Ziel:** Remote-Forensik und Remediation direkt aus dem Backend.

- [ ] **Remote Shell / RTR-Channel**: Bidirektionaler WebSocket/gRPC-Kanal für Remote-Befehle vom Backend
- [ ] **Artifact Collection**: Prozess-Speicher-Dump, Log-Archive, Datei-Upload an Backend auf Anfrage
- [ ] **File Download/Upload API**: Beliebige Dateien vom Host abrufen oder deployen
- [ ] **Prozess-Terminierung via API**: Remote-`SIGKILL` auf beliebige PIDs
- [ ] **Netzwerk-Isolation Command**: Auf Backend-Befehl alle Verbindungen außer dem Management-Channel sperren
- [ ] **Custom Script Execution**: Signierte Remediation-Skripte sicher ausführen
- [ ] **Forensics Timeline Export**: Vollständige Event-History als JSONL-Export für IR-Workflows

---

## 11. Agent-Selbstschutz & Anti-Tampering

**Ziel:** Den Agenten selbst vor Manipulation durch Malware schützen.

- [ ] **Process Self-Protection**: Eigene PID via LSM/eBPF gegen SIGKILL/SIGTERM von Nicht-root schützen
- [ ] **Binary Integrity Check**: SHA256-Verifikation des eigenen Binaries beim Start
- [ ] **Config File Protection**: Agent-Konfiguration mit `chattr +i` schützen, Manipulation erkennen
- [ ] **Watchdog Process**: Zweiter Prozess überwacht den Agenten und startet ihn neu bei Absturz
- [ ] **mTLS für Backend-Kommunikation**: Mutual TLS mit Client-Zertifikat – keine unsignierte Kommunikation
- [ ] **Systemd Service Hardening**: `ProtectSystem=strict`, `PrivateTmp`, `NoNewPrivileges`, `CapabilityBoundingSet` setzen
- [ ] **Anti-Debugging**: Erkennen von ptrace-Attachment auf den eigenen Prozess

---

## 12. Vulnerability Assessment & Compliance

**Ziel:** Kontinuierliche Schwachstellenbewertung und Compliance-Reporting.

- [ ] **Installed Package Scanning**: RPM/DEB-Pakete gegen CVE-NVD-Datenbank prüfen
- [ ] **CIS Benchmark Checks**: Automatisierte CIS Linux Benchmark-Prüfungen (Level 1 & 2)
- [ ] **Misconfig Detection**: Unsichere Konfigurationen erkennen (z. B. `PermitRootLogin yes`, offene Ports, schwache Passwörter)
- [ ] **SBOM Generation**: Software Bill of Materials für den Host generieren
- [ ] **License Exposure Reporting**: Nicht-konforme Open-Source-Lizenzen erkennen
- [ ] **Compliance Reports**: Automatisierte Reports für SOC2, ISO 27001, PCI DSS, HIPAA

---

## 13. SIEM & Logging-Integration

**Ziel:** Events an bestehende Sicherheits-Infrastruktur weiterleiten.

- [ ] **Syslog/RFC5424 Output**: Strukturierte Events via `syslog` an SIEM-Systeme
- [ ] **Kafka Producer**: Events direkt in Kafka-Topics publizieren
- [ ] **Elasticsearch/OpenSearch Output**: Native Indexierung via Bulk-API
- [ ] **AWS S3 / GCS Output**: Batch-Export von Events in Cloud-Storage
- [ ] **OpenTelemetry (OTEL) Exporter**: Traces und Metrics im OTEL-Format exportieren
- [ ] **CEF/LEEF Format Support**: ArcSight/QRadar-kompatibles Event-Format
- [ ] **Splunk HEC Integration**: HTTP Event Collector für Splunk

---

## 14. Management & Multi-Tenancy

**Ziel:** Enterprise-taugliches Policy- und Gruppen-Management.

- [ ] **Policy Engine**: Konfigurierbare Erkennungsregeln und Response-Aktionen per Gruppe/Host
- [ ] **Group-based Configuration**: Hosts in Gruppen einteilen, unterschiedliche Policies anwenden
- [ ] **Alert Management**: Severity-Scoring, Deduplication, Suppression-Rules
- [ ] **Multi-Tenant API**: Mandantenfähigkeit für MSSPs und große Organisationen
- [ ] **RBAC für Agent-API**: Rollen-basierte Zugriffskontrolle auf Management-Endpunkte
- [ ] **Audit Trail**: Vollständiges Logging aller Backend-Aktionen (wer hat was wann geändert)

---

## Priorisierung (Empfehlung)

| Priorität | Kategorie | Begründung |
|-----------|-----------|------------|
| 🔴 P0 | Kernel-Sichtbarkeit (Syscall-Ausdehnung) | Fundament aller weiteren Features |
| 🔴 P0 | SHA256-FIM + Ransomware-Erkennung | Sofortiger Mehrwert, geringer Aufwand |
| 🔴 P0 | Agent-Selbstschutz + mTLS | Sicherheit des Agenten selbst |
| 🟠 P1 | Prävention (Process/Network Blocking) | EDR statt reines Monitoring |
| 🟠 P1 | Threat Intelligence IOC-Matching | Bekannte Bedrohungen sofort erkennen |
| 🟠 P1 | Credential & Privilege Escalation Detection | Häufigster Angriffsvektor |
| 🟡 P2 | C2/Beaconing Detection | Erweiterte Netzwerk-Analytik |
| 🟡 P2 | Container & Cloud Security | Moderne Infrastruktur |
| 🟡 P2 | RTR / Incident Response | Reaktionsfähigkeit |
| 🟢 P3 | ML-basierte Anomalie-Erkennung | Komplex, langfristig |
| 🟢 P3 | SIEM-Integration | Je nach Kundenbedarf |
| 🟢 P3 | Compliance & Vulnerability Assessment | Ergänzend |
