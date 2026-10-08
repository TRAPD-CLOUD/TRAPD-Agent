# Agent 0.6.10: Detection Quality

Stand: 7. Oktober 2026. Implementierung auf `feat/agent-detection-quality`,
Basis `f07bb1f6ff98f8f7493370027a3c7eeda38fead7`. Plattform-Basis
`77142da9874075cdcb0f7e304a6bca7046c26929`; dort vorhandene Änderungen wurden erhalten.
Die Version ist lokal vorbereitet; kein Tag, Upload oder produktives Update wurde ausgeführt.

## Resultierendes Verhalten

- Metadatenzugriffe und NTFS-Last-Access-Zeitstempel bleiben auswertbare Hinweise.
  Sie erhöhen weder den Alarmstatus eines Honeytokens noch die Zahl offener Alarme.
- Bestätigter Inhaltszugriff bleibt ein Alarm. Ein Scannername, SYSTEM oder ein
  gelerntes Programm allein reicht niemals zur Entwarnung. Eine geplante Prüfung
  benötigt zusätzlich verifizierte Identität und passenden Session-/Scheduler-Kontext.
- Schreiben, Löschen, Umbenennen, Ausführen und Hardlinks bleiben starke Befunde;
  widersprüchliche Signal-/Shadow-Vorgaben dürfen diese Bewertung nicht abschwächen.
- Agent-Eigenzugriffe werden geprüft statt bloß anhand eines Prozessnamens verworfen.
  Windows prüft zusätzlich Prozessgeneration und Originalzeit des 4663-Ereignisses.
- ETW besitzt pro Sitzung einen eigenen begrenzten Kanal, sichere Decodergrenzen
  und einen überwachten Neustart. Prozess-/Netzwerk-Poller übernehmen je nach
  tatsächlich verfügbarem Provider. Dienst und Windows-Konsolenbetrieb nutzen
  denselben Supervisor und Security-Eventlog-Collector.
- Linux löst Kernel-Feldpositionen aus dem laufenden BTF auf. Fest angenommene
  Offsets hatten auf dem geprüften Kernel echte Lesezugriffe übersehen.
  Dateisystem **und** Inode bilden nun die Identität. Kandidaten werden erst nach
  erfolgreichem Öffnen bzw. erfolgreicher Ausführung gemeldet; `O_PATH` ist Metadaten.
  Dateibasierte `mmap`-Evidenz benötigt einen erfolgreichen Syscall; anonyme
  Mappings mit ignoriertem FD werden ausgeschlossen. Pending-Maps, Drops und
  Sensor-Tasks haben begrenzte und überprüfte Lebenszyklen.
- Backend und UI behalten Quelle, Bewertung und begrenzte Grundcodes. Windows-
  Dateipfade werden unter authentifiziertem Projekt/Agent auf kanonische Token-IDs
  abgebildet; eine fremde Tenant-Zuordnung darf dabei nicht übernommen werden.

ETW für Prozess/Netzwerk ersetzt die Windows-Dateiauditierung nicht. Inhaltszugriffe
auf Windows-Decoys benötigen wirksame **Audit File System**-Success-Policy und SACL.
Fehlende oder teilweise Auditierung wird als eingeschränkte Coverage gemeldet.
Der Agent überschreibt keine vom Betreiber verwaltete Audit-Policy.

## Lokales Lernen

Die bestehende statistische Baseline wurde gehärtet, ohne externen ML-Dienst oder
neue Runtime-Abhängigkeit. Neue Programme brauchen mindestens drei geeignete
Beobachtungen über 24 Stunden; Neuheitsbewertung beginnt erst nach drei bestätigten
Programmen und 24 Stunden Historie. Auffällige Ereignisse, Sensorlücken, Zeitrücksprünge
und auffällige Exec-Raten trainieren keine normale Baseline. Neuheit allein bleibt Signal.

Windows-Aktivitätslernen ist ein signiertes Opt-in. Stunden, Dateinamensmuster und
interne Hostnamen verfallen nach 30 Tagen. Begrenzte Profile bleiben lokal; beim
Abschalten werden Speicher und Datei gelöscht, auch bei konkurrierendem Persist.
Qualifizierte Windows-Accounts verhindern die Vermischung gleichnamiger Domainnutzer.
Das Lernen unterstützt bestehende Honeytoken-Platzierung und Kontextbewertung;
es erzeugt keine automatisch vertrauenswürdigen Executables.

## Gemessene Prüfungen

Referenzumgebung: x86_64, vier QEMU-vCPUs unter KVM, Linux `6.8.0-142-generic`,
Rust `1.98.1`, Ubuntu-24.04-Testcontainer mit Host-PID-Namespace, ohne Netzwerk.
Windows wurde für `x86_64-pc-windows-gnu` mit MinGW gebaut; kein Windows-Runtime-Zugriff.

| Prüfung | Ergebnis |
|---|---|
| Agent vollständige Standard-Suite | 978 bestanden, 11 ausdrücklich ignorierte Tests, keine Fehler |
| Gemeinsame Honeytoken-Policy | 17 identische Agent-/Backend-Vektoren, 11 Alarm- und 6 Hinweisfälle |
| Synthetischer Honeytoken-Benign-Replay | 120 Beobachtungen, 0 Alarme; bestehende Budgets nicht erhöht |
| Synthetische Honeytoken-Angriffe | 11 erwartete Alarme, 0 als Hinweis versteckte Angriffe |
| Linux eBPF | Release-Build, echter Kernel-Verifier/Attach und beide nativen Szenarien bestanden |
| Native Linux mit BTF | Direkter/Hardlink/Symlink-Read, drei Alias-Execs einschließlich anderer Thread, Schreibflags, Rename, Metadaten und fehlgeschlagene Opens geprüft |
| Native Linux ohne BTF | Erfolgreiche absolute Reads, Schreibflags, Rename und Metadaten geprüft; reduzierte Coverage ausgewiesen |
| Agent Clippy | Linux und Windows, jeweils alle Targets mit `-D warnings`, bestanden |
| Agent Release-Builds | Linux und Windows GNU bestanden; MSI/MSVC/Signatur nicht lokal geprüft |
| Stream Processor | 98 Tests und Clippy bestanden |
| SQL-Migration | Isolierter DB-Smoke: Hinweise/Alarme, Tamper, Dedup, Tenant-Grenzen, Revoke und ungültiger Mode bestanden |
| Frontend | 84 Deception-Tests, TypeScript und ESLint für betroffene Dateien bestanden |
| Frontend Produktionsbuild | Next/Webpack bestanden, in separater Kopie mit inerten Testwerten |
| Formatprüfung | Neue Rust-Module formatiert; globale Prüfung scheitert an bestehenden Formatabweichungen im Repository |
| Native Windows | CI-Abnahmen ergänzt, hier nicht ausgeführt: echte 4663-Self-/PowerShell-Reads, SACL-Erhalt, ETW-Neustart und Scanner-Verzeichnisvertrauen |

Die native Linux-Abnahme prüft außerdem mehr als 4096 fehlgeschlagene Ausführungen
vor einem erfolgreichen Read, damit verwaiste Pending-Einträge den Sensor nicht
blockieren. Sie verlangt null Eigenzugriffs-Befunde und einen sauberen SIGTERM-Abschluss.
Die finale BTF-Abnahme erwartet sieben Inhaltszugriffe, drei erfolgreiche
Mappings, drei Ausführungen, drei Schreibzugriffe, zwei Hardlinks, einen Rename
und zwei Metadatenhinweise. Der Fallback erwartet zwei Inhaltszugriffe, drei
Schreibzugriffe, einen Rename und zwei Metadatenhinweise. Beide schließen
fehlgeschlagene und anonyme Mappings aus. Die Zählungen liefert das Testskript.

Diese Szenarien sind Funktionsprüfungen, keine Flottenmessung von Precision/Recall.
CPU/RAM, p50/p95/p99 Alarm-Latenz, reale Fehlalarmrate pro Host/Tag und Windows-
NTFS-/GPO-Verhalten müssen im Canary gemessen werden. Keine Aussage über Überlegenheit
gegenüber CrowdStrike oder die Güte eines trainierten ML-Modells wurde abgeleitet.
Die fünf ignorierten Journal-Lasttests wurden nicht zusätzlich als Benchmark ausgeführt.

## Reproduktion

```sh
cargo test --manifest-path agent/Cargo.toml
cargo clippy --manifest-path agent/Cargo.toml --all-targets -- -D warnings
cargo build --release --manifest-path agent/Cargo.toml
cargo xtask build-ebpf --release
bash agent/tests/native_linux_honeytokens.sh inode
bash agent/tests/native_linux_honeytokens.sh fallback
```

Die nativen Skripte benötigen Docker, einen eBPF-fähigen Linux-Host, C-Compiler und
Python 3. Sie erstellen nur temporäre Testdateien, deaktivieren aktive Prevention,
verwenden kein Netzwerk und entfernen ihre Container/Dateien anschließend.
BTF-Ausfall wird ausschließlich innerhalb des Testcontainers simuliert.

Windows-Abnahmen stehen in `.github/workflows/windows-package.yml`; die 4663-Prüfung
aktiviert File-System-Auditing nur auf dem CI-Testhost und stellt dessen zuvor
gesicherte Audit-Policy anschließend wieder her. Für den Betrieb bleibt diese Policy
beim Administrator/GPO. Lokale Cross-Builds sind kein Ersatz für diese Abnahme.

Plattformprüfungen: `cargo test -p trapd-stream-processor` und
`cargo clippy -p trapd-stream-processor --all-targets -- -D warnings` im Backend;
`npm run test:deception`, `npx tsc --noEmit --incremental false`, ESLint auf den
betroffenen Dateien und `npm run build -- --webpack` im Frontend.
Migration: `20261009130000_honeytoken_assessment.sql`; Smoke-Test:
`backend/supabase/tests/honeytoken_assessment_smoke.sql`. Der isolierte Prüf-DB wurde
anschließend entfernt; die laufende Plattform-DB wurde nicht migriert.

## Rollout und Rollback

1. Native Windows-CI einschließlich 4663, SACL und ETW bestehen lassen; ergänzend
   Explorer/Defender/Backup, verspätete NTFS-Zeitstempel und Lernen-Aus/Dateilöschung
   auf Testhosts prüfen. Betroffenen PC: aktuelle Version, Audit-Policy, SACL,
   Coverage und konkrete Trigger sichern. Dieser PC wurde hier nicht erreicht.
2. Additive SQL-Migration vor Backend/Frontend bereitstellen. Agent-Beobachtungen
   bleiben tenantgebunden; Hinweise dürfen den aktiven Tokenstatus nicht verändern.
3. Agent `0.6.10` mit passendem eBPF-Objekt gemeinsam paketieren und über bestehende
   signierte Updatewege auf Windows-/Linux-Canaries verteilen. Hash, Signatur,
   Release-Statement und tatsächlich gestartete Version verifizieren.
4. Windows: ETW-Sitzung plus Provider, File-System-Audit und Decoy-SACL-Coverage
   prüfen. Linux: Consumer/Arming, angehängte Programme und inode-BTF-Coverage prüfen.
   Alte/mismatched eBPF-Objekte dürfen keine vollständige Read-Coverage behaupten.
5. Mindestens 24 Stunden für Baseline-Warmup und anschließend repräsentative Tage
   messen. Pro Host: echte/synthetische Angriffe getrennt, Hinweise/Alarme, Verlust-
   und Neustartzähler, Latenz und Ressourcen. Einzelfälle anhand Quelle/Grundcodes
   nachvollziehen; keine Scanner pauschal freischalten, um die Alarmzahl zu senken.
6. Rücknahme: vorheriges signiertes Agent-Paket **mit seinem** eBPF-Objekt verwenden.
   Additive DB-Spalten beibehalten. Alte sofort gelernte Binary-Listen werden nicht
   als bestätigte Baseline übernommen; erneuten Warmup einplanen. Lernen kann über
   signierte Config ausgeschaltet werden, ohne starke Honeytoken-Alarme abzuschalten.

Letztes geprüft veröffentlichtes Release: `v0.6.9`, 6. Oktober 2026, 15:53 UTC.
Die Änderungen wirken auf einem PC erst nach einem verifizierten Agent-Update und
wirksamer Sensorkonfiguration. Veröffentlichung und Produktionsrollout sind ausstehend.

## PR-Prüfung 8. Oktober 2026

Plattformänderungen wurden ohne fremde Arbeitsbaumänderungen auf `dev`
(`5085e46`) übertragen. Bestehende Shadow-/Suppression-/Coverage-Funktionen
bleiben erhalten. Die neue Migration trägt Version `20261009130000`, damit
sie nach den inzwischen hinzugekommenen Migrationen ausgeführt wird.
Erneut geprüft: 978 Agent-Tests, 100 Stream-Processor-Tests und 99 Deception-
Tests bestanden; Windows-Runtime bleibt ein verpflichtender CI-Gate.
