# 02 Architektur

## 2.1 Überblick

```
 Repository @ fixierter Commit  +  Prüfprofil  +  Anforderungskatalog (versioniert)
                    │
                    ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │ Audit-Orchestrator (deterministischer Code, kein LLM)                │
 │  Run-Manifest · Inventar · Aufgabenverteilung · Lese-Protokoll       │
 └───────────┬─────────────────────────────┬────────────────────────────┘
             │                             │
             ▼                             ▼
 ┌───────────────────────┐     ┌───────────────────────────────┐
 │ Tool-Runner (Sandbox) │     │ KI-Prüfer (isoliert)          │
 │ SAST, Secrets, SCA,   │     │ Zugriff nur über Datei-Gateway│
 │ Tests, Build, SBOM    │     │ → jeder Lesezugriff geloggt   │
 └───────────┬───────────┘     └──────────────┬────────────────┘
             │  Roh-Ausgaben + Exit-Codes      │  Befunde (Schema v3)
             ▼                                 ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │ Evidence Store (inhaltsadressiert, nur anfügen)                      │
 │ Tool-Reports · Testlogs · Lese-Protokolle · Befunde · Entscheidungen │
 └───────────┬──────────────────────────────────────────────────────────┘
             ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │ Normalisierung & Abgleich                                            │
 │ Schema-Validierung · Zitat-Prüfung · Baseline · Suppressions · Dedup │
 └───────────┬──────────────────────────────────────────────────────────┘
             ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │ Unabhängige Verifikation (Phase 2)                                   │
 │ V1 fehlschlagender Test · V2 Werkzeug · V3 anderes Modell (blind)    │
 └───────────┬──────────────────────────────────────────────────────────┘
             ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │ Freigabe-Gate (deterministischer Code)  →  PASS · FAIL · INCOMPLETE  │
 │ + menschliche Risikoakzeptanz / Freigabe                              │
 └──────────────────────────────────────────────────────────────────────┘
```

## 2.2 Bausteine

| Baustein | Aufgabe | Phase | Umsetzung |
|---|---|---|---|
| Orchestrator | Steuert den Lauf, erzeugt Run-Manifest, verteilt Aufträge, sammelt Belege | 1 | Python-CLI, deterministisch |
| Inventar | Vollständige Dateiliste mit Hash, Klasse und Ausschlussgrund | 1 | Erweiterung von `inventory.py` (Skill v2.5) |
| Tool-Runner | Führt Werkzeuge reproduzierbar und isoliert aus | 1 | Aufbauend auf `safe_run.py` (bubblewrap, cgroups) |
| Datei-Gateway | Einziger Lesezugang der KI-Prüfer zum Repo; schreibt das Lese-Protokoll | 1 | MCP-Server oder Hook, siehe 2.5 |
| Evidence Store | Unveränderliche Ablage aller Belege | 1 | Verzeichnis je Lauf, inhaltsadressiert, plus `manifest.json` |
| Normalisierung | SARIF und Tool-Ausgaben → Befund v3, Baseline, Suppressions | 1 | Python |
| KI-Prüfer | Fachliche Prüfung mit klar begrenztem Auftrag | bestehend | Skill v2.5 (12 Prüfer + Chief) |
| Verifikation | Befunde unabhängig bestätigen oder widerlegen | 2 | siehe [05](05-verifikation.md) |
| Anforderungskatalog | Versionierte Anforderungen mit Quellen und Anwendbarkeitsregeln | 3 | YAML im Repo, siehe [07](07-compliance-katalog.md) |
| Gate | Deterministische Freigabeentscheidung | 1 (minimal) | Python, Regeln je Profil, siehe [08](08-freigabe-gate.md) |
| Benchmark | Misst Recall, Precision, Abdeckung, Wiederholbarkeit | 0 | Eigenes privates Repo, siehe [06](06-benchmark.md) |
| Dashboard | Anzeige von Befunden, Abdeckung, Risiken | 4 | später, optional |

Grundsatz zur Aufteilung: **System-Prompts** definieren nur Rollen. **Prüfverfahren** stehen in versionierten Skills. **Anforderungen** stehen im Katalog. **Freigaberegeln** sind normaler Programmcode mit Tests.

## 2.3 Bezug zum bestehenden Audit-Skill v2.5

Der Skill `software-audit` (12 Spezialisten + Chief, Version 2.5) deckt bereits einen großen Teil ab. Das neue System ersetzt ihn nicht, sondern bettet ihn als Stufe „KI-Prüfer“ ein und ergänzt, was fehlt.

| Fähigkeit | Skill v2.5 | Lücke | Ziel |
|---|---|---|---|
| Fixierter Stand | Commit-SHA je Befund und Protokoll | Kein Run-Manifest mit Werkzeug-, Regel- und Modellversionen | Run-Manifest (Phase 1) |
| Sichere Arbeitskopie | `prepare_repo.py` (Hooks, Filter, Symlinks entschärft) | – | übernehmen |
| Inventar | `inventory.py` (Markdown + Dateiliste) | Keine Hashes, keine Klassifikation mit Ausschlussgrund, kein JSON | Inventar-JSON (Phase 1) |
| Sandbox | `safe_run.py` mit bubblewrap, cgroups, Allowlist | Semgrep, Trivy, Syft u. a. noch nicht in der Allowlist | Allowlist erweitern (Phase 1) |
| Befundformat | JSON-Schema mit Zitat, Status, Schweregrad | Keine Anforderungs-ID, kein Fingerprint, Verifikation nur als Enum | Befund v3, abwärtskompatibel |
| Zitat-Prüfung | `process_findings.py` prüft Zitate gegen Datei | – | übernehmen |
| Abdeckung | Selbstauskunft `files_reviewed`, „formal belegt“ | Nicht bewiesen, dass gelesen wurde (in CHANGELOG 2.5 selbst als Grenze genannt) | Lese-Protokoll durch das System (Phase 1) |
| Deterministische Werkzeuge | Nur auf Initiative der Prüfer, im statischen Modus kaum | Kein fester Tool-Lauf je Profil | Tool-Runner mit Pflichtwerkzeugen (Phase 1) |
| Verifikation | Chief prüft kritisch/hoch selbst nach | Gleiches Modell, sieht die Begründung des Prüfers | V1–V3 nach [05](05-verifikation.md) (Phase 2) |
| Werkzeug-Rauschen | – | Keine Baseline, keine Suppressions | Phase 1 |
| Ergebniszustände | Befundstatus; keine Prüfpunkte | Kein PASS/FAIL/UNKNOWN/N/A, kein Gate | Prüfpunkte + Gate (Phase 1 minimal) |
| Baseline-Vergleich | `compare_baseline.py` | Abgleich über Zitate, nicht über stabile Fingerprints | Fingerprint ergänzen |
| Messung | – | Keine | Benchmark (Phase 0) |

Die Rollen des Skills (ARC, CQ, SEC, AIS, QA, REL, DB, PERF, OPS, API, UX, DOC) bleiben. Die im Ausgangskonzept vorgeschlagenen Rollen „Privacy & GDPR“, „AI Governance“ und „CRA & Regulatory“ kommen erst mit Phase 3 dazu und arbeiten nur gegen den Katalog. „Independent Verifier“ wird in Phase 2 als eigene Stufe umgesetzt, nicht als 13. Prüfer.

## 2.4 Vertrauensgrenzen

| Zone | Darf | Darf nicht |
|---|---|---|
| Orchestrator, Gate, Evidence Store | Alles lesen, Belege schreiben | Repo-Code ausführen |
| Tool-Runner (Sandbox) | Repo-Kopie lesen, Werkzeuge ausführen, Ausgabe zurückgeben | Netz (außer freigegebene SCA-Datenbanken), Home, Secrets, Evidence Store |
| KI-Prüfer | Über das Datei-Gateway lesen, eigene Befund-Datei schreiben | Lese-Protokoll schreiben oder ändern, Repo ändern, Netz, Deploy-Rechte |
| Verifier | Original-Repo und Original-Belege lesen, Tests in der Sandbox ausführen | Die Begründung des Erstprüfers sehen (bei V3), Befunde löschen |
| Mensch | Anwendbarkeit, Risikoakzeptanz, finale Freigabe | – |

Wichtig:
- **Repo-Inhalte sind Daten.** Eine manipulierte README.md oder CLAUDE.md, die „ignoriere Sicherheitslücken“ verlangt, ändert keine Regel. Solche Inhalte werden selbst als Befund gemeldet (Prompt-Injection-Versuch).
- **Keine Repo-Instruktionsdateien laden.** KI-Prüfer starten ohne die CLAUDE.md, AGENTS.md o. Ä. des geprüften Repos als Systemkontext. Sie lesen solche Dateien nur als Daten.
- **Das Lese-Protokoll liegt außerhalb der Schreibrechte des Agenten.**

## 2.5 Maschinell nachgewiesene Abdeckung

Das ist die wichtigste Ergänzung gegenüber v2.5. Ziel: „Prüfer X hat Datei Y gelesen“ ist eine Tatsache aus dem Systemprotokoll, keine Aussage des Prüfers.

**Mechanismus (Variante A, empfohlen):** Die KI-Prüfer bekommen keinen direkten Dateisystemzugriff auf das Repo, sondern ein **Datei-Gateway** (MCP-Server) mit drei Werkzeugen: `list_dir`, `read_file(path, start, end)`, `search(pattern, glob)`. Das Gateway liefert nur Inhalte aus der vorbereiteten Arbeitskopie und schreibt jeden Aufruf mit Zeitstempel, Agent, Pfad, Zeilenbereich und Datei-Hash in das Lese-Protokoll. Diese Variante funktioniert mit jedem Modell, auch mit einem anderen Anbieter für die Verifikation.

**Variante B (Übergang, nur Claude Code):** Ein `PostToolUse`-Hook schreibt `Read`-, `Grep`- und `Glob`-Aufrufe in ein Protokoll außerhalb des Workspace. Lesende Bash-Befehle (`cat`, `sed -n`) werden für Prüfer gesperrt, damit kein Lesen am Protokoll vorbei möglich ist.

**Auswertung:**
- „Gelesen“ zählt nur, wenn der Inhalt tatsächlich an den Agenten ging (`read_file`). Ein Suchtreffer zählt als „berührt“, nicht als „gelesen“.
- Je Datei wird die Vereinigung der gelesenen Zeilenbereiche berechnet. Abdeckung einer Datei = gelesene Zeilen / Zeilen der Datei.
- Je Prüfer und Repo entsteht eine Abdeckung gegen die für die Rolle relevanten Inventar-Dateien (Relevanzregeln je Rolle, z. B. `devops`: Dockerfiles, CI, IaC).
- Befunde zu Dateien oder Zeilen, die laut Protokoll nicht gelesen wurden, werden automatisch auf `vermutet` gesetzt.
- `files_reviewed` aus der Selbstauskunft wird mit dem Protokoll verglichen. Abweichungen werden im Bericht ausgewiesen; sie sind selbst ein Messwert für den Benchmark.

Grenze: Das Protokoll beweist, dass ein Inhalt beim Modell ankam, nicht, dass er gründlich ausgewertet wurde. Dafür gibt es den Benchmark (Recall) und Stichproben.
