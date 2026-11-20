# 09 Roadmap und offene Entscheidungen

## 9.1 Phasen

| Phase | Inhalt | Ergebnis | Grobe Dauer |
|---|---|---|---|
| **0 Benchmark** | Benchmark-Repo mit 20 Fehlern, 4 Ködern, 1 Manipulationsversuch; `score.py`; Experimente E1–E3 | Recall, Precision, Abdeckung und Wiederholbarkeit des Skills v2.5 als Zahlen | 1–2 Wochen |
| **1 Technisches Audit** | Run-Manifest, Inventar-JSON, Tool-Runner, Evidence Store, Befund v3, Baseline/Suppressions, Datei-Gateway mit Lese-Protokoll, Prüfpunkte, Gate `basis` | Reproduzierbarer Lauf mit ehrlicher Abdeckung | 3–5 Wochen |
| **2 Verifikation** | V1 (fehlschlagende Tests), V2, V3 mit anderem Modell, Gegensuche; Profil `release-produktiv`; Experimente E4–E6 | Gemessene Wirkung der Verifikation | 3–4 Wochen |
| **3 Compliance-as-Code** | Katalog (DSGVO-Teil, ASVS-Auswahl, ggf. CRA), Anwendbarkeitsentscheidungen, drei Compliance-Rollen | Kontrollmatrix mit Belegen und Lücken | nach Bedarf |
| **4 Kontinuierlich** | Schnellprüfung je PR (Diff-basiert), Vollaudit vor Release, periodische Neuprüfung, CVE-Überwachung, Integration in die Levuvo Software Factory, optional Dashboard | Laufender Betrieb | fortlaufend |

**Reihenfolge-Empfehlung:** Phase 0 vor Phase 1. Die Messung zeigt, wo die echten Lücken liegen (z. B. ob v2.5 vor allem bei Abdeckung, bei bestimmten Rollen oder bei Precision schwächelt), und Phase 1 kann danach gezielt priorisiert werden. Der Bau des Benchmark-Repos ist zudem unabhängig von allem anderen.

Die Dauerangaben sind Schätzungen ohne Messgrundlage.

## 9.2 Arbeitspakete Phase 0

1. Benchmark-Repo `audit-benchmark-postfach` anlegen (privat), Grundanwendung schreiben, Tests grün.
2. Fehler B01–B20, Köder D1–D4 und Manipulation I1 einbauen; Ground Truth in diesem Repo unter `benchmark/ground-truth/v1.yaml`.
3. Sicherstellen, dass das Benchmark-Repo keinen Hinweis auf die Fehler enthält (Review durch eine zweite Instanz, die die Ground Truth nicht kennt, nur nach verräterischen Kommentaren/Namen sucht).
4. `benchmark/score.py`: liest Ground Truth + `findings_consolidated.json` (v2.5) bzw. `findings.json` (v3), erzeugt `metrics.json` und eine Triage-Vorlage.
5. Experimente E1, E2, E3 je dreimal; Triage; Ergebnisbericht.

## 9.3 Arbeitspakete Phase 1

1. Run-Manifest und Evidence Store (inkl. `audit verify`)
2. Inventar-JSON (Erweiterung von `inventory.py`)
3. Sandbox-Allowlist erweitern (Semgrep, Trivy, Syft, Hadolint, OSV-Scanner offline)
4. Tool-Runner mit Profil `basis`, Normalisierung SARIF → Befund v3
5. Fingerprint, Baseline, Suppressions
6. Datei-Gateway (MCP) mit Lese-Protokoll; Anbindung des Skills v2.5
7. Prüfpunkte und Gate `basis`
8. Akzeptanztests aus [03, Abschnitt 3.7](03-phase-1.md)

## 9.4 Offene Entscheidungen

| Nr. | Frage | Vorschlag | Entscheidet |
|---|---|---|---|
| E-1 | Wo liegt der Code des Systems: in diesem Repo oder als Erweiterung des Skills? | Orchestrator, Gate und Schemas in diesem Repo; der Skill bleibt eigenständig und wird angebunden | Peter |
| E-2 | Datei-Gateway als MCP-Server (modellunabhängig) oder Hook (nur Claude Code)? | MCP-Server; Hook nur als Übergang | Peter |
| E-3 | Welches zweite Modell für V3? | Ein Modell eines anderen Anbieters per API; falls nicht gewünscht, bleibt V3 leer und `release-produktiv` verlangt V1/V2/V5 | Peter |
| E-4 | Wo laufen Audits: Cloud-Sandbox, lokale Factory, GitHub Actions? | Phase 0/1 lokal bzw. Cloud; ab Phase 4 in der Levuvo Software Factory mit eigener, getrennter Rolle | Peter |
| E-5 | SCA mit Netz oder mit gespiegelter Datenbank? | Gespiegelte Datenbank mit Stand im Manifest (reproduzierbar) | Peter |
| E-6 | Sprache der Schemas und Feldnamen | Feldnamen englisch wie im Skill, Werte deutsch wie im Skill (Kompatibilität) | Peter |
| E-7 | Wer prüft die Fristen in [07, Abschnitt 7.6](07-compliance-katalog.md) gegen die Primärquellen? | Vor Phase 3; bis dahin nicht im Katalog | Peter / Jurist |

## 9.5 Risiken des Vorhabens

- **Umfang wächst schneller als Nutzen.** Gegenmaßnahme: Phase 0 und 1 strikt schlank halten; jede Erweiterung muss sich im Benchmark zeigen.
- **Benchmark wird auswendig gelernt.** Gegenmaßnahme: privat halten, Varianten, echte übersehene Fehler nachbauen.
- **Rauschen der Werkzeuge erstickt die Triage.** Gegenmaßnahme: Baseline, Suppressions mit Ablaufdatum, Regeln mit hoher FP-Rate abschalten statt Einzelfälle unterdrücken.
- **Scheinsicherheit durch „PASS“.** Gegenmaßnahme: `UNKNOWN` als Standard, `INCOMPLETE` sichtbar im Bericht, menschliche Freigabe getrennt vom Gate.
