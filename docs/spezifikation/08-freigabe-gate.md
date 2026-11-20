# 08 Freigabe-Gate

## 8.1 Grundsatz

Das Gate ist normaler, getesteter Programmcode. Es liest `checks.json`, `findings.json`, die wirksamen Suppressions und das Profil und gibt `PASS`, `FAIL` oder `INCOMPLETE` aus. Es gibt keine LLM-Abstimmung und keinen Ermessensspielraum. Gleiche Eingaben ergeben immer dasselbe Ergebnis.

Ein `PASS` des Gates ist **keine** Freigabe. Die finale Freigabe trifft ein namentlich genannter Mensch und wird in `gate.json` unter `human_release` festgehalten. Ein Mensch kann ein `PASS` ablehnen, aber ein `FAIL` oder `INCOMPLETE` nur über dokumentierte Risikoakzeptanzen (Suppressions der Art `risiko_akzeptiert`) und einen neuen Gate-Lauf überwinden.

## 8.2 Auswertungsreihenfolge

1. Alle Pflicht-Prüfpunkte des Profils einsammeln. Fehlt ein Ergebnis → `UNKNOWN`.
2. Gate-Regeln prüfen. Jede verletzte Regel → Eintrag in `violations`.
3. `violations` nicht leer → `FAIL`.
4. Sonst: ein Pflicht-Prüfpunkt `UNKNOWN` → `INCOMPLETE`.
5. Sonst → `PASS`.

## 8.3 Profile

Profile sind versionierte YAML-Dateien. Ein Profil legt fest: Pflicht-Prüfpunkte, Pflichtwerkzeuge, Abdeckungsschwellen, Mindest-Verifikationsstufe und Gate-Regeln.

### `basis` (Phase 1)

Für interne Entwicklungsstände. Ziel: ehrlicher Überblick, wenig Hürden.

| Regel | Bedingung |
|---|---|
| Pflicht-Prüfpunkte | TECH-INV-001, TECH-SECRETS-001, TECH-SAST-001, TECH-SCA-001, TECH-SBOM-001 |
| Kritische Befunde | 0 aktive, nicht unterdrückte Befunde `kritisch` mit Status `bestätigt` |
| Secrets | 0 aktive Befunde aus TECH-SECRETS-001 |
| Abdeckung KI (falls gelaufen) | Zeilenabdeckung ≥ 50 % je Prüfer; sonst TECH-AI-COV-001 `UNKNOWN` (kein Pflichtpunkt) |
| Verifikation | keine Mindeststufe |

### `release-produktiv` (ab Phase 2)

Für produktive Releases. Bewusst konservativ.

| Kriterium | Freigabebedingung |
|---|---|
| Pflicht-Prüfpunkte | 100 % `PASS` oder begründet `N/A` |
| Build und verpflichtende Tests | TECH-BUILD-001 und TECH-TEST-001 `PASS` (Ausführung damit Pflicht) |
| Kritische Sicherheitsbefunde | 0 offen |
| Hohe Sicherheitsbefunde | 0 ungeklärt (jeder ist behoben, widerlegt oder als Risiko akzeptiert mit Freigabe durch zweite Person) |
| Funktionale Blocker | 0 offen |
| Unabhängige Verifikation | Für alle Befunde `kritisch` und `hoch`: `verification.result` ≠ `nicht nachgeprüft`, Unabhängigkeit `methode`, `modell` oder `mensch` (V4 reicht nicht) |
| Abdeckung KI | Je Pflicht-Rolle Zeilenabdeckung ≥ 80 % der relevanten Dateien |
| Anwendbare verbindliche Anforderungen | Belege vorhanden, keine ungeklärte Nichterfüllung; Anwendbarkeitsentscheidungen nicht älter als 12 Monate |
| Traceability | Jeder Befund und jedes Prüfpunkt-Ergebnis ist Commit, Anforderung und Beleg zugeordnet; Manifest versiegelt und `audit verify` erfolgreich |
| Benchmark | Der verwendete Skill-/Modellstand hat einen Benchmark-Lauf, der die Zielwerte aus [06](06-benchmark.md) erfüllt, nicht älter als 90 Tage |
| Externe Prüfung | Bei rechtlich oder sicherheitstechnisch kritischen Produkten laut Risikoprofil: Nachweis vorhanden |

### Produktspezifische Prüfprofile

Das Framework bleibt gleich; Profile unterscheiden sich in Prüfpunkten, Werkzeugen und Schwellen.

| Profil | Zusätzliche Schwerpunkte |
|---|---|
| `levuvo-mail` | E-Mail-Protokolle, Synchronisation und Datenintegrität, Datenschutz, Desktop-Plattformen, Agentenschnittstellen |
| `levuvo-factory` | Agentenberechtigungen, Containerisolation, Supply Chain, Tool-Ausführung, Secret-Handling, Orchestrierung |
| `ki-funktionen` (Zusatz) | KI-Risikoklassifikation, Prompt-Injection- und Missbrauchstests, Evaluationsdaten, ggf. AI-Act-Belege |

## 8.4 Regeln, die das Gate unabhängig vom Profil durchsetzt

1. Ein Pflicht-Prüfpunkt ohne Beleg ist nie `PASS`.
2. Ein übersprungener Pflichtschritt führt mindestens zu `INCOMPLETE`.
3. Ein Befund mit `history`-Eintrag, der einen bestätigten Befund ohne Beleg herabstuft, ist eine Regelverletzung (`FAIL`).
4. Abgelaufene Suppressions zählen nicht.
5. Eine Risikoakzeptanz für einen kritischen Befund braucht zwei verschiedene Personen (`erstellt_von` ≠ `freigegeben_von`).
6. Das Gate prüft vor der Auswertung die Hashes im Manifest. Stimmt ein Beleg nicht → `FAIL` mit Regel `integrity`.

## 8.5 Tests des Gates

Das Gate hat eine eigene Testsuite mit Fällen für jede Regel, insbesondere:
- leere Befundliste bei fehlendem Werkzeug → `INCOMPLETE`, nicht `PASS`
- kritischer Befund mit abgelaufener Suppression → `FAIL`
- `N/A` ohne Entscheidung → Schemafehler, Lauf abgebrochen
- manipulierter Beleg → `FAIL` (`integrity`)
