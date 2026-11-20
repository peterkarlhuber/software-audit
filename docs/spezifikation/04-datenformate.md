# 04 Datenformate

Alle Formate sind JSON (UTF-8), mit JSON Schema (Draft 2020-12) unter [`schemas/`](../../schemas/) beschrieben. Jede Datei trägt `schema_version`. Konfiguration (Profile, Suppressions, Katalog) ist YAML und wird beim Laden gegen dasselbe Schema validiert.

## 4.1 Evidence Store

Ein Lauf liegt in `runs/<run_id>/`. `run_id` = `<JJJJMMTT-HHMMSS>-<repo>-<sha7>`.

```
runs/<run_id>/
  manifest.json            # Run-Manifest (4.2), zuletzt versiegelt
  inventory.json           # Inventar (4.3)
  evidence/
    sha256/<hash>          # jede Roh-Ausgabe, jedes Log, jedes Protokoll, nur anfügen
  tools/<tool>.json        # Laufmetadaten je Werkzeug, verweist auf evidence/<hash>
  access-log/<agent>__<repo>.jsonl   # Lese-Protokoll (4.5), vom Gateway geschrieben
  findings.json            # alle Befunde v3 (4.4)
  rejected.json            # ungültige Befunde mit Grund
  checks.json              # Prüfpunkt-Ergebnisse (4.7)
  gate.json                # Gate-Ergebnis (4.8)
  report.md                # menschenlesbarer Bericht
```

Regeln: Dateien unter `evidence/` werden nie geändert. Korrekturen entstehen als neue Belege mit Verweis auf den alten. Das versiegelte Manifest enthält die Hashes aller Dateien des Laufs.

## 4.2 Run-Manifest

Schema: [`run-manifest.schema.json`](../../schemas/run-manifest.schema.json)

```json
{
  "schema_version": "1.0",
  "run_id": "20261120-101500-levuvo-mail-a1b2c3d",
  "started_at": "2026-11-20T10:15:00Z",
  "finished_at": "2026-11-20T10:41:12Z",
  "target": {
    "repo": "levuvo-mail",
    "source": "https://github.com/<owner>/levuvo-mail",
    "commit": "a1b2c3d4e5f6...(40 Zeichen)",
    "tree": "9f8e7d...",
    "prepare_status": "ok",
    "prepare_warnings": []
  },
  "profile": {"id": "basis", "version": "1.0", "sha256": "..."},
  "mode": {"exec": false, "network": false, "sandbox": "bubblewrap", "cgroups": true},
  "toolchain": [
    {"tool": "semgrep", "version": "1.x.y", "ruleset": "audit-rules@2026-11-01", "ruleset_sha256": "..."},
    {"tool": "osv-scanner", "version": "2.x.y", "db_snapshot": "2026-11-19", "db_sha256": "..."}
  ],
  "ai": [
    {"stage": "reviewer", "agent": "app-security", "provider": "anthropic", "model": "<modell-id>", "skill": "software-audit@2.5", "prompt_sha256": "..."}
  ],
  "catalog": {"version": null},
  "artifacts": [{"path": "inventory.json", "sha256": "..."}],
  "sealed_sha256": "..."
}
```

## 4.3 Inventar

Schema: [`inventory.schema.json`](../../schemas/inventory.schema.json)

```json
{
  "schema_version": "1.0",
  "repo": "levuvo-mail",
  "commit": "a1b2c3d...",
  "files": [
    {"path": "src/auth/session.ts", "sha256": "...", "bytes": 4312, "lines": 128,
     "class": "source", "language": "typescript", "in_scope": true},
    {"path": "vendor/lib.min.js", "sha256": "...", "bytes": 90211, "lines": 3,
     "class": "vendored", "language": "javascript", "in_scope": false, "exclude_reason": "vendored"}
  ],
  "dependency_manifests": ["package.json", "package-lock.json"],
  "entry_points": ["src/main.ts"],
  "test_suites": [{"framework": "vitest", "paths": ["tests/"]}],
  "submodules": []
}
```

## 4.4 Befund v3

Schema: [`finding.schema.json`](../../schemas/finding.schema.json)

Befund v3 ist eine **abwärtskompatible Erweiterung** des Skill-v2.5-Formats. Alle v2.5-Pflichtfelder bleiben, mit gleicher Bedeutung und gleichen deutschen Werten. Neu:

| Feld | Bedeutung |
|---|---|
| `schema_version` | `"3.0"` |
| `run_id` | Lauf, in dem der Befund entstand |
| `origin` | `{"kind": "tool"\|"ai", "name": "semgrep"\|"app-security", "rule_id": "...", "model": "..."}` |
| `fingerprint` | Stabiler Fingerprint (siehe [03, Abschnitt 3.5](03-phase-1.md)) |
| `check_ids` | Betroffene Prüfpunkte, z. B. `["TECH-SAST-001"]` |
| `requirement_ids` | Betroffene Katalog-Anforderungen (ab Phase 3), z. B. `["ASVS-5.0-V6.2.1"]` |
| `evidence_refs` | Liste `{type, sha256, description}`: Verweise auf Belege im Evidence Store |
| `access_check` | Ergebnis des Abgleichs mit dem Lese-Protokoll: `gelesen`, `nur_berührt`, `nicht_gelesen`, `nicht_anwendbar` (Werkzeugbefund) |
| `verification` | Objekt statt Enum, siehe unten |
| `baseline_state` | `neu`, `bekannt` |
| `suppressed_by` | ID der wirksamen Suppression oder `null` |
| `history` | Liste aller Zustandsänderungen `{at, by, from, to, reason, evidence_sha256}` |

`verification` (v3):

```json
{
  "result": "verifiziert",            
  "method": "V1-test",                
  "independence": "methode",          
  "verifier": {"kind": "ai", "provider": "openai", "model": "<modell-id>"},
  "evidence_sha256": "...",
  "note": "Test tests/audit/test_sec_0042.py schlägt am Commit a1b2c3d fehl"
}
```

- `result`: `verifiziert`, `widerlegt`, `nicht prüfbar`, `nicht nachgeprüft` (wie v2.5)
- `method`: `V1-test`, `V2-werkzeug`, `V3-anderes-modell`, `V4-gleiches-modell`, `V5-mensch`
- `independence`: `methode` (V1, V2), `modell` (V3), `keine` (V4), `mensch` (V5)

Abwärtskompatibilität: Ein v2.5-Befund mit `verification: "verifiziert"` wird beim Import zu `{"result": "verifiziert", "method": "V4-gleiches-modell", "independence": "keine"}`, weil der Chief dasselbe Modell ist.

Regeln, die die Normalisierung maschinell durchsetzt:
- Kein `file`/`lines` ohne existierende Datei im Inventar.
- `evidence_type: "code"` → Zitat wird gegen die Datei geprüft (wie v2.5).
- `evidence_type: "output"` → es muss ein `evidence_refs`-Eintrag vom Typ `tool-output` oder `test-log` mit Exit-Code existieren.
- `origin.kind: "ai"` und `access_check` ≠ `gelesen` → `status` höchstens `vermutet`.
- `verification.result: "verifiziert"` braucht `evidence_sha256`.
- Kein Befund wird gelöscht. Widerlegte Befunde bleiben mit `verification.result: "widerlegt"` und Begründung erhalten.

## 4.5 Lese-Protokoll

Schema: [`access-log-entry.schema.json`](../../schemas/access-log-entry.schema.json). Eine JSON-Zeile pro Zugriff, geschrieben vom Datei-Gateway (nie vom Agenten).

```json
{"ts": "2026-11-20T10:22:03.114Z", "run_id": "...", "agent": "app-security", "repo": "levuvo-mail",
 "op": "read_file", "path": "src/auth/session.ts", "start": 1, "end": 128,
 "file_sha256": "...", "bytes_returned": 4312}
```

`op`: `list_dir`, `read_file`, `search`. Bei `search` statt `start`/`end` die Felder `pattern` und `matches` (Liste `{path, line}`).

Abgeleitet wird je Prüfer und Repo die Abdeckung (Teil von `checks.json`):

```json
{"agent": "app-security", "repo": "levuvo-mail",
 "relevant_files": 84, "files_read_fully": 51, "files_read_partially": 12, "files_touched_only": 9,
 "line_coverage": 0.71, "self_reported_not_in_log": ["src/db/migrate.ts"], "threshold": 0.6, "meets_threshold": true}
```

## 4.6 Suppression

Schema: [`suppression.schema.json`](../../schemas/suppression.schema.json)

```yaml
- id: SUP-0007
  match: {fingerprint: "3f9a..."}
  art: false_positive
  begruendung: "Testschlüssel in tests/fixtures, wird nie produktiv geladen"
  erstellt_von: peter
  freigegeben_von: null
  erstellt_am: 2026-11-20
  gueltig_bis: 2027-05-20
```

## 4.7 Prüfpunkt-Ergebnis

Schema: [`check-result.schema.json`](../../schemas/check-result.schema.json)

```json
{"check_id": "TECH-SCA-001", "state": "UNKNOWN",
 "reason": "osv-scanner von der Sandbox abgelehnt: --allow-network nicht freigegeben",
 "finding_ids": [], "evidence_refs": [], "decided_by": "gate@1.0"}
```

`state`: `PASS`, `FAIL`, `UNKNOWN`, `N/A`. `N/A` braucht `na_decision` mit `by`, `at`, `reason`.

## 4.8 Gate-Ergebnis

Schema: [`gate-result.schema.json`](../../schemas/gate-result.schema.json)

```json
{"run_id": "...", "profile": "basis@1.0", "result": "INCOMPLETE",
 "violations": [],
 "unknown_checks": ["TECH-SCA-001", "TECH-TEST-001"],
 "risk_acceptances": [],
 "human_release": null,
 "engine_version": "gate@1.0"}
```
