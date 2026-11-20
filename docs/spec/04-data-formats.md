# 04 Data formats

All formats are JSON (UTF-8), described by JSON Schema (draft 2020-12) in [`schemas/`](../../schemas/). Every file carries `schema_version`. Configuration (profiles, suppressions, catalogue) is YAML and is validated against the same schemas when loaded.

All field names and enum values are English. Imports from skill v2.5, which uses German values, are mapped as described in 4.9.

## 4.1 Evidence store

A run lives in `runs/<run_id>/`. `run_id` = `<YYYYMMDD-HHMMSS>-<repo>-<sha7>`.

```
runs/<run_id>/
  manifest.json            # run manifest (4.2), sealed last
  inventory.json           # inventory (4.3)
  evidence/
    sha256/<hash>          # every raw output, log and record; append-only
  tools/<tool>.json        # run metadata per tool, refers to evidence/<hash>
  access-log/<agent>__<repo>.jsonl   # access log (4.5), written by the gateway
  findings.json            # all findings v3 (4.4)
  rejected.json            # invalid findings with reason
  checks.json              # check results (4.7)
  gate.json                # gate result (4.8)
  report.md                # human-readable report
```

Rules: files under `evidence/` are never modified. Corrections are new evidence that references the old one. The sealed manifest contains the hashes of all files of the run.

## 4.2 Run manifest

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
    "commit": "a1b2c3d4e5f6...(40 chars)",
    "tree": "9f8e7d...",
    "prepare_status": "ok",
    "prepare_warnings": []
  },
  "profile": {"id": "basic", "version": "1.0", "sha256": "..."},
  "mode": {"exec": false, "network": false, "sandbox": "bubblewrap", "cgroups": true},
  "toolchain": [
    {"tool": "semgrep", "version": "1.x.y", "ruleset": "audit-rules@2026-11-01", "ruleset_sha256": "..."},
    {"tool": "osv-scanner", "version": "2.x.y", "db_snapshot": "2026-11-19", "db_sha256": "..."}
  ],
  "ai": [
    {"stage": "reviewer", "agent": "app-security", "provider": "anthropic", "model": "<model-id>", "skill": "software-audit@2.5", "prompt_sha256": "..."}
  ],
  "catalogue": {"version": null},
  "artifacts": [{"path": "inventory.json", "sha256": "..."}],
  "sealed_sha256": "..."
}
```

## 4.3 Inventory

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

## 4.4 Finding v3

Schema: [`finding.schema.json`](../../schemas/finding.schema.json)

Finding v3 extends the skill v2.5 format. All v2.5 required fields remain with the same meaning; enum values are English (mapping in 4.9). New:

| Field | Meaning |
|---|---|
| `schema_version` | `"3.0"` |
| `run_id` | Run in which the finding was created |
| `origin` | `{"kind": "tool"\|"ai", "name": "semgrep"\|"app-security", "rule_id": "...", "model": "..."}` |
| `fingerprint` | Stable fingerprint (see [03, section 3.5](03-phase-1.md)) |
| `check_ids` | Affected checks, e.g. `["TECH-SAST-001"]` |
| `requirement_ids` | Affected catalogue requirements (from Phase 3), e.g. `["ASVS-5.0-V6.2.1"]` |
| `evidence_refs` | List of `{type, sha256, description}`: references to evidence in the evidence store |
| `access_check` | Result of the comparison with the access log: `read`, `touched_only`, `not_read`, `not_applicable` (tool finding) |
| `verification` | Object instead of enum, see below |
| `baseline_state` | `new`, `known` |
| `suppressed_by` | ID of the active suppression or `null` |
| `history` | List of all state changes `{at, by, from, to, reason, evidence_sha256}` |

`verification` (v3):

```json
{
  "result": "verified",
  "method": "V1-test",
  "independence": "method",
  "verifier": {"kind": "ai", "provider": "<vendor>", "model": "<model-id>"},
  "evidence_sha256": "...",
  "note": "Test tests/audit/test_sec_0042.py fails at commit a1b2c3d"
}
```

- `result`: `verified`, `refuted`, `not_verifiable`, `not_checked`
- `method`: `V1-test`, `V2-tool`, `V3-other-model`, `V4-same-model`, `V5-human`
- `independence`: `method` (V1, V2), `model` (V3), `none` (V4), `human` (V5)

Rules enforced by normalisation:
- No `file`/`lines` without an existing file in the inventory.
- `evidence_type: "code"` → the quote is checked against the file (as in v2.5).
- `evidence_type: "output"` → there must be an `evidence_refs` entry of type `tool-output` or `test-log` with an exit code.
- `origin.kind: "ai"` and `access_check` ≠ `read` → `status` at most `suspected`.
- `verification.result: "verified"` requires `evidence_sha256`.
- No finding is deleted. Refuted findings remain with `verification.result: "refuted"` and a justification.

## 4.5 Access log

Schema: [`access-log-entry.schema.json`](../../schemas/access-log-entry.schema.json). One JSON line per access, written by the file gateway (never by the agent).

```json
{"ts": "2026-11-20T10:22:03.114Z", "run_id": "...", "agent": "app-security", "repo": "levuvo-mail",
 "op": "read_file", "path": "src/auth/session.ts", "start": 1, "end": 128,
 "file_sha256": "...", "bytes_returned": 4312}
```

`op`: `list_dir`, `read_file`, `search`. For `search`, the fields `pattern` and `matches` (list of `{path, line}`) replace `start`/`end`.

Coverage per reviewer and repo is derived from it (part of `checks.json`):

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
  kind: false_positive
  reason: "Test key in tests/fixtures, never loaded in production"
  created_by: peter
  approved_by: null
  created_at: 2026-11-20
  valid_until: 2027-05-20
```

## 4.7 Check result

Schema: [`check-result.schema.json`](../../schemas/check-result.schema.json)

```json
{"check_id": "TECH-SCA-001", "state": "UNKNOWN",
 "reason": "osv-scanner rejected by sandbox: --allow-network not approved",
 "finding_ids": [], "evidence_refs": [], "decided_by": "gate@1.0"}
```

`state`: `PASS`, `FAIL`, `UNKNOWN`, `N/A`. `N/A` requires `na_decision` with `by`, `at`, `reason`.

## 4.8 Gate result

Schema: [`gate-result.schema.json`](../../schemas/gate-result.schema.json)

```json
{"run_id": "...", "profile": "basic@1.0", "result": "INCOMPLETE",
 "violations": [],
 "unknown_checks": ["TECH-SCA-001", "TECH-TEST-001"],
 "risk_acceptances": [],
 "human_release": null,
 "engine_version": "gate@1.0"}
```

## 4.9 Import mapping from skill v2.5

| Field | v2.5 value | v3 value |
|---|---|---|
| `status` | `bestätigt` / `plausibel` / `vermutet` | `confirmed` / `plausible` / `suspected` |
| `severity` | `kritisch` / `hoch` / `mittel` / `niedrig` | `critical` / `high` / `medium` / `low` |
| `verification` | `verifiziert` / `widerlegt` / `nicht prüfbar` / `nicht nachgeprüft` | `{"result": "verified" / "refuted" / "not_verifiable" / "not_checked", ...}` |

A v2.5 finding with `verification: "verifiziert"` becomes `{"result": "verified", "method": "V4-same-model", "independence": "none"}` on import, because the chief is the same model as the reviewers.
