# 08 Release gate

## 8.1 Principle

The gate is ordinary, tested program code. It reads `checks.json`, `findings.json`, the active suppressions and the profile, and outputs `PASS`, `FAIL` or `INCOMPLETE`. There is no LLM vote and no discretion. The same inputs always produce the same result.

A gate `PASS` is **not** a release. The final release is made by a named person and recorded in `gate.json` under `human_release`. A person can reject a `PASS`, but can overcome a `FAIL` or `INCOMPLETE` only through documented risk acceptances (suppressions of kind `risk_accepted`) and a new gate run.

## 8.2 Evaluation order

1. Collect all mandatory checks of the profile. Missing result → `UNKNOWN`.
2. Evaluate gate rules. Every violated rule → entry in `violations`.
3. `violations` not empty → `FAIL`.
4. Otherwise: any mandatory check `UNKNOWN` → `INCOMPLETE`.
5. Otherwise → `PASS`.

## 8.3 Profiles

Profiles are versioned YAML files. A profile defines: mandatory checks, mandatory tools, coverage thresholds, minimum verification level and gate rules.

### `basic` (Phase 1)

For internal development states. Goal: an honest overview with few hurdles.

| Rule | Condition |
|---|---|
| Mandatory checks | TECH-INV-001, TECH-SECRETS-001, TECH-SAST-001, TECH-SCA-001, TECH-SBOM-001 |
| Critical findings | 0 active, unsuppressed `critical` findings with status `confirmed` |
| Secrets | 0 active findings from TECH-SECRETS-001 |
| AI coverage (if run) | Line coverage ≥ 50 % per reviewer; otherwise TECH-AI-COV-001 is `UNKNOWN` (not mandatory) |
| Verification | no minimum level |

### `production-release` (from Phase 2)

For production releases. Deliberately conservative.

| Criterion | Release condition |
|---|---|
| Mandatory checks | 100 % `PASS` or justified `N/A` |
| Build and mandatory tests | TECH-BUILD-001 and TECH-TEST-001 `PASS` (execution therefore mandatory) |
| Critical security findings | 0 open |
| High security findings | 0 unresolved (each fixed, refuted, or accepted as a risk with approval by a second person) |
| Functional blockers | 0 open |
| Independent verification | For all `critical` and `high` findings: `verification.result` ≠ `not_checked`, independence `method`, `model` or `human` (V4 is not enough) |
| AI coverage | Line coverage ≥ 80 % of the relevant files per mandatory role |
| Applicable binding requirements | Evidence present, no unresolved non-compliance; applicability decisions not older than 12 months |
| Traceability | Every finding and check result is linked to commit, requirement and evidence; manifest sealed and `audit verify` successful |
| Benchmark | The skill/model version used has a benchmark run meeting the targets in [06](06-benchmark.md), not older than 90 days |
| External assessment | For legally or security-critical products according to the risk profile: evidence present |

### Product-specific audit profiles

The framework stays the same; profiles differ in checks, tools and thresholds.

| Profile | Additional focus |
|---|---|
| `levuvo-mail` | Mail protocols, synchronisation and data integrity, privacy, desktop platforms, agent interfaces |
| `levuvo-factory` | Agent permissions, container isolation, supply chain, tool execution, secret handling, orchestration |
| `ai-features` (add-on) | AI risk classification, prompt injection and abuse tests, evaluation data, AI Act evidence if applicable |

## 8.4 Rules enforced by the gate regardless of profile

1. A mandatory check without evidence is never `PASS`.
2. A skipped mandatory step leads at least to `INCOMPLETE`.
3. A finding with a `history` entry that downgrades a confirmed finding without evidence is a rule violation (`FAIL`).
4. Expired suppressions do not count.
5. A risk acceptance for a critical finding requires two different people (`created_by` ≠ `approved_by`).
6. Before evaluation the gate checks the hashes in the manifest. If any evidence does not match → `FAIL` with rule `integrity`.

## 8.5 Gate tests

The gate has its own test suite with cases for every rule, in particular:
- empty finding list with a missing tool → `INCOMPLETE`, not `PASS`
- critical finding with an expired suppression → `FAIL`
- `N/A` without a decision → schema error, run aborted
- tampered evidence → `FAIL` (`integrity`)
