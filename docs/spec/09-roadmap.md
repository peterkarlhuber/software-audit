# 09 Roadmap and open decisions

## 9.1 Phases

| Phase | Content | Result | Rough duration |
|---|---|---|---|
| **0 Benchmark** | Benchmark repo with 20 defects, 4 decoys, 1 manipulation attempt; `score.py`; experiments E1–E3 | Recall, precision, coverage and reproducibility of skill v2.5 as numbers | 1–2 weeks |
| **1 Technical audit** | Run manifest, inventory JSON, tool runner, evidence store, finding v3, baseline/suppressions, file gateway with access log, checks, gate `basic` | Reproducible run with honest coverage | 3–5 weeks |
| **2 Verification** | V1 (failing tests), V2, V3 with a different model, counter-search; profile `production-release`; experiments E4–E6 | Measured effect of verification | 3–4 weeks |
| **3 Compliance as code** | Catalogue (GDPR part, ASVS selection, CRA if applicable), applicability decisions, three compliance roles | Control matrix with evidence and gaps | as needed |
| **4 Continuous** | Quick check per PR (diff-based), full audit before release, periodic re-audits, CVE monitoring, integration into the Levuvo Software Factory, optional dashboard | Ongoing operation | ongoing |

**Recommended order:** Phase 0 before Phase 1. The measurement shows where the real gaps are (e.g. whether v2.5 is weak mainly on coverage, on certain roles or on precision), so Phase 1 can be prioritised accordingly. Building the benchmark repo is also independent of everything else.

The durations are estimates without a measured basis.

## 9.2 Work packages Phase 0

1. Create the benchmark repo `audit-benchmark-mailbox` (private), write the base application, tests green.
2. Seed defects B01–B20, decoys D1–D4 and manipulation I1; ground truth in this repo under `benchmark/ground-truth/v1.yaml`.
3. Make sure the benchmark repo contains no hint of the defects (review by a second instance that does not know the ground truth and only looks for revealing comments/names).
4. `benchmark/score.py`: reads ground truth + `findings_consolidated.json` (v2.5) or `findings.json` (v3), produces `metrics.json` and a triage template.
5. Run experiments E1, E2, E3 three times each; triage; results report.

## 9.3 Work packages Phase 1

1. Run manifest and evidence store (incl. `audit verify`)
2. Inventory JSON (extension of `inventory.py`)
3. Extend the sandbox allowlist (Semgrep, Trivy, Syft, Hadolint, OSV-Scanner offline)
4. Tool runner with profile `basic`, normalisation SARIF → finding v3
5. Fingerprint, baseline, suppressions
6. File gateway (MCP) with access log; connect skill v2.5
7. Checks and gate `basic`
8. Acceptance tests from [03, section 3.7](03-phase-1.md)

## 9.4 Open decisions

| No. | Question | Proposal | Decides |
|---|---|---|---|
| D-1 | Where does the system's code live: in this repo or as an extension of the skill? | Orchestrator, gate and schemas in this repo; the skill stays standalone and is connected | Peter |
| D-2 | File gateway as MCP server (model-independent) or hook (Claude Code only)? | MCP server; hook only as an interim solution | Peter |
| D-3 | Which second model for V3? | A model from another vendor via API; if not wanted, V3 stays empty and `production-release` requires V1/V2/V5 | Peter |
| D-4 | Where do audits run: cloud sandbox, local factory, GitHub Actions? | Phase 0/1 locally or in the cloud; from Phase 4 in the Levuvo Software Factory with its own, separate role | Peter |
| D-5 | SCA with network or with a mirrored database? | Mirrored database with its state in the manifest (reproducible) | Peter |
| D-6 | Should skill v2.5 switch to English values, or stay German with an import mapping? | Keep the mapping (04, section 4.9) until the skill is next revised, then switch it to English | Peter |
| D-7 | Who checks the deadlines in [07, section 7.6](07-compliance-catalogue.md) against the primary sources? | Before Phase 3; until then not in the catalogue | Peter / lawyer |

## 9.5 Project risks

- **Scope grows faster than value.** Mitigation: keep Phase 0 and 1 strictly lean; every extension must show its value in the benchmark.
- **The benchmark gets memorised.** Mitigation: keep it private, add variants, rebuild real missed defects.
- **Tool noise drowns triage.** Mitigation: baseline, suppressions with expiry date, disable rules with a high FP rate instead of suppressing individual findings.
- **False confidence from "PASS".** Mitigation: `UNKNOWN` as default, `INCOMPLETE` visible in the report, human release separate from the gate.
