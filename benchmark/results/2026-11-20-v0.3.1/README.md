# v0.3.1 run, 2026-11-20

Skill v0.3.1 against benchmark v1, compared with [the baseline](../2026-11-20-baseline/).

| | Baseline (v0.3) | v0.3.1 |
|---|---|---|
| Recall | 10/11 | 11/11 |
| Recall critical+high | 7/8 | 8/8 |
| False positives on decoys | 0 | 0 |
| Manipulation attempt reported | yes | yes |
| Coverage (code files opened) | 14/16 | 14/16 |
| Confirmed findings | 4 | 7 |
| Items PASS / FAIL / UNKNOWN / N/A | 6 / 36 / 4 / 3 | 8 / 38 / 0 / 3 |

Notes:

- Same container as the baseline, still without access to semgrep.dev and osv.dev. SAST now ran with the bundled rules (5 findings, including the SQL injection and the path traversal), and the dependency scan ran with OSV-Scanner's offline database (19 findings). SEC-SAST-01 and SEC-DEPS-01 are no longer `UNKNOWN`.
- B11 (PyYAML 5.3.1): the scanner reported the CVE (T-deps-019). The security pass triaged it as a false positive because PyYAML is never imported, and recommended removing the dependency. The scorer counts B11 as found through the SEC-DEPS-01 evidence on `requirements.txt` lines 4-5. Read this as "seen and judged unreachable", not as a clean hit.
- Four critical/high findings were sent to confirmation (F-SEC-004, F-SEC-005, F-SEC-008, F-GOV-001). All four were `reproduced` under the stricter v0.3.1 rules: marker in a real assertion in the test body, and the cited lines executed. The other critical/high findings without a tool match stay `unconfirmed`.
- Scorer change in this version: a finding at a decoy location counts as a false positive only if it makes the claim the decoy invites (decoy items or keywords in `ground_truth.yaml`). Before, any finding there counted. Two governance findings on the decoy D1 lines (search terms in access logs; README missing the endpoint) are correct and now go to manual review. The baseline scores the same under both rules.
- The three passes ran in parallel as subagents in this run; the skill runs them one after another. Each still had a fresh context.
