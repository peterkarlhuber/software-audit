# v0.3.4 run, 2026-11-20

Skill v0.3.4 against benchmark v1, compared with [the v0.3.2 run](../2026-11-20-v0.3.2/).

| | v0.3.2 | v0.3.4 |
|---|---|---|
| Recall | 11/11 | 11/11 |
| Recall critical+high | 8/8 | 8/8 |
| False positives on decoys | 0 | 0 |
| Manipulation attempt reported | yes | yes |
| Coverage (code files opened) | 16/16 | 16/16 |
| Confirmed by test | 9 (+5 `tool_reported`) | 10 (+8 `tool_reported`) |
| Unconfirmed critical/high | 0 | 0 |
| Items PASS / FAIL / UNKNOWN / N/A | 8 / 38 / 2 / 2 | 10 / 38 / 0 / 2 |
| Findings to review by hand | 23 | 24 |

Notes:

- **New step 1b worked:** `install_deps.py` built the workspace venv from `requirements.txt` inside the sandbox, so the test suite ran with its dependencies (FUN-TEST-02 is no longer UNKNOWN) and no package had to be installed in the host Python for the confirmations.
- **Lowered severity still tested:** the security pass lowered F-SEC-009 (tokens cannot be revoked, SEC-TOKEN-01, checklist default high) to low. `check_run.py` queued it anyway; the confirmation test reproduced it. Findings lowered but backed by a tool finding (SQL injection, path traversal, secret in history) stay `tool_reported`, as before.
- **One rerun of the security pass.** In the first v0.3.4 run the security pass triaged the PyYAML 5.3.1 advisory as a false positive ("never imported") and B11 was missed (recall 10/11). That is agent variance, but the instructions allowed it, so `pass.md` now says a known vulnerability in a declared dependency is `real` and reachability may only lower the severity. With that rule the security pass was run again (fresh subagent, its earlier output and tests moved aside); the numbers above are from the final run. The functionality and governance passes were not repeated.
- Same container limits as before: no access to semgrep.dev and osv.dev; bundled Semgrep rules and the OSV offline database were used.
- The three passes and the confirmations ran in parallel as subagents, each with a fresh context.
