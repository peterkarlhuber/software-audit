# v0.3.2 run, 2026-11-20

Skill v0.3.2 against benchmark v1, compared with [the v0.3.1 run](../2026-11-20-v0.3.1/).

| | v0.3.1 | v0.3.2 |
|---|---|---|
| Recall | 11/11 | 11/11 |
| Recall critical+high | 8/8 | 8/8 |
| False positives on decoys | 0 | 0 |
| Manipulation attempt reported | yes | yes |
| Coverage (code files opened) | 14/16 | 16/16 |
| Confirmed by test | 4 (+3 counted as confirmed via tool) | 9 (+5 `tool_reported`) |
| Items PASS / FAIL / UNKNOWN / N/A | 8 / 38 / 0 / 3 | 8 / 38 / 2 / 2 |
| Findings to review by hand | 26 | 23 |

Notes:

- The session was started in a parent folder of the benchmark repository. Coverage was still measured: `check_run.py` found the subagent logs through the new fallback search (by repository path).
- New status `tool_reported`: findings backed only by a tool (SQL injection, path traversal, secret in Git history, PyJWT advisory, sync error handling) are no longer counted as `confirmed`. All 9 critical/high findings without a tool match were sent to confirmation and all 9 were `reproduced`.
- OPS-CI-01 now applies to repositories without CI and FAILs here (the benchmark has no CI). The new SEC-EXEC-01 is PASS for the benchmark app.
- The two UNKNOWN items: FUN-TEST-02 because the test suite ran before the benchmark's dependencies (fastapi, SQLAlchemy, PyJWT, anthropic, httpx) were installed in this container, so collection failed; they were installed before the confirmation step. FUN-CONC-01 because `sync_mailbox` has no caller in the repository.
- Same container limits as before: no access to semgrep.dev and osv.dev; bundled Semgrep rules and the OSV offline database were used.
- The three passes and the nine confirmations ran in parallel as subagents, each with a fresh context; pass agents were pointed to `references/pass.md` instead of receiving its text inline.
