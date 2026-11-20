# Baseline run, 2026-11-20

First run of skill v0.3 against benchmark v1, used as the reference for later changes.

- Environment: cloud container without access to semgrep.dev and osv.dev, so the SAST and dependency tools could not run (SEC-SAST-01 and SEC-DEPS-01 are `UNKNOWN`). This is why B11 (vulnerable PyYAML) was not counted as found.
- Passes run as three subagents; two critical/high findings confirmed with tests (F-SEC-002, F-GOV-001) as a check of the confirm step; the other critical/high findings were not sent to confirmation in this run and are `unconfirmed`.
- Result: recall 10/11, critical+high 7/8, 0 false positives on decoys, manipulation attempt reported. Coverage: 14 of 16 code files opened.
