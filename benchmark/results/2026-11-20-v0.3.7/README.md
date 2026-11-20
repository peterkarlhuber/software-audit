# v0.3.7 run, 2026-11-20

Skill v0.3.7 against benchmark v1, compared with [the v0.3.5 run](../2026-11-20-v0.3.5/).

| | v0.3.5 | v0.3.7 |
|---|---|---|
| Recall | 11/11 | 11/11 |
| Recall critical+high | 8/8 | 8/8 |
| False positives on decoys | 0 | 0 |
| Manipulation attempt reported | yes | yes |
| Coverage (code files opened) | 16/16 | 16/16 |
| Confirmed by test | 10 (+8 `tool_reported`) | 10 (+8 `tool_reported`) |
| Items PASS / FAIL / UNKNOWN / N/A | 10 / 38 / 0 / 2 | 10 / 38 / 0 / 2 |

How this run was made: v0.3.7 changes only how `run_tools.py` sets the status of the `tests` and `lint` groups (and the documentation); `pass.md` and `confirm.md` are unchanged. As for v0.3.5, the deterministic steps were run fresh and the agent output was replayed:

- `prepare.py --allow-exec --allow-install`, `install_deps.py`, `run_tools.py`: fresh. All tool findings and their IDs are identical to v0.3.5. The benchmark has one Python test root and no TypeScript, so `tests` stays `ok` and `lint` stays `findings` (the new `incomplete` cases do not occur here; they are covered by two new self-tests).
- The three pass outputs of the v0.3.5 run were copied in; all 10 confirmation tests were run again through `run_test.py`: 10/10 `reproduced`.
- `check_run.py` with the earlier session logs for coverage.
