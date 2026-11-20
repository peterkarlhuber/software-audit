# v0.3.5 run, 2026-11-20

Skill v0.3.5 against benchmark v1, compared with [the v0.3.4 run](../2026-11-20-v0.3.4/).

| | v0.3.4 | v0.3.5 |
|---|---|---|
| Recall | 11/11 | 11/11 |
| Recall critical+high | 8/8 | 8/8 |
| False positives on decoys | 0 | 0 |
| Manipulation attempt reported | yes | yes |
| Coverage (code files opened) | 16/16 | 16/16 |
| Confirmed by test | 10 (+8 `tool_reported`) | 10 (+8 `tool_reported`) |
| Items PASS / FAIL / UNKNOWN / N/A | 10 / 38 / 0 / 2 | 10 / 38 / 0 / 2 |

How this run was made: v0.3.5 changes only deterministic steps (dependency installation, Semgrep status, the ignore file of the run folder); `pass.md` and `confirm.md` are unchanged. So the deterministic steps were run fresh and the agent output of the v0.3.4 run was replayed:

- `prepare.py --allow-exec --allow-install`, `install_deps.py` (install scripts off), `run_tools.py`: fresh. All tool findings and their IDs are identical to v0.3.4.
- The three pass outputs of the v0.3.4 run were copied in, and all 10 confirmation tests were run again through `run_test.py` against the new workspace: 10/10 `reproduced`.
- `check_run.py` with the v0.3.4 session logs for coverage.

Observed effect of the new default (no install scripts): `pip --only-binary :all:` cannot install PyYAML 5.3.1 (sdist only for Python 3.13). The new one-by-one fallback installed every other requirement and recorded `PyYAML==5.3.1` under `not_installed` in `deps.json`; the test suite and all confirmations still ran. `git status` of the benchmark repository stayed clean, and `.git/info/exclude` was not touched.
