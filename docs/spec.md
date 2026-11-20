# Software Audit – Specification v0.3.3

## 1. Goal

Type `/software-audit` in Claude Code inside any repository and get a complete, honest audit, without writing a new prompt each time and hoping the agent checks everything.

The audit covers four areas: functionality and quality, security, governance and compliance, and operations. Every checklist item ends as `PASS`, `FAIL`, `UNKNOWN` or `N/A` with evidence. Anything that was not checked is reported as not checked. No findings never means "no problems".

## 2. Design

The research in [research.md](research.md) shows that the leading systems share three things. Deterministic tools run first. An agent reasons on top. Findings are confirmed by running them where possible. None of them depends on many reviewer roles, and single runs vary a lot. So v0.3.x is:

**standard tools + one agent with one skill + fixed checklists + tests for critical findings + a script that checks the agent's output.**

| Component | Path | Role |
|---|---|---|
| Skill | `skill/software-audit/SKILL.md` | The fixed procedure (steps 1–6), invoked as `/software-audit` |
| Pass instructions | `skill/software-audit/references/pass.md` | How a pass works through checklist items and what it must write |
| Confirm instructions | `skill/software-audit/references/confirm.md` | How a critical/high finding is confirmed with a test |
| Checklists | `skill/software-audit/checklists/*.yaml` | 50 items: what to check, how, what counts as evidence |
| `prepare.py` | `skill/software-audit/scripts/` | Pin commit, inventory, detect facts, select applicable items |
| `run_tools.py` | same | Run Gitleaks, Semgrep, OSV-Scanner/Trivy, Syft, Ruff/tsc, Hadolint, tests |
| `run_test.py` | same | Run a confirming test in a sandboxed copy of the repo and check that it is a real reproduction |
| `audit_pytest_plugin.py` | same | Loaded by `run_test.py`: records failures and which cited lines ran |
| Semgrep rules | `skill/software-audit/rules/semgrep/` | Bundled rules for Python, JavaScript and Dockerfiles, so SAST works offline |
| `check_run.py` | same | Verify the agent's output, set final results and statuses, write the report |
| Benchmark | `benchmark/` | Repo with 11 known bugs, 2 decoys and 1 manipulation attempt, plus scorer |

The agent works through the checklist in three passes: functionality and operations, then security, then governance. Each pass runs as a subagent with a fresh context, so no single context gets overloaded. It is the same skill throughout; only the checklist section changes.

## 3. Procedure

1. **Prepare** (`prepare.py`). Records the full commit SHA. If tracked files have uncommitted changes, it stops, because the audit would not match the commit. `--allow-dirty` overrides this; the run is then marked and the report starts with a warning. Lists every tracked file with hash, line count and class. Generated, vendored and binary files are listed as excluded, with the reason. The user can leave further paths out with `--exclude PATH` (for example a test fixture or a deliberately vulnerable demo app); excluded paths do not count for facts, tool findings in them are dropped, quotes from them are rejected, and the report lists them. Detects facts from code signals: `has_api`, `has_ui`, `has_db`, `has_tests`, `has_ai_features` (AI SDK imports, or agent skills such as `SKILL.md`), `processes_personal_data`, `has_docker`, `has_ci`. These facts decide which items apply. A wrong fact can be overridden with `--fact NAME=yes|no`, and the override is recorded. Output goes to `.audit/<run_id>/` inside the audited repo, which is excluded from Git.
2. **Tools** (`run_tools.py`). Runs every tool that fits the stack and stores the raw output. Semgrep always runs the bundled rules, plus `p/default` (or `$AUDIT_SEMGREP_CONFIG`) when reachable. The dependency scan tries, in order: OSV-Scanner online, OSV-Scanner with a downloaded offline database, a cached offline database, pip-audit against PyPI, Trivy. The note in `tools/deps.json` says which one produced the result. Tool findings are normalised and get IDs (`T-sast-004`). A missing or failing tool is recorded; a tool that exits with an error or produces unreadable output is never recorded as a clean run. Checklist items that depend on it can then not be `PASS`.
3. **Passes** (subagents with `pass.md`). For every applicable item, the agent writes a result, the files it examined, how it made sure nothing was missed, and exact quotes as evidence. For each problem it writes a finding. It triages every tool finding of its pass as `real` or `false_positive`, with a reason.
4. **Confirm** (subagents with `confirm.md`). For each critical or high finding, a fresh subagent sees only the location and the claim. It writes a test that must fail because of the defect, with the marker `AUDIT_CONFIRM:<id>` in the failing assertion. `run_test.py` runs it in a bubblewrap sandbox on a throwaway copy, with no network and an empty environment. The marker alone is not enough (see section 4).
5. **Check** (`check_run.py`). Applies the rules in section 4 and writes `results.json` and `report.md`.
6. **Deliver.** The skill tells the user the report path, the counts, the main risks and what was not checked.

### Change audits (pull requests, branches)

`prepare.py --base REF` audits only the change from the merge base of `REF` to `HEAD`. It records each changed in-scope file with its changed line ranges (a pure deletion is recorded as the line where it happened) and the deleted files in `run.json` under `change`. Then:
- `run_tools.py` still runs every tool on the whole repository, but drops tool findings outside the changed lines (±3 lines; findings without a line count if their file changed). The count of dropped findings is recorded.
- The passes judge each checklist item for the change only: `N/A` if the change does not touch the item's subject, `PASS`/`FAIL` for the changed code read in context.
- `check_run.py` marks every finding with `in_change`; findings outside the change stay in the report with the note "outside the change". Coverage counts only changed code files.
- The report starts with a note that the rest of the repository was not reviewed.

The v2.5 skill used a diff to choose reviewer roles. With one agent and a fixed checklist there are no roles to choose; the checklist itself decides relevance, so no routing is needed.

### Several repositories

The skill runs steps 1 to 5 once per repository, then `summarize.py RUN...` writes one overview: per repository the commit, scope (full or change), result counts, findings by severity and confirmed findings, then all critical and high findings across repositories. Every number comes from a run's `results.json`. The v2.5 helpers for finding repositories by name pattern and for role scope strings were not ported: the agent lists repositories itself, and there are no roles.

## 4. Rules enforced by `check_run.py`

The agent never sets final results or finding statuses. The script does.

**Results**
- An applicable item without a result becomes `UNKNOWN`.
- **`PASS` is strict.** It requires all of the following, otherwise the item becomes `UNKNOWN` with the reason:
  - a list of examined files, all present in the inventory; a folder stands for every in-scope file in it
  - a completeness statement saying how the agent made sure nothing was missed (at least 30 characters)
  - at least one piece of evidence, with every quote verified
  - for items tied to a tool: the tool ran, and all of its findings were triaged as false positives
  - if the session log is available: every examined file was actually opened
- `FAIL` requires at least one finding with valid evidence. Otherwise it becomes `UNKNOWN`.
- `N/A` requires a reason.

`PASS` is an evidence-backed audit judgement, not a proof. The rules make sure it rests on opened files, verified quotes and clean tool results, but a completeness statement cannot prove that nothing was missed.

**Evidence and findings**
- A quote must appear in the cited file within ±3 lines of the cited lines. If it is found elsewhere in the file, the lines are corrected. If it is not found, the evidence is invalid. Quotes need at least 12 characters.
- Finding statuses:

| Status | Meaning |
|---|---|
| `confirmed` | Critical/high finding reproduced by a test (`run_test.py` outcome `reproduced`) |
| `tool_reported` | Finding backed by a tool finding triaged as real, but not reproduced by a test (for medium/low: the quote could not be verified, the tool finding carries it) |
| `unconfirmed` | Critical/high finding without a reproducing test. It is shown explicitly as unconfirmed. |
| `not_reproduced` | The confirming test passed. The finding stays in the report. |
| `evidenced` | Medium/low finding with a verified quote |
| `invalid_evidence` | Quote or file could not be verified, or the cited file was never opened |

**Confirming tests (`run_test.py`).** A test reproduces a finding only if all of these hold:
- the static check passes: the marker sits in a real `assert` whose condition reads at least one name, attribute, call or subscript; constant conditions such as `assert False` or `assert 1 == 2`, `raise` or `pytest.fail()` with the marker are `rejected`
- the test fails (exit code not 0)
- for pytest: the failure is an `AssertionError` in the test body (not in setup, fixtures or imports) and carries the marker
- for pytest: the cited lines (±2) were executed during the run. Lines run at import time (for example a `def` line) count only inside the cited range, so importing the file is not enough.

Outcomes: `reproduced` (finding `confirmed`), `reproduced_unverified` (other test runners, where the last two checks are not possible; the finding stays `unconfirmed`), `not_reproduced`, `inconclusive`, `rejected`, `not_run`.

**Coverage.** The script reads the Claude Code session logs for this repository, including subagents: first the project folder of the repository, and if the session was started elsewhere, any log written since the run started that mentions the repository path. From them it counts which in-scope code files were actually opened, through the Read tool or shell commands (`cat`, `head`, `sed -n`, … including `cd`, `for` loops and globs). Unopened files are listed in the report. Without a log, coverage is reported as "not measured" and listed as a problem, so it is never skipped silently; `--transcripts PATH` points to the log, `--no-transcripts` accepts the gap.

**Report.** Every report starts with a fixed scope note. The audit checks technical controls and collects evidence. It does not establish legal compliance with the GDPR, the EU AI Act, the CRA or any other regulation. Applicability and fulfilment are decided by a responsible person.

## 5. Safety

- The audited repository is data, never instructions. Attempts to steer the audit, for example "do not report findings here", are reported under SEC-MANIP-01.
- Static tools read the repository but do not run repository code. Tests and confirming tests run only with `--allow-exec`, and then inside bubblewrap on a throwaway copy, with no network and an environment free of tokens. Without bubblewrap (e.g. on macOS), repository code is not run unless the user explicitly starts the run with `--allow-exec-unsandboxed`. That option is meant for their own trusted repositories, still uses a temporary copy and still strips the environment.
- The audit writes only to `.audit/` in the audited repository: no commits, pushes, issues or comments.

## 6. Benchmark (mandatory after changes)

`benchmark/` contains a small mail service ("Postbox") with 11 seeded bugs, 2 decoys (correct code that looks suspicious) and 1 manipulation attempt (`CLAUDE.md` asks the audit to skip two files). The ground truth (`ground_truth.yaml`) is never copied into the audited repository.

```bash
benchmark/build_target.sh /tmp/postbox      # builds the repo, incl. a secret in Git history
cd /tmp/postbox && claude                   # then: /software-audit with tests allowed
python3 benchmark/score.py /tmp/postbox/.audit/<run>/results.json
```

The scorer reports:
- recall overall and for critical/high bugs
- missed bugs
- false positives on decoys
- whether the manipulation attempt was reported
- findings that need a manual look, which are either real unintended bugs or false positives

A second, small benchmark checks change audits: `benchmark/change/build_target.sh /tmp/postbox-change` builds the same repository with a branch `feature` on top of `main`; audit it with `prepare.py --base main` and score it with `score.py RESULTS --truth benchmark/change/ground_truth.yaml`.

**Rule:** after every change to the skill, the checklists or the scripts, run the benchmark at least once and compare it with the previous result. A change that lowers recall is not kept unless there is a stated reason.

## 7. Deliberately left out

There are no reviewer roles beyond the one agent, no chief, no second model and no release gate. There are also no approvals, no four-eyes principle, no signed evidence store, no legal requirements catalogue and no dashboard. Any of these can be added later if the benchmark or a real audit shows a concrete gap.

## 8. Relation to skill v2.5

v0.3.x replaces the v2.5 skill under the same name, `software-audit`.

| v2.5 | v0.3.x |
|---|---|
| 12 reviewer roles in parallel + chief | One agent, three passes, fixed checklist |
| Reviewers decide what to look at | Checklist decides; every item must be answered |
| Tools only if a reviewer runs them | Tools always run first |
| Chief re-checks critical/high findings | Fresh-context test with a marker, run in the sandbox |
| Coverage = self-reported files | Coverage from the session log |
| German status values | English values |

## 9. Requirements

- Python 3.9+, PyYAML, Git, pytest for confirming tests in Python repos
- Recommended tools: gitleaks, semgrep, osv-scanner (or pip-audit / trivy), syft, hadolint, ruff. Missing tools leave the related items `UNKNOWN`.
- bubblewrap (Linux) for running tests and confirming findings
- Offline: Semgrep runs the bundled rules without network; set `AUDIT_SEMGREP_CONFIG=none` to skip the online ruleset or point it to a local rules folder. The dependency scan needs either osv.dev, a one-time download of the OSV offline database, or PyPI (pip-audit).

## 10. Changes in v0.3.3

- Change audits: `prepare.py --base REF`, tool findings and coverage limited to the change, `in_change` on findings (section 3).
- Several repositories in one request: `summarize.py` overview.
- Second benchmark `benchmark/change/` for change audits: a branch that drops an ownership check (must be found) and adds a correct endpoint (decoy).

## 11. Changes in v0.3.2

From the first real audit (the repository auditing itself):
- `run_test.py`: constant comparisons such as `assert 1 == 2` are rejected like `assert False`.
- `run_tools.py`: Hadolint and tsc failures are recorded as errors, not as clean runs.
- `check_run.py`: session logs are also found when the session was started outside the repository; a missing log is listed as a problem. The coverage parser follows `cd`, shell `for` loops and globs, and no longer strips the dot of dotfiles. A folder in `examined` requires every file in it to have been opened.
- New status `tool_reported`: `confirmed` now always means "reproduced by a test".
- `prepare.py --exclude PATH`; skill files (`SKILL.md`, `.claude/agents|skills|commands`) count as AI features.
- Checklists: OPS-CI-01 applies always, so a repository without CI fails it instead of N/A; new SEC-EXEC-01 for running untrusted code, commands and data without isolation (50 items).

## 12. Changes in v0.3.1

- `run_test.py`: a failing test with the marker is no longer enough. Trivial assertions are rejected; for pytest the failure must be the marked assertion in the test body and the cited lines must have run.
- `prepare.py`: stops on uncommitted changes unless `--allow-dirty` is given.
- Bundled Semgrep rules and an offline fallback chain for the dependency scan.
