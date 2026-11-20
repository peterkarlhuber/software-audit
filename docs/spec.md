# Software Audit – Specification v0.3

## 1. Goal

Type `/software-audit` in Claude Code inside any repository and get a complete, honest audit, without writing a new prompt each time and hoping the agent checks everything.

The audit covers four areas: functionality and quality, security, governance and compliance, and operations. Every checklist item ends as `PASS`, `FAIL`, `UNKNOWN` or `N/A` with evidence. Anything that was not checked is reported as not checked. No findings never means "no problems".

## 2. Design

The research in [research.md](research.md) shows that the leading systems share three things. Deterministic tools run first. An agent reasons on top. Findings are confirmed by running them where possible. None of them depends on many reviewer roles, and single runs vary a lot. So v0.3 is:

**standard tools + one agent with one skill + fixed checklists + tests for critical findings + a script that checks the agent's output.**

| Component | Path | Role |
|---|---|---|
| Skill | `skill/software-audit/SKILL.md` | The fixed procedure (steps 1–6), invoked as `/software-audit` |
| Pass instructions | `skill/software-audit/references/pass.md` | How a pass works through checklist items and what it must write |
| Confirm instructions | `skill/software-audit/references/confirm.md` | How a critical/high finding is confirmed with a test |
| Checklists | `skill/software-audit/checklists/*.yaml` | 49 items: what to check, how, what counts as evidence |
| `prepare.py` | `skill/software-audit/scripts/` | Pin commit, inventory, detect facts, select applicable items |
| `run_tools.py` | same | Run Gitleaks, Semgrep, OSV-Scanner/Trivy, Syft, Ruff/tsc, Hadolint, tests |
| `run_test.py` | same | Run a confirming test in a sandboxed copy of the repo |
| `check_run.py` | same | Verify the agent's output, set final results and statuses, write the report |
| Benchmark | `benchmark/` | Repo with 11 known bugs, 2 decoys and 1 manipulation attempt, plus scorer |

The agent works through the checklist in three passes: functionality and operations, then security, then governance. Each pass runs as a subagent with a fresh context, so no single context gets overloaded. It is the same skill throughout; only the checklist section changes.

## 3. Procedure

1. **Prepare** (`prepare.py`). Records the full commit SHA and whether the working tree has uncommitted changes. Lists every tracked file with hash, line count and class. Generated, vendored and binary files are listed as excluded, with the reason. Detects facts from code signals: `has_api`, `has_ui`, `has_db`, `has_tests`, `has_ai_features`, `processes_personal_data`, `has_docker`, `has_ci`. These facts decide which items apply. A wrong fact can be overridden with `--fact NAME=yes|no`, and the override is recorded. Output goes to `.audit/<run_id>/` inside the audited repo, which is excluded from Git.
2. **Tools** (`run_tools.py`). Runs every tool that fits the stack and stores the raw output. Tool findings are normalised and get IDs (`T-sast-004`). A missing or failing tool is recorded. Checklist items that depend on it can then not be `PASS`.
3. **Passes** (subagents with `pass.md`). For every applicable item, the agent writes a result, the files it examined, how it made sure nothing was missed, and exact quotes as evidence. For each problem it writes a finding. It triages every tool finding of its pass as `real` or `false_positive`, with a reason.
4. **Confirm** (subagents with `confirm.md`). For each critical or high finding, a fresh subagent sees only the location and the claim. It writes a test that must fail because of the defect, with the marker `AUDIT_CONFIRM:<id>` in the failing assertion. `run_test.py` runs it in a bubblewrap sandbox on a throwaway copy, with no network and an empty environment.
5. **Check** (`check_run.py`). Applies the rules in section 4 and writes `results.json` and `report.md`.
6. **Deliver.** The skill tells the user the report path, the counts, the main confirmed risks and what was not checked.

## 4. Rules enforced by `check_run.py`

The agent never sets final results or finding statuses. The script does.

**Results**
- An applicable item without a result becomes `UNKNOWN`.
- **`PASS` is strict.** It requires all of the following, otherwise the item becomes `UNKNOWN` with the reason:
  - a list of examined files, all present in the inventory
  - a completeness statement saying how the agent made sure nothing was missed (at least 30 characters)
  - at least one piece of evidence, with every quote verified
  - for items tied to a tool: the tool ran, and all of its findings were triaged as false positives
  - if the session log is available: every examined file was actually opened
- `FAIL` requires at least one finding with valid evidence. Otherwise it becomes `UNKNOWN`.
- `N/A` requires a reason.

**Evidence and findings**
- A quote must appear in the cited file within ±3 lines of the cited lines. If it is found elsewhere in the file, the lines are corrected. If it is not found, the evidence is invalid. Quotes need at least 12 characters.
- Finding statuses:

| Status | Meaning |
|---|---|
| `confirmed` | Critical/high finding reproduced by a test (`run_test.py` outcome `reproduced`), or reported by a tool and triaged as real |
| `unconfirmed` | Critical/high finding without a reproducing test. It is shown explicitly as unconfirmed. |
| `not_reproduced` | The confirming test passed. The finding stays in the report. |
| `evidenced` | Medium/low finding with a verified quote |
| `invalid_evidence` | Quote or file could not be verified, or the cited file was never opened |

**Coverage.** The script reads the Claude Code session logs for this repository, including subagents. From them it counts which in-scope code files were actually opened. Unopened files are listed in the report. Without a log, coverage is reported as "not measured".

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

**Rule:** after every change to the skill, the checklists or the scripts, run the benchmark at least once and compare it with the previous result. A change that lowers recall is not kept unless there is a stated reason.

## 7. Deliberately left out

There are no reviewer roles beyond the one agent, no chief, no second model and no release gate. There are also no approvals, no four-eyes principle, no signed evidence store, no legal requirements catalogue and no dashboard. Any of these can be added later if the benchmark or a real audit shows a concrete gap.

## 8. Relation to skill v2.5

v0.3 replaces the v2.5 skill under the same name, `software-audit`.

| v2.5 | v0.3 |
|---|---|
| 12 reviewer roles in parallel + chief | One agent, three passes, fixed checklist |
| Reviewers decide what to look at | Checklist decides; every item must be answered |
| Tools only if a reviewer runs them | Tools always run first |
| Chief re-checks critical/high findings | Fresh-context test with a marker, run in the sandbox |
| Coverage = self-reported files | Coverage from the session log |
| German status values | English values |

## 9. Requirements

- Python 3.9+, PyYAML, Git
- Recommended tools: gitleaks, semgrep, osv-scanner (or trivy), syft, hadolint, ruff. Missing tools leave the related items `UNKNOWN`.
- bubblewrap (Linux) for running tests and confirming findings
- Semgrep's default ruleset (`p/default`) and OSV-Scanner need internet access. For offline use, set `AUDIT_SEMGREP_CONFIG` to a local rules folder.
