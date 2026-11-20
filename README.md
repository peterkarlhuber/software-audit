# Software Audit

A repeatable, AI-assisted audit for any Git repository. Open Claude Code in the repository and type `/software-audit`. The skill runs standard tools, works through 50 fixed checklist items with one agent, confirms critical findings with tests, and a script checks that nothing was skipped or invented.

Output: `.audit/<run>/report.md` (to read) and `.audit/<run>/results.json` (machine-readable) inside the audited repository.

> Status: v0.3.8. The audit checks technical controls and collects evidence; it does not establish legal compliance (GDPR, AI Act, CRA). Every report says so.

## Install

```bash
git clone https://github.com/peterkarlhuber/software-audit
cd software-audit && ./install.sh        # copies skill/software-audit to ~/.claude/skills/
pip install pyyaml
```

Recommended tools (missing ones leave the related checklist items `UNKNOWN`): gitleaks, semgrep, osv-scanner (or pip-audit / trivy), syft, hadolint, ruff. Semgrep also runs the rules bundled in `skill/software-audit/rules/semgrep/`, so it works without network access. For running tests and confirming findings: bubblewrap (Linux).

If you use the skill through claude.ai instead, upload the folder `skill/software-audit` as a skill there. Build the upload from tracked files only, so no caches are included: `git archive --format=zip --prefix=software-audit/ -o software-audit-skill.zip HEAD:skill/software-audit`. It replaces the older skill of the same name.

## Use

In the repository to audit:

```
/software-audit                      # static audit, no repo code is executed
/software-audit with tests           # also runs the test suite and confirming tests (sandboxed)
/software-audit this PR against main # change audit: only the diff since the merge base with main
/software-audit repos A and B        # one run per repository plus a combined overview
```

To leave a folder out (for example a deliberately vulnerable demo app), say so, e.g. `/software-audit excluding benchmark/target`; the skill passes it to `prepare.py --exclude` and the report lists it.

Commit or stash your changes first: the audit stops on a dirty working tree so the report matches the commit (`--allow-dirty` overrides this and marks the report).

## Contents

| Path | Content |
|---|---|
| [docs/spec.md](docs/spec.md) | Specification v0.3.8 |
| [docs/research.md](docs/research.md) | How others build AI-assisted audits today |
| [skill/software-audit/](skill/software-audit/) | The skill: procedure, checklists, scripts, schema |
| [benchmark/](benchmark/) | Test repo with 11 known bugs, ground truth and scorer; `change/` for change audits |
| [tests/](tests/) | Self-tests for the scripts (`python3 -m pytest -q tests/`) |

## Benchmark

Run after every change to the skill, checklists or scripts:

```bash
benchmark/build_target.sh /tmp/postbox
cd /tmp/postbox && claude     # /software-audit with tests
python3 /path/to/software-audit/benchmark/score.py /tmp/postbox/.audit/<run>/results.json
```

## Licence

MIT, see [LICENSE](LICENSE).
