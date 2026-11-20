# Software Audit

A repeatable, AI-assisted audit for any repository. One command, one agent, fixed checklists and standard tools, instead of writing a new prompt each time and hoping the agent checks everything.

It covers functionality, security, governance/compliance and operations. Every checklist item ends as `PASS`, `FAIL`, `UNKNOWN` or `N/A` with evidence, and the report states plainly what was not checked.

> **Status:** Specification v0.2 (draft). No code yet.

## Contents

| Path | Content |
|---|---|
| [docs/spec.md](docs/spec.md) | The specification |
| [docs/research.md](docs/research.md) | How others build AI-assisted audits today, and what follows for this project |
| [checklists/](checklists/) | The checklists that replace the prompt (49 items) |
| [schemas/](schemas/) | JSON schemas for checklist results and findings |

## Design in one sentence

Tools run first, one agent works through a fixed checklist in three passes, critical findings are confirmed with a test, a script checks that nothing was skipped or invented, and a small test repo with known bugs shows what the audit misses.

## Licence

MIT, see [LICENSE](LICENSE).
