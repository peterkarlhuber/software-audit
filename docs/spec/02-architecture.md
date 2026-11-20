# 02 Architecture

## 2.1 Overview

```
 Repository @ pinned commit  +  audit profile  +  requirements catalogue (versioned)
                    │
                    ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │ Audit orchestrator (deterministic code, no LLM)                      │
 │  Run manifest · inventory · task distribution · access log           │
 └───────────┬─────────────────────────────┬────────────────────────────┘
             │                             │
             ▼                             ▼
 ┌───────────────────────┐     ┌───────────────────────────────┐
 │ Tool runner (sandbox) │     │ AI reviewers (isolated)       │
 │ SAST, secrets, SCA,   │     │ Access only via file gateway  │
 │ tests, build, SBOM    │     │ → every read is logged        │
 └───────────┬───────────┘     └──────────────┬────────────────┘
             │  raw output + exit codes        │  findings (schema v3)
             ▼                                 ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │ Evidence store (content-addressed, append-only)                      │
 │ Tool reports · test logs · access logs · findings · decisions        │
 └───────────┬──────────────────────────────────────────────────────────┘
             ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │ Normalisation & reconciliation                                       │
 │ Schema validation · quote check · baseline · suppressions · dedup    │
 └───────────┬──────────────────────────────────────────────────────────┘
             ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │ Independent verification (Phase 2)                                   │
 │ V1 failing test · V2 tool · V3 different model (blind)               │
 └───────────┬──────────────────────────────────────────────────────────┘
             ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │ Release gate (deterministic code)  →  PASS · FAIL · INCOMPLETE       │
 │ + human risk acceptance / release                                    │
 └──────────────────────────────────────────────────────────────────────┘
```

## 2.2 Components

| Component | Responsibility | Phase | Implementation |
|---|---|---|---|
| Orchestrator | Drives the run, creates the run manifest, distributes tasks, collects evidence | 1 | Python CLI, deterministic |
| Inventory | Complete file list with hash, class and exclusion reason | 1 | Extension of `inventory.py` (skill v2.5) |
| Tool runner | Runs tools reproducibly and isolated | 1 | Builds on `safe_run.py` (bubblewrap, cgroups) |
| File gateway | Only read access for AI reviewers to the repo; writes the access log | 1 | MCP server or hook, see 2.5 |
| Evidence store | Immutable storage of all evidence | 1 | Directory per run, content-addressed, plus `manifest.json` |
| Normalisation | SARIF and tool output → finding v3, baseline, suppressions | 1 | Python |
| AI reviewers | Domain review with a narrowly scoped task | existing | Skill v2.5 (12 reviewers + chief) |
| Verification | Independently confirm or refute findings | 2 | see [05](05-verification.md) |
| Requirements catalogue | Versioned requirements with sources and applicability rules | 3 | YAML in the repo, see [07](07-compliance-catalogue.md) |
| Gate | Deterministic release decision | 1 (minimal) | Python, rules per profile, see [08](08-release-gate.md) |
| Benchmark | Measures recall, precision, coverage, reproducibility | 0 | Separate private repo, see [06](06-benchmark.md) |
| Dashboard | Shows findings, coverage, risks | 4 | later, optional |

Separation principle: **system prompts** only define roles. **Audit procedures** live in versioned skills. **Requirements** live in the catalogue. **Release rules** are ordinary, tested program code.

## 2.3 Relation to the existing audit skill v2.5

The `software-audit` skill (12 specialists + chief, version 2.5) already covers a large part. The new system does not replace it; it embeds it as the "AI reviewers" stage and adds what is missing.

| Capability | Skill v2.5 | Gap | Target |
|---|---|---|---|
| Pinned state | Commit SHA per finding and coverage record | No run manifest with tool, ruleset and model versions | Run manifest (Phase 1) |
| Safe working copy | `prepare_repo.py` (hooks, filters, symlinks neutralised) | – | reuse |
| Inventory | `inventory.py` (Markdown + file list) | No hashes, no classification with exclusion reason, no JSON | Inventory JSON (Phase 1) |
| Sandbox | `safe_run.py` with bubblewrap, cgroups, allowlist | Semgrep, Trivy, Syft etc. not yet on the allowlist | Extend allowlist (Phase 1) |
| Finding format | JSON schema with quote, status, severity | No requirement ID, no fingerprint, verification only as enum | Finding v3, backward-compatible |
| Quote check | `process_findings.py` checks quotes against files | – | reuse |
| Coverage | Self-reported `files_reviewed`, "formally evidenced" | Not proven that files were read (named as a limitation in the 2.5 changelog itself) | System-written access log (Phase 1) |
| Deterministic tools | Only on reviewer initiative, hardly in static mode | No fixed tool run per profile | Tool runner with mandatory tools (Phase 1) |
| Verification | Chief re-checks critical/high findings | Same model, sees the reviewer's reasoning | V1–V3 per [05](05-verification.md) (Phase 2) |
| Tool noise | – | No baseline, no suppressions | Phase 1 |
| Result states | Finding status; no checks | No PASS/FAIL/UNKNOWN/N/A, no gate | Checks + gate (Phase 1, minimal) |
| Baseline comparison | `compare_baseline.py` | Matches via quotes, not stable fingerprints | Add fingerprint |
| Measurement | – | None | Benchmark (Phase 0) |

The skill's roles (ARC, CQ, SEC, AIS, QA, REL, DB, PERF, OPS, API, UX, DOC) remain. The roles "Privacy & GDPR", "AI Governance" and "CRA & Regulatory" from the original concept are added only in Phase 3 and work only against the catalogue. "Independent Verifier" becomes a separate stage in Phase 2, not a 13th reviewer.

## 2.4 Trust boundaries

| Zone | May | May not |
|---|---|---|
| Orchestrator, gate, evidence store | Read everything, write evidence | Execute repo code |
| Tool runner (sandbox) | Read repo copy, run tools, return output | Network (except approved SCA databases), home, secrets, evidence store |
| AI reviewers | Read via file gateway, write their own findings file | Write or modify the access log, modify the repo, network, deploy rights |
| Verifier | Read original repo and original evidence, run tests in the sandbox | See the first reviewer's reasoning (for V3), delete findings |
| Human | Applicability, risk acceptance, final release | – |

Important:
- **Repo content is data.** A manipulated README.md or CLAUDE.md asking to "ignore security issues" changes no rule. Such content is itself reported as a finding (prompt injection attempt).
- **Do not load repo instruction files.** AI reviewers start without the audited repo's CLAUDE.md, AGENTS.md or similar as system context. They read such files only as data.
- **The access log is outside the agent's write permissions.**

## 2.5 Machine-verified coverage

This is the most important addition compared to v2.5. Goal: "Reviewer X read file Y" is a fact from the system log, not a statement by the reviewer.

**Mechanism (option A, recommended):** AI reviewers get no direct file system access to the repo, but a **file gateway** (MCP server) with three tools: `list_dir`, `read_file(path, start, end)`, `search(pattern, glob)`. The gateway serves content only from the prepared working copy and writes every call with timestamp, agent, path, line range and file hash to the access log. This option works with any model, including another vendor's model for verification.

**Option B (interim, Claude Code only):** A `PostToolUse` hook writes `Read`, `Grep` and `Glob` calls to a log outside the workspace. Reading Bash commands (`cat`, `sed -n`) are blocked for reviewers so that no reading bypasses the log.

**Evaluation:**
- "Read" counts only if the content was actually returned to the agent (`read_file`). A search hit counts as "touched", not "read".
- Per file, the union of read line ranges is computed. File coverage = lines read / lines in file.
- Per reviewer and repo, coverage is computed against the inventory files relevant to the role (relevance rules per role, e.g. `devops`: Dockerfiles, CI, IaC).
- Findings on files or lines that were not read according to the log are automatically downgraded to status `suspected`.
- Self-reported `files_reviewed` is compared with the log. Deviations are shown in the report; they are themselves a benchmark metric.

Limitation: the log proves that content reached the model, not that it was analysed thoroughly. That is what the benchmark (recall) and spot checks are for.
