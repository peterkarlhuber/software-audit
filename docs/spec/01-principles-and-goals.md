# 01 Principles and goals

## 1.1 Claim

An absolute guarantee that complex software is free of defects or secure cannot be given. The system therefore promises something different that can be checked:

1. **100 % of the applicable mandatory checks** are performed or explicitly reported as not performed.
2. **All release criteria** of the selected audit profile are met.
3. **No unresolved critical risks** remain.
4. **Every result is traceable** to a requirement, a concrete piece of evidence and a reproducible audit process at the pinned commit.

The system examines four properties:

| Property | Question |
|---|---|
| Functionality and quality | Does the software meet its requirements, including edge cases and realistic operating conditions? |
| Cybersecurity | Do architecture, code, dependencies, permissions, data flows and operations meet verifiable security requirements? |
| Legal compliance | Are the regulations that actually apply (e.g. GDPR, AI Act, CRA) systematically checked and documented? |
| Traceability | Can every result be traced back to a requirement, evidence and an audit process? |

## 1.2 Core principles

**P1 – A claim is not proof.** An LLM may make a claim. The system must prove it or mark it as unconfirmed. Without evidence there is no `PASS` and no confirmed finding.

**P2 – Absence of findings proves nothing.** "No finding reported" never implies "defect-free". A check without proven execution is `UNKNOWN`, not `PASS`.

**P3 – Coverage is measured, not reported.** The system itself records which files an agent has read (access log, see [04](04-data-formats.md)). Agent self-reports are supplementary information only.

**P4 – Independence means a different method or a different model.** The same model with a fresh context shares the same blind spots. A failing test or a deterministic tool is worth more than a second LLM opinion (see [05](05-verification.md)).

**P5 – Deterministic release.** `PASS`, `FAIL` or `INCOMPLETE` is decided by ordinary program code based on the evidence, not by a model. Risk acceptances are made by a named person.

**P6 – A human decides whether a law applies.** AI may collect evidence and flag gaps. Whether a regulation applies to a product is decided and justified by a responsible person (see [07](07-compliance-catalogue.md)).

**P7 – The repository is untrusted.** Content of the audited repo (code, README, CLAUDE.md, comments, issues) is data, not instructions. Reviewers run isolated, without production secrets and without deploy rights.

**P8 – The audit system itself is measured.** Without recall and precision figures against known defects, every statement about agent quality is gut feeling (see [06](06-benchmark.md)).

**P9 – Nothing disappears silently.** A recorded finding is never silently removed or downgraded. Every state change has a reason, an author and evidence.

## 1.3 Result states

### Check (a single requirement at a commit)

| State | Meaning | Precondition |
|---|---|---|
| `PASS` | Demonstrably met | Required evidence per check is present and machine-verified |
| `FAIL` | Demonstrably not met | At least one open, unsuppressed finding or a failed mandatory run |
| `UNKNOWN` | Not sufficiently checked | Check missing, aborted, tool unavailable or coverage below threshold |
| `N/A` | Not applicable | Justified applicability decision with author and date |

`UNKNOWN` is the default. Every other state must be earned through evidence.

### Audit run (gate result)

| State | Meaning |
|---|---|
| `PASS` | All mandatory checks of the profile are `PASS` or `N/A`, no gate rule violated |
| `FAIL` | At least one gate rule violated (e.g. open critical finding) |
| `INCOMPLETE` | No rule violated, but at least one mandatory check is `UNKNOWN` |

`FAIL` takes precedence over `INCOMPLETE`.

### Finding (verification state)

`status` is `confirmed`, `plausible` or `suspected`. These correspond to the German values `bestätigt`, `plausibel` and `vermutet` of the existing skill v2.5 and are mapped on import. New is a structured `verification` object with method and level of independence (see [04](04-data-formats.md) and [05](05-verification.md)).

## 1.4 Terms

| Term | Meaning |
|---|---|
| Audit run | One audit of exactly one pinned commit with one profile. Has a unique `run_id`. |
| Audit profile | Selection of checks, tools and gate rules (e.g. `internal-dev`, `production-release`). |
| Check | A verifiable requirement with ID, method and required evidence, e.g. `TECH-SECRETS-001`. |
| Requirement | Entry in the versioned catalogue, e.g. a GDPR article or an ASVS item. Checks refer to requirements. |
| Finding | A concrete deviation with location, evidence and verification state. |
| Evidence | Immutable artefact in the evidence store, addressed by SHA-256. |
| Access log | List of all file accesses by a reviewer, written by the system (not by the agent). |
| Suppression | Justified, time-limited and approved suppression of a tool finding. |
| Baseline | Known legacy findings at a reference commit, which the gate treats separately from new findings. |

## 1.5 Non-goals

- No guarantee of correctness.
- No legally binding conformity assessment. The system provides evidence and a matrix; the assessment stays with humans or external assessors.
- No dynamic tests against running or third-party systems. Dynamic tests run only against locally started, isolated instances.
- No replacement for code review in day-to-day development. The system audits a state; it does not develop.
- In Phase 1: no dashboard, no policy language, no compliance checks.
