# Software Audit

Specification of an **evidence-based, AI-assisted audit and release system** for software repositories.

AI agents act as specialised reviewers in this system, but they are never the sole authority on quality, security or compliance. An LLM may make a claim. The system must prove it or mark it as unconfirmed. The release decision is made by a deterministic gate, not by an LLM vote.

> **Status:** Specification, version 0.1 (draft). There is no code in this repository yet.

## Documents

| No. | Document | Content |
|---|---|---|
| 01 | [Principles and goals](docs/spec/01-principles-and-goals.md) | Claim, principles, result states, terms, non-goals |
| 02 | [Architecture](docs/spec/02-architecture.md) | Components, data flow, trust boundaries, relation to the existing audit skill v2.5 |
| 03 | [Phase 1: Reproducible technical audit](docs/spec/03-phase-1.md) | Lean first increment with acceptance criteria |
| 04 | [Data formats](docs/spec/04-data-formats.md) | Run manifest, inventory, finding v3, access log, suppressions, gate result |
| 05 | [Independent verification](docs/spec/05-verification.md) | Ranking of verification methods, rules against self-confirmation |
| 06 | [Benchmark](docs/spec/06-benchmark.md) | Benchmark repo with 20 seeded bugs, decoys and an injection attempt; metrics; measurement protocol |
| 07 | [Compliance catalogue](docs/spec/07-compliance-catalogue.md) | Versioned requirements catalogue, applicability decided by humans, deadlines to verify |
| 08 | [Release gate](docs/spec/08-release-gate.md) | Deterministic release rules and audit profiles |
| 09 | [Roadmap and open decisions](docs/spec/09-roadmap.md) | Phases, order, pending decisions |

The JSON schemas for document 04 are in [`schemas/`](schemas/).

## Recommended order

1. **Phase 0 – Benchmark (1–2 weeks):** build the benchmark repo and measure the existing audit skill v2.5 against it. Result: recall, precision and coverage as numbers instead of gut feeling.
2. **Phase 1 – Reproducible technical audit:** pinned commit, inventory, tool runner, evidence store, machine-verified coverage, minimal gate.
3. Then, depending on the measurements: verification (Phase 2), compliance as code (Phase 3), continuous auditing (Phase 4).

## Licence

MIT, see [LICENSE](LICENSE).
