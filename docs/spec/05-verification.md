# 05 Independent verification

## 5.1 Problem

In skill v2.5 the chief re-checks critical and high findings. But the chief is the same model as the reviewers and sees their reasoning. It is therefore prone to the same blind spots and to confirmation bias: a convincingly worded argument is more likely to be accepted than refuted. A second opinion from the same model is **not an independent check**, it is a repetition.

## 5.2 Ranking of methods

The higher, the stronger the evidence. The gate requires a minimum level per profile.

| Level | Method | Independence | Evidence | Suited for |
|---|---|---|---|---|
| **V1** | **Failing test** | method | Test file + log + exit code at the audited commit | Logic errors, edge cases, authorisation, injection, race conditions (with repetition) |
| **V2** | **Deterministic tool** | method | Tool output that independently shows the finding | Secrets, CVEs, known patterns, type errors, configuration |
| **V3** | **Different model, blind** | model | Answer of the other model + access log | Architecture, design flaws, missing controls, cases without a practical test |
| V4 | Same model, fresh context | none | Answer + access log | Pre-filter only; does not count as independent |
| V5 | Human | human | Note with name and date | Edge cases, legal questions, risk acceptance |

Principle: **a finding for which the verifier writes a failing test is worth more than any LLM opinion.** V1 should therefore be the goal for every finding where a test is feasible with reasonable effort.

## 5.3 V1: verification by failing test

Procedure:
1. The verifier receives the location, the claim and the affected files (via the file gateway), **not** the first reviewer's reasoning.
2. It writes a test that triggers the claimed misbehaviour. The test lives outside the audited repo (`runs/<run_id>/verification/<finding_id>/`) and is placed into a throwaway copy.
3. The test runs in the sandbox (`--allow-exec` required) at the audited commit.
4. Assessment:
   - Test **fails as claimed** (correct assertion, not an import or syntax error) → `verified`, method `V1-test`.
   - Test **passes** → finding not confirmed. `refuted` only if the test demonstrably covers the claimed scenario completely; otherwise `not_verifiable`.
   - Test does not run (setup missing) → `not_verifiable`, reason recorded.
5. Guard against sham tests: the failure must come from an assertion related to the claimed behaviour. The orchestrator checks automatically that the failure is not a collection, import or timeout error (JUnit `failure` rather than `error`). A human spot-checks whether the test really tests the right thing.
6. The test is attached to the finding as a proposed regression test. After a fix it must pass.

For concurrency defects the test is run repeatedly (e.g. 50 repetitions); the finding is verified if it fails reproducibly at least once and the log shows the failure.

## 5.4 V2: verification by tool

An AI finding counts as V2-verified if a deterministic tool **independently** reports the same defect at the same location (fingerprint match, or location overlap plus a matching rule). Conversely, a tool finding that an AI reviewer merely repeats is not additional evidence.

The verifier may also run a tool with a new rule written specifically for this finding (e.g. a Semgrep rule). The rule is stored as evidence.

## 5.5 V3: verification by a different model, blind

When neither a test nor a tool is possible:
- **Different model:** preferably a different model family or vendor; at minimum a different model than the first reviewer. Vendor and model ID are recorded in the finding and the manifest.
- **Blind:** the verifier receives only the question ("At `src/auth/session.ts:85-103`, does the session remain valid after logout? Support your answer with a quote."), not the first reviewer's answer, severity or reasoning.
- **Same tools:** access only through the file gateway, so its reading is logged as well.
- **Own evidence:** its answer must contain its own quotes, which are checked automatically against the files.
- **Outcome:** both agree and both quotes are valid → `verified` (V3). They contradict each other → `not_verifiable` with both positions; decided by a human (V5) or a later test (V1).

If no other model is available, V4 is used and the finding is explicitly marked `independence: "none"`. Whether that is sufficient is defined by the gate profile (not in `production-release`).

## 5.6 Targeted search for missed defects

Verification is not only about checking reported findings. The verifier also gets a **counter-search** task:
- Files with high relevance and low coverage in the access log
- Checks that are `UNKNOWN` although a test would be possible
- A sample of files in which a reviewer reported "no findings"

Results of the counter-search are new findings with `origin.name: "verifier"` and go through verification by another instance themselves.

## 5.7 Rules

1. No `verified` without `evidence_sha256`.
2. The verifier never deletes a finding. Refutation requires evidence (a test that passes and covers the scenario, or a quote that disproves the claim).
3. The verifier never sees the first reviewer's reasoning (V3) and never sees another verifier's result for the same finding.
4. Downgrading severity is a state change with a `history` entry, reason and author.
5. Verification runs at the same commit as the audit. A finding verified at a different commit counts as `not_checked`.
6. Cost is measured (time and tokens per finding and method), so the cost/benefit ratio becomes visible in the benchmark.
