# 07 Compliance catalogue (Phase 3)

## 7.1 Principle

An agent does not decide afresh from its model knowledge in every audit which regulations apply. Instead there is a **central, versioned catalogue** with unique requirement IDs, official sources, version states and applicability rules.

Responsibilities are clearly split:

| Task | Who |
|---|---|
| Maintain the catalogue (sources, versions, deadlines) | Human, with AI support for drafting; every change as a pull request with source reference |
| Decide **applicability** of a regulation to a product | **Human** (responsible person, lawyer if needed), with justification and date |
| Collect evidence, flag gaps, pre-fill the control matrix | AI reviewers and tools |
| Assess "met / not met" for legal questions | Human; AI only provides a proposal with evidence |
| Legally binding conformity statement | Responsible person or external assessment body; not the system |

An LLM result alone never leads to a compliance release.

## 7.2 Start small

The catalogue does not start with every conceivable regulation, but only with what actually applies to the concrete Levuvo products after human review. Proposal for the first increment:

1. **GDPR**, technically verifiable parts: data minimisation, deletion, security of processing (Art. 32), data protection by design (Art. 25), logging of personal data.
2. **OWASP ASVS 5.0**, selected chapters as technical baseline (not legally mandatory, but easy to verify).
3. **CRA Annex I**, only if the applicability decision for a product is "applicable".
4. **AI Act**, only for products with built-in AI features and only after classification by a human.

Further regulations (NIS2, DORA, Data Act, product safety, accessibility) are added only after a documented applicability decision.

## 7.3 Catalogue entry

```yaml
- id: GDPR-ART17-ERASURE-01
  framework: GDPR
  source:
    legal_act: "Regulation (EU) 2016/679"
    reference: "Art. 17(1)"
    url: "https://eur-lex.europa.eu/eli/reg/2016/679/oj"
    version: "OJ L 119, 4.5.2016"
    verified_at: null              # date of the last check against the primary source
    verified_by: null
  kind: legal                      # legal | standard | internal
  validity:
    applies_from: "2018-05-25"
    time_status: binding           # binding | future_binding | best_practice
  applicability_question: "Does the product process personal data of users who have a right to erasure?"
  technical_requirement: "On an erasure request, all personal data of the user, including attachments, indexes, caches and backups, is removed or anonymised within the defined period."
  checks: [PRIV-DEL-001, PRIV-DEL-002]
  required_evidence:
    - "Data flow inventory of all locations storing personal data"
    - "Test that checks every storage location after deletion"
  note: "Legal exceptions (Art. 17(3)) are assessed by a human."
```

Rules:
- Every requirement has exactly one ID, which never changes. Content changes create a new version in the catalogue (Git history), not a new ID.
- A requirement without `source.url` and without `verified_at` must not be used as a mandatory requirement in the `production-release` profile.
- The catalogue state (Git commit of the catalogue) is recorded in the run manifest.

## 7.4 Applicability decision

Per product and regulation there is a decision made by a human:

```yaml
product: levuvo-mail
framework: CRA
decision: applicable               # applicable | not_applicable | open
justification: "Distributed as a desktop application on the EU market (free of charge, but with a commercial context)."
decided_by: peter
decided_at: 2026-11-20
next_review: 2027-05-20
sources: ["Regulation (EU) 2024/2847, Art. 2 and 3"]
```

- `open` means: all checks of this regulation are `UNKNOWN`, not `N/A`.
- `not_applicable` sets the checks to `N/A` and carries over justification, person and date.
- Typical false assumptions the catalogue is meant to prevent:
  - Using AI tools *to develop* software does not automatically trigger AI Act obligations *for the developed product*. An AI assistant built into the product, however, must be assessed by function, purpose and one's own role (provider/deployer).
  - Purely internal software is not automatically a product made available on the market within the meaning of the CRA. Free distribution with a commercial context can, however, be covered.

## 7.5 Time dimension

On the audit date, an audit distinguishes per requirement:

| Time status | Effect in the gate |
|---|---|
| `binding` | Mandatory, if applicable |
| `future_binding` | Reported as a preparation gap; gate effect per profile (e.g. warning, mandatory from 6 months before it applies) |
| `best_practice` | Voluntary, report only |
| `not_applicable` | `N/A` according to the applicability decision |

The time status is computed from `applies_from` and the audit date, not estimated by the model.

## 7.6 Deadlines: verify against primary sources before adoption

The following statements come from the original concept (as of 20 Nov 2026). **None of them has been checked against the primary source.** They may enter the catalogue only after a person has looked them up in the Official Journal (EUR-Lex) or the consolidated version and set `verified_at`. In particular, the postponements by the "Digital Omnibus" depend on whether and in which version the amending regulation has been adopted and published.

| Regulation | Statement in the concept | Primary source | Status |
|---|---|---|---|
| GDPR | Applies when personal data is processed | Reg. (EU) 2016/679 | ⚠ to verify |
| AI Act | Further core provisions apply since 2 Aug 2026 | Reg. (EU) 2024/1689, Art. 113 | ⚠ to verify |
| AI Act | High-risk rules for Annex III systems from 2 Dec 2027 (after Digital Omnibus) | Amending regulation "Digital Omnibus", OJ reference still to be determined | ⚠ to verify, especially whether in force |
| AI Act | Product-embedded high-risk AI from 2 Aug 2028 (after Digital Omnibus) | as above | ⚠ to verify, especially whether in force |
| CRA | Reporting obligations since 11 Sep 2026 | Reg. (EU) 2024/2847, Art. 14 and Art. 71 | ⚠ to verify |
| CRA | Main further obligations from 11 Dec 2027 | Reg. (EU) 2024/2847, Art. 71 | ⚠ to verify |

Technical standards as audit baseline (not automatically legally mandatory): NIST SSDF SP 800-218, OWASP ASVS 5.0, OWASP WSTG, OWASP SAMM, NIST AI RMF, ISO/IEC 42001, ISO/IEC 27001/27002, WCAG 2.2 AA. Here too, the version used is recorded in the catalogue.

## 7.7 Additional roles in Phase 3

| Role | Works against | Delivers |
|---|---|---|
| Privacy & GDPR | Catalogue entries `GDPR-*` with decision `applicable` | Control matrix with evidence and gaps |
| AI Governance | `AIA-*`, only after human classification | Evidence on transparency, logging, human oversight, agent permissions |
| CRA & Regulatory | `CRA-*` | Matrix for Annex I, SBOM, vulnerability handling, update mechanism |

These roles receive only the applicable catalogue entries as their task, not "check GDPR". Their results are proposals with evidence; `PASS` for a legal requirement requires human confirmation (V5).
