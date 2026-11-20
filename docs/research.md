# State of the art: AI-assisted code audits (as of November 2026)

Short survey of how vendors and researchers build AI-assisted code audits today, and what that means for this project. Figures are as reported by the sources; most are vendor-reported and not independently verified.

## What the leading systems do

| System | Setup | Deterministic tools | How findings are confirmed | Reported results |
|---|---|---|---|---|
| Claude Code `/security-review` and GitHub Action (Anthropic, 2025) | One agent with a security-focused prompt; runs on demand or per PR | None described | Custom rules filter false positives; proposes fixes | Anecdotal (RCE, SSRF caught before merge) |
| Claude Code Security (Anthropic, research preview 2026) | Reasoning-based analysis | – | Multi-stage verification per finding, severity + confidence; fixes need human approval | Over 500 vulnerabilities in open source (vendor claim) |
| Aardvark / Codex Security (OpenAI, 2025–2026) | One agent in stages: threat model → scan → validate → patch | No fuzzing or SCA; writes and runs tests | Triggers each suspected bug in a sandbox to confirm it | 92 % recall on "golden" repos with known and seeded bugs |
| CodeMender (Google DeepMind, 2025) | Several special-purpose agents incl. a critique agent | Static and dynamic analysis, fuzzing, differential testing, SMT solvers | Patches checked for correctness and regressions; humans review every patch | 72 upstream security fixes in 6 months |
| Copilot coding agent (GitHub, 2025) | Agent validates its own output | CodeQL, advisory database for new dependencies, secret scanning | Agent fixes issues before finishing the PR | No figures |
| Semgrep Assistant (2025) | Tools find, one LLM step triages | Semgrep SAST | LLM labels each tool finding as likely true/false positive; nothing is auto-closed | 96 % agreement on true positives, 41 % on false positives |

## What research shows

- **LLMs find more, tools are more precise.** On 10 C# projects with 63 known vulnerabilities, LLM scanners reached higher F1 than SonarQube, CodeQL and Snyk Code, mainly through recall, but had more false positives and often gave wrong line numbers. The authors recommend a hybrid: LLM for finding, deterministic tools for assurance (Gnieciak & Szandała, 2025).
- **One run is not enough.** In Snyk's VulnBench JS (2026), a single Claude agent reached about 68 % recall and 92 % precision at best. Of the additional findings, about half appeared in only 1 of 5 runs. On the largest fixture, recall dropped sharply. Repeated runs and fixed checklists reduce this randomness.
- **AI reviewers can be manipulated.** Checkmarx showed that a comment such as "safe demo only" convinced an AI reviewer that a reverse shell was harmless, and that a review triggered a live database query. Audits must run sandboxed, and repo content must be treated as data.

## Conclusions for this project

1. **One agent is enough.** None of the leading systems relies on a large panel of reviewer roles. What matters is a fixed procedure, tools and validation, not the number of agents.
2. **Tools always run first.** Every serious setup combines the LLM with SAST, dependency checks and secret scanning (Copilot, Semgrep, CodeMender).
3. **Confirm by execution where possible.** Aardvark and Claude Code Security confirm findings by running them. A failing test is the strongest evidence.
4. **A fixed checklist replaces the prompt.** Randomness between runs comes largely from the agent deciding what to look at. A checklist that must be answered item by item makes runs comparable.
5. **Measure with known bugs.** OpenAI reports recall on repos with seeded bugs. A small test repo with known bugs is the only way to know what the audit misses.
6. **Governance and compliance are not automated anywhere.** No vendor claims automated legal compliance. The realistic approach is a checklist of verifiable technical controls with evidence, while a person decides applicability.

## Sources

- Anthropic: [Automate security reviews with Claude Code](https://www.anthropic.com/news/automate-security-reviews-with-claude-code)
- Anthropic: [Claude Security](https://anthropic.com/product/security)
- OpenAI: [Introducing Aardvark](https://openai.com/index/introducing-aardvark)
- Google DeepMind: [Introducing CodeMender](https://deepmind.google/blog/introducing-codemender-an-ai-agent-for-code-security/)
- GitHub: [Copilot coding agent now automatically validates code security and quality](https://github.blog/changelog/2025-10-28-copilot-coding-agent-now-automatically-validates-code-security-and-quality/)
- Semgrep: [How we built an AppSec AI that security researchers agree with 96% of the time](https://semgrep.dev/blog/2025/building-an-appsec-ai-that-security-researchers-agree-with-96-of-the-time/)
- Gnieciak & Szandała: [LLMs vs static code analysis tools](https://arxiv.org/abs/2508.04448v1)
- Snyk: [VulnBench JS 1.0: Can LLMs find the same bugs twice?](https://arxiv.org/pdf/2606.15762)
- CSIS: [What Claude Code Security can and can't do](https://www.csis.org/blogs/strategic-technologies-blog/ai-driven-code-analysis-what-claude-code-security-can-and-cant-do)
- Checkmarx: [How easy is it to trick an AI security reviewer?](https://checkmarx.com/zero-post/bypassing-claude-code-how-easy-is-it-to-trick-an-ai-security-reviewer/)
