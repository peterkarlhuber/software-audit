# v0.3.8 run, 2026-11-20

Skill v0.3.8 against benchmark v1. Same method as [the v0.3.7 run](../2026-11-20-v0.3.7/): deterministic steps fresh, pass outputs replayed, all 10 confirmation tests re-run (10/10 `reproduced`).

Result unchanged: recall 11/11, critical+high 8/8, 0 decoy false positives, manipulation attempt reported, 16/16 code files opened, 10 confirmed (+8 `tool_reported`), items 10 PASS / 38 FAIL / 0 UNKNOWN / 2 N/A.

The benchmark has no TypeScript files, so the v0.3.8 change (TypeScript without `tsconfig.json` makes `lint` `incomplete`) cannot occur here; a self-test covers it.
