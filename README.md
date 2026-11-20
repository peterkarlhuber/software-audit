# Software-Audit

Spezifikation eines **evidenzbasierten, KI-gestützten Prüf- und Freigabesystems** für Software-Repositories.

KI-Agenten sind darin spezialisierte Prüfer, aber nie die alleinige Instanz, die über Qualität, Sicherheit oder Compliance entscheidet. Ein LLM darf eine Behauptung aufstellen. Das System muss sie belegen oder als unbestätigt kennzeichnen. Die Freigabe trifft ein deterministisches Gate, keine LLM-Abstimmung.

> **Stand:** Spezifikation, Version 0.1 (Entwurf). Es gibt noch keinen Code in diesem Repository.

## Dokumente

| Nr. | Dokument | Inhalt |
|---|---|---|
| 01 | [Grundsätze und Ziele](docs/spezifikation/01-grundsaetze-und-ziele.md) | Anspruch, Prinzipien, Ergebniszustände, Begriffe, Nicht-Ziele |
| 02 | [Architektur](docs/spezifikation/02-architektur.md) | Bausteine, Datenfluss, Vertrauensgrenzen, Bezug zum bestehenden Audit-Skill v2.5 |
| 03 | [Phase 1: Reproduzierbares technisches Audit](docs/spezifikation/03-phase-1.md) | Schlanker erster Ausbau mit Akzeptanzkriterien |
| 04 | [Datenformate](docs/spezifikation/04-datenformate.md) | Run-Manifest, Inventar, Befund v3, Lese-Protokoll, Suppressions, Gate-Ergebnis |
| 05 | [Unabhängige Verifikation](docs/spezifikation/05-verifikation.md) | Rangfolge der Verifikationsmethoden, Regeln gegen Selbstbestätigung |
| 06 | [Benchmark](docs/spezifikation/06-benchmark.md) | Benchmark-Repo mit 20 eingebauten Fehlern, Ködern und Manipulationsversuch, Metriken, Messprotokoll |
| 07 | [Compliance-Katalog](docs/spezifikation/07-compliance-katalog.md) | Versionierter Anforderungskatalog, Anwendbarkeit durch Menschen, zu prüfende Fristen |
| 08 | [Freigabe-Gate](docs/spezifikation/08-freigabe-gate.md) | Deterministische Freigaberegeln und Prüfprofile |
| 09 | [Roadmap und offene Entscheidungen](docs/spezifikation/09-roadmap.md) | Phasen, Reihenfolge, Entscheidungen, die noch ausstehen |

Die JSON-Schemas zu Dokument 04 liegen unter [`schemas/`](schemas/).

## Empfohlene Reihenfolge

1. **Phase 0 – Benchmark (1–2 Wochen):** Benchmark-Repo bauen und den bestehenden Audit-Skill v2.5 dagegen messen. Ergebnis: Recall, Precision und Abdeckung als Zahlen statt Bauchgefühl.
2. **Phase 1 – Reproduzierbares technisches Audit:** fixierter Commit, Inventar, Tool-Runner, Evidence Store, maschinell nachgewiesene Abdeckung, minimales Gate.
3. Danach je nach Messergebnis: Verifikation (Phase 2), Compliance-as-Code (Phase 3), kontinuierliche Prüfung (Phase 4).

## Lizenz

MIT, siehe [LICENSE](LICENSE).
