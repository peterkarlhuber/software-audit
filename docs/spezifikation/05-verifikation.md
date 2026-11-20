# 05 Unabhängige Verifikation

## 5.1 Problem

Im Skill v2.5 prüft der Chief kritische und hohe Befunde nach. Der Chief ist aber dasselbe Modell wie die Prüfer und sieht deren Begründung. Damit ist er anfällig für dieselben blinden Flecken und für Bestätigungsfehler: Eine überzeugend formulierte Begründung wird eher übernommen als widerlegt. Ein zweites Urteil desselben Modells ist **keine unabhängige Prüfung**, sondern eine Wiederholung.

## 5.2 Rangfolge der Methoden

Je weiter oben, desto stärker der Beleg. Das Gate verlangt je Profil eine Mindeststufe.

| Stufe | Methode | Unabhängigkeit | Beleg | Geeignet für |
|---|---|---|---|---|
| **V1** | **Fehlschlagender Test** | Methode | Test-Datei + Log + Exit-Code am auditierten Commit | Logikfehler, Grenzfälle, AuthZ, Injection, Race Conditions (mit Wiederholung) |
| **V2** | **Deterministisches Werkzeug** | Methode | Werkzeug-Ausgabe, die den Befund unabhängig zeigt | Secrets, CVEs, bekannte Muster, Typfehler, Konfiguration |
| **V3** | **Anderes Modell, blind** | Modell | Antwort des anderen Modells + Lese-Protokoll | Architektur, Designfehler, fehlende Maßnahmen, Fälle ohne praktikablen Test |
| V4 | Gleiches Modell, frischer Kontext | keine | Antwort + Lese-Protokoll | Nur Vorfilter; zählt nicht als unabhängig |
| V5 | Mensch | Mensch | Notiz mit Name und Datum | Grenzfälle, Rechtsfragen, Risikoakzeptanz |

Grundsatz: **Ein Befund, für den der Verifier einen fehlschlagenden Test schreibt, ist mehr wert als jedes LLM-Urteil.** V1 ist deshalb für alle Befunde anzustreben, bei denen ein Test mit vertretbarem Aufwand möglich ist.

## 5.3 V1: Verifikation durch fehlschlagenden Test

Ablauf:
1. Der Verifier bekommt Ort, Behauptung und die betroffenen Dateien (über das Datei-Gateway), **nicht** die Begründung des Erstprüfers.
2. Er schreibt einen Test, der das behauptete Fehlverhalten auslöst. Der Test liegt außerhalb des geprüften Repos (`runs/<run_id>/verification/<finding_id>/`) und wird in eine Wegwerf-Kopie gelegt.
3. Der Test läuft in der Sandbox (`--allow-exec` erforderlich) am auditierten Commit.
4. Bewertung:
   - Test **schlägt fehl wie behauptet** (richtige Assertion, nicht Import- oder Syntaxfehler) → `verifiziert`, Methode `V1-test`.
   - Test **besteht** → Befund nicht bestätigt. `widerlegt` nur, wenn der Test das behauptete Szenario nachweislich vollständig abbildet; sonst `nicht prüfbar`.
   - Test läuft nicht (Setup fehlt) → `nicht prüfbar`, Grund festhalten.
5. Plausibilitätsprüfung gegen Schein-Tests: Der Fehlschlag muss aus einer Assertion stammen, die sich auf das behauptete Verhalten bezieht. Der Orchestrator prüft maschinell, dass der Fehlschlag kein Collection-, Import- oder Timeout-Fehler ist (JUnit-`failure` statt `error`). Stichprobenhaft prüft ein Mensch, ob der Test tatsächlich das Richtige testet.
6. Der Test wird als Regressionstest-Vorschlag an den Befund gehängt. Nach einem Fix muss er bestehen.

Bei Nebenläufigkeitsfehlern wird der Test mehrfach ausgeführt (z. B. 50 Wiederholungen); verifiziert ist der Befund, wenn er mindestens einmal reproduzierbar fehlschlägt und das Protokoll den Fehlschlag zeigt.

## 5.4 V2: Verifikation durch Werkzeug

Ein KI-Befund gilt als V2-verifiziert, wenn ein deterministisches Werkzeug **unabhängig** denselben Fehler an derselben Stelle meldet (Fingerprint-Abgleich oder Ortsüberlappung + passende Regel). Ein Werkzeugbefund, den ein KI-Prüfer nur wiederholt, ist umgekehrt kein zusätzlicher Beleg.

Der Verifier darf auch gezielt ein Werkzeug mit einer neuen, für diesen Befund geschriebenen Regel ausführen (z. B. eine Semgrep-Regel). Die Regel wird als Beleg abgelegt.

## 5.5 V3: Verifikation durch anderes Modell, blind

Wenn weder Test noch Werkzeug möglich sind:
- **Anderes Modell:** möglichst eine andere Modellfamilie bzw. ein anderer Anbieter. Mindestens ein anderes Modell als der Erstprüfer. Anbieter und Modell-ID stehen im Befund und im Manifest.
- **Blind:** Der Verifier bekommt nur die Frage („Ist an `src/auth/session.ts:85-103` die Sitzung nach dem Logout weiter gültig? Belege mit Zitat.“), nicht die Antwort des Erstprüfers, nicht dessen Schweregrad, nicht dessen Begründung.
- **Gleiche Werkzeuge:** Zugriff nur über das Datei-Gateway, damit auch seine Lektüre protokolliert ist.
- **Eigene Belege:** Seine Antwort muss eigene Zitate enthalten, die maschinell gegen die Dateien geprüft werden.
- **Ergebnis:** Stimmen beide überein und sind beide Zitate gültig → `verifiziert` (V3). Widersprechen sie sich → `nicht prüfbar` mit beiden Positionen; Entscheidung durch Mensch (V5) oder späteren Test (V1).

Ist kein anderes Modell verfügbar, wird mit V4 gearbeitet und der Befund ausdrücklich als `independence: "keine"` gekennzeichnet. Ob das für ein Profil reicht, legt das Gate fest (in `release-produktiv` nicht).

## 5.6 Gezielte Suche nach übersehenen Fehlern

Verifikation heißt nicht nur, gemeldete Befunde zu prüfen. Der Verifier bekommt zusätzlich einen Auftrag zur **Gegensuche**:
- Dateien mit hoher Relevanz und niedriger Abdeckung im Lese-Protokoll
- Prüfpunkte, die `UNKNOWN` sind, obwohl ein Test möglich wäre
- Stichprobe von Dateien, in denen ein Prüfer „keine Befunde“ gemeldet hat

Ergebnisse der Gegensuche sind neue Befunde mit `origin.name: "verifier"` und durchlaufen selbst die Verifikation durch eine andere Instanz.

## 5.7 Regeln

1. Kein `verifiziert` ohne `evidence_sha256`.
2. Kein Befund wird durch den Verifier gelöscht. Widerlegung braucht einen Beleg (Test, der besteht und das Szenario abdeckt, oder ein Zitat, das die Behauptung widerlegt).
3. Der Verifier sieht nie die Begründung des Erstprüfers (V3) und nie das Ergebnis eines anderen Verifiers für denselben Befund.
4. Eine Herabstufung des Schweregrads ist eine Zustandsänderung mit Eintrag in `history`, Grund und Urheber.
5. Verifikation läuft am selben Commit wie das Audit. Ein Befund, der an einem anderen Commit verifiziert wurde, gilt als `nicht nachgeprüft`.
6. Kosten werden gemessen (Zeit, Tokens je Befund und Methode), damit das Verhältnis von Nutzen und Aufwand im Benchmark sichtbar wird.
