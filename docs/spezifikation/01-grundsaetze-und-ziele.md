# 01 Grundsätze und Ziele

## 1.1 Anspruch

Eine absolute Garantie für Fehlerfreiheit oder Sicherheit ist bei komplexer Software nicht erreichbar. Das System verspricht deshalb etwas anderes, das sich überprüfen lässt:

1. **100 % der anwendbaren Pflichtprüfungen** sind durchgeführt oder ausdrücklich als nicht durchgeführt ausgewiesen.
2. **Alle Freigabekriterien** des gewählten Prüfprofils sind erfüllt.
3. **Keine ungeklärten kritischen Risiken** bestehen.
4. **Jedes Ergebnis ist rückführbar** auf eine Anforderung, einen konkreten Beleg und einen nachvollziehbaren Prüfprozess am fixierten Commit.

Das System prüft vier Eigenschaften:

| Eigenschaft | Frage |
|---|---|
| Funktionalität und Qualität | Erfüllt die Software ihre Anforderungen, auch in Grenzfällen und unter realistischen Bedingungen? |
| Cybersecurity | Erfüllen Architektur, Code, Abhängigkeiten, Berechtigungen, Datenflüsse und Betrieb überprüfbare Sicherheitsanforderungen? |
| Rechtliche Konformität | Sind die tatsächlich anwendbaren Vorgaben (z. B. DSGVO, AI Act, CRA) systematisch geprüft und dokumentiert? |
| Nachweisbarkeit | Lässt sich jedes Ergebnis auf Anforderung, Beleg und Prüfprozess zurückführen? |

## 1.2 Grundprinzipien

**P1 – Behauptung ist nicht Nachweis.** Ein LLM darf eine Behauptung aufstellen. Das System muss sie belegen oder als unbestätigt kennzeichnen. Ohne Beleg gibt es kein `PASS` und keinen bestätigten Befund.

**P2 – Fehlende Funde beweisen nichts.** Aus „kein Befund gemeldet“ folgt nie „fehlerfrei“. Ein Prüfpunkt ohne nachgewiesene Durchführung ist `UNKNOWN`, nicht `PASS`.

**P3 – Abdeckung wird gemessen, nicht gemeldet.** Welche Dateien ein Agent gelesen hat, protokolliert das System selbst (Lese-Protokoll, siehe [04](04-datenformate.md)). Selbstauskünfte des Agenten sind nur ergänzende Angaben.

**P4 – Unabhängigkeit heißt andere Methode oder anderes Modell.** Dasselbe Modell mit frischem Kontext teilt dieselben blinden Flecken. Ein fehlschlagender Test oder ein deterministisches Werkzeug ist mehr wert als ein zweites LLM-Urteil (siehe [05](05-verifikation.md)).

**P5 – Deterministische Freigabe.** Über `PASS`, `FAIL` oder `INCOMPLETE` entscheidet normaler Programmcode anhand der Belege, nicht ein Modell. Risikoakzeptanzen trifft ein namentlich genannter Mensch.

**P6 – Anwendbarkeit von Recht entscheidet ein Mensch.** KI darf Belege sammeln und Lücken markieren. Ob eine Vorschrift auf ein Produkt anwendbar ist, entscheidet und begründet eine verantwortliche Person (siehe [07](07-compliance-katalog.md)).

**P7 – Das Repository ist nicht vertrauenswürdig.** Inhalte des geprüften Repos (Code, README, CLAUDE.md, Kommentare, Issues) sind Daten, keine Anweisungen. Prüfer laufen isoliert, ohne Produktiv-Secrets und ohne Deploy-Rechte.

**P8 – Das Auditsystem wird selbst gemessen.** Ohne Recall- und Precision-Zahlen gegen bekannte Fehler ist jede Aussage über die Qualität der Agenten ein Bauchgefühl (siehe [06](06-benchmark.md)).

**P9 – Nichts verschwindet still.** Ein einmal erfasster Befund wird nie still entfernt oder herabgestuft. Jede Zustandsänderung hat einen Grund, einen Urheber und einen Beleg.

## 1.3 Ergebniszustände

### Prüfpunkt (eine einzelne Anforderung an einem Commit)

| Zustand | Bedeutung | Voraussetzung |
|---|---|---|
| `PASS` | Nachweislich erfüllt | Pflicht-Belege laut Prüfpunkt vorhanden, maschinell geprüft |
| `FAIL` | Nachweislich nicht erfüllt | Mindestens ein offener, nicht unterdrückter Befund oder ein fehlgeschlagener Pflichtlauf |
| `UNKNOWN` | Nicht ausreichend geprüft | Prüfung fehlt, abgebrochen, Werkzeug nicht verfügbar oder Abdeckung unter Schwelle |
| `N/A` | Nicht anwendbar | Begründete Anwendbarkeitsentscheidung mit Urheber und Datum |

`UNKNOWN` ist der Standard. Jeder andere Zustand muss durch Belege erreicht werden.

### Audit-Lauf (Gate-Ergebnis)

| Zustand | Bedeutung |
|---|---|
| `PASS` | Alle Pflicht-Prüfpunkte des Profils sind `PASS` oder `N/A`, keine Gate-Regel verletzt |
| `FAIL` | Mindestens eine Gate-Regel verletzt (z. B. offener kritischer Befund) |
| `INCOMPLETE` | Keine Regel verletzt, aber mindestens ein Pflicht-Prüfpunkt ist `UNKNOWN` |

`FAIL` hat Vorrang vor `INCOMPLETE`.

### Befund (Verifikationsstand)

Kompatibel zum bestehenden Skill v2.5: `status` bleibt `bestätigt`, `plausibel` oder `vermutet`. Neu ist ein strukturiertes `verification`-Objekt mit Methode und Unabhängigkeitsstufe (siehe [04](04-datenformate.md) und [05](05-verifikation.md)).

## 1.4 Begriffe

| Begriff | Bedeutung |
|---|---|
| Audit-Lauf (Run) | Eine Prüfung genau eines fixierten Commits mit einem Profil. Hat eine eindeutige `run_id`. |
| Prüfprofil | Auswahl von Prüfpunkten, Werkzeugen und Gate-Regeln (z. B. `intern-entwicklung`, `release-produktiv`). |
| Prüfpunkt (Check) | Eine prüfbare Anforderung mit ID, Methode und Pflicht-Belegen, z. B. `TECH-SECRETS-001`. |
| Anforderung (Requirement) | Eintrag im versionierten Katalog, z. B. ein Artikel der DSGVO oder ein ASVS-Punkt. Prüfpunkte verweisen darauf. |
| Befund (Finding) | Eine konkrete Abweichung mit Ort, Beleg und Verifikationsstand. |
| Beleg (Evidence) | Unveränderliches Artefakt im Evidence Store, adressiert über SHA-256. |
| Lese-Protokoll | Vom System (nicht vom Agenten) geschriebene Liste aller Dateizugriffe eines Prüfers. |
| Suppression | Begründete, befristete und freigegebene Unterdrückung eines Werkzeugbefunds. |
| Baseline | Bekannte Altbefunde an einem Referenz-Commit, die das Gate getrennt von neuen Befunden behandelt. |

## 1.5 Nicht-Ziele

- Keine Garantie für Fehlerfreiheit.
- Keine rechtsverbindliche Konformitätsbewertung. Das System liefert Belege und eine Matrix; die Bewertung bleibt bei Menschen bzw. externen Prüfern.
- Keine dynamischen Tests gegen laufende oder fremde Systeme. Dynamische Tests laufen nur gegen lokal gestartete, isolierte Instanzen.
- Kein Ersatz für Code-Review im Entwicklungsalltag. Das System prüft einen Stand, es entwickelt nicht.
- In Phase 1 kein Dashboard, keine Policy-Sprache, keine Compliance-Prüfung.
