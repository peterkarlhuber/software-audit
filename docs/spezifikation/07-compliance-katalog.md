# 07 Compliance-Katalog (Phase 3)

## 7.1 Grundsatz

Ein Agent entscheidet nicht bei jedem Audit aus seinem Modellwissen neu, welche Vorschriften gelten. Stattdessen gibt es einen **zentralen, versionierten Katalog** mit eindeutigen Anforderungs-IDs, offiziellen Quellen, Fassungsständen und Anwendbarkeitsregeln.

Die Rollen sind klar verteilt:

| Aufgabe | Wer |
|---|---|
| Katalog pflegen (Quellen, Fassung, Fristen) | Mensch, mit KI-Unterstützung beim Entwurf; jede Änderung als Pull Request mit Quellenangabe |
| **Anwendbarkeit** einer Vorschrift auf ein Produkt festlegen | **Mensch** (verantwortliche Person, ggf. Jurist), mit Begründung und Datum |
| Belege sammeln, Lücken markieren, Kontrollmatrix vorbefüllen | KI-Prüfer und Werkzeuge |
| Bewertung „erfüllt / nicht erfüllt“ bei Rechtsfragen | Mensch; KI liefert nur einen Vorschlag mit Belegen |
| Rechtsverbindliche Konformitätsaussage | Verantwortliche Person bzw. externe Prüfstelle; nicht das System |

Ein LLM-Ergebnis allein führt nie zu einer Compliance-Freigabe.

## 7.2 Klein anfangen

Der Katalog startet nicht mit allen denkbaren Regelwerken, sondern nur mit dem, was für die konkreten Levuvo-Produkte nach menschlicher Prüfung tatsächlich gilt. Vorschlag für den ersten Ausbau:

1. **DSGVO**, technisch prüfbare Teile: Datenminimierung, Löschung, Sicherheit der Verarbeitung (Art. 32), Datenschutz durch Technikgestaltung (Art. 25), Protokollierung personenbezogener Daten.
2. **OWASP ASVS 5.0**, ausgewählte Kapitel als technische Prüfgrundlage (nicht gesetzlich verpflichtend, aber gut prüfbar).
3. **CRA Anhang I**, nur wenn die Anwendbarkeitsentscheidung für ein Produkt „anwendbar“ lautet.
4. **AI Act**, nur für Produkte mit eingebauten KI-Funktionen und erst nach Klassifikation durch einen Menschen.

Weitere Regelwerke (NIS2, DORA, Data Act, Produktsicherheit, Barrierefreiheit) kommen nur nach einer dokumentierten Anwendbarkeitsentscheidung dazu.

## 7.3 Katalogeintrag

```yaml
- id: DSGVO-ART17-LOESCHUNG-01
  regelwerk: DSGVO
  quelle:
    rechtsakt: "Verordnung (EU) 2016/679"
    fundstelle: "Art. 17 Abs. 1"
    url: "https://eur-lex.europa.eu/eli/reg/2016/679/oj"
    fassung: "ABl. L 119 vom 4.5.2016"
    geprueft_am: null              # Datum der letzten Prüfung gegen die Primärquelle
    geprueft_von: null
  art: gesetzlich                  # gesetzlich | standard | intern
  geltung:
    gilt_ab: "2018-05-25"
    zeitstatus: verbindlich        # verbindlich | kuenftig_verbindlich | best_practice
  anwendbarkeit_frage: "Verarbeitet das Produkt personenbezogene Daten von Nutzern, die ein Löschrecht haben?"
  anforderung_technisch: "Auf Löschanfrage werden alle personenbezogenen Daten des Nutzers einschließlich Anhängen, Indizes, Caches und Backups innerhalb der festgelegten Frist entfernt oder anonymisiert."
  pruefpunkte: [PRIV-DEL-001, PRIV-DEL-002]
  belege_erforderlich:
    - "Datenfluss-Inventar aller Speicherorte personenbezogener Daten"
    - "Test, der nach Löschung jeden Speicherort prüft"
  hinweis: "Rechtliche Ausnahmen (Art. 17 Abs. 3) bewertet ein Mensch."
```

Regeln:
- Jede Anforderung hat genau eine ID, die sich nie ändert. Inhaltliche Änderungen erzeugen einen neuen Fassungsstand im Katalog (Git-Historie), keine neue ID.
- Eine Anforderung ohne `quelle.url` und ohne `geprueft_am` darf im Profil `release-produktiv` nicht als Pflichtanforderung verwendet werden.
- Der Katalog-Stand (Git-Commit des Katalogs) steht im Run-Manifest.

## 7.4 Anwendbarkeitsentscheidung

Je Produkt und Regelwerk gibt es eine Entscheidung, die ein Mensch trifft:

```yaml
produkt: levuvo-mail
regelwerk: CRA
entscheidung: anwendbar            # anwendbar | nicht_anwendbar | offen
begruendung: "Wird als Desktop-Anwendung im EU-Markt bereitgestellt (auch kostenlos mit kommerziellem Bezug)."
entschieden_von: peter
entschieden_am: 2026-11-20
naechste_pruefung: 2027-05-20
quellen: ["Verordnung (EU) 2024/2847, Art. 2 und 3"]
```

- `offen` bedeutet: Alle Prüfpunkte dieses Regelwerks sind `UNKNOWN`, nicht `N/A`.
- `nicht_anwendbar` setzt die Prüfpunkte auf `N/A` und übernimmt Begründung, Person und Datum.
- Beispiele für typische Fehlannahmen, die der Katalog verhindern soll:
  - Die Nutzung von KI-Werkzeugen *zur Entwicklung* löst nicht automatisch Pflichten des AI Act *für das entwickelte Produkt* aus. Ein im Produkt eingebauter KI-Assistent muss dagegen nach Funktion, Zweck und eigener Rolle (Anbieter/Betreiber) geprüft werden.
  - Rein intern genutzte Software ist nicht automatisch ein Produkt, das im Sinne des CRA auf dem Markt bereitgestellt wird. Auch kostenlose Bereitstellung mit kommerziellem Bezug kann aber erfasst sein.

## 7.5 Zeitbezug

Ein Audit unterscheidet je Anforderung am Audit-Datum:

| Zeitstatus | Bedeutung im Gate |
|---|---|
| `verbindlich` | Pflicht, sofern anwendbar |
| `kuenftig_verbindlich` | Wird als Vorbereitungslücke berichtet; Gate-Wirkung je Profil (z. B. Warnung, ab 6 Monate vor Geltung Pflicht) |
| `best_practice` | Freiwillig, nur Bericht |
| `nicht_anwendbar` | `N/A` laut Anwendbarkeitsentscheidung |

Der Zeitstatus wird aus `gilt_ab` und dem Audit-Datum berechnet, nicht vom Modell eingeschätzt.

## 7.6 Fristen: vor Übernahme gegen Primärquellen prüfen

Die folgenden Angaben stammen aus dem Ausgangskonzept (Stand 20.11.2026). **Keine davon ist gegen die Primärquelle geprüft.** Sie dürfen erst in den Katalog, wenn eine Person sie im Amtsblatt (EUR-Lex) bzw. in der konsolidierten Fassung nachgeschlagen und `geprueft_am` gesetzt hat. Besonders die Verschiebungen durch den „Digital Omnibus“ hängen davon ab, ob und in welcher Fassung die Änderungsverordnung verabschiedet und veröffentlicht wurde.

| Regelwerk | Angabe im Konzept | Primärquelle | Status |
|---|---|---|---|
| DSGVO | Gilt bei Verarbeitung personenbezogener Daten | VO (EU) 2016/679 | ⚠ zu verifizieren |
| AI Act | Weitere zentrale Vorschriften gelten seit 02.08.2026 | VO (EU) 2024/1689, Art. 113 | ⚠ zu verifizieren |
| AI Act | Hochrisiko-Regeln für Anhang-III-Systeme ab 02.12.2027 (nach Digital Omnibus) | Änderungsverordnung „Digital Omnibus“, Fundstelle im ABl. noch zu ermitteln | ⚠ zu verifizieren, insbesondere ob in Kraft |
| AI Act | Produktintegrierte Hochrisiko-KI ab 02.08.2028 (nach Digital Omnibus) | wie oben | ⚠ zu verifizieren, insbesondere ob in Kraft |
| CRA | Meldepflichten seit 11.09.2026 | VO (EU) 2024/2847, Art. 14 und Art. 71 | ⚠ zu verifizieren |
| CRA | Wesentliche weitere Pflichten ab 11.12.2027 | VO (EU) 2024/2847, Art. 71 | ⚠ zu verifizieren |

Technische Standards als Prüfgrundlage (nicht automatisch gesetzlich verpflichtend): NIST SSDF SP 800-218, OWASP ASVS 5.0, OWASP WSTG, OWASP SAMM, NIST AI RMF, ISO/IEC 42001, ISO/IEC 27001/27002, WCAG 2.2 AA. Auch hier wird die verwendete Version im Katalog festgehalten.

## 7.7 Zusätzliche Rollen in Phase 3

| Rolle | Arbeitet gegen | Liefert |
|---|---|---|
| Privacy & DSGVO | Katalogeinträge `DSGVO-*` mit Entscheidung `anwendbar` | Kontrollmatrix mit Belegen und Lücken |
| AI Governance | `AIA-*`, nur nach menschlicher Klassifikation | Belege zu Transparenz, Protokollierung, menschlicher Aufsicht, Agentenrechten |
| CRA & Regulatory | `CRA-*` | Matrix zu Anhang I, SBOM, Schwachstellenbehandlung, Update-Mechanismus |

Diese Rollen bekommen nur die anwendbaren Katalogeinträge als Auftrag, nicht „prüfe DSGVO“. Ihre Ergebnisse sind Vorschläge mit Belegen; der Status `PASS` für eine gesetzliche Anforderung braucht eine menschliche Bestätigung (V5).
