# Architektur und Entscheidungen

## Festgelegte Anforderungen (Interview vom 19.10.2026)

| Thema | Entscheidung | Folge für die Umsetzung |
|---|---|---|
| Hardware | nur CPU, 16 GB RAM | Ollama mit `qwen3:8b` (Q4), 8k-Kontext, ein Job gleichzeitig; Fakten deterministisch, LLM nur für Prosa |
| Wiki | Wiki.js 2.x, Markdown-Editor | GraphQL-API; abschnittsweises Mergen mit Markern |
| Netbox | Agent trägt selbst ein (4.x) | Schritt-Plan mit Freigabe, Rollback, eigener Service-User |
| Netbox-Datenquelle | Auto-Discovery aus Intune + Wazuh | Abgleich über Seriennummer, Hostname, MAC; Ignorierliste |
| Intune | Graph API nur lesend | App-Registrierung, `*.Read.All`; Graph-Hosts auf der Allowlist |
| Wazuh | eigene Regeln/Decoder, Konfiguration, SCA | Wazuh-Server-API; keine Indexer-Auswertungen |
| Wiki-Regeln | nur implizit | Konventionen werden aus bestehenden Seiten gelernt |
| Schreiben | alles mit Freigabe | Freigabe-Liste mit Diff, Bearbeiten vor dem Übernehmen |
| Bedienung | Web-UI + CLI | FastAPI/Jinja2 ohne externe Ressourcen; argparse-CLI |
| Betrieb | Docker Compose auf Linux, nächtlich | interner Scheduler; Ollama im internen Netz |
| Freie Doku | Text + Dateien, keine Bilder | Textextraktion lokal (pypdf, python-docx), Map-Reduce bei langen Eingaben |
| Netbox-Abgleich (20.10.2026) | fehlende Angaben, OS/VM, Netzwerk, Umbenennung; IPs für alle Maschinen; veraltete IPs nur melden; Freigabe je Änderung; keine automatische Ausnahme | `netbox_sync.py`, Auswahl + Konfliktprüfung in `apply.py`, Feld-Rollback in `netbox_plan.py` |

## Module

```
src/doku_agent/
  config.py        YAML-Konfiguration mit ${ENV}-Platzhaltern
  egress.py        HTTP-Clients nur zu erlaubten Hosts (Allowlist, keine Redirects, kein Proxy)
  llm.py           Ollama /api/chat, Structured Outputs (JSON-Schema), think=false, Map-Reduce
  wiki.py          Wiki.js-2-GraphQL: list, single, singleByPath, search, create, update
  markdown.py      Abschnitte, verwaltete Blöcke, sichere Ergänzungs-Operationen, Diff, Tabellen
  conventions.py   Bereichs-Profile: Tags, Pflichtabschnitte, Pfad-Stil, Beispielseiten, ähnliche Seiten
  pages.py         Seiten-Entwurf -> Vorschlag (neu oder Ergänzung), Pfadvorlagen, Ignorierliste
  store.py         SQLite: Vorschläge, Jobs, Ignorierliste, Cache (LLM-Texte nach Eingabe-Hash)
  apply.py         Freigegebene Vorschläge ausführen, Konflikterkennung, Neuberechnung
  netbox_plan.py   Plan-Validierung (Endpunkt-/Aktions-Allowlist, Referenzen), Ausführung mit Rollback (Löschen + Feld-Restore)
  discovery.py     Intune/Wazuh-Inventar, Zusammenführung, Netbox-Index, Plan für neue Maschinen
  netbox_sync.py   Abweichungen bekannter Maschinen als einzeln freigebbare Änderungen (Vorher/Nachher, Abhängigkeiten)
  connectors/      netbox.py, wazuh.py, intune.py
  generators/      wazuh_docs, intune_docs, netbox_docs, freeform, common (Maskierung, Cache, Stil)
  jobs.py          Job-Registry, Job-Log, Worker-Thread
  scheduler.py     Tages-Zeitplan
  web/             FastAPI-App, Templates, CSS
  cli.py           Kommandozeile
```

Datenfluss eines Laufs: **Quelle → Generator → `PageDraft` → `propose_page` → Freigabe-Liste → `apply` → Wiki.js/Netbox**.

## Gegen Quellen verifizierte Schnittstellen

| Schnittstelle | Geprüft gegen | Wichtige Details |
|---|---|---|
| Wiki.js GraphQL | `server/graph/schemas/page.graphql`, `server/models/pages.js` @ v2.5.315, echter Server im Test | `update` setzt nicht übergebene Felder zurück (isPublished, CSS/JS, Publish-Zeitraum) → immer alle Werte senden. HTML-Kommentare werden beim Rendern entfernt. |
| Netbox REST | Serializer/Filtersets @ 4.7.3 | `role` statt `device_role`; MAC-Objekte (`dcim/mac-addresses`) ab 4.2; v2-Tokens `nbt_…` als Bearer; `?address=` matcht Host unabhängig von der Maske |
| Wazuh API | `api/api/spec/spec.yaml` @ v4.14.9 | `POST /security/user/authenticate` (Basic) → JWT; `raw=true` für Dateien; `relative_dirname` filtert eigene Regeln |
| Microsoft Graph | Microsoft Learn | `managedDevices` (v1.0, `ethernetMacAddress` nur per Einzelabfrage); Settings Catalog nur `/beta` mit `$expand=settingDefinitions` |
| Ollama | `docs/api.md`, `envconfig` @ v0.34.4 | `format` = JSON-Schema, `think: false`, `OLLAMA_NO_CLOUD=1` |

## Ende-zu-Ende geprüft (19.10.2026)

Mit dem ausgelieferten `docker-compose.yml` und echten Diensten: Wiki.js 2.5.315, Netbox 4.7.2 (v2-Token),
Wazuh-Manager 4.14.0, Ollama 0.34.4 mit `qwen3:8b`, Rechner mit 4 CPU-Kernen ohne GPU.

| Ablauf | Ergebnis |
|---|---|
| Ollama-Container ohne Internet | Namensauflösung externer Hosts schlägt fehl; Log: `Ollama cloud disabled: true` |
| Speicherbedarf `qwen3:8b`, 8k-Kontext | ca. 6,5 GB |
| Freier Auftrag → neue Seite | 1:23 min; Gliederung und Tags des Bereichs übernommen, nur Fakten aus den Notizen |
| Freier Auftrag → bestehende Seite ergänzen | 2:36 min; richtige Seite gewählt, nur neue Abschnitte angehängt |
| Freigabe im Browser → Wiki.js | Seite angelegt; Veröffentlichung, Tags und Beschreibung korrekt |
| Discovery (Wazuh) → Netbox-Plan → Freigabe | Gerät, Interface, MAC-Objekt, IP und primäre IPv4 angelegt; Steckbrief-Job folgt automatisch |
| Fehler im Plan | Rollback entfernt alle in diesem Lauf angelegten Objekte |

Im Test gefundene und behobene Fehler: endlose Generierung ohne `num_predict`; Wazuh lehnt `select=os` und Paging bei
`syscollector/*/hardware|os` ab; Konventionen eines Nachbarordners wurden auf leere Zielordner übertragen; LLM erfand
neue Tags. Für jeden Fall gibt es einen Test.

Ein anschließendes Code-Review fand zehn weitere Schwachstellen, alle behoben und in
`tests/test_review_regressions.py` abgesichert: u.a. Inhaltsverlust, wenn eine Seite zwischen Vorschlag und Freigabe
angelegt wird; abgeschnittene JSON-Antworten am Tokenlimit; HTTP-Clients pro Job; Code-Fences in Rohnotizen;
Überschreiben von Hand bearbeiteter Vorschläge durch nächtliche Läufe.

## Netbox-Abgleich geprüft (20.10.2026)

Gegen Netbox 4.7.2, Wazuh-Manager 4.14.0 und Wiki.js 2.5.315: Maschine per Discovery angelegt, in Netbox von Hand
umbenannt, Plattform verfälscht und primäre IP entfernt. Der nächste Lauf erkennt die Maschine über die MAC und schlägt
drei Änderungen vor. In der Oberfläche wird die Umbenennung abgewählt; Plattform und primäre IP werden übernommen, der
Steckbrief-Job läuft automatisch, und die bestehende Wiki-Seite übernimmt den neuen Titel (keine zweite Seite). Der
Folgelauf schlägt nur noch die abgewählte Umbenennung vor. Integrationstests decken zusätzlich IP-Wechsel, neue NIC,
Konfliktschutz bei Handänderung und Feld-Rollback ab.

Dabei gefunden und behoben: Netbox-Slugs erlauben keine Punkte (`ubuntu-24.04` scheiterte, betraf auch das Anlegen);
MAC-Vergleich war von der Schreibweise abhängig.

## Bewusst nicht umgesetzt

- Status-Pflege (z.B. offline nach längerer Funkstille) und Löschen in Netbox.
- Wazuh-Alarmberichte aus dem Indexer.
- Wiki.js 3.x und Visual-Editor-Seiten.
- Bildauswertung.
