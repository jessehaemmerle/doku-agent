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
  netbox_plan.py   Plan-Validierung (Endpunkt-/Aktions-Allowlist, Referenzen) und Ausführung mit Rollback
  discovery.py     Intune/Wazuh-Inventar, Zusammenführung, Netbox-Abgleich, Plan-Erzeugung
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

## Bewusst nicht umgesetzt

- Drift-Erkennung für bereits bekannte Netbox-Objekte.
- Wazuh-Alarmberichte aus dem Indexer.
- Wiki.js 3.x und Visual-Editor-Seiten.
- Bildauswertung.
