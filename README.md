# doku-agent

Lokaler KI-Agent, der IT-Dokumentation erzeugt und in **Wiki.js** pflegt – mit Fokus auf
**Netbox** (Maschinen erkennen und eintragen), **Wazuh** (eigene Regeln, Decoder, Konfiguration, SCA)
und **Intune** (Richtlinien, Profile, Apps), aber auch für beliebige andere Themen aus Stichpunkten und Dateien.

- **Komplett lokal:** Das Sprachmodell läuft per [Ollama](https://ollama.com) auf deiner Maschine.
  Der Agent darf nur die konfigurierten Hosts erreichen; alles andere wird vor dem Senden blockiert.
- **Nichts ohne Freigabe:** Jede Wiki-Änderung und jeder Netbox-Eintrag landet zuerst als Vorschlag
  (mit Diff bzw. Schritt-Plan) in einer Freigabe-Liste.
- **Hält sich an eure Konventionen:** Es gibt keine geschriebenen Regeln? Der Agent lernt sie aus den
  bestehenden Seiten eines Bereichs (Tags, wiederkehrende Abschnitte, Pfad-Schreibweise).
- **Ergänzt statt zu überschreiben:** Bestehende Seiten werden erweitert. Von Hand geschriebener Text
  bleibt unangetastet.

```
               ┌──────────── Docker Compose ────────────────────────────┐
  Browser ───▶ │  agent (Web-UI, CLI, Worker, Zeitplan)                 │
  localhost    │     │  Netz "llm" (intern, kein Internet)               │
               │     └──────────▶ ollama (qwen3:8b, CPU)                 │
               │     │  Netz "lan"                                        │
               └─────┼────────────────────────────────────────────────────┘
                     ├──▶ Wiki.js 2.x  (GraphQL, lesen + schreiben nach Freigabe)
                     ├──▶ Netbox 4.x   (REST, Discovery + Anlegen nach Freigabe)
                     ├──▶ Wazuh 4.x    (Server-API, nur lesend)
                     └──▶ Microsoft Graph (Intune, nur lesend, optional)
```

## Was der Agent kann

| Bereich | Was passiert | Ergebnis |
|---|---|---|
| **Netbox-Discovery** | Liest Geräte aus Intune und Wazuh-Agents (Seriennummer, Hostname, MACs, IPs, OS), führt sie zusammen und gleicht mit Netbox ab | Pro fehlender Maschine ein **Netbox-Plan** (Hersteller, Gerätetyp, Plattform, Gerät/VM, Interfaces, MACs, IPs, primäre IP). Nach Freigabe wird angelegt und automatisch ein **Steckbrief** im Wiki vorgeschlagen |
| **Netbox-Steckbriefe** | Gerät/VM aus Netbox mit Interfaces und IPs | Wiki-Seite pro Maschine; der Netbox-Teil wird bei Änderungen aktualisiert |
| **Wazuh-Regeln/Decoder** | Liest `etc/rules` bzw. `etc/decoders`, parst das XML | Seite pro Datei: Übersicht, Regel-Tabelle (Level, Bedingungen, MITRE) und Erläuterung jeder Regel durch das LLM |
| **Wazuh-Konfiguration** | `ossec.conf` des Managers und `agent.conf` jeder Gruppe | Zusammenfassung und Einstellungen je Abschnitt; Passwörter, API-Keys und Webhooks werden maskiert |
| **Wazuh-SCA** | SCA-Ergebnisse aller (oder ausgewählter) Agents | Score je Richtlinie und fehlgeschlagene Prüfungen mit Behebung |
| **Intune** | Compliance-Richtlinien, Konfigurationsprofile, Settings Catalog, Apps | Seite je Richtlinie mit Beschreibung, Zuweisungen (Gruppennamen) und allen Einstellungen; App-Übersicht |
| **Freie Doku** | Stichpunkte und Dateien (TXT, Config, Log, CSV/JSON/XML/YAML, PDF, DOCX) | Der Agent sucht eine passende bestehende Seite und ergänzt sie, oder legt eine neue im passenden Bereich an |

## Installation

Voraussetzungen: Linux-Host mit Docker und Docker Compose, **16 GB RAM** (CPU genügt), Netzzugriff auf Wiki.js,
Netbox und Wazuh.

```bash
git clone <dieses-repo> doku-agent && cd doku-agent
cp config.example.yaml config.yaml     # URLs, Standort, Zeitplan anpassen
cp .env.example .env                   # Tokens und Passwörter eintragen
docker compose --profile setup run --rm ollama-pull   # Modell einmalig laden (ca. 5 GB)
docker compose up -d
docker compose exec agent doku-agent check            # Verbindungen prüfen
```

Danach ist die Oberfläche unter <http://127.0.0.1:8080> erreichbar (Benutzer `admin`, Passwort aus `WEB_PASSWORD`).
Für Zugriff aus dem LAN die Port-Bindung in `docker-compose.yml` anpassen.

### Zugänge einrichten

**Wiki.js** – *Administration › API-Zugriff*: API aktivieren und einen Schlüssel anlegen. Der Schlüssel braucht eine
Gruppe mit `read:pages`, `read:source` und `write:pages` (oder vollen Zugriff). Wichtig: Der Agent arbeitet mit
dem **Markdown-Editor**. Seiten im Visual Editor (HTML) werden erkannt und übersprungen.

**Netbox** – eigenen Benutzer `doku-agent` anlegen, Token erzeugen (v1 oder v2 `nbt_…`, beides wird unterstützt).
Rechte: Anzeigen auf DCIM/IPAM/Virtualization, Anlegen/Ändern für Geräte, Gerätetypen, Hersteller, Rollen,
Plattformen, Interfaces, MAC-Adressen, IP-Adressen und VMs. Löschen wird nur für das Rollback eines
fehlgeschlagenen Plans benötigt. Alle Änderungen stehen im Netbox-Changelog unter diesem Benutzer.
In `config.yaml` muss `netbox.site` auf einen existierenden Standort zeigen.

**Wazuh** – API-Benutzer mit Leserechten (z.B. Rolle `readonly`) auf dem Manager (Port 55000).

**Intune (optional)** – App-Registrierung in Entra ID mit Client-Secret und den **Anwendungsberechtigungen**
`DeviceManagementManagedDevices.Read.All`, `DeviceManagementConfiguration.Read.All`,
`DeviceManagementApps.Read.All` sowie optional `Group.Read.All` (Gruppennamen in Zuweisungen). Admin-Zustimmung
erteilen und `intune.enabled: true` setzen. Der Agent stellt ausschließlich GET-Anfragen. Die Daten werden nur
gelesen und lokal verarbeitet.

Mit interner CA: Zertifikat nach `./ca.pem` legen, Volume in `docker-compose.yml` einkommentieren und
`verify_tls: /config/ca.pem` setzen.

## Arbeiten mit dem Agent

**Web-Oberfläche**
- *Freigaben*: offene Vorschläge mit Diff (Wiki) bzw. Schritt-Plan (Netbox). Vor dem Übernehmen lassen sich
  Titel, Pfad, Tags und Inhalt bzw. der Netbox-Plan (JSON) bearbeiten. *Ablehnen + Nicht mehr vorschlagen*
  setzt das Objekt auf die Ignorierliste.
- *Neuer Auftrag*: Stichpunkte und Dateien hochladen, optional eine Zielseite angeben.
- *Jobs*: Läufe starten und Protokolle ansehen. Jobs laufen nacheinander, damit das Modell die CPU nicht doppelt
  belegt.
- *Konventionen*: zeigt, was der Agent je Wiki-Bereich gelernt hat.
- *Status*: Verbindungstest, erlaubte Hosts und Ignorierliste.

**Kommandozeile** (im Container: `docker compose exec agent doku-agent …`)

```bash
doku-agent check                         # Verbindungen und Allowlist prüfen
doku-agent run discovery                 # Netbox-Discovery jetzt ausführen
doku-agent run wazuh_rules               # weitere: wazuh_decoders, wazuh_config, wazuh_sca, intune, netbox_devices
doku-agent run netbox_device --param id=42 --param kind=device
doku-agent doc "Backup der Fileserver" -f notizen.txt [-t infrastruktur/backup/fileserver]
doku-agent proposals                     # offene Vorschläge
doku-agent show 12                       # Vorschlag mit Diff
doku-agent approve 12 | doku-agent reject 12 --ignore
doku-agent conventions [bereich]         # gelernte Konventionen
```

**Zeitplan** – in `config.yaml` unter `schedule` (Uhrzeit in `general.timezone`). Ergebnisse der nächtlichen Läufe
liegen morgens in der Freigabe-Liste. Unveränderte Quellen erzeugen keine neuen Vorschläge, weil LLM-Texte nach
Eingabe-Hash zwischengespeichert werden und Seiten ohne Änderung übersprungen werden.

## So ergänzt der Agent bestehende Seiten

Abschnitte, die der Agent aus Quelldaten erzeugt (z.B. der Netbox-Steckbrief), stehen zwischen unsichtbaren Markern:

```markdown
## Steckbrief

<!-- doku-agent:begin netbox-device -->
| Eigenschaft | Wert |
…
<!-- doku-agent:end netbox-device -->

## Notizen        ← von Hand geschrieben, bleibt immer erhalten
```

- Bei Aktualisierungen ersetzt der Agent **nur** den Inhalt zwischen seinen Markern. Fehlt ein Block, fügt er ihn
  unter der passenden Überschrift ein oder hängt einen neuen Abschnitt an.
- Bei freien Aufträgen darf das LLM nur **anhängen** oder **neue Abschnitte einfügen**, niemals löschen oder umschreiben.
- Wiki.js entfernt die Marker beim Rendern, Leser sehen sie nicht (getestet mit Wiki.js 2.5.315).
- Wurde die Seite nach dem Vorschlag im Wiki geändert, rechnet der Agent den Vorschlag auf der neuen Fassung neu
  und legt ihn erneut zur Prüfung vor, statt fremde Änderungen zu überschreiben.
- Beim Speichern werden alle Seiteneigenschaften (Veröffentlichung, CSS/JS, Tags) unverändert mitgeschickt. Wiki.js
  würde sie sonst zurücksetzen. Tags werden nur ergänzt, nie entfernt.
- Existiert zu einem Objekt schon eine Seite an anderer Stelle (gleicher Name im Pfad oder Titel), wird diese ergänzt.

## So lernt der Agent eure Konventionen

Für den Zielpfad einer Seite sucht der Agent den tiefsten Bereich (Pfad-Präfix), in dem es schon Seiten gibt, und leitet
daraus ab:

- **Tags**, die mindestens die Hälfte der Seiten trägt, werden übernommen.
- **Pflichtabschnitte**: `##`-Überschriften, die in mindestens 60 % der gelesenen Seiten vorkommen. Fehlen sie, werden sie
  als „Noch zu ergänzen“ angelegt.
- **Pfad-Schreibweise** (`kebab-case`, `snake_case`, gemischt).
- **Stilvorlage**: Gliederung der neuesten Seite des Bereichs geht als Vorbild in den Prompt.

Wohin welcher Doku-Typ gehört, steht in `wiki.paths`. Unter *Konventionen* in der Oberfläche siehst du, welche Bereiche es
gibt, und kannst die Pfade an eure Struktur anpassen.

## Netbox-Pläne

Ein Plan ist eine Liste nachvollziehbarer Schritte, z.B.:

```json
[
  {"ref": "mfr", "action": "ensure", "endpoint": "dcim/manufacturers", "lookup": {"slug": "dell"},
   "data": {"name": "Dell", "slug": "dell"}},
  {"ref": "dev", "action": "create", "endpoint": "dcim/devices",
   "data": {"name": "srv01", "device_type": "$dtype", "role": "$role", "site": 1, "serial": "ABC123"}},
  {"action": "update", "endpoint": "dcim/devices", "id": "$dev", "data": {"primary_ip4": "$ip0"}}
]
```

- Erlaubt sind nur `create`, `ensure` (anlegen, falls nicht vorhanden) und `update` auf einer festen Liste von
  Endpunkten (DCIM, IPAM, Virtualization). Löschen ist im Plan nicht möglich.
- Schlägt ein Schritt fehl, werden die in diesem Lauf angelegten Objekte wieder entfernt (Rollback).
- Abgleich mit Netbox über Seriennummer, Hostname und MAC-Adresse. Virtuelle Maschinen werden an Seriennummer bzw.
  Modell erkannt (`vm_serial_patterns`, `vm_model_patterns`) und als VM angelegt.
- Ab Netbox 4.2 werden MAC-Adressen als eigene Objekte angelegt, ältere 4.x-Versionen erhalten die MAC am Interface.

## Modell und Leistung (16 GB RAM, nur CPU)

| Modell | RAM | Einsatz |
|---|---|---|
| `qwen3:8b` (Standard) | ca. 6–7 GB inkl. 8k-Kontext | gute Texte und zuverlässiges JSON; einige Minuten pro Seite |
| `qwen3:4b` | ca. 3–4 GB | etwa doppelt so schnell, schwächer bei langen Erklärungen |

Modell wechseln: `llm.model` in `config.yaml` und `LLM_MODEL` in `.env` anpassen, dann
`docker compose --profile setup run --rm ollama-pull` und `docker compose restart agent`.
Strukturierte Daten (Tabellen, Steckbriefe, Netbox-Pläne) erzeugt der Agent immer deterministisch, das LLM schreibt
nur Erklärungen, Beschreibungen und freie Texte. So bleiben Fakten korrekt, auch wenn das kleine Modell schwächelt.

## Datenschutz und Sicherheit

- **Egress-Allowlist:** Jeder HTTP-Client des Agents prüft vor dem Senden, ob der Ziel-Host konfiguriert ist (Wiki,
  Ollama, Netbox, Wazuh, bei Intune `login.microsoftonline.com` und `graph.microsoft.com`). Weiterleitungen werden
  nicht verfolgt, Proxy-Variablen werden standardmäßig ignoriert.
- **Ollama ohne Internet:** Der Ollama-Container hängt nur am internen Netz `llm`. Zusätzlich ist
  `OLLAMA_NO_CLOUD=1` gesetzt (keine Cloud-Modelle, keine Websuche). Nur der einmalige `ollama-pull` hat Internet.
- **Geheimnisse:** Tokens nur in `.env` (nicht eingecheckt). In Wazuh-Konfigurationen und Intune-Einstellungen
  werden Passwörter, Keys, Tokens und Webhooks vor dem Prompt und vor dem Wiki maskiert.
- **Oberfläche:** Basic-Auth (Pflicht), CSRF-Schutz, strikte Content-Security-Policy, keine externen Skripte oder Fonts,
  standardmäßig nur auf `127.0.0.1` gebunden. Der Agent-Container läuft ohne Root, mit read-only Dateisystem und
  ohne Capabilities.
- **Zugriff aus dem LAN:** Basic-Auth überträgt das Passwort nur Base64-kodiert und es gibt kein Rate-Limiting.
  Wer die Oberfläche über `localhost` hinaus freigibt, sollte einen Reverse-Proxy mit TLS davorsetzen (z.B. den
  vorhandenen Nginx/Traefik) und den Zugriff auf das Admin-Netz beschränken.

## Entwicklung

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/pytest                      # Unit- und Komponententests (Fakes für Wiki.js, Netbox, LLM)
```

Integrationstests gegen echte Test-Instanzen (werden ohne Variablen übersprungen; nie gegen Produktion laufen lassen,
sie legen Testseiten bzw. Testobjekte an):

```bash
DOKU_IT_WIKI_URL=http://127.0.0.1:3000 DOKU_IT_WIKI_KEY=… \
DOKU_IT_NETBOX_URL=http://127.0.0.1:8000 DOKU_IT_NETBOX_TOKEN=nbt_… \
DOKU_IT_WAZUH_URL=https://127.0.0.1:55000 DOKU_IT_WAZUH_USER=… DOKU_IT_WAZUH_PASSWORD=… DOKU_IT_WAZUH_INSECURE=1 \
.venv/bin/pytest tests/test_integration_*.py
```

Aufbau und Entscheidungen: [docs/ARCHITEKTUR.md](docs/ARCHITEKTUR.md).

## Grenzen

- Wiki.js 3.x wird nicht unterstützt (andere API). Seiten im Visual Editor werden nicht bearbeitet.
- Discovery legt nur **fehlende** Maschinen an. Abweichungen bei bekannten Maschinen (z.B. neue IP) werden noch nicht
  gemeldet.
- Wazuh-Alarm-Auswertungen aus dem Indexer sind nicht enthalten (bewusst ausgeklammert).
- Bilder bzw. Screenshots in Aufträgen werden nicht ausgewertet (Vision-Modell auf CPU zu langsam).

## Lizenz

GPL-3.0, siehe [LICENSE](LICENSE).
