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
| Firewall (20.10.2026) | nur FortiGate; Regeln + NAT, Objekte, Interfaces/VLANs/Routen, VPN; Erklärung je Regel wie bei Wazuh | `connectors/fortigate.py` (REST, nur GET), `generators/fortigate_docs.py`, fünf Seiten je Firewall/VDOM |
| Entra-Gruppen (20.10.2026) | Mitgliederzahlen nur auf einer Übersichtsseite, Richtlinien-Seiten zeigen Name und Art | `IntuneClient.group/member_counts` (`$count`, `ConsistencyLevel: eventual`), `document_groups` |
| Netbox-Custom-Fields (20.10.2026) | Agent legt Felder nach Freigabe an; IDs mit Freigabe; `last_seen` automatisch (einzige Ausnahme) | `netbox_fields.py`, ID-Treffer vor Seriennummer/Name/MAC in `NetboxIndex.find`, Kategorie „Kennung“ |
| Embeddings (20.10.2026) | `qwen3-embedding:0.6b` über dasselbe Ollama; Fragen in UI und CLI | `embeddings.py`, `semantic.py` (Index in SQLite, numpy-Suche), freie Aufträge nutzen semantische Kandidaten |
| Wiki-Lint (20.10.2026) | Bericht in UI und als Wiki-Seite; veraltete Seiten → Aktualisierungs-Vorschlag | `lint.py`, Zuordnung Seite ↔ Quelle über `page-for:<stable_id>` |
| Lint-Korrekturen (20.10.2026) | tote Links und fehlende Tags als Vorschlag mit Diff | `lint.suggest_target`/`suggest_tags`, `markdown.replace_links` (nur außerhalb von Code und Agent-Blöcken), bei Konflikt in `apply.py` neu angewendet |
| vCenter (20.10.2026) | Cluster + VMs, ESXi-Hosts als Geräte, auch ausgeschaltete VMs, Disks einzeln | `connectors/vcenter.py` (Automation-API + VI/JSON für Host-Hardware), `vcenter_inventory.py` als dritte Discovery-Quelle, Kategorie „vCenter“ im Abgleich |
| Switches (20.10.2026) | SNMP, herstellerunabhängig; Kabel aus LLDP + MAC-Tabelle, Endgeräte nur bei genau einer MAC am Port | `connectors/snmp.py` (pysnmp, Allowlist), `switches.py`, ein Vorschlag je Switch |
| FortiGate → Netbox (20.10.2026) | Gerät + Interfaces, IPs, VLANs, Präfixe, alles mit Freigabe | `fortigate_netbox.py`, Job `fortigate_netbox` |
| Abdeckung (20.10.2026) | Wazuh auf Servern und Clients, Intune auf Clients, Netbox für alles, Funkstille 30 Tage | `coverage.py`, nach jeder Discovery, Seite ohne Datum |
| Firewall im Steckbrief / Prüfung (20.10.2026) | Regeln über Host-, Bereichs-, VIP-Objekte und Netze bis /24; Hygiene-Check als eigene Seite je Firewall | `fortigate_docs.machine_rules`, `fortigate_docs.audit` (Intervall-Mengen für Adressen und Dienste) |

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
  discovery.py     Intune/Wazuh/vCenter-Inventar, Zusammenführung, Netbox-Index, Plan für neue Maschinen
  vcenter_inventory.py  vCenter-Hosts und VMs als Assets, Cluster-Schritte
  switches.py      SNMP-Daten -> Switch, Ports und Kabel (LLDP, MAC-Tabelle) als Änderungen
  fortigate_netbox.py   FortiGate -> Gerät, Interfaces, IPs, VLANs, Präfixe als Änderungen
  coverage.py      Abdeckungsbericht (Wazuh, Intune, Netbox, Funkstille)
  netbox_sync.py   Abweichungen bekannter Maschinen als einzeln freigebbare Änderungen (Vorher/Nachher, Abhängigkeiten)
  netbox_fields.py Custom Fields des Agents: Status/Anlage-Vorschlag, Werte, last_seen
  embeddings.py    Ollama /api/embed
  semantic.py      Suchindex (Abschnitte je Überschrift), Suche, Fragen mit Quellen
  lint.py          Wiki-Lint: tote Links, Dubletten, ohne Tags, veraltete Seiten (Neuberechnung über stable_id), Korrekturen
  connectors/      netbox.py, wazuh.py, intune.py, fortigate.py, vcenter.py, snmp.py
  generators/      wazuh_docs, intune_docs, netbox_docs, fortigate_docs, freeform, common (Maskierung, Cache, Stil)
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
| Ollama | `docs/api.md`, `envconfig` @ v0.34.4 | `format` = JSON-Schema, `think: false`, `OLLAMA_NO_CLOUD=1`; `POST /api/embed` mit `input`-Liste, `truncate` |
| FortiOS REST | Schema der Fortinet-Ansible-Collection (`fortinet.fortios`) | Pfade wie CLI (`firewall.service/custom`, `vpn.ipsec/phase1-interface`), Feldnamen mit Bindestrich; `version`/`serial`/`build` in jeder Antwort; `system/interface` global mit Feld `vdom` |
| Graph Gruppen | Microsoft Learn | `/groups/{id}/transitiveMembers/microsoft.graph.{user,device,group}/$count` mit `ConsistencyLevel: eventual`, Antwort `text/plain`; Untergruppen bei M365-Gruppen → 400 |
| Netbox Custom Fields | `extras/api/customfields.py`, Serializer @ main | `object_types` als `"dcim.device"`; PATCH von `custom_fields` wird mit bestehenden Werten zusammengeführt; unbekannte Felder werden abgelehnt; neu: `status` (nur `active` ist nutzbar) |
| Wiki.js Links | `server/graph/resolvers/page.js`, `modules/rendering/html-core/renderer.js` @ v2.5.315 | `pages.links(locale)` liefert je Seite alle internen Links als `locale/pfad`, auch auf fehlende Seiten; relative Links gelten relativ zur Seite |
| vSphere Automation API | API-Referenz auf developer.broadcom.com | `POST /api/session` (Basic) → Token als JSON-String, Header `vmware-api-session-id`; `/api/vcenter/{cluster,host,vm}` mit Filtern `clusters`/`hosts`; Gastdaten (`guest/identity`, `guest/networking/interfaces`) ohne VMware Tools → 503 |
| vSphere VI/JSON | Referenz ab 8.0 U1 | `ServiceInstance/ServiceInstance/content` → `sessionManager`, `SessionManager/{id}/Login`; `HostSystem/{id}/hardware` → `systemInfo` (vendor, model, serialNumber, otherIdentifyingInfo) |
| Netbox Virtualisierung/IPAM/Kabel | Serializer und Validierung @ 4.7.2 (Image) | `virtual-disks.size` in MB, Disk-Summe der VM wird berechnet; Cluster und Prefix mit `scope_type`/`scope_id` ab 4.2; VM-Device muss im VM-Cluster liegen; Kabel mit `a_terminations`/`b_terminations` als `{object_type, object_id}`; `serial` max. 50 Zeichen |
| SNMP | pysnmp 7.1 (asyncio-API), RFC-MIBs | `bulk_walk_cmd` mit `lexicographicMode=False`; IF-MIB, ENTITY-MIB (Chassis = Klasse 3), LLDP-MIB (`lldpRem*`, Index `timeMark.localPort.index`), Q-BRIDGE `dot1qTpFdbPort` mit Fallback auf BRIDGE-MIB |
| FortiOS Status | Fortinet-Ansible-Collection | `monitor/system/status` → `model_name`/`model_number`; `system/interface` mit `type`, `vlanid`, `interface` (Parent), `member`, `secondaryip`, `role` |

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

## Erweiterungen geprüft (20.10.2026)

Gegen Wiki.js 2.5.315, Netbox 4.7.2 und Ollama 0.34.4 mit `qwen3:8b` und `qwen3-embedding:0.6b` (4 CPU-Kerne, ohne GPU):

| Ablauf | Ergebnis |
|---|---|
| Custom Fields fehlen → Vorschlag → Freigabe | drei Felder für Geräte und VMs angelegt; Gerät mit IDs und `last_seen` angelegt; Wiedererkennung über die Agent-ID trotz neuem Namen; `last_seen` ohne Freigabe, andere Felder bleiben; Rollback setzt nur das geänderte Feld zurück |
| Suchindex | 10 Seiten (20 Abschnitte) in 10 s; danach nur geänderte Seiten; nach jeder Freigabe automatisch nachgezogen |
| Fragen | „Wo läuft der Lizenzserver …?“ → srv-lic01, Port 27000 mit Quellen in 55 s; Frage ohne Antwort im Wiki → „nicht genannt“; im Browser 34 s, Hinweis auf veraltete Notiz |
| Wiki-Lint | tote Links (absolut und relativ, wie Wiki.js sie auflöst), Dubletten nach Titel, Seiten ohne Tags; geänderte Seriennummer in Netbox → Aktualisierungs-Vorschlag mit genau diesem Diff; gelöschtes Gerät → „Quelle gelöscht“ |

Inhaltliche Ähnlichkeit echter Seiten liegt mit `qwen3-embedding` bei 0,7–0,8 auch für verwandte Themen; die Schwelle
für Dubletten ist deshalb mit 0,93 bewusst hoch (nur nahezu gleicher Inhalt). FortiGate und Graph sind mangels
Testinstanz mit Fakes nach dem verifizierten Schema getestet.

Gefunden und behoben: Variablenname im Steckbrief überdeckte den Gerätenamen (Test), Netbox-Fake lieferte keinen 404
für gelöschte Objekte. Das Code-Review der Erweiterungen fand zehn weitere Punkte, alle behoben und in
`tests/test_review_regressions.py` abgesichert, u.a.: `last_seen` wurde auch bei unsicherem MAC-Treffer gesetzt;
IPv6-Adressobjekte vom Typ Bereich/FQDN erschienen als „beliebig“; fehlendes Leserecht auf Custom Fields brach die
Discovery ab; Erklärungen der Firewall-Regeln wurden je Gruppe statt je Regel zwischengespeichert (eine neue Regel
hätte alle folgenden neu erklären lassen); Einzel- und Gesamtlauf erzeugten unterschiedliche NAT- bzw. Gruppen-Seiten. In der Sandbox brauchte das erste Laden von `qwen3:8b` wegen langsamer Platte länger als Ollamas
Ladezeitlimit – auf echter Hardware mit SSD kein Thema.

## Inventar-Erweiterungen geprüft (20.10.2026)

Gegen Netbox 4.7.2 und Wiki.js 2.5.315, Switches über einen SNMP-Simulator (`snmpsim`, v2c) mit einer Aufzeichnung
nach Standard-MIBs:

| Ablauf | Ergebnis |
|---|---|
| Switch per SNMP → Netbox | Switch mit Seriennummer und Modell aus der ENTITY-MIB, alle Ports, Kabel zum LLDP-Nachbarn und zum Endgerät über die MAC-Tabelle; geprüft über `link_peers` in Netbox; zweiter Lauf ohne neue Änderungen |
| FortiGate (Fake) → echtes Netbox | Gerät, LAG mit Mitgliedern, VLAN-Interfaces mit Parent und VLAN, IPs mit primärer IP, Präfixe mit `scope`; WAN ohne Präfix |
| vCenter (Fake) → echtes Netbox | Cluster, ESXi-Host im Cluster, VM im Cluster auf dem Host, virtuelle Disks; Netbox berechnet die Disk-Summe; vergrößerte Disk → Änderungsvorschlag |
| Lint-Korrektur → Wiki.js | toter Link ersetzt, Anker erhalten, nächster Lint ohne toten Link |

Dabei gefunden und behoben: Die aus der BIOS-UUID gebildete VMware-Seriennummer ist 54 Zeichen lang, Netbox erlaubt nur
50 – das Anlegen jeder VM scheiterte. Seriennummern werden jetzt ohne Leerzeichen gespeichert und überall ohne
Leerzeichen verglichen (`netbox_serial`, `serial_key`); ein Regressionstest sichert das ab. Die vCenter-Anbindung ist
mangels Testinstanz nur gegen Fakes nach der dokumentierten API geprüft, die FortiGate weiterhin ebenso.

Das Code-Review dieser Runde fand zehn Punkte; acht sind behoben und mit Tests abgesichert: Das IPv6-Objekt „all“
überdeckte das gleichnamige IPv4-Objekt, sodass die Prüfung keine any-any-Regeln fand (IPv4- und IPv6-Objekte werden
jetzt getrennt aufgelöst); LAG-Mitglieder, die alphabetisch vor ihrem neuen Aggregat stehen, bekamen keinen LAG;
negierte Adressen („alles außer srv01“) erschienen im Steckbrief als Regel für srv01; mehrfach vorhandene IPs und
Präfixe (z.B. in mehreren VRFs) galten als fehlend; ein Switch bzw. eine Firewall ohne Änderungen zählte bei einem
Fehler an einem anderen Gerät als gescheitert; LLDP-Kabel wurden von beiden Switches vorgeschlagen; der
Dedup-Schlüssel von Maschinen mit Leerzeichen in der Seriennummer hätte sich geändert (Ignorierliste); der
Abdeckungsbericht fragte offene Vorschläge je Maschine ab. Nicht geändert: Zweibuchstabige erste Pfadsegmente gelten
wie in Wiki.js als Sprache (Wiki.js sperrt solche Pfade für Seiten); virtuelle Disks setzen Netbox 4.0 voraus, das
ohnehin Mindestversion ist.

## Bewusst nicht umgesetzt

- Status-Pflege (z.B. offline nach längerer Funkstille) und Löschen in Netbox; `last_seen` und der Abdeckungsbericht
  liefern die Grundlage dafür.
- Ändern oder Löschen bestehender Kabel; abweichende Kabel erscheinen nur als Hinweis.
- VLAN-Zuordnung von Switch-Ports, Ressourcenpools, Datastores und Portgruppen aus dem vCenter.
- Wazuh-Alarmberichte aus dem Indexer.
- Wiki.js 3.x und Visual-Editor-Seiten.
- Bildauswertung.
