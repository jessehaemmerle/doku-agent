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
| Entra ID (21.10.2026) | Conditional Access (+ Standorte, Stärken), Authentifizierungsmethoden, Mandanten-Einstellungen, Rollen inkl. PIM; Übersicht + Seite je CA-Richtlinie mit LLM-Erklärung; Benutzer als Name + UPN; Prüfseite | `connectors/graph.py` (gemeinsame Basis für Intune und Entra), `connectors/entra.py`, `generators/entra_docs.py`, Job `entra` |
| Active Directory (21.10.2026) | Gruppenrichtlinien, OU-Struktur mit Delegationen, Kennwort- und Sperrrichtlinien, privilegierte Gruppen und Domäne; GPO-Einstellungen aus SYSVOL per SMB; eigene Prüfseite | `connectors/ad.py` (ldap3, nur TLS), `connectors/sysvol.py` (smbprotocol), `ad_acl.py`, `gpo_files.py`, `generators/ad_common.py`, `ad_docs.py`, `gpo_docs.py`, Job `ad` |
| Fließtext (21.10.2026) | Steckbriefe, Prüfseiten, Übersichten und Einstellungsseiten mit Text; Tabellen bleiben darunter; automatische Faktenprüfung; ausführlich (2–4 Absätze) | `generators/narrative.py` (`narrate`, `assessment`, `unverified`), neue Blöcke über bestehenden (`markdown.upsert_block(before_block=…)`), `narrative.*` in der Konfiguration |
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
  ad_acl.py        Sicherheitsbeschreibungen (MS-DTYP) lesen, Rechte in Worten, Standard- und Admin-Prinzipale
  gpo_files.py     Registry.pol, GptTmpl.inf, audit.csv, scripts.ini, Preferences-XML, ADMX/ADML (reine Parser)
  lint.py          Wiki-Lint: tote Links, Dubletten, ohne Tags, veraltete Seiten (Neuberechnung über stable_id), Korrekturen
  connectors/      netbox.py, wazuh.py, graph.py (Graph-Basis: Token, 403-Meldungen), intune.py, entra.py,
                   fortigate.py, vcenter.py, snmp.py, ad.py (LDAP), sysvol.py (SMB)
  generators/      narrative (Fließtext + Faktenprüfung), wazuh_docs, intune_docs, entra_docs, netbox_docs,
                   fortigate_docs, ad_common/ad_docs/gpo_docs (Active Directory), freeform,
                   common (Maskierung, Cache, Stil)
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
| Graph: Entra ID | Microsoft Learn (Graph v1.0, 21.10.2026) | CA-Richtlinien enthalten `authenticationStrength` vollständig; Stärken unter `/policies/authenticationStrengthPolicies`; `policyMigrationState` und `includeApplications` uneinheitlich geschrieben (`preMigration`/`premigration`, `none`/`None`) → ohne Groß-/Kleinschreibung verglichen; `isPrivileged` nur in beta → Admin-Rollen der Vorlage „MFA für Administratoren“ (Vorlagen-IDs); `$expand=principal` auf Rollen-Listen; PIM-Instanzen mit `assignmentType` Assigned/Activated und `endDateTime` (null = dauerhaft); Fehlercode ohne P2-Lizenz nicht dokumentiert → jeder Fehler gilt als „PIM nicht verfügbar“ |
| Active Directory (LDAP) | Microsoft Learn (MS-ADTS, Schema-Referenz), Samba 4.17 im Test | Funktionsebenen 0–7 und 10 (Server 2025); `gPLink` `[LDAP://…;Optionen]`, Bit 1 deaktiviert, Bit 2 erzwungen, **letzter Eintrag = Reihenfolge 1**; `gPOptions` 1 = Vererbung blockiert; `flags` 1/2/3 = Benutzer/Computer/alles deaktiviert; `versionNumber` oben Benutzer, unten Computer; `nTSecurityDescriptor` nur mit SD-Flags-Control (Besitzer + DACL), sonst fehlt es für Nicht-Admins; PSOs sind standardmäßig nur für Domänen-Admins lesbar |
| GPO-Dateien | MS-GPREG, MS-GPSB, MS-GPAC, MS-GPSCR, MS-GPPREF, MS-GPOL, MS-GPFAS (Rev. 2024-04-23) | `Registry.pol`: `PReg`, Version 1, `[Schlüssel;Wert;Typ;Größe;Daten]` in UTF-16LE, Steuerwerte `**del.`/`**delvals` ohne Groß-/Kleinschreibung; GptTmpl.inf und scripts.ini UTF-16LE mit BOM; audit.csv UTF-8; `cpassword` in Groups, Drives, Printers, ScheduledTasks, Services, DataSources; Firewall-Regeln als REG_SZ `v2.x|Action=…|` unter `WindowsFirewall\FirewallRules`; Dateinamen ohne Groß-/Kleinschreibung |
| ldap3 2.9.1 / smbprotocol 1.17 | Quelltext | ldap3-NTLM braucht MD4 (fehlt in OpenSSL 3) → einfache Anmeldung über TLS; ldap3 prüft Hostnamen mit einem alten Backport → eigener `SSLContext`; `auto_referrals=False`; smbclient folgt DFS-Verweisen → Low-Level-API (`Connection`/`Session`/`TreeConnect`/`Open`), Signatur Pflicht, NTLM aus pyspnego |
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

## Entra ID (21.10.2026)

Graph-Zugriff liegt jetzt in `connectors/graph.py`. Intune und Entra teilen sich Anmeldung, Paging und Drosselung
sowie die verständliche 403-Meldung mit der fehlenden Berechtigung. Nach einem 403 holt der Client beim nächsten
Aufruf ein neues Token, höchstens einmal pro Minute; so greift eine frisch erteilte Zustimmung ohne Neustart.

Wiki-Pfade und Tags aus der `config.yaml` werden mit den Standardwerten zusammengeführt. Dokutypen neuer Versionen
landen damit auch bei bestehenden Konfigurationen am vorgesehenen Ort und nicht im Wurzelverzeichnis des Wikis.

Getestet ist Entra nur gegen einen Graph-Fake nach dem verifizierten Schema; ein Testmandant stand nicht zur Verfügung.
Die Tests haben zwei Fehler gefunden, beide sind behoben:
- Eine Blockier-Regel nur für Legacy-Clients zählte als MFA-Schutz.
- Im Modus `count` erschienen Prüfer und Notfallkonten mit Namen.

Das Code-Review fand zehn weitere Punkte; alle sind behoben und mit Tests in `tests/test_entra.py` abgesichert:
- Die CA-Übersicht wäre nach der ersten Freigabe abgestürzt (`pages` ist eine Property).
- Ein nicht lesbares Notfallkonto, etwa ohne `User.Read.All`, galt als „nicht gefunden“, und seine Ausnahmen blieben
  ungeprüft.
- Die Legacy-Einstellung „Vertrauenswürdige MFA-IPs“ erschien als gelöschter Standort.
- Vorübergehende Graph-Störungen (429, 5xx) schalteten still auf „ohne PIM“ um oder erzeugten abweichende Seiten. Jetzt
  bricht der Bereich ab.
- Notfallkonten erschienen bei `user_names: name` mit UPN.
- Abgewählte Bereiche wurden vom Wiki-Lint weiter aktualisiert.
- Link und Pfad einer Richtlinie ohne Namen passten nicht zusammen.
- `]` im Richtliniennamen brach den Link.
- Die Berechtigungsprüfung wird jetzt aus denselben Datengruppen abgeleitet wie der Job.

## Active Directory (21.10.2026)

Der Agent liest das AD nur: LDAP-Suchen über TLS und Dateien aus `\\<DC>\SYSVOL`. Beides geht nur an die Domänencontroller
aus `ad.servers`. Dafür prüft `EgressGuard.check_host` den Host, LDAP-Referrals werden nicht verfolgt und DFS-Weiterleitungen
nicht aufgelöst. Die GPO-Dateien stammen vom DC, mit dem LDAP verbunden ist, über einen aus der GUID gebildeten Pfad.
`gPCFileSysPath` wird nur geprüft, nie benutzt; ein Pfad auf einen fremden Server ist ein Befund.

**Entscheidungen:**
- **Einfache Anmeldung über TLS statt NTLM/Kerberos:** ldap3 braucht für NTLM MD4, das OpenSSL 3 nicht mehr hat, und
  Kerberos bräuchte eine krb5-Umgebung im Container. Eine einfache Anmeldung über TLS erfüllt die LDAP-Signaturpflicht
  der DCs und ist von Channel Binding nicht betroffen. Unverschlüsseltes LDAP ist nicht vorgesehen.
- **Eigener TLS-Kontext:** ldap3 prüft den Hostnamen mit einem Backport aus Python 2, deshalb nutzt der Agent einen
  eigenen `ssl.SSLContext` mit Hostnamenprüfung. Ab Python 3.13 verlangt der strikte Modus einen Authority Key
  Identifier. Viele interne CAs (auch Samba) liefern ihn nicht, darum ist nur dieses Flag aus; Kette und Name werden
  weiter geprüft.
- **Delegationen:** Gezählt werden explizite Einträge außerhalb der Schema-Vorgabe neuer Objekte, ohne reine Leserechte
  und ohne den Löschschutz. Schreibrechte für breite Gruppen sind nie Standard.
- **GUIDs je nach Recht:** Dieselbe GUID kann ein Attribut und einen bestätigten Schreibvorgang bezeichnen, etwa
  `bf9679c0…` für `member` und für Self-Membership. Darum entscheidet das Recht des Eintrags, welcher Name gilt:
  Lesen/Schreiben → Attribut, Steuerzugriff → erweitertes Recht, Self → bestätigter Schreibvorgang. Wichtige erweiterte
  Rechte haben feste deutsche Namen über die GUID, weil sich die Anzeigenamen zwischen Windows und Samba unterscheiden.
- **Stabile Seiten:** Auf den Seiten stehen Daten statt Zeitspannen („Kennwort gesetzt am“, „ohne Anmeldung
  > 90 Tage“). Ein zweiter Lauf ohne Änderung im AD erzeugt nach dem Übernehmen keinen Vorschlag; das prüft ein Test.
- **ADMX:** Die Rückwärtssuche Registrierungswert → Richtlinie läuft über Schlüssel + Wertname, bei Listen über den
  Schlüssel. Kategorien werden dateiübergreifend über die Namespaces aufgelöst. Ohne Angabe gilt 1 = aktiviert, 0 bzw.
  gelöscht = deaktiviert. Der Katalog bleibt im Prozess zwischengespeichert, solange sich die Dateiliste nicht ändert.

**Test mit Samba 4.17 als AD-DC** (`tests/samba_ad/`, angemeldet als normaler Domänenbenutzer):
- Samba legt Computerkonten deaktiviert an; Befunde zählen nur aktivierte Konten, die Testdaten aktivieren sie daher.
- Ohne Admin-Rechte sind PSOs unsichtbar. Statt einer leeren Tabelle steht der Hinweis auf das fehlende Leserecht.
- Die Anzeigenamen erweiterter Rechte weichen von Windows ab („DS Replication Get Changes All“ statt „Replicating
  Directory Changes All“); daher die festen Namen über die GUID.
- Samba schreibt `MACHINE`/`USER` in Großbuchstaben. Pfade werden ohne Rücksicht auf Groß-/Kleinschreibung erkannt.

**Code-Review** – 16 Punkte, alle behoben und mit Tests in `tests/test_ad.py` abgesichert:
- Ein Klartext-Kennwort in einem Preferences-Registrierungswert (`DefaultPassword`), in Umgebungsvariablen, INI-Werten,
  `Registry.pol` oder Sicherheitsoptionen wäre ins Wiki und an das Sprachmodell gegangen. Maskiert wird jetzt auch über
  den Namen des Werts, nicht nur über den Attributnamen.
- Eine abgeschnittene `Registry.pol` oder eine UTF-16-Datei ungerader Länge brach den ganzen AD-Lauf ab. Jetzt ist nur
  diese Datei betroffen (Hinweis auf der GPO-Seite und Befund). Dasselbe gilt für zu große Dateien und Fehler wie
  „wird gerade gelöscht“; nur ein Verbindungsabbruch lässt den Bereich ausfallen.
- Im Modus `count` erschienen beim Geltungsbereich einer PSO, bei Mitgliedern lokaler Gruppen, bei „ausführen als“ von
  Aufgaben und bei Namen in GptTmpl.inf Personennamen. Außerdem lieferte der Wiki-Lint bei PSOs einen anderen Namen als
  der Job, sodass bei jedem Lint ein Vorschlag entstand. Jetzt werden DNs und Kontonamen über LDAP aufgelöst.
- Die MS16-072-Prüfung schlug nie an, weil die Organisations-DCs (S-1-5-9) in jeder GPO Leserecht haben. Sie zählen
  nicht mehr; geprüft wird nur, wenn die GPO Benutzereinstellungen hat.
- SID-Filterung wurde bei eingehenden statt bei ausgehenden Vertrauensstellungen verlangt; MIT-Bereiche sind
  ausgenommen.
- ADMX: Richtlinien nur mit `enabledList`/`disabledList`, das Deaktivieren per `**del.` ohne `disabledValue` und
  Schalter mit `<falseValue><delete/>` wurden falsch bewertet.
- Eine PSO-Sperrdauer „bis zur Entsperrung durch einen Administrator“ erschien als „nie“.
- SYSVOL blieb nach einem Ausfall am ersten DC hängen; jetzt folgt es beim Neuverbinden dem DC der LDAP-Verbindung.
- Kerberos-Werte kommen je Einstellung aus der GPO mit der höchsten Priorität, ohne deaktivierte Verknüpfungen und
  ohne GPOs mit deaktivierter Computerkonfiguration.
- Weitere Korrekturen:
  - Störungen beim Auflösen von Namen brechen den Bereich ab, statt SIDs auf die Seite zu schreiben.
  - Die Reihenfolge aller Listen hängt nicht mehr vom DC ab.
  - Die LDAP-Verbindung wird bei fehlgeschlagener Anmeldung geschlossen.
  - Große Attribute werden über die gemeldete Bereichsgrenze gelesen.
  - Die Gruppe „Replikations-Operator“ zählt zu den privilegierten Gruppen.

**Versuch mit qwen3:8b:** Die Beschreibungen zweier GPOs und die Bewertung der Prüfseite bestanden die Faktenprüfung
im ersten Versuch (250–550 s je Text). Eine Beschreibung hielt „Server - Basis“ für unwirksam: Eine von zwei
Verknüpfungen war deaktiviert, und die Fakten sagten das nur indirekt. Die Fakten nennen jetzt ausdrücklich, wo die GPO
wirkt und welcher Teil deaktiviert ist.

## Fließtext mit Faktenprüfung (21.10.2026)

Grundsatz bleibt: Fakten entstehen deterministisch, das LLM formuliert nur. Neu ist, dass es auf den meisten Seiten
erklärenden Text über den Tabellen schreibt. Ablauf in `narrative.narrate`:

1. Der Aufrufer stellt die Fakten als Text zusammen, entweder als „Bezeichnung: Wert“-Zeilen oder direkt aus den
   Tabellen der Seite (`facts_from_markdown`). Speichergrößen stehen schon in MB und GB darin.
2. Das LLM schreibt Fließtext mit festen Regeln: keine Listen, keine eigenen Zahlen, Namen exakt übernehmen.
3. `unverified` sucht im Text IPv4-, IPv6- und MAC-Adressen, Zahlen (auch mit Einheit, Tausendertrennzeichen und
   deutschem Datum), technische Namen mit Ziffern, Punkt, Unterstrich oder @ sowie zitierte und technisch aussehende
   fett gesetzte Namen. Jede Angabe muss als eigenes Wort in den Fakten stehen:
   - `10.0.0.1` gilt nicht durch `10.0.0.15` als belegt, `srv1` nicht durch `srv10`, `7.4` nicht durch `7.4.5`.
   - Zahlen zählen nur, wenn sie in den Fakten als eigene Angabe vorkommen; Oktette einer IP-Adresse zählen nicht.
4. Bei unbelegten Angaben gibt es einen zweiten Versuch mit genau dieser Liste. Scheitert er, gilt eine feste
   Vorlage, die nach `RETRY_FALLBACK_DAYS` erneut versucht wird.
5. Ergebnis und Vorlage werden nach Eingabe-Hash gespeichert. Ist das LLM nicht erreichbar, liefert `narrate`
   None: Der Abschnitt entfällt, ein bestehender bleibt im Wiki unverändert, und im selben Lauf wird nicht erneut
   gewartet.

Grenzen: Ausgeschriebene Zahlwörter und allgemeine Aussagen ohne Ziffern werden nicht geprüft. Eine Zahl kann
zufällig an anderer Stelle in den Fakten stehen, etwa eine Regel-ID gleich einer Anzahl. Die Prüfung senkt das Risiko
erfundener Details deutlich, ersetzt aber nicht das Lesen bei der Freigabe.

Das Code-Review fand neun Punkte; alle sind behoben und in `tests/test_narrative.py` abgesichert:
- Neue Abschnitte konnten über einer H1-Seitenüberschrift landen.
- Ohne Sprachmodell scheiterten auch Seiten, die vorher ohne LLM auskamen.
- Die Prüfung verglich Teilstrings und zählte IP-Oktette als Zahlen.
- Leere FortiGate-Bereiche riefen das LLM auf.
- Die Entra-Bewertung verschwieg fehlende PIM-Daten.
- Eine Vorlage blieb für immer gespeichert.
- Gemeldet wurden Token-Teile statt der ganzen Angabe.
- Kleine VMs bekamen „0 GB“.

### Versuch mit qwen3:8b (21.10.2026)

Vier typische Texte: Steckbrief, CA-Richtlinie, FortiGate-Bewertung und Intune-Richtlinie, auf 4 CPU-Kernen.

**Erster Durchgang:** Drei Texte wurden verworfen. Fehlalarme gab es durch zitierte bzw. fett gesetzte Wortgruppen wie
„IP-Adressen“ oder „Plattform Ubuntu 24.04“. Echte Fehler wurden korrekt erkannt: „ens19,2“ statt `ens192` und
eine selbst addierte, falsche Befundzahl.

**Korrekturen:**
- Wortgruppen werden nicht mehr als Ganzes verglichen; ihre technischen Bestandteile prüft die Wortprüfung.
- Versionsbestandteile gelten als belegt.
- Name mit Nummer (`webfarm-01`) gilt nur als Ganzes als belegt.
- Bewertungen bekommen die Summen vorgegeben.

**Zweiter Durchgang:** Alle vier Texte bestanden im ersten Versuch, in 121 bis 212 s je Text.

Inhaltlich waren sie korrekt bis auf falsch zugeordnete Befunde in der Bewertung. Darauf reagiert jetzt der Prompt
(„Ordne jeden Befund nur der Prüfung zu, unter der er steht“), und die Summenzeile ist eindeutiger formuliert.
Grundsätzlich bleibt: Die Prüfung sichert Werte, nicht Beziehungen zwischen Werten.

