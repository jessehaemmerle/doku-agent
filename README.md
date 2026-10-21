# doku-agent

Lokaler KI-Agent, der IT-Dokumentation erzeugt und in **Wiki.js** pflegt – mit Fokus auf
**Netbox** (Maschinen erkennen, eintragen und aktuell halten), **Wazuh** (eigene Regeln, Decoder, Konfiguration, SCA),
**Intune** (Richtlinien, Profile, Apps, Entra-Gruppen), **Entra ID** (Conditional Access, Authentifizierungsmethoden,
Mandanten-Einstellungen, privilegierte Rollen, Prüfung), das lokale **Active Directory** (Gruppenrichtlinien mit allen
Einstellungen, OU-Struktur und Delegationen, Kennwortrichtlinien, privilegierte Konten, Domäne, Prüfung) und
**FortiGate** (Regelwerk, NAT, Objekte, Netzwerk, VPN, Prüfung), aber auch für beliebige andere Themen aus Stichpunkten und Dateien. **vCenter** (Cluster, ESXi-Hosts, VMs),
**Switches** (SNMP/LLDP mit Verkabelung) und die **FortiGate** selbst trägt er in Netbox ein; ein **Abdeckungsbericht**
zeigt, wo Wazuh, Intune oder Netbox fehlen. Dazu kommen **Fragen ans Wiki** mit Quellenangabe und ein **Wiki-Lint**,
der tote Links, Dubletten, fehlende Tags und veraltete Seiten findet und Korrekturen vorschlägt.

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
               │     └──────────▶ ollama (qwen3:8b + qwen3-embedding)    │
               │     │  Netz "lan"                                        │
               └─────┼────────────────────────────────────────────────────┘
                     ├──▶ Wiki.js 2.x  (GraphQL, lesen + schreiben nach Freigabe)
                     ├──▶ Netbox 4.x   (REST, Discovery + Anlegen nach Freigabe)
                     ├──▶ Wazuh 4.x    (Server-API, nur lesend)
                     ├──▶ FortiGate    (REST-API, nur lesend, optional)
                     ├──▶ vCenter 7/8  (Automation-API + VI/JSON, nur lesend, optional)
                     ├──▶ Switches     (SNMP v2c/v3, nur lesend, optional)
                     ├──▶ Active Directory (LDAPS + SYSVOL per SMB, nur lesend, optional)
                     └──▶ Microsoft Graph (Intune, Entra ID, nur lesend, optional)
```

## Was der Agent kann

| Bereich | Was passiert | Ergebnis |
|---|---|---|
| **Netbox-Discovery** | Liest Geräte aus Intune, Wazuh-Agents und vCenter (Seriennummer, Hostname, MACs, IPs, OS), führt sie zusammen und gleicht mit Netbox ab | Pro fehlender Maschine ein **Netbox-Plan** (Hersteller, Gerätetyp, Plattform, Gerät/VM, Interfaces, MACs, IPs, primäre IP). Nach Freigabe wird angelegt und automatisch ein **Steckbrief** im Wiki vorgeschlagen |
| **Netbox-Abgleich** | Vergleicht bereits eingetragene Maschinen mit Intune und Wazuh | Pro Maschine ein Vorschlag mit **Vorher/Nachher je Änderung**, jede einzeln per Häkchen übernehmbar: fehlende Angaben, OS/Plattform und VM-Ressourcen, Netzwerk (IPs, MACs, primäre IP), Umbenennungen, Wazuh-/Intune-ID |
| **Netbox-Custom-Fields** | `wazuh_agent_id`, `intune_device_id`, `last_seen` | Maschinen werden zuerst über die IDs wiedererkannt; „zuletzt gesehen“ wird täglich gepflegt. Fehlende Felder schlägt der Agent einmalig zum Anlegen vor |
| **vCenter** | Cluster, ESXi-Hosts (Hersteller, Modell, Seriennummer) und VMs mit vCPU, RAM, NICs, Gast-IPs und Disks | Teil der Discovery: Cluster und Hosts als Geräte, VMs im Cluster auf ihrem Host, virtuelle Disks einzeln; auch ausgeschaltete VMs |
| **Switches** | SNMP: Systemdaten, Ports, LLDP-Nachbarn, MAC-Tabelle | Je Switch ein Vorschlag: Gerät, Ports und **Kabel** zu LLDP-Nachbarn und zu Endgeräten an Ports mit genau einer bekannten MAC |
| **FortiGate → Netbox** | Interfaces, VLANs, IPs der Firewall | Gerät mit Interfaces (LAG-Mitglieder, VLAN-Parent), IP-Adressen samt primärer IP, VLANs und Präfixe; alles einzeln freigebbar |
| **Netbox-Steckbriefe** | Gerät/VM aus Netbox mit Interfaces, IPs und Kabeln | Wiki-Seite pro Maschine: oben ein **Überblick in Fließtext** (was sie ist, wo sie läuft, wie sie angebunden ist, welche Firewall-Regeln sie betreffen), darunter die Tabellen mit „Verbunden mit“ je Port und den **Firewall-Regeln**; wird bei Änderungen aktualisiert |
| **Abdeckung** | Netbox gegen Wazuh, Intune und vCenter | Seite `infrastruktur/abdeckung`: Maschinen ohne Wazuh-Agent, Clients ohne Intune, Maschinen, die in Netbox fehlen, und Funkstille seit über 30 Tagen |
| **Wazuh-Regeln/Decoder** | Liest `etc/rules` bzw. `etc/decoders`, parst das XML | Seite pro Datei: Übersicht, Regel-Tabelle (Level, Bedingungen, MITRE) und Erläuterung jeder Regel durch das LLM |
| **Wazuh-Konfiguration** | `ossec.conf` des Managers und `agent.conf` jeder Gruppe | Zusammenfassung und Einstellungen je Abschnitt; Passwörter, API-Keys und Webhooks werden maskiert |
| **Wazuh-SCA** | SCA-Ergebnisse aller (oder ausgewählter) Agents | Score je Richtlinie und fehlgeschlagene Prüfungen mit Behebung |
| **Intune** | Compliance-Richtlinien, Konfigurationsprofile, Settings Catalog, Apps | Seite je Richtlinie mit Beschreibung, Zuweisungen (Gruppenname und Art: dynamisch/zugewiesen) und allen Einstellungen; App-Übersicht |
| **Entra ID: Conditional Access** | Richtlinien, benannte Standorte, Authentifizierungsstärken | Übersicht aller Richtlinien und je Richtlinie eine Seite (Zuweisungen, Bedingungen, Steuerung, Erklärung durch das LLM); Standorte und Stärken mit „Verwendet in“ |
| **Entra ID: Mandant und Rollen** | Authentifizierungsmethoden, Sicherheitsstandards, Benutzer-/Gast-/Zustimmungs-Einstellungen, mandantenübergreifender Zugriff, Rollen inkl. PIM | Je Bereich eine Seite; Benutzer als „Anzeigename (UPN)“ |
| **Entra ID: Prüfung** | Alles oben zusammen | Nicht durchgesetzte Richtlinien, fehlender Grundschutz (MFA für alle und Admins, Legacy-Authentifizierung), Notfallkonten nicht ausgenommen, Verweise auf gelöschte Objekte, dauerhafte Admin-Rollen, Gäste in Admin-Rollen, riskante Mandanten-Einstellungen, SMS/Anruf aktiv |
| **AD: Gruppenrichtlinien** | GPOs aus dem AD, ihre Dateien aus SYSVOL, Namen aus dem Central Store | Je GPO eine Seite: Beschreibung durch das LLM, Status, Verknüpfungen mit Reihenfolge, WMI-Filter, Sicherheitsfilterung und Bearbeitungsrechte, dazu alle Einstellungen – administrative Vorlagen mit Richtliniennamen, Sicherheitseinstellungen (Kontorichtlinien, Benutzerrechte, Sicherheitsoptionen, eingeschränkte Gruppen, Dienste), erweiterte Überwachung, Firewall-Regeln, Skripte, Preferences. Kennwörter aus Preferences erscheinen nie |
| **AD: Struktur und Richtlinien** | OUs, Domäne, PSOs, privilegierte Gruppen, DCs, Standorte, Vertrauensstellungen | Seiten zu OU-Struktur (verknüpfte GPOs, blockierte Vererbung, Löschschutz, **Delegationen** in Worten), Kennwort- und Sperrrichtlinien inkl. feingranularer Richtlinien und Kerberos, privilegierten Gruppen (auch verschachtelt), Dienstkonten und Kerberos-Delegierung, Domäne und Gesamtstruktur |
| **AD: Prüfung** | Alles oben zusammen | GPOs mit gespeicherten Kennwörtern, unwirksame oder beschädigte GPOs, schwache Kennwortrichtlinien, Admins mit „Kennwort läuft nie ab“, Kerberoasting und AS-REP-Roasting, uneingeschränkte Delegierung, altes krbtgt-Kennwort, verwaiste Konten, DCSync-Rechte, gefährliche Rechte auf Domäne und AdminSDHolder, Papierkorb, MachineAccountQuota, Vertrauensstellungen ohne SID-Filterung |
| **Entra-Gruppen** | Alle Gruppen, die in Intune-Zuweisungen vorkommen | Übersichtsseite mit Art, dynamischer Regel, Mitgliederzahlen (Benutzer, Geräte, Untergruppen) und allen Zuweisungen je Gruppe |
| **FortiGate** | Policies, Adressen/Dienste, VIPs/IP-Pools, Interfaces/Zonen/Routen, IPsec | Je Firewall (und VDOM) sechs Seiten: Regeln mit Erklärung jeder Regel durch das LLM, NAT, Objekte mit Verwendung, Netzwerk, VPN und eine **Prüfung** (verdeckte Regeln, any-any, ohne Logging, Internet ohne Sicherheitsprofil, unbenutzte Objekte). PSKs und Passwörter werden nie übernommen |
| **Freie Doku** | Stichpunkte und Dateien (TXT, Config, Log, CSV/JSON/XML/YAML, PDF, DOCX) | Der Agent sucht eine passende bestehende Seite (auch inhaltlich über den Suchindex) und ergänzt sie, oder legt eine neue im passenden Bereich an |
| **Fragen ans Wiki** | Frage in eigenen Worten („Wo läuft der Lizenzserver?“) | Antwort nur aus Wiki-Auszügen, mit nummerierten Quellen und Links; sagt ehrlich, wenn das Wiki die Antwort nicht enthält |
| **Wiki-Lint** | Ganzes Wiki | Bericht über tote interne Links, mögliche Dubletten, Seiten ohne Tags und veraltete Seiten (Quelle geändert → Aktualisierungs-Vorschlag); für tote Links mit eindeutigem Ziel und Seiten ohne Tags je ein **Korrekturvorschlag mit Diff** |

## Installation

Voraussetzungen: Linux-Host mit Docker und Docker Compose, **16 GB RAM** (CPU genügt), Netzzugriff auf Wiki.js,
Netbox und Wazuh.

```bash
git clone <dieses-repo> doku-agent && cd doku-agent
cp config.example.yaml config.yaml     # URLs, Standort, Zeitplan anpassen
cp .env.example .env                   # Tokens und Passwörter eintragen
docker compose --profile setup run --rm ollama-pull   # Modelle einmalig laden (ca. 5,2 + 0,6 GB)
docker compose up -d
docker compose exec agent doku-agent check            # Verbindungen prüfen
docker compose exec agent doku-agent run wiki_index   # Suchindex für Fragen ans Wiki aufbauen
```

Danach ist die Oberfläche unter <http://127.0.0.1:8080> erreichbar (Benutzer `admin`, Passwort aus `WEB_PASSWORD`).

**Nach Änderungen an der `config.yaml`:** `docker compose restart agent`. `docker compose up -d` startet den Agent nicht
neu, wenn sich nur die `config.yaml` geändert hat. Der laufende Dienst (Weboberfläche, Zeitplan) arbeitet dann mit der
alten Fassung weiter, während `docker compose exec agent doku-agent …` die neue liest. Der Agent erkennt das:
`check` meldet es unter „Konfiguration“, und jeder Job schreibt eine Warnung ins Protokoll.
Für Zugriff aus dem LAN die Port-Bindung in `docker-compose.yml` anpassen.

### Zugänge einrichten

**Wiki.js** – *Administration › API-Zugriff*: API aktivieren und einen Schlüssel anlegen. Der Schlüssel braucht eine
Gruppe mit `read:pages`, `read:source` und `write:pages` (oder vollen Zugriff). Wichtig: Der Agent arbeitet mit
dem **Markdown-Editor**. Seiten im Visual Editor (HTML) werden erkannt und übersprungen.

**Netbox** – eigenen Benutzer `doku-agent` anlegen, Token erzeugen (v1 oder v2 `nbt_…`, beides wird unterstützt).
Rechte: Anzeigen auf DCIM/IPAM/Virtualization, Anlegen/Ändern für Geräte, Gerätetypen, Hersteller, Rollen,
Plattformen, Interfaces, MAC-Adressen, IP-Adressen und VMs. Mit vCenter zusätzlich Cluster, Clustertypen und virtuelle
Disks, mit FortiGate → Netbox VLANs und Präfixe, mit Switches Kabel. Löschen wird nur für das Rollback eines
fehlgeschlagenen Plans benötigt. Für die Custom Fields braucht der Benutzer einmalig *Custom Field anlegen/ändern*
(oder du legst die drei Felder selbst an, siehe unten). Alle Änderungen stehen im Netbox-Changelog unter diesem
Benutzer. In `config.yaml` muss `netbox.site` auf einen existierenden Standort zeigen.

**Wazuh** – API-Benutzer mit Leserechten (z.B. Rolle `readonly`) auf dem Manager (Port 55000).

**Intune (optional)** – App-Registrierung in Entra ID mit Client-Secret und den **Anwendungsberechtigungen**
`DeviceManagementManagedDevices.Read.All`, `DeviceManagementConfiguration.Read.All`,
`DeviceManagementApps.Read.All` sowie optional `Group.Read.All` (Gruppennamen, Art und Mitgliederzahlen). Admin-Zustimmung
erteilen und `intune.enabled: true` setzen. Der Agent stellt ausschließlich GET-Anfragen. Die Daten werden nur
gelesen und lokal verarbeitet.

| Bereich (`intune.include`) | Anwendungsberechtigung |
|---|---|
| Discovery (Geräte) | `DeviceManagementManagedDevices.Read.All` |
| `compliance`, `configurations`, `settings_catalog` | `DeviceManagementConfiguration.Read.All` |
| `apps` | `DeviceManagementApps.Read.All` |
| `groups` bzw. Gruppennamen | `Group.Read.All` |

`doku-agent check` (bzw. *Status*) fragt jeden Bereich einmal ab und nennt fehlende Berechtigungen. Häufigste Ursachen
für „HTTP 403“: die Berechtigung wurde als *delegiert* statt als *Anwendung* hinzugefügt, oder die
Administratorzustimmung fehlt (Spalte *Status* in den API-Berechtigungen). Ist ein Bereich nicht lesbar, dokumentiert
der Intune-Job die übrigen trotzdem und meldet am Ende einen Fehler; die Gruppen-Übersicht wird dann ausgelassen,
weil ihr Zuweisungen fehlen würden. Nach erteilter Zustimmung holt der Agent beim nächsten Lauf selbst ein neues Token.

**Entra ID (optional)** – nutzt standardmäßig dieselbe App-Registrierung wie Intune (eigener Zugang unter `entra.*`
möglich). Zusätzliche **Anwendungsberechtigungen** (nicht delegiert), danach Administratorzustimmung erteilen:

| Berechtigung | Wofür |
|---|---|
| `Policy.Read.All` | Conditional Access, benannte Standorte, Authentifizierungsstärken und -methoden, Mandanten-Einstellungen |
| `RoleManagement.Read.Directory` | Rollen und Zuweisungen, mit Entra ID P2 auch PIM (berechtigt, befristet, aktiviert) |
| `User.Read.All` | Benutzernamen und Notfallkonten (entfällt bei `user_names: count` ohne `breakglass`) |
| `Group.Read.All` | Gruppennamen und Mitglieder ausgenommener Gruppen |
| `Application.Read.All` | optional: Namen der Ziel-Apps statt App-IDs |

`entra.enabled: true` setzen und unter `entra.breakglass` die Notfallkonten eintragen (UPN oder Objekt-ID), damit die
Prüfung sie kennt. `doku-agent check` zeigt in „Entra-Berechtigungen“, was noch fehlt.

**HTTP 500 von Graph:** Das ist ein Fehler auf Microsofts Seite, keine fehlende Berechtigung; die wäre ein 403.
Der Agent wiederholt solche Anfragen mit kurzer Pause.

Antwortet v1.0 bei Conditional Access dauerhaft mit 5xx, liest der Agent eine Stunde lang über beta. Eine mögliche,
aber nicht offiziell dokumentierte Ursache sind Richtlinien mit Vorschau-Funktionen, die nur beta abbildet. Das Job-Protokoll und `check`
weisen darauf hin.

Bleibt der Fehler auch über beta bestehen, mit Graph Explorer oder
`Get-MgBetaIdentityConditionalAccessPolicy` gegenprüfen und die request-id aus der Meldung an den Microsoft-Support
geben.

**Active Directory (optional)** – ein **normaler Domänenbenutzer** als Lesekonto genügt (z.B. `svc-doku`, Kennwort
läuft nicht ab, Mitglied nur von „Domänen-Benutzer“). Zugang als `AD_USER` (UPN, `svc-doku@corp.example.local`) und
`AD_PASSWORD` in `.env`, dann unter `ad.*` Domäne und Domänencontroller eintragen und `ad.enabled: true` setzen.

- **LDAP immer verschlüsselt:** LDAPS auf Port 636 oder StartTLS auf 389 (`starttls: true`), einfache Anmeldung über
  TLS. Das DC-Zertifikat wird geprüft: Stammzertifikat der Domänen-CA als PEM unter `verify_tls` angeben und die DCs
  mit dem DNS-Namen aus dem Zertifikat eintragen. Haben die DCs noch kein Zertifikat, zuerst eins ausstellen (AD CS,
  Vorlage „Domänencontrollerauthentifizierung“) – unverschlüsseltes LDAP unterstützt der Agent nicht.
- **SYSVOL per SMB** (Port 445) mit demselben Konto, signiert, Anmeldung per NTLMv2. Gelesen wird nur die Freigabe
  `SYSVOL` des Domänencontrollers, mit dem LDAP verbunden ist; DFS-Weiterleitungen zu anderen Servern folgt der Agent
  nicht. Ohne SMB (`sysvol: false`) fehlen nur die Einstellungen der GPOs.
- **Feingranulare Kennwortrichtlinien** darf standardmäßig nur „Domänen-Admins“ lesen. Für die Kennwortseite dem
  Lesekonto Leserechte auf `CN=Password Settings Container,CN=System,<Domäne>` geben (*AD-Benutzer und -Computer ›
  Erweiterte Features › System › Password Settings Container › Eigenschaften › Sicherheit*). Ohne das Recht steht
  dort ein Hinweis.
- **Richtliniennamen** kommen aus dem Central Store (`SYSVOL\<domäne>\Policies\PolicyDefinitions`) in der Sprache
  `admx_language`, ersatzweise `en-US`. Ohne Central Store einen Ordner mit den ADMX/ADML-Dateien einhängen
  (`admx_dir`), sonst erscheinen die Registrierungswerte ohne Namen.

`doku-agent check` prüft Anmeldung, Leserechte (Berechtigungen, GPOs, PSOs) und SYSVOL.

**FortiGate (optional)** – *System › Administratoren › REST-API-Admin* anlegen, mit einem Admin-Profil, das alles
nur lesen darf, und den Agent-Host als *Trusted Host* eintragen. Das Token als `FORTIGATE_TOKEN` in `.env`, die
Firewall unter `fortigate.devices` eintragen und `fortigate.enabled: true` setzen. Getestet ist das Schema von
FortiOS 7.x; ältere Versionen ohne einzelne Tabellen (z.B. zentrale SNAT) werden übersprungen.

**vCenter (optional)** – Benutzer (z.B. `doku-agent@vsphere.local`) mit der Rolle **Nur lesen**, auf der obersten
Ebene vergeben und an untergeordnete Objekte weitergegeben. Zugang als `VCENTER_USER`/`VCENTER_PASSWORD` in `.env`,
`vcenter.url` setzen und `vcenter.enabled: true`. Cluster, Hosts und VMs kommen aus der Automation-API (ab vCenter
7.0 U2). Hersteller, Modell und Seriennummer der ESXi-Hosts liefert nur die VI/JSON-API ab **vCenter 8.0 U1**; bei
älteren Versionen `vijson_release: ""` setzen, dann bleiben diese Angaben leer. Gast-Hostname und IPs gibt es nur bei
laufenden VMware Tools.

**Switches (optional)** – SNMP-Lesezugang auf jedem Switch: v2c mit einer Read-only-Community (`SNMP_COMMUNITY` in
`.env`) oder v3 mit Benutzer, `auth_protocol`/`auth_key` und `priv_protocol`/`priv_key`; ACL des Switches auf den
Agent-Host beschränken. LLDP muss auf den Switches aktiv sein. Die Switches unter `switches.devices` eintragen (je
Switch eigene Zugangsdaten möglich) und `switches.enabled: true` setzen. Benötigt werden die Standard-MIBs (IF-MIB,
ENTITY-MIB, LLDP-MIB, BRIDGE-/Q-BRIDGE-MIB), herstellerspezifische MIBs nicht. `doku-agent check` fragt jeden Switch
einmal ab.

„Keine Antwort per SNMP“ hat meist eine dieser Ursachen:
- **Falsche Community bzw. falsche v3-Zugangsdaten:** Switches verwerfen solche Anfragen ohne Antwort.
- **SNMP ist auf dem Switch nicht aktiv** oder läuft in einer anderen Version (v2c bzw. v3).
- **Eine ACL lässt den Agent nicht zu:** Absender ist die IP des Docker-Hosts, nicht die des Containers.
- **Eine Firewall blockiert UDP 161.**
- **Die Adresse unter `switches.devices` stimmt nicht.** `10.0.0.2` ist der Beispielwert aus `config.example.yaml`.

Zum Gegentest vom Docker-Host aus: `snmpget -v2c -c <community> <switch> 1.3.6.1.2.1.1.5.0`.

**Weitere Switches per LLDP finden** (`switches.lldp_discovery`): Von den eingetragenen Switches aus folgt der
Agent ihren LLDP-Nachbarn und fragt diese über die Management-Adresse ab, die der Nachbar per LLDP mitteilt. Das
läuft als Breitensuche über bis zu `max_depth` Ebenen und höchstens `max_switches` Switches.

Abgefragt wird ein Nachbar nur, wenn alle Bedingungen erfüllt sind:
- Er meldet die Fähigkeit „Bridge“.
- Er ist weder WLAN-AP noch Telefon.
- Er hat eine IPv4-Management-Adresse.
- Die Adresse liegt in `networks`. Die Netze erweitern die SNMP-Allowlist, und nur für SNMP. Ohne Netze findet keine
  Suche statt.

Gefundene Switches nutzen die Standard-Zugangsdaten `switches.snmp` und den Netbox-Standort des Switches, über den sie
gefunden wurden. Derselbe Switch unter einer zweiten Adresse wird über den sysName erkannt und nur einmal abgeglichen.
Das Job-Protokoll listet die gefundenen Switches und für jeden übersprungenen Nachbarn den Grund. Mit
`--param host=…` wird nur dieser eine Switch abgeglichen, ohne Suche.

Mit interner CA: Zertifikat nach `./ca.pem` legen, Volume in `docker-compose.yml` einkommentieren und
`verify_tls: /config/ca.pem` setzen.

## Arbeiten mit dem Agent

**Web-Oberfläche**
- *Freigaben*: offene Vorschläge mit Diff (Wiki) bzw. Schritt-Plan (Netbox). Vor dem Übernehmen lassen sich
  Titel, Pfad, Tags und Inhalt bzw. der Netbox-Plan (JSON) bearbeiten. *Ablehnen + Nicht mehr vorschlagen*
  setzt das Objekt auf die Ignorierliste.
- *Neuer Auftrag*: Stichpunkte und Dateien hochladen, optional eine Zielseite angeben.
- *Fragen*: Frage ans Wiki stellen, Antwort mit Quellen.
- *Wiki-Lint*: letzter Prüfbericht, „Jetzt prüfen“ startet eine neue Prüfung.
- *Jobs*: Läufe starten und Protokolle ansehen. Jobs laufen nacheinander, damit das Modell die CPU nicht doppelt
  belegt.
- *Konventionen*: zeigt, was der Agent je Wiki-Bereich gelernt hat.
- *Status*: Verbindungstest, erlaubte Hosts und Ignorierliste.

**Kommandozeile** (im Container: `docker compose exec agent doku-agent …`)

```bash
doku-agent check                         # Verbindungen und Allowlist prüfen
doku-agent run discovery                 # Netbox-Discovery jetzt ausführen
doku-agent run wazuh_rules               # weitere: wazuh_decoders, wazuh_config, wazuh_sca, intune, fortigate,
                                         #          fortigate_netbox, switches, netbox_devices, wiki_index, wiki_lint
doku-agent run entra                     # Entra ID komplett; nur Teile: --param areas=conditional_access,audit
doku-agent run fortigate --param device=fw-zentrale --param sections=policies,audit
doku-agent run fortigate_netbox --param device=fw-zentrale   # Firewall in Netbox eintragen/abgleichen
doku-agent run switches --param host=10.0.0.2                # ein Switch (ohne host: alle)
doku-agent run netbox_device --param id=42 --param kind=device
doku-agent doc "Backup der Fileserver" -f notizen.txt [-t infrastruktur/backup/fileserver]
doku-agent proposals                     # offene Vorschläge
doku-agent show 12                       # Vorschlag mit Diff
doku-agent approve 12 | doku-agent reject 12 --ignore
doku-agent conventions [bereich]         # gelernte Konventionen
doku-agent frage "Wo läuft der Lizenzserver?"   # Antwort mit Quellen
doku-agent lint                          # Wiki prüfen und Bericht ausgeben
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

## Bestehende Maschinen abgleichen

Findet die Discovery eine Maschine bereits in Netbox (über Seriennummer, Hostname oder MAC), vergleicht sie die
Angaben und schlägt Anpassungen vor. Welche Arten aktiv sind, steuert `netbox.sync`:

| Art | Was angepasst wird |
|---|---|
| `missing` | Leere Felder füllen: Seriennummer, Plattform, Gerätetyp statt „Unbekannt“, primäre IPv4; fehlende Interfaces, MACs und IPs ergänzen |
| `os` | Plattform nach OS-Wechsel (z.B. Ubuntu 22.04 → 24.04), vCPUs und RAM von VMs (RAM erst ab `memory_tolerance_percent` Abweichung) |
| `network` | Neue IP-Adressen, MAC-Wechsel an einem Interface, primäre IPv4 auf die aktuelle Haupt-IP |
| `rename` | Neuer Hostname bei gleicher Seriennummer/MAC; eine Domain-Endung (`.firma.local`) bleibt erhalten |

So bleibt eure Handarbeit geschützt:

- **Alles mit Freigabe.** Ein Vorschlag pro Maschine, jede Änderung mit Vorher/Nachher und einzeln abwählbar
  (CLI: `doku-agent approve 12 --nur c1,c3`). Hängt eine Änderung von einer anderen ab (IP an einem neuen
  Interface), wird das angezeigt und geprüft.
- **Konfliktschutz.** Wurde ein Feld nach dem Vorschlag in Netbox von Hand geändert, wird diese Änderung beim
  Übernehmen übersprungen statt überschrieben.
- **Nichts wird gelöscht.** IPs oder Interfaces, die Wazuh nicht mehr meldet, erscheinen nur als Hinweis.
  Abweichende Seriennummern oder Modelle werden ebenfalls nur gemeldet (möglicher Hardwaretausch).
- **Vollständiges Rollback.** Scheitert ein Schritt, werden angelegte Objekte gelöscht und geänderte Felder auf den
  vorherigen Wert zurückgesetzt.
- Ein allgemeinerer OS-Name gilt nicht als Abweichung: Meldet Intune nur „Windows“, bleibt eine gepflegte Plattform
  „Windows 11 Pro“ stehen.
- Abgewählte oder abgelehnte Änderungen werden beim nächsten Lauf erneut vorgeschlagen. Soll eine Maschine dauerhaft
  in Ruhe gelassen werden: ablehnen mit „Nicht mehr vorschlagen“ (rückgängig unter *Status › Ignorierliste*).
- Hat sich die Abweichung erledigt (z.B. von Hand korrigiert), wird ein offener Vorschlag automatisch geschlossen.
- Nach dem Übernehmen wird der Wiki-Steckbrief aktualisiert. Nach einer Umbenennung folgt die bestehende Seite dem
  neuen Namen (Titel), statt dass eine zweite Seite entsteht.

### Custom Fields: feste Zuordnung und „zuletzt gesehen“

Seriennummer, Hostname und MAC können sich ändern. Deshalb merkt sich der Agent in drei Custom Fields, welche Maschine
zu welchem Wazuh-Agent und welchem Intune-Gerät gehört:

| Feld | Typ | Pflege |
|---|---|---|
| `wazuh_agent_id` | Text | beim Anlegen gesetzt; bei bestehenden Maschinen bzw. nach Neuinstallation des Agents als Änderung „Kennung“ mit Freigabe |
| `intune_device_id` | Text | wie oben |
| `last_seen` | Datum | letzter Kontakt laut Wazuh/Intune (Ortszeit); wird **ohne Freigabe** gesetzt und nur vorwärts geändert |

- Die Wiedererkennung prüft zuerst die IDs, dann Seriennummer, Hostname und MAC.
- Fehlen die Felder, schlägt die Discovery **einmalig** vor, sie anzulegen (für Geräte und VMs, Gruppe „doku-agent“).
  Wer sie lieber selbst anlegt: Namen, Typen und Objekttypen wie in der Tabelle; `doku-agent check` zeigt, ob alles passt.
  Die Namen sind unter `netbox.custom_fields` einstellbar, `enabled: false` schaltet die Funktion ab.
- `last_seen` ist die einzige Ausnahme von „alles mit Freigabe“: Der Wert ändert sich bei jeder aktiven Maschine täglich.
  Er erscheint deshalb auch nicht im Wiki-Steckbrief (sonst gäbe es jede Nacht neue Vorschläge). Jede Aktualisierung
  steht wie gewohnt im Netbox-Changelog.

## vCenter

Mit `vcenter.enabled: true` ist das vCenter dritte Quelle der Discovery, neben Wazuh und Intune:

- **Cluster** werden angelegt (Clustertyp `VMware vSphere`, Standort `netbox.site`). **ESXi-Hosts** werden Geräte mit
  Rolle `hypervisor`, Hersteller, Modell und Seriennummer und gehören zum Cluster.
- **VMs** kommen in ihren Cluster und, sobald der Host in Netbox steht, auf ihr Gerät (Netbox verlangt, dass Host und
  VM im selben Cluster liegen; sonst erscheint ein Hinweis). vCPU und RAM stammen aus dem vCenter, nicht aus dem
  Gastsystem. Ausgeschaltete VMs werden ebenfalls angelegt (`powered_off: false` schaltet das ab).
- Jede Disk wird als **virtuelle Disk** angelegt (Größe in MB); Netbox bildet daraus die Disk-Summe der VM. Wird eine
  Disk vergrößert, schlägt der Abgleich die neue Größe vor.
- Die Zuordnung zu Wazuh und Intune läuft über die Seriennummer: Aus der BIOS-UUID der VM entsteht dieselbe
  `VMware-42 1a …`-Nummer, die das Gastsystem meldet. Netbox erlaubt nur 50 Zeichen; der Agent speichert sie deshalb
  ohne Leerzeichen und vergleicht Seriennummern immer ohne Leerzeichen.
- Bei bekannten VMs schlägt der Abgleich unter „vCenter“ Cluster- bzw. Host-Wechsel (vMotion zwischen Clustern) vor.

## Switches (SNMP, LLDP, MAC-Tabelle)

Der Job `switches` fragt jeden Switch aus `switches.devices` per SNMP ab – herstellerunabhängig über Standard-MIBs –
und erzeugt je Switch **einen** Vorschlag mit einzeln abwählbaren Änderungen:

| Änderung | Woher |
|---|---|
| Gerät | `sysName`, Modell und Seriennummer aus der ENTITY-MIB; Rolle `switch` |
| Ports | IF-MIB: fehlende Ports mit Name, Beschreibung (`ifAlias`) und Typ nach Geschwindigkeit (z.B. `1000base-t`, `10gbase-x-sfpp`) |
| Kabel zu Nachbarn | LLDP: Gegenstelle wird über Systemname bzw. Chassis-MAC und Port in Netbox gesucht |
| Kabel zu Endgeräten | MAC-Tabelle: nur an Ports mit genau einer gelernten MAC (`mac_table_max_macs`), deren Interface in Netbox bekannt ist |

- Uplinks (Ports mit LLDP-Nachbar oder vielen MACs) bekommen nie ein Endgeräte-Kabel. MACs von VMs werden nicht
  verkabelt.
- Ist ein Port schon verkabelt, wird nur ein Hinweis angezeigt, falls das Kabel woanders hinführt – bestehende Kabel
  werden nie geändert oder gelöscht.
- Abgefragt werden nur die konfigurierten Hosts (UDP 161); andere Ziele blockiert der SNMP-Client wie die HTTP-Allowlist.
- Der Steckbrief zeigt danach je Port die Spalte „Verbunden mit“.

## Abdeckungsbericht

Nach jeder Discovery vergleicht der Agent Netbox mit den Quellen und schlägt die Seite `infrastruktur/abdeckung` vor
(ohne Datum, also nur bei geänderten Befunden):

| Prüfung | Regel |
|---|---|
| Ohne Wazuh-Agent | Netbox-Maschinen mit Rolle aus `coverage.wazuh_roles` (Standard: `server`, `client`), die kein Wazuh-Agent meldet |
| Ohne Intune | Rollen aus `coverage.intune_roles` (Standard: `client`), die Intune nicht kennt |
| Nicht in Netbox | von Wazuh, vCenter oder Intune gemeldet, in Netbox nicht gefunden – mit Status „Vorschlag offen“ oder „ignoriert“ |
| Funkstille | `last_seen` älter als `coverage.stale_days` (Standard 30 Tage); ausgeschaltete VMs sind gekennzeichnet |

## Entra ID

Der Job `entra` liest über Microsoft Graph (nur GET) und schlägt diese Seiten unter `identitaet/entra/` vor:

| Seite | Inhalt |
|---|---|
| `conditional-access` | Übersicht: jede Richtlinie mit Status, Benutzern, Ressourcen, Bedingungen und Steuerung, verlinkt auf ihre Seite |
| `conditional-access/<name>` | je Richtlinie: Erklärung durch das LLM, Grunddaten, Zuweisungen (Benutzer, Gruppen, Rollen, Gäste, Apps, Benutzeraktionen), Bedingungen (Client-Apps, Plattformen, Standorte, Risiken, Gerätefilter), Gewähren und Sitzung |
| `benannte-standorte` | IP-Bereiche und Länder, vertrauenswürdig ja/nein, verwendet in welchen Richtlinien |
| `authentifizierungsstaerken` | integrierte und eigene Stärken mit erlaubten Methodenkombinationen |
| `authentifizierungsmethoden` | jede Methode (FIDO2, Authenticator, SMS …) mit Status, Zielgruppen und Einstellungen; Migrationsstatus, Registrierungskampagne |
| `mandant` | Sicherheitsstandards, Benutzer- und Gastrechte, Benutzerzustimmung für Apps, Admin-Zustimmungsanforderungen, mandantenübergreifender Zugriff (Standard und Partner) |
| `rollen` | Verzeichnisrollen mit Zuweisungen: aktiv dauerhaft, aktiv befristet, aktiviert oder über PIM berechtigt; Admin-Rollen zuerst |
| `pruefung` | Befunde (siehe unten) |

**Prüfung:**

- **Nicht durchgesetzte Richtlinien:** aus oder nur im Berichtsmodus.
- **Grundschutz** (entfällt bei aktiven Sicherheitsstandards):
  - Es gibt eine aktive MFA-Richtlinie für alle Benutzer und für jede Admin-Rolle der Microsoft-Vorlage.
  - Die Richtlinien gelten ohne Standort-, Plattform-, Risiko- oder Gerätebedingung. Nur bedingt geltende Richtlinien
    werden genannt.
  - Legacy-Authentifizierung wird für alle blockiert.
- **Notfallkonten:** Die Konten aus `entra.breakglass` müssen in jeder aktiven Richtlinie ausgenommen sein, direkt oder
  über eine Gruppe. Ohne Konfiguration nennt die Prüfung Kandidaten, also Benutzer, die in vielen Richtlinien
  ausgenommen sind.
- **Verweise auf gelöschte Objekte:** Benutzer, Gruppen oder Standorte, die eine Richtlinie noch nennt.
- **Privilegierte Rollen:**
  - mehr als `max_global_admins` oder nur ein Globaler Administrator
  - Gäste in Admin-Rollen
  - dauerhaft aktive statt über PIM berechtigte Admin-Rollen (nur mit PIM-Daten; Notfallkonten ausgenommen)
- **Mandant:** Jeder darf Apps registrieren, Benutzer dürfen allen Apps zustimmen, jeder darf Gäste einladen, Gäste
  haben Mitgliederrechte.
- **Methoden:** SMS oder Anruf sind aktiv.

Erklärungen werden je Richtlinie nach Inhalt zwischengespeichert; unveränderte Richtlinien erzeugen keine neuen
Vorschläge. Ist ein Bereich nicht lesbar (fehlende Berechtigung), werden die übrigen dokumentiert und die Prüfung
entfällt, weil sie unvollständig wäre. Mit `user_names: count` erscheinen keine Personennamen im Wiki, nur Anzahlen
(„2 Benutzer“, „Notfallkonto 1“).

## Active Directory

Der Job `ad` liest per LDAP (nur Suchen) und SYSVOL (nur Lesen) und schlägt diese Seiten unter
`identitaet/active-directory/` vor:

| Seite | Inhalt |
|---|---|
| `gruppenrichtlinien` | alle GPOs mit Status, Verknüpfungen, WMI-Filter, Änderungsdatum und Erweiterungen, verlinkt auf ihre Seite; Verknüpfungen auf gelöschte GPOs |
| `gruppenrichtlinien/<name>` | je GPO: Beschreibung durch das LLM, Grunddaten (Status, Version in AD und SYSVOL, WMI-Filter mit Abfrage), Verknüpfungen (Domäne, OUs, Standorte; Reihenfolge, erzwungen, deaktiviert, blockierte Vererbung am Ziel), Sicherheitsfilterung, Bearbeitungsrechte, Besitzer, Computer- und Benutzerkonfiguration |
| `ou-struktur` | OU-Baum mit verknüpften GPOs in Reihenfolge, Vererbung, Löschschutz und Anzahl der Benutzer/Computer; Delegationen („Helpdesk – Kennwort zurücksetzen – untergeordnete user-Objekte“); Standardcontainer für neue Objekte |
| `kennwortrichtlinien` | wirksame Domänenrichtlinie, feingranulare Kennwortrichtlinien mit Rangfolge und Geltungsbereich, Kerberos-Richtlinie aus der GPO an der Domäne |
| `privilegierte-konten` | Organisations-, Domänen- und Schema-Admins, Administratoren, Konten-/Server-/Sicherungs-/Druck-Operatoren, Schlüsseladministratoren, Richtlinien-Ersteller-Besitzer, DnsAdmins – mit allen Mitgliedern auch über verschachtelte Gruppen und die primäre Gruppe; Dienstkonten (SPN, gMSA), Kerberos-Delegierung, krbtgt, Administrator, Gast |
| `domaene` | Funktionsebenen, Papierkorb, Tombstone, MachineAccountQuota, LAPS, Domänencontroller mit Standort, GC, RODC und Betriebsmasterrollen, Standorte, Subnetze, Standortverknüpfungen, Vertrauensstellungen, Betriebssysteme der Computer |
| `pruefung` | Befunde (siehe unten) |

**Einstellungen einer GPO:**
- **Administrative Vorlagen** aus `Registry.pol` mit Richtlinienname, Status (aktiviert/deaktiviert), Optionen und
  Kategorie aus dem Central Store. Werte ohne Vorlage erscheinen roh mit Schlüssel, Wert und Daten, Windows-Firewall-
  Regeln als eigene Tabelle.
- **Sicherheitseinstellungen** aus `GptTmpl.inf`: Konto- und Kerberos-Richtlinien, Überwachungsrichtlinie, Zuweisen von
  Benutzerrechten (mit aufgelösten Namen), Sicherheitsoptionen, eingeschränkte Gruppen, Systemdienste,
  Ereignisprotokoll, Berechtigungen auf Registrierung und Dateisystem.
- **Erweiterte Überwachung** (`audit.csv`), **Skripte** (Start/Herunterfahren, An-/Abmeldung, auch PowerShell) und
  **Preferences** (lokale Benutzer und Gruppen, Laufwerke, Registrierung, Aufgaben, Dienste, Dateien, Drucker …) mit
  Aktion und Zielgruppenadressierung. Andere Erweiterungen (Softwareinstallation, Ordnerumleitung …) werden als
  Dateien genannt, aber nicht ausgewertet.

**Prüfung:**
- **Gruppenrichtlinien:** gespeicherte Kennwörter in Preferences (MS14-025), nicht verknüpft oder alle Verknüpfungen
  aus, verknüpft aber komplett deaktiviert, leer, Ordner fehlt in SYSVOL, Version in AD und SYSVOL verschieden,
  Dateipfad zeigt auf fremden Server, WMI-Filter fehlt, Computer ohne Leserecht (MS16-072), bearbeitbar für alle,
  Verknüpfungen auf gelöschte GPOs.
- **Kennwortrichtlinien:** Mindestlänge unter `min_password_length`, ohne Komplexität, ohne Sperre, umkehrbare
  Verschlüsselung, kurze Chronik; PSOs, die für niemanden gelten.
- **Privilegierte Konten:** „Kennwort läuft nie ab“, SPN an Admin-Konten, nicht in Protected Users und nicht „nicht
  delegierbar“, inaktive Admins, Kennwort älter als ein Jahr, `adminCount=1` ohne privilegierte Gruppe, krbtgt
  älter als `krbtgt_max_age_days`, aktives Gastkonto.
- **Kerberos:** Benutzerkonten mit SPN (Kerberoasting), ohne Vorauthentifizierung (AS-REP-Roasting), uneingeschränkte
  Delegierung außerhalb der DCs, Protokollübergang, nur DES.
- **Konten:** Computer und Benutzer ohne Lebenszeichen seit `stale_days`, „Kennwort nicht erforderlich“, Computer im
  Standardcontainer, Computer ohne LAPS-Kennwort.
- **Berechtigungen:** DCSync-Rechte außerhalb der DCs, Vollzugriff, Berechtigungen ändern oder Besitz übernehmen auf
  Domäne und AdminSDHolder für Nicht-Admins, Schreibrechte für alle auf OUs.
- **Domäne:** Papierkorb aus, MachineAccountQuota > 0, Funktionsebene unter 2016, DCs ohne Herstellersupport, externe
  Vertrauensstellungen ohne SID-Filterung, TGT-Delegierung über Vertrauensstellungen, kein LAPS im Schema.

Damit unveränderte Daten keine Schein-Änderungen erzeugen, stehen auf den Seiten Daten statt Zeitspannen
(„Kennwort gesetzt am …“, „ohne Anmeldung > 90 Tage“). `lastLogonTimestamp` wird im AD nur alle 9–14 Tage
repliziert; „inaktiv“ ist daher eine Näherung (bei Computern zählt auch der automatische Kennwortwechsel). Mit
`user_names: count` erscheinen keine Personennamen im Wiki, nur Anzahlen; Gruppen, Computer und Dienstkonten bleiben
benannt.

## Firewall-Dokumentation (FortiGate)

Je Firewall und VDOM entstehen sechs Seiten unter `netzwerk/firewall/<name>/`:

| Seite | Inhalt |
|---|---|
| `regeln` | Zusammenfassung des Regelwerks, Tabelle aller Policies in Auswertungsreihenfolge (Quelle, Ziel, Dienst mit aufgelösten Objekten, Aktion, NAT, Sicherheitsprofile, Logging) und je Regel eine Erklärung durch das LLM |
| `nat` | Virtuelle IPs/Portweiterleitungen, IP-Pools, Regeln mit Quell-NAT, zentrale SNAT-Tabelle |
| `objekte` | Adressen, Adressgruppen, Dienste und Dienstgruppen mit der Spalte „In Regel“ – unbenutzte Objekte fallen sofort auf |
| `netzwerk` | Interfaces mit VLANs, IPs, Rollen und Verwaltungszugriff, Zonen, statische Routen |
| `vpn` | IPsec-Tunnel (Gegenstelle, IKE-Version, Verfahren) und Phase-2-Netze; Hinweis auf veraltete Verfahren |
| `pruefung` | Hygiene-Check: verdeckte Regeln (eine frühere Regel deckt Quelle, Ziel, Dienst und Interfaces vollständig ab), any-any, erlaubt ohne Logging, Internet ohne Sicherheitsprofil, deaktivierte Regeln, unbenutzte Objekte |

- Erklärungen werden in Gruppen zu sechs Regeln erzeugt und nach Inhalt zwischengespeichert. Der erste Lauf bei einigen
  hundert Regeln dauert auf CPU entsprechend (nachts unkritisch), danach werden nur geänderte Regeln neu erklärt.
- Geheimnisse (PSKs, Passwörter, verschlüsselte `ENC …`-Werte) werden entfernt, bevor Daten das LLM oder das Wiki
  erreichen.
- Es werden ausschließlich GET-Anfragen gestellt.
- Verdeckte Regeln erkennt die Prüfung über IP-Netze, Bereiche und Ports. FQDN-, Länder- und ähnliche Objekte gelten
  nur bei gleichem Namen als abgedeckt, damit keine Regel fälschlich als überflüssig erscheint.

**Firewall-Regeln im Steckbrief:** Der Netbox-Steckbrief einer Maschine listet die Regeln, deren Quelle oder Ziel ihre
IP enthält – über Host-, Bereichs- und VIP-Objekte sowie Netze bis `/24` (`steckbrief_min_prefix`). Größere Netze und
„all“ werden ausgelassen, sonst stünde jede Regel auf jeder Seite.

**FortiGate → Netbox:** Der Job `fortigate_netbox` trägt jede Firewall als Gerät (Rolle `firewall`) ein und gleicht
sie danach ab: physische Interfaces, Aggregate als LAG mit Mitgliedern, VLAN-Interfaces mit Parent und VLAN, IP-Adressen
(die IP aus der Geräte-URL wird primäre IP), VLANs und Präfixe je Interface-Netz. Für WAN-Interfaces werden keine
Präfixe angelegt (`netbox_skip_roles`). Ein Vorschlag je Firewall, jede Änderung einzeln abwählbar.

## Fragen ans Wiki

Der Agent zerlegt jede Wiki-Seite an ihren Überschriften, berechnet mit dem lokalen Embedding-Modell
(`qwen3-embedding:0.6b`, mehrsprachig) Vektoren und speichert sie in der SQLite-Datenbank. Bei einer Frage sucht er die
passendsten Abschnitte und lässt das Sprachmodell **nur auf deren Grundlage** antworten, mit Nummern als Belegen.

- Der Index wird inkrementell aktualisiert: nachts (`wiki_index`) und nach jeder Freigabe für die geänderte Seite.
- Dieselbe Suche hilft bei freien Aufträgen, die richtige bestehende Seite zum Ergänzen zu finden – auch wenn Titel und
  Pfad andere Wörter verwenden als der Auftrag.
- Steht die Antwort nicht im Wiki, sagt das Modell das. Getestet: „Wo läuft der Lizenzserver?“ → richtige Antwort mit
  Quellen in knapp einer Minute auf 4 CPU-Kernen.
- Der Agent liest alle Seiten, die sein Wiki.js-API-Schlüssel sehen darf. Wer Fragen stellen kann, sieht also Auszüge
  aus all diesen Seiten – die Oberfläche hat nur einen Benutzer.

## Wiki-Lint

`wiki_lint` (Standard: sonntags) prüft das ganze Wiki:

| Prüfung | Wie |
|---|---|
| Tote Links | Wiki.js erfasst beim Rendern jeden internen Link, auch auf fehlende Seiten. Geprüft wird gegen die Seitenliste aller Sprachen. Relative Links löst Wiki.js relativ zur Seite selbst auf – genauso zeigt sie der Bericht. Externe Links werden nicht aufgerufen. |
| Mögliche Dubletten | Gleicher Titel oder nahezu gleicher Inhalt (Suchindex, Schwelle `lint.duplicate_threshold`). Vom Agent gepflegte Seiten verschiedener Objekte (z.B. zwei Steckbriefe) gelten nie als Dublette. |
| Seiten ohne Tags | Seiten ohne ein einziges Tag. |
| Veraltete Seiten | Jede Seite mit Quellobjekt (Netbox, Intune, Wazuh, FortiGate) wird über ihren Generator neu berechnet. Weicht das Ergebnis ab, entsteht ein normaler Vorschlag mit Diff. |
| Quelle gelöscht | Gerät, Richtlinie, Regeldatei usw. existiert nicht mehr – wird nur gemeldet, nichts gelöscht. |

Der Bericht steht unter *Wiki-Lint* und zusätzlich als Seite `wartung/wiki-lint` (als Vorschlag, ohne Datum – sie ändert
sich nur, wenn sich die Befunde ändern).

**Korrekturvorschläge** (`lint.fix_links`, `lint.suggest_tags`):

- **Tote Links:** Gibt es genau ein plausibles Ziel, entsteht je Seite ein Vorschlag mit Diff, der die Links ersetzt
  (Anker wie `#restore` bleiben erhalten). Gesucht wird nach einer Seite mit gleichem Namen an anderer Stelle, nach einem
  sehr ähnlichen Pfad und über den Suchindex. Ist das Ziel nicht eindeutig, nennt der Bericht nur die Kandidaten.
- Links in Code-Blöcken und in Blöcken des Agents werden nicht angefasst. Wurde die Seite vor der Freigabe geändert,
  wird die Korrektur auf der neuen Fassung neu angewendet.
- **Seiten ohne Tags:** Vorschlag mit den Tags, die die Seiten im selben Ordner tragen, sonst die der inhaltlich
  ähnlichsten Seiten.

## Modell und Leistung (16 GB RAM, nur CPU)

| Modell | RAM | Einsatz |
|---|---|---|
| `qwen3:8b` (Standard) | ca. 6–7 GB inkl. 8k-Kontext | gute Texte und zuverlässiges JSON; einige Minuten pro Seite |
| `qwen3:4b` | ca. 3–4 GB | etwa doppelt so schnell, schwächer bei langen Erklärungen |
| `qwen3-embedding:0.6b` (Suche) | ca. 1 GB | Suchindex und Fragen; bleibt neben dem Sprachmodell geladen (`OLLAMA_MAX_LOADED_MODELS=2`) |

Modell wechseln: `llm.model` in `config.yaml` und `LLM_MODEL` in `.env` anpassen, dann
`docker compose --profile setup run --rm ollama-pull` und `docker compose restart agent`.
Strukturierte Daten (Tabellen, Steckbriefe, Netbox-Pläne) erzeugt der Agent immer deterministisch, das LLM schreibt
nur Erklärungen, Beschreibungen und freie Texte. So bleiben Fakten korrekt, auch wenn das kleine Modell schwächelt.

## Fließtext und Faktenprüfung

Damit Seiten lesbar sind und nicht nur aus Tabellen bestehen, steht über den Tabellen erklärender Text:

| Seite | Abschnitt | Inhalt |
|---|---|---|
| Steckbrief | **Überblick** | Was die Maschine ist, wofür sie laut Rolle und Beschreibung dient, wo sie läuft, wie sie angebunden ist, welche Firewall-Regeln sie betreffen |
| Prüfseiten (FortiGate, Entra ID, Abdeckung) | **Bewertung** | Gesamtzustand, die dringendsten Befunde mit Begründung und die nächsten Schritte in sinnvoller Reihenfolge |
| Übersichten (Conditional Access, Methoden, Mandant, Rollen, Intune-Gruppen, Firewall-Regeln/Netzwerk/NAT/VPN, SCA) | **Zusammenfassung** | Der Ist-Zustand im Zusammenhang |
| Einstellungsseiten (Intune-Richtlinien, Wazuh-Konfiguration, CA-Richtlinien) | **Beschreibung** | Einstellungen thematisch erklärt statt einzeln aufgezählt |

Die Tabellen bleiben vollständig darunter. Der Text entsteht aus genau den Daten, die auch in den Tabellen stehen, und
wird danach automatisch geprüft:

- Jede **IP-Adresse, Zahl, Version, jedes Datum** und jeder **technische Name** im Text (Hostnamen, Domains, UPNs,
  Dateinamen, zitierte oder fett gesetzte Namen) muss in den Daten vorkommen. Zahlen mit Einheit („16 GB“) und
  deutsche Datumsangaben werden erkannt. Speichergrößen bekommt das Modell schon in MB und GB, damit es nicht rechnet.
- Findet die Prüfung unbelegte Angaben, bekommt das Modell einen zweiten Versuch mit genau dieser Liste. Scheitert
  auch der, steht statt des Textes eine **feste Vorlage** aus denselben Daten, und das Job-Protokoll nennt die Angaben.
- Allgemeines Fachwissen ohne konkrete Zahlen („MFA erschwert die Übernahme von Konten“) ist erlaubt. Ausgeschriebene
  Zahlwörter („zwei“) werden nicht geprüft.
- Texte werden nach Eingabe-Hash zwischengespeichert. Unveränderte Daten erzeugen keinen neuen Text und keinen neuen
  Vorschlag. Mitgliederzahlen von Gruppen fließen bewusst nicht in den Text ein, damit er sich nicht täglich ändert.

Einstellbar unter `narrative`:
- `areas` legt fest, wo zusätzlicher Text entsteht.
- `length: compact` erzeugt einen Absatz statt zwei bis vier.
- `fact_check: false` schaltet die Prüfung ab; das ist nicht empfohlen.
- `enabled: false` schaltet die zusätzlichen Abschnitte ganz ab.

**Nach dem Update:** Bestehende Seiten bekommen die neuen Abschnitte als normalen Vorschlag mit Diff, oben eingefügt.
Eigene Texte bleiben unverändert. Beim ersten Lauf entsteht dafür viel Text auf einmal, entsprechend lange rechnet der
Agent. Danach wird nur noch geänderter Inhalt neu formuliert.

**Gemessen** mit `qwen3:8b` auf 4 CPU-Kernen ohne GPU (langsame Testumgebung, auf echter Hardware eher schneller):

| Text | Dauer | Ergebnis |
|---|---|---|
| Steckbrief (VM mit Firewall-Regeln) | 150 s | bestanden im ersten Versuch |
| Conditional-Access-Richtlinie | 121 s | bestanden im ersten Versuch |
| Bewertung der FortiGate-Prüfung | 188 s | bestanden im ersten Versuch |
| Intune-Compliance-Richtlinie | 212 s | bestanden im ersten Versuch |

Grob zwei bis vier Minuten je Text: 100 Steckbriefe brauchen beim ersten Lauf also einige Stunden, nachts unkritisch.
In einem früheren Versuch hat die Prüfung echte Fehler des Modells abgefangen: einen verstümmelten Interface-Namen
(„ens19,2“ statt `ens192`) und eine falsch addierte Befundzahl.

**Was die Prüfung nicht leistet:** Sie erkennt erfundene oder falsch abgeschriebene Werte, aber keine falschen
Zusammenhänge zwischen echten Werten. Im Versuch ordnete eine Bewertung etwa eine Regel der falschen Prüfung zu. Den Text
deshalb bei der Freigabe lesen. Die Tabellen darunter sind immer exakt.

## Datenschutz und Sicherheit

- **Egress-Allowlist:** Jeder HTTP-Client des Agents prüft vor dem Senden, ob der Ziel-Host konfiguriert ist (Wiki,
  Ollama, Netbox, Wazuh, FortiGates, vCenter, bei Intune `login.microsoftonline.com` und `graph.microsoft.com`). Weiterleitungen werden
  nicht verfolgt, Proxy-Variablen werden standardmäßig ignoriert. SNMP geht nur an die Switches aus `switches.devices`,
  LDAP und SMB nur an die Domänencontroller aus `ad.servers` (keine LDAP-Referrals, keine DFS-Weiterleitungen).
- **Ollama ohne Internet:** Der Ollama-Container hängt nur am internen Netz `llm`. Zusätzlich ist
  `OLLAMA_NO_CLOUD=1` gesetzt (keine Cloud-Modelle, keine Websuche). Nur der einmalige `ollama-pull` hat Internet.
- **Geheimnisse:** Tokens nur in `.env` (nicht eingecheckt). In Wazuh-Konfigurationen, Intune-Einstellungen und
  FortiGate-Objekten werden Passwörter, Keys, PSKs, Tokens und Webhooks vor dem Prompt und vor dem Wiki maskiert.
- **Entra ID:** Benutzernamen und UPNs (z.B. ausgenommene Notfallkonten) stehen in den Seiten, wenn
  `entra.user_names` nicht `count` ist. Sie gehen nur an das lokale Sprachmodell und ins eigene Wiki.
- **Active Directory:** Das Lesekonto braucht keine Administratorrechte; der Agent schreibt nie ins AD. Kennwörter aus
  GPO-Preferences (`cpassword`) werden erkannt, aber weder ans Sprachmodell noch ins Wiki gegeben. Namen von Personen
  (Mitglieder privilegierter Gruppen, Befunde) lassen sich mit `ad.user_names: count` ausblenden.
- **Embeddings und Fragen** laufen über dasselbe lokale Ollama; Index und Fragen liegen in der lokalen SQLite-Datenbank.
- **Oberfläche:** Basic-Auth (Pflicht), CSRF-Schutz, strikte Content-Security-Policy, keine externen Skripte oder Fonts,
  standardmäßig nur auf `127.0.0.1` gebunden. Der Agent-Container läuft ohne Root, mit read-only Dateisystem und
  ohne Capabilities.
- **Zugriff aus dem LAN:** Basic-Auth überträgt das Passwort nur Base64-kodiert und es gibt kein Rate-Limiting.
  Wer die Oberfläche über `localhost` hinaus freigibt, sollte einen Reverse-Proxy mit TLS davorsetzen (z.B. den
  vorhandenen Nginx/Traefik) und den Zugriff auf das Admin-Netz beschränken.

## Entwicklung

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/pytest                      # Unit- und Komponententests (Fakes für Wiki.js, Netbox, Graph, FortiGate, vCenter, LLM)
```

Integrationstests gegen echte Test-Instanzen (werden ohne Variablen übersprungen; nie gegen Produktion laufen lassen,
sie legen Testseiten bzw. Testobjekte an):

```bash
DOKU_IT_WIKI_URL=http://127.0.0.1:3000 DOKU_IT_WIKI_KEY=… \
DOKU_IT_NETBOX_URL=http://127.0.0.1:8000 DOKU_IT_NETBOX_TOKEN=nbt_… \
DOKU_IT_WAZUH_URL=https://127.0.0.1:55000 DOKU_IT_WAZUH_USER=… DOKU_IT_WAZUH_PASSWORD=… DOKU_IT_WAZUH_INSECURE=1 \
DOKU_IT_OLLAMA_URL=http://127.0.0.1:11434 \
DOKU_IT_SNMP_HOST=127.0.0.1 DOKU_IT_SNMP_PORT=1161 \
.venv/bin/pytest tests/test_integration_*.py
```

Der AD-Test (`DOKU_IT_AD_SERVER`, `DOKU_IT_AD_PORT`, `DOKU_IT_AD_SMB_PORT`, `DOKU_IT_AD_CA`) läuft gegen einen
Samba-AD-DC mit den Testdaten aus `tests/samba_ad/` (Aufbau siehe `tests/samba_ad/README.md`).

Der Switch-Test braucht einen SNMP-Simulator (z.B. `snmpsim`, Community `public`) mit den Daten des Switches
`sw-core01`, die im Kopf von `tests/test_integration_switches.py` beschrieben sind, und zusätzlich Netbox.

Aufbau und Entscheidungen: [docs/ARCHITEKTUR.md](docs/ARCHITEKTUR.md).

## Grenzen

- Wiki.js 3.x wird nicht unterstützt (andere API). Seiten im Visual Editor werden nicht bearbeitet.
- Der Netbox-Abgleich löscht nie etwas und ändert den Gerätetyp nur, wenn er „Unbekannt“ ist. Status (z.B. offline)
  wird nicht gepflegt (`last_seen` zeigt aber, wann eine Maschine zuletzt gemeldet hat). Wiki-Seiten werden nach einer
  Umbenennung nicht verschoben (nur der Titel ändert sich).
- Firewalls: nur FortiGate (FortiOS 7.x). SSL-VPN, Security-Profile im Detail und SD-WAN werden nicht dokumentiert.
  Die Prüfung erkennt verdeckte Regeln nur über auflösbare Objekte und berücksichtigt keine Zeitpläne und Benutzergruppen.
- vCenter: Ressourcenpools, Ordner, Datastores und Portgruppen werden nicht übernommen; Hosts ohne Cluster bekommen keinen
  Cluster. Mangels Testinstanz ist die vCenter-Anbindung nur gegen Fakes nach der dokumentierten API getestet.
- Switches: VLAN-Zuordnung der Ports, Port-Channels und Stacks werden nicht gepflegt. Kabel entstehen nur, wenn die
  Gegenstelle in Netbox schon ein passendes Interface hat.
- Entra ID: Identity-Protection-Risikorichtlinien, Zugriffsüberprüfungen, App-Registrierungen und Unternehmens-Apps
  werden nicht dokumentiert. Der Grundschutz-Check bewertet nur Benutzer, Rollen und „alle Ressourcen“, keine
  einzelnen Apps. PIM-Daten gibt es nur mit Entra ID P2. Mangels Testmandant ist Entra nur gegen einen Graph-Fake nach
  dem dokumentierten Schema getestet.
- Active Directory: eine Domäne je Agent; GPOs aus anderen Domänen der Gesamtstruktur erscheinen nur als Verknüpfung.
  Kein Richtlinienergebnissatz (RSoP), also keine Berechnung, was auf einem bestimmten Computer gilt. Software-
  installation, Ordnerumleitung, WLAN-/Kabel-Richtlinien, IPsec, AppLocker und WDAC werden nicht ausgewertet;
  Sicherheitsoptionen nur für eine Auswahl häufiger Werte mit Namen. SYSVOL braucht NTLM (Kerberos wird nicht
  unterstützt). Getestet gegen Samba 4.17 als AD-DC und Fakes nach der Protokolldokumentation, nicht gegen einen
  Windows-DC; Standardrechte und Anzeigenamen können bei Windows abweichen.
- Fragen ans Wiki kennen nur Wiki-Inhalte, keine Live-Daten aus Netbox oder Wazuh.
- Wazuh-Alarm-Auswertungen aus dem Indexer sind nicht enthalten (bewusst ausgeklammert).
- Bilder bzw. Screenshots in Aufträgen werden nicht ausgewertet (Vision-Modell auf CPU zu langsam).

## Lizenz

GPL-3.0, siehe [LICENSE](LICENSE).
