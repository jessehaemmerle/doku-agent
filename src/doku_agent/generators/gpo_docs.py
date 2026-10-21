"""Gruppenrichtlinien: eine Seite je GPO und eine Übersicht.

Je GPO: Status, Verknüpfungen (Domäne, OUs, Standorte) mit Reihenfolge, Sicherheitsfilterung und
Bearbeitungsrechte aus dem AD, dazu die Einstellungen aus SYSVOL – administrative Vorlagen (mit Namen aus
dem Central Store), Sicherheitseinstellungen, erweiterte Überwachung, Skripte und Einstellungen
(Preferences). Kennwörter aus Preferences erscheinen nie; das LLM beschreibt nur die Wirkung.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from doku_agent import gpo_files, markdown
from doku_agent.ad_acl import (APPLY_GROUP_POLICY, CONTROL_ACCESS, GENERIC_ALL, GENERIC_READ, GENERIC_WRITE,
                               READ_PROP, WRITE_DAC, WRITE_OWNER, WRITE_PROP, is_admin, parse_sd)
from doku_agent.connectors.ad import Entry
from doku_agent.context import Context
from doku_agent.generators import narrative
from doku_agent.generators.ad_common import AdData, AdNames, day, ou_path
from doku_agent.generators.common import mask_value
from doku_agent.pages import Block, PageDraft, propose_page, render_path

GUID_RE = re.compile(r"\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}")
GPLINK_RE = re.compile(r"\[LDAP://([^;\]]+);(\d+)\]", re.I)
STATUS = {0: "Aktiviert", 1: "Benutzerkonfiguration deaktiviert", 2: "Computerkonfiguration deaktiviert",
          3: "Alle Einstellungen deaktiviert"}
DEFAULT_DOMAIN_POLICY = "{31B2F340-016D-11D2-945F-00C04FB984F9}"
DEFAULT_DC_POLICY = "{6AC1786C-016F-11D2-945F-00C04FB984F9}"

# Clientseitige Erweiterungen (CSE-GUIDs aus den MS-GP*-Spezifikationen)
CSE_NAMES = {
    "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}": "Administrative Vorlagen",
    "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}": "Sicherheit",
    "{42B5FAAE-6536-11D2-AE5A-0000F87571E3}": "Skripte",
    "{F3CCC681-B74C-4060-9F26-CD84525DCA2A}": "Erweiterte Überwachung",
    "{C6DC5466-785A-11D2-84D0-00C04FB169F7}": "Softwareinstallation",
    "{25537BA6-77A8-11D2-9B6C-0000F8080861}": "Ordnerumleitung",
    "{B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A}": "EFS-Wiederherstellung",
    "{E437BC1C-AA7D-11D2-A382-00C04F991E27}": "IP-Sicherheit",
    "{0ACDD40C-75AC-47AB-BAA0-BF6DE7E7FE63}": "Drahtlosnetzwerk (802.11)",
    "{B587E2B1-4D59-4E7E-AED9-22B9DF11D053}": "Kabelnetzwerk (802.3)",
    "{8A28E2C5-8D06-49A4-A08C-632DAA493E17}": "Bereitgestellte Drucker",
    "{16BE69FA-4209-4250-88CB-716CF41954E0}": "Zentrale Zugriffsrichtlinien",
    "{A2E30F80-D7DE-11D2-BBDE-00C04F86AE3B}": "Internet Explorer-Wartung",
    "{D76B9641-3288-4F75-942D-087DE603E3EA}": "LAPS (Legacy)",
    "{F9C77450-3A41-477E-9310-9ACD617BD9E3}": "Einstellungen: Anwendungen",
    "{728EE579-943C-4519-9EF7-AB56765798ED}": "Einstellungen: Datenquellen",
    "{1A6364EB-776B-4120-ADE1-B63A406A76B5}": "Einstellungen: Geräte",
    "{5794DAFD-BE60-433F-88A2-1A31939AC01F}": "Einstellungen: Laufwerkszuordnungen",
    "{0E28E245-9368-4853-AD84-6DA3BA35BB75}": "Einstellungen: Umgebung",
    "{7150F9BF-48AD-4DA4-A49C-29EF4A8369BA}": "Einstellungen: Dateien",
    "{A3F3E39B-5D83-4940-B954-28315B82F0A8}": "Einstellungen: Ordneroptionen",
    "{6232C319-91AC-4931-9385-E70C2B099F0E}": "Einstellungen: Ordner",
    "{74EE6C03-5363-4554-B161-627540339CAB}": "Einstellungen: INI-Dateien",
    "{E47248BA-94CC-49C4-BBB5-9EB7F05183D0}": "Einstellungen: Interneteinstellungen",
    "{17D89FEC-5C44-4972-B12D-241CAEF74509}": "Einstellungen: Lokale Benutzer und Gruppen",
    "{3A0DBA37-F8B2-4356-83DE-3E90BD5C261F}": "Einstellungen: Netzwerkoptionen",
    "{6A4C88C6-C502-4F74-8F60-2CB23EDC24E2}": "Einstellungen: Netzwerkfreigaben",
    "{E62688F0-25FD-4C90-BFF5-F508B9D2E31F}": "Einstellungen: Energieoptionen",
    "{BC75B1ED-5833-4858-9BB8-CBF0B166DF9D}": "Einstellungen: Drucker",
    "{E5094040-C46C-4115-B030-04FB2E545B00}": "Einstellungen: Regions- und Sprachoptionen",
    "{B087BE9D-ED37-454F-AF9C-04291E351182}": "Einstellungen: Registrierung",
    "{AADCED64-746C-4633-A97C-D61349046527}": "Einstellungen: Geplante Aufgaben",
    "{91FBB303-0CD5-4055-BF42-E512A681B325}": "Einstellungen: Dienste",
    "{C418DD9D-0D14-4EFB-8FBF-CFE535C8FAC7}": "Einstellungen: Verknüpfungen",
    "{E4F48E54-F38D-4884-BFB9-D4D2E5729C18}": "Einstellungen: Startmenü",
}
PREF_AREAS = {
    "applications": "Anwendungen", "controlpanel": "Systemsteuerung", "datasources": "Datenquellen",
    "devices": "Geräte", "drives": "Laufwerkszuordnungen", "environmentvariables": "Umgebung", "files": "Dateien",
    "folderoptions": "Ordneroptionen", "folders": "Ordner", "inifiles": "INI-Dateien",
    "internetsettings": "Interneteinstellungen", "groups": "Lokale Benutzer und Gruppen",
    "networkoptions": "Netzwerkoptionen", "networkshares": "Netzwerkfreigaben", "poweroptions": "Energieoptionen",
    "printers": "Drucker", "regionaloptions": "Regions- und Sprachoptionen", "registry": "Registrierung",
    "scheduledtasks": "Geplante Aufgaben", "services": "Dienste", "shortcuts": "Verknüpfungen",
    "startmenutaskbar": "Startmenü",
}
PREF_LABELS = {"userName": "Benutzer", "newName": "neuer Name", "fullName": "vollständiger Name",
               "description": "Beschreibung", "acctDisabled": "deaktiviert", "neverExpires": "läuft nie ab",
               "noChange": "Benutzer darf nicht ändern", "groupName": "Gruppe", "groupSid": "SID",
               "deleteAllUsers": "alle Benutzer entfernen", "deleteAllGroups": "alle Gruppen entfernen",
               "letter": "Laufwerk", "path": "Pfad", "label": "Bezeichnung", "persistent": "dauerhaft",
               "hive": "Struktur", "key": "Schlüssel", "name": "Name", "type": "Typ", "value": "Wert",
               "serviceName": "Dienst", "startupType": "Starttyp", "serviceAction": "Aktion",
               "accountName": "Konto", "fromPath": "Quelle", "targetPath": "Ziel", "shortcutPath": "Verknüpfung",
               "runAs": "ausführen als", "logonType": "Anmeldetyp", "Befehl": "Befehl"}

PREF_ACCOUNTS = {"runAs", "accountName"}  # können Personen sein (im Modus count nicht namentlich)
PREF_BOOLS = {"acctDisabled", "neverExpires", "noChange", "changeLogon", "deleteAllUsers", "deleteAllGroups",
              "removeAccounts", "persistent", "useLetter", "readOnly", "hidden", "archive", "default", "user",
              "partial", "deleteFolder", "deleteSubFolders", "deleteFiles", "userDSN", "allRegular", "limitUsers"}
SYSTEM_ACCESS = {
    "MinimumPasswordLength": ("Minimale Kennwortlänge", "Zeichen"),
    "PasswordComplexity": ("Kennwort muss Komplexitätsvoraussetzungen entsprechen", "bool"),
    "PasswordHistorySize": ("Kennwortchronik erzwingen", "gespeicherte Kennwörter"),
    "MaximumPasswordAge": ("Maximales Kennwortalter", "Tage"),
    "MinimumPasswordAge": ("Minimales Kennwortalter", "Tage"),
    "ClearTextPassword": ("Kennwörter mit umkehrbarer Verschlüsselung speichern", "bool"),
    "LockoutBadCount": ("Kontensperrungsschwelle", "ungültige Anmeldeversuche"),
    "LockoutDuration": ("Kontosperrdauer", "Minuten"),
    "ResetLockoutCount": ("Kontosperrungszähler zurücksetzen nach", "Minuten"),
    "ForceLogoffWhenHourExpire": ("Abmeldung nach Ablauf der Anmeldezeit erzwingen", "bool"),
    "LSAAnonymousNameLookup": ("Anonyme SID-/Namensübersetzung zulassen", "bool"),
    "EnableAdminAccount": ("Konto Administrator aktiviert", "bool"),
    "EnableGuestAccount": ("Konto Gast aktiviert", "bool"),
    "NewAdministratorName": ("Administratorkonto umbenennen", "text"),
    "NewGuestName": ("Gastkonto umbenennen", "text"),
    "RequireLogonToChangePassword": ("Anmeldung zum Ändern des Kennworts erforderlich", "bool"),
}
KERBEROS = {
    "MaxTicketAge": ("Maximale Gültigkeitsdauer des Benutzertickets", "Stunden"),
    "MaxRenewAge": ("Maximale Zeitspanne für die Erneuerung von Benutzertickets", "Tage"),
    "MaxServiceAge": ("Maximale Gültigkeitsdauer des Diensttickets", "Minuten"),
    "MaxClockSkew": ("Maximale Toleranz für die Synchronisation des Computertakts", "Minuten"),
    "TicketValidateClient": ("Benutzeranmeldeeinschränkungen erzwingen", "bool"),
}
EVENT_AUDIT = {"AuditSystemEvents": "Systemereignisse", "AuditLogonEvents": "Anmeldeereignisse",
               "AuditPrivilegeUse": "Rechteverwendung", "AuditPolicyChange": "Richtlinienänderungen",
               "AuditAccountManage": "Kontenverwaltung", "AuditProcessTracking": "Prozessverfolgung",
               "AuditDSAccess": "Verzeichnisdienstzugriff", "AuditObjectAccess": "Objektzugriffsversuche",
               "AuditAccountLogon": "Anmeldeversuche (Kontoanmeldung)"}
AUDIT_VALUES = {"0": "Keine Überwachung", "1": "Erfolg", "2": "Fehler", "3": "Erfolg und Fehler", "4": "Keine Überwachung"}
AUDIT_TEXT = {"success": "Erfolg", "failure": "Fehler", "success and failure": "Erfolg und Fehler",
              "no auditing": "Keine Überwachung", "not specified": "Nicht konfiguriert"}
PRIVILEGES = {
    "SeNetworkLogonRight": "Auf diesen Computer vom Netzwerk aus zugreifen",
    "SeInteractiveLogonRight": "Lokal anmelden zulassen",
    "SeRemoteInteractiveLogonRight": "Anmelden über Remotedesktopdienste zulassen",
    "SeBatchLogonRight": "Anmelden als Batchauftrag", "SeServiceLogonRight": "Anmelden als Dienst",
    "SeDenyNetworkLogonRight": "Zugriff vom Netzwerk auf diesen Computer verweigern",
    "SeDenyInteractiveLogonRight": "Lokal anmelden verweigern",
    "SeDenyRemoteInteractiveLogonRight": "Anmelden über Remotedesktopdienste verweigern",
    "SeDenyBatchLogonRight": "Anmelden als Batchauftrag verweigern",
    "SeDenyServiceLogonRight": "Anmelden als Dienst verweigern",
    "SeBackupPrivilege": "Sichern von Dateien und Verzeichnissen",
    "SeRestorePrivilege": "Wiederherstellen von Dateien und Verzeichnissen", "SeDebugPrivilege": "Programme debuggen",
    "SeTakeOwnershipPrivilege": "Übernehmen des Besitzes von Dateien und Objekten",
    "SeShutdownPrivilege": "Herunterfahren des Systems",
    "SeRemoteShutdownPrivilege": "Erzwingen des Herunterfahrens von einem Remotesystem aus",
    "SeSecurityPrivilege": "Verwalten von Überwachungs- und Sicherheitsprotokollen",
    "SeSystemtimePrivilege": "Ändern der Systemzeit", "SeTimeZonePrivilege": "Ändern der Zeitzone",
    "SeImpersonatePrivilege": "Annehmen der Clientidentität nach Authentifizierung",
    "SeLoadDriverPrivilege": "Laden und Entfernen von Gerätetreibern",
    "SeMachineAccountPrivilege": "Hinzufügen von Arbeitsstationen zur Domäne",
    "SeEnableDelegationPrivilege": "Ermöglichen, dass Computer- und Benutzerkonten für Delegierungszwecke vertraut wird",
    "SeTcbPrivilege": "Als Teil des Betriebssystems handeln", "SeCreateTokenPrivilege": "Erstellen eines Tokenobjekts",
    "SeAssignPrimaryTokenPrivilege": "Ersetzen eines Tokens auf Prozessebene",
    "SeIncreaseQuotaPrivilege": "Anpassen von Speicherkontingenten für einen Prozess",
    "SeChangeNotifyPrivilege": "Auslassen der durchsuchenden Überprüfung",
    "SeSystemEnvironmentPrivilege": "Verändern der Firmwareumgebungsvariablen",
    "SeManageVolumePrivilege": "Durchführen von Volumewartungsaufgaben",
    "SeCreatePagefilePrivilege": "Erstellen einer Auslagerungsdatei", "SeCreateGlobalPrivilege": "Erstellen globaler Objekte",
    "SeCreateSymbolicLinkPrivilege": "Erstellen symbolischer Verknüpfungen",
    "SeIncreaseBasePriorityPrivilege": "Anheben der Zeitplanungspriorität",
    "SeProfileSingleProcessPrivilege": "Erstellen eines Profils für einen Einzelprozess",
    "SeSystemProfilePrivilege": "Erstellen eines Profils der Systemleistung",
    "SeUndockPrivilege": "Entfernen des Computers von der Dockingstation",
    "SeAuditPrivilege": "Generieren von Sicherheitsüberwachungen", "SeLockMemoryPrivilege": "Sperren von Seiten im Speicher",
    "SeTrustedCredManAccessPrivilege": "Auf Anmeldeinformations-Manager als vertrauenswürdiger Aufrufer zugreifen",
    "SeIncreaseWorkingSetPrivilege": "Arbeitssatz eines Prozesses vergrößern",
    "SeSyncAgentPrivilege": "Synchronisieren von Verzeichnisdienstdaten",
    "SeCreatePermanentPrivilege": "Erstellen dauerhaft freigegebener Objekte",
    "SeRelabelPrivilege": "Bezeichnung eines Objekts ändern",
}
# Sicherheitsoptionen ([Registry Values]): Pfad (klein) -> (Bezeichnung, Werte)
_LSA = r"machine\system\currentcontrolset\control\lsa"
_SYS = r"machine\software\microsoft\windows\currentversion\policies\system"
_SVC = r"machine\system\currentcontrolset\services"
SECURITY_OPTIONS = {
    _LSA + r"\lmcompatibilitylevel": ("LAN-Manager-Authentifizierungsebene (LmCompatibilityLevel)", {
        "0": "LM- und NTLM-Antworten senden", "1": "LM und NTLM senden, NTLMv2-Sitzungssicherheit wenn ausgehandelt",
        "2": "Nur NTLM-Antworten senden", "3": "Nur NTLMv2-Antworten senden",
        "4": "Nur NTLMv2-Antworten senden, LM verweigern", "5": "Nur NTLMv2-Antworten senden, LM und NTLM verweigern"}),
    _LSA + r"\nolmhash": ("Keinen LAN-Manager-Hash speichern (NoLMHash)", None),
    _LSA + r"\restrictanonymous": ("Anonyme Aufzählung von SAM-Konten und Freigaben einschränken (RestrictAnonymous)",
                                   None),
    _LSA + r"\restrictanonymoussam": ("Anonyme Aufzählung von SAM-Konten nicht erlauben (RestrictAnonymousSAM)", None),
    _LSA + r"\everyoneincludesanonymous": ("„Jeder“-Berechtigungen gelten für anonyme Benutzer "
                                           "(EveryoneIncludesAnonymous)", None),
    _LSA + r"\limitblankpassworduse": ("Leere Kennwörter nur an der Konsole (LimitBlankPasswordUse)", None),
    _LSA + r"\scenoapplylegacyauditpolicy": ("Erweiterte Überwachung vor klassischer Überwachung "
                                             "(SCENoApplyLegacyAuditPolicy)", None),
    _LSA + r"\msv1_0\restrictsendingntlmtraffic": ("Ausgehenden NTLM-Verkehr einschränken "
                                                   "(RestrictSendingNTLMTraffic)",
                                                   {"0": "alle zulassen", "1": "alle überwachen", "2": "alle verweigern"}),
    _SVC + r"\lanmanserver\parameters\requiresecuritysignature": ("SMB-Server: Signatur immer erforderlich "
                                                                  "(RequireSecuritySignature)", None),
    _SVC + r"\lanmanserver\parameters\enablesecuritysignature": ("SMB-Server: Signatur, wenn der Client zustimmt "
                                                                 "(EnableSecuritySignature)", None),
    _SVC + r"\lanmanworkstation\parameters\requiresecuritysignature": ("SMB-Client: Signatur immer erforderlich "
                                                                       "(RequireSecuritySignature)", None),
    _SVC + r"\lanmanworkstation\parameters\enableplaintextpassword": ("SMB-Client: unverschlüsseltes Kennwort an "
                                                                      "Drittanbieter-Server (EnablePlainTextPassword)",
                                                                      None),
    _SVC + r"\ntds\parameters\ldapserverintegrity": ("DC: Signaturanforderungen für LDAP-Server (LDAPServerIntegrity)",
                                                     {"1": "keine", "2": "Signatur erforderlich"}),
    _SVC + r"\ldap\ldapclientintegrity": ("Signaturanforderungen für LDAP-Clients (LDAPClientIntegrity)",
                                          {"0": "keine", "1": "Signatur aushandeln", "2": "Signatur erforderlich"}),
    _SVC + r"\netlogon\parameters\requiresignorseal": ("Sicherer Kanal: immer signieren oder verschlüsseln "
                                                       "(RequireSignOrSeal)", None),
    _SVC + r"\netlogon\parameters\requirestrongkey": ("Sicherer Kanal: starker Sitzungsschlüssel (RequireStrongKey)",
                                                      None),
    _SVC + r"\netlogon\parameters\disablepasswordchange": ("Kennwortwechsel des Computerkontos deaktivieren "
                                                           "(DisablePasswordChange)", None),
    _SVC + r"\netlogon\parameters\maximumpasswordage": ("Maximales Alter des Computerkontokennworts in Tagen "
                                                        "(MaximumPasswordAge)", None),
    _SYS + r"\enablelua": ("Benutzerkontensteuerung: Administratorbestätigungsmodus (EnableLUA)", None),
    _SYS + r"\consentpromptbehavioradmin": ("Benutzerkontensteuerung: Verhalten für Administratoren "
                                            "(ConsentPromptBehaviorAdmin)", {
        "0": "ohne Eingabeaufforderung erhöhen", "1": "Anmeldeinformationen auf dem sicheren Desktop",
        "2": "Zustimmung auf dem sicheren Desktop", "3": "Anmeldeinformationen", "4": "Zustimmung",
        "5": "Zustimmung für Nicht-Windows-Binärdateien"}),
    _SYS + r"\consentpromptbehavioruser": ("Benutzerkontensteuerung: Verhalten für Standardbenutzer "
                                           "(ConsentPromptBehaviorUser)", {
        "0": "Anforderungen automatisch ablehnen", "1": "Anmeldeinformationen auf dem sicheren Desktop",
        "3": "Anmeldeinformationen"}),
    _SYS + r"\promptonsecuredesktop": ("Benutzerkontensteuerung: sicherer Desktop (PromptOnSecureDesktop)", None),
    _SYS + r"\dontdisplaylastusername": ("Letzten Benutzernamen nicht anzeigen (DontDisplayLastUserName)", None),
    _SYS + r"\disablecad": ("Kein STRG+ALT+ENTF erforderlich (DisableCAD)", None),
    _SYS + r"\inactivitytimeoutsecs": ("Inaktivitätsgrenze in Sekunden (InactivityTimeoutSecs)", None),
    _SYS + r"\legalnoticecaption": ("Anmeldehinweis: Titel (LegalNoticeCaption)", None),
    _SYS + r"\legalnoticetext": ("Anmeldehinweis: Text (LegalNoticeText)", None),
    _SYS + r"\kerberos\parameters\supportedencryptiontypes": ("Für Kerberos zulässige Verschlüsselungstypen "
                                                              "(SupportedEncryptionTypes)", None),
}
SERVICE_START = {"2": "Automatisch", "3": "Manuell", "4": "Deaktiviert"}
LOG_NAMES = {"System Log": "Systemprotokoll", "Security Log": "Sicherheitsprotokoll",
             "Application Log": "Anwendungsprotokoll"}
LOG_KEYS = {"MaximumLogSize": "Maximale Größe (KB)", "AuditLogRetentionPeriod": "Aufbewahrungsmethode",
            "RetentionDays": "Aufbewahrung (Tage)", "RestrictGuestAccess": "Gastzugriff verhindern"}
FIREWALL_KEY = r"software\policies\microsoft\windowsfirewall\firewallrules"


# --- Verknüpfungen ------------------------------------------------------------------------------

@dataclass
class Link:
    target_dn: str
    target: str  # lesbar: Domäne, OU-Pfad oder Standort
    kind: str  # Domäne, OU, Standort
    order: int  # 1 = höchste Priorität am Ziel
    enabled: bool
    enforced: bool
    blocked: bool = False  # Ziel blockiert die Vererbung


def parse_gplink(value: str) -> list[tuple[str, int]]:
    """gPLink in Dateireihenfolge; der letzte Eintrag hat die Verknüpfungsreihenfolge 1."""
    return [(m.group(1), int(m.group(2))) for m in GPLINK_RE.finditer(value or "")]


def gpo_guid(dn: str) -> str:
    m = GUID_RE.search(dn or "")
    return m.group(0).upper() if m else ""


def link_targets(data: AdData) -> list[tuple[Entry, str, str]]:
    """(Objekt, Anzeige, Art) aller Container, an denen GPOs hängen können."""
    out = []
    if data.domain is not None:
        out.append((data.domain, f"Domäne {data.dns}", "Domäne"))
    for ou in sorted(data.ous, key=lambda o: ou_path(o.dn, data.base).lower()):
        out.append((ou, ou_path(ou.dn, data.base), "OU"))
    for site in sorted(data.sites, key=lambda s: s.name.lower()):
        out.append((site, f"Standort {site.name}", "Standort"))
    return out


def links(data: AdData) -> dict[str, list[Link]]:
    """GPO-GUID (groß) -> Verknüpfungen; Schlüssel ohne passende GPO sind verwaiste Verknüpfungen."""
    out: dict[str, list[Link]] = {}
    for obj, label, kind in link_targets(data):
        entries = parse_gplink(obj.str("gPLink"))
        blocked = (obj.int("gPOptions", 0) or 0) & 1 == 1
        for i, (dn, options) in enumerate(entries):
            out.setdefault(gpo_guid(dn) or dn, []).append(Link(
                obj.dn, label, kind, len(entries) - i, not options & 1, bool(options & 2), blocked))
    return out


def gpo_name(data: AdData, guid: str) -> str:
    g = next((x for x in data.gpos if x.str("cn").upper() == guid.upper()), None)
    return (g.str("displayName") or guid) if g else f"gelöschte GPO {guid}"


def link_text(data: AdData, obj: Entry) -> list[str]:
    """Verknüpfte GPOs eines Containers in Reihenfolge (1 zuerst) mit Kennzeichen."""
    entries = parse_gplink(obj.str("gPLink"))
    out = []
    for i, (dn, options) in reversed(list(enumerate(entries))):
        flags = (["erzwungen"] if options & 2 else []) + (["deaktiviert"] if options & 1 else [])
        out.append(f"{len(entries) - i}. {gpo_name(data, gpo_guid(dn))}" + (f" ({', '.join(flags)})" if flags else ""))
    return out


# --- Berechtigungen der GPO ---------------------------------------------------------------------

@dataclass
class GpoAcl:
    readable: bool  # Sicherheitsbeschreibung gelesen
    apply: list[str] = field(default_factory=list)  # SIDs mit "Gruppenrichtlinie übernehmen"
    deny: list[str] = field(default_factory=list)
    read: list[str] = field(default_factory=list)
    edit: list[str] = field(default_factory=list)  # Schreibrechte (ohne Administratoren)
    owner: str = ""


def gpo_acl(gpo: Entry) -> GpoAcl:
    sd = parse_sd(gpo.raw("nTSecurityDescriptor"))
    if sd is None:
        return GpoAcl(False)
    acl = GpoAcl(True, owner=sd.owner or "")
    for ace in sd.dacl:
        if ace.inherit_only or ace.inherited_object_type:
            continue
        applies = ace.mask & GENERIC_ALL or (ace.mask & CONTROL_ACCESS and ace.object_type in (None, APPLY_GROUP_POLICY))
        if ace.deny:
            if applies:
                acl.deny.append(ace.sid)
            continue
        if not ace.allow:
            continue
        if applies:
            acl.apply.append(ace.sid)
        if ace.mask & (READ_PROP | GENERIC_READ | GENERIC_ALL) and ace.object_type is None:
            acl.read.append(ace.sid)
        if ace.mask & (WRITE_PROP | WRITE_DAC | WRITE_OWNER | GENERIC_ALL | GENERIC_WRITE) and not is_admin(ace.sid) \
                and ace.sid != "S-1-3-0":
            acl.edit.append(ace.sid)
    for name in ("apply", "deny", "read", "edit"):
        setattr(acl, name, list(dict.fromkeys(getattr(acl, name))))
    return acl


def computers_can_read(acl: GpoAcl, domain_sid: str) -> bool:
    """Seit MS16-072 liest der Computer die GPO auch für Benutzereinstellungen. Die Domänencontroller der
    Organisation (S-1-5-9) haben in jeder GPO Leserecht und zählen deshalb nicht."""
    readers = set(acl.read)
    return bool(readers & {"S-1-5-11", "S-1-1-0", f"{domain_sid}-515"})


def ms16_072(gpo: Entry, acl: GpoAcl, domain_sid: str) -> bool:
    """Benutzereinstellungen, die nicht greifen, weil Computer die GPO nicht lesen dürfen."""
    return acl.readable and bool(gpo.str("gPCUserExtensionNames")) and not computers_can_read(acl, domain_sid)


# --- SYSVOL --------------------------------------------------------------------------------------

@dataclass
class GpoFiles:
    found: bool = True  # GPO-Ordner vorhanden
    version: int | None = None  # GPT.INI
    registry: dict[str, list] = field(default_factory=dict)  # Machine/User -> RegEntry
    template: gpo_files.SecurityTemplate | None = None
    audit: list = field(default_factory=list)
    scripts: dict[str, list] = field(default_factory=dict)
    prefs: dict[str, list[tuple[str, list]]] = field(default_factory=dict)  # scope -> [(Bereich, PrefItem)]
    other: list[str] = field(default_factory=list)  # Dateien ohne Auswertung (z.B. Softwareinstallation)
    errors: list[str] = field(default_factory=list)

    @property
    def cpassword(self) -> list[str]:
        return [f"{scope}: {area} – {item.name}" for scope, groups in self.prefs.items() for area, items in groups
                for item in items if item.has_cpassword]


SCOPES = {"machine": "Machine", "user": "User"}
KNOWN = {"gpt.ini", "registry.pol", "gpttmpl.inf", "audit.csv", "scripts.ini", "psscripts.ini", "comment.cmtx",
         "desktop.ini"}


def _walk(ctx: Context, path: str, depth: int = 0, limit: list | None = None) -> list[tuple[str, int]]:
    """Alle Dateien unterhalb eines GPO-Ordners (relativ, Originalschreibweise) mit Größe; ohne den alten
    ADM-Ordner (Vorlagen, keine Einstellungen)."""
    limit = limit if limit is not None else [0]
    out = []
    for e in ctx.sysvol.listdir(path) or []:
        limit[0] += 1
        if limit[0] > 2000 or depth > 8:
            break
        rel = f"{path}\\{e.name}"
        if e.is_dir:
            if depth == 0 and e.name.lower() == "adm":
                continue
            out += _walk(ctx, rel, depth + 1, limit)
        else:
            out.append((rel, e.size))
    return out


def load_files(ctx: Context, data: AdData, guid: str) -> GpoFiles:
    """Dateien einer GPO aus SYSVOL des verbundenen DCs (nicht über gPCFileSysPath – das könnte auf einen
    fremden Server zeigen)."""
    if not GUID_RE.fullmatch(guid or ""):
        return GpoFiles(found=False, errors=[f"ungültige GPO-Kennung {guid!r}"])
    from doku_agent.connectors.sysvol import SysvolFileError
    root = f"{data.dns}\\Policies\\{guid}"
    try:
        if ctx.sysvol.listdir(root) is None:
            return GpoFiles(found=False)
        entries = _walk(ctx, root)
    except SysvolFileError as exc:  # Rechte der GPO in SYSVOL geändert: nur diese GPO betroffen
        return GpoFiles(errors=[f"Ordner nicht lesbar: {exc}"])
    files = GpoFiles()
    for path, size in entries:
        rel = path[len(root) + 1:]
        parts = rel.split("\\")
        low = [p.lower() for p in parts]
        name = low[-1]
        scope = SCOPES.get(low[0], "") if len(low) > 1 else ""
        try:
            if low == ["gpt.ini"]:
                files.version = gpo_files.parse_gpt_ini(ctx.sysvol.read(path) or b"")
            elif scope and low[1:] == ["registry.pol"]:
                files.registry[scope] = gpo_files.parse_registry_pol(ctx.sysvol.read(path) or b"")
            elif scope == "Machine" and name == "gpttmpl.inf":
                files.template = gpo_files.parse_gpttmpl(ctx.sysvol.read(path) or b"")
            elif scope == "Machine" and name == "audit.csv":
                files.audit = gpo_files.parse_audit_csv(ctx.sysvol.read(path) or b"")
            elif scope and name in ("scripts.ini", "psscripts.ini") and "scripts" in low:
                files.scripts.setdefault(scope, []).extend(
                    gpo_files.parse_scripts_ini(ctx.sysvol.read(path) or b"", powershell=name == "psscripts.ini"))
            elif scope and "preferences" in low and name.endswith(".xml"):
                area = PREF_AREAS.get(low[-2], parts[-2])
                files.prefs.setdefault(scope, []).append(
                    (area, gpo_files.parse_preferences(ctx.sysvol.read(path) or b"")))
            elif name not in KNOWN and not ("scripts" in low and len(low) > 3):
                files.other.append(rel)
        except (gpo_files.GpoFileError, SysvolFileError, ValueError) as exc:  # eine kaputte Datei betrifft nur sich
            files.errors.append(f"{rel}: {exc}")
    return files


def admx_catalog(ctx: Context, data: AdData) -> tuple[gpo_files.AdmxCatalog | None, str]:
    """Namen der administrativen Vorlagen aus dem Central Store (oder ad.admx_dir). Im Prozess
    zwischengespeichert, solange sich Dateinamen, Größen und Zeitstempel nicht ändern."""
    from pathlib import Path
    cfg = ctx.cfg.ad
    langs = [cfg.admx_language] + (["en-US"] if cfg.admx_language.lower() != "en-us" else [])
    if cfg.admx_dir:
        base = Path(cfg.admx_dir)
        if not base.is_dir():
            return None, f"ad.admx_dir {cfg.admx_dir} nicht gefunden – Registrierungswerte erscheinen ohne Namen"
        listing = {p.name: (p.stat().st_size, p.stat().st_mtime) for p in base.glob("*.admx")}
        read = lambda name: (base / name).read_bytes()  # noqa: E731
        lang_dirs = {d.name.lower(): d for d in base.iterdir() if d.is_dir()}

        def adml(lang, name):
            d = lang_dirs.get(lang.lower())
            p = d / name if d else None
            return p.read_bytes() if p and p.exists() else None
        source = cfg.admx_dir
    else:
        store = f"{data.dns}\\Policies\\PolicyDefinitions"
        entries = ctx.sysvol.listdir(store)
        if entries is None:
            return None, ("Kein Central Store (SYSVOL\\Policies\\PolicyDefinitions) – Registrierungswerte erscheinen "
                          "ohne Richtliniennamen")
        listing = {e.name: (e.size, str(e.modified)) for e in entries if e.name.lower().endswith(".admx")}
        dirs = {e.name.lower(): e.name for e in entries if e.is_dir}
        read = lambda name: ctx.sysvol.read(f"{store}\\{name}") or b""  # noqa: E731
        lang_files: dict[str, set[str]] = {}

        def adml(lang, name):
            real = dirs.get(lang.lower())
            if not real:
                return None
            if real not in lang_files:
                lang_files[real] = {e.name.lower() for e in ctx.sysvol.listdir(f"{store}\\{real}") or []}
            return ctx.sysvol.read(f"{store}\\{real}\\{name}") if name.lower() in lang_files[real] else None
        source = "Central Store"
    signature = (source, cfg.admx_language, tuple(sorted(listing.items())))
    cached = ctx._clients.get("admx")
    if cached and cached[0] == signature:
        return cached[1], cached[2]
    admx, adml_files = {}, {}
    for name in listing:
        admx[name] = read(name)
        stem = name.rsplit(".", 1)[0] + ".adml"
        for lang in langs:
            content = adml(lang, stem)
            if content:
                adml_files[stem] = content
                break
    catalog = gpo_files.AdmxCatalog().load(admx, adml_files)
    note = f"{len(catalog)} Richtlinien aus {catalog.files} ADMX-Dateien ({source})"
    if catalog.errors:
        ctx.log.warning("ADMX-Dateien nicht lesbar: %s", "; ".join(catalog.errors[:5]))
    ctx._clients["admx"] = (signature, catalog, note)
    return catalog, note


# --- Einstellungen in Markdown -------------------------------------------------------------------

def _bool(value: str) -> str:
    return "aktiviert" if value.strip() not in ("0", "") else "deaktiviert"


def _access_value(key: str, value: str) -> str:
    label, unit = SYSTEM_ACCESS.get(key, KERBEROS.get(key, (key, "")))
    value = value.strip().strip('"')
    if unit == "bool":
        return _bool(value)
    if key == "MaximumPasswordAge" and value == "-1":
        return "läuft nie ab"
    if key == "LockoutDuration" and value == "-1":
        return "bis ein Administrator entsperrt"
    if key == "LockoutBadCount" and value == "0":
        return "0 (keine Sperre)"
    return f"{value} {unit}" if unit not in ("text", "") else value


def _security_option(path: str, kind: str, value: str) -> tuple[str, str]:
    label, values = SECURITY_OPTIONS.get(path.lower(), (path, None))
    value = str(mask_value(path.replace("\\", "/").rsplit("/", 1)[-1], value.strip().strip('"')))
    if values and value in values:
        return label, f"{values[value]} ({value})"
    if kind == "4" and values is None and value in ("0", "1") and path.lower() in SECURITY_OPTIONS:
        return label, _bool(value)
    if kind == "7":
        value = value.replace(",", "; ")
    return label, value


def template_sections(t: gpo_files.SecurityTemplate, names: AdNames) -> list[tuple[str, str, list[str]]]:
    """Sicherheitseinstellungen als (Überschrift, Tabelle, Faktenzeilen)."""
    out = []

    def add(title: str, headers: list[str], rows: list[list]):
        if rows:
            out.append((title, markdown.table(headers, rows),
                        [f"{title}: " + "; ".join(f"{h}: {v}" for h, v in zip(headers, r)) for r in rows]))

    order = list(SYSTEM_ACCESS)
    add("Kontorichtlinien", ["Einstellung", "Wert"],
        [[SYSTEM_ACCESS.get(k, (k,))[0], _access_value(k, v)]
         for k, v in sorted(t.system_access.items(), key=lambda kv: order.index(kv[0]) if kv[0] in order else 99)])
    add("Kerberos-Richtlinie", ["Einstellung", "Wert"],
        [[KERBEROS.get(k, (k,))[0], _access_value(k, v)] for k, v in t.kerberos.items()])
    add("Überwachungsrichtlinie", ["Ereignisse", "Überwachung"],
        [[EVENT_AUDIT.get(k, k), AUDIT_VALUES.get(v.strip(), v)] for k, v in t.event_audit.items()])
    add("Zuweisen von Benutzerrechten", ["Recht", "Zugewiesen an"],
        [[f"{PRIVILEGES.get(k, k)} ({k})", ", ".join(names.principal(p) for p in v) or "niemand"]
         for k, v in sorted(t.privileges.items(), key=lambda kv: PRIVILEGES.get(kv[0], kv[0]).lower())])
    add("Sicherheitsoptionen", ["Option", "Wert"], [list(_security_option(*r)) for r in t.registry_values])
    groups: dict[str, dict[str, list[str]]] = {}
    for group, rel, members in t.group_membership:
        groups.setdefault(group, {}).setdefault(rel, []).extend(members)
    add("Eingeschränkte Gruppen", ["Gruppe", "Mitglieder (ersetzt)", "Mitglied von"],
        [[names.principal(g), ", ".join(names.principal(m) for m in v.get("members", [])) or
          ("keine (Gruppe wird geleert)" if "members" in v else "–"),
          ", ".join(names.principal(m) for m in v.get("memberof", [])) or "–"] for g, v in groups.items()])
    add("Systemdienste", ["Dienst", "Starttyp"], [[s, SERVICE_START.get(m, m)] for s, m in t.services])
    add("Ereignisprotokoll", ["Protokoll", "Einstellung", "Wert"],
        [[LOG_NAMES.get(log, log), LOG_KEYS.get(k, k), v] for log, values in t.logs.items() for k, v in values.items()])
    add("Registrierung und Dateisystem (Berechtigungen)", ["Pfad"],
        [[p] for p in t.registry_keys + t.file_security])
    return out


def _firewall_rows(entries: list) -> list[list]:
    rows = []
    for e in entries:
        if e.key.lower() != FIREWALL_KEY or not isinstance(e.data, str) or not e.data.startswith("v"):
            continue
        r = gpo_files.parse_firewall_rule(e.data)
        first = lambda k: (r.get(k) or [""])[0]  # noqa: E731
        proto = {"6": "TCP", "17": "UDP", "1": "ICMPv4", "58": "ICMPv6"}.get(first("Protocol"), first("Protocol") or "alle")
        ports = ", ".join(x for x in [first("LPort") and f"lokal {first('LPort')}", first("RPort") and
                                      f"remote {first('RPort')}"] if x) or "alle"
        rows.append([first("Name") or e.value, {"In": "eingehend", "Out": "ausgehend"}.get(first("Dir"), first("Dir")),
                     {"Allow": "zulassen", "Block": "blockieren"}.get(first("Action"), first("Action")), proto, ports,
                     ", ".join(r.get("RA4", []) + r.get("RA6", [])) or "alle",
                     ", ".join(r.get("Profile", [])) or "alle", "ja" if first("Active").upper() == "TRUE" else "nein"])
    return rows


def scope_markdown(scope: str, files: GpoFiles, catalog, names: AdNames) -> tuple[str, list[str], int]:
    """Einstellungen eines Teils (Machine/User): (Markdown, Faktenzeilen, Anzahl Einstellungen)."""
    parts, facts, count = [], [], 0
    entries = files.registry.get(scope, [])
    if entries:
        if catalog is not None:
            settings, unknown = catalog.evaluate(scope, entries)
        else:
            settings, unknown = [], entries
        if settings:
            rows = [[s.policy.display, s.state, "<br>".join(f"{k} {v}" if k.endswith(":") else f"{k}: {v}"
                                                             for k, v in s.options) or "–", s.policy.category or "–"]
                    for s in settings]
            parts.append("### Administrative Vorlagen\n\n" + markdown.table(
                ["Richtlinie", "Status", "Optionen", "Kategorie"], rows))
            facts += [f"Administrative Vorlage: {r[3]} / {r[0]}: {r[1]}" + (f" ({r[2]})" if r[2] != "–" else "")
                      for r in rows]
            count += len(settings)
        firewall = _firewall_rows(unknown)
        if firewall:
            parts.append("### Windows-Firewall-Regeln\n\n" + markdown.table(
                ["Regel", "Richtung", "Aktion", "Protokoll", "Ports", "Remote-Adressen", "Profile", "Aktiv"], firewall))
            facts += [f"Firewall-Regel {r[0]}: {r[2]}, {r[1]}, {r[3]}, Ports {r[4]}, Remote {r[5]}" for r in firewall]
            count += len(firewall)
        raw = [e for e in unknown if e.key.lower() != FIREWALL_KEY]
        if raw:
            hive = "HKLM" if scope == "Machine" else "HKCU"
            rows = []
            for e in raw:
                kind, name = gpo_files.special_value(e.value)
                if kind in ("del", "delvals", "deletevalues", "deletekeys"):
                    rows.append([f"{hive}\\{e.key}", name or "(alle Werte)", "löschen", "–"])
                elif kind != "securekey":
                    rows.append([f"{hive}\\{e.key}", name or "(Standard)", e.type_name, str(mask_value(name, e.text()))])
            title = "### Registrierungswerte" + (" ohne administrative Vorlage" if catalog is not None else "")
            parts.append(f"{title}\n\n" + markdown.table(["Schlüssel", "Wert", "Typ", "Daten"], rows))
            facts += [f"Registrierungswert {r[0]}\\{r[1]} = {r[3]}" for r in rows]
            count += len(rows)
    if scope == "Machine" and files.template is not None:
        for title, table, lines in template_sections(files.template, names):
            parts.append(f"### Sicherheitseinstellungen: {title}\n\n{table}")
            facts += lines
            count += len(lines)
    if scope == "Machine" and files.audit:
        rows = [[a.subcategory, AUDIT_TEXT.get(a.setting.lower(), a.setting)] for a in files.audit if a.subcategory]
        if rows:
            parts.append("### Erweiterte Überwachungsrichtlinie\n\n" + markdown.table(
                ["Unterkategorie", "Überwachung"], rows))
            facts += [f"Erweiterte Überwachung {r[0]}: {r[1]}" for r in rows]
            count += len(rows)
    scripts = files.scripts.get(scope, [])
    if scripts:
        kinds = {"startup": "Start", "shutdown": "Herunterfahren", "logon": "Anmeldung", "logoff": "Abmeldung"}
        rows = [[kinds.get(s.kind.lower(), s.kind) + (" (PowerShell)" if s.powershell else ""), s.command,
                 s.parameters or "–"] for s in scripts]
        parts.append("### Skripte\n\n" + markdown.table(["Zeitpunkt", "Skript", "Parameter"], rows))
        facts += [f"Skript beim {r[0]}: {r[1]} {r[2] if r[2] != '–' else ''}".strip() for r in rows]
        count += len(rows)
    prefs = files.prefs.get(scope, [])
    rows = []
    for area, items in prefs:
        for item in items:
            details = []
            for k, v in item.details:
                if v == "NOCHANGE":
                    continue
                if k in PREF_BOOLS:
                    v = {"0": "nein", "1": "ja"}.get(v, v)
                elif k in PREF_ACCOUNTS or (k == "userName" and item.kind != "User"):
                    v = names.principal(v) if names.mode == "count" else v
                elif k == "fullName" and names.mode == "count":
                    continue
                details.append(f"{PREF_LABELS.get(k, k)}: {v}")
            if item.members:
                details.append("Mitglieder: " + ", ".join(
                    f"{action}: {names.sid(sid) if sid and (names.mode == 'count' or not name) else name or '?'}"
                    for action, name, sid in item.members))
            if item.has_cpassword:
                details.append("**gespeichertes Kennwort (cpassword)**")
            rows.append([area, item.name + (" (deaktiviert)" if item.disabled else ""), item.action or "–",
                         "<br>".join(details) or "–", "<br>".join(item.filters) or "–"])
    if rows:
        parts.append("### Einstellungen (Preferences)\n\n" + markdown.table(
            ["Bereich", "Element", "Aktion", "Details", "Zielgruppenadressierung"], rows))
        facts += [f"Einstellung {r[0]}: {r[1]}, {r[2]}, {r[3].replace('<br>', '; ')}" for r in rows]
        count += len(rows)
    return "\n\n".join(parts), facts, count


# --- Seiten --------------------------------------------------------------------------------------

def extension_names(value: str) -> list[str]:
    """[{CSE}{Tool}…][…] -> Namen der Erweiterungen (ohne den Platzhalter aus Nullen)."""
    out = []
    for block in re.findall(r"\[([^\]]*)\]", value or ""):
        guids = GUID_RE.findall(block)
        if not guids or guids[0].strip("{}").strip("0-") == "":
            continue
        out.append(CSE_NAMES.get(guids[0].upper(), guids[0].upper()))
    return out


def versions(value: int | None) -> tuple[int, int]:
    """versionNumber bzw. GPT.INI -> (Computer, Benutzer)."""
    value = value or 0
    return value & 0xFFFF, value >> 16


def wmi_filter(data: AdData, gpo: Entry) -> tuple[str, Entry | None, bool]:
    """(Anzeige, Filterobjekt, fehlt) aus gPCWQLFilter '[domäne;{ID};0]'."""
    value = gpo.str("gPCWQLFilter")
    m = GUID_RE.search(value)
    if not m:
        return "", None, False
    found = next((w for w in data.wmi if w.str("msWMI-ID").upper() == m.group(0).upper()
                  or (GUID_RE.search(w.dn) and GUID_RE.search(w.dn).group(0).upper() == m.group(0).upper())), None)
    if found is None:
        return f"fehlt ({m.group(0)})", None, True
    return found.str("msWMI-Name") or m.group(0), found, False


def wql(entry: Entry) -> str:
    """Abfragen aus msWMI-Parm2: '1;3;10;66;WQL;root\\CIMv2;SELECT …;' (Länge;Sprache;Namespace;Abfrage …)."""
    raw = entry.str("msWMI-Parm2")
    queries = re.findall(r"WQL;([^;]*);(.*?);(?=\d+;\d+;WQL;|$)", raw)
    return "<br>".join(f"`{q.strip()}` ({ns})" for ns, q in queries) or raw


def gpo_page_path(ctx: Context, guid: str, name: str) -> str:
    """Pfad der GPO-Seite für Links: zugeordnete Seite, sonst der geplante Pfad."""
    mapped = ctx.store.kv_get(f"page-for:ad:gpo:{guid.upper()}")
    if mapped:
        page = next((p for p in ctx.conventions.pages if p.id == int(mapped)), None)
        if page:
            return page.path
    template = ctx.cfg.wiki.paths.get("ad_gpo") or "{name}"
    path = render_path(template, {"name": name}, "kebab")
    style = ctx.conventions.profile_for_path(path).slug_style
    return path if style == "kebab" else render_path(template, {"name": name}, style)


def _describe(ctx: Context, name: str, facts: list[str], link_count: int, settings: int) -> str | None:
    fallback = (f"Die Gruppenrichtlinie **{name}** ist an {link_count} Stellen verknüpft und enthält {settings} "
                f"Einstellungen; sie stehen in den Abschnitten unten.")
    return narrative.narrate(
        ctx, "ad-gpo", expert="Active Directory und Gruppenrichtlinien", fallback=fallback,
        facts=f"Gruppenrichtlinie: {name}\n" + "\n".join(facts[:180]),
        task="Beschreibe Zweck und Wirkung dieser Gruppenrichtlinie für die Dokumentation: wo sie gilt (Verknüpfungen, "
             "Filter), was sie auf Computern und für Benutzer einstellt – thematisch zusammengefasst statt einzeln "
             "aufgezählt – und warum man so etwas einstellt. Ist sie deaktiviert, nicht verknüpft oder gefiltert, sage "
             "das deutlich. Nenne nur, was aus den Daten hervorgeht.")


def gpo_page(ctx: Context, data: AdData, gpo: Entry, names: AdNames, all_links: dict[str, list[Link]]) -> int | None:
    guid = gpo.str("cn").upper()
    name = gpo.str("displayName") or guid
    flags = gpo.int("flags", 0) or 0
    files = data.files.get(guid.lower())
    ad_c, ad_u = versions(gpo.int("versionNumber"))
    wmi_text, wmi_entry, _ = wmi_filter(data, gpo)
    machine_ext, user_ext = extension_names(gpo.str("gPCMachineExtensionNames")), \
        extension_names(gpo.str("gPCUserExtensionNames"))
    version = f"Computer {ad_c}, Benutzer {ad_u}"
    if files is not None and files.found and files.version is not None:
        sv_c, sv_u = versions(files.version)
        if (sv_c, sv_u) != (ad_c, ad_u):
            version += f" (SYSVOL: Computer {sv_c}, Benutzer {sv_u} – nicht synchron)"
    basics = markdown.table(["Eigenschaft", "Wert"], [
        ["Name", name], ["Status", STATUS.get(flags, str(flags))], ["GUID", guid],
        ["Erstellt", day(gpo.time("whenCreated")) or "–"], ["Geändert", day(gpo.time("whenChanged")) or "–"],
        ["Version", version], ["WMI-Filter", wmi_text or "–"],
        ["Erweiterungen Computer", ", ".join(machine_ext) or "–"],
        ["Erweiterungen Benutzer", ", ".join(user_ext) or "–"],
    ])
    if wmi_entry is not None:
        basics += f"\n\nWMI-Filter **{wmi_text}**: {wql(wmi_entry)}"
    gpo_links = sorted(all_links.get(guid, []), key=lambda lk: ({"Standort": 0, "Domäne": 1, "OU": 2}[lk.kind],
                                                                 lk.target.lower()))
    link_rows = [[lk.target, lk.kind, lk.order, "ja" if lk.enabled else "nein", "ja" if lk.enforced else "nein",
                  "ja" if lk.blocked else "–"] for lk in gpo_links]
    links_md = markdown.table(["Ziel", "Art", "Reihenfolge", "Aktiviert", "Erzwungen", "Vererbung am Ziel blockiert"],
                              link_rows) if link_rows else "_Nicht verknüpft – die GPO wirkt nirgends._"
    acl = gpo_acl(gpo)
    names.resolve(acl.apply + acl.deny + acl.edit + [acl.owner])
    if acl.readable:
        sec_rows = [["Angewendet auf", ", ".join(sorted(names.sid(s) for s in acl.apply)) or "niemand"]]
        if acl.deny:
            sec_rows.append(["Verweigert für", ", ".join(sorted(names.sid(s) for s in acl.deny))])
        sec_rows.append(["Bearbeiten dürfen (außer Administratoren)",
                         ", ".join(sorted(names.sid(s) for s in acl.edit)) or "–"])
        sec_rows.append(["Besitzer", names.sid(acl.owner) if acl.owner else "–"])
        if ms16_072(gpo, acl, data.domain_sid):
            sec_rows.append(["Hinweis", "Computer haben kein Leserecht (MS16-072) – Benutzereinstellungen greifen nicht"])
        security = markdown.table(["Berechtigung", "Wer"], sec_rows)
    else:
        security = "_Berechtigungen nicht lesbar._"

    active = [lk.target for lk in gpo_links if lk.enabled]
    effect = {0: "Computer- und Benutzereinstellungen wirken", 1: "nur die Computereinstellungen wirken",
              2: "nur die Benutzereinstellungen wirken", 3: "keine Einstellung wirkt"}.get(flags, "")
    facts = [f"Status der GPO: {STATUS.get(flags, flags)} ({effect})",
             "Wirkt an: " + (", ".join(active) if active and flags != 3 else "nirgends"),
             f"WMI-Filter: {wmi_text or 'keiner'}"]
    facts += [f"Verknüpfung an {lk.target} ({lk.kind}): " + ("aktiv" if lk.enabled else "deaktiviert, wirkt dort nicht")
              + f", Reihenfolge {lk.order}" + (", erzwungen" if lk.enforced else "") for lk in gpo_links] \
        or ["Nicht verknüpft"]
    if acl.readable:
        facts.append("Angewendet auf: " + (", ".join(sorted(names.sid(s) for s in acl.apply)) or "niemand"))
    blocks_cfg = []
    total = 0
    for scope, heading, disabled_flag in (("Machine", "Computerkonfiguration", 2), ("User", "Benutzerkonfiguration", 1)):
        if files is None:
            body = f"_Einstellungen nicht gelesen ({data.admx_note or 'SYSVOL nicht verfügbar'})._"
        elif not files.found:
            body = "_Der GPO-Ordner fehlt in SYSVOL – die GPO ist beschädigt oder nicht repliziert._"
        else:
            body, lines, count = scope_markdown(scope, files, data.admx, names)
            total += count
            prefix = "Computer" if scope == "Machine" else "Benutzer"
            facts += [f"{prefix} – {line}" for line in lines]
            body = body or "_Keine Einstellungen._"
            if flags & disabled_flag and count:
                body = f"_Dieser Teil ist in der GPO deaktiviert – die Einstellungen wirken nicht._\n\n{body}"
            if scope == "Machine" and files.other:
                body += "\n\n_Weitere Dateien ohne Auswertung:_ " + ", ".join(f"`{p}`" for p in files.other[:20])
            if scope == "Machine" and files.errors:
                body += "\n\n_Nicht lesbar:_ " + "; ".join(files.errors[:10])
        blocks_cfg.append(Block(f"ad-gpo-{scope.lower()}", heading, body))
    if files is not None and files.found and total == 0 and not files.errors:
        description = "_Diese GPO enthält keine Einstellungen._"
    elif files is None:
        description = None if not gpo_links else _describe(ctx, name, facts, len(gpo_links), 0)
    else:
        description = _describe(ctx, name, facts, len(gpo_links), total)
    blocks = ([Block("ad-gpo-description", "Beschreibung", description)] if description is not None else []) + [
        Block("ad-gpo-basics", "Grunddaten", basics),
        Block("ad-gpo-links", "Verknüpfungen", links_md),
        Block("ad-gpo-security", "Sicherheitsfilterung und Berechtigungen", security),
    ] + blocks_cfg
    return propose_page(ctx, PageDraft(
        doc_type="ad_gpo", title=f"GPO: {name}", description=f"Gruppenrichtlinie {name}", blocks=blocks,
        path_vars={"name": name},
        intro=f"Dokumentation der Gruppenrichtlinie **{name}**. Die markierten Abschnitte werden automatisch aus dem "
              f"Active Directory und SYSVOL (nur lesend) aktualisiert.",
        source=f"ad:gpo:{guid}", stable_id=f"ad:gpo:{guid}", sync_title=True,
    ))


def overview(ctx: Context, data: AdData, names: AdNames) -> tuple[str, list[Block]]:
    all_links = links(data)
    rows, counts = [], {"gesamt": 0, "verknüpft": 0, "ohne Verknüpfung": 0, "deaktiviert": 0}
    for g in sorted(data.gpos, key=lambda x: (x.str("displayName") or x.str("cn")).lower()):
        guid = g.str("cn").upper()
        name = g.str("displayName") or guid
        gl = all_links.get(guid, [])
        flags = g.int("flags", 0) or 0
        counts["gesamt"] += 1
        counts["verknüpft" if any(lk.enabled for lk in gl) else "ohne Verknüpfung"] += 1
        counts["deaktiviert"] += flags == 3
        targets = [f"{lk.target}" + (" (erzwungen)" if lk.enforced else "") + ("" if lk.enabled else " (deaktiviert)")
                   for lk in sorted(gl, key=lambda lk: lk.target.lower())]
        exts = extension_names(g.str("gPCMachineExtensionNames")) + extension_names(g.str("gPCUserExtensionNames"))
        rows.append([markdown.link(gpo_page_path(ctx, guid, name), name), STATUS.get(flags, str(flags)),
                     "<br>".join(targets[:6]) + (f"<br>(+{len(targets) - 6})" if len(targets) > 6 else "") or "–",
                     wmi_filter(data, g)[0] or "–", day(g.time("whenChanged")) or "–",
                     ", ".join(dict.fromkeys(exts)) or "–"])
    orphan = [[lk.target, guid] for guid, gl in sorted(all_links.items()) for lk in gl
              if not any(g.str("cn").upper() == guid for g in data.gpos)]
    summary = markdown.table(["Gruppenrichtlinien", "Anzahl"], [[k, v] for k, v in counts.items()])
    table = markdown.table(["GPO", "Status", "Verknüpft mit", "WMI-Filter", "Geändert", "Erweiterungen"], rows) \
        if rows else "_Keine Gruppenrichtlinien._"
    if orphan:
        table += "\n\n**Verknüpfungen auf nicht vorhandene GPOs:**\n\n" + markdown.table(["Ziel", "GPO"], orphan)
    note = f" Richtliniennamen: {data.admx_note}." if data.admx_note else ""
    return ("Alle Gruppenrichtlinienobjekte der Domäne mit Status, Verknüpfungen und Filtern. Details und Einstellungen "
            "stehen auf der Seite der jeweiligen GPO." + note), [
        Block("ad-gpo-overview", "Übersicht", summary), Block("ad-gpo-list", "Gruppenrichtlinien", table)]
