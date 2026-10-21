"""Sicherheitsbeschreibungen (nTSecurityDescriptor) aus dem Active Directory lesen und in Worten beschreiben.

Binärformat nach MS-DTYP (SECURITY_DESCRIPTOR in Self-Relative-Form, ACL, ACE, SID, GUID). Rechte von
Verzeichnisobjekten nach den ADS_RIGHT_*-Werten. Namen von Attributen, Klassen und erweiterten Rechten
kommen aus dem Schema bzw. CN=Extended-Rights (GuidNames).
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, field

# ACE-Typen
ALLOWED, DENIED, ALLOWED_OBJECT, DENIED_OBJECT = 0x00, 0x01, 0x05, 0x06
ALLOWED_CALLBACK, DENIED_CALLBACK, ALLOWED_CALLBACK_OBJECT, DENIED_CALLBACK_OBJECT = 0x09, 0x0A, 0x0B, 0x0C
OBJECT_ACES = {ALLOWED_OBJECT, DENIED_OBJECT, ALLOWED_CALLBACK_OBJECT, DENIED_CALLBACK_OBJECT, 0x07, 0x0F}
ALLOW_TYPES = {ALLOWED, ALLOWED_OBJECT, ALLOWED_CALLBACK, ALLOWED_CALLBACK_OBJECT}
DENY_TYPES = {DENIED, DENIED_OBJECT, DENIED_CALLBACK, DENIED_CALLBACK_OBJECT}
# ACE-Flags
OBJECT_INHERIT, CONTAINER_INHERIT, NO_PROPAGATE, INHERIT_ONLY, INHERITED = 0x01, 0x02, 0x04, 0x08, 0x10
OBJECT_TYPE_PRESENT, INHERITED_OBJECT_TYPE_PRESENT = 0x1, 0x2
SE_DACL_PRESENT, SE_DACL_PROTECTED = 0x0004, 0x1000

# Zugriffsrechte auf Verzeichnisobjekte
CREATE_CHILD, DELETE_CHILD, LIST_CHILDREN, SELF, READ_PROP, WRITE_PROP = 0x1, 0x2, 0x4, 0x8, 0x10, 0x20
DELETE_TREE, LIST_OBJECT, CONTROL_ACCESS = 0x40, 0x80, 0x100
DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER = 0x10000, 0x20000, 0x40000, 0x80000
GENERIC_ALL, GENERIC_EXECUTE, GENERIC_WRITE, GENERIC_READ = 0x10000000, 0x20000000, 0x40000000, 0x80000000
FULL_CONTROL = 0xF01FF
WRITE_RIGHTS = (CREATE_CHILD | DELETE_CHILD | SELF | WRITE_PROP | DELETE_TREE | DELETE | WRITE_DAC | WRITE_OWNER
                | GENERIC_ALL | GENERIC_WRITE)
READ_RIGHTS = READ_PROP | LIST_CHILDREN | LIST_OBJECT | READ_CONTROL | GENERIC_READ

# Erweiterte Rechte (rightsGuid, gleich in allen Gesamtstrukturen)
APPLY_GROUP_POLICY = "edacfd8f-ffb3-11d1-b41d-00a0c968f939"
GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
GET_CHANGES_FILTERED = "89e95b76-444d-4c62-991a-0facbeda640c"
RESET_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529"

# Bekannte SIDs ohne Verzeichnisobjekt bzw. mit lokalisiertem Namen
WELL_KNOWN = {
    "S-1-0-0": "Niemand", "S-1-1-0": "Jeder", "S-1-2-0": "Lokal", "S-1-3-0": "ERSTELLER-BESITZER",
    "S-1-3-1": "ERSTELLERGRUPPE", "S-1-3-4": "BESITZERRECHTE", "S-1-5-1": "Dialup", "S-1-5-2": "Netzwerk",
    "S-1-5-3": "Batch", "S-1-5-4": "Interaktiv", "S-1-5-6": "Dienst", "S-1-5-7": "Anonymous-Anmeldung",
    "S-1-5-9": "Domänencontroller der Organisation", "S-1-5-10": "SELBST", "S-1-5-11": "Authentifizierte Benutzer",
    "S-1-5-12": "Eingeschränkt", "S-1-5-13": "Terminalserverbenutzer", "S-1-5-14": "Remoteinteraktive Anmeldung",
    "S-1-5-15": "Diese Organisation", "S-1-5-17": "IUSR", "S-1-5-18": "SYSTEM", "S-1-5-19": "Lokaler Dienst",
    "S-1-5-20": "Netzwerkdienst", "S-1-5-113": "Lokales Konto",
    "S-1-5-114": "Lokales Konto und Mitglied der Gruppe Administratoren", "S-1-5-80-0": "Alle Dienste",
    "S-1-5-32-544": "Administratoren", "S-1-5-32-545": "Benutzer", "S-1-5-32-546": "Gäste",
    "S-1-5-32-547": "Hauptbenutzer", "S-1-5-32-548": "Konten-Operatoren", "S-1-5-32-549": "Server-Operatoren",
    "S-1-5-32-550": "Druck-Operatoren", "S-1-5-32-551": "Sicherungs-Operatoren", "S-1-5-32-552": "Replikations-Operator",
    "S-1-5-32-554": "Prä-Windows 2000 kompatibler Zugriff", "S-1-5-32-555": "Remotedesktopbenutzer",
    "S-1-5-32-556": "Netzwerkkonfigurations-Operatoren", "S-1-5-32-558": "Leistungsüberwachungsbenutzer",
    "S-1-5-32-559": "Leistungsprotokollbenutzer", "S-1-5-32-560": "Windows-Autorisierungszugriffsgruppe",
    "S-1-5-32-561": "Terminalserver-Lizenzserver", "S-1-5-32-562": "Distributed COM-Benutzer",
    "S-1-5-32-568": "IIS_IUSRS", "S-1-5-32-569": "Kryptografie-Operatoren", "S-1-5-32-573": "Ereignisprotokollleser",
    "S-1-5-32-574": "Zertifikatdienst-DCOM-Zugriff", "S-1-5-32-575": "RDS-Remotezugriffsserver",
    "S-1-5-32-576": "RDS-Endpunktserver", "S-1-5-32-577": "RDS-Verwaltungsserver", "S-1-5-32-578": "Hyper-V-Administratoren",
    "S-1-5-32-579": "Zugriffssteuerungs-Unterstützungsoperatoren", "S-1-5-32-580": "Remoteverwaltungsbenutzer",
}
# Gruppen und Konten mit fester RID in jeder Domäne (Name nur, falls das Objekt nicht lesbar ist)
DOMAIN_RIDS = {
    498: "Organisations-Domänencontroller ohne Schreibzugriff", 500: "Administrator", 501: "Gast", 502: "krbtgt",
    512: "Domänen-Admins", 513: "Domänen-Benutzer", 514: "Domänen-Gäste", 515: "Domänencomputer",
    516: "Domänencontroller", 517: "Zertifikatherausgeber", 518: "Schema-Admins", 519: "Organisations-Admins",
    520: "Richtlinien-Ersteller-Besitzer", 521: "Domänencontroller ohne Schreibzugriff",
    522: "Klonbare Domänencontroller", 525: "Protected Users", 526: "Schlüsseladministratoren",
    527: "Unternehmensschlüsseladministratoren", 553: "RAS- und IAS-Server",
    571: "Zulässige RODC-Kennwortreplikationsgruppe", 572: "Abgelehnte RODC-Kennwortreplikationsgruppe",
}
# Vollständig vertrauenswürdige Prinzipale: ihre Rechte sind keine Delegation und kein Befund
ADMIN_SIDS = {"S-1-5-18", "S-1-5-32-544", "S-1-5-9"}
ADMIN_RIDS = {512, 516, 518, 519, 498, 521}
# Standard-Einträge eines neuen Objekts (Schema-Vorgabe), die keine Delegation darstellen
DEFAULT_SIDS = ADMIN_SIDS | {"S-1-5-11", "S-1-5-10", "S-1-3-0", "S-1-5-32-548", "S-1-5-32-550", "S-1-5-32-554",
                             "S-1-5-32-557", "S-1-5-32-560", "S-1-5-32-561", "S-1-5-32-549", "S-1-5-32-551"}
DEFAULT_RIDS = ADMIN_RIDS | {517, 520, 522, 526, 527, 553}
# Breite Gruppen: Schreibrechte für sie sind immer ein Befund
BROAD_SIDS = {"S-1-1-0", "S-1-5-11", "S-1-5-7", "S-1-5-32-545", "S-1-5-32-546", "S-1-5-2", "S-1-5-4"}
BROAD_RIDS = {513, 514, 515}

# Erweiterte Rechte und Eigenschaftssätze (CN=Extended-Rights, displayName) auf Deutsch
RIGHT_NAMES = {
    "Reset Password": "Kennwort zurücksetzen", "Change Password": "Kennwort ändern",
    "Apply Group Policy": "Gruppenrichtlinie übernehmen", "Send As": "Senden als", "Receive As": "Empfangen als",
    "Replicating Directory Changes": "Verzeichnisänderungen replizieren",
    "Replicating Directory Changes All": "Verzeichnisänderungen replizieren (alle, inkl. Kennwörter)",
    "Replicating Directory Changes In Filtered Set": "Verzeichnisänderungen replizieren (gefilterter Satz)",
    "Allowed to Authenticate": "Authentifizierung erlaubt", "Generate Resultant Set of Policy (Logging)":
        "Richtlinienergebnissatz generieren (Protokollierung)",
    "Generate Resultant Set of Policy (Planning)": "Richtlinienergebnissatz generieren (Planung)",
    "Personal Information": "Persönliche Informationen", "Public Information": "Öffentliche Informationen",
    "General Information": "Allgemeine Informationen", "Group Membership": "Gruppenmitgliedschaft",
    "Account Restrictions": "Kontoeinschränkungen", "Logon Information": "Anmeldeinformationen",
    "Web Information": "Webinformationen", "Phone and Mail Options": "Telefon- und E-Mail-Optionen",
    "Remote Access Information": "RAS-Informationen", "Validated write to DNS host name":
        "bestätigt: DNS-Hostname schreiben", "Validated write to service principal name":
        "bestätigt: Dienstprinzipalnamen schreiben", "Add/Remove self as member": "sich selbst als Mitglied hinzufügen/entfernen",
}


def sid_to_str(raw: bytes) -> str:
    if len(raw) < 8:
        raise ValueError("SID zu kurz")
    revision, count = raw[0], raw[1]
    authority = int.from_bytes(raw[2:8], "big")
    subs = struct.unpack("<" + "I" * count, raw[8:8 + 4 * count])
    return "S-" + "-".join([str(revision), str(authority)] + [str(s) for s in subs])


def sid_to_bytes(sid: str) -> bytes:
    parts = sid.split("-")
    if len(parts) < 3 or parts[0].upper() != "S":
        raise ValueError(f"keine SID: {sid}")
    subs = [int(p) for p in parts[3:]]
    return bytes([int(parts[1]), len(subs)]) + int(parts[2]).to_bytes(6, "big") + struct.pack("<" + "I" * len(subs), *subs)


def sid_size(raw: bytes, offset: int = 0) -> int:
    return 8 + 4 * raw[offset + 1]


def guid_to_str(raw: bytes) -> str:
    return str(uuid.UUID(bytes_le=bytes(raw[:16])))


def rid(sid: str) -> int | None:
    try:
        return int(sid.rsplit("-", 1)[1]) if sid.startswith("S-1-5-21-") else None
    except (IndexError, ValueError):
        return None


@dataclass
class Ace:
    type: int
    flags: int
    mask: int
    sid: str
    object_type: str | None = None  # Attribut, Eigenschaftssatz, Klasse oder erweitertes Recht
    inherited_object_type: str | None = None  # gilt nur für Unterobjekte dieser Klasse

    @property
    def allow(self) -> bool:
        return self.type in ALLOW_TYPES

    @property
    def deny(self) -> bool:
        return self.type in DENY_TYPES

    @property
    def inherited(self) -> bool:
        return bool(self.flags & INHERITED)

    @property
    def inherit_only(self) -> bool:
        return bool(self.flags & INHERIT_ONLY)

    @property
    def applies_here(self) -> bool:
        """Wirkt auf das Objekt selbst (nicht nur auf Unterobjekte)."""
        return not self.inherit_only and self.inherited_object_type is None

    def grants(self, right: int) -> bool:
        return self.allow and bool(self.mask & right or self.mask & GENERIC_ALL)


@dataclass
class SecurityDescriptor:
    owner: str | None = None
    group: str | None = None
    dacl: list[Ace] = field(default_factory=list)
    dacl_present: bool = False
    protected: bool = False  # Vererbung deaktiviert


def _parse_acl(raw: bytes, offset: int) -> list[Ace]:
    _, _, size, count, _ = struct.unpack_from("<BBHHH", raw, offset)
    pos, end, aces = offset + 8, offset + size, []
    for _ in range(count):
        if pos + 4 > end:
            break
        ace_type, flags, ace_size = struct.unpack_from("<BBH", raw, pos)
        if ace_size < 8:
            break
        body = pos + 4
        mask = struct.unpack_from("<I", raw, body)[0]
        if ace_type in OBJECT_ACES:
            obj_flags = struct.unpack_from("<I", raw, body + 4)[0]
            p = body + 8
            obj = inh = None
            if obj_flags & OBJECT_TYPE_PRESENT:
                obj, p = guid_to_str(raw[p:p + 16]), p + 16
            if obj_flags & INHERITED_OBJECT_TYPE_PRESENT:
                inh, p = guid_to_str(raw[p:p + 16]), p + 16
            sid = sid_to_str(raw[p:pos + ace_size])
            aces.append(Ace(ace_type, flags, mask, sid, obj, inh))
        elif ace_type in (ALLOWED, DENIED, ALLOWED_CALLBACK, DENIED_CALLBACK):
            aces.append(Ace(ace_type, flags, mask, sid_to_str(raw[body + 4:pos + ace_size])))
        pos += ace_size
    return aces


def parse_sd(raw: bytes | None) -> SecurityDescriptor | None:
    """Self-relative SECURITY_DESCRIPTOR; None, wenn nichts gelesen wurde (z.B. fehlende Berechtigung)."""
    if not raw or len(raw) < 20:
        return None
    _, _, control, off_owner, off_group, _, off_dacl = struct.unpack_from("<BBHIIII", raw, 0)
    sd = SecurityDescriptor(protected=bool(control & SE_DACL_PROTECTED), dacl_present=bool(control & SE_DACL_PRESENT))
    if off_owner:
        sd.owner = sid_to_str(raw[off_owner:off_owner + sid_size(raw, off_owner)])
    if off_group:
        sd.group = sid_to_str(raw[off_group:off_group + sid_size(raw, off_group)])
    if off_dacl and control & SE_DACL_PRESENT:
        sd.dacl = _parse_acl(raw, off_dacl)
    return sd


def sd_bytes(aces: list[Ace], owner: str = "S-1-5-32-544", protected: bool = False) -> bytes:
    """Gegenstück zu parse_sd (Tests)."""
    body = b""
    for a in aces:
        sid = sid_to_bytes(a.sid)
        if a.type in OBJECT_ACES:
            flags = (OBJECT_TYPE_PRESENT if a.object_type else 0) | (INHERITED_OBJECT_TYPE_PRESENT
                                                                    if a.inherited_object_type else 0)
            data = struct.pack("<II", a.mask, flags)
            data += uuid.UUID(a.object_type).bytes_le if a.object_type else b""
            data += uuid.UUID(a.inherited_object_type).bytes_le if a.inherited_object_type else b""
            data += sid
        else:
            data = struct.pack("<I", a.mask) + sid
        body += struct.pack("<BBH", a.type, a.flags, 4 + len(data)) + data
    acl = struct.pack("<BBHHH", 4, 0, 8 + len(body), len(aces), 0) + body
    owner_raw = sid_to_bytes(owner)
    control = 0x8000 | SE_DACL_PRESENT | (SE_DACL_PROTECTED if protected else 0)
    header = struct.pack("<BBHIIII", 1, 0, control, 20, 0, 0, 20 + len(owner_raw))
    return header + owner_raw + acl


# --- Beschreibung in Worten -------------------------------------------------------------------

# Erweiterte Rechte und bestätigte Schreibvorgänge über die GUID (Anzeigenamen unterscheiden sich je Implementierung)
RIGHT_GUIDS = {
    APPLY_GROUP_POLICY: "Gruppenrichtlinie übernehmen", RESET_PASSWORD: "Kennwort zurücksetzen",
    "ab721a53-1e2f-11d0-9819-00aa0040529b": "Kennwort ändern", "ab721a54-1e2f-11d0-9819-00aa0040529b": "Senden als",
    "ab721a56-1e2f-11d0-9819-00aa0040529b": "Empfangen als",
    GET_CHANGES: "Verzeichnisänderungen replizieren",
    GET_CHANGES_ALL: "Verzeichnisänderungen replizieren (alle, inkl. Kennwörter)",
    GET_CHANGES_FILTERED: "Verzeichnisänderungen replizieren (gefilterter Satz)",
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "sich selbst als Mitglied hinzufügen/entfernen",
    "72e39547-7b18-11d1-adef-00c04fd8d5cd": "bestätigt: DNS-Hostname schreiben",
    "f3a64788-5306-11d1-a9c5-0000f80367c1": "bestätigt: Dienstprinzipalnamen schreiben",
}


class GuidNames:
    """schemaIDGUID -> (lDAPDisplayName, 'attribute'|'class'), rightsGuid -> (Anzeigename, validAccesses).
    Welche Bedeutung eine GUID hat, hängt vom Recht ab: Eigenschaften (Lesen/Schreiben) sind Attribute oder
    Eigenschaftssätze, CONTROL_ACCESS meint ein erweitertes Recht, SELF einen bestätigten Schreibvorgang
    (dieselbe GUID kann z.B. das Attribut member und den Schreibvorgang Self-Membership bezeichnen)."""

    def __init__(self, schema: dict[str, tuple[str, str]] | None = None,
                 rights: dict[str, tuple[str, int]] | None = None):
        self.schema = {k.lower(): v for k, v in (schema or {}).items()}
        self.rights = {k.lower(): v for k, v in (rights or {}).items()}

    def name(self, guid: str | None, access: int = 0) -> str:
        if not guid:
            return ""
        g = guid.lower()
        right = self.rights.get(g)
        attr = self.schema.get(g)
        property_access = access & (READ_PROP | WRITE_PROP) and not access & (CONTROL_ACCESS | SELF)
        if property_access and attr:
            return attr[0]
        if right and (not property_access or right[1] & (READ_PROP | WRITE_PROP)):
            return RIGHT_GUIDS.get(g) or RIGHT_NAMES.get(right[0], right[0])
        if g in RIGHT_GUIDS and not property_access:
            return RIGHT_GUIDS[g]
        if attr:
            return attr[0]
        if right:
            return RIGHT_NAMES.get(right[0], right[0])
        return guid

    def is_class(self, guid: str | None) -> bool:
        return bool(guid) and self.schema.get(guid.lower(), ("", ""))[1] == "class"


def is_admin(sid: str) -> bool:
    return sid in ADMIN_SIDS or rid(sid) in ADMIN_RIDS


def is_default(sid: str) -> bool:
    return sid in DEFAULT_SIDS or rid(sid) in DEFAULT_RIDS


def is_broad(sid: str) -> bool:
    return sid in BROAD_SIDS or rid(sid) in BROAD_RIDS


def is_write(ace: Ace) -> bool:
    return bool(ace.mask & WRITE_RIGHTS) or (bool(ace.mask & CONTROL_ACCESS) and ace.object_type is None)


def rights_text(ace: Ace, names: GuidNames) -> str:
    """'Vollzugriff', 'Kennwort zurücksetzen', 'Schreiben: member', 'user-Objekte erstellen' …"""
    m = ace.mask
    if m & GENERIC_ALL or (m & FULL_CONTROL) == FULL_CONTROL:
        return "Vollzugriff"
    target = names.name(ace.object_type, m)
    parts = []
    if m & GENERIC_WRITE:
        parts.append("Schreiben (alle Eigenschaften)")
    if m & CREATE_CHILD and m & DELETE_CHILD:
        parts.append(f"{target}-Objekte erstellen und löschen" if target else "Unterobjekte erstellen und löschen")
    elif m & CREATE_CHILD:
        parts.append(f"{target}-Objekte erstellen" if target else "Unterobjekte erstellen")
    elif m & DELETE_CHILD:
        parts.append(f"{target}-Objekte löschen" if target else "Unterobjekte löschen")
    if m & WRITE_PROP:
        parts.append(f"Schreiben: {target}" if target else "Alle Eigenschaften schreiben")
    if m & SELF:
        parts.append(f"Bestätigter Schreibvorgang: {target}" if target else "Alle bestätigten Schreibvorgänge")
    if m & CONTROL_ACCESS:
        parts.append(target if target else "Alle erweiterten Rechte")
    if m & DELETE:
        parts.append("Löschen")
    if m & DELETE_TREE:
        parts.append("Unterstruktur löschen")
    if m & WRITE_DAC:
        parts.append("Berechtigungen ändern")
    if m & WRITE_OWNER:
        parts.append("Besitz übernehmen")
    if not parts and m & (READ_PROP | GENERIC_READ):
        parts.append(f"Lesen: {target}" if target and m & READ_PROP else "Lesen")
    if not parts and m & (LIST_CHILDREN | LIST_OBJECT | READ_CONTROL):
        parts.append("Auflisten")
    return ", ".join(parts) or f"Rechte 0x{m:x}"


def scope_text(ace: Ace, names: GuidNames) -> str:
    cls = names.name(ace.inherited_object_type)
    if cls:
        return f"untergeordnete {cls}-Objekte"
    if ace.inherit_only:
        return "nur untergeordnete Objekte"
    if ace.flags & CONTAINER_INHERIT:
        return "dieses und untergeordnete Objekte" + (" (eine Ebene)" if ace.flags & NO_PROPAGATE else "")
    return "nur dieses Objekt"


def protected_from_deletion(sd: SecurityDescriptor | None) -> bool:
    """'Objekt vor zufälligem Löschen schützen': Jeder – Verweigern: Löschen, Unterstruktur löschen."""
    return bool(sd) and any(a.deny and a.sid == "S-1-1-0" and a.mask & DELETE and a.mask & DELETE_TREE
                            and not a.inherited for a in sd.dacl)
