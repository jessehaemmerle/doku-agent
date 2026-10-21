"""Dateien einer Gruppenrichtlinie aus SYSVOL lesen – reine Parser ohne Netzwerkzugriff.

Formate (Microsoft-Protokolldokumentation):
  Registry.pol      MS-GPREG  administrative Vorlagen (Registrierungswerte)
  GptTmpl.inf       MS-GPSB   Sicherheitseinstellungen (Kennwort, Rechte, Gruppen, Dienste, Ereignisüberwachung)
  audit.csv         MS-GPAC   erweiterte Überwachungsrichtlinie
  scripts.ini       MS-GPSCR  Start-/Herunterfahren-, An-/Abmeldeskripte (auch psscripts.ini)
  Preferences/*.xml MS-GPPREF Einstellungen (Laufwerke, lokale Gruppen, Aufgaben, Registrierung …)
  *.admx / *.adml             Namen der administrativen Vorlagen (Central Store PolicyDefinitions)

Kennwörter aus Preferences (cpassword, MS14-025) werden nie ausgegeben, nur als Befund gemeldet.
"""

from __future__ import annotations

import csv
import io
import re
import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from doku_agent.generators.common import mask_value

REG_TYPES = {0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY", 4: "REG_DWORD",
             5: "REG_DWORD_BIG_ENDIAN", 6: "REG_LINK", 7: "REG_MULTI_SZ", 11: "REG_QWORD"}
PREG_SIGNATURE = b"PReg"


class GpoFileError(ValueError):
    pass


def decode_text(data: bytes) -> str:
    """Textdatei aus SYSVOL: UTF-16 mit BOM (GptTmpl.inf, scripts.ini), sonst UTF-8 bzw. ANSI."""
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        return data.decode("utf-16", "replace")  # abgeschnittene Dateien (z.B. während der Replikation)
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", "replace")
    if len(data) >= 2 and data[1:2] == b"\x00":  # UTF-16LE ohne BOM
        return data.decode("utf-16-le", "replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("cp1252", "replace")


# --- Registry.pol -----------------------------------------------------------------------------

@dataclass
class RegEntry:
    key: str
    value: str
    type: int
    data: object  # str, int, list[str] oder bytes

    @property
    def type_name(self) -> str:
        return REG_TYPES.get(self.type, str(self.type))

    def text(self) -> str:
        if isinstance(self.data, list):
            return "; ".join(self.data)
        if isinstance(self.data, bytes):
            return self.data.hex(" ") if len(self.data) <= 32 else f"{self.data[:32].hex(' ')} … ({len(self.data)} Bytes)"
        return str(self.data)


def _reg_data(kind: int, raw: bytes):
    if kind in (1, 2, 6):
        return raw.decode("utf-16-le", "replace").rstrip("\x00")
    if kind == 7:
        return [s for s in raw.decode("utf-16-le", "replace").split("\x00") if s]
    if kind == 4 and len(raw) >= 4:
        return struct.unpack("<I", raw[:4])[0]
    if kind == 5 and len(raw) >= 4:
        return struct.unpack(">I", raw[:4])[0]
    if kind == 11 and len(raw) >= 8:
        return struct.unpack("<Q", raw[:8])[0]
    return raw


def parse_registry_pol(data: bytes) -> list[RegEntry]:
    """PReg-Datei: Kopf 'PReg' + Version 1, dann Einträge [Schlüssel;Wert;Typ;Größe;Daten] in UTF-16LE."""
    if not data:
        return []
    if len(data) < 8 or data[:4] != PREG_SIGNATURE or struct.unpack("<I", data[4:8])[0] != 1:
        raise GpoFileError("Registry.pol: unbekanntes Format (Kopf 'PReg', Version 1 erwartet)")
    pos, out = 8, []

    def dword() -> int:
        nonlocal pos
        if pos + 4 > len(data):
            raise GpoFileError("Registry.pol: Datei endet mitten in einem Eintrag")
        pos += 4
        return struct.unpack("<I", data[pos - 4:pos])[0]

    def expect(char: str) -> None:
        nonlocal pos
        if data[pos:pos + 2] != char.encode("utf-16-le"):
            raise GpoFileError(f"Registry.pol: '{char}' an Position {pos} erwartet")
        pos += 2

    def string() -> str:
        nonlocal pos
        end = pos
        while end + 1 < len(data) and data[end:end + 2] != b"\x00\x00":
            end += 2
        text = data[pos:end].decode("utf-16-le", "replace")
        pos = end + 2
        return text

    while pos < len(data):
        expect("[")
        key = string()
        expect(";")
        value = string()
        expect(";")
        kind = dword()
        expect(";")
        size = dword()
        expect(";")
        raw = data[pos:pos + size]
        if len(raw) != size:
            raise GpoFileError("Registry.pol: Datei endet mitten in einem Eintrag")
        pos += size
        expect("]")
        out.append(RegEntry(key, value, kind, _reg_data(kind, raw)))
    return out


def registry_pol_bytes(entries: list[RegEntry]) -> bytes:
    """Gegenstück zu parse_registry_pol (für Tests und die Testumgebung)."""
    def enc(s: str) -> bytes:
        return s.encode("utf-16-le") + b"\x00\x00"

    out = PREG_SIGNATURE + struct.pack("<I", 1)
    for e in entries:
        if isinstance(e.data, int):
            raw = struct.pack(">I" if e.type == 5 else "<Q" if e.type == 11 else "<I", e.data)
        elif isinstance(e.data, list):
            raw = "".join(s + "\x00" for s in e.data).encode("utf-16-le") + b"\x00\x00"
        elif isinstance(e.data, str):
            raw = enc(e.data)
        else:
            raw = bytes(e.data)
        out += ("[".encode("utf-16-le") + enc(e.key) + ";".encode("utf-16-le") + enc(e.value)
                + ";".encode("utf-16-le") + struct.pack("<I", e.type) + ";".encode("utf-16-le")
                + struct.pack("<I", len(raw)) + ";".encode("utf-16-le") + raw + "]".encode("utf-16-le"))
    return out


def special_value(value: str) -> tuple[str, str]:
    """Steuerwerte in Registry.pol: (Art, betroffener Wert). Art '' = normaler Wert."""
    low = value.lower()
    if low.startswith("**del."):
        return "del", value[6:]
    if low.startswith("**delvals"):
        return "delvals", ""
    if low == "**deletevalues":
        return "deletevalues", ""
    if low == "**deletekeys":
        return "deletekeys", ""
    if low == "**securekey":
        return "securekey", ""
    if low.startswith("**soft."):
        return "soft", value[7:]
    return "", value


# --- INI-artige Dateien (GptTmpl.inf, scripts.ini) ---------------------------------------------

def parse_inf(data: bytes) -> dict[str, list[tuple[str, str]]]:
    """Abschnitt -> [(Schlüssel, Wert)] in Dateireihenfolge; Schlüssel ohne '=' haben den Wert ''."""
    sections: dict[str, list[tuple[str, str]]] = {}
    current = None
    for line in decode_text(data).splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = sections.setdefault(line[1:-1].strip(), [])
            continue
        if current is None:
            continue
        key, sep, value = line.partition("=")
        current.append((key.strip(), value.strip() if sep else ""))
    return sections


def _section(sections: dict, name: str) -> list[tuple[str, str]]:
    return next((v for k, v in sections.items() if k.lower() == name.lower()), [])


@dataclass
class SecurityTemplate:
    """GptTmpl.inf, in lesbare Teile zerlegt (Werte noch roh, Namen löst der Generator auf)."""
    system_access: dict[str, str] = field(default_factory=dict)
    kerberos: dict[str, str] = field(default_factory=dict)
    event_audit: dict[str, str] = field(default_factory=dict)
    privileges: dict[str, list[str]] = field(default_factory=dict)  # Recht -> SIDs bzw. Namen
    registry_values: list[tuple[str, str, str]] = field(default_factory=list)  # (Pfad, Typ, Wert)
    group_membership: list[tuple[str, str, list[str]]] = field(default_factory=list)  # (Gruppe, members|memberof, …)
    services: list[tuple[str, str]] = field(default_factory=list)  # (Dienst, Starttyp)
    logs: dict[str, dict[str, str]] = field(default_factory=dict)  # System/Security/Application Log
    registry_keys: list[str] = field(default_factory=list)
    file_security: list[str] = field(default_factory=list)


def _principals(value: str) -> list[str]:
    return [p.strip().lstrip("*") for p in value.split(",") if p.strip()]


def _unquote(value: str) -> str:
    return value.strip().strip('"')


def parse_gpttmpl(data: bytes) -> SecurityTemplate:
    s = parse_inf(data)
    t = SecurityTemplate(
        system_access=dict(_section(s, "System Access")),
        kerberos=dict(_section(s, "Kerberos Policy")),
        event_audit=dict(_section(s, "Event Audit")),
        privileges={k: _principals(v) for k, v in _section(s, "Privilege Rights")},
    )
    for key, value in _section(s, "Registry Values"):
        kind, _, val = value.partition(",")
        t.registry_values.append((key, kind.strip(), val.strip()))
    for key, value in _section(s, "Group Membership"):
        group, _, rel = key.rpartition("__")
        t.group_membership.append((group.lstrip("*"), rel.lower(), _principals(value)))
    for key, value in _section(s, "Service General Setting"):
        parts = next(csv.reader([f"{key}={value}" if value else key], skipinitialspace=True))
        if len(parts) >= 2:
            t.services.append((_unquote(parts[0]), parts[1].strip()))
    for log in ("System Log", "Security Log", "Application Log"):
        entries = _section(s, log)
        if entries:
            t.logs[log] = dict(entries)
    t.registry_keys = [_unquote(next(csv.reader([k]))[0]) for k, _ in _section(s, "Registry Keys") if k]
    t.file_security = [_unquote(next(csv.reader([k]))[0]) for k, _ in _section(s, "File Security") if k]
    return t


@dataclass
class Script:
    kind: str  # Startup, Shutdown, Logon, Logoff
    command: str
    parameters: str
    powershell: bool


def parse_scripts_ini(data: bytes, powershell: bool = False) -> list[Script]:
    """scripts.ini / psscripts.ini: [Startup] 0CmdLine=… 0Parameters=…"""
    out = []
    for section, entries in parse_inf(data).items():
        if section.lower() in ("scriptsconfig", "scriptconfig"):  # Spezifikation nennt beide Schreibweisen
            continue
        values = {k.lower(): v for k, v in entries}
        n = 0
        while f"{n}cmdline" in values:
            out.append(Script(section, values[f"{n}cmdline"], values.get(f"{n}parameters", ""), powershell))
            n += 1
    return out


def parse_gpt_ini(data: bytes) -> int | None:
    """Version aus GPT.INI (oben Benutzer, unten Computer – wie versionNumber im AD)."""
    for key, value in _section(parse_inf(data), "General"):
        if key.lower() == "version":
            try:
                return int(value)
            except ValueError:
                return None
    return None


@dataclass
class AuditSetting:
    subcategory: str
    guid: str
    setting: str  # Inclusion Setting im Klartext (englisch)
    value: int | None


def parse_audit_csv(data: bytes) -> list[AuditSetting]:
    """audit.csv: Machine Name, Policy Target, Subcategory, Subcategory GUID, Inclusion Setting, Exclusion Setting,
    Setting Value."""
    rows = list(csv.reader(io.StringIO(decode_text(data))))
    if not rows:
        return []
    header = [h.strip().lower() for h in rows[0]]

    def col(row: list[str], name: str) -> str:
        return row[header.index(name)].strip() if name in header and header.index(name) < len(row) else ""

    out = []
    for row in rows[1:]:
        if not any(c.strip() for c in row):
            continue
        value = col(row, "setting value")
        out.append(AuditSetting(col(row, "subcategory"), col(row, "subcategory guid"), col(row, "inclusion setting"),
                                int(value) if value.isdigit() else None))
    return out


# --- Preferences --------------------------------------------------------------------------------

ACTIONS = {"C": "Erstellen", "R": "Ersetzen", "U": "Aktualisieren", "D": "Löschen"}
# Wichtigste Eigenschaften je Elementtyp für die Kurzbeschreibung (Reihenfolge = Ausgabe)
PREF_FIELDS = {
    "User": ("userName", "newName", "fullName", "description", "acctDisabled", "neverExpires", "noChange"),
    "Group": ("groupName", "groupSid", "newName", "description", "deleteAllUsers", "deleteAllGroups"),
    "Drive": ("letter", "path", "label", "persistent", "thisDrive", "allDrives"),
    "Registry": ("hive", "key", "name", "type", "value"),
    "NTService": ("serviceName", "startupType", "serviceAction", "accountName"),
    "File": ("fromPath", "targetPath", "readOnly", "hidden"),
    "Folder": ("path", "deleteFolder", "deleteSubFolders", "deleteFiles"),
    "Shortcut": ("shortcutPath", "targetType", "targetPath", "arguments"),
    "EnvironmentVariable": ("name", "value", "user", "partial"),
    "SharedPrinter": ("path", "default", "location"),
    "PortPrinter": ("ipAddress", "localName", "path", "default"),
    "LocalPrinter": ("name", "port", "path", "default"),
    "IniFile": ("path", "section", "property", "value"),
    "NetShare": ("name", "path", "comment", "allRegular", "limitUsers"),
    "DataSource": ("dsn", "driver", "description", "userDSN"),
}
TASK_TAGS = {"Task", "ImmediateTask", "TaskV2", "ImmediateTaskV2"}
SECRET_ATTRS = {"cpassword"}
# Elemente, deren Attribut 'value' zu einem benannten Wert gehört: Registry (name), Umgebung (name), INI (property)
VALUE_NAME_ATTR = {"Registry": "name", "EnvironmentVariable": "name", "IniFile": "property"}


@dataclass
class PrefItem:
    kind: str  # Elementname, z.B. Drive, Group, TaskV2
    name: str
    action: str
    details: list[tuple[str, str]]
    disabled: bool = False
    has_cpassword: bool = False
    filters: list[str] = field(default_factory=list)  # Zielgruppenadressierung (Item-Level Targeting)
    members: list[tuple[str, str, str]] = field(default_factory=list)  # lokale Gruppe: (Aktion, Name, SID)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _filters(elem: ET.Element) -> list[str]:
    out = []
    for f in elem:
        if _local(f.tag) != "Filters":
            continue
        for flt in f.iter():
            tag = _local(flt.tag)
            if not tag.startswith("Filter") or tag == "Filters":
                continue
            what = flt.get("name") or flt.get("query") or flt.get("value") or flt.get("version") or ""
            prefix = ("nicht " if flt.get("not") == "1" else "") + ("oder " if flt.get("bool") == "OR" else "")
            out.append(f"{prefix}{tag[6:] or tag}{': ' + what if what else ''}")
    return out


def _task_summary(props: ET.Element) -> list[tuple[str, str]]:
    out = []
    for attr in ("name", "runAs", "logonType", "appName", "args", "startIn"):
        if props.get(attr):
            out.append((attr, props.get(attr)))
    for exec_ in props.iter():
        if _local(exec_.tag) == "Exec":
            cmd = next((c.text for c in exec_ if _local(c.tag) == "Command"), "") or ""
            args = next((c.text for c in exec_ if _local(c.tag) == "Arguments"), "") or ""
            out.append(("Befehl", f"{cmd} {args}".strip()))
        elif _local(exec_.tag) == "UserId" and exec_.text and not props.get("runAs"):
            out.append(("runAs", exec_.text))
    return out


def parse_preferences(data: bytes) -> list[PrefItem]:
    """Eine Preferences-XML (z.B. Drives.xml). Elemente mit <Properties> sind Einträge, Collection gruppiert."""
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise GpoFileError(f"Preferences-XML nicht lesbar: {exc}") from exc
    items = []
    all_disabled = root.get("disabled") == "1"
    for elem in root.iter():
        props = next((c for c in elem if _local(c.tag) == "Properties"), None)
        if props is None:
            continue
        kind = _local(elem.tag)
        has_cpassword = any(props.get(a) for a in SECRET_ATTRS) or any(
            el.get(a) for el in elem.iter() for a in SECRET_ATTRS)
        if kind in TASK_TAGS:
            details = _task_summary(props)
        else:
            fields = PREF_FIELDS.get(kind)
            attrs = [(k, v) for k, v in props.attrib.items() if k not in SECRET_ATTRS and k != "action"]
            if fields:
                order = {f: i for i, f in enumerate(fields)}
                attrs = sorted((a for a in attrs if a[0] in order and a[1] not in ("", None)), key=lambda a: order[a[0]])
            else:
                attrs = [a for a in attrs if a[1] not in ("", None)][:8]
            owner = props.get(VALUE_NAME_ATTR.get(kind, ""), "")
            details = [(k, str(mask_value(owner if k == "value" and owner else k, v))) for k, v in attrs]
        members = []
        for m in props.iter():
            if _local(m.tag) == "Member":
                members.append(("Hinzufügen" if (m.get("action") or "").upper() == "ADD" else "Entfernen",
                                m.get("name") or "", m.get("sid") or ""))
        items.append(PrefItem(kind=kind, name=elem.get("name") or props.get("name") or "",
                              action=ACTIONS.get((props.get("action") or "").upper(), props.get("action") or ""),
                              details=details, disabled=all_disabled or elem.get("disabled") == "1",
                              has_cpassword=has_cpassword, filters=_filters(elem), members=members))
    return items


# --- Windows-Firewall-Regeln (Registry.pol, SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules) ---

def parse_firewall_rule(value: str) -> dict[str, list[str]]:
    """'v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=443|Name=…|' -> {Feld: [Werte]}"""
    out: dict[str, list[str]] = {}
    for part in value.split("|")[1:]:
        key, sep, val = part.partition("=")
        if sep:
            out.setdefault(key, []).append(val)
    return out


# --- ADMX / ADML ----------------------------------------------------------------------------------

_STRING_REF = re.compile(r"^\$\((string|presentation)\.([^)]+)\)$")


@dataclass
class AdmxValue:
    """Wert aus enabledValue/trueValue/item: ('decimal', 1), ('string', 'x') oder ('delete', None)."""
    kind: str
    value: object

    def matches(self, entry: RegEntry) -> bool:
        if self.kind == "delete":
            return special_value(entry.value)[0] == "del"
        if self.kind == "decimal":
            return isinstance(entry.data, int) and entry.data == self.value
        if self.kind == "longDecimal":
            return isinstance(entry.data, int) and entry.data == self.value
        return isinstance(entry.data, str) and entry.data == self.value


@dataclass
class AdmxElement:
    kind: str  # boolean, decimal, longDecimal, text, multiText, enum, list
    id: str
    key: str
    value_name: str
    label: str = ""
    items: list[tuple[str, AdmxValue]] = field(default_factory=list)  # enum: (Anzeige, Wert)
    true_value: AdmxValue | None = None
    false_value: AdmxValue | None = None
    value_prefix: str = ""
    explicit_value: bool = False


@dataclass
class AdmxPolicy:
    name: str
    namespace: str
    cls: str  # Machine, User, Both
    display: str
    category: str
    key: str
    value_name: str
    enabled_value: AdmxValue | None
    disabled_value: AdmxValue | None
    elements: list[AdmxElement] = field(default_factory=list)
    enabled_list: list[tuple[str, str, AdmxValue]] = field(default_factory=list)  # (Schlüssel, Wert, Daten)
    disabled_list: list[tuple[str, str, AdmxValue]] = field(default_factory=list)


@dataclass
class PolicySetting:
    """Auswertung einer Richtlinie in einer GPO."""
    policy: AdmxPolicy
    state: str  # Aktiviert, Deaktiviert, Konfiguriert
    options: list[tuple[str, str]] = field(default_factory=list)


def _admx_value(elem: ET.Element | None) -> AdmxValue | None:
    if elem is None:
        return None
    for child in elem:
        kind = _local(child.tag)
        if kind in ("decimal", "longDecimal"):
            try:
                return AdmxValue(kind, int(child.get("value", "0")))
            except ValueError:
                return None
        if kind == "string":
            return AdmxValue("string", child.text or "")
        if kind == "delete":
            return AdmxValue("delete", None)
    return None


class AdmxCatalog:
    """Rückwärtssuche Registrierungswert -> Richtlinie aus den ADMX-Dateien (Namen aus den ADML-Dateien)."""

    def __init__(self):
        self.policies: list[AdmxPolicy] = []
        self._by_value: dict[tuple[str, str], list[tuple[AdmxPolicy, AdmxElement | None]]] = {}
        self._by_key: dict[str, list[tuple[AdmxPolicy, AdmxElement]]] = {}  # list-Elemente: ganzer Schlüssel
        self._categories: dict[str, tuple[str, str]] = {}  # "namespace:name" -> (Anzeige, Eltern "namespace:name")
        self.files = 0
        self.errors: list[str] = []

    def __len__(self) -> int:
        return len(self.policies)

    def load(self, admx: dict[str, bytes], adml: dict[str, bytes]) -> "AdmxCatalog":
        """admx/adml: Dateiname (ohne Pfad) -> Inhalt. ADML wird über den Dateinamen zugeordnet."""
        adml_by_stem = {name.rsplit(".", 1)[0].lower(): data for name, data in adml.items()}
        pending = []
        for name, data in sorted(admx.items()):
            try:
                root = ET.fromstring(data)
            except ET.ParseError as exc:
                self.errors.append(f"{name}: {exc}")
                continue
            strings, presentations = self._adml(adml_by_stem.get(name.rsplit(".", 1)[0].lower()))
            pending.append((root, strings, presentations))
            self.files += 1
        # erst alle Kategorien, dann die Richtlinien (Kategorien verweisen dateiübergreifend aufeinander)
        for root, strings, _ in pending:
            self._load_categories(root, strings)
        for root, strings, presentations in pending:
            self._load_policies(root, strings, presentations)
        return self

    @staticmethod
    def _adml(data: bytes | None) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
        if not data:
            return {}, {}
        try:
            root = ET.fromstring(data)
        except ET.ParseError:
            return {}, {}
        strings = {s.get("id"): (s.text or "").strip() for s in root.iter() if _local(s.tag) == "string"}
        presentations: dict[str, dict[str, str]] = {}
        for p in root.iter():
            if _local(p.tag) != "presentation":
                continue
            labels = {}
            for c in p.iter():
                ref = c.get("refId")
                if ref:
                    label = next((x.text for x in c if _local(x.tag) == "label"), None) or c.text or ""
                    labels[ref] = " ".join(label.split())
            presentations[p.get("id")] = labels
        return strings, presentations

    @staticmethod
    def _text(value: str | None, strings: dict[str, str]) -> str:
        m = _STRING_REF.match(value or "")
        if m and m.group(1) == "string":
            return strings.get(m.group(2), m.group(2))
        return value or ""

    @staticmethod
    def _namespaces(root: ET.Element) -> tuple[str, dict[str, str]]:
        target, using = "", {}
        for el in root.iter():
            tag = _local(el.tag)
            if tag == "target":
                target = el.get("namespace", "")
                using[el.get("prefix", "")] = target
            elif tag == "using":
                using[el.get("prefix", "")] = el.get("namespace", "")
        return target, using

    @staticmethod
    def _ref(ref: str, target: str, using: dict[str, str]) -> str:
        prefix, sep, name = (ref or "").partition(":")
        if not sep:
            return f"{target}:{ref}"
        return f"{using.get(prefix, prefix)}:{name}"

    def _load_categories(self, root: ET.Element, strings: dict[str, str]) -> None:
        target, using = self._namespaces(root)
        for el in root.iter():
            if _local(el.tag) != "category":
                continue
            parent = next((c.get("ref") for c in el if _local(c.tag) == "parentCategory"), "")
            self._categories[f"{target}:{el.get('name')}"] = (
                self._text(el.get("displayName"), strings) or el.get("name", ""),
                self._ref(parent, target, using) if parent else "")

    def category_path(self, ref: str) -> str:
        parts, seen = [], set()
        while ref and ref in self._categories and ref not in seen:
            seen.add(ref)
            name, ref = self._categories[ref]
            parts.append(name)
        return " / ".join(reversed(parts))

    def _load_policies(self, root: ET.Element, strings: dict[str, str],
                       presentations: dict[str, dict[str, str]]) -> None:
        target, using = self._namespaces(root)
        for el in root.iter():
            if _local(el.tag) != "policy":
                continue
            parent = next((c.get("ref") for c in el if _local(c.tag) == "parentCategory"), "")
            pres_ref = _STRING_REF.match(el.get("presentation") or "")
            labels = presentations.get(pres_ref.group(2), {}) if pres_ref else {}
            key = el.get("key", "")
            policy = AdmxPolicy(
                name=el.get("name", ""), namespace=target, cls=el.get("class", "Both"),
                display=self._text(el.get("displayName"), strings) or el.get("name", ""),
                category=self.category_path(self._ref(parent, target, using)) if parent else "",
                key=key, value_name=el.get("valueName", ""),
                enabled_value=_admx_value(next((c for c in el if _local(c.tag) == "enabledValue"), None)),
                disabled_value=_admx_value(next((c for c in el if _local(c.tag) == "disabledValue"), None)))
            for child in el:
                tag = _local(child.tag)
                if tag == "elements":
                    for e in child:
                        policy.elements.append(self._element(e, key, strings, labels))
                elif tag in ("enabledList", "disabledList"):
                    default_key = child.get("defaultKey") or key
                    for item in child:
                        value = _admx_value(next((c for c in item if _local(c.tag) == "value"), None))
                        if value is not None:
                            entry = (item.get("key") or default_key, item.get("valueName", ""), value)
                            (policy.enabled_list if tag == "enabledList" else policy.disabled_list).append(entry)
            self._index(policy)

    def _element(self, e: ET.Element, key: str, strings: dict[str, str], labels: dict[str, str]) -> AdmxElement:
        kind = _local(e.tag)
        el = AdmxElement(kind=kind, id=e.get("id", ""), key=e.get("key") or key, value_name=e.get("valueName", ""),
                         label=labels.get(e.get("id", ""), e.get("id", "")), value_prefix=e.get("valuePrefix", ""),
                         explicit_value=e.get("explicitValue") == "true")
        if kind == "enum":
            for item in e:
                if _local(item.tag) != "item":
                    continue
                value = _admx_value(next((c for c in item if _local(c.tag) == "value"), None))
                if value is not None:
                    el.items.append((self._text(item.get("displayName"), strings), value))
        elif kind == "boolean":
            el.true_value = _admx_value(next((c for c in e if _local(c.tag) == "trueValue"), None))
            el.false_value = _admx_value(next((c for c in e if _local(c.tag) == "falseValue"), None))
        return el

    def _index(self, policy: AdmxPolicy) -> None:
        self.policies.append(policy)
        if policy.value_name:
            self._by_value.setdefault((policy.key.lower(), policy.value_name.lower()), []).append((policy, None))
        for el in policy.elements:
            if el.kind == "list":
                self._by_key.setdefault(el.key.lower(), []).append((policy, el))
            elif el.value_name:
                self._by_value.setdefault((el.key.lower(), el.value_name.lower()), []).append((policy, el))
        for k, v, _ in policy.enabled_list + policy.disabled_list:
            if v:
                self._by_value.setdefault((k.lower(), v.lower()), []).append((policy, None))

    def match(self, scope: str, entry: RegEntry) -> tuple[AdmxPolicy, AdmxElement | None] | None:
        """Richtlinie zu einem Eintrag; scope 'Machine' oder 'User'."""
        kind, name = special_value(entry.value)
        key = entry.key.lower()
        if kind in ("delvals", "deletevalues", "securekey", "deletekeys") or (kind == "" and not name):
            hits = [(p, e) for p, e in self._by_key.get(key, []) if p.cls in (scope, "Both")]
            return hits[0] if hits else None
        for p, e in self._by_value.get((key, name.lower()), []):
            if p.cls in (scope, "Both"):
                return p, e
        hits = [(p, e) for p, e in self._by_key.get(key, []) if p.cls in (scope, "Both")]
        return hits[0] if hits else None

    def evaluate(self, scope: str, entries: list[RegEntry]) -> tuple[list[PolicySetting], list[RegEntry]]:
        """Einträge einer Registry.pol -> (erkannte Richtlinien mit Status und Optionen, nicht zuordenbare)."""
        grouped: dict[int, tuple[AdmxPolicy, list[tuple[AdmxElement | None, RegEntry]]]] = {}
        unknown = []
        for entry in entries:
            hit = self.match(scope, entry)
            if hit is None:
                if special_value(entry.value)[0] not in ("securekey",):
                    unknown.append(entry)
                continue
            policy, element = hit
            grouped.setdefault(id(policy), (policy, []))[1].append((element, entry))
        settings = [self._setting(policy, hits) for policy, hits in grouped.values()]
        settings.sort(key=lambda s: (s.policy.category.lower(), s.policy.display.lower()))
        return settings, unknown

    @staticmethod
    def _setting(policy: AdmxPolicy, hits: list[tuple[AdmxElement | None, RegEntry]]) -> PolicySetting:
        state, options = "", []

        def list_state(entry: RegEntry) -> str:
            for items, label in ((policy.enabled_list, "Aktiviert"), (policy.disabled_list, "Deaktiviert")):
                for key, name, value in items:
                    if key.lower() == entry.key.lower() and name.lower() == special_value(entry.value)[1].lower() \
                            and value.matches(entry):
                        return label
            return ""

        for el, entry in hits:
            if el is not None:
                continue
            kind, name = special_value(entry.value)
            if policy.value_name and name.lower() == policy.value_name.lower():
                if policy.enabled_value and policy.enabled_value.matches(entry):
                    state = "Aktiviert"
                elif policy.disabled_value and policy.disabled_value.matches(entry):
                    state = "Deaktiviert"
                elif kind == "del" and policy.disabled_value is None:
                    state = "Deaktiviert"  # ohne disabledValue wird beim Deaktivieren der Wert gelöscht
                elif policy.enabled_value is None and policy.disabled_value is None:
                    # ohne Angabe: 1 = aktiviert, 0 = deaktiviert
                    state = "Aktiviert" if entry.data == 1 else "Deaktiviert" if entry.data == 0 else state
            state = state or list_state(entry)
        list_values: dict[str, list[str]] = {}
        deleted_elements = 0
        element_hits = [(el, e) for el, e in hits if el is not None]
        for el, entry in element_hits:
            kind, name = special_value(entry.value)
            if kind == "del":
                if el.kind == "boolean" and el.false_value and el.false_value.kind == "delete":
                    options.append((el.label or el.id, "nein"))  # "aus" wird als Löschen gespeichert
                else:
                    deleted_elements += 1
                continue
            if el.kind == "list":
                if kind in ("delvals", "deletevalues", "securekey") or not entry.value:
                    continue
                text = str(mask_value(entry.value, entry.text()))
                shown = f"{entry.value} = {text}" if el.explicit_value else text
                list_values.setdefault(el.label or el.id, []).append(shown)
                continue
            options.append((el.label or el.id, str(mask_value(el.value_name, _element_text(el, entry)))))
        for label, values in list_values.items():
            options.append((label, "; ".join(values)))
        if not state:
            if options or list_values:
                state = "Aktiviert"
            elif deleted_elements or any(special_value(e.value)[0] in ("delvals",) for _, e in element_hits):
                state = "Deaktiviert"
            else:
                state = "Konfiguriert"
        if not state.startswith("Aktiv"):
            options = []
        return PolicySetting(policy, state, options)


def _element_text(el: AdmxElement, entry: RegEntry) -> str:
    if el.kind == "enum":
        for label, value in el.items:
            if value.matches(entry):
                return label
    if el.kind == "boolean":
        if el.true_value and el.true_value.matches(entry):
            return "ja"
        if el.false_value and el.false_value.matches(entry):
            return "nein"
        return "ja" if entry.data == 1 else "nein" if entry.data == 0 else entry.text()
    return entry.text()
