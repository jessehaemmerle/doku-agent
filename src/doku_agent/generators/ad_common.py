"""Active Directory: gemeinsames Datenmodell, Laden der Daten und Namen für die AD-Seiten und die Prüfung."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from doku_agent.ad_acl import DOMAIN_RIDS, WELL_KNOWN, GuidNames, rid
from doku_agent.connectors.ad import AdError, Entry, rdn
from doku_agent.context import Context

# userAccountControl
DISABLED, PASSWD_NOTREQD, REVERSIBLE = 0x2, 0x20, 0x80
WORKSTATION_TRUST, SERVER_TRUST = 0x1000, 0x2000
DONT_EXPIRE, SMARTCARD, TRUSTED_FOR_DELEGATION, NOT_DELEGATED = 0x10000, 0x40000, 0x80000, 0x100000
DES_ONLY, DONT_REQ_PREAUTH, TRUSTED_TO_AUTH, PARTIAL_SECRETS = 0x200000, 0x400000, 0x1000000, 0x4000000

FUNCTIONAL_LEVELS = {0: "Windows 2000", 1: "Windows Server 2003 (Interim)", 2: "Windows Server 2003",
                     3: "Windows Server 2008", 4: "Windows Server 2008 R2", 5: "Windows Server 2012",
                     6: "Windows Server 2012 R2", 7: "Windows Server 2016", 10: "Windows Server 2025"}

# Privilegierte Gruppen: (RID in der Domäne oder SID von Builtin, Anzeige-Reihenfolge)
PRIVILEGED_RIDS = [519, 512, 518, "S-1-5-32-544", 527, 526, "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-551",
                   "S-1-5-32-550", "S-1-5-32-552", 520]
PROTECTED_USERS = 525

# Domänenteil eingebauter Konten (nie Personen)
WELL_KNOWN_DOMAINS = {"NT AUTHORITY", "NT-AUTORITÄT", "AUTORITE NT", "BUILTIN", "VORDEFINIERT", "NT SERVICE"}

# Datengruppen und welcher Bereich sie braucht
GROUPS = ("base", "structure", "gpo", "files", "password", "accounts", "privileged", "topology", "acl")
NEEDS = {
    "gpo": {"base", "structure", "gpo", "files", "acl"},
    "ous": {"base", "structure", "gpo", "accounts", "acl"},
    "password_policy": {"base", "password", "structure", "gpo"},
    "privileged": {"base", "accounts", "privileged"},
    "domain": {"base", "topology", "accounts", "structure"},
    "audit": set(GROUPS),
}
AREA_LABELS = {"gpo": "Gruppenrichtlinien", "ous": "OU-Struktur", "password_policy": "Kennwortrichtlinien",
               "privileged": "Privilegierte Konten", "domain": "Domäne", "audit": "Prüfung"}


def day(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d") if value else ""


def now() -> datetime:
    return datetime.now(timezone.utc)


def uac(e: Entry) -> int:
    return e.int("userAccountControl", 0) or 0


def enabled(e: Entry) -> bool:
    return not uac(e) & DISABLED


def last_activity(e: Entry) -> datetime | None:
    """Letztes Lebenszeichen: Anmeldung (bis zu 14 Tage verzögert repliziert) oder – bei Computern –
    der automatische Kennwortwechsel alle 30 Tage."""
    times = [t for t in (e.time("lastLogonTimestamp"), e.time("pwdLastSet") if "computer" in e.classes() else None)
             if t]
    return max(times) if times else None


def stale(e: Entry, days: int) -> bool:
    """Seit 'days' Tagen kein Lebenszeichen; nie angemeldete Konten zählen ab der Erstellung."""
    limit = now() - timedelta(days=days)
    seen = last_activity(e) or e.time("whenCreated")
    return seen is not None and seen < limit


def ou_path(dn: str, base: str) -> str:
    """'OU=Clients,OU=Firma,DC=…' -> 'Firma / Clients'; Container (CN=…) erscheinen mit Namen."""
    if not dn or dn.lower() == base.lower():
        return ""
    inner = dn[: -len(base) - 1] if dn.lower().endswith("," + base.lower()) else dn
    parts = [rdn(p) for p in re.split(r"(?<!\\),", inner) if p]
    return " / ".join(reversed(parts))


def dns_name(base: str) -> str:
    return ".".join(p.split("=", 1)[1] for p in base.split(",") if p.upper().startswith("DC="))


@dataclass
class PrivGroup:
    key: object  # RID oder Builtin-SID
    group: Entry | None
    members: list[Entry] = field(default_factory=list)  # alle, auch verschachtelt
    direct: list[str] = field(default_factory=list)  # DNs direkter Mitglieder
    primary: list[Entry] = field(default_factory=list)  # Mitglieder über die primäre Gruppe


@dataclass
class AdData:
    root: dict = field(default_factory=dict)
    domain: Entry | None = None
    ous: list[Entry] = field(default_factory=list)
    sites: list[Entry] = field(default_factory=list)
    gpos: list[Entry] = field(default_factory=list)
    wmi: list[Entry] = field(default_factory=list)
    files: dict[str, object] = field(default_factory=dict)  # GUID (klein) -> GpoFiles
    admx: object = None  # AdmxCatalog oder None
    admx_note: str = ""
    psos: list[Entry] = field(default_factory=list)
    users: list[Entry] = field(default_factory=list)
    computers: list[Entry] = field(default_factory=list)
    msas: list[Entry] = field(default_factory=list)
    privileged: list[PrivGroup] = field(default_factory=list)
    protected_users: set[str] = field(default_factory=set)  # DNs (Mitglieder von Protected Users)
    adminsdholder: Entry | None = None
    dcs: list[Entry] = field(default_factory=list)
    ntds: list[Entry] = field(default_factory=list)
    fsmo: dict[str, str] = field(default_factory=dict)
    subnets: list[Entry] = field(default_factory=list)
    site_links: list[Entry] = field(default_factory=list)
    trusts: list[Entry] = field(default_factory=list)
    features: list[Entry] = field(default_factory=list)
    directory_service: Entry | None = None
    crossref: Entry | None = None
    forest_level: int | None = None
    laps: dict[str, bool] = field(default_factory=dict)  # Attribut -> im Schema
    guid_names: GuidNames = field(default_factory=GuidNames)
    loaded: set[str] = field(default_factory=set)

    @property
    def base(self) -> str:
        return self.root.get("defaultnamingcontext", "")

    @property
    def domain_sid(self) -> str:
        return self.domain.sid() if self.domain else ""

    @property
    def dns(self) -> str:
        return (self.crossref.str("dnsRoot") if self.crossref else "") or dns_name(self.base)


def fetch(ctx: Context, groups: set[str]) -> tuple[AdData, dict[str, str]]:
    """Daten der gewünschten Gruppen laden; Rückgabe (Daten, {Gruppe: Fehler}). Ohne Domänenobjekt geht nichts."""
    client = ctx.ad
    data, errors = AdData(), {}
    data.root = client.root()
    data.domain = client.domain()
    data.loaded.add("base")

    def load(group: str, fn) -> None:
        if group not in groups:
            return
        try:
            fn()
            data.loaded.add(group)
        except (AdError, RuntimeError, OSError) as exc:
            errors[group] = str(exc)

    def structure():
        data.ous = client.ous()
        data.sites = client.sites()

    def gpo():
        data.gpos = client.gpos()
        data.wmi = client.wmi_filters()

    def files():
        from doku_agent.generators.gpo_docs import admx_catalog, load_files
        if not ctx.cfg.ad.sysvol:
            data.admx_note = "SYSVOL wird nicht gelesen (ad.sysvol: false)"
            return
        for g in data.gpos:
            data.files[g.str("cn").lower()] = load_files(ctx, data, g.str("cn"))
        data.admx, data.admx_note = admx_catalog(ctx, data)

    def password():
        data.psos = client.psos()

    def accounts():
        data.users = client.users()
        data.computers = client.computers()
        data.msas = client.managed_service_accounts()
        data.laps = {a: client.schema_has(a) for a in ("msLAPS-PasswordExpirationTime", "ms-Mcs-AdmPwdExpirationTime")}

    def privileged():
        sids = [f"{data.domain_sid}-{k}" if isinstance(k, int) else k for k in PRIVILEGED_RIDS]
        found = {g.sid(): g for g in client.groups_by_sid(sids + [f"{data.domain_sid}-{PROTECTED_USERS}"])}
        dns_admins = client.group_by_name("DnsAdmins")
        for key, sid in zip(PRIVILEGED_RIDS, sids):
            group = found.get(sid)
            pg = PrivGroup(key, group)
            if group is not None:
                pg.members = client.members(group.dn)
                pg.direct = client.direct_members(group.dn)
                if isinstance(key, int):
                    pg.primary = client.primary_group_members(key)
            data.privileged.append(pg)
        if dns_admins is not None:
            data.privileged.append(PrivGroup("DnsAdmins", dns_admins, client.members(dns_admins.dn),
                                             client.direct_members(dns_admins.dn)))
        protected = found.get(f"{data.domain_sid}-{PROTECTED_USERS}")
        if protected is not None:
            data.protected_users = {m.dn.lower() for m in client.members(protected.dn)}
        data.adminsdholder = client.adminsdholder()

    def topology():
        data.dcs = client.domain_controllers()
        data.ntds = client.ntds_settings()
        data.fsmo = client.fsmo()
        data.subnets = client.subnets()
        data.site_links = client.site_links()
        data.trusts = client.trusts()
        data.features = client.optional_features()
        data.directory_service = client.directory_service()
        data.crossref = client.crossref()
        data.forest_level = client.forest_level()

    def acl():
        data.guid_names = GuidNames(client.schema_names(), client.extended_rights())

    for name, fn in (("structure", structure), ("gpo", gpo), ("files", files), ("password", password),
                     ("accounts", accounts), ("privileged", privileged), ("topology", topology), ("acl", acl)):
        if name == "files" and "gpo" not in data.loaded:
            continue
        load(name, fn)
    # Reihenfolge der LDAP-Antworten kann je DC abweichen – Seiten sollen davon nicht abhängen
    for attr in ("ous", "sites", "gpos", "wmi", "psos", "users", "computers", "msas", "dcs", "ntds", "subnets",
                 "site_links", "trusts", "features"):
        setattr(data, attr, sorted(getattr(data, attr), key=lambda e: e.dn.lower()))
    for pg in data.privileged:
        pg.members.sort(key=lambda e: e.dn.lower())
        pg.primary.sort(key=lambda e: e.dn.lower())
        pg.direct.sort(key=str.lower)
    if "topology" not in groups:
        try:
            data.crossref = client.crossref()
        except AdError:
            pass
    return data, errors


class AdNames:
    """SIDs und Konten in lesbare Namen; Personen je nach ad.user_names mit oder ohne Namen."""

    def __init__(self, ctx: Context, data: AdData):
        self.ctx = ctx
        self.mode = ctx.cfg.ad.user_names
        self.domain_sid = data.domain_sid
        self.objects: dict[str, Entry] = {}
        self.by_dn: dict[str, Entry] = {}
        for e in data.users + data.computers + data.msas:
            self._add(e)
        for pg in data.privileged:
            if pg.group is not None:
                self._add(pg.group)
            for m in pg.members + pg.primary:
                self._add(m)
        self._unknown: set[str] = set()
        self._unknown_dns: set[str] = set()
        self._accounts: dict[str, Entry | None] = {}

    def _add(self, e: Entry) -> None:
        sid = e.sid()
        if sid:
            self.objects[sid] = e
        self.by_dn[e.dn.lower()] = e

    def resolve(self, sids) -> None:
        missing = sorted({s for s in sids if s and s not in self.objects and s not in WELL_KNOWN
                          and s not in self._unknown and s.startswith(("S-1-5-21-", "S-1-5-32-"))})
        if not missing:
            return
        found = self.ctx.ad.resolve_sids(missing)  # Störung: Lauf abbrechen statt SIDs statt Namen zu zeigen
        for sid in missing:
            if sid in found:
                self._add(found[sid])
            else:
                self._unknown.add(sid)

    def is_person(self, e: Entry) -> bool:
        classes = e.classes()
        return ("user" in classes or "person" in classes or "inetorgperson" in classes) and "computer" not in classes

    def person(self, e: Entry) -> str:
        account = e.str("sAMAccountName") or e.name
        display = e.str("displayName")
        if self.mode == "count":
            return "Benutzer"
        if self.mode == "name":
            return display or account
        return f"{display} ({account})" if display and display != account else account

    def entry(self, e: Entry) -> str:
        classes = e.classes()
        if "computer" in classes:  # auch gMSA (Unterklasse von computer)
            return e.str("sAMAccountName") or e.name
        if "group" in classes:
            return e.str("sAMAccountName") or e.name
        if self.is_person(e):
            return self.person(e)
        return e.name

    def sid(self, sid: str) -> str:
        if sid in WELL_KNOWN:
            return WELL_KNOWN[sid]
        if sid not in self.objects:
            self.resolve([sid])
        e = self.objects.get(sid)
        if e is not None:
            return self.entry(e)
        r = rid(sid)
        if self.domain_sid and sid.startswith(self.domain_sid + "-") and r in DOMAIN_RIDS:
            return DOMAIN_RIDS[r]
        return sid

    def resolve_dns(self, dns) -> None:
        missing = sorted({d.lower() for d in dns if d and d.lower() not in self.by_dn
                          and d.lower() not in self._unknown_dns})
        if not missing:
            return
        found = self.ctx.ad.resolve_dns(missing)
        for dn in missing:
            if dn in found:
                self._add(found[dn])
            else:
                self._unknown_dns.add(dn)

    def dn(self, dn: str) -> str:
        """Objekt über den DN; Job und Wiki-Lint liefern denselben Namen, auch ohne geladene Konten."""
        self.resolve_dns([dn])
        e = self.by_dn.get(dn.lower())
        if e is not None:
            return self.entry(e)
        return "gelöschtes oder nicht lesbares Objekt" if self.mode == "count" else rdn(dn)

    def principal(self, value: str) -> str:
        """Eintrag aus GptTmpl.inf oder Preferences: SID (ohne *) oder Name (auch DOMÄNE\\Name)."""
        value = value.strip()
        if value.upper().startswith("S-1-"):
            return self.sid(value)
        domain, sep, account = value.rpartition("\\")
        if domain.upper() in WELL_KNOWN_DOMAINS or value.startswith("%"):
            return value
        key = (account if sep else value).lower()
        if key not in self._accounts:
            self._accounts[key] = self.ctx.ad.accounts_by_name([key]).get(key)
        e = self._accounts[key]
        if e is not None:
            return self.entry(e)
        return "Konto" if self.mode == "count" and sep else value

    def accounts(self, entries: list[Entry], limit: int = 10) -> str:
        """Kontenliste für Befunde; im Modus count nur die Anzahl."""
        if not entries:
            return "–"
        people = [e for e in entries if self.is_person(e)]
        if self.mode == "count" and people:
            others = sorted((self.entry(e) for e in entries if not self.is_person(e)), key=str.lower)
            more = f" (+{len(others) - limit})" if len(others) > limit else ""
            return ", ".join(others[:limit]) + more + (", " if others else "") + f"Benutzerkonten: {len(people)}"
        names = sorted((self.entry(e) for e in entries), key=str.lower)
        return ", ".join(names[:limit]) + (f" (+{len(names) - limit})" if len(names) > limit else "")


def group_label(pg: PrivGroup, names: AdNames) -> str:
    if pg.group is not None:
        return pg.group.str("sAMAccountName") or pg.group.name
    if isinstance(pg.key, int):
        return DOMAIN_RIDS.get(pg.key, str(pg.key))
    return WELL_KNOWN.get(str(pg.key), str(pg.key))
