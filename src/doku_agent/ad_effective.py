"""Welche Gruppenrichtlinien für einen Computer wirken – eine Näherung des Richtlinienergebnissatzes (RSoP).

Reihenfolge wie bei Windows: Standort, Domäne, dann die OUs von oben nach unten; innerhalb eines Containers
zuletzt die Verknüpfung mit Reihenfolge 1. Blockierte Vererbung verwirft nicht erzwungene GPOs der Ebenen
darüber. Erzwungene GPOs kommen zuletzt, und unter ihnen gewinnt die höhere Ebene. Ausgelassen werden
deaktivierte Verknüpfungen, GPOs mit deaktivierter Computerkonfiguration und GPOs, die der Computer laut
Sicherheitsfilterung nicht übernimmt. WMI-Filter werden genannt, aber nicht ausgewertet (das geht nur auf dem
Computer selbst); der Standort folgt aus der IP-Adresse und den Subnetzen im AD.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from doku_agent.connectors.ad import Entry, parent_dn
from doku_agent.context import Context
from doku_agent.generators import gpo_docs
from doku_agent.generators.ad_common import AdData, ou_path

LOOPBACK_KEY = r"software\policies\microsoft\windows\system"
LOOPBACK = {1: "Zusammenführen", 2: "Ersetzen"}


@dataclass
class Applied:
    guid: str
    name: str
    container: str  # Anzeige des Containers, an dem die GPO verknüpft ist
    enforced: bool
    wmi: str = ""


@dataclass
class Effective:
    computer: Entry
    container: str  # OU-Pfad des Computers
    site: str  # aus IP und Subnetz; leer = unbekannt
    applied: list[Applied] = field(default_factory=list)  # Priorität 1 zuerst
    skipped: list[tuple[str, str, str]] = field(default_factory=list)  # (GPO, Container, Grund)
    loopback: str = ""


class AdStructure:
    """AD-Daten, die für alle Computer eines Laufs gleich sind (einmal je Job geladen)."""

    def __init__(self, ctx: Context):
        from doku_agent.generators.ad_common import fetch
        self.ctx = ctx
        self.data, errors = fetch(ctx, {"base", "structure", "gpo"})
        if errors:
            raise RuntimeError("; ".join(errors.values()))
        self.data.subnets = ctx.ad.subnets()
        self.computers: dict[str, Entry] = {}
        for c in ctx.ad.computers():
            for key in (c.str("sAMAccountName").rstrip("$"), c.name, c.str("dNSHostName").split(".")[0]):
                if key:
                    self.computers.setdefault(key.lower(), c)
        self.by_dn = {e.dn.lower(): e for e in [self.data.domain, *self.data.ous]}
        self.gpos = {g.str("cn").upper(): g for g in self.data.gpos}
        self._loopback: dict[str, int] = {}
        self._via_primary: dict[str, set[str]] = {}
        self._subnets = []
        for s in self.data.subnets:
            try:
                self._subnets.append((ipaddress.ip_network(s.name, strict=False), s.str("siteObject")))
            except ValueError:
                continue

    def computer(self, name: str) -> Entry | None:
        short = (name or "").split(".")[0].lower()
        return self.computers.get(short)

    def site_for(self, ips: list[str]) -> Entry | None:
        """Standort über das spezifischste Subnetz, das eine der IPs enthält."""
        best = None
        for ip in ips:
            try:
                addr = ipaddress.ip_address(ip.split("/")[0])
            except ValueError:
                continue
            for net, site_dn in self._subnets:
                if addr.version == net.version and addr in net and (best is None or net.prefixlen > best[0].prefixlen):
                    best = (net, site_dn)
        if best is None:
            return None
        return next((s for s in self.data.sites if s.dn.lower() == best[1].lower()), None)

    def via_primary(self, sid: str) -> set[str]:
        """SIDs der Gruppen, in denen eine primäre Gruppe (z.B. Domänencomputer) Mitglied ist – je Lauf einmal."""
        if sid not in self._via_primary:
            groups = self.ctx.ad.groups_by_sid([sid])
            self._via_primary[sid] = {g.sid() for g in self.ctx.ad.groups_of(groups[0].dn)} if groups else set()
        return self._via_primary[sid]

    def loopback(self, guid: str) -> int:
        """Loopback-Modus einer GPO (UserPolicyMode in der Computer-Registry.pol), 0 = keiner."""
        if guid not in self._loopback:
            mode = 0
            if self.ctx.cfg.ad.sysvol:
                files = self.data.files.get(guid.lower())
                if files is None:
                    files = gpo_docs.load_files(self.ctx, self.data, guid)
                    self.data.files[guid.lower()] = files
                for e in files.registry.get("Machine", []):
                    if e.key.lower() == LOOPBACK_KEY and e.value.lower() == "userpolicymode" and isinstance(e.data, int):
                        mode = e.data
            self._loopback[guid] = mode
        return self._loopback[guid]


def structure(ctx: Context) -> AdStructure:
    """Je Job einmal laden (der Kontext eines Jobs lebt nur so lange wie der Job)."""
    cached = ctx.__dict__.get("_ad_structure")
    if cached is None:
        try:
            cached = AdStructure(ctx)
        except Exception as exc:  # nicht bei jeder Maschine erneut auf den DC warten
            cached = exc
        ctx.__dict__["_ad_structure"] = cached
    if isinstance(cached, Exception):
        raise cached
    return cached


def _chain(st: AdStructure, dn: str) -> list[tuple[Entry, str]]:
    """Domäne und OUs von oben bis zum Container des Computers, jeweils mit Anzeige."""
    data: AdData = st.data
    out, current = [], parent_dn(dn)
    while current and current.lower() != data.base.lower():
        e = st.by_dn.get(current.lower())
        if e is not None:  # Container (CN=Computers) haben keine Verknüpfungen
            out.append((e, ou_path(e.dn, data.base)))
        current = parent_dn(current)
    return [(data.domain, f"Domäne {data.dns}")] + list(reversed(out))


def effective(ctx: Context, computer: Entry, ips: list[str]) -> Effective:
    st = structure(ctx)
    data = st.data
    site = st.site_for(ips)
    containers = ([(site, f"Standort {site.name}")] if site is not None else []) + _chain(st, computer.dn)
    # Sicherheitstoken des Computers: primäre Gruppe (515 Domänencomputer, 516 Domänencontroller) samt den Gruppen,
    # die sie enthalten – member:IN_CHAIN folgt primaryGroupID nicht
    primary = f"{data.domain_sid}-{computer.int('primaryGroupID', 515) or 515}"
    sids = {computer.sid(), "S-1-1-0", "S-1-5-11", primary}
    sids |= {g.sid() for g in ctx.ad.groups_of(computer.dn)} | st.via_primary(primary)
    if primary.endswith("-516"):
        sids.add("S-1-5-9")  # Organisations-Domänencontroller
    normal: list[tuple[str, str, bool, str]] = []  # (GUID, Container, erzwungen, DN) in Anwendungsreihenfolge
    enforced_by_level: list[list[tuple[str, str, bool, str]]] = []
    for obj, label in containers:
        if (obj.int("gPOptions", 0) or 0) & 1:
            normal = []  # Vererbung blockiert: nicht erzwungene GPOs der Ebenen darüber entfallen
        level = []
        for dn, options in gpo_docs.parse_gplink(obj.str("gPLink")):  # Dateireihenfolge = Anwendungsreihenfolge
            if options & 1:
                continue
            entry = (gpo_docs.gpo_guid(dn), label, bool(options & 2), dn)
            (level if entry[2] else normal).append(entry)
        enforced_by_level.append(level)
    # Erzwungene zuletzt, die höchste Ebene ganz zum Schluss (sie gewinnt)
    order = normal + [e for level in reversed(enforced_by_level) for e in level]
    result = Effective(computer, ou_path(parent_dn(computer.dn), data.base) or parent_dn(computer.dn),
                       site.name if site is not None else "")
    seen: set[str] = set()
    for guid, label, enforced, dn in reversed(order):  # höchste Priorität zuerst
        if guid in seen:
            continue
        seen.add(guid)
        gpo = st.gpos.get(guid)
        if gpo is None:
            foreign = gpo_docs.foreign_domain(data, dn)
            result.skipped.append((f"GPO {guid} der Domäne {foreign}", label, "aus einer anderen Domäne – hier nicht "
                                   "ausgewertet") if foreign else (f"gelöschte GPO {guid}", label,
                                                                   "GPO existiert nicht mehr"))
            continue
        name = gpo.str("displayName") or guid
        if (gpo.int("flags", 0) or 0) & 2:
            result.skipped.append((name, label, "Computerkonfiguration deaktiviert"))
            continue
        acl = gpo_docs.gpo_acl(gpo)
        if acl.readable and (set(acl.deny) & sids or not set(acl.apply) & sids):
            result.skipped.append((name, label, "Sicherheitsfilterung: Computer übernimmt die GPO nicht"))
            continue
        result.applied.append(Applied(guid, name, label, enforced, gpo_docs.wmi_filter(data, gpo)[0]))
    for a in result.applied:  # Loopback: die GPO mit der höchsten Priorität, die ihn setzt, gilt
        mode = st.loopback(a.guid)
        if mode in LOOPBACK:
            result.loopback = f"{LOOPBACK[mode]} (gesetzt durch {a.name})"
            break
    return result
