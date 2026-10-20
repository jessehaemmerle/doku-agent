"""FortiGate: Regelwerk, NAT, Objekte, Netzwerk und VPN dokumentieren (eine Wiki-Seite je Bereich).

Tabellen entstehen deterministisch aus der API. Das LLM erklärt jede Regel (in kleinen Gruppen,
nach Eingabe-Hash zwischengespeichert) und fasst Regelwerk, NAT und VPN zusammen. Geheimnisse
(PSKs, Passwörter, verschlüsselte "ENC ..."-Werte) werden vor Prompt und Wiki entfernt.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field

from doku_agent import markdown
from doku_agent.connectors.fortigate import FortiGateClient
from doku_agent.context import Context
from doku_agent.generators.common import MASK, STYLE_RULES, cached, digest
from doku_agent.pages import Block, PageDraft, propose_page

POLICY_BATCH = 6  # Regeln pro LLM-Aufruf (Kontextbudget eines 8B-Modells auf CPU)
# Schlüssel (Teil) -> Abschnitt im Pfad, Seitentitel
SECTIONS = {
    "policies": ("regeln", "Regeln"),
    "nat": ("nat", "NAT"),
    "objects": ("objekte", "Objekte"),
    "network": ("netzwerk", "Netzwerk"),
    "vpn": ("vpn", "VPN"),
}
_SECRET_KEY = re.compile(r"(?i)(psk|secret|passw|passphrase|private-key|ppk|^key$|-key$)")
ACTIONS = {"accept": "erlauben", "deny": "verwerfen", "ipsec": "IPsec"}
LOGGING = {"all": "alle Sitzungen", "utm": "Sicherheitsereignisse", "disable": "aus"}
PROFILE_KEYS = ("av-profile", "webfilter-profile", "ips-sensor", "application-list", "dnsfilter-profile",
                "emailfilter-profile", "file-filter-profile", "ssl-ssh-profile")

EXPLAIN_SCHEMA = {
    "type": "object",
    "properties": {"regeln": {"type": "array", "items": {
        "type": "object",
        "properties": {"id": {"type": "string"}, "erklaerung": {"type": "string"}},
        "required": ["id", "erklaerung"],
    }}},
    "required": ["regeln"],
}


def mask_obj(value, key: str = ""):
    """Geheimnisse in FortiGate-Objekten ersetzen (Feldnamen mit Bindestrich, z.B. psksecret, ppk-secret)."""
    if isinstance(value, dict):
        return {k: mask_obj(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [mask_obj(v, key) for v in value]
    if isinstance(value, str):
        if value.startswith("ENC "):
            return MASK
        if _SECRET_KEY.search(key) and value.strip() and value not in ("enable", "disable"):
            return MASK
    return value


def names(items) -> list[str]:
    out = []
    for item in items or []:
        if isinstance(item, dict):
            out.append(str(item.get("name") or item.get("interface-name") or item.get("range")
                           or item.get("q_origin_key") or ""))
        else:
            out.append(str(item))
    return [n for n in out if n]


def cidr(subnet: str) -> str:
    """'10.0.0.0 255.255.255.0' -> '10.0.0.0/24', Host-Adressen ohne Präfix."""
    parts = (subnet or "").split()
    if not parts:
        return ""
    try:
        net = ipaddress.ip_interface("/".join(parts[:2]) if len(parts) > 1 else parts[0])
    except ValueError:
        return subnet
    if net.network.prefixlen == net.network.max_prefixlen:
        return str(net.ip)
    return str(net.network) if net.ip == net.network.network_address else str(net)


@dataclass
class FortiData:
    device: str
    vdom: str
    system: dict
    policies: list[dict] = field(default_factory=list)
    addresses: list[dict] = field(default_factory=list)
    addrgrps: list[dict] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    service_groups: list[dict] = field(default_factory=list)
    vips: list[dict] = field(default_factory=list)
    vipgrps: list[dict] = field(default_factory=list)
    ippools: list[dict] = field(default_factory=list)
    snat: list[dict] = field(default_factory=list)
    interfaces: list[dict] = field(default_factory=list)
    zones: list[dict] = field(default_factory=list)
    routes: list[dict] = field(default_factory=list)
    phase1: list[dict] = field(default_factory=list)
    phase2: list[dict] = field(default_factory=list)


# Welche Tabellen ein Bereich braucht (Regeln brauchen die Objekte, um Namen aufzulösen)
_NEEDS = {
    "policies": {"policies", "objects", "vips"},
    "nat": {"policies", "objects", "vips", "ippools", "snat"},  # VIPs können über Adressgruppen in Regeln stehen
    "objects": {"policies", "objects", "vips"},
    "network": {"interfaces", "zones", "routes"},
    "vpn": {"vpn", "objects", "vips"},
}


def fetch(client: FortiGateClient, vdom: str, sections: list[str]) -> FortiData:
    need = set().union(*(_NEEDS[s] for s in sections)) if sections else set()
    data = FortiData(device=client.dev.name, vdom=vdom, system=client.system())

    def get(path, optional=False):
        return [mask_obj(o) for o in client.cmdb(path, vdom, optional=optional)]

    if "policies" in need:
        data.policies = get("firewall/policy")
    if "objects" in need:
        data.addresses = get("firewall/address") + get("firewall/address6", optional=True)
        data.addrgrps = get("firewall/addrgrp") + get("firewall/addrgrp6", optional=True)
        data.services = get("firewall.service/custom")
        data.service_groups = get("firewall.service/group")
    if "vips" in need:
        data.vips = get("firewall/vip")
        data.vipgrps = get("firewall/vipgrp", optional=True)
    if "ippools" in need:
        data.ippools = get("firewall/ippool")
    if "snat" in need:
        data.snat = get("firewall/central-snat-map", optional=True)
    if "interfaces" in need:
        # system/interface ist global; die Zugehörigkeit zur VDOM steht im Feld "vdom"
        data.interfaces = [i for i in (mask_obj(o) for o in client.cmdb("system/interface"))
                           if not i.get("vdom") or i.get("vdom") == vdom]
    if "zones" in need:
        data.zones = get("system/zone", optional=True)
    if "routes" in need:
        data.routes = get("router/static")
    if "vpn" in need:
        data.phase1 = get("vpn.ipsec/phase1-interface", optional=True)
        data.phase2 = get("vpn.ipsec/phase2-interface", optional=True)
    return data


class Resolver:
    """Löst Adress-, Dienst- und VIP-Namen in lesbare Werte auf."""

    def __init__(self, data: FortiData):
        self.addresses = {a.get("name"): a for a in data.addresses}
        self.addrgrps = {g.get("name"): g for g in data.addrgrps}
        self.services = {s.get("name"): s for s in data.services}
        self.service_groups = {g.get("name"): g for g in data.service_groups}
        self.vips = {v.get("name"): v for v in data.vips}
        self.vipgrps = {g.get("name"): g for g in data.vipgrps}

    def address(self, name: str) -> str:
        if name in self.addrgrps:
            return "Gruppe: " + ", ".join(names(self.addrgrps[name].get("member")))
        if name in self.vips:
            return "VIP: " + vip_mapping(self.vips[name])
        if name in self.vipgrps:
            return "VIP-Gruppe: " + ", ".join(names(self.vipgrps[name].get("member")))
        a = self.addresses.get(name)
        if a is None:
            return ""
        kind = a.get("type") or "ipmask"
        if kind in ("ipmask", "ipprefix"):  # IPv4-Netz bzw. IPv6-Präfix (address6)
            value = cidr(a.get("subnet") or "") if kind == "ipmask" else a.get("ip6", "")
            return "beliebig" if value in ("0.0.0.0/0", "::/0") else value
        if kind == "iprange":
            return f"{a.get('start-ip', '')}–{a.get('end-ip', '')}"
        if kind == "fqdn":
            return f"FQDN {a.get('fqdn', '')}"
        if kind == "geography":
            return f"Land {a.get('country', '')}"
        if kind == "wildcard":
            return f"Wildcard {a.get('wildcard', '')}"
        if kind == "wildcard-fqdn":
            return f"Wildcard-FQDN {a.get('wildcard-fqdn', '')}"
        if kind == "interface-subnet":
            return f"Netz von Interface {a.get('interface', '')}"
        if kind == "dynamic":
            return f"dynamisch ({a.get('sdn', '') or a.get('sub-type', '')})"
        if kind == "mac":
            return "MAC " + ", ".join(names(a.get("macaddr")))
        return kind

    def service(self, name: str) -> str:
        if name in self.service_groups:
            return "Gruppe: " + ", ".join(names(self.service_groups[name].get("member")))
        s = self.services.get(name)
        if s is None:
            return ""
        return service_ports(s)


def service_ports(s: dict) -> str:
    proto = (s.get("protocol") or "TCP/UDP/SCTP").upper()
    if proto == "ICMP" or proto == "ICMP6":
        typ = s.get("icmptype")
        return proto + (f" Typ {typ}" if typ not in (None, "") else "")
    if proto == "IP":
        number = s.get("protocol-number")
        return "alle Dienste" if not number else f"IP-Protokoll {number}"
    parts = []
    for label, key in (("TCP", "tcp-portrange"), ("UDP", "udp-portrange"), ("SCTP", "sctp-portrange")):
        ranges = (s.get(key) or "").split()
        if ranges:
            # "8080-8090:1024-65535" = Ziel:Quelle – für die Doku zählt der Zielport
            parts.append(f"{label} " + ", ".join(r.split(":")[0] for r in ranges))
    return "; ".join(parts) or proto


def vip_mapping(v: dict) -> str:
    ext = v.get("extip", "")
    mapped = ", ".join(names(v.get("mappedip"))) or v.get("mapped-addr", "")
    if v.get("portforward") == "enable":
        proto = (v.get("protocol") or "tcp").upper()
        return f"{ext}:{v.get('extport', '')} → {mapped}:{v.get('mappedport') or v.get('extport', '')} ({proto})"
    return f"{ext} → {mapped}"


def _join(values: list[str]) -> str:
    return ", ".join(values) or "–"


def policy_view(p: dict, r: Resolver) -> dict:
    """Kompakte, aufgelöste Sicht auf eine Regel – für Tabelle, Details und LLM."""
    def side(key: str, key6: str, negate: str) -> list[str]:
        items = names(p.get(key)) + names(p.get(key6))
        prefix = "nicht " if p.get(negate) == "enable" else ""
        return [prefix + (f"{n} ({r.address(n)})" if r.address(n) and r.address(n) != n else n) for n in items]

    source = side("srcaddr", "srcaddr6", "srcaddr-negate")
    who = names(p.get("users")) + names(p.get("groups"))
    if who:
        source.append("Benutzer/Gruppen: " + ", ".join(who))
    if p.get("internet-service") == "enable":
        dest = ["Internet-Service: " + ", ".join(names(p.get("internet-service-name")) or ["?"])]
    else:
        dest = side("dstaddr", "dstaddr6", "dstaddr-negate")
    prefix = "nicht " if p.get("service-negate") == "enable" else ""
    services = [prefix + (f"{n} ({r.service(n)})" if r.service(n) else n) for n in names(p.get("service"))]
    if p.get("utm-status") == "enable":
        if p.get("profile-type") == "group":
            profiles = [f"Profilgruppe {p.get('profile-group', '')}"]
        else:
            profiles = [f"{k.split('-')[0]}: {p[k]}" for k in PROFILE_KEYS if p.get(k)]
    else:
        profiles = []
    if p.get("nat") == "enable":
        nat = ("Pool " + ", ".join(names(p.get("poolname")))) if p.get("ippool") == "enable" else "Interface-IP"
    else:
        nat = "nein"
    action = ACTIONS.get(p.get("action", ""), p.get("action", ""))
    if p.get("status") == "disable":
        action += " (deaktiviert)"
    return {
        "id": str(p.get("policyid", "")),
        "name": p.get("name") or "",
        "von": _join(names(p.get("srcintf"))),
        "nach": _join(names(p.get("dstintf"))),
        "quelle": source,
        "ziel": dest,
        "dienst": services,
        "aktion": action,
        "nat": nat,
        "profile": profiles,
        "zeitplan": p.get("schedule") or "",
        "log": LOGGING.get(p.get("logtraffic", ""), p.get("logtraffic", "")),
        "kommentar": p.get("comments") or "",
    }


def _explain(ctx: Context, data: FortiData, views: list[dict]) -> dict[str, str]:
    """Erklärung je Regel, nach Inhalt der einzelnen Regel zwischengespeichert. Nur Regeln ohne
    Cache-Treffer gehen (in Gruppen) an das LLM – eine neue Regel löst nicht alle folgenden neu aus."""
    out: dict[str, str] = {}
    missing = []
    for view in views:
        key = f"llm:{ctx.cfg.llm.model}:fortigate-policy:" + digest(data.device, data.vdom, view)
        hit = ctx.store.kv_get(key)
        if hit is not None:
            out[view["id"]] = hit
        else:
            missing.append((key, view))
    for i in range(0, len(missing), POLICY_BATCH):
        batch = missing[i:i + POLICY_BATCH]
        text = json.dumps([view for _, view in batch], ensure_ascii=False, indent=1)
        result = ctx.llm.json(
            "Du bist Experte für FortiGate-Firewalls und dokumentierst ein Regelwerk für das IT-Team. " + STYLE_RULES,
            "Erkläre für jede Firewall-Regel in 2-3 Sätzen, welcher Verkehr von wo nach wo erlaubt oder "
            "verworfen wird und wofür sie dient – den Zweck nur, wenn er aus Name, Objekten oder Kommentar "
            "hervorgeht. Nenne Auffälligkeiten wie 'beliebig'/'alle Dienste', fehlendes Logging, fehlende "
            f"Sicherheitsprofile oder eine deaktivierte Regel.\n\nRegeln (JSON):\n{ctx.llm.fit(text)}",
            EXPLAIN_SCHEMA,
        )
        answers = {str(item.get("id")): (item.get("erklaerung") or "").strip() for item in result.get("regeln", [])}
        for key, view in batch:
            if answers.get(view["id"]):  # fehlende Antworten werden beim nächsten Lauf erneut erfragt
                ctx.store.kv_set(key, answers[view["id"]])
                out[view["id"]] = answers[view["id"]]
    return out


def _summary(ctx: Context, key: str, task: str, text: str) -> str:
    if not text.strip():
        return ""
    return cached(ctx, f"fortigate-{key}:" + digest(text), lambda: ctx.llm.text(
        "Du bist Experte für FortiGate-Firewalls. " + STYLE_RULES, f"{task}\n\n{ctx.llm.fit(text)}"))


def _overview(data: FortiData, extra: list[list]) -> str:
    sysinfo = data.system
    version = f"{sysinfo.get('version', '')} (Build {sysinfo['build']})" if sysinfo.get("build") else sysinfo.get("version", "")
    return markdown.table(["Eigenschaft", "Wert"], [
        ["Firewall", sysinfo.get("hostname", data.device)], ["FortiOS", version],
        ["Seriennummer", sysinfo.get("serial", "")], ["VDOM", data.vdom], *extra,
    ])


def _usage(data: FortiData) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Welche Regeln ein Adress- bzw. Dienstobjekt nutzen (auch über Gruppen)."""
    addr: dict[str, set[str]] = {}
    svc: dict[str, set[str]] = {}
    for p in data.policies:
        pid = str(p.get("policyid", ""))
        for key in ("srcaddr", "dstaddr", "srcaddr6", "dstaddr6"):
            for n in names(p.get(key)):
                addr.setdefault(n, set()).add(pid)
        for n in names(p.get("service")):
            svc.setdefault(n, set()).add(pid)
    for groups, usage in ((data.addrgrps + data.vipgrps, addr), (data.service_groups, svc)):
        for _ in range(5):  # verschachtelte Gruppen
            for g in groups:
                for member in names(g.get("member")):
                    usage.setdefault(member, set()).update(usage.get(g.get("name"), set()))
    return addr, svc


def _ids(ids: set[str]) -> str:
    return ", ".join(sorted(ids, key=lambda x: int(x) if x.isdigit() else 0)) if ids else "–"


def policies_page(ctx: Context, data: FortiData) -> tuple[str, list[Block]]:
    r = Resolver(data)
    views = [policy_view(p, r) for p in data.policies]
    table = markdown.table(
        ["Nr", "ID", "Name", "Von → Nach", "Quelle", "Ziel", "Dienst", "Aktion", "NAT", "Profile", "Log"],
        [[n, v["id"], v["name"], f"{v['von']} → {v['nach']}", "<br>".join(v["quelle"]), "<br>".join(v["ziel"]),
          "<br>".join(v["dienst"]), v["aktion"], v["nat"], "<br>".join(v["profile"]) or "–", v["log"]]
         for n, v in enumerate(views, 1)],
    ) if views else "_Keine Regeln._"
    explanations = _explain(ctx, data, views) if views else {}
    compact = "\n".join(f"ID {v['id']} {v['name']}: {v['von']} -> {v['nach']}, Quelle {_join(v['quelle'])}, "
                        f"Ziel {_join(v['ziel'])}, Dienst {_join(v['dienst'])}, {v['aktion']}, NAT {v['nat']}"
                        for v in views)
    summary = _summary(ctx, "policies-summary",
                       "Fasse dieses Firewall-Regelwerk in 4-8 Stichpunkten zusammen: welche Interfaces/Zonen "
                       "miteinander kommunizieren dürfen, was ins Internet darf, was aus dem Internet erreichbar "
                       "ist und welche Regeln auffällig breit sind. Die Regeln werden von oben nach unten "
                       "geprüft, die erste passende gilt.", compact)
    details = []
    for v in views:
        expl = explanations.get(v["id"]) or "_Keine Erläuterung erzeugt._"
        rows = [["Von → Nach", f"{v['von']} → {v['nach']}"], ["Quelle", "<br>".join(v["quelle"]) or "–"],
                ["Ziel", "<br>".join(v["ziel"]) or "–"], ["Dienst", "<br>".join(v["dienst"]) or "–"],
                ["Aktion", v["aktion"]], ["NAT", v["nat"]], ["Sicherheitsprofile", "<br>".join(v["profile"]) or "–"],
                ["Zeitplan", v["zeitplan"]], ["Logging", v["log"]]]
        if v["kommentar"]:
            rows.append(["Kommentar", v["kommentar"]])
        details.append(f"### Regel {v['id']}{' – ' + v['name'] if v['name'] else ''}\n\n{expl}\n\n"
                       + markdown.table(["Eigenschaft", "Wert"], rows))
    enabled = sum(1 for p in data.policies if p.get("status") != "disable")
    overview = _overview(data, [["Regeln", f"{len(views)} ({enabled} aktiv)"]])
    if summary:
        overview = f"{summary}\n\n{overview}"
    blocks = [Block("fortigate-policies-overview", "Übersicht", overview),
              Block("fortigate-policies-table", "Regeln",
                    "Reihenfolge wie auf der Firewall – die erste passende Regel gilt.\n\n" + table)]
    if details:
        blocks.append(Block("fortigate-policies-details", "Erläuterungen", "\n\n".join(details)))
    return "Firewall-Regeln (Policies) in Auswertungsreihenfolge mit Erläuterung jeder Regel.", blocks


def nat_page(ctx: Context, data: FortiData) -> tuple[str, list[Block]]:
    addr_usage, _ = _usage(data)
    pool_usage: dict[str, set[str]] = {}
    nat_rows = []
    for p in data.policies:
        pid = str(p.get("policyid", ""))
        for n in names(p.get("poolname")):
            pool_usage.setdefault(n, set()).add(pid)
        if p.get("nat") == "enable":
            pool = ", ".join(names(p.get("poolname"))) if p.get("ippool") == "enable" else "Interface-IP"
            nat_rows.append([pid, p.get("name") or "", f"{_join(names(p.get('srcintf')))} → "
                             f"{_join(names(p.get('dstintf')))}", pool])
    vip_rows = [[v.get("name"), v.get("type") or "static-nat", v.get("extintf") or "", vip_mapping(v),
                 v.get("comment") or "", _ids(addr_usage.get(v.get("name"), set()))] for v in data.vips]
    pool_rows = [[p.get("name"), p.get("type") or "", p.get("startip") or "", p.get("endip") or "",
                  p.get("comments") or "", _ids(pool_usage.get(p.get("name"), set()))] for p in data.ippools]
    snat_rows = [[s.get("policyid"), f"{_join(names(s.get('srcintf')))} → {_join(names(s.get('dstintf')))}",
                  _join(names(s.get("orig-addr"))), _join(names(s.get("dst-addr"))),
                  _join(names(s.get("nat-ippool"))) if s.get("nat", "enable") == "enable" else "kein NAT",
                  "aktiv" if s.get("status", "enable") == "enable" else "deaktiviert", s.get("comments") or ""]
                 for s in data.snat]
    sections = [
        "### Virtuelle IPs (Ziel-NAT, Portweiterleitungen)\n\n" + (markdown.table(
            ["Name", "Typ", "Externes Interface", "Abbildung", "Kommentar", "In Regel"], vip_rows)
            if vip_rows else "_Keine._"),
        "### IP-Pools (Quell-NAT)\n\n" + (markdown.table(
            ["Name", "Typ", "Start-IP", "End-IP", "Kommentar", "In Regel"], pool_rows) if pool_rows else "_Keine._"),
        "### Regeln mit Quell-NAT\n\n" + (markdown.table(["Regel", "Name", "Von → Nach", "NAT auf"], nat_rows)
                                         if nat_rows else "_Keine._"),
    ]
    if snat_rows:
        sections.append("### Zentrale SNAT-Tabelle\n\n" + markdown.table(
            ["ID", "Von → Nach", "Quelle", "Ziel", "NAT", "Status", "Kommentar"], snat_rows))
    text = "\n".join([*(" | ".join(map(str, r)) for r in vip_rows), *(" | ".join(map(str, r)) for r in snat_rows),
                      *(" | ".join(map(str, r)) for r in nat_rows)])
    summary = _summary(ctx, "nat-summary",
                       "Fasse die NAT-Konfiguration dieser FortiGate in 3-6 Stichpunkten zusammen: welche internen "
                       "Dienste aus dem Internet erreichbar sind (VIPs) und wie ausgehender Verkehr übersetzt wird.",
                       text)
    overview = _overview(data, [["Virtuelle IPs", len(vip_rows)], ["IP-Pools", len(pool_rows)],
                                ["Regeln mit NAT", len(nat_rows)]])
    if summary:
        overview = f"{summary}\n\n{overview}"
    return "NAT der FortiGate: virtuelle IPs, IP-Pools und Quell-NAT.", [
        Block("fortigate-nat-overview", "Übersicht", overview),
        Block("fortigate-nat-tables", "NAT", "\n\n".join(sections)),
    ]


def objects_page(ctx: Context, data: FortiData) -> tuple[str, list[Block]]:
    r = Resolver(data)
    addr_usage, svc_usage = _usage(data)
    addr_rows = [[a.get("name"), a.get("type") or ("ipv6" if "ip6" in a else "ipmask"), r.address(a.get("name")),
                  a.get("associated-interface") or "", a.get("comment") or "", _ids(addr_usage.get(a.get("name"), set()))]
                 for a in data.addresses]
    grp_rows = [[g.get("name"), _join(names(g.get("member"))), g.get("comment") or "",
                 _ids(addr_usage.get(g.get("name"), set()))] for g in data.addrgrps]
    shown = [s for s in data.services if svc_usage.get(s.get("name")) or not s.get("category")]
    svc_rows = [[s.get("name"), s.get("category") or "", service_ports(s), s.get("comment") or "",
                 _ids(svc_usage.get(s.get("name"), set()))] for s in shown]
    sgrp_rows = [[g.get("name"), _join(names(g.get("member"))), g.get("comment") or "",
                  _ids(svc_usage.get(g.get("name"), set()))] for g in data.service_groups]
    unused = sum(1 for a in data.addresses + data.addrgrps if not addr_usage.get(a.get("name")))
    hidden = len(data.services) - len(shown)
    body = [
        "### Adressen\n\n" + (markdown.table(["Name", "Typ", "Wert", "Interface", "Kommentar", "In Regel"], addr_rows)
                              if addr_rows else "_Keine._"),
        "### Adressgruppen\n\n" + (markdown.table(["Name", "Mitglieder", "Kommentar", "In Regel"], grp_rows)
                                   if grp_rows else "_Keine._"),
        "### Dienste\n\n" + (markdown.table(["Name", "Kategorie", "Protokoll/Ports", "Kommentar", "In Regel"], svc_rows)
                             if svc_rows else "_Keine._")
        + (f"\n\n_{hidden} vordefinierte, nicht verwendete Dienste sind ausgeblendet._" if hidden else ""),
        "### Dienstgruppen\n\n" + (markdown.table(["Name", "Mitglieder", "Kommentar", "In Regel"], sgrp_rows)
                                   if sgrp_rows else "_Keine._"),
    ]
    overview = _overview(data, [["Adressen / Gruppen", f"{len(addr_rows)} / {len(grp_rows)}"],
                                ["Dienste / Gruppen", f"{len(data.services)} / {len(sgrp_rows)}"],
                                ["Nicht verwendete Adressobjekte", unused]])
    return "Adress- und Dienstobjekte der FortiGate mit ihrer Verwendung in Regeln.", [
        Block("fortigate-objects-overview", "Übersicht", overview),
        Block("fortigate-objects-tables", "Objekte", "\n\n".join(body)),
    ]


def network_page(ctx: Context, data: FortiData) -> tuple[str, list[Block]]:
    if_rows = []
    for i in data.interfaces:
        vlan = f"{i.get('vlanid')} auf {i.get('interface')}" if i.get("vlanid") else ""
        ip = cidr(i.get("ip") or "")
        if_rows.append([i.get("name"), i.get("alias") or "", i.get("type") or "", vlan,
                        "" if ip in ("0.0.0.0", "0.0.0.0/0") else ip, i.get("mode") or "", i.get("role") or "",
                        i.get("allowaccess") or "", i.get("status") or "", i.get("description") or ""])
    zone_rows = [[z.get("name"), _join(names(z.get("interface"))), z.get("intrazone") or "", z.get("description") or ""]
                 for z in data.zones]
    route_rows = []
    for rt in data.routes:
        dst = _join(names(rt.get("dstaddr"))) if rt.get("dstaddr") else cidr(rt.get("dst") or "")
        gateway = "Blackhole" if rt.get("blackhole") == "enable" else rt.get("gateway") or ""
        route_rows.append([rt.get("seq-num"), "0.0.0.0/0 (Standard)" if dst in ("0.0.0.0", "0.0.0.0/0") else dst,
                           gateway, rt.get("device") or "", rt.get("distance") or "",
                           "aktiv" if rt.get("status", "enable") == "enable" else "deaktiviert", rt.get("comment") or ""])
    body = [
        "### Interfaces\n\n" + (markdown.table(
            ["Name", "Alias", "Typ", "VLAN", "IP", "Modus", "Rolle", "Verwaltungszugriff", "Status", "Beschreibung"],
            if_rows) if if_rows else "_Keine._"),
        "### Zonen\n\n" + (markdown.table(["Zone", "Interfaces", "Intra-Zone", "Beschreibung"], zone_rows)
                           if zone_rows else "_Keine._"),
        "### Statische Routen\n\n" + (markdown.table(
            ["Nr", "Ziel", "Gateway", "Interface", "Distanz", "Status", "Kommentar"], route_rows)
            if route_rows else "_Keine._"),
    ]
    overview = _overview(data, [["Interfaces", len(if_rows)], ["Zonen", len(zone_rows)],
                                ["Statische Routen", len(route_rows)]])
    return "Interfaces, VLANs, Zonen und statische Routen der FortiGate.", [
        Block("fortigate-network-overview", "Übersicht", overview),
        Block("fortigate-network-tables", "Netzwerk", "\n\n".join(body)),
    ]


def _selector(r: Resolver, p2: dict, side: str) -> str:
    kind = p2.get(f"{side}-addr-type") or "subnet"
    if kind == "name":
        name = p2.get(f"{side}-name") or ""
        value = r.address(name)
        return f"{name} ({value})" if value else name
    if kind == "range":
        return f"{p2.get(f'{side}-start-ip', '')}–{p2.get(f'{side}-end-ip', '')}"
    if kind == "ip":
        return p2.get(f"{side}-start-ip", "")
    return cidr(p2.get(f"{side}-subnet") or "")


def vpn_page(ctx: Context, data: FortiData) -> tuple[str, list[Block]]:
    r = Resolver(data)
    auth = {"psk": "Pre-Shared Key", "signature": "Zertifikat"}
    p1_rows = [[p.get("name"), p.get("interface") or "",
                p.get("remote-gw") if p.get("type", "static") == "static" else f"dynamisch ({p.get('type')})",
                f"IKEv{p.get('ike-version') or '1'}", auth.get(p.get("authmethod", ""), p.get("authmethod") or ""),
                p.get("proposal") or "", p.get("dhgrp") or "", p.get("comments") or ""] for p in data.phase1]
    p2_rows = [[p.get("name"), p.get("phase1name") or "", _selector(r, p, "src"), _selector(r, p, "dst"),
                p.get("proposal") or "", p.get("pfs") or "", p.get("dhgrp") or "", p.get("keylifeseconds") or ""]
               for p in data.phase2]
    body = [
        "### IPsec-Tunnel (Phase 1)\n\n" + (markdown.table(
            ["Name", "Interface", "Gegenstelle", "IKE", "Authentifizierung", "Proposal", "DH-Gruppen", "Kommentar"],
            p1_rows) if p1_rows else "_Keine._"),
        "### Netze im Tunnel (Phase 2)\n\n" + (markdown.table(
            ["Name", "Phase 1", "Lokales Netz", "Entferntes Netz", "Proposal", "PFS", "DH-Gruppen", "Lebensdauer (s)"],
            p2_rows) if p2_rows else "_Keine._"),
    ]
    text = "\n".join(" | ".join(map(str, row)) for row in p1_rows + p2_rows)
    summary = _summary(ctx, "vpn-summary",
                       "Fasse die IPsec-VPNs dieser FortiGate in 3-6 Stichpunkten zusammen: welche Standorte bzw. "
                       "Gegenstellen mit welchen Netzen verbunden sind und welche Verfahren genutzt werden. Weise "
                       "auf veraltete Verfahren hin (z.B. IKEv1, 3DES, SHA1, DH-Gruppe 2 oder 5).", text)
    overview = _overview(data, [["IPsec-Tunnel", len(p1_rows)], ["Phase-2-Selektoren", len(p2_rows)]])
    if summary:
        overview = f"{summary}\n\n{overview}"
    return "IPsec-VPNs der FortiGate. Pre-Shared Keys und Passwörter werden nicht übernommen.", [
        Block("fortigate-vpn-overview", "Übersicht", overview),
        Block("fortigate-vpn-tables", "VPN", "\n\n".join(body)),
    ]


BUILDERS = {"policies": policies_page, "nat": nat_page, "objects": objects_page, "network": network_page,
            "vpn": vpn_page}


def stable_id(device: str, vdom: str, section: str) -> str:
    return f"fortigate:{device}:{vdom}:{section}"


def document_fortigate(ctx: Context, device: str = "", vdom: str = "", sections: list[str] | None = None) -> list[int | None]:
    """Seiten für alle (oder die angegebenen) FortiGates, VDOMs und Bereiche vorschlagen."""
    cfg = ctx.cfg.fortigate
    wanted = [s for s in cfg.include if not sections or s in sections]
    template = ctx.cfg.wiki.paths.get("fortigate", "")
    results: list[int | None] = []
    failed = []
    for dev in cfg.devices:
        if device and dev.name != device:
            continue
        for vd in dev.vdoms:
            if vdom and vd != vdom:
                continue
            label = dev.name if len(dev.vdoms) == 1 or "{vdom}" in template else f"{dev.name}-{vd}"
            try:
                data = fetch(ctx.fortigate(dev.name), vd, wanted)
            except Exception as exc:
                ctx.log.error("FortiGate %s (VDOM %s): %s", dev.name, vd, exc)
                failed.append(f"{dev.name}/{vd}")
                continue
            ctx.log.info("FortiGate %s/%s: %s Regeln, FortiOS %s", dev.name, vd, len(data.policies),
                         data.system.get("version", "?"))
            for section in wanted:
                slug, heading = SECTIONS[section]
                intro, blocks = BUILDERS[section](ctx, data)
                results.append(propose_page(ctx, PageDraft(
                    doc_type="fortigate", title=f"FortiGate {label}: {heading}",
                    description=f"FortiGate {label} – {heading}", blocks=blocks,
                    path_vars={"device": label, "section": slug, "vdom": vd},
                    intro=f"{intro} Die markierten Abschnitte werden automatisch über die FortiGate-API (nur "
                          f"lesend) aktualisiert.",
                    source=f"fortigate:{dev.name}:{vd}", stable_id=stable_id(dev.name, vd, section),
                )))
    if failed and not results:
        raise RuntimeError("Keine FortiGate erreichbar: " + ", ".join(failed))
    return results
