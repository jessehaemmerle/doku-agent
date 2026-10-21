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
from doku_agent.generators import narrative
from doku_agent.generators.common import MASK, STYLE_RULES, digest
from doku_agent.pages import Block, PageDraft, propose_page

POLICY_BATCH = 6  # Regeln pro LLM-Aufruf (Kontextbudget eines 8B-Modells auf CPU)
# Schlüssel (Teil) -> Abschnitt im Pfad, Seitentitel
SECTIONS = {
    "policies": ("regeln", "Regeln"),
    "nat": ("nat", "NAT"),
    "objects": ("objekte", "Objekte"),
    "network": ("netzwerk", "Netzwerk"),
    "vpn": ("vpn", "VPN"),
    "audit": ("pruefung", "Prüfung"),
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
    "audit": {"policies", "objects", "vips", "interfaces", "zones"},
}


def fetch(client: FortiGateClient, vdom: str, sections: list[str]) -> FortiData:
    need = set().union(*(_NEEDS[s] for s in sections)) if sections else set()
    data = FortiData(device=client.dev.name, vdom=vdom, system=client.system())

    def get(path, optional=False):
        return [mask_obj(o) for o in client.cmdb(path, vdom, optional=optional)]

    if "policies" in need:
        data.policies = get("firewall/policy")
    if "objects" in need:
        # IPv4- und IPv6-Objekte dürfen gleich heißen (FortiOS liefert "all" in beiden) -> Familie merken
        data.addresses = get("firewall/address") + [dict(a, _v6=True) for a in get("firewall/address6", optional=True)]
        data.addrgrps = get("firewall/addrgrp") + [dict(g, _v6=True) for g in get("firewall/addrgrp6", optional=True)]
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
        def by_family(objs):  # (IPv4 gewinnt, IPv6 gewinnt) – fehlt ein Name in einer Familie, gilt die andere
            v4 = {o.get("name"): o for o in objs if not o.get("_v6")}
            v6 = {o.get("name"): o for o in objs if o.get("_v6")}
            return {**v6, **v4}, {**v4, **v6}

        self.addresses, self.addresses6 = by_family(data.addresses)
        self.addrgrps, self.addrgrps6 = by_family(data.addrgrps)
        self.services = {s.get("name"): s for s in data.services}
        self.service_groups = {g.get("name"): g for g in data.service_groups}
        self.vips = {v.get("name"): v for v in data.vips}
        self.vipgrps = {g.get("name"): g for g in data.vipgrps}

    def groups(self, v6: bool = False) -> dict:
        return self.addrgrps6 if v6 else self.addrgrps

    def address(self, name: str, v6: bool = False) -> str:
        if name in self.groups(v6):
            return "Gruppe: " + ", ".join(names(self.groups(v6)[name].get("member")))
        if name in self.vips:
            return "VIP: " + vip_mapping(self.vips[name])
        if name in self.vipgrps:
            return "VIP-Gruppe: " + ", ".join(names(self.vipgrps[name].get("member")))
        a = (self.addresses6 if v6 else self.addresses).get(name)
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
        items = [(n, False) for n in names(p.get(key))] + [(n, True) for n in names(p.get(key6))]
        prefix = "nicht " if p.get(negate) == "enable" else ""
        return [prefix + (f"{n} ({v})" if (v := r.address(n, six)) and v != n else n) for n, six in items]

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


def _summary(ctx: Context, data: FortiData, key: str, task: str, counts: str, rows: str, fallback: str) -> str:
    """Fließtext über einer Tabelle (mit Faktenprüfung gegen genau diese Daten); leer ohne Daten bzw. wenn das
    Sprachmodell nicht erreichbar ist."""
    if not rows.strip():
        return ""
    facts = f"Firewall: {data.system.get('hostname', data.device)}, VDOM {data.vdom}\n{counts}\n{rows}"
    return narrative.narrate(ctx, f"fortigate-{key}:{data.device}:{data.vdom}", expert="FortiGate-Firewalls",
                             task=task, facts=facts, fallback=fallback) or ""


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
    enabled = sum(1 for p in data.policies if p.get("status") != "disable")
    summary = _summary(ctx, data, "policies-summary",
                       "Beschreibe dieses Firewall-Regelwerk im Zusammenhang: welche Interfaces bzw. Zonen "
                       "miteinander kommunizieren dürfen, was ins Internet darf, was aus dem Internet erreichbar "
                       "ist und welche Regeln auffällig breit sind. Die Regeln werden von oben nach unten "
                       "geprüft, die erste passende gilt.",
                       f"Regeln gesamt: {len(views)}, davon aktiv: {enabled}", compact,
                       f"Das Regelwerk umfasst {len(views)} Regeln, davon {enabled} aktiv. Sie werden von oben nach "
                       f"unten geprüft; die erste passende Regel gilt.")
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
    summary = _summary(ctx, data, "nat-summary",
                       "Beschreibe die NAT-Konfiguration dieser FortiGate: welche internen Dienste aus dem Internet "
                       "erreichbar sind (virtuelle IPs, Portweiterleitungen) und wie ausgehender Verkehr übersetzt "
                       "wird.",
                       f"Virtuelle IPs: {len(vip_rows)}, IP-Pools: {len(pool_rows)}, Regeln mit NAT: {len(nat_rows)}",
                       text,
                       f"Die FortiGate hat {len(vip_rows)} virtuelle IPs, {len(pool_rows)} IP-Pools und "
                       f"{len(nat_rows)} Regeln mit Quell-NAT.")
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
    addr_rows = [[a.get("name"), a.get("type") or ("ipv6" if "ip6" in a else "ipmask"),
                  r.address(a.get("name"), a.get("_v6", False)),
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
    if narrative.enabled(ctx, "overview"):
        text = "\n".join([*("Interface: " + " | ".join(map(str, r)) for r in if_rows),
                          *("Zone: " + " | ".join(map(str, r)) for r in zone_rows),
                          *("Route: " + " | ".join(map(str, r)) for r in route_rows)])
        summary = _summary(ctx, data, "network-summary",
                           "Beschreibe den Netzaufbau dieser FortiGate: welche Netze bzw. VLANs an welchen "
                           "Interfaces hängen und welche Rolle sie haben (LAN, WAN, DMZ), wie Zonen gebildet sind, "
                           "wohin der Standardweg führt und auf welchen Interfaces die Verwaltung erreichbar ist.",
                           f"Interfaces: {len(if_rows)}, Zonen: {len(zone_rows)}, statische Routen: "
                           f"{len(route_rows)}", text,
                           f"Die FortiGate hat {len(if_rows)} Interfaces, {len(zone_rows)} Zonen und "
                           f"{len(route_rows)} statische Routen.")
        if summary:
            overview = f"{summary}\n\n{overview}"
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
    summary = _summary(ctx, data, "vpn-summary",
                       "Beschreibe die IPsec-VPNs dieser FortiGate: welche Standorte bzw. Gegenstellen mit welchen "
                       "Netzen verbunden sind und welche Verfahren genutzt werden. Weise auf veraltete Verfahren hin "
                       "(z.B. IKEv1, 3DES, SHA1 oder schwache DH-Gruppen), aber nur, wenn sie in den Daten vorkommen.",
                       f"IPsec-Tunnel: {len(p1_rows)}, Phase-2-Selektoren: {len(p2_rows)}", text,
                       f"Die FortiGate hat {len(p1_rows)} IPsec-Tunnel mit {len(p2_rows)} Phase-2-Selektoren.")
    overview = _overview(data, [["IPsec-Tunnel", len(p1_rows)], ["Phase-2-Selektoren", len(p2_rows)]])
    if summary:
        overview = f"{summary}\n\n{overview}"
    return "IPsec-VPNs der FortiGate. Pre-Shared Keys und Passwörter werden nicht übernommen.", [
        Block("fortigate-vpn-overview", "Übersicht", overview),
        Block("fortigate-vpn-tables", "VPN", "\n\n".join(body)),
    ]


# --- Prüfung (Hygiene) des Regelwerks ------------------------------------------

V4_ALL = (4, 0, 2 ** 32 - 1)
V6_ALL = (6, 0, 2 ** 128 - 1)
SVC_ALL = ("all", 0, 0)


def _net_interval(value: str) -> tuple[int, int, int] | None:
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
    return (net.version, int(net.network_address), int(net.broadcast_address))


def _range_interval(start: str, end: str) -> tuple[int, int, int] | None:
    try:
        a, b = ipaddress.ip_address(start), ipaddress.ip_address(end or start)
    except ValueError:
        return None
    return (a.version, int(a), int(b)) if a.version == b.version else None


class AddressSets:
    """Adress- und Dienstobjekte als Intervalle; nicht auflösbare Objekte (FQDN, Land, ...) als Marke."""

    def __init__(self, data: FortiData):
        self.r = Resolver(data)

    def address(self, name: str, depth: int = 0, v6: bool = False) -> tuple[set, set]:
        intervals, opaque = set(), set()
        r = self.r
        marker = f"obj6:{name}" if v6 else f"obj:{name}"
        if depth > 10:
            return intervals, {marker}
        if name in r.groups(v6) or name in r.vipgrps:
            group = r.groups(v6).get(name) or r.vipgrps.get(name)
            for member in names(group.get("member")):
                i, o = self.address(member, depth + 1, v6)
                intervals |= i
                opaque |= o
            return intervals, opaque
        if name in r.vips:
            ext = r.vips[name].get("extip") or ""
            iv = _range_interval(*ext.split("-", 1)) if "-" in ext else _range_interval(ext, ext)
            return ({iv} if iv else set()), ({f"vip:{name}"} if not iv else set())
        a = (r.addresses6 if v6 else r.addresses).get(name)
        if a is None:
            return intervals, {marker}
        kind = a.get("type") or "ipmask"
        iv = None
        if kind == "ipmask":
            parts = (a.get("subnet") or "").split()
            iv = _net_interval("/".join(parts[:2])) if parts else None
        elif kind == "ipprefix":
            iv = _net_interval(a.get("ip6") or "")
        elif kind == "iprange":
            iv = _range_interval(a.get("start-ip") or "", a.get("end-ip") or "")
        return ({iv} if iv else set()), (set() if iv else {marker})

    def side(self, p: dict, key: str, key6: str) -> tuple[set, set]:
        intervals, opaque = set(), set()
        for n, six in [(n, False) for n in names(p.get(key))] + [(n, True) for n in names(p.get(key6))]:
            i, o = self.address(n, v6=six)
            intervals |= i
            opaque |= o
        return intervals, opaque

    def service(self, name: str, depth: int = 0) -> tuple[set, set]:
        r = self.r
        if name in r.service_groups and depth < 10:
            intervals, opaque = set(), set()
            for member in names(r.service_groups[name].get("member")):
                i, o = self.service(member, depth + 1)
                intervals |= i
                opaque |= o
            return intervals, opaque
        s = r.services.get(name)
        if s is None:
            return set(), {f"svc:{name}"}
        proto = (s.get("protocol") or "TCP/UDP/SCTP").upper()
        if proto == "IP":
            number = s.get("protocol-number") or 0
            return ({SVC_ALL} if not number else set()), (set() if not number else {f"ip:{number}"})
        if proto.startswith("ICMP"):
            return set(), {f"{proto.lower()}:{s.get('icmptype', 'alle')}"}
        intervals = set()
        for label, key in (("tcp", "tcp-portrange"), ("udp", "udp-portrange"), ("sctp", "sctp-portrange")):
            for rng in (s.get(key) or "").split():
                dst = rng.split(":")[0]
                lo, _, hi = dst.partition("-")
                if lo.isdigit():
                    intervals.add((label, int(lo), int(hi or lo)))
        return intervals, (set() if intervals else {f"svc:{name}"})

    def services(self, p: dict) -> tuple[set, set]:
        intervals, opaque = set(), set()
        for n in names(p.get("service")):
            i, o = self.service(n)
            intervals |= i
            opaque |= o
        return intervals, opaque


def _covered(outer: set, inner: tuple) -> bool:
    family = inner[0]
    spans = sorted((lo, hi) for f, lo, hi in outer if f == family)
    pos = inner[1]
    for lo, hi in spans:
        if lo > pos:
            return False
        if hi >= pos:
            pos = hi + 1
            if pos > inner[2]:
                return True
    return pos > inner[2]


def covers(a: tuple[set, set], b: tuple[set, set], everything: tuple) -> bool:
    """Deckt Menge a die Menge b vollständig ab? 'everything' sind die Intervalle für 'beliebig'."""
    a_iv, a_op = a
    if any(_covered(a_iv, e) for e in everything):
        return True  # a ist beliebig (IPv4 "all" bzw. IPv6 "all"): deckt alles, auch FQDN-/Länder-Objekte
    b_iv, b_op = b
    return b_op <= a_op and all(_covered(a_iv, iv) for iv in b_iv)


def _is_any(sets: tuple[set, set], everything: tuple) -> bool:
    return all(_covered(sets[0], e) for e in everything)


def audit(data: FortiData) -> dict[str, list]:
    sets = AddressSets(data)
    wan = {i.get("name") for i in data.interfaces if i.get("role") == "wan"}
    wan |= {z.get("name") for z in data.zones if wan & set(names(z.get("interface")))}
    findings: dict[str, list] = {"shadowed": [], "any_any": [], "no_log": [], "no_profile": [], "disabled": [],
                                 "unused": []}
    seen: list[tuple[dict, tuple, tuple, tuple]] = []
    addr_all, svc_all = (V4_ALL, V6_ALL), (SVC_ALL,)
    tcp_udp_all = tuple((p, 0, 65535) for p in ("tcp", "udp", "sctp"))
    for p in data.policies:
        pid, name = str(p.get("policyid", "")), p.get("name") or ""
        if p.get("status") == "disable":
            findings["disabled"].append([pid, name])
            continue
        src, dst = sets.side(p, "srcaddr", "srcaddr6"), sets.side(p, "dstaddr", "dstaddr6")
        svc = sets.services(p)
        accept = p.get("action") == "accept"
        simple = not any(p.get(k) == "enable" for k in ("srcaddr-negate", "dstaddr-negate", "service-negate",
                                                        "internet-service", "internet-service-src"))
        svc_any = _is_any(svc, svc_all) or all(_covered(svc[0], e) for e in tcp_udp_all)
        if accept and _is_any(src, addr_all[:1]) and _is_any(dst, addr_all[:1]) and svc_any and simple:
            findings["any_any"].append([pid, name, f"{_join(names(p.get('srcintf')))} → {_join(names(p.get('dstintf')))}"])
        if accept and p.get("logtraffic") == "disable":
            findings["no_log"].append([pid, name])
        intfs = set(names(p.get("srcintf"))) | set(names(p.get("dstintf")))
        if accept and intfs & wan and p.get("utm-status") != "enable":
            findings["no_profile"].append([pid, name, ", ".join(sorted(intfs & wan))])
        if simple:
            for earlier, e_src, e_dst, e_svc in seen:
                e_in, e_out = set(names(earlier.get("srcintf"))), set(names(earlier.get("dstintf")))
                if not ({"any"} & e_in or set(names(p.get("srcintf"))) <= e_in):
                    continue
                if not ({"any"} & e_out or set(names(p.get("dstintf"))) <= e_out):
                    continue
                if earlier.get("schedule", "always") not in ("always", p.get("schedule", "always")):
                    continue
                who = set(names(earlier.get("users"))) | set(names(earlier.get("groups")))
                if who and who != set(names(p.get("users"))) | set(names(p.get("groups"))):
                    continue
                if covers(e_src, src, addr_all) and covers(e_dst, dst, addr_all) and covers(e_svc, svc, svc_all):
                    other = earlier.get("action") != p.get("action")
                    findings["shadowed"].append([pid, name, str(earlier.get("policyid", "")),
                                                 "andere Aktion – Regel greift nie" if other else "gleiche Aktion – überflüssig"])
                    break
            seen.append((p, src, dst, svc))
    addr_usage, svc_usage = _usage(data)
    for kind, objs, usage in (("Adresse", data.addresses, addr_usage), ("Adressgruppe", data.addrgrps, addr_usage),
                              ("Dienst", [s for s in data.services if not s.get("category")], svc_usage),
                              ("Dienstgruppe", data.service_groups, svc_usage)):
        for o in objs:
            if not usage.get(o.get("name")) and o.get("name") not in ("all", "none", "ALL"):
                findings["unused"].append([kind, o.get("name")])
    return findings


# --- Regeln, die eine bestimmte Maschine betreffen (für den Netbox-Steckbrief) ------------------

def _vip_maps(v: dict, ip: int) -> bool:
    for rng in names(v.get("mappedip")) or [v.get("mapped-addr") or ""]:
        start, _, end = rng.partition("-")
        iv = _range_interval(start, end or start)
        if iv and iv[0] == 4 and iv[1] <= ip <= iv[2]:
            return True
    return False


def _object_hits(sets: AddressSets, name: str, ip: int, min_prefix: int, depth: int = 0) -> str:
    """Name des (Teil-)Objekts, über das die IP gezielt erfasst ist – '' wenn nicht (oder nur als großes Netz)."""
    r = sets.r
    if depth > 10:
        return ""
    if name in r.vips:
        return f"VIP {name} ({vip_mapping(r.vips[name])})" if _vip_maps(r.vips[name], ip) else ""
    if name in r.addrgrps or name in r.vipgrps:
        group = r.addrgrps.get(name) or r.vipgrps.get(name)
        for member in names(group.get("member")):
            hit = _object_hits(sets, member, ip, min_prefix, depth + 1)
            if hit:
                return f"{name} → {hit}"
        return ""
    intervals, _ = sets.address(name)
    largest = 2 ** (32 - min_prefix)
    for family, lo, hi in intervals:
        if family == 4 and lo <= ip <= hi and hi - lo + 1 <= largest:
            return name
    return ""


def machine_rules(data: FortiData, hosts: list[str], min_prefix: int) -> list[list]:
    """Regeln, deren Quelle oder Ziel eine der IPs über Host-, Bereichs-, VIP- oder Netzobjekte bis
    /min_prefix erfasst ('beliebig' und große Netze zählen nicht)."""
    sets = AddressSets(data)
    r = sets.r
    ips = []
    for h in hosts:
        try:
            addr = ipaddress.ip_address(h)
        except ValueError:
            continue
        if addr.version == 4:
            ips.append(int(addr))
    rows = []
    for p in data.policies:
        view = policy_view(p, r)
        for direction, key, other_key in (("ausgehend", "srcaddr", "dstaddr"), ("eingehend", "dstaddr", "srcaddr")):
            if p.get(f"{key}-negate") == "enable":  # "alles außer …" betrifft die Maschine gerade nicht gezielt
                continue
            hit = ""
            for ip in ips:
                hit = next((h for n in names(p.get(key)) if (h := _object_hits(sets, n, ip, min_prefix))), "")
                if hit:
                    break
            if not hit:
                continue
            other = view["ziel"] if direction == "ausgehend" else view["quelle"]
            rows.append([f"{data.device}" + (f"/{data.vdom}" if data.vdom != "root" else ""),
                         f"{view['id']}" + (f" {view['name']}" if view["name"] else ""), direction,
                         "<br>".join(other) or "–", "<br>".join(view["dienst"]) or "–", view["aktion"], hit])
    return rows


def rules_for_machine(ctx: Context, hosts: list[str]) -> list[list] | None:
    """Treffer über alle FortiGates; None, wenn eine Firewall nicht lesbar war (Block dann nicht ändern)."""
    cfg = ctx.cfg.fortigate
    cache = ctx.__dict__.setdefault("_fortigate_rules_cache", {})
    rows = []
    for dev in cfg.devices:
        for vdom in dev.vdoms:
            key = (dev.name, vdom)
            if key not in cache:
                try:
                    cache[key] = fetch(ctx.fortigate(dev.name), vdom, ["policies"])
                except Exception as exc:
                    ctx.log.warning("FortiGate %s/%s für den Steckbrief nicht lesbar: %s", dev.name, vdom, exc)
                    cache[key] = None
            if cache[key] is None:
                return None
            rows += machine_rules(cache[key], hosts, cfg.steckbrief_min_prefix)
    return rows


def audit_page(ctx: Context, data: FortiData) -> tuple[str, list[Block]]:
    f = audit(data)
    sections = [
        ("Verdeckte Regeln", "shadowed", ["Regel", "Name", "verdeckt durch Regel", "Bewertung"],
         "Eine frühere Regel deckt Quelle, Ziel, Dienst und Interfaces vollständig ab."),
        ("Alles erlaubt (any-any)", "any_any", ["Regel", "Name", "Von → Nach"], "Quelle, Ziel und Dienst beliebig."),
        ("Erlaubt ohne Logging", "no_log", ["Regel", "Name"], ""),
        ("Internet ohne Sicherheitsprofil", "no_profile", ["Regel", "Name", "WAN-Interface"],
         "Erlaubter Verkehr über ein WAN-Interface ohne Virenschutz, IPS oder Webfilter."),
        ("Deaktivierte Regeln", "disabled", ["Regel", "Name"], ""),
        ("Nicht verwendete Objekte", "unused", ["Art", "Name"], "Kandidaten zum Aufräumen (vordefinierte Dienste ausgenommen)."),
    ]
    labels = {"shadowed": "Verdeckte Regeln", "any_any": "any-any", "no_log": "ohne Logging",
              "no_profile": "Internet ohne Profil", "disabled": "deaktiviert", "unused": "unbenutzte Objekte"}
    overview = _overview(data, [[labels[k], len(v)] for k, v in f.items()])
    blocks = []
    text = narrative.assessment(
        ctx, f"fortigate-audit:{data.device}:{data.vdom}", expert="FortiGate-Firewalls",
        subject=f"FortiGate {data.system.get('hostname', data.device)}", context=f"Regeln gesamt: {len(data.policies)}",
        sections=[(title, headers, f[key]) for title, key, headers, _ in sections]) \
        if narrative.enabled(ctx, "audit") else None
    if text is not None:
        blocks.append(Block("fortigate-audit-assessment", "Bewertung", text))
    body = []
    for title, key, headers, note in sections:
        rows = f[key]
        text = markdown.table(headers, rows) if rows else "_Keine Befunde._"
        body.append(f"### {title}\n\n" + (f"{note}\n\n" if note and rows else "") + text)
    return ("Automatische Prüfung des Regelwerks: verdeckte und zu breite Regeln, fehlendes Logging, Internet-Verkehr "
            "ohne Sicherheitsprofil, deaktivierte Regeln und unbenutzte Objekte. Verdeckte Regeln werden nur für "
            "auflösbare Objekte erkannt (IP-Netze, Bereiche, Ports); FQDN- und Länderobjekte gelten nur bei gleichem "
            "Namen als abgedeckt."), blocks + [
        Block("fortigate-audit-overview", "Übersicht", overview),
        Block("fortigate-audit-findings", "Befunde", "\n\n".join(body)),
    ]


BUILDERS = {"policies": policies_page, "nat": nat_page, "objects": objects_page, "network": network_page,
            "vpn": vpn_page, "audit": audit_page}


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
