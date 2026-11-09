"""AD-integriertes DNS dokumentieren: eine Seite je Zone mit ihren Einträgen, eine Übersicht, und ein
Abgleich der A-Einträge mit den IP-Adressen in Netbox (Bericht + Vorschläge für den DNS-Namen, nur lesend
aus dem AD; Netbox-Änderungen nur mit Freigabe).
"""

from __future__ import annotations

from doku_agent import ad_dns, markdown
from doku_agent.connectors.ad import Entry
from doku_agent.context import Context
from doku_agent.generators.ad_common import AdData
from doku_agent.pages import Block, PageDraft, propose_page, render_path

RECORD_ORDER = ["SOA", "NS", "A", "AAAA", "CNAME", "MX", "SRV", "PTR", "TXT"]


def _fqdn(node: str, zone: str) -> str:
    return zone if node in ("@", "") else f"{node}.{zone}"


def _records(entry: Entry) -> list[ad_dns.DnsRecord]:
    out = []
    for raw in entry.values("dnsRecord"):
        rec = ad_dns.parse_dns_record(raw)
        if rec is not None and rec.type != "ZERO":
            out.append(rec)
    return out


def zone_page(ctx: Context, data: AdData, zone: Entry) -> int | None:
    from datetime import datetime, timedelta, timezone
    name = zone.str("name")
    props = ad_dns.parse_properties(zone.values("dnsProperty"))
    aging = bool(props.get("aging"))
    nodes = data.dns_records.get(name, [])
    stale_before = datetime.now(timezone.utc) - timedelta(days=ctx.cfg.ad.dns_stale_days)
    rows, counts, stale = [], {}, 0
    for node in sorted(nodes, key=lambda n: n.str("name").lower()):
        host = node.str("name")
        for rec in sorted(_records(node), key=lambda r: (RECORD_ORDER.index(r.type) if r.type in RECORD_ORDER else 9)):
            counts[rec.type] = counts.get(rec.type, 0) + 1
            # Kein Datum für aktuelle dynamische Einträge: der Zeitstempel wandert mit jeder Auffrischung, die Seite
            # bekäme sonst bei jedem Lauf einen neuen Vorschlag. Ohne Alterung frischt der DNS-Server Zeitstempel gar
            # nicht auf – ein altes Datum heißt dann nichts, also nur mit Alterung als veraltet werten.
            if rec.static:
                age = "statisch"
            elif aging and rec.stamp and rec.stamp < stale_before:
                age = f"veraltet (letzte Aktualisierung {rec.stamp.strftime('%Y-%m-%d')})"
                stale += 1
            else:
                age = "dynamisch"
            rows.append([_fqdn(host, name), rec.type, rec.value, age])
    if not aging:
        stale_text = "nicht bewertbar (ohne Alterung frischt der DNS-Server die Zeitstempel nicht auf)"
    else:
        stale_text = f"{stale} (seit über {ctx.cfg.ad.dns_stale_days} Tagen nicht aufgefrischt)" if stale else "0"
    info = markdown.table(["Eigenschaft", "Wert"], [
        ["Zone", name], ["Art", props.get("zone_type", "–")],
        ["Dynamische Updates", props.get("allow_update", "–")],
        ["Alterung (Scavenging)", "ein" if aging else "aus"],
        ["Einträge", str(len(rows))],
        ["Veraltete dynamische Einträge", stale_text],
    ])
    summary = markdown.table(["Typ", "Anzahl"], [[t, counts[t]] for t in RECORD_ORDER if t in counts]) or "–"
    table = markdown.table(["Name", "Typ", "Wert", "Stand"], rows) if rows else "_Keine Einträge._"
    blocks = [Block("dns-info", "Zone", info), Block("dns-summary", "Einträge nach Typ", summary),
              Block("dns-records", "Einträge", table)]
    return propose_page(ctx, PageDraft(
        doc_type="addns", title=f"DNS-Zone: {name}", description=f"DNS-Zone {name}", blocks=blocks,
        path_vars={"zone": name},
        intro=f"Einträge der DNS-Zone **{name}** aus dem Active Directory (nur lesend). Die markierten Abschnitte "
              f"werden automatisch aktualisiert.",
        source=f"addns:{name}", stable_id=f"addns:zone:{name}", sync_title=True))


def zone_path(ctx: Context, name: str) -> str:
    template = ctx.cfg.wiki.paths.get("addns") or "netzwerk/dns/{zone}"
    style = ctx.conventions.profile_for_path(render_path(template, {"zone": name}, "kebab")).slug_style
    return render_path(template, {"zone": name}, style)


def index_page(ctx: Context, data: AdData) -> int | None:
    rows = []
    for z in sorted(data.dns_zones, key=lambda z: z.str("name").lower()):
        name = z.str("name")
        props = ad_dns.parse_properties(z.values("dnsProperty"))
        rows.append([markdown.link(zone_path(ctx, name), name), props.get("zone_type", "–"),
                     props.get("allow_update", "–"), str(len(data.dns_records.get(name, [])))])
    table = markdown.table(["Zone", "Art", "Dynamische Updates", "Knoten"], rows) if rows else "_Keine Zonen._"
    return propose_page(ctx, PageDraft(
        doc_type="addns_index", title="DNS-Zonen", description="AD-integrierte DNS-Zonen",
        blocks=[Block("dns-zones", "Zonen", table)],
        target_path=ctx.cfg.wiki.paths.get("addns_index") or "netzwerk/dns",
        intro="AD-integrierte DNS-Zonen (nur lesend aus dem Active Directory).",
        source="addns", stable_id="addns:index"))


# --- Netbox-Abgleich ------------------------------------------------------------------------------

# Namen, die auf die Domänencontroller zeigen, ohne deren Hostname zu sein (Zonenspitze, DNS-Partitionen)
DC_ALIASES = {"@", "", "domaindnszones", "forestdnszones"}


def _host_zone(name: str) -> bool:
    """Zonen mit Hostnamen: nicht Reverse, nicht _msdcs (Dienst-/GC-Namen), nicht die Stammhinweise
    (RootDNSServers: A-Einträge der Root-Server) und keine internen Zonen wie ..TrustAnchors."""
    low = name.lower()
    return not (low.endswith((".in-addr.arpa", ".ip6.arpa")) or low.startswith(("_msdcs.", ".."))
                or low == "rootdnsservers")


def host_names(data: AdData) -> dict[str, list[str]]:
    """IP -> Hostnamen aus den A/AAAA-Einträgen, ohne DC-Aliasse, Dienstnamen (_ldap._tcp …) und Platzhalter (*)."""
    by_ip: dict[str, dict[str, str]] = {}
    for zone in data.dns_zones:
        name = zone.str("name")
        if not _host_zone(name):
            continue
        for node in data.dns_records.get(name, []):
            labels = node.str("name").split(".")
            if labels[0].lower() in DC_ALIASES or any(p.startswith("_") or p == "*" for p in labels):
                continue
            fqdn = _fqdn(node.str("name"), name)
            for rec in _records(node):
                if rec.type in ("A", "AAAA") and _is_ip(rec.value):  # unlesbare Einträge liefern keine IP
                    by_ip.setdefault(rec.value, {}).setdefault(fqdn.lower(), fqdn)
    return {ip: sorted(names.values(), key=str.lower) for ip, names in by_ip.items()}


def _is_ip(value: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _netbox_ips(nb, ips: list[str]) -> dict[str, list[dict]]:
    """Host-IP -> IP-Objekte in Netbox; in Paketen abgefragt statt einer Anfrage je Eintrag."""
    import ipaddress
    out: dict[str, list[dict]] = {}
    for i in range(0, len(ips), 50):
        for m in nb.list("ipam/ip-addresses", address=ips[i:i + 50]):
            try:
                host = str(ipaddress.ip_address((m.get("address") or "").split("/")[0]))
            except ValueError:
                continue
            out.setdefault(host, []).append(m)
    return out


def netbox_mismatches(ctx: Context, data: AdData) -> list[dict]:
    """A/AAAA-Namen mit dem dns_name der IP-Adressen in Netbox vergleichen – je IP, nicht je Eintrag: eine IP
    hat in Netbox nur einen DNS-Namen. Liste von {fqdn, names, ip, netbox_id, current, state}; fqdn ist der
    vorzuschlagende Name, leer bei mehreren Kandidaten (dann nur Bericht, kein Vorschlag)."""
    names_by_ip = host_names(data)
    netbox = _netbox_ips(ctx.netbox, sorted(names_by_ip))
    out = []
    for ip in sorted(names_by_ip, key=_ip_key):
        names = names_by_ip[ip]
        single = names[0] if len(names) == 1 else ""
        hosts = netbox.get(ip, [])
        if not hosts:
            out.append({"fqdn": single, "names": names, "ip": ip, "netbox_id": None, "current": "",
                        "state": "nicht in Netbox"})
            continue
        for m in hosts:
            current = m.get("dns_name") or ""
            if current.rstrip(".").lower() in {n.lower() for n in names}:
                continue  # einer der AD-Namen ist bereits eingetragen
            state = "mehrdeutig" if not single else ("abweichend" if current else "leer")
            out.append({"fqdn": single, "names": names, "ip": ip, "netbox_id": m["id"], "current": current,
                        "state": state})
    return out


def _ip_key(ip: str):
    import ipaddress
    addr = ipaddress.ip_address(ip)
    return addr.version, int(addr)


def _sync_proposal(ctx: Context, mism: list[dict]) -> None:
    """Je abweichender IP eine einzeln freigebbare Änderung des dns_name (nur mit Freigabe)."""
    changes = []
    for m in mism:
        if not m["netbox_id"] or not m["fqdn"]:
            continue
        key = f"dns:{m['netbox_id']}"  # je Netbox-Objekt: dieselbe IP kann es in mehreren VRFs geben
        changes.append({
            "key": key, "category": "network", "label": f"DNS-Name von {m['ip']}",
            "before": m["current"] or "–", "after": m["fqdn"],
            "steps": [{"action": "update", "endpoint": "ipam/ip-addresses", "id": m["netbox_id"],
                       "data": {"dns_name": m["fqdn"]}, "note": f"DNS-Name {m['fqdn']} aus AD-DNS"}],
            "requires": [], "check": {"endpoint": "ipam/ip-addresses", "id": m["netbox_id"], "field": "dns_name",
                                      "value": m["current"]},
        })
    dedup = "dns-netbox"
    if not changes:
        ctx.store.close_pending(dedup, "Keine Abweichung mehr – Vorschlag erledigt.")
        return
    summary = (f"{len(changes)} IP-Adressen mit abweichendem oder fehlendem DNS-Namen.\n\n"
               + markdown.table(["IP", "DNS-Name (Netbox)", "DNS-Name (AD)"],
                                [[m["ip"], m["current"] or "–", m["fqdn"]] for m in mism
                                 if m["netbox_id"] and m["fqdn"]]))
    ctx.store.add_proposal(
        "netbox_plan", f"Netbox: DNS-Namen aus AD-DNS ({len(changes)} IP-Adressen)",
        {"changes": changes, "hints": ["Die DNS-Namen stammen aus dem AD-DNS; jede Zeile ist einzeln übernehmbar."],
         "target": {"name": "DNS-Namen"}}, summary=summary, source="addns", dedup_key=dedup)


def netbox_page(ctx: Context, data: AdData) -> int | None:
    """Bericht der Abweichungen zu Netbox plus Vorschlag für die DNS-Namen."""
    mism = netbox_mismatches(ctx, data)
    _sync_proposal(ctx, [m for m in mism if m["netbox_id"]])
    report = [[m["fqdn"] or ", ".join(m["names"]), m["ip"], m["current"] or "–", m["state"]] for m in mism]
    return propose_page(ctx, PageDraft(
        doc_type="addns_index", title="DNS-Abgleich mit Netbox",
        description="Abweichungen zwischen AD-DNS und Netbox",
        blocks=[Block("dns-netbox", "Abweichungen", markdown.table(
            ["DNS-Name", "IP", "DNS-Name in Netbox", "Status"], report) if report else "_Keine Abweichungen._")],
        target_path=(ctx.cfg.wiki.paths.get("addns_index") or "netzwerk/dns") + "/netbox-abgleich",
        intro="A- und AAAA-Einträge aus dem AD-DNS im Vergleich zu den IP-Adressen in Netbox. Für IPs mit mehreren "
              "Namen im AD (Status *mehrdeutig*) gibt es keinen Änderungsvorschlag – der richtige Name ist dort "
              "selbst einzutragen.",
        source="addns", stable_id="addns:netbox"))


def document_dns(ctx: Context, data: AdData) -> list[int | None]:
    if not data.dns_zones:
        ctx.log.info("Keine AD-integrierten DNS-Zonen gefunden – DNS übersprungen")
        return []
    results = [index_page(ctx, data)]
    for zone in data.dns_zones:
        results.append(zone_page(ctx, data, zone))
    if ctx.cfg.ad.dns_netbox_sync and ctx.cfg.netbox.enabled:
        try:
            results.append(netbox_page(ctx, data))
        except Exception as exc:  # Netbox-Abgleich darf die DNS-Doku nicht scheitern lassen
            ctx.log.warning("DNS-Abgleich mit Netbox nicht möglich: %s", exc)
    return results


class ZoneGone(LookupError):
    pass


def refresh(ctx: Context, stable_id: str) -> int | None:
    """Genau eine DNS-Seite neu berechnen (Wiki-Lint): eine Zone lädt nur ihre eigenen Einträge.
    ZoneGone, wenn es die Quelle der Seite nicht mehr gibt."""
    from doku_agent.generators.ad_common import fetch
    if stable_id.startswith("addns:zone:"):
        name = stable_id.split(":", 2)[2]
        zone = next((z for z in ctx.ad.dns_zones() if z.str("name").lower() == name.lower()), None)
        if zone is None:
            raise ZoneGone(f"DNS-Zone {name} gibt es im Active Directory nicht mehr")
        base = (zone.raw("_base") or b"").decode() or ctx.ad.base
        data = AdData()
        data.dns_records = {zone.str("name"): ctx.ad.dns_records(f"DC={zone.str('name')},{base}")}
        return zone_page(ctx, data, zone)
    if stable_id == "addns:netbox" and not (ctx.cfg.ad.dns_netbox_sync and ctx.cfg.netbox.enabled):
        raise ZoneGone("Netbox-Abgleich für DNS ist abgeschaltet")
    data, errors = fetch(ctx, {"base", "dns"})
    if errors:
        raise RuntimeError("; ".join(errors.values()))
    return netbox_page(ctx, data) if stable_id == "addns:netbox" else index_page(ctx, data)
