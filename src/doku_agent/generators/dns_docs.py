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
    nodes = data.dns_records.get(name, [])
    stale_before = datetime.now(timezone.utc) - timedelta(days=ctx.cfg.ad.dns_stale_days)
    rows, counts, stale = [], {}, 0
    for node in sorted(nodes, key=lambda n: n.str("name").lower()):
        host = node.str("name")
        for rec in sorted(_records(node), key=lambda r: (RECORD_ORDER.index(r.type) if r.type in RECORD_ORDER else 9)):
            counts[rec.type] = counts.get(rec.type, 0) + 1
            if rec.static:
                age = "statisch"
            elif rec.stamp and rec.stamp < stale_before:
                age = f"{rec.stamp.strftime('%Y-%m-%d')} (veraltet)"
                stale += 1
            else:
                age = rec.stamp.strftime("%Y-%m-%d") if rec.stamp else "dynamisch"
            rows.append([_fqdn(host, name), rec.type, rec.value, age])
    info = markdown.table(["Eigenschaft", "Wert"], [
        ["Zone", name], ["Art", props.get("zone_type", "–")],
        ["Dynamische Updates", props.get("allow_update", "–")],
        ["Alterung (Scavenging)", "ein" if props.get("aging") else "aus"],
        ["Einträge", str(len(rows))],
        ["Veraltete dynamische Einträge", f"{stale} (seit über {ctx.cfg.ad.dns_stale_days} Tagen)" if stale else "0"],
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

def netbox_mismatches(ctx: Context, data: AdData) -> list[dict]:
    """A/AAAA-Einträge mit der dns_name-Angabe in Netbox vergleichen. Liste von
    {fqdn, ip, netbox_id, current, state}."""
    nb = ctx.netbox
    out = []
    for zone in data.dns_zones:
        name = zone.str("name")
        if name.endswith(".in-addr.arpa") or name.endswith(".ip6.arpa"):
            continue  # Reverse-Zonen haben keine Host-IPs
        for node in data.dns_records.get(name, []):
            fqdn = _fqdn(node.str("name"), name)
            for rec in _records(node):
                if rec.type not in ("A", "AAAA"):
                    continue
                matches = nb.list("ipam/ip-addresses", address=rec.value)
                hosts = [m for m in matches if (m.get("address") or "").split("/")[0] == rec.value]
                if not hosts:
                    out.append({"fqdn": fqdn, "ip": rec.value, "netbox_id": None, "current": "", "state": "nicht in Netbox"})
                    continue
                for m in hosts:
                    current = m.get("dns_name") or ""
                    if current.lower() != fqdn.lower():
                        out.append({"fqdn": fqdn, "ip": rec.value, "netbox_id": m["id"], "current": current,
                                    "state": "abweichend" if current else "leer"})
    return out


def _sync_proposal(ctx: Context, mism: list[dict]) -> None:
    """Je abweichender IP eine einzeln freigebbare Änderung des dns_name (nur mit Freigabe)."""
    changes = []
    for m in mism:
        if not m["netbox_id"]:
            continue
        key = f"dns:{m['ip']}"
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
                                [[m["ip"], m["current"] or "–", m["fqdn"]] for m in mism if m["netbox_id"]]))
    ctx.store.add_proposal(
        "netbox_plan", f"Netbox: DNS-Namen aus AD-DNS ({len(changes)} IP-Adressen)",
        {"changes": changes, "hints": ["Die DNS-Namen stammen aus dem AD-DNS; jede Zeile ist einzeln übernehmbar."],
         "target": {"name": "DNS-Namen"}}, summary=summary, source="addns", dedup_key=dedup)


def netbox_page(ctx: Context, data: AdData) -> int | None:
    """Bericht der Abweichungen zu Netbox plus Vorschlag für die DNS-Namen."""
    mism = netbox_mismatches(ctx, data)
    _sync_proposal(ctx, [m for m in mism if m["netbox_id"]])
    report = [[m["fqdn"], m["ip"], m["current"] or "–", m["state"]] for m in mism]
    return propose_page(ctx, PageDraft(
        doc_type="addns_index", title="DNS-Abgleich mit Netbox",
        description="Abweichungen zwischen AD-DNS und Netbox",
        blocks=[Block("dns-netbox", "Abweichungen", markdown.table(
            ["DNS-Name", "IP", "DNS-Name in Netbox", "Status"], report) if report else "_Keine Abweichungen._")],
        target_path=(ctx.cfg.wiki.paths.get("addns_index") or "netzwerk/dns") + "/netbox-abgleich",
        intro="A- und AAAA-Einträge aus dem AD-DNS im Vergleich zu den IP-Adressen in Netbox.",
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
