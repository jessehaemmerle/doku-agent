"""Abdeckungsbericht: Welche Maschinen haben keinen Wazuh-Agent, welche Clients fehlen in Intune,
was fehlt in Netbox und wer hat sich seit Wochen nicht gemeldet.

Grundlage sind dieselben, zusammengeführten Daten wie bei der Discovery (Wazuh, vCenter, Intune)
und der Netbox-Index. Der Bericht ist eine Wiki-Seite (Vorschlag) ohne Datum – sie ändert sich nur,
wenn sich die Befunde ändern.
"""

from __future__ import annotations

from datetime import date, timedelta

from doku_agent import markdown, netbox_fields
from doku_agent.context import Context
from doku_agent.discovery import Asset, NetboxIndex
from doku_agent.pages import Block, PageDraft, propose_page

DEVICE = "dcim/devices"


def _slug(value) -> str:
    return (value.get("slug") or "") if isinstance(value, dict) else ""


def build_report(ctx: Context, assets: list[Asset], index: NetboxIndex) -> dict[str, list[list]]:
    cfg = ctx.cfg.coverage
    tz = ctx.cfg.general.timezone
    by_object: dict[tuple[str, int], list[Asset]] = {}
    report: dict[str, list[list]] = {"no_wazuh": [], "no_intune": [], "not_in_netbox": [], "stale": []}
    pending = ctx.store.pending_dedup_keys()
    for asset in assets:
        if not asset.name:
            continue
        found = index.find(asset)
        if found:
            by_object.setdefault(found[:2], []).append(asset)
            continue
        dedup = f"netbox:{asset.key}"
        if ctx.store.is_ignored(dedup):
            state = "ignoriert"
        elif dedup in pending:
            state = "Vorschlag offen"
        else:
            state = "–"
        report["not_in_netbox"].append([asset.name, ", ".join(sorted(asset.sources)), asset.serial or "–", state])

    last_seen_field = ctx.cfg.netbox.custom_fields.last_seen
    threshold = (date.today() - timedelta(days=cfg.stale_days)).isoformat()
    for key, obj in sorted(index.objects.items(), key=lambda kv: (kv[1].get("name") or "").lower()):
        name = obj.get("name") or f"#{key[1]}"
        role = _slug(obj.get("role"))
        kind = "Gerät" if key[0] == DEVICE else "VM"
        matched = by_object.get(key, [])
        sources = set().union(*(a.sources.keys() for a in matched)) if matched else set()
        if role in cfg.wazuh_roles and "wazuh" not in sources:
            report["no_wazuh"].append([name, kind, role, ", ".join(sorted(sources)) or "keine Quelle"])
        if role in cfg.intune_roles and "intune" not in sources:
            report["no_intune"].append([name, kind, role, ", ".join(sorted(sources)) or "keine Quelle"])
        seen = str((obj.get("custom_fields") or {}).get(last_seen_field) or "")
        if not seen and matched:
            seen = max((netbox_fields.last_seen(a.sources, tz) or "" for a in matched), default="")
        if seen and seen < threshold:
            power = next(((a.sources.get("vcenter") or {}).get("power_state") for a in matched
                          if (a.sources.get("vcenter") or {}).get("power_state")), "")
            note = "VM ausgeschaltet" if power and power != "POWERED_ON" else ""
            report["stale"].append([name, kind, role or "–", seen, note])
    for rows in report.values():
        rows.sort(key=lambda r: str(r[0]).lower())
    return report


def propose_coverage(ctx: Context, assets: list[Asset], index: NetboxIndex) -> int | None:
    report = build_report(ctx, assets, index)
    cfg = ctx.cfg.coverage
    sections = [
        ("cov-no-wazuh", "Ohne Wazuh-Agent", "no_wazuh", ["Maschine", "Art", "Rolle", "Gemeldet von"],
         f"Netbox-Rollen {', '.join(cfg.wazuh_roles)} sollten einen Wazuh-Agent haben."),
        ("cov-no-intune", "Ohne Intune", "no_intune", ["Maschine", "Art", "Rolle", "Gemeldet von"],
         f"Netbox-Rollen {', '.join(cfg.intune_roles)} sollten in Intune verwaltet sein."),
        ("cov-not-in-netbox", "Nicht in Netbox", "not_in_netbox", ["Maschine", "Quellen", "Seriennummer", "Status"],
         "Von Wazuh, vCenter oder Intune gemeldet, aber in Netbox nicht gefunden."),
        ("cov-stale", "Funkstille", "stale", ["Maschine", "Art", "Rolle", "Zuletzt gesehen", "Hinweis"],
         f"Letzter Kontakt laut Wazuh/Intune älter als {cfg.stale_days} Tage."),
    ]
    summary = markdown.table(["Prüfung", "Befunde"], [[title, len(report[key])] for _, title, key, _, _ in sections])
    blocks = [Block("cov-summary", "Zusammenfassung", summary)]
    for block_id, title, key, headers, note in sections:
        rows = report[key]
        blocks.append(Block(block_id, title, f"{note}\n\n" + (markdown.table(headers, rows) if rows else "_Keine._")))
    return propose_page(ctx, PageDraft(
        doc_type="coverage", title="Abdeckung: Wazuh, Intune, Netbox", description="Abdeckungsbericht der Discovery",
        blocks=blocks, target_path=ctx.cfg.wiki.paths.get("coverage") or "infrastruktur/abdeckung",
        intro="Automatischer Abgleich zwischen Netbox, Wazuh, vCenter und Intune nach jeder Discovery.",
        source="coverage", stable_id="coverage:report",
    ))
