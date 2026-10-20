"""Netbox: Steckbrief-Seite pro Gerät bzw. VM (deterministisch, ohne LLM – Netbox ist die Quelle)."""

from __future__ import annotations

from doku_agent import markdown
from doku_agent.context import Context
from doku_agent.pages import Block, PageDraft, propose_page


def _n(obj: dict | None, key: str = "name") -> str:
    return (obj or {}).get(key) or ""


def _mac(iface: dict) -> str:
    mac = iface.get("mac_address")
    if isinstance(mac, str) and mac:
        return mac
    return _n(iface.get("primary_mac_address"), "mac_address")


def document_object(ctx: Context, kind: str, obj_id: int) -> int | None:
    nb = ctx.netbox
    if kind == "vm":
        endpoint, if_endpoint, if_filter, ip_filter = ("virtualization/virtual-machines", "virtualization/interfaces",
                                                       "virtual_machine_id", "virtual_machine_id")
    else:
        endpoint, if_endpoint, if_filter, ip_filter = "dcim/devices", "dcim/interfaces", "device_id", "device_id"
    obj = nb.get(endpoint, obj_id)
    interfaces = nb.list(if_endpoint, **{if_filter: obj_id})
    ips = nb.list("ipam/ip-addresses", **{ip_filter: obj_id})
    ips_by_iface: dict[int, list[str]] = {}
    for ip in ips:
        ips_by_iface.setdefault(ip.get("assigned_object_id"), []).append(ip.get("address", ""))

    name = obj.get("name") or f"{kind}-{obj_id}"
    rows = [
        ["Name", name],
        ["Art", "Virtuelle Maschine" if kind == "vm" else "Gerät"],
        ["Status", _n(obj.get("status"), "label")],
        ["Rolle", _n(obj.get("role"))],
        ["Standort", _n(obj.get("site"))],
    ]
    if kind == "vm":
        rows += [["Cluster", _n(obj.get("cluster"))], ["vCPUs", obj.get("vcpus") or ""],
                 ["Arbeitsspeicher (MB)", obj.get("memory") or ""], ["Disk (MB)", obj.get("disk") or ""]]
    else:
        dtype = obj.get("device_type") or {}
        position = f"{_n(obj.get('rack'))} / U{obj.get('position')}" if obj.get("rack") and obj.get("position") else _n(obj.get("rack"))
        rows += [["Raum/Location", _n(obj.get("location"))], ["Rack / Position", position],
                 ["Hersteller", _n(dtype.get("manufacturer"))], ["Modell", dtype.get("model", "")],
                 ["Asset-Tag", obj.get("asset_tag") or ""]]
    cf, values = ctx.cfg.netbox.custom_fields, obj.get("custom_fields") or {}
    # Kennungen ja, "zuletzt gesehen" nicht: das ändert sich täglich und würde jede Nacht einen Vorschlag erzeugen
    for field, label in ((cf.wazuh_agent_id, "Wazuh-Agent-ID"), (cf.intune_device_id, "Intune-Geräte-ID")):
        if cf.enabled and values.get(field):
            rows.append([label, values[field]])
    rows += [
        ["Seriennummer", obj.get("serial") or ""],
        ["Plattform", _n(obj.get("platform"))],
        ["Primäre IP", _n(obj.get("primary_ip"), "address")],
        ["Mandant", _n(obj.get("tenant"))],
        ["Beschreibung", obj.get("description") or ""],
        ["Netbox", f"[{endpoint}/{obj_id}]({nb.ui_url(endpoint, obj_id)})"],
    ]
    if_rows = [[i.get("name"), _n(i.get("type"), "label"), _mac(i),
                ", ".join(ips_by_iface.get(i.get("id"), [])), i.get("description") or ""] for i in interfaces]
    blocks = [
        Block("netbox-device", "Steckbrief", markdown.table(["Eigenschaft", "Wert"], rows)),
        Block("netbox-interfaces", "Netzwerk",
              markdown.table(["Interface", "Typ", "MAC", "IP-Adressen", "Beschreibung"], if_rows)
              if if_rows else "_Keine Interfaces in Netbox._"),
    ]
    if obj.get("comments"):
        blocks.append(Block("netbox-comments", "Kommentare aus Netbox", obj["comments"]))
    return propose_page(ctx, PageDraft(
        doc_type="netbox_device", title=name, description=f"Steckbrief {name} ({_n(obj.get('role')) or kind})",
        blocks=blocks, path_vars={"name": name, "site": _n(obj.get("site"), "slug"), "role": _n(obj.get("role"), "slug")},
        intro=f"Steckbrief von **{name}**. Die markierten Abschnitte werden automatisch aus Netbox aktualisiert – "
              f"eigene Ergänzungen bitte außerhalb davon.",
        lookup_name=name, source=f"netbox:{kind}:{obj_id}", stable_id=f"netbox:{kind}:{obj_id}", sync_title=True,
    ))


def document_all(ctx: Context, site: str = "", role: str = "") -> list[int | None]:
    filters = {k: v for k, v in (("site", site), ("role", role)) if v}
    results = []
    for kind, endpoint in (("device", "dcim/devices"), ("vm", "virtualization/virtual-machines")):
        for obj in ctx.netbox.list(endpoint, **filters):
            results.append(document_object(ctx, kind, obj["id"]))
    return results
