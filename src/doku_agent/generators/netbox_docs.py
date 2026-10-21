"""Netbox: Steckbrief-Seite pro Gerät bzw. VM. Tabellen kommen deterministisch aus Netbox; darüber
steht ein Überblick in Fließtext, den das LLM aus genau diesen Angaben schreibt (mit Faktenprüfung)."""

from __future__ import annotations

from doku_agent import markdown
from doku_agent.context import Context
from doku_agent.generators import narrative
from doku_agent.pages import Block, PageDraft, propose_page


def _n(obj: dict | str | None, key: str = "name") -> str:
    if isinstance(obj, str):  # schon aufgelöster Wert
        return obj
    return (obj or {}).get(key) or ""


def _mac(iface: dict) -> str:
    mac = iface.get("mac_address")
    if isinstance(mac, str) and mac:
        return mac
    return _n(iface.get("primary_mac_address"), "mac_address")


def _size(mb, label: str) -> str:
    """Speicher in MB auch in GB angeben, damit der Text nicht umrechnen muss (RAM in 1024er-, Disks wie
    in Netbox und vCenter in 1000er-Schritten)."""
    try:
        value = int(mb)
    except (TypeError, ValueError):
        return ""
    gb = value / (1024 if label == "RAM" else 1000)
    if gb < 1:
        return f"{value} MB"
    shown = f"{gb:.1f}".rstrip("0").rstrip(".") if gb < 10 else str(round(gb))
    return f"{value} MB ({shown} GB)"


def overview(ctx: Context, name: str, kind: str, obj: dict, rows: list[list], interfaces: list[dict],
             ips_by_iface: dict, fw_rows: list[list] | None) -> str | None:
    """Fließtext-Überblick aus denselben Angaben wie die Tabellen darunter."""
    facts = [(label, value) for label, value in rows if label not in ("Netbox", "Wazuh-Agent-ID", "Intune-Geräte-ID")]
    if kind == "vm":
        facts = [(lbl, _size(obj.get("memory"), "RAM") if lbl.startswith("Arbeitsspeicher") else
                  _size(obj.get("disk"), "Disk") if lbl.startswith("Disk") else val) for lbl, val in facts]
    for i in interfaces:
        peers = ", ".join(f"{_n(p.get('device'))} {p.get('name', '')}".strip() for p in i.get("link_peers") or [])
        facts.append((f"Interface {i.get('name')}", "; ".join(filter(None, [
            _n(i.get("type"), "label"), ", ".join(ips_by_iface.get(i.get("id"), [])),
            f"verbunden mit {peers}" if peers else "", i.get("description") or ""]))))
    if fw_rows:
        facts.append(("Firewall-Regeln, die die Maschine gezielt betreffen", len(fw_rows)))
        facts += [(f"Regel {r[1]} auf {r[0]}", f"{r[2]}, Gegenseite {r[3]}, Dienst {r[4]}, Aktion {r[5]}".replace("<br>", ", "))
                  for r in fw_rows[:25]]
    if obj.get("comments"):
        facts.append(("Kommentare", obj["comments"][:800]))
    role = _n(obj.get("role"))
    fallback = f"**{name}** ist {'eine virtuelle Maschine' if kind == 'vm' else 'ein Gerät'}" + (
        f" mit der Rolle {role}" if role else "") + (f" am Standort {_n(obj.get('site'))}" if obj.get("site") else "") + "." + (
        f" Plattform: {_n(obj.get('platform'))}." if obj.get("platform") else "") + (
        f" Primäre IP: {_n(obj.get('primary_ip'), 'address')}." if obj.get("primary_ip") else "") + (
        f" Netzwerk: {len(interfaces)} Interface(s)." if interfaces else "")
    return narrative.narrate(
        ctx, f"steckbrief:{kind}:{obj.get('id')}", expert="IT-Infrastruktur und Netbox",
        task=f"Beschreibe die Maschine {name} für ihren Steckbrief im Wiki: was sie ist und wofür sie (laut Rolle, "
             "Plattform und Beschreibung) vermutlich dient, wo sie steht bzw. läuft, wie sie ans Netz angebunden ist "
             "und welche Firewall-Regeln sie betreffen. Spekuliere nicht über Dienste, die nicht in den Daten stehen.",
        facts=narrative.fact_lines(facts), fallback=fallback)


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
    headers = ["Interface", "Typ", "MAC", "IP-Adressen", "Beschreibung"]
    if any(i.get("link_peers") for i in interfaces):  # Spalte nur, wenn verkabelt (sonst keine Schein-Änderung)
        headers.append("Verbunden mit")
        for row, i in zip(if_rows, interfaces):
            row.append(", ".join(f"{_n(p.get('device'))} {p.get('name', '')}".strip()
                                 for p in i.get("link_peers") or []))
    blocks = [
        Block("netbox-device", "Steckbrief", markdown.table(["Eigenschaft", "Wert"], rows)),
        Block("netbox-interfaces", "Netzwerk", markdown.table(headers, if_rows) if if_rows
              else "_Keine Interfaces in Netbox._"),
    ]
    fw = ctx.cfg.fortigate
    fw_rows = None
    if fw.enabled and fw.steckbrief_rules and fw.devices:
        from doku_agent.generators.fortigate_docs import rules_for_machine
        hosts = [(ip.get("address") or "").split("/")[0] for ip in ips]
        fw_rows = rules_for_machine(ctx, hosts) if hosts else []
        if fw_rows is not None:  # Firewall nicht lesbar: bestehenden Abschnitt unverändert lassen
            blocks.append(Block("netbox-firewall", "Firewall-Regeln", markdown.table(
                ["Firewall", "Regel", "Richtung", "Gegenseite", "Dienst", "Aktion", "Über Objekt"], fw_rows)
                if fw_rows else "_Keine Firewall-Regel betrifft diese Maschine gezielt (nur über große Netze oder "
                                "'beliebig')._"))
    fw_unreadable = fw_rows is None and fw.enabled and fw.steckbrief_rules and bool(fw.devices)
    if narrative.enabled(ctx, "steckbrief") and not fw_unreadable:
        # Ohne lesbare Firewall bliebe der Überblick unvollständig -> dann bestehenden Text nicht ändern
        text = overview(ctx, name, kind, obj, rows, interfaces, ips_by_iface, fw_rows)
        if text is not None:  # Sprachmodell nicht erreichbar: bestehenden Überblick unverändert lassen
            blocks.insert(0, Block("netbox-summary", "Überblick", text))
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
