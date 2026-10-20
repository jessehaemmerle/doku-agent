"""Netbox-Auto-Discovery: Maschinen aus Intune und Wazuh finden, die in Netbox fehlen.

Ablauf: Inventar sammeln -> Quellen zusammenführen (Seriennummer, Hostname, MAC) ->
gegen Netbox abgleichen -> für jede fehlende Maschine einen Netbox-Plan zur Freigabe.
"""

from __future__ import annotations

import ipaddress
import re
import time
from dataclasses import dataclass, field
from datetime import date

from doku_agent import markdown, netbox_fields
from doku_agent.config import NetboxConfig, NetboxCustomFields
from doku_agent.connectors.netbox import NetboxClient
from doku_agent.context import Context
from doku_agent.conventions import slugify

JUNK_SERIALS = {
    "", "0", "none", "null", "n/a", "na", "unknown", "default string", "to be filled by o.e.m.",
    "system serial number", "not specified", "not applicable", "0123456789", "chassis serial number",
    "serial", "invalid", "not available",
}
SKIP_IFACES = re.compile(r"^(lo\d*|docker\d*|veth.*|br-.*|virbr.*|vmnet.*|tun\d*|tap.*|cali.*|flannel.*|cni.*"
                         r"|kube.*|wg\d*|isatap.*|teredo.*|loopback.*)$", re.I)


class DiscoveryError(RuntimeError):
    pass


def netbox_slug(text: str) -> str:
    """Netbox-Slug: nur Buchstaben, Ziffern, '-' und '_', höchstens 100 Zeichen (Punkte sind nicht erlaubt)."""
    return slugify(text).replace(".", "-").strip("-")[:100].strip("-") or "unbekannt"


def norm_serial(serial: str | None) -> str:
    s = (serial or "").strip()
    return "" if s.lower() in JUNK_SERIALS else s


def norm_mac(mac: str | None) -> str:
    hexes = re.sub(r"[^0-9a-fA-F]", "", mac or "")
    if len(hexes) != 12 or hexes == "0" * 12:
        return ""
    return ":".join(hexes[i:i + 2] for i in range(0, 12, 2)).upper()


def short_name(name: str | None) -> str:
    return (name or "").strip().split(".")[0]


def prefix_len(netmask: str, version: int) -> int | None:
    try:
        if not netmask:
            return 32 if version == 4 else 128
        if netmask.isdigit():
            return int(netmask)
        addr = ipaddress.ip_address(netmask)
        return bin(int(addr)).count("1")
    except ValueError:
        return None


def usable_ip(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address.split("%")[0])
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast)


@dataclass
class Iface:
    name: str
    mac: str = ""
    ips: list[str] = field(default_factory=list)  # CIDR-Notation
    # False: MAC taugt nicht zur Wiedererkennung (Intune-Ethernet-MAC gehört oft der Docking-Station).
    identifies: bool = True


@dataclass
class Asset:
    name: str
    serial: str = ""
    manufacturer: str = ""
    model: str = ""
    os_name: str = ""
    os_version: str = ""
    cpu_cores: int | None = None
    memory_mb: int | None = None
    primary_ip: str = ""
    interfaces: list[Iface] = field(default_factory=list)
    sources: dict[str, dict] = field(default_factory=dict)
    is_virtual: bool = False

    @property
    def key(self) -> str:
        return f"serial:{self.serial.upper()}" if self.serial else f"name:{self.name.lower()}"

    @property
    def macs(self) -> set[str]:
        return {i.mac for i in self.interfaces if i.mac}

    @property
    def identifying_macs(self) -> set[str]:
        return {i.mac for i in self.interfaces if i.mac and i.identifies}

    def merge(self, other: "Asset") -> None:
        for attr in ("serial", "manufacturer", "model", "os_name", "os_version", "primary_ip"):
            if not getattr(self, attr) and getattr(other, attr):
                setattr(self, attr, getattr(other, attr))
        self.cpu_cores = self.cpu_cores or other.cpu_cores
        self.memory_mb = self.memory_mb or other.memory_mb
        self.is_virtual = self.is_virtual or other.is_virtual
        self.sources.update(other.sources)
        by_mac = {i.mac: i for i in self.interfaces if i.mac}
        for iface in other.interfaces:
            mine = by_mac.get(iface.mac) if iface.mac else None
            if mine:
                mine.ips = list(dict.fromkeys([*mine.ips, *iface.ips]))
            elif not any(i.name == iface.name for i in self.interfaces):
                self.interfaces.append(iface)


# --- Inventar sammeln ------------------------------------------------------

def wazuh_assets(ctx: Context) -> list[Asset]:
    wz = ctx.wazuh
    assets = []
    for agent in wz.agents():
        if agent.get("status") == "never_connected":
            continue
        aid = agent["id"]
        try:
            hw, osinfo = wz.hardware(aid), wz.os_info(aid)
            nics, addrs = wz.interfaces(aid), wz.addresses(aid)
        except Exception as exc:  # einzelner Agent ohne Syscollector-Daten
            ctx.log.warning("Wazuh-Agent %s (%s): kein Inventar (%s)", aid, agent.get("name"), exc)
            continue
        ifaces = []
        for nic in nics:
            name = nic.get("name") or ""
            mac = norm_mac(nic.get("mac"))
            if SKIP_IFACES.match(name) or not mac:
                continue
            ips = []
            for a in addrs:
                if a.get("iface") != name or not usable_ip(a.get("address", "")):
                    continue
                version = 6 if a.get("proto") == "ipv6" else 4
                plen = prefix_len(a.get("netmask", ""), version)
                if plen is not None:
                    ips.append(f"{a['address'].split('%')[0]}/{plen}")
            ifaces.append(Iface(name=name, mac=mac, ips=ips))
        os_block = osinfo.get("os", {}) or {}
        ram_kb = (hw.get("ram") or {}).get("total")
        assets.append(Asset(
            name=short_name(osinfo.get("hostname") or agent.get("name")),
            serial=norm_serial(hw.get("board_serial")),
            os_name=os_block.get("name") or (agent.get("os") or {}).get("name", ""),
            os_version=os_block.get("version") or "",
            cpu_cores=(hw.get("cpu") or {}).get("cores"),
            memory_mb=int(ram_kb) // 1024 if ram_kb else None,
            primary_ip=agent.get("ip") if usable_ip(agent.get("ip") or "") else "",
            interfaces=ifaces,
            sources={"wazuh": {"agent_id": aid, "agent_name": agent.get("name"), "status": agent.get("status"),
                               "version": agent.get("version"), "groups": agent.get("group") or [],
                               "last_seen": agent.get("lastKeepAlive")}},
        ))
    return assets


def intune_assets(ctx: Context) -> list[Asset]:
    allowed_os = {o.lower() for o in ctx.cfg.intune.discovery_os}
    assets = []
    for dev in ctx.intune.managed_devices():
        os_name = dev.get("operatingSystem") or ""
        if allowed_os and os_name.lower() not in allowed_os:
            continue
        ifaces = []
        if norm_mac(dev.get("wiFiMacAddress")):
            ifaces.append(Iface(name="WLAN", mac=norm_mac(dev.get("wiFiMacAddress"))))
        assets.append(Asset(
            name=short_name(dev.get("deviceName")),
            serial=norm_serial(dev.get("serialNumber")),
            manufacturer=(dev.get("manufacturer") or "").strip(),
            model=(dev.get("model") or "").strip(),
            os_name=os_name,
            os_version=dev.get("osVersion") or "",
            interfaces=ifaces,
            sources={"intune": {"id": dev.get("id"), "user": dev.get("userPrincipalName"),
                                "last_sync": dev.get("lastSyncDateTime"), "compliance": dev.get("complianceState"),
                                "owner": dev.get("managedDeviceOwnerType")}},
        ))
    return assets


def merge_assets(assets: list[Asset]) -> list[Asset]:
    merged: list[Asset] = []
    by_serial: dict[str, Asset] = {}
    by_name: dict[str, Asset] = {}
    by_mac: dict[str, Asset] = {}
    for asset in assets:
        target = (by_serial.get(asset.serial.upper()) if asset.serial else None) \
            or by_name.get(asset.name.lower()) \
            or next((by_mac[m] for m in asset.identifying_macs if m in by_mac), None)
        if target is None:
            merged.append(asset)
            target = asset
        else:
            target.merge(asset)
        if target.serial:
            by_serial[target.serial.upper()] = target
        if target.name:
            by_name[target.name.lower()] = target
        for mac in target.identifying_macs:
            by_mac[mac] = target
    return merged


def detect_virtual(asset: Asset, cfg: NetboxConfig) -> bool:
    if asset.is_virtual:
        return True
    serial_hit = any(re.search(p, asset.serial) for p in cfg.vm_serial_patterns) if asset.serial else False
    model_hit = any(re.search(p, f"{asset.manufacturer} {asset.model}") for p in cfg.vm_model_patterns)
    return serial_hit or model_hit


# --- Abgleich mit Netbox ---------------------------------------------------

class NetboxIndex:
    """Alle Geräte und VMs aus Netbox, indiziert nach Wazuh-/Intune-ID (Custom Fields),
    Seriennummer, Name und MAC."""

    def __init__(self, nb: NetboxClient, cf: NetboxCustomFields | None = None):
        self.objects: dict[tuple[str, int], dict] = {}
        self.serials: dict[str, tuple[str, int]] = {}
        self.names: dict[str, tuple[str, int]] = {}
        self.macs: dict[str, tuple[str, int]] = {}
        self.orphan_macs: set[str] = set()  # MAC-Objekte ohne Gerät/VM
        self.fields = netbox_fields.status(nb, cf) if cf else netbox_fields.FieldStatus()
        self.cf = cf
        self.wazuh_ids: dict[str, tuple[str, int]] = {}
        self.intune_ids: dict[str, tuple[str, int]] = {}
        for endpoint in ("dcim/devices", "virtualization/virtual-machines"):
            for obj in nb.list(endpoint):
                key = (endpoint, obj["id"])
                self.objects[key] = obj
                values = obj.get("custom_fields") or {}
                if cf and values.get(cf.wazuh_agent_id):
                    self.wazuh_ids[str(values[cf.wazuh_agent_id])] = key
                if cf and values.get(cf.intune_device_id):
                    self.intune_ids[str(values[cf.intune_device_id])] = key
                if norm_serial(obj.get("serial")):
                    self.serials[obj["serial"].strip().upper()] = key
                if obj.get("name"):
                    self.names[obj["name"].lower()] = key
                    self.names.setdefault(short_name(obj["name"]).lower(), key)
        if nb.has_mac_objects:
            for mac in nb.list("dcim/mac-addresses"):
                assigned = mac.get("assigned_object") or {}
                if assigned.get("device"):
                    self.macs[norm_mac(mac.get("mac_address"))] = ("dcim/devices", assigned["device"]["id"])
                elif assigned.get("virtual_machine"):
                    self.macs[norm_mac(mac.get("mac_address"))] = (
                        "virtualization/virtual-machines", assigned["virtual_machine"]["id"])
                else:
                    self.orphan_macs.add(norm_mac(mac.get("mac_address")))

    def find(self, asset: Asset) -> tuple[str, int, str] | None:
        """(Endpunkt, ID, Trefferart) – Trefferart: wazuh_id, intune_id, serial, name oder mac."""
        agent_id = str((asset.sources.get("wazuh") or {}).get("agent_id") or "")
        if agent_id in self.wazuh_ids:
            return (*self.wazuh_ids[agent_id], "wazuh_id")
        device_id = str((asset.sources.get("intune") or {}).get("id") or "")
        if device_id in self.intune_ids:
            return (*self.intune_ids[device_id], "intune_id")
        if asset.serial and asset.serial.upper() in self.serials:
            return (*self.serials[asset.serial.upper()], "serial")
        if asset.name.lower() in self.names:
            return (*self.names[asset.name.lower()], "name")
        for mac in sorted(asset.identifying_macs):
            if mac in self.macs:
                return (*self.macs[mac], "mac")
        return None

    def match(self, asset: Asset) -> str | None:
        found = self.find(asset)
        if found is None:
            return None
        endpoint, oid, how = found
        name = self.objects.get((endpoint, oid), {}).get("name") or f"#{oid}"
        return {"wazuh_id": "Wazuh-Agent-ID", "intune_id": "Intune-Geräte-ID", "serial": "Seriennummer",
                "name": "Hostname", "mac": "MAC"}[how] + f" → {name}"

    def name_taken(self, name: str, own: tuple[str, int]) -> bool:
        key = self.names.get(name.lower()) or self.names.get(short_name(name).lower())
        return key is not None and key != own


# --- Plan erzeugen ---------------------------------------------------------

def _role_for(asset: Asset, cfg: NetboxConfig) -> str:
    text = f"{asset.os_name} {asset.os_version}"
    for rule in cfg.roles:
        if re.search(rule.os, text):
            return rule.role
    return cfg.roles[-1].role if cfg.roles else "server"


def build_plan(asset: Asset, nb: NetboxClient, cfg: NetboxConfig, site_id: int,
               custom_fields: dict[str, dict] | None = None) -> tuple[list[dict], list[str]]:
    """custom_fields: Werte je Endpunkt (Gerät/VM), soweit die Felder in Netbox existieren."""
    steps: list[dict] = []
    hints: list[str] = []
    vm = detect_virtual(asset, cfg)
    sources = ", ".join(sorted(asset.sources))
    role = _role_for(asset, cfg)
    steps.append({"ref": "role", "action": "ensure", "endpoint": "dcim/device-roles", "lookup": {"slug": role},
                  "data": {"name": role.replace("-", " ").title(), "slug": role, "color": "9e9e9e", "vm_role": True},
                  "note": f"Rolle '{role}'"})
    if asset.os_name:
        pslug = netbox_slug(asset.os_name)
        steps.append({"ref": "platform", "action": "ensure", "endpoint": "dcim/platforms", "lookup": {"slug": pslug},
                      "data": {"name": asset.os_name, "slug": pslug}, "note": f"Plattform '{asset.os_name}'"})
    comments = [f"Automatisch erkannt am {date.today().isoformat()} über {sources}."]
    if asset.os_version:
        comments.append(f"OS-Version: {asset.os_version}")
    for src, info in asset.sources.items():
        comments.append(f"{src}: " + ", ".join(f"{k}={v}" for k, v in info.items() if v not in (None, "", [])))

    common = {"name": asset.name, "role": "$role", "site": site_id, "status": cfg.status,
              "description": f"Auto-Discovery ({sources})", "comments": "\n".join(comments)}
    if asset.serial:
        common["serial"] = asset.serial
    if asset.os_name:
        common["platform"] = "$platform"

    if custom_fields:
        endpoint = "virtualization/virtual-machines" if vm else "dcim/devices"
        if custom_fields.get(endpoint):
            common["custom_fields"] = dict(custom_fields[endpoint])

    if vm:
        data = {**common}
        if cfg.vm_cluster:
            data["cluster"] = cfg.vm_cluster
        if asset.cpu_cores:
            data["vcpus"] = asset.cpu_cores
        if asset.memory_mb:
            data["memory"] = asset.memory_mb
        steps.append({"ref": "dev", "action": "create", "endpoint": "virtualization/virtual-machines", "data": data,
                      "note": f"Virtuelle Maschine '{asset.name}'"})
        if_endpoint, if_parent, obj_type = "virtualization/interfaces", "virtual_machine", "virtualization.vminterface"
    else:
        manufacturer = asset.manufacturer or cfg.unknown_manufacturer
        model = asset.model or cfg.unknown_model
        mslug, tslug = netbox_slug(manufacturer), netbox_slug(model)
        steps.append({"ref": "mfr", "action": "ensure", "endpoint": "dcim/manufacturers", "lookup": {"slug": mslug},
                      "data": {"name": manufacturer, "slug": mslug}, "note": f"Hersteller '{manufacturer}'"})
        steps.append({"ref": "dtype", "action": "ensure", "endpoint": "dcim/device-types",
                      "lookup": {"manufacturer_id": "$mfr", "slug": tslug},
                      "data": {"manufacturer": "$mfr", "model": model, "slug": tslug}, "note": f"Gerätetyp '{model}'"})
        if not asset.model:
            hints.append("Modell unbekannt (Wazuh liefert keine Herstellerdaten) – bitte Gerätetyp prüfen.")
        steps.append({"ref": "dev", "action": "create", "endpoint": "dcim/devices",
                      "data": {**common, "device_type": "$dtype"}, "note": f"Gerät '{asset.name}'"})
        if_endpoint, if_parent, obj_type = "dcim/interfaces", "device", "dcim.interface"

    primary_ref = None
    ip_counter = 0
    for n, iface in enumerate(asset.interfaces):
        data = {if_parent: "$dev", "name": iface.name}
        if not vm:
            data["type"] = "other"
        if iface.mac and not nb.has_mac_objects:
            data["mac_address"] = iface.mac
        steps.append({"ref": f"if{n}", "action": "create", "endpoint": if_endpoint, "data": data,
                      "note": f"Interface {iface.name}"})
        if iface.mac and nb.has_mac_objects:
            steps.append({"ref": f"mac{n}", "action": "create", "endpoint": "dcim/mac-addresses",
                          "data": {"mac_address": iface.mac, "assigned_object_type": obj_type,
                                   "assigned_object_id": f"$if{n}"}, "note": f"MAC {iface.mac}"})
            steps.append({"action": "update", "endpoint": if_endpoint, "id": f"$if{n}",
                          "data": {"primary_mac_address": f"$mac{n}"}, "note": "Primäre MAC setzen"})
        if not cfg.assign_ips:
            continue
        for cidr in iface.ips:
            host = cidr.split("/")[0]
            existing = nb.find_one("ipam/ip-addresses", address=host)
            ref = f"ip{ip_counter}"
            ip_counter += 1
            assignment = {"assigned_object_type": obj_type, "assigned_object_id": f"$if{n}"}
            if existing and existing.get("assigned_object_id"):
                hints.append(f"IP {cidr} ist in Netbox bereits einem anderen Objekt zugewiesen – übersprungen.")
                continue
            if existing:
                steps.append({"ref": ref, "action": "update", "endpoint": "ipam/ip-addresses", "id": existing["id"],
                              "data": assignment, "note": f"Bestehende IP {existing.get('address')} zuweisen"})
                hints.append(f"IP {cidr} existiert bereits in Netbox (#{existing['id']}) und wird zugewiesen.")
            else:
                steps.append({"ref": ref, "action": "create", "endpoint": "ipam/ip-addresses",
                              "data": {"address": cidr, "status": "active", **assignment}, "note": f"IP {cidr}"})
            if primary_ref is None and ":" not in host and (not asset.primary_ip or host == asset.primary_ip):
                primary_ref = ref
    if cfg.set_primary_ip and primary_ref:
        steps.append({"action": "update", "endpoint": "virtualization/virtual-machines" if vm else "dcim/devices",
                      "id": "$dev", "data": {"primary_ip4": f"${primary_ref}"}, "note": "Primäre IPv4 setzen"})
    return steps, hints


def plan_summary(asset: Asset, vm: bool, steps: list[dict], match_hint: str = "") -> str:
    rows = [[asset.name, "VM" if vm else "Gerät", asset.serial, f"{asset.manufacturer} {asset.model}".strip(),
             f"{asset.os_name} {asset.os_version}".strip(), ", ".join(sorted(asset.sources))]]
    text = f"{'VM' if vm else 'Gerät'} {asset.name} aus {', '.join(sorted(asset.sources))}, {len(steps)} Schritte\n\n"
    text += markdown.table(["Name", "Art", "Seriennummer", "Hersteller/Modell", "Betriebssystem", "Quellen"], rows)
    text += "\n\n" + "\n".join(f"{i}. {s.get('note', s['endpoint'])} ({s['action']})" for i, s in enumerate(steps, 1))
    return text + (f"\n\n{match_hint}" if match_hint else "")


def _ethernet_mac(ctx: Context, device_id: str) -> str:
    """Ethernet-MAC aus Intune (eine Graph-Abfrage pro Gerät) – 7 Tage zwischengespeichert."""
    key = f"intune-ethmac:{device_id}"
    cached = ctx.store.kv_get(key)
    if cached and time.time() - cached.get("at", 0) < 7 * 86400:
        return cached.get("mac", "")
    mac = norm_mac(ctx.intune.ethernet_mac(device_id))
    ctx.store.kv_set(key, {"mac": mac, "at": time.time()})
    return mac


def update_last_seen(ctx: Context, asset: Asset, found: tuple[str, int, str], index: NetboxIndex) -> bool:
    """'Zuletzt gesehen' direkt setzen – bewusst ohne Freigabe (ändert sich täglich), nur vorwärts."""
    from doku_agent.netbox_sync import doubtful_match

    endpoint, oid, how = found
    name = ctx.cfg.netbox.custom_fields.last_seen
    if name not in index.fields.available.get(endpoint, set()):
        return False
    if doubtful_match(asset, index.objects[(endpoint, oid)], how):
        return False
    seen = netbox_fields.last_seen(asset.sources, ctx.cfg.general.timezone)
    current = (index.objects[(endpoint, oid)].get("custom_fields") or {}).get(name)
    if not seen or (current and str(current) >= seen):
        return False
    try:
        ctx.netbox.update(endpoint, oid, {"custom_fields": {name: seen}})
    except Exception as exc:  # einzelne Maschine darf den Lauf nicht abbrechen
        ctx.log.warning("%s: '%s' nicht gesetzt (%s)", asset.name, name, exc)
        return False
    return True


def run_discovery(ctx: Context) -> dict:
    cfg = ctx.cfg
    if not cfg.netbox.site:
        raise DiscoveryError("netbox.site ist nicht gesetzt (Slug des Standorts für neue Geräte)")
    nb = ctx.netbox
    site = nb.find_one("dcim/sites", slug=cfg.netbox.site)
    if not site:
        raise DiscoveryError(f"Standort '{cfg.netbox.site}' existiert nicht in Netbox")

    # Wazuh zuerst: dessen OS-Angaben sind genauer als Intunes "Windows"; Intune ergänzt Hersteller und Modell.
    raw: list[Asset] = []
    if cfg.wazuh.enabled:
        raw += wazuh_assets(ctx)
        ctx.log.info("Wazuh: %s Agents mit Inventar", len(raw))
    if cfg.intune.enabled:
        it = intune_assets(ctx)
        ctx.log.info("Intune: %s Geräte", len(it))
        raw += it
    assets = merge_assets(raw)
    ctx.log.info("%s Maschinen nach Zusammenführung", len(assets))

    index = NetboxIndex(nb, cfg.netbox.custom_fields)
    for hint in index.fields.hints:
        ctx.log.warning(hint)
    if index.fields.steps:
        if netbox_fields.propose_setup(ctx, index.fields):
            ctx.log.info("Custom Fields fehlen in Netbox – Vorschlag zum Anlegen erstellt")
    elif index.fields.readable:
        ctx.store.close_pending(netbox_fields.SETUP_KEY, "Custom Fields sind inzwischen vorhanden.")
    stats = {"gefunden": len(assets), "bekannt": 0, "vorgeschlagen": 0, "anzupassen": 0, "ignoriert": 0,
             "zuletzt_gesehen": 0}
    for asset in assets:
        if not asset.name:
            continue
        found = index.find(asset)
        wants_mac = found is None or bool({"missing", "network"} & set(cfg.netbox.sync))
        if wants_mac and cfg.intune.enabled and cfg.intune.fetch_ethernet_mac and "intune" in asset.sources:
            mac = _ethernet_mac(ctx, asset.sources["intune"]["id"])
            if mac and mac not in asset.macs:
                asset.interfaces.append(Iface(name="Ethernet", mac=mac, identifies=False))
        if found is None and asset.macs & index.orphan_macs:
            ctx.log.info("%s: MAC %s existiert in Netbox ohne Zuordnung – keine Neuanlage", asset.name,
                         ", ".join(sorted(asset.macs & index.orphan_macs)))
            stats["bekannt"] += 1
            continue
        if found:
            stats["bekannt"] += 1
            if cfg.netbox.sync or index.fields.available[found[0]]:
                from doku_agent.netbox_sync import propose_sync
                if propose_sync(ctx, asset, found, index):
                    stats["anzupassen"] += 1
            if update_last_seen(ctx, asset, found, index):
                stats["zuletzt_gesehen"] += 1
            continue
        dedup = f"netbox:{asset.key}"
        if ctx.store.is_ignored(dedup):
            stats["ignoriert"] += 1
            continue
        vm = detect_virtual(asset, cfg.netbox)
        values = {ep: netbox_fields.values_for(asset.sources, cfg.netbox.custom_fields, names, cfg.general.timezone)
                  for ep, names in index.fields.available.items()}
        steps, hints = build_plan(asset, nb, cfg.netbox, site["id"], values)
        ctx.store.add_proposal(
            "netbox_plan", f"Netbox: {'VM' if vm else 'Gerät'} {asset.name} anlegen",
            {"steps": steps, "hints": hints, "asset": asset.__dict__ | {"interfaces": [i.__dict__ for i in asset.interfaces]},
             "followup": {"ref": "dev", "kind": "vm" if vm else "device"}},
            summary=plan_summary(asset, vm, steps), source="discovery", dedup_key=dedup,
        )
        stats["vorgeschlagen"] += 1
    ctx.log.info("Discovery: %s", stats)
    return stats
