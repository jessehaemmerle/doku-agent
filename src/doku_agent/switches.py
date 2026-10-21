"""Switches per SNMP: Switch und Ports in Netbox, Kabel aus LLDP-Nachbarn und MAC-Tabelle.

Optional werden weitere Switches über LLDP gefunden: Von den eingetragenen Switches aus folgt der Agent
Nachbarn, die per LLDP die Fähigkeit "Bridge" melden, über deren Management-Adresse – aber nur innerhalb
der freigegebenen Netze (switches.lldp_discovery.networks).

Pro Switch ein Vorschlag mit einzeln freigebbaren Änderungen:
- Gerät (falls es fehlt) und fehlende Ports (eine Änderung für alle neuen Ports),
- je Port ein Kabel: über LLDP (Nachbar sendet LLDP) oder über die MAC-Tabelle, aber nur an Ports
  mit höchstens `mac_table_max_macs` gelernten MACs, deren MAC in Netbox genau einem Interface gehört.
Vorhandene Kabel werden nie geändert; Abweichungen erscheinen als Hinweis.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from doku_agent.config import LldpDiscoveryConfig, SwitchDevice
from doku_agent.connectors.snmp import SnmpClient, SnmpData
from doku_agent.context import Context
from doku_agent.discovery import netbox_serial, netbox_slug, norm_mac, norm_serial, short_name
from doku_agent.netbox_sync import Change, sync_summary

PHYSICAL_TYPES = {6, 62, 69, 117}  # ethernetCsmacd, fastEther, fastEtherFX, gigabitEthernet
LAG_TYPE = 161  # ieee8023adLag
SPEED_TYPES = [(100, "100base-tx"), (1000, "1000base-t"), (2500, "2.5gbase-t"), (5000, "5gbase-t"),
               (10000, "10gbase-x-sfpp"), (25000, "25gbase-x-sfp28"), (40000, "40gbase-x-qsfpp"),
               (100000, "100gbase-x-qsfp28")]
NOT_CABLEABLE = {"virtual", "lag", "bridge"}


def _text(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace").replace("\x00", "").strip()
    return str(value or "").strip()


def _mac(value) -> str:
    if isinstance(value, bytes) and len(value) == 6:
        return norm_mac(value.hex())
    return norm_mac(_text(value))


def iface_type(speed: int, iftype: int) -> str:
    if iftype == LAG_TYPE:
        return "lag"
    for limit, name in SPEED_TYPES:
        if speed and speed <= limit:
            return name
    return "other"


@dataclass
class Port:
    ifindex: int
    name: str
    alias: str = ""
    speed: int = 0
    iftype: int = 6
    mac: str = ""


@dataclass
class Neighbor:
    ifindex: int
    sys_name: str
    chassis_mac: str = ""
    port_name: str = ""
    port_mac: str = ""
    port_desc: str = ""


# LldpSystemCapabilitiesMap (BITS): Bit 0 ist das höchstwertige Bit des ersten Oktetts
CAPABILITIES = ["other", "repeater", "bridge", "wlanAccessPoint", "router", "telephone", "docsisCableDevice",
                "stationOnly"]


def capabilities(value) -> set[str] | None:
    """LLDP-Fähigkeiten als Namen; None, wenn der Nachbar keine meldet."""
    if not isinstance(value, bytes) or not value:
        return None
    return {name for i, name in enumerate(CAPABILITIES)
            if i // 8 < len(value) and value[i // 8] >> (7 - i % 8) & 1}


def management_ips(table: dict) -> dict[tuple, str]:
    """(timeMark, lokaler Port, Nachbar-Index) -> IPv4-Management-Adresse aus dem Index der
    lldpRemManAddrTable (Familie 1 = IPv4, danach Länge und Oktette; manche Geräte ohne Länge)."""
    out: dict[tuple, str] = {}
    for index in table:
        if len(index) < 5 or index[3] != 1:
            continue
        rest = index[4:]
        octets = rest[1:] if len(rest) == 5 and rest[0] == 4 else rest
        if len(octets) == 4 and all(0 <= o <= 255 for o in octets):
            out.setdefault(index[:3], ".".join(str(o) for o in octets))
    return out


@dataclass
class Peer:
    """LLDP-Nachbar für die Suche nach weiteren Switches (unabhängig von der Port-Zuordnung)."""
    sys_name: str
    capabilities: set[str] | None
    mgmt_ip: str = ""


@dataclass
class SwitchInfo:
    host: str
    name: str
    descr: str = ""
    serial: str = ""
    model: str = ""
    manufacturer: str = ""
    ports: dict[int, Port] = field(default_factory=dict)
    neighbors: list[Neighbor] = field(default_factory=list)
    fdb: dict[int, set[str]] = field(default_factory=dict)
    peers: list[Peer] = field(default_factory=list)


def parse(host: str, data: SnmpData, name: str = "") -> SwitchInfo:
    t = data.tables
    info = SwitchInfo(host=host, name=name or short_name(_text(data.scalars.get("sysName"))) or host,
                      descr=_text(data.scalars.get("sysDescr")))
    for idx, cls in t.get("entPhysicalClass", {}).items():  # Chassis (Klasse 3) liefert Seriennummer und Modell
        if cls == 3:
            info.serial = netbox_serial(norm_serial(_text(t.get("entPhysicalSerialNum", {}).get(idx))))
            info.model = _text(t.get("entPhysicalModelName", {}).get(idx))
            info.manufacturer = _text(t.get("entPhysicalMfgName", {}).get(idx))
            break
    for (ifindex, *_), iftype in t.get("ifType", {}).items():
        if iftype not in PHYSICAL_TYPES and iftype != LAG_TYPE:
            continue
        key = (ifindex,)
        name = _text(t.get("ifName", {}).get(key)) or _text(t.get("ifDescr", {}).get(key)) or f"if{ifindex}"
        info.ports[ifindex] = Port(ifindex, name, _text(t.get("ifAlias", {}).get(key)),
                                   int(t.get("ifHighSpeed", {}).get(key) or 0), iftype,
                                   _mac(t.get("ifPhysAddress", {}).get(key)))

    # LLDP-Portnummer -> ifIndex (je nach Hersteller über Name, MAC, Beschreibung oder identisch)
    by_name = {p.name.lower(): p.ifindex for p in info.ports.values()}
    by_name.update({_text(t.get("ifDescr", {}).get((i,))).lower(): i for i in info.ports})
    by_mac = {p.mac: p.ifindex for p in info.ports.values() if p.mac}

    def local_port(num: int) -> int | None:
        subtype = t.get("lldpLocPortIdSubtype", {}).get((num,))
        raw = t.get("lldpLocPortId", {}).get((num,))
        if subtype == 3 and _mac(raw) in by_mac:
            return by_mac[_mac(raw)]
        if _text(raw).lower() in by_name:
            return by_name[_text(raw).lower()]
        desc = _text(t.get("lldpLocPortDesc", {}).get((num,))).lower()
        if desc in by_name:
            return by_name[desc]
        return num if num in info.ports else None

    mgmt = management_ips(t.get("lldpRemManAddrIfSubtype", {}))
    for index, sys_name in t.get("lldpRemSysName", {}).items():
        if len(index) < 3:
            continue
        info.peers.append(Peer(short_name(_text(sys_name)), capabilities(t.get("lldpRemSysCapEnabled", {}).get(index)),
                               mgmt.get(index[:3], "")))
        ifindex = local_port(index[1])
        if ifindex is None:
            continue
        chassis_type = t.get("lldpRemChassisIdSubtype", {}).get(index)
        port_type = t.get("lldpRemPortIdSubtype", {}).get(index)
        port_raw = t.get("lldpRemPortId", {}).get(index)
        info.neighbors.append(Neighbor(
            ifindex=ifindex, sys_name=short_name(_text(sys_name)),
            chassis_mac=_mac(t.get("lldpRemChassisId", {}).get(index)) if chassis_type == 4 else "",
            port_name=_text(port_raw) if port_type in (1, 5, 7) else "",
            port_mac=_mac(port_raw) if port_type == 3 else "",
            port_desc=_text(t.get("lldpRemPortDesc", {}).get(index))))

    bridge = {bp: ifi for (bp, *_), ifi in t.get("dot1dBasePortIfIndex", {}).items()}
    fdb_rows = [(idx[-6:], port) for idx, port in t.get("dot1qTpFdbPort", {}).items()]
    if not fdb_rows:  # ältere Switches ohne Q-BRIDGE-MIB
        fdb_rows = [(idx[-6:], port) for idx, port in t.get("dot1dTpFdbPort", {}).items()]
    for mac_parts, port in fdb_rows:
        ifindex = bridge.get(port, port)
        mac = norm_mac("".join(f"{x:02x}" for x in mac_parts)) if len(mac_parts) == 6 else ""
        if mac and ifindex in info.ports:
            info.fdb.setdefault(ifindex, set()).add(mac)
    return info


class _NetboxView:
    """Was aus Netbox für die Kabelzuordnung gebraucht wird: Geräte nach Name, MACs nach Interface."""

    def __init__(self, nb):
        self.nb = nb
        self.devices = {}
        for d in nb.list("dcim/devices"):
            if d.get("name"):
                self.devices.setdefault(short_name(d["name"]).lower(), d)
        self.mac_iface: dict[str, dict] = {}  # MAC -> {"iface_id", "device_id", "vm"}
        if nb.has_mac_objects:
            for m in nb.list("dcim/mac-addresses"):
                obj = m.get("assigned_object") or {}
                if not obj:
                    continue
                vm = m.get("assigned_object_type") == "virtualization.vminterface" or "virtual_machine" in obj
                self.mac_iface[norm_mac(m.get("mac_address"))] = {
                    "iface_id": m.get("assigned_object_id") or obj.get("id"), "vm": vm,
                    "device_id": (obj.get("device") or {}).get("id")}
        else:  # Netbox < 4.2: MAC am Interface
            for i in nb.list("dcim/interfaces"):
                if i.get("mac_address"):
                    self.mac_iface[norm_mac(i["mac_address"])] = {
                        "iface_id": i["id"], "vm": False, "device_id": (i.get("device") or {}).get("id")}
        self._ifaces: dict[int, dict] = {}

    def iface(self, iface_id: int) -> dict:
        if iface_id not in self._ifaces:
            self._ifaces[iface_id] = self.nb.get("dcim/interfaces", iface_id)
        return self._ifaces[iface_id]

    def iface_by_name(self, device_id: int, name: str) -> dict | None:
        if not name:
            return None
        return self.nb.find_one("dcim/interfaces", device_id=device_id, name=name)


class _Builder:
    def __init__(self, ctx: Context, sw: SwitchDevice, info: SwitchInfo, view: _NetboxView):
        self.ctx, self.sw, self.info, self.view = ctx, sw, info, view
        self.nb = ctx.netbox
        self.cfg = ctx.cfg.switches
        self.changes: list[Change] = []
        self.hints: list[str] = []
        site_slug = sw.netbox_site or ctx.cfg.netbox.site
        site = self.nb.find_one("dcim/sites", slug=site_slug)
        if not site:
            raise RuntimeError(f"Standort '{site_slug}' existiert nicht in Netbox")
        self.site_id = site["id"]
        self.device = (self.nb.find_one("dcim/devices", serial=info.serial) if info.serial else None) \
            or view.devices.get(info.name.lower())
        self.device_ref = self.device["id"] if self.device else "$sw_dev"
        self.nb_ports = ({i["name"]: i for i in self.nb.list("dcim/interfaces", device_id=self.device["id"])}
                         if self.device else {})
        self.port_ids: dict[int, object] = {}

    def add(self, key, label, before, after, steps, requires=()) -> str:
        self.changes.append(Change(key, "missing", label, str(before) if before not in (None, "") else "–",
                                   str(after) if after not in (None, "") else "–", steps, list(requires)))
        return key

    def device_change(self):
        if self.device:
            return
        mfr = self.info.manufacturer or self.ctx.cfg.netbox.unknown_manufacturer
        model = self.info.model or self.ctx.cfg.netbox.unknown_model
        role = self.cfg.netbox_role
        steps = [
            {"ref": "sw_mfr", "action": "ensure", "endpoint": "dcim/manufacturers", "lookup": {"slug": netbox_slug(mfr)},
             "data": {"name": mfr, "slug": netbox_slug(mfr)}, "note": f"Hersteller '{mfr}'"},
            {"ref": "sw_type", "action": "ensure", "endpoint": "dcim/device-types",
             "lookup": {"manufacturer_id": "$sw_mfr", "slug": netbox_slug(model)},
             "data": {"manufacturer": "$sw_mfr", "model": model, "slug": netbox_slug(model)},
             "note": f"Gerätetyp '{model}'"},
            {"ref": "sw_role", "action": "ensure", "endpoint": "dcim/device-roles", "lookup": {"slug": role},
             "data": {"name": role.replace("-", " ").title(), "slug": role, "color": "2196f3"},
             "note": f"Rolle '{role}'"},
            {"ref": "sw_dev", "action": "create", "endpoint": "dcim/devices",
             "data": {"name": self.info.name, "serial": self.info.serial, "site": self.site_id, "role": "$sw_role",
                      "device_type": "$sw_type", "status": "active",
                      "description": f"Switch {self.sw.host} (doku-agent, SNMP)",
                      "comments": self.info.descr[:500]},
             "note": f"Switch '{self.info.name}'"},
        ]
        if not self.info.model:
            self.hints.append("Modell per SNMP (ENTITY-MIB) nicht lesbar – Gerätetyp bitte prüfen.")
        self.add("device", "Gerät", "", f"{self.info.name} ({mfr} {model}, {self.info.serial or 'ohne Seriennummer'})",
                 steps)

    def ports_change(self):
        missing = []
        for p in sorted(self.info.ports.values(), key=lambda p: p.ifindex):
            existing = self.nb_ports.get(p.name)
            if existing:
                self.port_ids[p.ifindex] = existing["id"]
                continue
            ref = f"sw_if_{p.ifindex}"
            data = {"device": self.device_ref, "name": p.name, "type": iface_type(p.speed, p.iftype)}
            if p.alias:
                data["description"] = p.alias[:200]
            missing.append({"ref": ref, "action": "create", "endpoint": "dcim/interfaces", "data": data,
                            "note": f"Port {p.name}"})
            self.port_ids[p.ifindex] = f"${ref}"
        if missing:
            names = ", ".join(s["data"]["name"] for s in missing[:5]) + (" …" if len(missing) > 5 else "")
            self.add("ports", "Ports", "", f"{len(missing)} neu ({names})", missing,
                     requires=[] if self.device else ["device"])

    def _device_of(self, iface: dict) -> dict:
        dev = iface.get("device")
        if isinstance(dev, dict):
            return dev
        return next((d for d in self.view.devices.values() if d["id"] == dev), {"id": dev, "name": f"#{dev}"})

    def _remote_for_neighbor(self, n: Neighbor) -> tuple[dict | None, str]:
        dev = self.view.devices.get(n.sys_name.lower()) if n.sys_name else None
        if dev is None and n.chassis_mac in self.view.mac_iface:
            dev_id = self.view.mac_iface[n.chassis_mac].get("device_id")
            dev = next((d for d in self.view.devices.values() if d["id"] == dev_id), None)
        if dev is None:
            return None, f"Nachbar {n.sys_name or n.chassis_mac} ist nicht in Netbox"
        iface = self.view.iface_by_name(dev["id"], n.port_name) or self.view.iface_by_name(dev["id"], n.port_desc)
        if iface is None and n.port_mac in self.view.mac_iface and not self.view.mac_iface[n.port_mac]["vm"]:
            iface = self.view.iface(self.view.mac_iface[n.port_mac]["iface_id"])
        if iface is None:
            return None, f"Port {n.port_name or n.port_desc or n.port_mac} von {dev['name']} ist nicht in Netbox"
        return iface, "LLDP"

    def _remote_for_mac(self, macs: set[str]) -> tuple[dict | None, str]:
        hits = [self.view.mac_iface[m] for m in macs if m in self.view.mac_iface]
        if len(hits) != 1 or hits[0]["vm"]:
            return None, ""
        return self.view.iface(hits[0]["iface_id"]), "MAC-Tabelle"

    def _pending_cables(self) -> dict[frozenset, str]:
        """Kabel aus offenen Vorschlägen anderer Switches – LLDP sieht jede Verbindung von beiden Seiten."""
        own = f"switch-netbox:{self.sw.host}"
        pairs = {}
        for prop in self.ctx.store.pending_by_source("switches"):
            if prop.dedup_key == own:
                continue
            for change in prop.payload.get("changes", []):
                for step in change.get("steps", []):
                    if step.get("endpoint") != "dcim/cables":
                        continue
                    ends = [t[0].get("object_id") for t in (step["data"].get("a_terminations") or [{}],
                                                            step["data"].get("b_terminations") or [{}])]
                    if all(isinstance(e, int) for e in ends):
                        pairs[frozenset(ends)] = prop.payload.get("target", {}).get("name") or prop.title
        return pairs

    def cables(self):
        pending = self._pending_cables()
        uplinks = {n.ifindex for n in self.info.neighbors}
        candidates: dict[int, tuple[dict | None, str]] = {}
        for n in self.info.neighbors:
            candidates[n.ifindex] = self._remote_for_neighbor(n)
        if self.cfg.mac_table:
            for ifindex, macs in self.info.fdb.items():
                if ifindex in uplinks or not macs or len(macs) > self.cfg.mac_table_max_macs:
                    continue
                candidates[ifindex] = self._remote_for_mac(macs)
        own_device = (self.device or {}).get("id")
        for ifindex, (remote, how) in sorted(candidates.items()):
            port = self.info.ports.get(ifindex)
            if port is None:
                continue
            if remote is None:
                if how:
                    self.hints.append(f"{port.name}: {how} – kein Kabel vorgeschlagen.")
                continue
            remote_dev = self._device_of(remote)
            if own_device and remote_dev.get("id") == own_device:
                continue
            rtype = remote.get("type")
            if (rtype.get("value") if isinstance(rtype, dict) else rtype) in NOT_CABLEABLE:
                self.hints.append(f"{port.name}: Gegenstelle {remote_dev.get('name')} {remote.get('name')} ist "
                                  "ein virtuelles Interface – kein Kabel möglich.")
                continue
            local = self.nb_ports.get(port.name)
            peer_text = f"{remote_dev.get('name')} {remote.get('name')}"
            if local and local.get("cable"):
                peers = {p.get("id") for p in local.get("link_peers") or []}
                if remote["id"] not in peers:
                    self.hints.append(f"{port.name}: hat in Netbox bereits ein anderes Kabel; {how} meldet "
                                      f"{peer_text} (nur Hinweis).")
                continue
            if remote.get("cable"):
                self.hints.append(f"{port.name}: {peer_text} ist in Netbox schon anderweitig verkabelt (nur Hinweis).")
                continue
            other = pending.get(frozenset((self.port_ids[ifindex], remote["id"])))
            if other:
                self.hints.append(f"{port.name}: Kabel zu {peer_text} steht schon im Vorschlag für {other}.")
                continue
            requires = ["ports"] if str(self.port_ids[ifindex]).startswith("$") else []
            self.add(f"cable:{port.name}", f"Kabel {port.name}", "", f"{peer_text} ({how})",
                     [{"action": "create", "endpoint": "dcim/cables", "note": f"Kabel {port.name} – {peer_text}",
                       "data": {"a_terminations": [{"object_type": "dcim.interface",
                                                    "object_id": self.port_ids[ifindex]}],
                                "b_terminations": [{"object_type": "dcim.interface", "object_id": remote["id"]}],
                                "status": "connected", "description": f"doku-agent ({how})"}}],
                     requires=requires + ([] if self.device else ["device"]))


def propose_switch(ctx: Context, sw: SwitchDevice, data: SnmpData | None = None,
                   view: _NetboxView | None = None) -> int | None:
    if data is None:
        data = SnmpClient(sw.host, sw.snmp or ctx.cfg.switches.snmp, ctx.guard).collect()
    info = parse(sw.host, data, sw.name)
    b = _Builder(ctx, sw, info, view or _NetboxView(ctx.netbox))
    b.device_change()
    b.ports_change()
    b.cables()
    dedup = f"switch-netbox:{sw.host}"
    if ctx.store.is_ignored(dedup):
        return None
    if not b.changes:
        ctx.store.close_pending(dedup, "Netbox entspricht dem Switch – nichts mehr zu tun.")
        return None
    name = (b.device or {}).get("name") or info.name
    followup = {"id": b.device["id"], "kind": "device"} if b.device else {"ref": "sw_dev", "kind": "device"}
    n = len(b.changes)
    return ctx.store.add_proposal(
        "netbox_plan", f"Netbox: Switch {name} abgleichen ({n} Änderung{'en' if n != 1 else ''})",
        {"changes": [asdict(c) for c in b.changes], "hints": b.hints,
         "target": {"endpoint": "dcim/devices", "id": (b.device or {}).get("id"), "name": name},
         "followup": followup},
        summary=sync_summary(name, False, b.changes).replace("Gerät ", "Switch ", 1), source="switches",
        dedup_key=dedup,
    )


def skip_reason(peer: Peer, disc: LldpDiscoveryConfig, guard) -> str:
    """Warum ein LLDP-Nachbar nicht abgefragt wird ('' = abfragen)."""
    if peer.capabilities is None:
        return "meldet keine LLDP-Fähigkeiten"
    if peer.capabilities & set(disc.skip_capabilities):
        return "laut LLDP " + ", ".join(sorted(peer.capabilities & set(disc.skip_capabilities)))
    if not set(disc.require_capabilities) <= peer.capabilities:
        return "laut LLDP kein " + ", ".join(disc.require_capabilities)
    if not peer.mgmt_ip:
        return "keine IPv4-Management-Adresse per LLDP"
    if not guard.allows_snmp(peer.mgmt_ip):
        return f"{peer.mgmt_ip} liegt außerhalb von lldp_discovery.networks"
    return ""


def sync_switches(ctx: Context, host: str = "") -> list[int | None]:
    """Eingetragene Switches abgleichen; mit lldp_discovery auch die per LLDP gefundenen (Breitensuche)."""
    cfg = ctx.cfg.switches
    if not cfg.enabled:
        raise RuntimeError("Switches sind in der Konfiguration deaktiviert (switches.enabled: false)"
                           + (" – die config.yaml wurde aber nach dem Start geändert: Agent neu starten "
                              "(docker compose restart agent)" if ctx.cfg.changed_on_disk() else ""))
    disc = cfg.lldp_discovery
    crawl = disc.enabled and not host and bool(disc.networks)
    if disc.enabled and not disc.networks and not host:
        ctx.log.warning("LLDP-Suche ist an, aber lldp_discovery.networks ist leer – es werden nur die "
                        "eingetragenen Switches abgefragt.")
    view = _NetboxView(ctx.netbox)
    queue = [(sw, 0) for sw in cfg.devices if not host or sw.host == host]
    known_hosts = {sw.host.lower() for sw, _ in queue}
    done_names: set[str] = set()
    results, failed, found, skipped = [], [], [], {}
    while queue:
        sw, depth = queue.pop(0)
        try:
            data = SnmpClient(sw.host, sw.snmp or cfg.snmp, ctx.guard).collect()
            info = parse(sw.host, data, sw.name)
            # Wiedererkennung über den sysName (so melden ihn die Nachbarn), auch wenn ein eigener Name gesetzt ist
            names = {info.name.lower(), short_name(_text(data.scalars.get("sysName"))).lower()} - {""}
            if names & done_names:  # derselbe Switch unter einer weiteren Adresse
                ctx.log.info("Switch %s ist %s – bereits abgeglichen", sw.host, info.name)
                continue
            done_names |= names
            results.append(propose_switch(ctx, sw, data=data, view=view))
        except Exception as exc:
            ctx.log.error("Switch %s: %s", sw.host, exc)
            failed.append(sw.host)
            continue
        if not crawl or depth >= disc.max_depth:
            continue
        for peer in info.peers:
            if peer.sys_name.lower() in done_names or (peer.mgmt_ip and peer.mgmt_ip.lower() in known_hosts):
                continue
            reason = skip_reason(peer, disc, ctx.guard)
            if reason:
                skipped.setdefault(peer.sys_name or peer.mgmt_ip or "?", reason)
                continue
            if len(known_hosts) >= disc.max_switches:
                skipped.setdefault(peer.sys_name, f"Grenze von {disc.max_switches} Switches erreicht")
                continue
            known_hosts.add(peer.mgmt_ip.lower())
            found.append(f"{peer.sys_name or peer.mgmt_ip} ({peer.mgmt_ip}, über {info.name})")
            queue.append((SwitchDevice(host=peer.mgmt_ip, netbox_site=sw.netbox_site), depth + 1))
    if crawl:
        ctx.log.info("LLDP-Suche: %s weitere Switches gefunden%s", len(found), ": " + "; ".join(found) if found else "")
        for name, reason in sorted(skipped.items()):
            ctx.log.info("LLDP-Nachbar %s nicht abgefragt: %s", name, reason)
    if failed and not results:  # None (nichts zu tun) zählt als erfolgreich
        raise RuntimeError("Kein Switch abgleichbar: " + ", ".join(failed))
    return results
