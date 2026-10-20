"""FortiGate -> Netbox: Firewall als Gerät mit Interfaces, IP-Adressen, VLANs und Präfixen.

Wie beim Maschinen-Abgleich entsteht pro Firewall ein Vorschlag mit einzelnen Änderungen
(Häkchen). Angelegt wird nur, was fehlt; bestehende Objekte werden nicht umgebaut. Abhängigkeiten
(IP an neuem Interface, VLAN-Interface an neuem VLAN) stehen in `requires`.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict

from doku_agent.config import FortiGateDevice
from doku_agent.context import Context
from doku_agent.discovery import netbox_slug, norm_mac
from doku_agent.generators.fortigate_docs import cidr, mask_obj, names
from doku_agent.netbox_sync import Change, sync_summary

# FortiGate-Interfacetyp -> Netbox-Interfacetyp
IFACE_TYPES = {"physical": "other", "aggregate": "lag", "redundant": "lag", "hard-switch": "bridge", "switch": "bridge"}
# Interne Interfaces ohne Bedeutung für die Doku
SKIP_IFACES = re.compile(r"^(ssl\.|naf\.|l2t\.|npu\d|modem$|ha$|mgmt\d?$)|_vlink", re.I)


def _iface_key(name: str) -> str:
    return f"iface:{name}"


class _Builder:
    def __init__(self, ctx: Context, dev: FortiGateDevice, info: dict, model: str, interfaces: list[dict]):
        self.ctx, self.dev, self.info, self.model = ctx, dev, info, model
        self.nb = ctx.netbox
        self.cfg = ctx.cfg.fortigate
        self.enabled = set(self.cfg.netbox_sync)
        self.interfaces = [i for i in interfaces if i.get("name") and not SKIP_IFACES.search(i["name"])]
        self.changes: list[Change] = []
        self.hints: list[str] = []
        site_slug = dev.netbox_site or ctx.cfg.netbox.site
        site = self.nb.find_one("dcim/sites", slug=site_slug)
        if not site:
            raise RuntimeError(f"Standort '{site_slug}' existiert nicht in Netbox")
        self.site_id = site["id"]
        self.device = self._find_device()
        self.device_ref = self.device["id"] if self.device else "$fgt_dev"
        self.nb_ifaces = ({i["name"]: i for i in self.nb.list("dcim/interfaces", device_id=self.device["id"])}
                          if self.device else {})
        self.iface_ids: dict[str, object] = {n: i["id"] for n, i in self.nb_ifaces.items()}
        self.vlan_ids: dict[int, object] = {}

    def _find_device(self) -> dict | None:
        serial = self.info.get("serial")
        found = self.nb.find_one("dcim/devices", serial=serial) if serial else None
        return found or self.nb.find_one("dcim/devices", name=self.info.get("hostname") or self.dev.name)

    def add(self, key, label, before, after, steps, requires=(), check=None, category="missing") -> str:
        self.changes.append(Change(key, category, label, str(before) if before not in (None, "") else "–",
                                   str(after) if after not in (None, "") else "–", steps, list(requires), check))
        return key

    def _device_requires(self) -> list[str]:
        return [] if self.device else ["device"]

    # --- Gerät ----------------------------------------------------------------

    def device_change(self):
        if self.device:
            return
        if "device" not in self.enabled:
            raise RuntimeError(f"FortiGate {self.dev.name} fehlt in Netbox und 'device' ist abgeschaltet")
        model = self.model or "FortiGate"
        mslug, tslug, role = "fortinet", netbox_slug(model), self.cfg.netbox_role
        name = self.info.get("hostname") or self.dev.name
        version = (self.info.get("version") or "").lstrip("v")
        platform = f"FortiOS {'.'.join(version.split('.')[:2])}".strip() if version else "FortiOS"
        steps = [
            {"ref": "fgt_mfr", "action": "ensure", "endpoint": "dcim/manufacturers", "lookup": {"slug": mslug},
             "data": {"name": "Fortinet", "slug": mslug}, "note": "Hersteller 'Fortinet'"},
            {"ref": "fgt_type", "action": "ensure", "endpoint": "dcim/device-types",
             "lookup": {"manufacturer_id": "$fgt_mfr", "slug": tslug},
             "data": {"manufacturer": "$fgt_mfr", "model": model, "slug": tslug}, "note": f"Gerätetyp '{model}'"},
            {"ref": "fgt_role", "action": "ensure", "endpoint": "dcim/device-roles", "lookup": {"slug": role},
             "data": {"name": role.replace("-", " ").title(), "slug": role, "color": "f44336"},
             "note": f"Rolle '{role}'"},
            {"ref": "fgt_platform", "action": "ensure", "endpoint": "dcim/platforms",
             "lookup": {"slug": netbox_slug(platform)},
             "data": {"name": platform, "slug": netbox_slug(platform)}, "note": f"Plattform '{platform}'"},
            {"ref": "fgt_dev", "action": "create", "endpoint": "dcim/devices",
             "data": {"name": name, "serial": self.info.get("serial", ""), "site": self.site_id, "role": "$fgt_role",
                      "device_type": "$fgt_type", "platform": "$fgt_platform", "status": "active",
                      "description": f"FortiGate {self.dev.name} (doku-agent)"},
             "note": f"Gerät '{name}'"},
        ]
        self.add("device", "Gerät", "", f"{name} ({model}, {self.info.get('serial', '')})", steps)

    # --- VLANs ----------------------------------------------------------------

    def vlans(self):
        seen = set()
        for i in self.interfaces:
            vid = i.get("vlanid")
            if not vid or vid in seen:
                continue
            seen.add(vid)
            existing = self.nb.list("ipam/vlans", vid=vid, site_id=self.site_id)
            if len(existing) > 1:
                self.hints.append(f"VLAN {vid} gibt es am Standort mehrfach – nicht zugeordnet.")
                continue
            if existing:
                self.vlan_ids[vid] = existing[0]["id"]
                continue
            if "vlans" not in self.enabled:
                continue
            name = (i.get("alias") or i["name"])[:64]
            self.add(f"vlan:{vid}", f"VLAN {vid}", "", name,
                     [{"ref": f"vlan_{vid}", "action": "create", "endpoint": "ipam/vlans",
                       "data": {"vid": vid, "name": name, "site": self.site_id, "status": "active",
                                "description": f"FortiGate {self.dev.name} {i['name']}"}, "note": f"VLAN {vid}"}])
            self.vlan_ids[vid] = f"$vlan_{vid}"

    # --- Interfaces -------------------------------------------------------------

    def interfaces_changes(self):
        if "interfaces" not in self.enabled:
            return
        # Aggregate vor ihren Mitgliedern, VLAN-Interfaces zuletzt, damit Referenzen auflösbar sind
        rank = {"aggregate": 0, "redundant": 0, "vlan": 2}
        ordered = sorted(self.interfaces, key=lambda i: (rank.get(i.get("type"), 1), i["name"]))
        lag_of = {m: i["name"] for i in self.interfaces if i.get("type") in ("aggregate", "redundant")
                  for m in names(i.get("member"))}
        for i in ordered:
            name = i["name"]
            if name in self.nb_ifaces:
                self._update_existing(i, lag_of)
                continue
            ftype = i.get("type") or "physical"
            data: dict = {"device": self.device_ref, "name": name, "type": IFACE_TYPES.get(ftype, "virtual"),
                          "enabled": i.get("status", "up") != "down"}
            label = name + (f" ({i['alias']})" if i.get("alias") else "")
            if i.get("description") or i.get("alias"):
                data["description"] = (i.get("description") or i.get("alias"))[:200]
            requires = self._device_requires()
            parent = i.get("interface")
            if ftype == "vlan" and parent:
                if parent not in self.iface_ids:
                    self.hints.append(f"{name}: Parent-Interface {parent} fehlt – ohne Parent angelegt.")
                else:
                    data["parent"] = self.iface_ids[parent]
                    if str(self.iface_ids[parent]).startswith("$"):
                        requires.append(_iface_key(parent))
                vid = i.get("vlanid")
                if vid in self.vlan_ids:
                    data["mode"] = "access"
                    data["untagged_vlan"] = self.vlan_ids[vid]
                    if str(self.vlan_ids[vid]).startswith("$"):
                        requires.append(f"vlan:{vid}")
            lag = lag_of.get(name)
            if lag and lag in self.iface_ids:
                data["lag"] = self.iface_ids[lag]
                if str(self.iface_ids[lag]).startswith("$"):
                    requires.append(_iface_key(lag))
            mac = norm_mac(i.get("macaddr"))
            ref = f"if_{netbox_slug(name)}"
            self.add(_iface_key(name), "Interface", "", f"{label}, {data['type']}"
                     + (f", VLAN {i.get('vlanid')}" if i.get("vlanid") else ""),
                     [{"ref": ref, "action": "create", "endpoint": "dcim/interfaces", "data": data,
                       "note": f"Interface {name}"}], requires=requires)
            if mac:
                self.hints.append(f"{name}: MAC {mac} aus der Konfiguration (Override) – nicht übernommen.")
            self.iface_ids[name] = f"${ref}"

    def _update_existing(self, i: dict, lag_of: dict):
        """Bestehendes Interface: nur fehlende Zuordnungen ergänzen (LAG, untagged VLAN)."""
        nb_if = self.nb_ifaces[i["name"]]
        data, requires, parts = {}, [], []
        lag = lag_of.get(i["name"])
        if lag and not nb_if.get("lag") and lag in self.iface_ids:
            data["lag"] = self.iface_ids[lag]
            parts.append(f"LAG {lag}")
            if str(self.iface_ids[lag]).startswith("$"):
                requires.append(_iface_key(lag))
        vid = i.get("vlanid")
        if vid and not nb_if.get("untagged_vlan") and vid in self.vlan_ids and not nb_if.get("mode"):
            data.update(mode="access", untagged_vlan=self.vlan_ids[vid])
            parts.append(f"VLAN {vid}")
            if str(self.vlan_ids[vid]).startswith("$"):
                requires.append(f"vlan:{vid}")
        if data:
            self.add(f"ifupd:{i['name']}", f"Interface {i['name']}", "", ", ".join(parts),
                     [{"action": "update", "endpoint": "dcim/interfaces", "id": nb_if["id"], "data": data,
                       "note": f"Interface {i['name']} ergänzen"}], requires=requires)

    # --- IPs und Präfixe ------------------------------------------------------

    def _addresses(self, i: dict) -> list[str]:
        out = []
        for raw in [i.get("ip") or "", *[s.get("ip") or "" for s in i.get("secondaryip") or []]]:
            value = cidr(raw)
            if value and value not in ("0.0.0.0", "0.0.0.0/0") and "/" in value:
                out.append(value)
        return out

    def ips_and_prefixes(self):
        primary_host = (self.dev.url.split("//", 1)[-1].split("/")[0].split(":")[0])
        primary_ref = None
        for i in self.interfaces:
            if i["name"] not in self.iface_ids:
                continue
            if_id = self.iface_ids[i["name"]]
            if_requires = [_iface_key(i["name"])] if str(if_id).startswith("$") else self._device_requires()
            for address in self._addresses(i):
                host = address.split("/")[0]
                if "ips" in self.enabled:
                    ref = self._ip(i["name"], if_id, address, if_requires)
                    if host == primary_host and ref:
                        primary_ref = ref
                if "prefixes" in self.enabled and i.get("role") not in self.cfg.netbox_skip_roles:
                    self._prefix(i, address)
        if primary_ref and "ips" in self.enabled:
            current = (self.device or {}).get("primary_ip4")
            if not current:
                value, requires = primary_ref
                self.add("primary_ip4", "Primäre IPv4", "", primary_host,
                         [{"action": "update", "endpoint": "dcim/devices", "id": self.device_ref,
                           "data": {"primary_ip4": value}, "note": "Primäre IPv4 setzen"}],
                         requires=requires + self._device_requires())

    def _ip(self, iface: str, if_id, address: str, if_requires: list[str]):
        host = address.split("/")[0]
        matches = self.nb.list("ipam/ip-addresses", address=host)
        if len(matches) > 1:
            self.hints.append(f"IP {address} gibt es in Netbox mehrfach – nicht übernommen.")
            return None
        existing = matches[0] if matches else None
        assignment = {"assigned_object_type": "dcim.interface", "assigned_object_id": if_id}
        if existing and existing.get("assigned_object_id"):
            if existing.get("assigned_object_id") == if_id:
                return (existing["id"], [])
            self.hints.append(f"IP {address} ist in Netbox einem anderen Objekt zugewiesen – nicht übernommen.")
            return None
        key, ref = f"ip:{host}", f"ip_{host.replace('.', '_').replace(':', '_')}"
        if existing:
            step = {"ref": ref, "action": "update", "endpoint": "ipam/ip-addresses", "id": existing["id"],
                    "data": assignment, "note": f"Bestehende IP {existing.get('address')} zuweisen"}
        else:
            step = {"ref": ref, "action": "create", "endpoint": "ipam/ip-addresses",
                    "data": {"address": address, "status": "active", **assignment}, "note": f"IP {address}"}
        self.add(key, f"IP an {iface}", "", address, [step], requires=if_requires)
        return (f"${ref}", [key])

    def _prefix(self, i: dict, address: str):
        net = ipaddress.ip_interface(address).network
        if net.prefixlen >= net.max_prefixlen - 1:  # /31, /32: Transfer- bzw. Hostnetze
            return
        prefix = str(net)
        if any(c.key == f"prefix:{prefix}" for c in self.changes):
            return
        if self.nb.list("ipam/prefixes", prefix=prefix):  # auch mehrfach vorhanden (z.B. in mehreren VRFs)
            return
        data = {"prefix": prefix, "status": "active", "description": f"FortiGate {self.dev.name} {i['name']}"[:200]}
        if self.nb.version() >= (4, 2):  # ab 4.2 generischer Geltungsbereich statt Feld "site"
            data.update(scope_type="dcim.site", scope_id=self.site_id)
        else:
            data["site"] = self.site_id
        requires = []
        vid = i.get("vlanid")
        if vid and vid in self.vlan_ids:
            data["vlan"] = self.vlan_ids[vid]
            if str(self.vlan_ids[vid]).startswith("$"):
                requires.append(f"vlan:{vid}")
        self.add(f"prefix:{prefix}", "Präfix", "", f"{prefix} ({i['name']})",
                 [{"action": "create", "endpoint": "ipam/prefixes", "data": data, "note": f"Präfix {prefix}"}],
                 requires=requires)


def propose_fortigate(ctx: Context, dev: FortiGateDevice) -> int | None:
    client = ctx.fortigate(dev.name)
    info = client.system()
    interfaces = [mask_obj(i) for i in client.cmdb("system/interface")]
    b = _Builder(ctx, dev, info, client.model(), interfaces)
    b.device_change()
    b.vlans()
    b.interfaces_changes()
    b.ips_and_prefixes()
    dedup = f"fortigate-netbox:{dev.name}"
    if ctx.store.is_ignored(dedup):
        return None
    # Änderungen ohne erlaubte Voraussetzung entfallen (transitiv), z.B. wenn 'interfaces' abgeschaltet ist
    changes = b.changes
    while True:
        kept = {c.key for c in changes}
        remaining = [c for c in changes if all(r in kept for r in c.requires)]
        if len(remaining) == len(changes):
            break
        changes = remaining
    if not changes:
        ctx.store.close_pending(dedup, "Netbox entspricht der FortiGate – nichts mehr zu tun.")
        return None
    name = (b.device or {}).get("name") or info.get("hostname") or dev.name
    followup = {"id": b.device["id"], "kind": "device"} if b.device else {"ref": "fgt_dev", "kind": "device"}
    return ctx.store.add_proposal(
        "netbox_plan", f"Netbox: FortiGate {name} abgleichen ({len(changes)} Änderung{'en' if len(changes) != 1 else ''})",
        {"changes": [asdict(c) for c in changes], "hints": b.hints,
         "target": {"endpoint": "dcim/devices", "id": (b.device or {}).get("id"), "name": name},
         "followup": followup},
        summary=sync_summary(name, False, changes).replace("Gerät ", "FortiGate ", 1), source="fortigate",
        dedup_key=dedup,
    )


def sync_fortigates(ctx: Context, device: str = "") -> list[int | None]:
    results, failed = [], []
    for dev in ctx.cfg.fortigate.devices:
        if device and dev.name != device:
            continue
        try:
            results.append(propose_fortigate(ctx, dev))
        except Exception as exc:
            ctx.log.error("FortiGate %s -> Netbox: %s", dev.name, exc)
            failed.append(dev.name)
    if failed and not results:  # None (nichts zu tun) zählt als erfolgreich
        raise RuntimeError("FortiGate -> Netbox fehlgeschlagen: " + ", ".join(failed))
    return results
