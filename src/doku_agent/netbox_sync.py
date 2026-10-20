"""Abgleich bereits eingetragener Maschinen: Abweichungen zwischen Intune/Wazuh und Netbox
als einzeln freigebbare Änderungen (Vorher/Nachher) vorschlagen.

Jede Änderung trägt ihre eigenen Plan-Schritte. Hängt eine Änderung von einer anderen ab
(z.B. IP an einem neuen Interface), steht das in `requires`. Für Feldänderungen hält `check`
den Wert zum Zeitpunkt des Vorschlags fest; wurde das Feld in Netbox inzwischen von Hand
geändert, wird die Änderung beim Übernehmen übersprungen statt die Handarbeit zu überschreiben.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from doku_agent import markdown
from doku_agent.config import NetboxConfig, VCenterConfig
from doku_agent.connectors.netbox import NetboxClient
from doku_agent.context import Context
from doku_agent.discovery import (Asset, NetboxIndex, detect_virtual, netbox_serial, netbox_slug, norm_mac, norm_serial,
                                  serial_key, short_name)
from doku_agent.netbox_plan import comparable, field_value

CATEGORY_LABELS = {"missing": "Fehlende Angabe", "os": "Betriebssystem/Ressourcen",
                   "network": "Netzwerk", "rename": "Umbenennung", "ids": "Kennung (Custom Field)",
                   "vcenter": "vCenter (Cluster, Host, Disks)"}


@dataclass
class Change:
    key: str
    category: str
    label: str
    before: str
    after: str
    steps: list[dict]
    requires: list[str] = field(default_factory=list)
    check: dict | None = None  # {"endpoint", "id", "field", "value"}


def _host(cidr: str) -> str:
    return (cidr or "").split("/")[0]


def _iface_macs(iface: dict) -> set[str]:
    macs = {norm_mac(m.get("mac_address")) for m in iface.get("mac_addresses") or []}
    macs.add(norm_mac(iface.get("mac_address") if isinstance(iface.get("mac_address"), str) else ""))
    macs.add(norm_mac((iface.get("primary_mac_address") or {}).get("mac_address")))
    macs.discard("")
    return macs


class _Builder:
    def __init__(self, asset: Asset, obj: dict, endpoint: str, how: str, nb: NetboxClient, cfg: NetboxConfig,
                 index: NetboxIndex):
        self.asset, self.obj, self.endpoint, self.how = asset, obj, endpoint, how
        self.nb, self.cfg, self.index = nb, cfg, index
        self.vm = endpoint == "virtualization/virtual-machines"
        self.oid = obj["id"]
        self.changes: list[Change] = []
        self.hints: list[str] = []
        self.ctx_vcenter = None  # VCenterConfig, wenn das vCenter angebunden ist
        if self.vm:
            self.if_endpoint, self.if_parent, self.obj_type = (
                "virtualization/interfaces", "virtual_machine", "virtualization.vminterface")
            self.filter = {"virtual_machine_id": self.oid}
        else:
            self.if_endpoint, self.if_parent, self.obj_type = "dcim/interfaces", "device", "dcim.interface"
            self.filter = {"device_id": self.oid}

    def add(self, key: str, category: str, label: str, before, after, steps: list[dict], requires=(),
            check_field=None) -> str:
        """key ist stabil über Läufe hinweg (z.B. "platform", "ip:10.0.0.5"), damit eine Freigabe
        nie eine andere Änderung trifft, falls der Vorschlag zwischendurch neu berechnet wurde."""
        check = None
        if check_field:
            check = {"endpoint": self.endpoint, "id": self.oid, "field": check_field,
                     "value": field_value(self.obj, check_field)}
        self.changes.append(Change(key, category, label, str(before) if before not in (None, "") else "–",
                                   str(after) if after not in (None, "") else "–", steps, list(requires), check))
        return key

    def update(self, data: dict, note: str) -> dict:
        return {"action": "update", "endpoint": self.endpoint, "id": self.oid, "data": data, "note": note}

    # --- Stammdaten ---------------------------------------------------------

    def serial(self):
        current = norm_serial(self.obj.get("serial"))
        if not self.asset.serial or serial_key(current) == serial_key(netbox_serial(self.asset.serial)):
            return
        if not current:
            value = netbox_serial(self.asset.serial)
            self.add("serial", "missing", "Seriennummer", "", value,
                     [self.update({"serial": value}, "Seriennummer setzen")], check_field="serial")
        else:
            self.hints.append(f"Seriennummer weicht ab: Netbox {current}, Quelle {self.asset.serial} – "
                              "nicht automatisch geändert (Hardwaretausch?).")

    def platform(self):
        if not self.asset.os_name:
            return
        slug = netbox_slug(self.asset.os_name)
        current = self.obj.get("platform") or {}
        # Ein allgemeinerer Name ist keine Abweichung: Intune meldet nur "Windows", Netbox hat "windows-11-pro".
        current_slug = current.get("slug") or ""
        if current_slug == slug or current_slug.startswith(slug + "-"):
            return
        category = "missing" if not current else "os"
        ref = "platform_ref"
        steps = [{"ref": ref, "action": "ensure", "endpoint": "dcim/platforms", "lookup": {"slug": slug},
                  "data": {"name": self.asset.os_name, "slug": slug}, "note": f"Plattform '{self.asset.os_name}'"},
                 self.update({"platform": f"${ref}"}, "Plattform setzen")]
        self.add("platform", category, "Plattform", current.get("name"), self.asset.os_name, steps,
                 check_field="platform")

    def device_type(self):
        if self.vm or not self.asset.model:
            return
        dtype = self.obj.get("device_type") or {}
        model = dtype.get("model") or ""
        manufacturer = (dtype.get("manufacturer") or {}).get("name") or ""
        if model != self.cfg.unknown_model and manufacturer != self.cfg.unknown_manufacturer:
            if netbox_slug(model) != netbox_slug(self.asset.model):
                self.hints.append(f"Modell weicht ab: Netbox '{manufacturer} {model}', Quelle "
                                  f"'{self.asset.manufacturer} {self.asset.model}' – nicht automatisch geändert.")
            return
        mname = self.asset.manufacturer or self.cfg.unknown_manufacturer
        mslug, tslug = netbox_slug(mname), netbox_slug(self.asset.model)
        base = "device_type"
        steps = [
            {"ref": f"{base}_mfr", "action": "ensure", "endpoint": "dcim/manufacturers", "lookup": {"slug": mslug},
             "data": {"name": mname, "slug": mslug}, "note": f"Hersteller '{mname}'"},
            {"ref": f"{base}_dtype", "action": "ensure", "endpoint": "dcim/device-types",
             "lookup": {"manufacturer_id": f"${base}_mfr", "slug": tslug},
             "data": {"manufacturer": f"${base}_mfr", "model": self.asset.model, "slug": tslug},
             "note": f"Gerätetyp '{self.asset.model}'"},
            self.update({"device_type": f"${base}_dtype"}, "Gerätetyp setzen"),
        ]
        self.add("device_type", "missing", "Gerätetyp", f"{manufacturer} {model}", f"{mname} {self.asset.model}", steps,
                 check_field="device_type")

    def vm_resources(self):
        if not self.vm:
            return
        cores, vcpus = self.asset.cpu_cores, self.obj.get("vcpus")
        if cores and (vcpus is None or float(vcpus) != float(cores)):
            self.add("vcpus", "missing" if vcpus is None else "os", "vCPUs", vcpus, cores,
                     [self.update({"vcpus": cores}, "vCPUs setzen")], check_field="vcpus")
        mem, current = self.asset.memory_mb, self.obj.get("memory")
        if mem and (current is None or abs(mem - current) * 100 > current * self.cfg.memory_tolerance_percent):
            self.add("memory", "missing" if current is None else "os", "Arbeitsspeicher (MB)", current, mem,
                     [self.update({"memory": mem}, "RAM setzen")], check_field="memory")

    def rename(self):
        current = self.obj.get("name") or ""
        if self.how == "name" or not current or short_name(current).lower() == self.asset.name.lower():
            return
        domain = current[len(short_name(current)):]  # Domain-Anteil (FQDN-Schreibweise) beibehalten
        new = self.asset.name + domain
        if self.index.name_taken(new, (self.endpoint, self.oid)):
            self.hints.append(f"Umbenennung zu '{new}' nicht möglich: Name ist in Netbox schon vergeben.")
            return
        self.add("name", "rename", "Name", current, new, [self.update({"name": new}, "Umbenennen")], check_field="name")

    def ids(self, available: set[str]):
        """Wazuh-Agent-ID und Intune-Geräte-ID in die Custom Fields schreiben (z.B. nach Neuinstallation
        des Agents eine neue ID). Feste Zuordnung für alle folgenden Läufe."""
        cf = self.cfg.custom_fields
        wanted = [(cf.wazuh_agent_id, "Wazuh-Agent-ID", (self.asset.sources.get("wazuh") or {}).get("agent_id")),
                  (cf.intune_device_id, "Intune-Geräte-ID", (self.asset.sources.get("intune") or {}).get("id"))]
        for name, label, value in wanted:
            if not value or name not in available:
                continue
            current = (self.obj.get("custom_fields") or {}).get(name)
            if str(current or "") == str(value):
                continue
            self.add(f"cf:{name}", "ids", label, current, value,
                     [self.update({"custom_fields": {name: str(value)}}, f"{label} setzen")],
                     check_field=f"custom_fields.{name}")

    def vcenter(self):
        """Cluster und ESXi-Host laut vCenter; bei VMs zusätzlich die virtuellen Disks."""
        vc = self.asset.sources.get("vcenter") or {}
        vcfg = self.ctx_vcenter
        if not vc or vcfg is None:
            return
        cluster = vc.get("cluster") or ""
        current_cluster = (self.obj.get("cluster") or {}).get("name") or ""
        data: dict = {}
        steps: list[dict] = []
        before, after = [current_cluster or "–"], [cluster or current_cluster or "–"]
        if cluster and cluster != current_cluster:
            from doku_agent.vcenter_inventory import cluster_steps
            site_id = comparable(self.obj.get("site")) or (self.nb.find_one("dcim/sites", slug=self.cfg.site) or {}).get("id")
            steps += cluster_steps(cluster, vcfg, site_id, self.nb, prefix="vc_")
            data["cluster"] = "$vc_cluster"
        if self.vm and vc.get("host"):
            from doku_agent.vcenter_inventory import host_device_for
            host = host_device_for(self.asset, self.index)
            current_host = (self.obj.get("device") or {}).get("name") or ""
            before.append(current_host or "–")
            if host is None:
                self.hints.append(f"ESXi-Host {vc['host']} ist nicht in Netbox – VM ohne Host-Zuordnung.")
                after.append(current_host or "–")
            elif ((host.get("cluster") or {}).get("name") or "") != (cluster or current_cluster):
                self.hints.append(f"ESXi-Host {host.get('name')} gehört in Netbox nicht zum Cluster "
                                  f"{cluster or current_cluster} – Host-Zuordnung folgt nach dessen Abgleich.")
                after.append(current_host or "–")
            else:
                after.append(host.get("name"))
                if (self.obj.get("device") or {}).get("id") != host["id"]:
                    data["device"] = host["id"]
            if "cluster" in data and "device" not in data and self.obj.get("device"):
                data["device"] = None  # alter Host liegt im alten Cluster – sonst lehnt Netbox ab
        if data:
            steps.append(self.update(data, "Cluster/Host setzen"))
            self.add("placement", "vcenter", "Cluster / Host" if self.vm else "Cluster", " / ".join(before),
                     " / ".join(after), steps, check_field="cluster")
        if self.vm and vcfg.virtual_disks and self.asset.disks:
            self._disks()

    def _disks(self):
        existing = {d.get("name"): d for d in self.nb.list("virtualization/virtual-disks", virtual_machine_id=self.oid)}
        for name, size in self.asset.disks:
            disk = existing.get(name)
            if disk is None:
                self.add(f"disk:{name}", "vcenter", f"Disk {name}", "", f"{size} MB",
                         [{"action": "create", "endpoint": "virtualization/virtual-disks",
                           "data": {"virtual_machine": self.oid, "name": name, "size": size},
                           "note": f"Disk {name}"}])
            elif abs((disk.get("size") or 0) - size) > max(size // 100, 1):  # mehr als 1 % Abweichung
                self.add(f"disk:{name}", "vcenter", f"Disk {name}", f"{disk.get('size')} MB", f"{size} MB",
                         [{"action": "update", "endpoint": "virtualization/virtual-disks", "id": disk["id"],
                           "data": {"size": size}, "note": f"Disk {name} vergrößern/verkleinern"}])
        for name in set(existing) - {n for n, _ in self.asset.disks}:
            self.hints.append(f"Disk {name} steht in Netbox, im vCenter aber nicht mehr (nur Hinweis).")

    # --- Netzwerk -----------------------------------------------------------

    def network(self):
        nb_ifaces = self.nb.list(self.if_endpoint, **self.filter)
        nb_ips = self.nb.list("ipam/ip-addresses", **self.filter) if self.cfg.assign_ips else []
        ip_by_host = {_host(ip.get("address", "")): ip for ip in nb_ips}
        had_ips = bool(nb_ips)
        iface_target: dict[str, tuple[object, str | None]] = {}  # Asset-Interface -> (Netbox-ID oder Ref, Änderung)
        seen_iface_ids: set[int] = set()

        for n, iface in enumerate(self.asset.interfaces):
            iface.mac = norm_mac(iface.mac)  # Schreibweise vereinheitlichen (Netbox liefert Großbuchstaben)
            by_mac = next((i for i in nb_ifaces if iface.mac and iface.mac in _iface_macs(i)), None)
            by_name = next((i for i in nb_ifaces if i.get("name", "").lower() == iface.name.lower()), None)
            if by_mac:
                iface_target[iface.name] = (by_mac["id"], None)
                seen_iface_ids.add(by_mac["id"])
            elif by_name:
                seen_iface_ids.add(by_name["id"])
                if iface.mac:
                    self._set_mac(by_name, iface.mac, _iface_macs(by_name))
                iface_target[iface.name] = (by_name["id"], None)
            else:
                iface_target[iface.name] = self._new_interface(n, iface)
            if self.cfg.assign_ips:
                self._ips(iface, iface_target[iface.name], ip_by_host, had_ips)

        if self.cfg.set_primary_ip:
            self._primary_ip(ip_by_host)
        if "wazuh" in self.asset.sources:
            self._report_stale(nb_ifaces, seen_iface_ids, ip_by_host)

    def _set_mac(self, nb_iface: dict, mac: str, old_macs: set[str]) -> str:
        key = f"mac:{nb_iface['name']}"
        category = "missing" if not old_macs else "network"
        label = f"MAC an {nb_iface['name']}"
        if self.nb.has_mac_objects:
            steps = [{"ref": f"{key}_mac", "action": "create", "endpoint": "dcim/mac-addresses",
                      "data": {"mac_address": mac, "assigned_object_type": self.obj_type,
                               "assigned_object_id": nb_iface["id"]}, "note": f"MAC {mac}"},
                     {"action": "update", "endpoint": self.if_endpoint, "id": nb_iface["id"],
                      "data": {"primary_mac_address": f"${key}_mac"}, "note": "Primäre MAC setzen"}]
            if old_macs:
                self.hints.append(f"{nb_iface['name']}: bisherige MAC {', '.join(sorted(old_macs))} bleibt als "
                                  "weiteres MAC-Objekt erhalten.")
        else:
            steps = [{"action": "update", "endpoint": self.if_endpoint, "id": nb_iface["id"],
                      "data": {"mac_address": mac}, "note": f"MAC {mac}"}]
            if old_macs:
                self.hints.append(f"{nb_iface['name']}: bisherige MAC {', '.join(sorted(old_macs))} wird ersetzt "
                                  "(Netbox vor 4.2 kennt nur eine MAC pro Interface).")
        return self.add(key, category, label, ", ".join(sorted(old_macs)), mac, steps)

    def _new_interface(self, n: int, iface) -> tuple[str, str]:
        base = f"iface:{iface.name}"
        data = {self.if_parent: self.oid, "name": iface.name}
        if not self.vm:
            data["type"] = "other"
        if iface.mac and not self.nb.has_mac_objects:
            data["mac_address"] = iface.mac
        steps = [{"ref": f"{base}_if", "action": "create", "endpoint": self.if_endpoint, "data": data,
                  "note": f"Interface {iface.name}"}]
        if iface.mac and self.nb.has_mac_objects:
            steps += [{"ref": f"{base}_mac", "action": "create", "endpoint": "dcim/mac-addresses",
                       "data": {"mac_address": iface.mac, "assigned_object_type": self.obj_type,
                                "assigned_object_id": f"${base}_if"}, "note": f"MAC {iface.mac}"},
                      {"action": "update", "endpoint": self.if_endpoint, "id": f"${base}_if",
                       "data": {"primary_mac_address": f"${base}_mac"}, "note": "Primäre MAC setzen"}]
        key = self.add(base, "missing", "Interface", "", f"{iface.name} ({iface.mac or 'ohne MAC'})", steps)
        return f"${base}_if", key

    def _ips(self, iface, target: tuple[object, str | None], ip_by_host: dict, had_ips: bool):
        if_id, if_change = target
        for cidr in iface.ips:
            host = _host(cidr)
            if host in ip_by_host:
                continue
            existing = self.nb.find_one("ipam/ip-addresses", address=host)
            assignment = {"assigned_object_type": self.obj_type, "assigned_object_id": if_id}
            key = f"ip:{host}"
            ref = f"{key}_ip"
            if existing and existing.get("assigned_object_id"):
                self.hints.append(f"IP {cidr} ist in Netbox einem anderen Objekt zugewiesen – nicht übernommen.")
                continue
            if existing:
                step = {"ref": ref, "action": "update", "endpoint": "ipam/ip-addresses", "id": existing["id"],
                        "data": assignment, "note": f"Bestehende IP {existing.get('address')} zuweisen"}
            else:
                step = {"ref": ref, "action": "create", "endpoint": "ipam/ip-addresses",
                        "data": {"address": cidr, "status": "active", **assignment}, "note": f"IP {cidr}"}
            self.add(key, "network" if had_ips else "missing", f"IP an {iface.name}", "", cidr, [step],
                     requires=[if_change] if if_change else [])
            ip_by_host[host] = {"ref": f"${ref}", "change": key, "address": cidr, "_new": True}

    def _primary_ip(self, ip_by_host: dict):
        asset_hosts = [_host(c) for i in self.asset.interfaces for c in i.ips if ":" not in c]
        if not asset_hosts:
            return
        desired = self.asset.primary_ip if self.asset.primary_ip in asset_hosts else asset_hosts[0]
        target = ip_by_host.get(desired)
        if target is None:  # IP konnte nicht übernommen werden (z.B. anderem Objekt zugewiesen)
            return
        current = self.obj.get("primary_ip4") or {}
        if _host(current.get("address", "")) == desired:
            return
        value = target["ref"] if target.get("_new") else target["id"]
        self.add("primary_ip4", "missing" if not current else "network", "Primäre IPv4", current.get("address"),
                 target.get("address"), [self.update({"primary_ip4": value}, "Primäre IPv4 setzen")],
                 requires=[target["change"]] if target.get("_new") else [], check_field="primary_ip4")

    def _report_stale(self, nb_ifaces: list[dict], seen_iface_ids: set[int], ip_by_host: dict):
        asset_hosts = {_host(c) for i in self.asset.interfaces for c in i.ips}
        for ip in [v for v in ip_by_host.values() if not v.get("_new")]:
            if ip.get("assigned_object_id") in seen_iface_ids and _host(ip.get("address", "")) not in asset_hosts:
                self.hints.append(f"IP {ip.get('address')} ist in Netbox zugewiesen, wird von Wazuh aber nicht "
                                  "mehr gemeldet (nur Hinweis, keine Änderung).")
        for iface in nb_ifaces:
            if iface["id"] not in seen_iface_ids and _iface_macs(iface):
                self.hints.append(f"Interface {iface.get('name')} ({', '.join(sorted(_iface_macs(iface)))}) wird "
                                  "von Wazuh nicht gemeldet (nur Hinweis, keine Änderung).")


def build_changes(asset: Asset, obj: dict, endpoint: str, how: str, nb: NetboxClient, cfg: NetboxConfig,
                  index: NetboxIndex, vcenter: VCenterConfig | None = None) -> tuple[list[Change], list[str]]:
    b = _Builder(asset, obj, endpoint, how, nb, cfg, index)
    b.ctx_vcenter = vcenter
    enabled = set(cfg.sync)
    if vcenter and "vcenter" in asset.sources:
        enabled.add("vcenter")
        b.vcenter()
    available = index.fields.available.get(endpoint, set())
    if available:
        enabled.add("ids")
        b.ids(available)
    b.serial()
    b.platform()
    b.device_type()
    b.vm_resources()
    if "rename" in enabled:
        b.rename()
    if enabled & {"missing", "network"}:
        b.network()
    changes = [c for c in b.changes if c.category in enabled]
    # Änderungen ohne erlaubte Voraussetzung entfallen – transitiv (IP am neuen Interface -> primäre IP).
    while True:
        kept = {c.key for c in changes}
        remaining = [c for c in changes if all(r in kept for r in c.requires)]
        if len(remaining) == len(changes):
            return changes, b.hints
        changes = remaining


def sync_summary(name: str, vm: bool, changes: list[Change]) -> str:
    text = f"{'VM' if vm else 'Gerät'} {name}: {', '.join(c.label for c in changes)}\n\n"
    return text + markdown.table(["Änderung", "Art", "Vorher", "Nachher"],
                                 [[c.label, CATEGORY_LABELS[c.category], c.before, c.after] for c in changes])


def doubtful_match(asset: Asset, obj: dict, how: str) -> bool:
    """Gleiche MAC, andere Seriennummer: vermutlich geteilte MAC (Dock, USB-Adapter) – nicht dieselbe Maschine."""
    nb_serial = norm_serial(obj.get("serial"))
    return how == "mac" and bool(asset.serial and nb_serial) and serial_key(nb_serial) != serial_key(netbox_serial(asset.serial))


def propose_sync(ctx: Context, asset: Asset, found: tuple[str, int, str], index: NetboxIndex) -> bool:
    """Legt einen Anpassungs-Vorschlag an (oder schließt einen erledigten). True, wenn Änderungen anstehen."""
    endpoint, oid, how = found
    obj = index.objects[(endpoint, oid)]
    dedup = f"netbox-sync:{endpoint}:{oid}"
    if ctx.store.is_ignored(dedup):
        return False
    if doubtful_match(asset, obj, how):
        ctx.log.warning("%s: MAC-Treffer auf %s, aber Seriennummer abweichend (%s/%s) – kein Abgleich",
                        asset.name, obj.get("name"), asset.serial, norm_serial(obj.get("serial")))
        return False
    changes, hints = build_changes(asset, obj, endpoint, how, ctx.netbox, ctx.cfg.netbox, index,
                                   ctx.cfg.vcenter if ctx.cfg.vcenter.enabled else None)
    if how == "mac":
        hints.insert(0, "Maschine nur über die MAC-Adresse erkannt – bitte prüfen, ob es wirklich dieselbe ist.")
    if not changes:
        ctx.store.close_pending(dedup, "Keine Abweichung mehr – Vorschlag erledigt.")
        return False
    vm = endpoint == "virtualization/virtual-machines"
    if detect_virtual(asset, ctx.cfg.netbox) != vm:
        hints.append("Quelle deutet auf " + ("eine VM" if not vm else "physische Hardware")
                     + f" hin, Netbox führt die Maschine als {'VM' if vm else 'Gerät'}.")
    name = obj.get("name") or f"#{oid}"
    ctx.store.add_proposal(
        "netbox_plan", f"Netbox: {name} anpassen ({len(changes)} Änderung{'en' if len(changes) != 1 else ''})",
        {"changes": [asdict(c) for c in changes], "hints": hints,
         "target": {"endpoint": endpoint, "id": oid, "name": name, "matched_by": how},
         "followup": {"id": oid, "kind": "vm" if vm else "device"}},
        summary=sync_summary(name, vm, changes), source="discovery", dedup_key=dedup,
    )
    return True
