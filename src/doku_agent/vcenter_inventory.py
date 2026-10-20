"""vCenter als Discovery-Quelle: ESXi-Hosts und VMs als Assets, Cluster-Schritte für Netbox-Pläne."""

from __future__ import annotations

import ipaddress

from doku_agent.config import VCenterConfig
from doku_agent.connectors.netbox import NetboxClient
from doku_agent.connectors.vcenter import vmware_serial
from doku_agent.context import Context
from doku_agent.discovery import Asset, Iface, netbox_slug, norm_mac, norm_serial, short_name, usable_ip


def _host_label(name: str) -> str:
    """ESXi-Hosts heißen im vCenter oft nach FQDN oder IP – IPs bleiben, FQDNs werden gekürzt."""
    try:
        ipaddress.ip_address(name)
        return name
    except ValueError:
        return short_name(name)


def vcenter_assets(ctx: Context) -> list[Asset]:
    cfg = ctx.cfg.vcenter
    vc = ctx.vcenter
    clusters = {c["cluster"]: c["name"] for c in vc.clusters()}
    host_cluster: dict[str, str] = {}
    for cid, cname in clusters.items():
        for h in vc.hosts(cid):
            host_cluster[h["host"]] = cname
    hosts = vc.hosts()
    host_names = {h["host"]: h["name"] for h in hosts}
    assets: list[Asset] = []
    if cfg.hosts:
        for h in hosts:
            hw = vc.host_hardware(h["host"])
            assets.append(Asset(
                name=_host_label(h["name"]), serial=norm_serial(hw.get("serial")), manufacturer=hw.get("vendor", ""),
                model=hw.get("model", ""), os_name="VMware ESXi", role=cfg.host_role,
                sources={"vcenter": {"host_id": h["host"], "cluster": host_cluster.get(h["host"], ""),
                                     "connection": h.get("connection_state"), "power_state": h.get("power_state")}},
            ))
    vm_host: dict[str, str] = {}
    for host_id in host_names:
        for v in vc.vms(host_id):
            vm_host[v["vm"]] = host_id
    for summary in vc.vms():
        powered_on = summary.get("power_state") == "POWERED_ON"
        if not powered_on and not cfg.powered_off:
            continue
        vm_id = summary["vm"]
        info = vc.vm(vm_id)
        ident = (vc.guest_identity(vm_id) or {}) if powered_on else {}
        guest_nets = (vc.guest_interfaces(vm_id) or []) if powered_on else []
        ips_by_mac: dict[str, list[str]] = {}
        for gnic in guest_nets:
            for addr in ((gnic.get("ip") or {}).get("ip_addresses") or []):
                ip = addr.get("ip_address") or ""
                if usable_ip(ip) and addr.get("prefix_length") is not None:
                    ips_by_mac.setdefault(norm_mac(gnic.get("mac_address")), []).append(f"{ip}/{addr['prefix_length']}")
        interfaces = []
        for nic in sorted((info.get("nics") or {}).values(), key=lambda n: n.get("label", "")):
            mac = norm_mac(nic.get("mac_address"))
            interfaces.append(Iface(name=nic.get("label") or mac or "nic", mac=mac, ips=ips_by_mac.get(mac, [])))
        disks = [(d.get("label") or f"Disk {key}", int(d.get("capacity") or 0) // 1_000_000)
                 for key, d in sorted((info.get("disks") or {}).items()) if d.get("capacity")]
        host_id = vm_host.get(vm_id, "")
        full_name = ((ident.get("full_name") or {}).get("default_message") or "").strip()
        cpus = (info.get("cpu") or {}).get("count") or summary.get("cpu_count")
        memory = (info.get("memory") or {}).get("size_mib") or summary.get("memory_size_mib")
        assets.append(Asset(
            name=short_name(ident.get("host_name")) or info.get("name") or summary.get("name") or vm_id,
            serial=vmware_serial((info.get("identity") or {}).get("bios_uuid", "")),
            os_name=full_name, cpu_cores=cpus, memory_mb=memory,
            primary_ip=ident.get("ip_address") if usable_ip(ident.get("ip_address") or "") else "",
            interfaces=interfaces, disks=disks, is_virtual=True,
            sources={"vcenter": {"vm_id": vm_id, "vm_name": info.get("name") or summary.get("name"),
                                 "power_state": summary.get("power_state"), "host_id": host_id,
                                 "host": _host_label(host_names.get(host_id, "")),
                                 "cluster": host_cluster.get(host_id, ""), "cpus": cpus, "memory_mb": memory}},
        ))
    return assets


def apply_precedence(asset: Asset) -> None:
    """Für VMs sind die im vCenter zugewiesenen Werte maßgeblich (das Gastsystem meldet weniger RAM)."""
    vc = asset.sources.get("vcenter") or {}
    if vc.get("vm_id"):
        asset.cpu_cores = vc.get("cpus") or asset.cpu_cores
        asset.memory_mb = vc.get("memory_mb") or asset.memory_mb
        asset.is_virtual = True


def cluster_steps(name: str, cfg: VCenterConfig, site_id: int, nb: NetboxClient, prefix: str = "") -> list[dict]:
    """Schritte: Clustertyp und Cluster sicherstellen (Refs <prefix>cluster_type, <prefix>cluster)."""
    tslug = netbox_slug(cfg.cluster_type)
    data = {"name": name, "type": f"${prefix}cluster_type", "status": "active"}
    if nb.version() >= (4, 2):
        data.update(scope_type="dcim.site", scope_id=site_id)
    else:
        data["site"] = site_id
    return [
        {"ref": f"{prefix}cluster_type", "action": "ensure", "endpoint": "virtualization/cluster-types",
         "lookup": {"slug": tslug}, "data": {"name": cfg.cluster_type, "slug": tslug},
         "note": f"Clustertyp '{cfg.cluster_type}'"},
        {"ref": f"{prefix}cluster", "action": "ensure", "endpoint": "virtualization/clusters", "lookup": {"name": name},
         "data": data, "note": f"Cluster '{name}'"},
    ]


def host_device_for(asset: Asset, index) -> dict | None:
    """Netbox-Gerät des ESXi-Hosts, auf dem die VM läuft (falls schon in Netbox)."""
    host = (asset.sources.get("vcenter") or {}).get("host") or ""
    key = index.names.get(host.lower()) if host else None
    if key and key[0] == "dcim/devices":
        return index.objects.get(key)
    return None
