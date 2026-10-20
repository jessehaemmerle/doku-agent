"""vCenter: Hosts und VMs als Discovery-Quelle, Cluster/Host-Zuordnung, virtuelle Disks, Abgleich."""

import httpx
import pytest

from doku_agent import discovery
from doku_agent.apply import apply_proposal
from doku_agent.connectors.netbox import NetboxClient
from doku_agent.connectors.vcenter import VCenterClient, vmware_serial
from doku_agent.discovery import Asset, Iface, NetboxIndex, netbox_serial
from doku_agent.egress import EgressGuard
from doku_agent.netbox_sync import propose_sync
from doku_agent.vcenter_inventory import apply_precedence, vcenter_assets
from tests.conftest import FakeNetbox

BIOS = "421a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8"


def _vm(name, power="POWERED_ON", cpus=4, mem=8192, mac="00:50:56:aa:bb:01", disks=((2000, 53687091200),),
        bios=None):
    return {"name": name, "power_state": power, "guest_OS": "UBUNTU_64", "guest_os": "UBUNTU_64",
            "identity": {"name": name, "bios_uuid": bios or (BIOS if name == "web01" else "421a2b3c-0000-0000-0000-000000000002"),
                         "instance_uuid": "x"},
            "cpu": {"count": cpus}, "memory": {"size_mib": mem},
            "nics": {"4000": {"label": "Network adapter 1", "mac_address": mac, "state": "CONNECTED"}},
            "disks": {str(k): {"label": f"Hard disk {i}", "capacity": cap} for i, (k, cap) in enumerate(disks, 1)}}


class FakeVCenter:
    def __init__(self):
        self.vms = {"vm-1": _vm("web01", disks=((2000, 53687091200), (2001, 107374182400))),
                    "vm-2": _vm("old01", power="POWERED_OFF", mac="00:50:56:aa:bb:02")}
        self.vm_host = {"vm-1": "host-1", "vm-2": "host-1"}
        self.hosts = {"host-1": {"host": "host-1", "name": "esx01.firma.local", "connection_state": "CONNECTED",
                                 "power_state": "POWERED_ON"}}
        self.host_cluster = {"host-1": "domain-c1"}
        self.vijson = True
        self.guest_host = "web01.firma.local"
        self.host_serial = "ESXSER1"
        self.requests = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        path, q = request.url.path, request.url.params
        self.requests.append(path)
        if path == "/api/session":
            assert request.headers["authorization"].startswith("Basic ")
            return httpx.Response(201, json="tok-123")
        if path.startswith("/sdk/vim25/"):
            if not self.vijson:
                return httpx.Response(404, text="Not Found")
            if path.endswith("/ServiceInstance/ServiceInstance/content"):
                return httpx.Response(200, json={"sessionManager": {"_typeName": "ManagedObjectReference",
                                                                    "type": "SessionManager", "value": "SessionManager"}})
            if path.endswith("/SessionManager/SessionManager/Login"):
                return httpx.Response(200, json={"key": "vim-tok"}, headers={"vmware-api-session-id": "vim-tok"})
            assert request.headers["vmware-api-session-id"] == "vim-tok"
            return httpx.Response(200, json={"systemInfo": {"vendor": "Dell Inc.", "model": "PowerEdge R750",
                                                            "uuid": "u", "serialNumber": self.host_serial}})
        assert request.headers["vmware-api-session-id"] == "tok-123"
        if path == "/api/vcenter/cluster":
            return httpx.Response(200, json=[{"cluster": "domain-c1", "name": "Cluster-HQ", "ha_enabled": True}])
        if path == "/api/vcenter/host":
            hosts = [h for hid, h in self.hosts.items() if not q.get("clusters") or self.host_cluster.get(hid) == q["clusters"]]
            return httpx.Response(200, json=hosts)
        if path == "/api/vcenter/vm":
            ids = [v for v in self.vms if not q.get("hosts") or self.vm_host.get(v) == q["hosts"]]
            return httpx.Response(200, json=[{"vm": v, "name": self.vms[v]["name"], "power_state": self.vms[v]["power_state"],
                                              "cpu_count": 1, "memory_size_mib": 1} for v in ids])
        parts = path.split("/")
        vm = self.vms.get(parts[4]) if len(parts) > 4 else None
        if vm is None:
            return httpx.Response(404, json={"error_type": "NOT_FOUND"})
        if path.endswith("/guest/identity"):
            if vm["power_state"] != "POWERED_ON":
                return httpx.Response(503, json={"error_type": "SERVICE_UNAVAILABLE"})
            return httpx.Response(200, json={"host_name": self.guest_host, "ip_address": "10.10.5.21",
                                             "full_name": {"default_message": "Ubuntu Linux (64-bit)"}, "family": "LINUX"})
        if path.endswith("/guest/networking/interfaces"):
            return httpx.Response(200, json=[{"mac_address": "00:50:56:aa:bb:01", "nic": "4000", "ip": {"ip_addresses": [
                {"ip_address": "10.10.5.21", "prefix_length": 24, "state": "PREFERRED"},
                {"ip_address": "fe80::1", "prefix_length": 64, "state": "PREFERRED"}]}}])
        return httpx.Response(200, json=vm)


@pytest.fixture
def env(ctx):
    nbf = FakeNetbox()
    ctx.__dict__["netbox"] = NetboxClient(ctx.cfg.netbox, EgressGuard.from_config(ctx.cfg),
                                          transport=httpx.MockTransport(nbf.handler))
    nbf.add("dcim/sites", {"slug": "hq", "name": "HQ"})
    nbf.add("extras/custom-fields", {"name": "unrelated", "type": {"value": "text"}, "object_types": []})
    ctx.cfg.netbox.custom_fields.enabled = False
    fake = FakeVCenter()
    ctx.cfg.vcenter.enabled = True
    ctx.cfg.vcenter.url = "https://vc.test"
    ctx.cfg.wazuh.enabled = False
    ctx.__dict__["vcenter"] = VCenterClient(ctx.cfg.vcenter, EgressGuard({"vc.test"}),
                                            transport=httpx.MockTransport(fake.handler))
    return ctx, nbf, fake


def test_vmware_serial_matches_guest_format():
    assert vmware_serial(BIOS) == "VMware-42 1a 2b 3c 4d 5e 6f 70-81 92 a3 b4 c5 d6 e7 f8"
    assert vmware_serial("kaputt") == ""


def test_vcenter_assets(env):
    ctx, _, fake = env
    assets = {a.name: a for a in vcenter_assets(ctx)}
    host, web, old = assets["esx01"], assets["web01"], assets["old01"]
    assert (host.serial, host.manufacturer, host.model, host.role) == ("ESXSER1", "Dell Inc.", "PowerEdge R750", "hypervisor")
    assert host.sources["vcenter"]["cluster"] == "Cluster-HQ" and not host.is_virtual
    assert web.serial == vmware_serial(BIOS) and web.is_virtual and web.os_name == "Ubuntu Linux (64-bit)"
    assert web.interfaces[0].ips == ["10.10.5.21/24"] and web.primary_ip == "10.10.5.21"  # fe80:: verworfen
    assert web.disks == [("Hard disk 1", 53687), ("Hard disk 2", 107374)]
    assert web.sources["vcenter"]["host"] == "esx01" and web.sources["vcenter"]["cluster"] == "Cluster-HQ"
    assert old.sources["vcenter"]["power_state"] == "POWERED_OFF" and old.interfaces[0].ips == []
    assert not any(r.endswith("/vm-2/guest/identity") for r in fake.requests)  # ausgeschaltet: keine Gastabfrage
    ctx.cfg.vcenter.powered_off = False
    assert "old01" not in {a.name for a in vcenter_assets(ctx)}


def test_without_vijson_hosts_have_no_hardware(env):
    ctx, _, fake = env
    fake.vijson = False
    host = next(a for a in vcenter_assets(ctx) if a.name == "esx01")
    assert host.serial == "" and host.model == ""


def test_discovery_creates_cluster_host_vm_and_disks(env):
    ctx, nbf, fake = env
    stats = discovery.run_discovery(ctx)
    assert stats["vorgeschlagen"] == 3
    props = {p.title: p for p in ctx.store.list_proposals("pending")}
    host_prop = props["Netbox: Gerät esx01 anlegen"]
    assert any(s["endpoint"] == "virtualization/clusters" for s in host_prop.payload["steps"])
    vm_prop = props["Netbox: VM web01 anlegen"]
    assert any("ESXi-Host esx01" in h for h in vm_prop.payload["hints"])  # Host noch nicht in Netbox
    assert apply_proposal(ctx, host_prop.id) == "applied"
    host = next(d for d in nbf.objects["dcim/devices"].values() if d["name"] == "esx01")
    cluster = next(iter(nbf.objects["virtualization/clusters"].values()))
    assert cluster["name"] == "Cluster-HQ" and cluster["scope_type"] == "dcim.site" and host["cluster"] == cluster["id"]
    role = nbf.objects["dcim/device-roles"][host["role"]]
    assert role["slug"] == "hypervisor" and host["serial"] == "ESXSER1"

    # Netbox liefert Fremdschlüssel verschachtelt – im Fake von Hand nachbilden
    host["cluster"] = {"id": cluster["id"], "name": cluster["name"]}
    dtype = nbf.objects["dcim/device-types"][host["device_type"]]
    host["device_type"] = {"id": dtype["id"], "model": dtype["model"],
                           "manufacturer": {"id": dtype["manufacturer"], "name": "Dell Inc."}}
    host["platform"] = {"id": host["platform"], "slug": "vmware-esxi", "name": "VMware ESXi"}
    discovery.run_discovery(ctx)  # VM-Vorschlag wird mit Host-Zuordnung neu berechnet
    vm_prop = ctx.store.get_proposal(vm_prop.id)
    vm_step = next(s for s in vm_prop.payload["steps"] if s.get("ref") == "dev")
    assert vm_step["data"]["device"] == host["id"] and vm_step["data"]["cluster"] == "$cluster"
    assert vm_step["data"]["vcpus"] == 4 and vm_step["data"]["memory"] == 8192
    assert apply_proposal(ctx, vm_prop.id) == "applied"
    vm = next(v for v in nbf.objects["virtualization/virtual-machines"].values() if v["name"] == "web01")
    disks = sorted((d["name"], d["size"]) for d in nbf.objects["virtualization/virtual-disks"].values())
    assert disks == [("Hard disk 1", 53687), ("Hard disk 2", 107374)] and vm["serial"] == netbox_serial(vmware_serial(BIOS))


def test_sync_detects_move_and_disk_growth(env):
    ctx, nbf, fake = env
    cluster_a = nbf.add("virtualization/clusters", {"name": "Cluster-Alt"})
    vm = nbf.add("virtualization/virtual-machines", {
        "name": "web01", "serial": vmware_serial(BIOS), "vcpus": 4, "memory": 8192, "platform": None,
        "cluster": {"id": cluster_a["id"], "name": "Cluster-Alt"}, "device": None, "primary_ip4": None})
    nbf.add("virtualization/virtual-disks", {"virtual_machine": vm["id"], "name": "Hard disk 1", "size": 20000})
    host = nbf.add("dcim/devices", {"name": "esx01", "cluster": {"id": 77, "name": "Cluster-HQ"}})
    asset = next(a for a in vcenter_assets(ctx) if a.name == "web01")
    apply_precedence(asset)
    index = NetboxIndex(ctx.netbox)
    assert propose_sync(ctx, asset, index.find(asset), index)
    changes = {c["key"]: c for c in ctx.store.list_proposals("pending")[0].payload["changes"]}
    assert changes["placement"]["before"] == "Cluster-Alt / –" and changes["placement"]["after"] == "Cluster-HQ / esx01"
    update = changes["placement"]["steps"][-1]
    assert update["data"] == {"cluster": "$vc_cluster", "device": host["id"]}
    assert changes["disk:Hard disk 1"]["after"] == "53687 MB" and "disk:Hard disk 2" in changes
    assert changes["placement"]["category"] == "vcenter"


def test_wazuh_and_vcenter_merge_with_vcenter_resources(env):
    w = Asset(name="web01", serial=vmware_serial(BIOS), os_name="Ubuntu", cpu_cores=2, memory_mb=7900,
              interfaces=[Iface("ens160", "00:50:56:AA:BB:01", ["10.10.5.21/24"])], sources={"wazuh": {"agent_id": "1"}})
    v = next(a for a in vcenter_assets(env[0]) if a.name == "web01")
    merged = discovery.merge_assets([w, v])
    assert len(merged) == 1
    apply_precedence(merged[0])
    m = merged[0]
    assert (m.os_name, m.cpu_cores, m.memory_mb) == ("Ubuntu", 4, 8192)
    assert [i.name for i in m.interfaces] == ["ens160"] and m.disks and set(m.sources) == {"wazuh", "vcenter"}


def test_long_vmware_serial_fits_netbox_and_still_matches(env):
    ctx, nbf, fake = env
    from doku_agent.discovery import build_plan, serial_key
    asset = next(a for a in vcenter_assets(ctx) if a.name == "web01")
    steps, _ = build_plan(asset, ctx.netbox, ctx.cfg.netbox, 1)
    vm_step = next(s for s in steps if s.get("ref") == "dev")
    assert len(vm_step["data"]["serial"]) <= 50 and " " not in vm_step["data"]["serial"]
    nbf.add("virtualization/virtual-machines", {"name": "anders", "serial": vm_step["data"]["serial"]})
    assert NetboxIndex(ctx.netbox).find(asset)[2] == "serial"  # gekürzte Netbox-Seriennummer wird erkannt
    assert serial_key(asset.serial) == serial_key(vm_step["data"]["serial"])
    # Dedup-Schlüssel (Ignorierliste, offene Vorschläge) bleibt wie vor der Kürzung
    assert asset.key == f"serial:{asset.serial.upper()}" and " " in asset.key
