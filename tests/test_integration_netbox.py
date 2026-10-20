"""Integrationstest gegen ein echtes Netbox 4.x (läuft nur mit DOKU_IT_NETBOX_URL und DOKU_IT_NETBOX_TOKEN).

Legt einen Test-Standort sowie ein Gerät und eine VM an und räumt danach wieder auf.
"""

import logging
import os
import uuid

import pytest

from doku_agent.connectors.netbox import NetboxClient
from doku_agent.discovery import Asset, Iface, NetboxIndex, build_plan
from doku_agent.egress import EgressGuard
from doku_agent.generators.netbox_docs import document_object
from doku_agent.netbox_plan import execute_plan
from tests.conftest import make_config

URL, TOKEN = os.environ.get("DOKU_IT_NETBOX_URL"), os.environ.get("DOKU_IT_NETBOX_TOKEN")
pytestmark = pytest.mark.skipif(not (URL and TOKEN), reason="kein Test-Netbox konfiguriert")
log = logging.getLogger("it")


@pytest.fixture
def nb(tmp_path):
    cfg = make_config(tmp_path, netbox={"url": URL, "token": TOKEN})
    client = NetboxClient(cfg.netbox, EgressGuard.from_config(cfg))
    slug = f"it-{uuid.uuid4().hex[:6]}"
    site = client.create("dcim/sites", {"name": slug, "slug": slug, "status": "active"})
    created = []
    yield client, cfg, site, created
    for endpoint, oid in reversed(created):
        try:
            client.delete(endpoint, oid)
        except Exception:
            pass
    client.delete("dcim/sites", site["id"])


def test_discovery_plan_against_real_netbox(nb, ctx):
    client, cfg, site, created = nb
    suffix = uuid.uuid4().hex[:4].upper()
    mac = f"02:00:00:00:{suffix[:2]}:{suffix[2:]}"
    asset = Asset(name=f"srv-it-{suffix.lower()}", serial=f"IT{suffix}", manufacturer="Dell Inc.",
                  model="PowerEdge R650", os_name="Ubuntu", os_version="24.04", primary_ip="10.99.0.5",
                  interfaces=[Iface("eth0", mac, [f"10.99.{int(suffix[:2], 16)}.{int(suffix[2:], 16) % 250 + 1}/24"])],
                  sources={"wazuh": {"agent_id": "001"}})
    asset.primary_ip = asset.interfaces[0].ips[0].split("/")[0]
    steps, hints = build_plan(asset, client, cfg.netbox, site["id"])
    refs = execute_plan(client, steps, log)
    created.extend(refs[r] for r in ("dev",))
    dev = client.get("dcim/devices", refs["dev"][1])
    assert dev["name"] == asset.name and dev["serial"] == asset.serial
    assert dev["role"]["slug"] == "server" and dev["platform"]["slug"] == "ubuntu"
    assert dev["primary_ip4"]["address"] == asset.interfaces[0].ips[0]
    iface = client.list("dcim/interfaces", device_id=dev["id"])[0]
    assert (iface.get("mac_address") or iface["primary_mac_address"]["mac_address"]).upper() == mac

    # Ein zweiter Discovery-Lauf erkennt die Maschine wieder (Seriennummer, Name, MAC)
    index = NetboxIndex(client)
    assert index.match(Asset(name="anders", serial=asset.serial))
    assert index.match(Asset(name=asset.name.upper()))
    assert index.match(Asset(name="x", interfaces=[Iface("e", mac)]))

    # Steckbrief aus echten Netbox-Daten (Wiki ist hier der Fake aus conftest)
    ctx.__dict__["netbox"] = client
    prop = ctx.store.get_proposal(document_object(ctx, "device", dev["id"]))
    content = prop.payload["content"]
    assert asset.serial in content and "PowerEdge R650" in content and mac in content.upper()
    for ip in client.list("ipam/ip-addresses", device_id=dev["id"]):
        created.insert(0, ("ipam/ip-addresses", ip["id"]))


def test_vm_plan_against_real_netbox(nb):
    client, cfg, site, created = nb
    suffix = uuid.uuid4().hex[:4]
    asset = Asset(name=f"vm-it-{suffix}", serial=f"VMware-56 4d {suffix}", os_name="Microsoft Windows Server 2022",
                  cpu_cores=4, memory_mb=8192, interfaces=[Iface("Ethernet0", f"00:50:56:00:{suffix[:2]}:{suffix[2:]}")])
    steps, _ = build_plan(asset, client, cfg.netbox, site["id"])
    refs = execute_plan(client, steps, log)
    created.append(refs["dev"])
    vm = client.get("virtualization/virtual-machines", refs["dev"][1])
    assert vm["vcpus"] == 4 and vm["memory"] == 8192 and vm["role"]["slug"] == "server"
    assert client.list("virtualization/interfaces", virtual_machine_id=vm["id"])[0]["name"] == "Ethernet0"


def test_rollback_on_real_validation_error(nb):
    client, cfg, site, created = nb
    name = f"rb-{uuid.uuid4().hex[:6]}"
    role = client.list("dcim/device-roles", slug="server") or [client.create(
        "dcim/device-roles", {"name": "Server", "slug": "server", "color": "9e9e9e"})]
    mfr = client.list("dcim/manufacturers", slug="it-test") or [client.create(
        "dcim/manufacturers", {"name": "IT-Test", "slug": "it-test"})]
    dtype = client.list("dcim/device-types", slug="it-box") or [client.create(
        "dcim/device-types", {"manufacturer": mfr[0]["id"], "model": "IT-Box", "slug": "it-box"})]
    steps = [
        {"ref": "dev", "action": "create", "endpoint": "dcim/devices",
         "data": {"name": name, "site": site["id"], "role": role[0]["id"], "device_type": dtype[0]["id"]}},
        {"ref": "if0", "action": "create", "endpoint": "dcim/interfaces",
         "data": {"device": "$dev", "name": "eth0", "type": "other"}},
        {"action": "create", "endpoint": "ipam/ip-addresses", "data": {"address": "999.1.1.1/24"}},
    ]
    with pytest.raises(Exception, match="Rollback"):
        execute_plan(client, steps, log)
    assert client.list("dcim/devices", name=name) == []


def test_sync_existing_machine_against_real_netbox(nb, ctx):
    from doku_agent.apply import apply_proposal
    from doku_agent.netbox_sync import propose_sync

    client, cfg, site, created = nb
    ctx.__dict__["netbox"] = client
    ctx.cfg.netbox = cfg.netbox
    sfx = uuid.uuid4().hex[:4]
    octet = int(sfx[:2], 16) % 200 + 10
    asset = Asset(name=f"sync-{sfx}", serial=f"SY{sfx}", os_name="Ubuntu", primary_ip=f"10.98.{octet}.10",
                  interfaces=[Iface("eth0", f"02:00:00:01:{sfx[:2]}:{sfx[2:]}", [f"10.98.{octet}.10/24"])],
                  sources={"wazuh": {"agent_id": "042"}})
    refs = execute_plan(client, build_plan(asset, client, cfg.netbox, site["id"])[0], log)
    dev_id = refs["dev"][1]
    created.append(("dcim/devices", dev_id))

    # Abweichungen: OS-Upgrade, IP-Wechsel, zweite Netzwerkkarte, neuer Hostname
    changed = Asset(name=f"sync-neu-{sfx}", serial=asset.serial, os_name="Ubuntu 24.04", primary_ip=f"10.98.{octet}.20",
                    interfaces=[Iface("eth0", asset.interfaces[0].mac, [f"10.98.{octet}.20/24"]),
                                Iface("eth1", f"02:00:00:02:{sfx[:2]}:{sfx[2:]}")],
                    sources={"wazuh": {"agent_id": "042"}})
    index = NetboxIndex(client)
    assert propose_sync(ctx, changed, index.find(changed), index)
    prop = ctx.store.list_proposals("pending")[0]
    labels = {c["label"]: c for c in prop.payload["changes"]}
    assert set(labels) == {"Plattform", "Name", "Interface", "IP an eth0", "Primäre IPv4"}
    assert any(f"10.98.{octet}.10/24" in h for h in prop.payload["hints"])  # alte IP nur gemeldet

    keep = [c["key"] for c in prop.payload["changes"] if c["label"] != "Name"]
    ctx.store.update_proposal(prop.id, payload={**prop.payload, "selected": keep})
    assert apply_proposal(ctx, prop.id) == "applied"
    dev = client.get("dcim/devices", dev_id)
    assert dev["name"] == asset.name  # Umbenennung abgewählt
    assert dev["platform"]["slug"] == "ubuntu-24-04"
    assert dev["primary_ip4"]["address"] == f"10.98.{octet}.20/24"
    ifaces = {i["name"]: i for i in client.list("dcim/interfaces", device_id=dev_id)}
    assert ifaces["eth1"]["primary_mac_address"]["mac_address"].upper() == changed.interfaces[1].mac
    hosts = {ip["address"] for ip in client.list("ipam/ip-addresses", device_id=dev_id)}
    assert hosts == {f"10.98.{octet}.10/24", f"10.98.{octet}.20/24"}  # alte IP bleibt (nur melden)
    created[:0] = [("ipam/ip-addresses", ip["id"]) for ip in client.list("ipam/ip-addresses", device_id=dev_id)]

    # Nächster Lauf schlägt nur noch die Umbenennung vor; Name wird vorher von Hand geändert -> übersprungen
    index = NetboxIndex(client)
    assert propose_sync(ctx, changed, index.find(changed), index)
    prop = ctx.store.list_proposals("pending")[0]
    assert [c["label"] for c in prop.payload["changes"]] == ["Name"]
    client.update("dcim/devices", dev_id, {"name": f"von-hand-{sfx}"})
    with pytest.raises(Exception, match="Nichts übernommen"):
        apply_proposal(ctx, prop.id)
    assert client.get("dcim/devices", dev_id)["name"] == f"von-hand-{sfx}"


def test_update_rollback_against_real_netbox(nb):
    client, cfg, site, created = nb
    role = client.list("dcim/device-roles", slug="server") or [client.create(
        "dcim/device-roles", {"name": "Server", "slug": "server", "color": "9e9e9e"})]
    mfr = client.list("dcim/manufacturers", slug="it-test") or [client.create(
        "dcim/manufacturers", {"name": "IT-Test", "slug": "it-test"})]
    dtype = client.list("dcim/device-types", slug="it-box") or [client.create(
        "dcim/device-types", {"manufacturer": mfr[0]["id"], "model": "IT-Box", "slug": "it-box"})]
    dev = client.create("dcim/devices", {"name": f"rb2-{uuid.uuid4().hex[:6]}", "site": site["id"], "serial": "ALT",
                                         "role": role[0]["id"], "device_type": dtype[0]["id"]})
    created.append(("dcim/devices", dev["id"]))
    steps = [{"action": "update", "endpoint": "dcim/devices", "id": dev["id"], "data": {"serial": "NEU"}},
             {"action": "create", "endpoint": "ipam/ip-addresses", "data": {"address": "999.1.1.1/24"}}]
    with pytest.raises(Exception, match="zurückgesetzt"):
        execute_plan(client, steps, log)
    assert client.get("dcim/devices", dev["id"])["serial"] == "ALT"


def test_custom_fields_against_real_netbox(nb, ctx):
    from doku_agent import discovery, netbox_fields
    from doku_agent.apply import apply_proposal
    from doku_agent.netbox_sync import propose_sync

    client, cfg, site, created = nb
    ctx.__dict__["netbox"] = client
    sfx = uuid.uuid4().hex[:6]
    cf = cfg.netbox.custom_fields
    cf.wazuh_agent_id, cf.intune_device_id, cf.last_seen = f"it_wazuh_{sfx}", f"it_intune_{sfx}", f"it_seen_{sfx}"
    ctx.cfg.netbox = cfg.netbox
    fields = []
    try:
        # 1. Felder fehlen -> Vorschlag -> nach Freigabe angelegt
        fs = netbox_fields.status(client, cf)
        assert len(fs.steps) == 3
        assert apply_proposal(ctx, netbox_fields.propose_setup(ctx, fs)) == "applied"
        fields = [f for f in client.list("extras/custom-fields") if f["name"].endswith(sfx)]
        assert {f["name"] for f in fields} == {cf.wazuh_agent_id, cf.intune_device_id, cf.last_seen}
        assert all(set(f["object_types"]) == {"dcim.device", "virtualization.virtualmachine"} for f in fields)
        fs = netbox_fields.status(client, cf)
        assert fs.steps == [] and fs.available["dcim/devices"] == {cf.wazuh_agent_id, cf.intune_device_id, cf.last_seen}

        # 2. Neue Maschine bekommt IDs und "zuletzt gesehen" gleich beim Anlegen
        octet = int(sfx[:2], 16) % 200 + 10
        asset = Asset(name=f"cf-{sfx}", serial=f"CF{sfx}", os_name="Ubuntu", primary_ip=f"10.97.{octet}.10",
                      interfaces=[Iface("eth0", f"02:00:00:03:{sfx[:2]}:{sfx[2:4]}", [f"10.97.{octet}.10/24"])],
                      sources={"wazuh": {"agent_id": f"9{sfx[:3]}", "last_seen": "2026-10-18T10:00:00Z"}})
        values = {ep: netbox_fields.values_for(asset.sources, cf, names, "UTC") for ep, names in fs.available.items()}
        refs = execute_plan(client, build_plan(asset, client, cfg.netbox, site["id"], values)[0], log)
        dev_id = refs["dev"][1]
        created.append(("dcim/devices", dev_id))
        created[:0] = [("ipam/ip-addresses", ip["id"]) for ip in client.list("ipam/ip-addresses", device_id=dev_id)]
        dev = client.get("dcim/devices", dev_id)
        assert dev["custom_fields"][cf.wazuh_agent_id] == f"9{sfx[:3]}"
        assert dev["custom_fields"][cf.last_seen] == "2026-10-18"

        # 3. Wiedererkennung über die Agent-ID trotz neuem Namen und ohne Seriennummer
        moved = Asset(name=f"ganz-anders-{sfx}", sources={"wazuh": {"agent_id": f"9{sfx[:3]}",
                                                                      "last_seen": "2026-10-20T08:00:00Z"},
                                                            "intune": {"id": f"intune-{sfx}"}})
        index = NetboxIndex(client, cf)
        found = index.find(moved)
        assert found == ("dcim/devices", dev_id, "wazuh_id")

        # 4. "zuletzt gesehen" direkt, andere Custom Fields bleiben erhalten (PATCH führt zusammen)
        assert discovery.update_last_seen(ctx, moved, found, index)
        dev = client.get("dcim/devices", dev_id)
        assert dev["custom_fields"][cf.last_seen] == "2026-10-20"
        assert dev["custom_fields"][cf.wazuh_agent_id] == f"9{sfx[:3]}"

        # 5. Intune-ID als freigebbare Änderung; Umbenennung abgewählt
        assert propose_sync(ctx, moved, found, NetboxIndex(client, cf))
        prop = ctx.store.list_proposals("pending")[0]
        keys = {c["key"] for c in prop.payload["changes"]}
        assert f"cf:{cf.intune_device_id}" in keys and "name" in keys
        ctx.store.update_proposal(prop.id, payload={**prop.payload, "selected": [f"cf:{cf.intune_device_id}"]})
        assert apply_proposal(ctx, prop.id) == "applied"
        dev = client.get("dcim/devices", dev_id)
        assert dev["custom_fields"][cf.intune_device_id] == f"intune-{sfx}" and dev["name"] == asset.name
        assert dev["custom_fields"][cf.last_seen] == "2026-10-20"

        # 6. Rollback setzt nur das geänderte Custom Field zurück
        steps = [{"action": "update", "endpoint": "dcim/devices", "id": dev_id,
                  "data": {"custom_fields": {cf.wazuh_agent_id: "kaputt"}}},
                 {"action": "create", "endpoint": "ipam/ip-addresses", "data": {"address": "999.1.1.1/24"}}]
        with pytest.raises(Exception, match="zurückgesetzt"):
            execute_plan(client, steps, log)
        dev = client.get("dcim/devices", dev_id)
        assert dev["custom_fields"][cf.wazuh_agent_id] == f"9{sfx[:3]}"
        assert dev["custom_fields"][cf.intune_device_id] == f"intune-{sfx}"
    finally:
        for endpoint, oid in reversed(created):
            try:
                client.delete(endpoint, oid)
            except Exception:
                pass
        created.clear()
        for f in fields or [f for f in client.list("extras/custom-fields") if f["name"].endswith(sfx)]:
            client.delete("extras/custom-fields", f["id"])


def _cleanup(client, items):
    for endpoint, oid in items:
        try:
            client.delete(endpoint, oid)
        except Exception:
            pass


def test_fortigate_to_real_netbox(nb, ctx):
    import httpx

    from doku_agent.apply import apply_proposal
    from doku_agent.config import FortiGateDevice
    from doku_agent.connectors.fortigate import FortiGateClient
    from doku_agent.fortigate_netbox import propose_fortigate
    from tests import test_fortigate as tf

    client, cfg, site, created = nb
    ctx.__dict__["netbox"] = client
    ctx.cfg.netbox.site = site["slug"]
    sfx = uuid.uuid4().hex[:6]
    tables = {k: v for k, v in tf.TABLES.items()}
    octet = int(sfx[:2], 16) % 200 + 20
    tables["cmdb/system/global"] = {"hostname": f"fgt-{sfx}"}
    tables["cmdb/system/interface"] = [
        {"name": "internal", "vdom": "root", "ip": f"10.{octet}.0.1 255.255.255.0", "type": "hard-switch", "role": "lan",
         "status": "up"},
        {"name": "vlan77", "vdom": "root", "ip": f"10.{octet}.77.1 255.255.255.0", "type": "vlan", "vlanid": 77,
         "interface": "internal", "role": "dmz", "status": "up", "alias": "DMZ-Test"},
        {"name": "agg1", "vdom": "root", "type": "aggregate", "member": [{"interface-name": "port7"}], "status": "up"},
        {"name": "port7", "vdom": "root", "type": "physical", "status": "up"},
    ]
    original, tf.TABLES = tf.TABLES, tables
    fake = tf.FakeFortiGate()
    dev = FortiGateDevice(name="fw-it", url=f"https://10.{octet}.0.1", token="fgt-token")
    ctx.cfg.fortigate.enabled = True
    ctx.cfg.fortigate.devices = [dev]
    ctx._clients["fortigate:fw-it"] = FortiGateClient(dev, EgressGuard({f"10.{octet}.0.1"}),
                                                      transport=httpx.MockTransport(fake.handler))
    cleanup = []
    try:
        fake_serial = f"FGTIT{sfx}"
        orig_handler = fake.handler

        def handler(request):  # eigene Seriennummer je Lauf
            resp = orig_handler(request)
            if resp.status_code == 200:
                data = resp.json()
                data["serial"] = fake_serial
                return httpx.Response(200, json=data)
            return resp

        ctx._clients["fortigate:fw-it"] = FortiGateClient(dev, EgressGuard({f"10.{octet}.0.1"}),
                                                          transport=httpx.MockTransport(handler))
        pid = propose_fortigate(ctx, dev)
        assert apply_proposal(ctx, pid) == "applied"
        fw = client.find_one("dcim/devices", serial=fake_serial)
        cleanup.append(("dcim/devices", fw["id"]))
        ifaces = {i["name"]: i for i in client.list("dcim/interfaces", device_id=fw["id"])}
        vlan = client.find_one("ipam/vlans", vid=77, site_id=site["id"])
        prefixes = {p["prefix"]: p for p in client.list("ipam/prefixes", q=f"10.{octet}.")}
        ips = client.list("ipam/ip-addresses", device_id=fw["id"])
        cleanup[:0] = [("ipam/ip-addresses", i["id"]) for i in ips]
        cleanup += [("ipam/prefixes", p["id"]) for p in prefixes.values()] + [("ipam/vlans", vlan["id"])]
        assert ifaces["vlan77"]["parent"]["id"] == ifaces["internal"]["id"]
        assert ifaces["vlan77"]["mode"]["value"] == "access" and ifaces["vlan77"]["untagged_vlan"]["id"] == vlan["id"]
        assert ifaces["port7"]["lag"]["id"] == ifaces["agg1"]["id"] and ifaces["agg1"]["type"]["value"] == "lag"
        assert ifaces["internal"]["type"]["value"] == "bridge"
        dmz = prefixes[f"10.{octet}.77.0/24"]
        assert dmz["vlan"]["id"] == vlan["id"] and dmz["scope_type"] == "dcim.site" and dmz["scope_id"] == site["id"]
        assert fw["primary_ip4"]["address"] == f"10.{octet}.0.1/24"
        assert propose_fortigate(ctx, dev) is None  # zweiter Lauf: nichts zu tun
    finally:
        tf.TABLES = original
        _cleanup(client, cleanup)


def test_vcenter_to_real_netbox(nb, ctx):
    import httpx

    from doku_agent import discovery
    from doku_agent.apply import apply_proposal
    from doku_agent.connectors.vcenter import VCenterClient, vmware_serial
    from doku_agent.discovery import netbox_serial
    from doku_agent.netbox_sync import propose_sync
    from doku_agent.vcenter_inventory import apply_precedence, vcenter_assets
    from tests.test_vcenter import FakeVCenter, _vm

    client, cfg, site, created = nb
    ctx.__dict__["netbox"] = client
    ctx.cfg.netbox = cfg.netbox
    ctx.cfg.netbox.site = site["slug"]
    ctx.cfg.netbox.custom_fields.enabled = False
    ctx.cfg.wazuh.enabled = False
    sfx = uuid.uuid4().hex[:6]
    bios = f"42{sfx}-0000-0000-0000-{uuid.uuid4().hex[:12]}"
    fake = FakeVCenter()
    fake.hosts["host-1"]["name"] = f"esx-{sfx}.firma.local"
    fake.host_serial = f"ESX{sfx}"
    fake.guest_host = f"web-{sfx}.firma.local"
    fake.vms = {"vm-1": _vm(f"web-{sfx}", bios=bios, mac=f"00:50:56:{sfx[:2]}:{sfx[2:4]}:{sfx[4:6]}",
                            disks=((2000, 53687091200), (2001, 107374182400)))}
    fake.vm_host = {"vm-1": "host-1"}
    ctx.cfg.vcenter.enabled = True
    ctx.cfg.vcenter.url = "https://vc.test"
    ctx.__dict__["vcenter"] = VCenterClient(ctx.cfg.vcenter, EgressGuard({"vc.test"}),
                                            transport=httpx.MockTransport(fake.handler))
    cleanup = []
    try:
        discovery.run_discovery(ctx)
        props = {p.title: p for p in ctx.store.list_proposals("pending")}
        assert apply_proposal(ctx, props[f"Netbox: Gerät esx-{sfx} anlegen"].id) == "applied"
        host = client.find_one("dcim/devices", serial=f"ESX{sfx}")
        cleanup.append(("dcim/devices", host["id"]))
        cluster = client.get("virtualization/clusters", host["cluster"]["id"])
        assert cluster["name"] == "Cluster-HQ" and cluster["scope_id"] == site["id"]
        cleanup.append(("virtualization/clusters", cluster["id"]))

        discovery.run_discovery(ctx)  # VM-Vorschlag jetzt mit Host-Zuordnung
        vm_prop = next(p for p in ctx.store.list_proposals("pending") if p.title == f"Netbox: VM web-{sfx} anlegen")
        assert apply_proposal(ctx, vm_prop.id) == "applied"
        vm = client.find_one("virtualization/virtual-machines", serial=netbox_serial(vmware_serial(bios)))
        cleanup.insert(0, ("virtualization/virtual-machines", vm["id"]))
        cleanup[:0] = [("ipam/ip-addresses", ip["id"]) for ip in client.list("ipam/ip-addresses", virtual_machine_id=vm["id"])]
        assert vm["device"]["id"] == host["id"] and vm["cluster"]["id"] == cluster["id"]
        assert (vm["vcpus"], vm["memory"]) == (4, 8192)
        disks = {d["name"]: d["size"] for d in client.list("virtualization/virtual-disks", virtual_machine_id=vm["id"])}
        assert disks == {"Hard disk 1": 53687, "Hard disk 2": 107374}
        assert client.get("virtualization/virtual-machines", vm["id"])["disk"] == 53687 + 107374

        # Disk im vCenter vergrößert -> Abgleich schlägt die neue Größe vor
        fake.vms["vm-1"]["disks"]["2000"]["capacity"] = 85899345920
        asset = next(a for a in vcenter_assets(ctx) if a.name == f"web-{sfx}")
        apply_precedence(asset)
        index = NetboxIndex(client)
        assert propose_sync(ctx, asset, index.find(asset), index)
        prop = next(p for p in ctx.store.list_proposals("pending") if p.dedup_key.startswith("netbox-sync:"))
        assert [c["key"] for c in prop.payload["changes"]] == ["disk:Hard disk 1"]
        assert apply_proposal(ctx, prop.id) == "applied"
        disks = {d["name"]: d["size"] for d in client.list("virtualization/virtual-disks", virtual_machine_id=vm["id"])}
        assert disks["Hard disk 1"] == 85899
    finally:
        _cleanup(client, cleanup)
