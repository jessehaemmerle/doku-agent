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
