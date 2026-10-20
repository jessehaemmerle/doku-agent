import logging

import httpx
import pytest

from doku_agent.connectors.netbox import NetboxClient, NetboxError
from doku_agent.discovery import (Asset, Iface, NetboxIndex, build_plan, detect_virtual, merge_assets, norm_mac,
                                  norm_serial, prefix_len)
from doku_agent.egress import EgressGuard
from doku_agent.netbox_plan import PlanError, execute_plan, validate_plan
from tests.conftest import FakeNetbox, make_config

log = logging.getLogger("test")


@pytest.fixture
def nb_fake():
    return FakeNetbox()


@pytest.fixture
def nb(tmp_path, nb_fake):
    cfg = make_config(tmp_path)
    return NetboxClient(cfg.netbox, EgressGuard.from_config(cfg), transport=httpx.MockTransport(nb_fake.handler))


def test_v2_token_uses_bearer(tmp_path):
    cfg = make_config(tmp_path, netbox={"token": "nbt_abc.def"})
    seen = {}

    def handler(request):
        seen["auth"] = request.headers["authorization"]
        return httpx.Response(200, json={"netbox-version": "4.7.0"})

    NetboxClient(cfg.netbox, EgressGuard.from_config(cfg), transport=httpx.MockTransport(handler)).version()
    assert seen["auth"] == "Bearer nbt_abc.def"


def test_validate_plan_rejects_unsafe_steps():
    with pytest.raises(PlanError, match="nicht erlaubt"):
        validate_plan([{"action": "delete", "endpoint": "dcim/devices", "id": 1}])
    with pytest.raises(PlanError, match="Endpunkt"):
        validate_plan([{"action": "create", "endpoint": "users/users", "data": {}}])
    with pytest.raises(PlanError, match="vor Definition"):
        validate_plan([{"action": "create", "endpoint": "dcim/interfaces", "data": {"device": "$dev"}}])


def test_execute_plan_resolves_refs_and_ensures(nb, nb_fake):
    existing = nb_fake.add("dcim/manufacturers", {"name": "Dell", "slug": "dell"})
    steps = [
        {"ref": "mfr", "action": "ensure", "endpoint": "dcim/manufacturers", "lookup": {"slug": "dell"},
         "data": {"name": "Dell", "slug": "dell"}},
        {"ref": "dt", "action": "ensure", "endpoint": "dcim/device-types",
         "lookup": {"manufacturer_id": "$mfr", "slug": "r650"}, "data": {"manufacturer": "$mfr", "model": "R650", "slug": "r650"}},
        {"ref": "dev", "action": "create", "endpoint": "dcim/devices", "data": {"name": "srv01", "device_type": "$dt"}},
        {"action": "update", "endpoint": "dcim/devices", "id": "$dev", "data": {"serial": "ABC"}},
    ]
    refs = execute_plan(nb, steps, log)
    assert refs["mfr"] == ("dcim/manufacturers", existing["id"])
    dev = nb_fake.objects["dcim/devices"][refs["dev"][1]]
    assert dev["device_type"] == refs["dt"][1] and dev["serial"] == "ABC"
    assert nb_fake.objects["dcim/device-types"][refs["dt"][1]]["manufacturer"] == existing["id"]


def test_execute_plan_rolls_back_on_failure(nb, nb_fake):
    nb_fake.fail_on = "ipam/ip-addresses"
    steps = [
        {"ref": "dev", "action": "create", "endpoint": "dcim/devices", "data": {"name": "srv01"}},
        {"ref": "if0", "action": "create", "endpoint": "dcim/interfaces", "data": {"device": "$dev", "name": "eth0"}},
        {"action": "create", "endpoint": "ipam/ip-addresses", "data": {"address": "10.0.0.5/24"}},
    ]
    with pytest.raises(NetboxError, match="Rollback"):
        execute_plan(nb, steps, log)
    assert nb_fake.objects["dcim/devices"] == {} and nb_fake.objects["dcim/interfaces"] == {}
    deletes = [p for m, p in nb_fake.log if m == "DELETE"]
    assert deletes[0].startswith("dcim/interfaces") and deletes[1].startswith("dcim/devices")


def test_normalizers():
    assert norm_mac("a1b2c3d4e5f6") == "A1:B2:C3:D4:E5:F6"
    assert norm_mac("00:00:00:00:00:00") == ""
    assert norm_serial("To be filled by O.E.M.") == "" and norm_serial(" ABC123 ") == "ABC123"
    assert prefix_len("255.255.255.0", 4) == 24
    assert prefix_len("ffff:ffff:ffff:ffff::", 6) == 64


def test_merge_assets_by_serial_name_and_mac():
    intune = Asset(name="NB-0815", serial="5CG123", manufacturer="HP", model="EliteBook 840",
                   os_name="Windows", interfaces=[Iface("WLAN", "AA:AA:AA:AA:AA:01")], sources={"intune": {"id": "1"}})
    wazuh = Asset(name="nb-0815", serial="", os_name="Microsoft Windows 11 Pro",
                  interfaces=[Iface("Ethernet", "AA:AA:AA:AA:AA:02", ["10.0.0.20/24"])], sources={"wazuh": {"agent_id": "007"}})
    other = Asset(name="srv-x", interfaces=[Iface("eth0", "AA:AA:AA:AA:AA:02")], sources={"wazuh": {"agent_id": "008"}})
    merged = merge_assets([intune, wazuh, other])
    assert len(merged) == 1
    asset = merged[0]
    assert asset.serial == "5CG123" and set(asset.sources) == {"intune", "wazuh"}
    assert {i.mac for i in asset.interfaces} == {"AA:AA:AA:AA:AA:01", "AA:AA:AA:AA:AA:02"}


def test_detect_virtual(tmp_path):
    cfg = make_config(tmp_path).netbox
    assert detect_virtual(Asset(name="a", serial="VMware-56 4d 12"), cfg)
    assert detect_virtual(Asset(name="b", manufacturer="Microsoft Corporation", model="Virtual Machine"), cfg)
    assert not detect_virtual(Asset(name="c", serial="5CG123", manufacturer="HP", model="EliteBook"), cfg)


def test_build_plan_device_with_mac_objects_and_ips(tmp_path, nb, nb_fake):
    cfg = make_config(tmp_path).netbox
    nb_fake.add("ipam/ip-addresses", {"address": "10.0.0.99/24", "assigned_object_id": 5})
    asset = Asset(name="srv01", serial="ABC", manufacturer="Dell Inc.", model="PowerEdge R650", os_name="Ubuntu",
                  primary_ip="10.0.0.5",
                  interfaces=[Iface("eth0", "AA:BB:CC:DD:EE:FF", ["10.0.0.5/24", "10.0.0.99/24"])],
                  sources={"wazuh": {"agent_id": "001"}})
    steps, hints = build_plan(asset, nb, cfg, site_id=1)
    validate_plan(steps)
    endpoints = [s["endpoint"] for s in steps]
    assert endpoints[:5] == ["dcim/device-roles", "dcim/platforms", "dcim/manufacturers", "dcim/device-types", "dcim/devices"]
    assert steps[0]["lookup"] == {"slug": "server"}
    assert "dcim/mac-addresses" in endpoints
    assert steps[-1]["data"] == {"primary_ip4": "$ip0"}
    assert any("bereits einem anderen Objekt" in h for h in hints)
    execute_plan(nb, steps, log)
    dev = next(iter(nb_fake.objects["dcim/devices"].values()))
    assert dev["name"] == "srv01" and dev["primary_ip4"] in nb_fake.objects["ipam/ip-addresses"]


def test_build_plan_old_netbox_puts_mac_on_interface(tmp_path):
    fake = FakeNetbox(version="4.1.0")
    cfg = make_config(tmp_path)
    client = NetboxClient(cfg.netbox, EgressGuard.from_config(cfg), transport=httpx.MockTransport(fake.handler))
    steps, _ = build_plan(Asset(name="c1", interfaces=[Iface("WLAN", "AA:BB:CC:DD:EE:01")]), client, cfg.netbox, 1)
    assert "dcim/mac-addresses" not in [s["endpoint"] for s in steps]
    iface = next(s for s in steps if s["endpoint"] == "dcim/interfaces")
    assert iface["data"]["mac_address"] == "AA:BB:CC:DD:EE:01"


def test_netbox_index_matches(nb, nb_fake):
    nb_fake.add("dcim/devices", {"name": "srv01.firma.local", "serial": "ABC"})
    sw = nb_fake.add("dcim/devices", {"name": "sw01"})
    nb_fake.add("dcim/mac-addresses", {"mac_address": "AA:BB:CC:DD:EE:FF",
                                       "assigned_object": {"device": {"id": sw["id"], "name": "sw01"}}})
    index = NetboxIndex(nb)
    assert "Seriennummer" in index.match(Asset(name="x", serial="abc"))
    assert "Hostname" in index.match(Asset(name="SRV01"))
    assert "MAC" in index.match(Asset(name="y", interfaces=[Iface("e", "AA:BB:CC:DD:EE:FF")]))
    assert index.match(Asset(name="neu")) is None


def test_netbox_slug_has_no_dots():
    from doku_agent.discovery import netbox_slug
    assert netbox_slug("Ubuntu 24.04") == "ubuntu-24-04"
    assert netbox_slug("Dell Inc.") == "dell-inc"
    assert netbox_slug("Virtual Machine 7.0") == "virtual-machine-7-0"
    assert len(netbox_slug("x" * 300)) == 100
