"""FortiGate -> Netbox: Gerät, Interfaces, IPs, VLANs und Präfixe als einzeln freigebbare Änderungen."""

import httpx
import pytest

from doku_agent.apply import apply_proposal
from doku_agent.config import FortiGateDevice
from doku_agent.connectors.fortigate import FortiGateClient
from doku_agent.connectors.netbox import NetboxClient
from doku_agent.egress import EgressGuard
from doku_agent.fortigate_netbox import propose_fortigate
from tests.conftest import FakeNetbox
from tests.test_fortigate import FakeFortiGate


@pytest.fixture
def env(ctx):
    nbf = FakeNetbox()
    ctx.__dict__["netbox"] = NetboxClient(ctx.cfg.netbox, EgressGuard.from_config(ctx.cfg),
                                          transport=httpx.MockTransport(nbf.handler))
    nbf.add("dcim/sites", {"slug": "hq", "name": "HQ"})
    fake = FakeFortiGate()
    dev = FortiGateDevice(name="fw-zentrale", url="https://10.10.0.1:8443", token="fgt-token")
    ctx.cfg.fortigate.enabled = True
    ctx.cfg.fortigate.devices = [dev]
    ctx._clients["fortigate:fw-zentrale"] = FortiGateClient(dev, EgressGuard({"10.10.0.1"}),
                                                            transport=httpx.MockTransport(fake.handler))
    return ctx, nbf, dev


def _changes(ctx, pid):
    return {c["key"]: c for c in ctx.store.get_proposal(pid).payload["changes"]}


def test_new_firewall_is_created_with_everything(env):
    ctx, nbf, dev = env
    pid = propose_fortigate(ctx, dev)
    changes = _changes(ctx, pid)
    assert {"device", "vlan:20", "iface:internal", "iface:vlan20", "iface:ppp1", "iface:fremd", "ip:10.10.0.1",
            "ip:10.20.0.1", "ip:192.168.9.1", "prefix:10.10.0.0/16", "prefix:10.20.0.0/24",
            "prefix:192.168.9.0/24", "primary_ip4"} <= set(changes)
    assert set(changes["iface:vlan20"]["requires"]) == {"device", "iface:internal", "vlan:20"}
    assert changes["iface:internal"]["after"].startswith("internal, bridge")
    assert changes["primary_ip4"]["requires"] == ["ip:10.10.0.1", "device"]

    assert apply_proposal(ctx, pid) == "applied"
    fw = next(iter(nbf.objects["dcim/devices"].values()))
    assert fw["name"] == "FGT-ZENTRALE" and fw["serial"] == "FGT60FTK1234"
    ifaces = {i["name"]: i for i in nbf.objects["dcim/interfaces"].values()}
    vlan = next(iter(nbf.objects["ipam/vlans"].values()))
    assert vlan["vid"] == 20 and vlan["site"] == next(iter(nbf.objects["dcim/sites"]))
    assert ifaces["vlan20"]["parent"] == ifaces["internal"]["id"] and ifaces["vlan20"]["mode"] == "access"
    assert ifaces["vlan20"]["untagged_vlan"] == vlan["id"]
    prefixes = {p["prefix"]: p for p in nbf.objects["ipam/prefixes"].values()}
    assert prefixes["10.20.0.0/24"]["vlan"] == vlan["id"] and prefixes["10.20.0.0/24"]["scope_type"] == "dcim.site"
    ips = {i["address"]: i for i in nbf.objects["ipam/ip-addresses"].values()}
    assert ips["10.10.0.1/16"]["assigned_object_id"] == ifaces["internal"]["id"]
    assert fw["primary_ip4"] == ips["10.10.0.1/16"]["id"]
    assert ctx.store.list_jobs()[0].name == "netbox_device"  # Steckbrief folgt

    # Zweiter Lauf: nichts mehr zu tun
    assert propose_fortigate(ctx, dev) is None


def test_wan_networks_get_no_prefix_and_existing_objects_are_reused(env):
    ctx, nbf, dev = env
    from tests import test_fortigate as tf
    tf.TABLES["cmdb/system/interface"].append({"name": "wan1", "vdom": "root", "ip": "203.0.113.2 255.255.255.248",
                                               "type": "physical", "role": "wan", "status": "up"})
    try:
        nbf.add("ipam/vlans", {"vid": 20, "name": "DMZ", "site": next(iter(nbf.objects["dcim/sites"]))})
        changes = _changes(ctx, propose_fortigate(ctx, dev))
    finally:
        tf.TABLES["cmdb/system/interface"].pop()
    assert "ip:203.0.113.2" in changes and "prefix:203.0.113.0/29" not in changes
    assert "vlan:20" not in changes and "vlan:20" not in changes["iface:vlan20"]["requires"]


def test_existing_device_only_gets_missing_parts(env):
    ctx, nbf, dev = env
    fw = nbf.add("dcim/devices", {"name": "FGT-ZENTRALE", "serial": "FGT60FTK1234", "primary_ip4": None})
    nbf.add("dcim/interfaces", {"device": fw["id"], "name": "internal"})
    ctx.cfg.fortigate.netbox_sync = ["interfaces", "ips"]
    changes = _changes(ctx, propose_fortigate(ctx, dev))
    assert "device" not in changes and "iface:internal" not in changes
    assert not any(k.startswith(("vlan:", "prefix:")) for k in changes)
    assert changes["ip:10.10.0.1"]["requires"] == []  # Interface existiert schon


def test_lag_members_sorting_before_their_aggregate_get_the_lag(env):
    ctx, nbf, dev = env
    from tests import test_fortigate as tf
    added = [{"name": "internal1", "vdom": "root", "type": "physical", "status": "up"},
             {"name": "internal2", "vdom": "root", "type": "physical", "status": "up"},
             {"name": "lan-agg", "vdom": "root", "type": "aggregate", "status": "up",
              "member": [{"interface-name": "internal1"}, {"interface-name": "internal2"}]}]
    tf.TABLES["cmdb/system/interface"].extend(added)
    try:
        changes = _changes(ctx, propose_fortigate(ctx, dev))
    finally:
        del tf.TABLES["cmdb/system/interface"][-len(added):]
    for member in ("internal1", "internal2"):
        step = changes[f"iface:{member}"]["steps"][0]
        assert step["data"]["lag"] == "$if_lan-agg" and "iface:lan-agg" in changes[f"iface:{member}"]["requires"]


def test_ips_and_prefixes_existing_more_than_once_are_not_created_again(env):
    ctx, nbf, dev = env
    for vrf in (1, 2):
        nbf.add("ipam/prefixes", {"prefix": "10.20.0.0/24", "vrf": vrf})
        nbf.add("ipam/ip-addresses", {"address": "10.20.0.1/24", "vrf": vrf})
    pid = propose_fortigate(ctx, dev)
    changes = _changes(ctx, pid)
    assert "prefix:10.20.0.0/24" not in changes and "ip:10.20.0.1" not in changes
    assert any("10.20.0.1/24 gibt es in Netbox mehrfach" in h for h in ctx.store.get_proposal(pid).payload["hints"])


def test_job_succeeds_when_one_firewall_is_in_sync_and_another_fails(env, monkeypatch):
    from doku_agent import fortigate_netbox

    ctx, nbf, dev = env
    ctx.cfg.fortigate.devices = [dev, FortiGateDevice(name="fw-kaputt", url="https://10.0.0.9", token="x")]

    def fake_propose(ctx, d):
        if d.name == "fw-kaputt":
            raise RuntimeError("nicht erreichbar")
        return None  # nichts zu tun

    monkeypatch.setattr(fortigate_netbox, "propose_fortigate", fake_propose)
    assert fortigate_netbox.sync_fortigates(ctx) == [None]
    monkeypatch.setattr(fortigate_netbox, "propose_fortigate", lambda c, d: (_ for _ in ()).throw(RuntimeError("x")))
    with pytest.raises(RuntimeError, match="fehlgeschlagen"):
        fortigate_netbox.sync_fortigates(ctx)
