"""Switches per SNMP: Auswertung von IF-/LLDP-/BRIDGE-MIB und Kabelvorschläge für Netbox."""

import httpx
import pytest

from doku_agent.apply import apply_proposal
from doku_agent.config import SnmpCredentials, SwitchDevice
from doku_agent.connectors.netbox import NetboxClient
from doku_agent.connectors.snmp import SnmpClient, SnmpData
from doku_agent.egress import EgressBlocked, EgressGuard
from doku_agent.switches import iface_type, parse, propose_switch
from tests.conftest import FakeNetbox

MAC = {k: bytes.fromhex(v) for k, v in {"srv01": "aabbccddee01", "sw2": "aabbccddee02", "ap": "aabbccddee04",
                                         "vm": "aabbccddee05"}.items()}


def switch_data() -> SnmpData:
    """Gleiche Daten wie die snmpsim-Aufzeichnung im Integrationstest."""
    ports = {1: "Gi1/0/1", 2: "Gi1/0/2", 3: "Gi1/0/3", 4: "Gi1/0/4", 5: "Gi1/0/5", 100: "Vlan1"}
    d = SnmpData(scalars={"sysName": b"sw-core01.firma.local", "sysDescr": b"Aruba 2930F"})
    t = d.tables
    t["ifName"] = {(i,): n.encode() for i, n in ports.items()}
    t["ifType"] = {(i,): 136 if i == 100 else 6 for i in ports}
    t["ifHighSpeed"] = {(i,): 1000 for i in ports}
    t["ifAlias"] = {(1,): b"srv01", (2,): b"Uplink Access"}
    t["entPhysicalClass"] = {(1,): 3}
    t["entPhysicalSerialNum"] = {(1,): b"CN12AB3456"}
    t["entPhysicalModelName"] = {(1,): b"JL075A"}
    t["entPhysicalMfgName"] = {(1,): b"Aruba"}
    t["lldpLocPortIdSubtype"] = {(i,): 5 for i in range(1, 6)}
    t["lldpLocPortId"] = {(i,): ports[i].encode() for i in range(1, 6)}
    t["lldpRemChassisIdSubtype"] = {(0, 2, 1): 4, (0, 4, 1): 4}
    t["lldpRemChassisId"] = {(0, 2, 1): MAC["sw2"], (0, 4, 1): MAC["ap"]}
    t["lldpRemPortIdSubtype"] = {(0, 2, 1): 5, (0, 4, 1): 3}
    t["lldpRemPortId"] = {(0, 2, 1): b"Gi0/48", (0, 4, 1): MAC["ap"]}
    t["lldpRemPortDesc"] = {(0, 2, 1): b"Uplink Core", (0, 4, 1): b"eth0"}
    t["lldpRemSysName"] = {(0, 2, 1): b"sw-access02", (0, 4, 1): b"ap-lobby"}
    t["dot1dBasePortIfIndex"] = {(bp,): bp for bp in range(1, 6)}
    fdb = {MAC["srv01"]: 1, MAC["sw2"]: 2, MAC["ap"]: 4, MAC["vm"]: 5,
           bytes.fromhex("020000000301"): 3, bytes.fromhex("020000000302"): 3}
    t["dot1qTpFdbPort"] = {(1, *m): port for m, port in fdb.items()}
    return d


@pytest.fixture
def env(ctx):
    nbf = FakeNetbox()
    ctx.__dict__["netbox"] = NetboxClient(ctx.cfg.netbox, EgressGuard.from_config(ctx.cfg),
                                          transport=httpx.MockTransport(nbf.handler))
    nbf.add("dcim/sites", {"slug": "hq", "name": "HQ"})

    def device(name, iface, mac=None, vm=False):
        dev = nbf.add("virtualization/virtual-machines" if vm else "dcim/devices", {"name": name})
        itf = nbf.add("virtualization/interfaces" if vm else "dcim/interfaces",
                      {"virtual_machine" if vm else "device": dev["id"], "name": iface, "type": "other", "cable": None})
        if mac:
            nbf.add("dcim/mac-addresses", {
                "mac_address": mac, "assigned_object_type": "virtualization.vminterface" if vm else "dcim.interface",
                "assigned_object_id": itf["id"],
                "assigned_object": {"id": itf["id"], ("virtual_machine" if vm else "device"): {"id": dev["id"]}}})
        return dev, itf

    nodes = {"srv01": device("srv01", "eth0", "AA:BB:CC:DD:EE:01"), "sw2": device("sw-access02", "Gi0/48"),
             "ap": device("ap-lobby", "eth0", "AA:BB:CC:DD:EE:04"), "vm": device("vm01", "eth0", "AA:BB:CC:DD:EE:05", vm=True)}
    sw = SwitchDevice(host="10.0.0.2")
    ctx.cfg.switches.enabled = True
    ctx.cfg.switches.devices = [sw]
    return ctx, nbf, sw, nodes


def test_parse_maps_lldp_and_mac_table_to_ports():
    info = parse("10.0.0.2", switch_data())
    assert info.name == "sw-core01" and info.serial == "CN12AB3456" and info.model == "JL075A"
    assert sorted(info.ports) == [1, 2, 3, 4, 5]  # Vlan1 (ifType 136) ist kein Port
    n = {x.ifindex: x for x in info.neighbors}
    assert n[2].sys_name == "sw-access02" and n[2].port_name == "Gi0/48"
    assert n[4].port_mac == "AA:BB:CC:DD:EE:04" and n[4].chassis_mac == "AA:BB:CC:DD:EE:04"
    assert info.fdb[1] == {"AA:BB:CC:DD:EE:01"} and len(info.fdb[3]) == 2
    assert iface_type(1000, 6) == "1000base-t" and iface_type(10000, 6) == "10gbase-x-sfpp"
    assert iface_type(0, 6) == "other" and iface_type(0, 161) == "lag"


def test_new_switch_gets_device_ports_and_cables(env):
    ctx, nbf, sw, nodes = env
    pid = propose_switch(ctx, sw, data=switch_data())
    prop = ctx.store.get_proposal(pid)
    changes = {c["key"]: c for c in prop.payload["changes"]}
    assert set(changes) == {"device", "ports", "cable:Gi1/0/1", "cable:Gi1/0/2", "cable:Gi1/0/4"}
    assert changes["cable:Gi1/0/1"]["after"] == "srv01 eth0 (MAC-Tabelle)"
    assert changes["cable:Gi1/0/2"]["after"] == "sw-access02 Gi0/48 (LLDP)"
    assert changes["cable:Gi1/0/4"]["after"] == "ap-lobby eth0 (LLDP)"
    assert set(changes["cable:Gi1/0/1"]["requires"]) == {"ports", "device"}
    # Port 3: Uplink mit mehreren MACs, Port 5: MAC gehört einer VM -> keine Kabel
    assert "cable:Gi1/0/3" not in changes and "cable:Gi1/0/5" not in changes

    assert apply_proposal(ctx, pid) == "applied"
    switch = next(d for d in nbf.objects["dcim/devices"].values() if d["name"] == "sw-core01")
    assert switch["serial"] == "CN12AB3456"
    ports = {i["name"]: i for i in nbf.objects["dcim/interfaces"].values() if i.get("device") == switch["id"]}
    assert len(ports) == 5 and ports["Gi1/0/1"]["type"] == "1000base-t" and ports["Gi1/0/1"]["description"] == "srv01"
    cables = list(nbf.objects["dcim/cables"].values())
    ends = {(c["a_terminations"][0]["object_id"], c["b_terminations"][0]["object_id"]) for c in cables}
    assert (ports["Gi1/0/1"]["id"], nodes["srv01"][1]["id"]) in ends
    assert all(c["status"] == "connected" for c in cables) and len(cables) == 3


def test_existing_cables_are_respected(env):
    ctx, nbf, sw, nodes = env
    switch = nbf.add("dcim/devices", {"name": "sw-core01", "serial": "CN12AB3456"})
    for i, name in enumerate(["Gi1/0/1", "Gi1/0/2", "Gi1/0/3", "Gi1/0/4", "Gi1/0/5"], 1):
        cable = None
        peers = []
        if name == "Gi1/0/1":  # schon richtig verkabelt
            cable, peers = {"id": 1}, [{"id": nodes["srv01"][1]["id"], "name": "eth0"}]
        if name == "Gi1/0/2":  # anderes Kabel als LLDP meldet
            cable, peers = {"id": 2}, [{"id": 999, "name": "Gi0/1"}]
        nbf.add("dcim/interfaces", {"device": switch["id"], "name": name, "type": "1000base-t", "cable": cable,
                                    "link_peers": peers})
    pid = propose_switch(ctx, sw, data=switch_data())
    prop = ctx.store.get_proposal(pid)
    assert [c["key"] for c in prop.payload["changes"]] == ["cable:Gi1/0/4"]
    assert any("Gi1/0/2" in h and "anderes Kabel" in h for h in prop.payload["hints"])


def test_cable_already_proposed_from_the_other_switch_is_not_proposed_twice(env):
    ctx, nbf, sw, nodes = env
    switch = nbf.add("dcim/devices", {"name": "sw-core01", "serial": "CN12AB3456"})
    ports = {n: nbf.add("dcim/interfaces", {"device": switch["id"], "name": n, "type": "1000base-t", "cable": None})
             for n in ["Gi1/0/1", "Gi1/0/2", "Gi1/0/3", "Gi1/0/4", "Gi1/0/5"]}
    cable = {"action": "create", "endpoint": "dcim/cables", "data": {
        "a_terminations": [{"object_type": "dcim.interface", "object_id": nodes["sw2"][1]["id"]}],
        "b_terminations": [{"object_type": "dcim.interface", "object_id": ports["Gi1/0/2"]["id"]}]}}
    ctx.store.add_proposal("netbox_plan", "Netbox: Switch sw-access02 abgleichen",
                           {"changes": [{"key": "cable:Gi0/48", "steps": [cable]}],
                            "target": {"name": "sw-access02"}}, source="switches", dedup_key="switch-netbox:10.0.0.3")
    prop = ctx.store.get_proposal(propose_switch(ctx, sw, data=switch_data()))
    assert "cable:Gi1/0/2" not in {c["key"] for c in prop.payload["changes"]}
    assert any("Gi1/0/2" in h and "sw-access02" in h for h in prop.payload["hints"])


def test_snmp_client_respects_allowlist():
    with pytest.raises(EgressBlocked):
        SnmpClient("10.9.9.9", SnmpCredentials(community="public"), EgressGuard({"10.0.0.2"}))


def test_steckbrief_shows_cable_peers(env, fake_wiki):
    from doku_agent.generators.netbox_docs import document_object

    ctx, nbf, sw, nodes = env
    dev, itf = nodes["srv01"]
    itf["link_peers"] = [{"id": 5, "name": "Gi1/0/1", "device": {"id": 9, "name": "sw-core01"}}]
    content = ctx.store.get_proposal(document_object(ctx, "device", dev["id"])).payload["content"]
    assert "| Verbunden mit |" in content and "sw-core01 Gi1/0/1" in content


def test_job_succeeds_when_one_switch_is_in_sync_and_another_fails(env, monkeypatch):
    from doku_agent import switches

    ctx, nbf, sw, nodes = env
    ctx.cfg.switches.devices = [sw, SwitchDevice(host="10.0.0.9")]

    def fake_propose(ctx, s, view=None):
        if s.host == "10.0.0.9":
            raise RuntimeError("Zeitüberschreitung")
        return None  # nichts zu tun

    monkeypatch.setattr(switches, "propose_switch", fake_propose)
    assert switches.sync_switches(ctx) == [None]
