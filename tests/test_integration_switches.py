"""Integrationstest: echtes SNMP (z.B. snmpsim mit der Aufzeichnung aus tests/test_switches.py) und echtes Netbox.

Läuft nur mit DOKU_IT_SNMP_HOST (z.B. 127.0.0.1), DOKU_IT_SNMP_PORT (Standard 161) sowie
DOKU_IT_NETBOX_URL und DOKU_IT_NETBOX_TOKEN. Die SNMP-Daten müssen den Switch sw-core01 mit den
Nachbarn sw-access02 (Gi0/48) und ap-lobby sowie der MAC AA:BB:CC:DD:EE:01 an Gi1/0/1 enthalten.
"""

import logging
import os
import uuid

import pytest

from doku_agent.apply import apply_proposal
from doku_agent.config import SnmpCredentials, SwitchDevice
from doku_agent.connectors.netbox import NetboxClient
from doku_agent.egress import EgressGuard
from doku_agent.switches import propose_switch
from tests.conftest import make_config

HOST, PORT = os.environ.get("DOKU_IT_SNMP_HOST"), int(os.environ.get("DOKU_IT_SNMP_PORT", "161"))
URL, TOKEN = os.environ.get("DOKU_IT_NETBOX_URL"), os.environ.get("DOKU_IT_NETBOX_TOKEN")
pytestmark = pytest.mark.skipif(not (HOST and URL and TOKEN), reason="kein Test-SNMP/Test-Netbox konfiguriert")
log = logging.getLogger("it")


def test_switch_cables_from_real_snmp(ctx, tmp_path):
    cfg = make_config(tmp_path, netbox={"url": URL, "token": TOKEN})
    client = NetboxClient(cfg.netbox, EgressGuard.from_config(cfg))
    ctx.__dict__["netbox"] = client
    slug = f"it-{uuid.uuid4().hex[:6]}"
    site = client.create("dcim/sites", {"name": slug, "slug": slug, "status": "active"})
    ctx.cfg.netbox.site = slug
    ctx.cfg.netbox.url, ctx.cfg.netbox.token = URL, TOKEN
    ctx.cfg.switches.enabled = True
    sw = SwitchDevice(host=HOST, snmp=SnmpCredentials(community="public", port=PORT, timeout_s=3))
    ctx.cfg.switches.devices = [sw]
    ctx.guard = EgressGuard(set(ctx.guard.hosts) | {HOST})
    created = []
    try:
        role = client.find_one("dcim/device-roles", slug="server") or client.create(
            "dcim/device-roles", {"name": "Server", "slug": "server", "color": "9e9e9e"})
        mfr = client.find_one("dcim/manufacturers", slug="it-test") or client.create(
            "dcim/manufacturers", {"name": "IT-Test", "slug": "it-test"})
        dtype = client.find_one("dcim/device-types", slug="it-box") or client.create(
            "dcim/device-types", {"manufacturer": mfr["id"], "model": "IT-Box", "slug": "it-box"})
        ifaces = {}
        for name, port, mac in (("srv-fdb", "eth0", "AA:BB:CC:DD:EE:01"), ("sw-access02", "Gi0/48", None),
                                ("ap-lobby", "eth0", "AA:BB:CC:DD:EE:04")):
            dev = client.create("dcim/devices", {"name": name, "site": site["id"], "role": role["id"],
                                                 "device_type": dtype["id"]})
            created.append(("dcim/devices", dev["id"]))
            itf = client.create("dcim/interfaces", {"device": dev["id"], "name": port, "type": "1000base-t"})
            if mac:
                m = client.create("dcim/mac-addresses", {"mac_address": mac, "assigned_object_type": "dcim.interface",
                                                         "assigned_object_id": itf["id"]})
                created.insert(0, ("dcim/mac-addresses", m["id"]))
            ifaces[name] = itf

        pid = propose_switch(ctx, sw)
        prop = ctx.store.get_proposal(pid)
        keys = {c["key"] for c in prop.payload["changes"]}
        assert {"device", "ports", "cable:Gi1/0/1", "cable:Gi1/0/2", "cable:Gi1/0/4"} == keys
        assert apply_proposal(ctx, pid) == "applied"
        switch = client.find_one("dcim/devices", serial="CN12AB3456")
        created.append(("dcim/devices", switch["id"]))
        cables = client.list("dcim/cables", device_id=switch["id"])
        created[:0] = [("dcim/cables", c["id"]) for c in cables]
        peers = {}
        for c in cables:
            a = c["a_terminations"][0]["object_id"]
            b = c["b_terminations"][0]["object_id"]
            peers[a] = b
        ports = {i["name"]: i for i in client.list("dcim/interfaces", device_id=switch["id"])}
        assert peers[ports["Gi1/0/1"]["id"]] == ifaces["srv-fdb"]["id"]
        assert peers[ports["Gi1/0/2"]["id"]] == ifaces["sw-access02"]["id"]
        assert peers[ports["Gi1/0/4"]["id"]] == ifaces["ap-lobby"]["id"]
        srv = client.get("dcim/interfaces", ifaces["srv-fdb"]["id"])
        assert srv["link_peers"][0]["name"] == "Gi1/0/1"
        assert propose_switch(ctx, sw) is None  # zweiter Lauf: alles verkabelt
    finally:
        for endpoint, oid in created:
            try:
                client.delete(endpoint, oid)
            except Exception:
                pass
        client.delete("dcim/sites", site["id"])
