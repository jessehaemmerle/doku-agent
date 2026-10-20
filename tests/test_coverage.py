"""Abdeckungsbericht: ohne Wazuh, ohne Intune, nicht in Netbox, Funkstille."""

import httpx

from doku_agent.connectors.netbox import NetboxClient
from doku_agent.coverage import build_report, propose_coverage
from doku_agent.discovery import Asset, NetboxIndex
from doku_agent.egress import EgressGuard
from tests.conftest import FakeNetbox


def test_coverage_report(ctx):
    nbf = FakeNetbox()
    ctx.__dict__["netbox"] = NetboxClient(ctx.cfg.netbox, EgressGuard.from_config(ctx.cfg),
                                          transport=httpx.MockTransport(nbf.handler))
    server, client = {"slug": "server"}, {"slug": "client"}
    nbf.add("dcim/devices", {"name": "srv-ok", "serial": "S1", "role": server, "custom_fields": {"last_seen": "2099-01-01"}})
    nbf.add("dcim/devices", {"name": "srv-ohne", "serial": "S2", "role": server})
    nbf.add("dcim/devices", {"name": "laptop1", "serial": "L1", "role": client, "custom_fields": {"last_seen": "2020-01-01"}})
    nbf.add("dcim/devices", {"name": "sw01", "role": {"slug": "switch"}})
    nbf.add("virtualization/virtual-machines", {"name": "vm-aus", "serial": "V1", "role": server,
                                                "custom_fields": {"last_seen": "2020-02-02"}})
    assets = [
        Asset(name="srv-ok", serial="S1", sources={"wazuh": {"agent_id": "1"}}),
        Asset(name="laptop1", serial="L1", sources={"wazuh": {"agent_id": "2"}}),
        Asset(name="vm-aus", serial="V1", sources={"wazuh": {"agent_id": "3"}, "vcenter": {"power_state": "POWERED_OFF"}}),
        Asset(name="neu01", serial="N1", sources={"intune": {"id": "x"}}),
    ]
    ctx.store.add_proposal("netbox_plan", "Netbox: Gerät neu01 anlegen", {"steps": []}, dedup_key="netbox:serial:N1")
    index = NetboxIndex(ctx.netbox)
    report = build_report(ctx, assets, index)
    assert report["no_wazuh"] == [["srv-ohne", "Gerät", "server", "keine Quelle"]]  # Switch zählt nicht
    assert report["no_intune"] == [["laptop1", "Gerät", "client", "wazuh"]]
    assert report["not_in_netbox"] == [["neu01", "intune", "N1", "Vorschlag offen"]]
    assert report["stale"] == [["laptop1", "Gerät", "client", "2020-01-01", ""],
                               ["vm-aus", "VM", "server", "2020-02-02", "VM ausgeschaltet"]]
    pid = propose_coverage(ctx, assets, index)
    content = ctx.store.get_proposal(pid).payload["content"]
    assert "## Ohne Wazuh-Agent" in content and "| srv-ohne | Gerät | server | keine Quelle |" in content
    assert ctx.store.get_proposal(pid).payload["path"] == "infrastruktur/abdeckung"
