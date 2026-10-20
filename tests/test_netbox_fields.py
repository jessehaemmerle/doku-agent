"""Netbox-Custom-Fields: Anlage-Vorschlag, Wiedererkennung über IDs, ID-Abgleich, 'zuletzt gesehen'."""

import logging

import httpx
import pytest

from doku_agent import discovery, netbox_fields
from doku_agent.apply import ApplyError, apply_proposal
from doku_agent.connectors.netbox import NetboxClient
from doku_agent.discovery import Asset, Iface, NetboxIndex, build_plan
from doku_agent.egress import EgressGuard
from doku_agent.netbox_plan import execute_plan
from doku_agent.netbox_sync import propose_sync
from tests.conftest import FakeNetbox

ALL_TYPES = ["dcim.device", "virtualization.virtualmachine"]


@pytest.fixture
def nbf():
    return FakeNetbox()


@pytest.fixture
def sctx(ctx, nbf):
    ctx.__dict__["netbox"] = NetboxClient(ctx.cfg.netbox, EgressGuard.from_config(ctx.cfg),
                                          transport=httpx.MockTransport(nbf.handler))
    return ctx


def _fields(nbf, types=ALL_TYPES, **overrides):
    for name, (ftype, label, _) in netbox_fields.SPECS.items():
        nbf.add("extras/custom-fields", {"name": name, "label": label, "object_types": list(types),
                                         "type": {"value": overrides.get(name, ftype), "label": ftype},
                                         "status": {"value": "active", "label": "Active"}})


def _device(nbf, **fields):
    base = {"name": "srv01", "serial": "ABC123", "platform": None, "primary_ip4": None, "custom_fields": {},
            "device_type": {"id": 1, "model": "R650", "manufacturer": {"id": 1, "name": "Dell"}}}
    return nbf.add("dcim/devices", {**base, **fields})


def test_missing_fields_are_proposed_once_and_created(sctx, nbf):
    fs = netbox_fields.status(sctx.netbox, sctx.cfg.netbox.custom_fields)
    assert [s["data"]["name"] for s in fs.steps] == ["wazuh_agent_id", "intune_device_id", "last_seen"]
    assert fs.steps[2]["data"]["type"] == "date" and fs.steps[0]["data"]["object_types"] == ALL_TYPES
    pid = netbox_fields.propose_setup(sctx, fs)
    assert netbox_fields.propose_setup(sctx, fs) == pid  # kein zweiter Vorschlag
    assert apply_proposal(sctx, pid) == "applied"
    created = {f["name"]: f for f in nbf.objects["extras/custom-fields"].values()}
    assert set(created) == {"wazuh_agent_id", "intune_device_id", "last_seen"}


def test_existing_field_gets_missing_object_type_and_type_mismatch_is_reported(sctx, nbf):
    _fields(nbf, types=["dcim.device"], last_seen="text")
    fs = netbox_fields.status(sctx.netbox, sctx.cfg.netbox.custom_fields)
    assert fs.available["dcim/devices"] == {"wazuh_agent_id", "intune_device_id"}
    assert fs.available["virtualization/virtual-machines"] == set()
    assert {s["action"] for s in fs.steps} == {"update"}
    assert all(s["data"]["object_types"] == ALL_TYPES for s in fs.steps)
    assert any("last_seen" in h and "text" in h for h in fs.hints)


def test_ids_win_over_name_and_serial(sctx, nbf):
    _fields(nbf)
    right = _device(nbf, name="alt-name", serial="", custom_fields={"wazuh_agent_id": "042"})
    _device(nbf, name="srv01", serial="OTHER")
    index = NetboxIndex(sctx.netbox, sctx.cfg.netbox.custom_fields)
    asset = Asset(name="srv01", serial="ABC123", sources={"wazuh": {"agent_id": "042"}})
    assert index.find(asset) == ("dcim/devices", right["id"], "wazuh_id")
    assert index.match(asset).startswith("Wazuh-Agent-ID")
    intune = Asset(name="x", sources={"intune": {"id": "dev-guid"}})
    _device(nbf, name="laptop", custom_fields={"intune_device_id": "dev-guid"})
    assert NetboxIndex(sctx.netbox, sctx.cfg.netbox.custom_fields).find(intune)[2] == "intune_id"


def test_id_change_is_a_single_approvable_change_with_conflict_check(sctx, nbf):
    _fields(nbf)
    dev = _device(nbf, custom_fields={"wazuh_agent_id": "001", "last_seen": "2026-10-01"})
    asset = Asset(name="srv01", serial="ABC123", sources={"wazuh": {"agent_id": "009"}, "intune": {"id": "i-1"}})
    index = NetboxIndex(sctx.netbox, sctx.cfg.netbox.custom_fields)
    assert propose_sync(sctx, asset, index.find(asset), index)
    prop = sctx.store.list_proposals("pending")[0]
    changes = {c["key"]: c for c in prop.payload["changes"]}
    assert set(changes) == {"cf:wazuh_agent_id", "cf:intune_device_id"}
    assert changes["cf:wazuh_agent_id"]["before"] == "001" and changes["cf:wazuh_agent_id"]["category"] == "ids"

    nbf.objects["dcim/devices"][dev["id"]]["custom_fields"]["wazuh_agent_id"] = "005"  # von Hand geändert
    sctx.store.update_proposal(prop.id, payload={**prop.payload, "selected": ["cf:wazuh_agent_id"]})
    with pytest.raises(ApplyError, match="Nichts übernommen"):
        apply_proposal(sctx, prop.id)

    sctx.store.update_proposal(prop.id, status="pending", payload={**prop.payload, "selected": ["cf:intune_device_id"]})
    assert apply_proposal(sctx, prop.id) == "applied"
    values = nbf.objects["dcim/devices"][dev["id"]]["custom_fields"]
    assert values == {"wazuh_agent_id": "005", "last_seen": "2026-10-01", "intune_device_id": "i-1"}


def test_ids_are_proposed_even_without_sync_categories(sctx, nbf):
    _fields(nbf)
    _device(nbf)
    sctx.cfg.netbox.sync = []
    asset = Asset(name="srv01", serial="ABC123", sources={"wazuh": {"agent_id": "7"}})
    index = NetboxIndex(sctx.netbox, sctx.cfg.netbox.custom_fields)
    assert propose_sync(sctx, asset, index.find(asset), index)
    assert [c["label"] for c in sctx.store.list_proposals("pending")[0].payload["changes"]] == ["Wazuh-Agent-ID"]


def test_rollback_restores_only_touched_custom_fields(sctx, nbf):
    _fields(nbf)
    dev = _device(nbf, custom_fields={"wazuh_agent_id": "001", "last_seen": "2026-10-01"})
    nbf.fail_on = "ipam/ip-addresses"
    steps = [{"action": "update", "endpoint": "dcim/devices", "id": dev["id"],
              "data": {"custom_fields": {"wazuh_agent_id": "009"}}},
             {"action": "create", "endpoint": "ipam/ip-addresses", "data": {"address": "10.0.0.9/24"}}]
    with pytest.raises(Exception, match="zurückgesetzt"):
        execute_plan(sctx.netbox, steps, logging.getLogger("t"))
    assert nbf.objects["dcim/devices"][dev["id"]]["custom_fields"] == {"wazuh_agent_id": "001",
                                                                       "last_seen": "2026-10-01"}


def test_last_seen_parsing_and_timezone():
    sources = {"wazuh": {"last_seen": "2026-10-19T22:30:00Z"}, "intune": {"last_sync": "2026-10-18T08:00:00Z"}}
    assert netbox_fields.last_seen(sources, "Europe/Vienna") == "2026-10-20"  # 00:30 Ortszeit
    assert netbox_fields.last_seen({"wazuh": {"last_seen": "9999-12-31T23:59:59+00:00"}}, "UTC") is None
    assert netbox_fields.last_seen({"intune": {"last_sync": "0001-01-01T00:00:00Z"}}, "UTC") is None
    assert netbox_fields.last_seen({"wazuh": {"last_seen": "kaputt"}}, "UTC") is None


def test_last_seen_is_updated_without_approval_but_only_forward(sctx, nbf):
    _fields(nbf)
    dev = _device(nbf, custom_fields={"last_seen": "2026-10-10"})
    index = NetboxIndex(sctx.netbox, sctx.cfg.netbox.custom_fields)
    newer = Asset(name="srv01", serial="ABC123", sources={"wazuh": {"last_seen": "2026-10-19T10:00:00Z"}})
    found = index.find(newer)
    assert discovery.update_last_seen(sctx, newer, found, index)
    assert nbf.objects["dcim/devices"][dev["id"]]["custom_fields"]["last_seen"] == "2026-10-19"
    assert sctx.store.list_proposals("pending") == []
    older = Asset(name="srv01", serial="ABC123", sources={"wazuh": {"last_seen": "2026-10-01T10:00:00Z"}})
    index = NetboxIndex(sctx.netbox, sctx.cfg.netbox.custom_fields)
    assert not discovery.update_last_seen(sctx, older, index.find(older), index)


def test_new_machine_plan_carries_custom_fields(sctx, nbf):
    asset = Asset(name="vm-neu", serial="VMware-42", os_name="Ubuntu", sources={"wazuh": {"agent_id": "11"}})
    values = {"dcim/devices": {"wazuh_agent_id": "x"}, "virtualization/virtual-machines": {"wazuh_agent_id": "11"}}
    steps, _ = build_plan(asset, sctx.netbox, sctx.cfg.netbox, 1, values)
    vm = next(s for s in steps if s.get("ref") == "dev")
    assert vm["endpoint"] == "virtualization/virtual-machines" and vm["data"]["custom_fields"] == {"wazuh_agent_id": "11"}
    assert netbox_fields.values_for({"wazuh": {"agent_id": "11", "last_seen": "2026-10-19T10:00:00Z"}},
                                    sctx.cfg.netbox.custom_fields, {"wazuh_agent_id", "last_seen"}, "UTC") == {
        "wazuh_agent_id": "11", "last_seen": "2026-10-19"}


def test_discovery_proposes_setup_and_closes_it_when_fields_exist(sctx, nbf, monkeypatch):
    nbf.add("dcim/sites", {"slug": "hq", "name": "HQ"})
    monkeypatch.setattr(discovery, "wazuh_assets", lambda ctx: [])
    discovery.run_discovery(sctx)
    pending = [p for p in sctx.store.list_proposals("pending") if p.dedup_key == netbox_fields.SETUP_KEY]
    assert len(pending) == 1
    _fields(nbf)
    discovery.run_discovery(sctx)
    assert sctx.store.get_proposal(pending[0].id).status == "rejected"


def test_steckbrief_shows_ids_but_not_last_seen(sctx, nbf, fake_wiki):
    from doku_agent.generators.netbox_docs import document_object

    dev = _device(nbf, custom_fields={"wazuh_agent_id": "042", "last_seen": "2026-10-19"})
    content = sctx.store.get_proposal(document_object(sctx, "device", dev["id"])).payload["content"]
    assert "| Wazuh-Agent-ID | 042 |" in content and "2026-10-19" not in content


def test_interfaces_unaffected_by_ids(sctx, nbf):
    _fields(nbf)
    dev = _device(nbf, custom_fields={"wazuh_agent_id": "1"})
    nbf.add("dcim/interfaces", {"device": dev["id"], "name": "eth0"})
    asset = Asset(name="srv01", serial="ABC123", interfaces=[Iface("eth0", "AA:BB:CC:DD:EE:01")],
                  sources={"wazuh": {"agent_id": "1"}})
    index = NetboxIndex(sctx.netbox, sctx.cfg.netbox.custom_fields)
    assert propose_sync(sctx, asset, index.find(asset), index)
    assert [c["label"] for c in sctx.store.list_proposals("pending")[0].payload["changes"]] == ["MAC an eth0"]
