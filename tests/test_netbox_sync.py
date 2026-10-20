"""Abgleich bestehender Netbox-Maschinen: Änderungen, Auswahl, Konflikte, Rollback, UI."""

import logging
import re

import httpx
import pytest
from fastapi.testclient import TestClient

from doku_agent.apply import ApplyError, apply_proposal
from doku_agent.connectors.netbox import NetboxClient, NetboxError
from doku_agent.discovery import Asset, Iface, NetboxIndex
from doku_agent.egress import EgressGuard
from doku_agent.netbox_plan import execute_plan
from doku_agent.netbox_sync import build_changes, propose_sync
from doku_agent.web.app import create_app
from tests.conftest import FakeNetbox

AUTH = ("admin", "geheim")


@pytest.fixture
def nbf():
    return FakeNetbox()


@pytest.fixture
def sctx(ctx, nbf):
    ctx.__dict__["netbox"] = NetboxClient(ctx.cfg.netbox, EgressGuard.from_config(ctx.cfg),
                                          transport=httpx.MockTransport(nbf.handler))
    return ctx


def _device(nbf, **fields):
    base = {"name": "srv01", "serial": "", "platform": None, "primary_ip4": None,
            "device_type": {"id": 1, "model": "Unbekannt", "manufacturer": {"id": 1, "name": "Unbekannt"}}}
    return nbf.add("dcim/devices", {**base, **fields})


def _asset(**fields):
    base = dict(name="srv01", serial="ABC123", manufacturer="Dell Inc.", model="PowerEdge R650",
                os_name="Microsoft Windows Server 2022", primary_ip="10.0.0.5",
                interfaces=[Iface("eth0", "AA:BB:CC:DD:EE:01", ["10.0.0.5/24"])], sources={"wazuh": {"agent_id": "1"}})
    return Asset(**{**base, **fields})


def _changes(sctx, asset, found=None):
    index = NetboxIndex(sctx.netbox)
    endpoint, oid, how = found or index.find(asset)
    return build_changes(asset, index.objects[(endpoint, oid)], endpoint, how, sctx.netbox, sctx.cfg.netbox, index)


def test_fills_missing_fields_and_network(sctx, nbf):
    dev = _device(nbf, platform={"id": 9, "slug": "windows-server-2019", "name": "Windows Server 2019"})
    nbf.add("dcim/interfaces", {"device": dev["id"], "name": "eth0"})
    changes, _ = _changes(sctx, _asset())
    labels = {c.label: c for c in changes}
    assert set(labels) == {"Seriennummer", "Plattform", "Gerätetyp", "MAC an eth0", "IP an eth0", "Primäre IPv4"}
    assert labels["Plattform"].category == "os" and labels["Seriennummer"].category == "missing"
    assert labels["Primäre IPv4"].requires == [labels["IP an eth0"].key]

    assert propose_sync(sctx, _asset(), NetboxIndex(sctx.netbox).find(_asset()), NetboxIndex(sctx.netbox))
    prop = sctx.store.list_proposals("pending")[0]
    assert apply_proposal(sctx, prop.id) == "applied"
    dev = nbf.objects["dcim/devices"][dev["id"]]
    assert dev["serial"] == "ABC123" and dev["primary_ip4"] in nbf.objects["ipam/ip-addresses"]
    assert nbf.objects["dcim/platforms"][dev["platform"]]["slug"] == "microsoft-windows-server-2022"
    assert any(m["mac_address"] == "AA:BB:CC:DD:EE:01" for m in nbf.objects["dcim/mac-addresses"].values())
    jobs = sctx.store.list_jobs()
    assert jobs[0].name == "netbox_device" and jobs[0].params["id"] == dev["id"]  # Steckbrief folgt


def test_generic_os_name_is_not_a_change(sctx, nbf):
    _device(nbf, serial="ABC123", platform={"id": 2, "slug": "windows-11-pro", "name": "Windows 11 Pro"})
    changes, _ = _changes(sctx, _asset(os_name="Windows", interfaces=[], model=""))
    assert "Plattform" not in {c.label for c in changes}


def test_vm_resources_respect_tolerance(sctx, nbf):
    nbf.add("virtualization/virtual-machines", {"name": "vm01", "serial": "VMware-1", "vcpus": 2.0, "memory": 16384,
                                                "platform": {"id": 1, "slug": "ubuntu", "name": "Ubuntu"}})
    asset = _asset(name="vm01", serial="VMware-1", os_name="Ubuntu", cpu_cores=4, memory_mb=16093, interfaces=[])
    labels = {c.label: c for c in _changes(sctx, asset)[0]}
    assert labels["vCPUs"].after == "4" and labels["vCPUs"].category == "os"
    assert "Arbeitsspeicher (MB)" not in labels  # 1,8 % Abweichung liegt in der Toleranz
    asset.memory_mb = 32000
    assert "Arbeitsspeicher (MB)" in {c.label for c in _changes(sctx, asset)[0]}


def test_rename_by_serial_keeps_domain_and_detects_conflict(sctx, nbf):
    _device(nbf, name="srv-alt.firma.local", serial="ABC123")
    changes, _ = _changes(sctx, _asset(name="srv-neu", interfaces=[]))
    rename = next(c for c in changes if c.category == "rename")
    assert (rename.before, rename.after) == ("srv-alt.firma.local", "srv-neu.firma.local")
    _device(nbf, name="srv-neu.firma.local")
    changes, hints = _changes(sctx, _asset(name="srv-neu", interfaces=[]))
    assert not [c for c in changes if c.category == "rename"]
    assert any("schon vergeben" in h for h in hints)


def test_ip_change_with_stale_ip_only_reported(sctx, nbf):
    dev = _device(nbf, serial="ABC123", platform={"id": 1, "slug": "microsoft-windows-server-2022", "name": "x"},
                  device_type={"id": 1, "model": "PowerEdge R650", "manufacturer": {"id": 1, "name": "Dell Inc."}})
    iface = nbf.add("dcim/interfaces", {"device": dev["id"], "name": "eth0",
                                         "mac_addresses": [{"mac_address": "AA:BB:CC:DD:EE:01"}]})
    old_ip = nbf.add("ipam/ip-addresses", {"address": "10.0.0.5/24", "assigned_object_id": iface["id"],
                                           "assigned_object_type": "dcim.interface"})
    nbf.objects["dcim/devices"][dev["id"]]["primary_ip4"] = {"id": old_ip["id"], "address": "10.0.0.5/24"}
    asset = _asset(primary_ip="10.0.0.9", interfaces=[Iface("eth0", "AA:BB:CC:DD:EE:01", ["10.0.0.9/24"])])
    changes, hints = _changes(sctx, asset)
    assert [(c.label, c.category) for c in changes] == [("IP an eth0", "network"), ("Primäre IPv4", "network")]
    assert any("10.0.0.5/24" in h and "nur Hinweis" in h for h in hints)


def test_disabled_categories_are_not_proposed(sctx, nbf):
    sctx.cfg.netbox.sync = ["missing"]
    _device(nbf, name="srv-alt", serial="ABC123", platform={"id": 9, "slug": "debian", "name": "Debian"})
    changes, _ = _changes(sctx, _asset(name="srv-neu", os_name="Ubuntu", interfaces=[]))
    assert {c.category for c in changes} == {"missing"}


def test_selection_dependencies_and_conflicts(sctx, nbf):
    dev = _device(nbf)
    nbf.add("dcim/interfaces", {"device": dev["id"], "name": "eth0"})
    asset = _asset()
    index = NetboxIndex(sctx.netbox)
    propose_sync(sctx, asset, index.find(asset), index)
    prop = sctx.store.list_proposals("pending")[0]
    keys = {c["label"]: c["key"] for c in prop.payload["changes"]}

    sctx.store.update_proposal(prop.id, payload={**prop.payload, "selected": [keys["Primäre IPv4"]]})
    with pytest.raises(ApplyError, match="voraus"):
        apply_proposal(sctx, prop.id)

    sctx.store.update_proposal(prop.id, status="pending", payload={
        **prop.payload, "selected": [keys["Seriennummer"], keys["Plattform"]]})
    nbf.objects["dcim/devices"][dev["id"]]["serial"] = "VON-HAND"  # Kollege war schneller
    assert apply_proposal(sctx, prop.id) == "applied"
    result = sctx.store.get_proposal(prop.id).result
    assert "Seriennummer: in Netbox inzwischen geändert" in result and "Übernommen: Plattform" in result
    assert nbf.objects["dcim/devices"][dev["id"]]["serial"] == "VON-HAND"


def test_rollback_restores_changed_fields(sctx, nbf):
    dev = _device(nbf, serial="ALT")
    nbf.fail_on = "ipam/ip-addresses"
    steps = [{"action": "update", "endpoint": "dcim/devices", "id": dev["id"], "data": {"serial": "NEU"}},
             {"action": "create", "endpoint": "ipam/ip-addresses", "data": {"address": "10.1.1.1/24"}}]
    with pytest.raises(NetboxError, match="zurückgesetzt"):
        execute_plan(sctx.netbox, steps, logging.getLogger("t"))
    assert nbf.objects["dcim/devices"][dev["id"]]["serial"] == "ALT"


def test_resolved_deviation_closes_pending_proposal(sctx, nbf):
    dev = _device(nbf)
    asset = _asset(interfaces=[], os_name="", model="")
    index = NetboxIndex(sctx.netbox)
    assert propose_sync(sctx, asset, index.find(asset), index)
    nbf.objects["dcim/devices"][dev["id"]]["serial"] = "ABC123"  # von Hand korrigiert
    index = NetboxIndex(sctx.netbox)
    assert not propose_sync(sctx, asset, index.find(asset), index)
    prop = sctx.store.list_proposals()[0]
    assert prop.status == "rejected" and "Keine Abweichung mehr" in prop.result


def test_web_checkboxes_select_changes(sctx, nbf):
    dev = _device(nbf)
    asset = _asset(interfaces=[], model="")
    index = NetboxIndex(sctx.netbox)
    propose_sync(sctx, asset, index.find(asset), index)
    prop = sctx.store.list_proposals("pending")[0]
    client = TestClient(create_app(sctx), base_url="http://localhost")
    html = client.get(f"/vorschlaege/{prop.id}", auth=AUTH).text
    assert html.count('name="change"') == 2 and "Ausgewählte in Netbox übernehmen" in html
    token = re.search(r'name="csrf" value="([^"]+)"', html).group(1)
    serial_key = next(c["key"] for c in prop.payload["changes"] if c["label"] == "Seriennummer")
    resp = client.post(f"/vorschlaege/{prop.id}/freigeben", auth=AUTH, follow_redirects=False,
                       data={"csrf": token, "change": [serial_key]})
    assert "msg=" in resp.headers["location"]
    assert nbf.objects["dcim/devices"][dev["id"]]["serial"] == "ABC123"
    assert nbf.objects["dcim/devices"][dev["id"]]["platform"] is None  # abgewählt


def test_web_empty_selection_keeps_proposal_open(sctx, nbf):
    _device(nbf)
    asset = _asset(interfaces=[], model="", os_name="")
    index = NetboxIndex(sctx.netbox)
    propose_sync(sctx, asset, index.find(asset), index)
    prop = sctx.store.list_proposals("pending")[0]
    client = TestClient(create_app(sctx), base_url="http://localhost")
    token = re.search(r'name="csrf" value="([^"]+)"', client.get("/", auth=AUTH).text).group(1)
    resp = client.post(f"/vorschlaege/{prop.id}/freigeben", auth=AUTH, follow_redirects=False, data={"csrf": token})
    assert "err=" in resp.headers["location"]
    assert sctx.store.get_proposal(prop.id).status == "pending"


def test_wiki_page_follows_rename(sctx, nbf, fake_wiki):
    from doku_agent.generators.netbox_docs import document_object

    dev = _device(nbf, name="srv-alt", serial="ABC123", status={"value": "active", "label": "Active"})
    apply_proposal(sctx, document_object(sctx, "device", dev["id"]))
    assert [p["path"] for p in fake_wiki.pages.values()] == ["infrastruktur/geraete/srv-alt"]
    nbf.objects["dcim/devices"][dev["id"]]["name"] = "srv-neu"
    sctx.__dict__.pop("conventions", None)
    prop = sctx.store.get_proposal(document_object(sctx, "device", dev["id"]))
    assert prop.payload["action"] == "update" and prop.payload["path"] == "infrastruktur/geraete/srv-alt"
    assert prop.payload["title"] == "srv-neu"
    apply_proposal(sctx, prop.id)
    assert len(fake_wiki.pages) == 1 and next(iter(fake_wiki.pages.values()))["title"] == "srv-neu"


def test_mac_case_does_not_matter(sctx, nbf):
    dev = _device(nbf, serial="ABC123", platform={"id": 1, "slug": "microsoft-windows-server-2022", "name": "x"})
    nbf.add("dcim/interfaces", {"device": dev["id"], "name": "eth0", "mac_addresses": [{"mac_address": "AA:BB:CC:DD:EE:01"}]})
    changes, _ = _changes(sctx, _asset(model="", interfaces=[Iface("eth0", "aa:bb:cc:dd:ee:01")]))
    assert not [c for c in changes if c.label.startswith("MAC") or c.label == "Interface"]


# --- Regressionen aus dem Code-Review des Abgleichs -------------------------

def test_dependencies_are_dropped_transitively(sctx, nbf):
    sctx.cfg.netbox.sync = ["network"]
    dev = _device(nbf, serial="ABC123", platform={"id": 1, "slug": "microsoft-windows-server-2022", "name": "x"})
    iface = nbf.add("dcim/interfaces", {"device": dev["id"], "name": "eth0",
                                         "mac_addresses": [{"mac_address": "AA:BB:CC:DD:EE:01"}]})
    ip = nbf.add("ipam/ip-addresses", {"address": "10.0.0.5/24", "assigned_object_id": iface["id"]})
    # primäre IP gesetzt -> ein Wechsel wäre Kategorie "network" und fällt nur über die Abhängigkeitskette weg
    nbf.objects["dcim/devices"][dev["id"]]["primary_ip4"] = {"id": ip["id"], "address": "10.0.0.5/24"}
    asset = _asset(model="", primary_ip="10.0.9.9", interfaces=[
        Iface("eth0", "AA:BB:CC:DD:EE:01", ["10.0.0.5/24"]), Iface("eth1", "AA:BB:CC:DD:EE:02", ["10.0.9.9/24"])])
    changes, _ = _changes(sctx, asset)
    keys = {c.key for c in changes}
    assert all(r in keys for c in changes for r in c.requires)
    assert "primary_ip4" not in keys and "ip:10.0.9.9" not in keys  # hingen am (nicht erlaubten) neuen Interface


def test_change_keys_are_stable_and_stale_form_is_refused(sctx, nbf):
    dev = _device(nbf)
    asset = _asset(interfaces=[], model="")
    index = NetboxIndex(sctx.netbox)
    propose_sync(sctx, asset, index.find(asset), index)
    prop = sctx.store.list_proposals("pending")[0]
    assert {c["key"] for c in prop.payload["changes"]} == {"serial", "platform"}
    client = TestClient(create_app(sctx), base_url="http://localhost")
    token = re.search(r'name="csrf" value="([^"]+)"', client.get("/", auth=AUTH).text).group(1)
    resp = client.post(f"/vorschlaege/{prop.id}/freigeben", auth=AUTH, follow_redirects=False,
                       data={"csrf": token, "change": ["serial"], "version": "2000-01-01T00:00:00+00:00"})
    assert "aktualisiert" in resp.headers["location"].replace("%20", " ") or "err=" in resp.headers["location"]
    assert nbf.objects["dcim/devices"][dev["id"]]["serial"] == ""


def test_mac_only_match_with_other_serial_is_not_synced(sctx, nbf):
    dev = _device(nbf, name="laptop-a", serial="SERIAL-A")
    nbf.add("dcim/mac-addresses", {"mac_address": "AA:BB:CC:00:00:01",
                                   "assigned_object": {"device": {"id": dev["id"], "name": "laptop-a"}}})
    asset = _asset(name="laptop-b", serial="SERIAL-B", interfaces=[Iface("WLAN", "AA:BB:CC:00:00:01")])
    index = NetboxIndex(sctx.netbox)
    assert index.find(asset)[2] == "mac"
    assert not propose_sync(sctx, asset, index.find(asset), index)
    assert sctx.store.list_proposals() == []


def test_intune_ethernet_mac_does_not_identify(sctx, nbf):
    dev = _device(nbf, name="laptop-a")
    nbf.add("dcim/mac-addresses", {"mac_address": "DD:00:CC:00:00:01",  # MAC der Docking-Station
                                   "assigned_object": {"device": {"id": dev["id"], "name": "laptop-a"}}})
    asset = Asset(name="laptop-b", interfaces=[Iface("Ethernet", "DD:00:CC:00:00:01", identifies=False)])
    assert NetboxIndex(sctx.netbox).find(asset) is None


def test_orphan_mac_prevents_duplicate_creation(sctx, nbf, monkeypatch):
    from doku_agent import discovery

    nbf.add("dcim/sites", {"slug": "hq", "name": "HQ"})
    nbf.add("dcim/mac-addresses", {"mac_address": "AA:AA:AA:AA:AA:AA", "assigned_object": None})
    monkeypatch.setattr(discovery, "wazuh_assets", lambda ctx: [Asset(
        name="neu", interfaces=[Iface("eth0", "AA:AA:AA:AA:AA:AA")], sources={"wazuh": {"agent_id": "9"}})])
    stats = discovery.run_discovery(sctx)
    assert stats["bekannt"] == 1 and stats["vorgeschlagen"] == 0


def test_old_netbox_hint_says_mac_is_replaced(ctx):
    old = FakeNetbox(version="4.1.0")
    ctx.__dict__["netbox"] = NetboxClient(ctx.cfg.netbox, EgressGuard.from_config(ctx.cfg),
                                          transport=httpx.MockTransport(old.handler))
    dev = _device(old, serial="ABC123")
    old.add("dcim/interfaces", {"device": dev["id"], "name": "eth0", "mac_address": "11:11:11:11:11:11"})
    _, hints = _changes(ctx, _asset(model="", os_name="", interfaces=[Iface("eth0", "22:22:22:22:22:22")]))
    assert any("wird ersetzt" in h for h in hints)


def test_platform_prefix_compares_whole_slug_parts(sctx, nbf):
    _device(nbf, serial="ABC123", platform={"id": 2, "slug": "windows-10-pro", "name": "Windows 10 Pro"})
    labels = lambda os_name: {c.label for c in _changes(sctx, _asset(os_name=os_name, interfaces=[], model=""))[0]}
    assert "Plattform" not in labels("Windows")
    assert "Plattform" in labels("Windows 1")


def test_ethernet_mac_is_cached(ctx):
    from doku_agent.discovery import _ethernet_mac

    calls = []

    class FakeIntune:
        def ethernet_mac(self, device_id):
            calls.append(device_id)
            return "aa:bb:cc:dd:ee:ff"

    ctx.__dict__["intune"] = FakeIntune()
    assert _ethernet_mac(ctx, "dev-1") == "AA:BB:CC:DD:EE:FF"
    assert _ethernet_mac(ctx, "dev-1") == "AA:BB:CC:DD:EE:FF"
    assert calls == ["dev-1"]


def test_page_mapping_survives_wiki_errors(sctx, nbf, fake_wiki):
    from doku_agent.generators.netbox_docs import document_object
    from doku_agent.wiki import WikiError

    dev = _device(nbf, name="srv-x", serial="ABC123", status={"value": "active", "label": "Active"})
    page_id = fake_wiki.add("it/irgendwo/srv-x", "srv-x", "Alt\n", [])  # bestehende Seite, Name passt
    document_object(sctx, "device", dev["id"])
    assert sctx.store.kv_get(f"page-for:netbox:device:{dev['id']}") == page_id  # beim Finden gemerkt

    original = fake_wiki.handler
    fake_wiki.handler = lambda request: httpx.Response(500, text="kaputt")
    sctx.__dict__["wiki"] = type(sctx.wiki)(sctx.cfg.wiki, EgressGuard.from_config(sctx.cfg),
                                            transport=httpx.MockTransport(lambda r: fake_wiki.handler(r)))
    sctx.__dict__.pop("conventions", None)
    with pytest.raises(WikiError):
        document_object(sctx, "device", dev["id"])
    assert sctx.store.kv_get(f"page-for:netbox:device:{dev['id']}") == page_id  # Zuordnung bleibt
    fake_wiki.handler = original
