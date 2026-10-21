"""Regressionstests zu den Funden des Code-Reviews."""

import json
import logging

import httpx
import pytest
from fastapi.testclient import TestClient

from doku_agent import markdown
from doku_agent.apply import ApplyError, apply_proposal
from doku_agent.conventions import AreaProfile
from doku_agent.egress import EgressGuard
from doku_agent.generators.freeform import run_freeform
from doku_agent.jobs import run_now
from doku_agent.llm import LLM
from doku_agent.pages import Block, PageDraft, build_new_content, propose_page
from doku_agent.web.app import create_app
from tests.conftest import FakeLLM, make_config


def test_create_conflict_keeps_freeform_content(ctx, fake_wiki):
    pid = propose_page(ctx, PageDraft(doc_type="freeform", title="VPN", description="", blocks=[],
                                      intro="## Zweck\n\nWichtiger Text.", target_path="it/vpn"))
    fake_wiki.add("it/vpn", "VPN", "Von einer Kollegin angelegt.\n", [])
    with pytest.raises(ApplyError, match="inzwischen eine Seite"):
        apply_proposal(ctx, pid)
    prop = ctx.store.get_proposal(pid)
    assert prop.status == "failed" and "Wichtiger Text." in prop.payload["content"]


def test_profile_uses_only_same_folder(ctx, fake_wiki):
    fake_wiki.add("infrastruktur/uebersicht", "Übersicht", "## Inhalt\n", ["infra"])
    for i in range(3):
        fake_wiki.add(f"infrastruktur/backup/job{i}", f"Job {i}", "## Wiederherstellung\n", ["veeam"])
    prof = ctx.conventions.profile_for_path("infrastruktur/neue-seite")
    assert prof.page_count == 1 and "veeam" not in prof.common_tags
    assert "Wiederherstellung" not in prof.required_sections


def test_truncated_json_retries_with_larger_limit(tmp_path):
    cfg = make_config(tmp_path)
    limits = []

    def handler(request):
        body = json.loads(request.content)
        limits.append(body["options"]["num_predict"])
        if len(limits) == 1:
            return httpx.Response(200, json={"message": {"content": '{"inhalt": "abgeschn'}, "done_reason": "length"})
        return httpx.Response(200, json={"message": {"content": '{"inhalt": "ok"}'}, "done_reason": "stop"})

    llm = LLM(cfg.llm, EgressGuard.from_config(cfg), transport=httpx.MockTransport(handler))
    assert llm.json("s", "u", {"type": "object"}) == {"inhalt": "ok"}
    assert limits == [2048, 4096]


def test_truncated_text_is_marked(tmp_path):
    cfg = make_config(tmp_path)
    llm = LLM(cfg.llm, EgressGuard.from_config(cfg), transport=httpx.MockTransport(
        lambda r: httpx.Response(200, json={"message": {"content": "Halber Satz"}, "done_reason": "length"})))
    assert "abgeschnitten" in llm.text("s", "u")


def test_job_contexts_share_clients(tmp_path):
    from doku_agent.context import Context
    from doku_agent.store import Store

    cfg = make_config(tmp_path)
    base = Context(cfg, Store(cfg.db_path))
    first, second = base.with_log(logging.getLogger("a")), base.with_log(logging.getLogger("b"))
    assert first.wiki is second.wiki and first.netbox is second.netbox


def test_tag_filter_keeps_wiki_spelling(ctx, fake_wiki):
    fake_wiki.add("it/vpn/clients", "Clients", "x", ["VPN Client"])
    ctx.__dict__["llm"] = FakeLLM(json_answers=[
        {"titel": "Neu", "beschreibung": "", "aktion": "neu", "seiten_id": 0, "bereich": "it/vpn",
         "tags": ["vpn client", "erfunden"]},
        {"inhalt": "## Zweck\n\n" + "Ausführlicher Text. " * 20},
    ])
    prop = ctx.store.get_proposal(run_freeform(ctx, "VPN"))
    assert "VPN Client" in prop.payload["tags"] and "erfunden" not in prop.payload["tags"]


def test_raw_notes_with_code_fences_stay_intact(ctx, fake_wiki):
    notes = "Konfiguration:\n```\nlisten 443\n```\n## Keine Überschrift, sondern Notiz"
    ctx.__dict__["llm"] = FakeLLM(json_answers=[
        {"titel": "Proxy", "beschreibung": "", "aktion": "neu", "seiten_id": 0, "bereich": "it", "tags": []},
        {"inhalt": ""},
    ])
    ctx.llm.condense = lambda text, purpose: "ZUSAMMENFASSUNG"  # langer Input würde verdichtet
    content = ctx.store.get_proposal(run_freeform(ctx, notes)).payload["content"]
    assert "listen 443" in content and "ZUSAMMENFASSUNG" not in content
    assert "````text" in content
    titles = [t for _, t in markdown.headings(content)]
    assert "Keine Überschrift, sondern Notiz" not in titles


def test_new_page_follows_learned_section_order():
    profile = AreaProfile(prefix="x", page_count=3, required_sections=["Zweck", "Netzwerk", "Kontakt"])
    draft = PageDraft(doc_type="netbox_device", title="t", description="", blocks=[
        Block("a", "Steckbrief", "S"), Block("b", "Netzwerk", "N")])
    titles = [t for _, t in markdown.headings(build_new_content(draft, profile))]
    assert titles == ["Steckbrief", "Zweck", "Netzwerk", "Kontakt"]


def test_edited_update_gets_fresh_diff(ctx, fake_wiki):
    fake_wiki.add("infrastruktur/geraete/srv01", "srv01", "Alt\n", [])
    pid = propose_page(ctx, PageDraft(doc_type="netbox_device", title="srv01", description="",
                                      blocks=[Block("netbox-device", "Steckbrief", "| a |")], path_vars={"name": "srv01"}))
    client = TestClient(create_app(ctx), base_url="http://localhost")
    html = client.get(f"/vorschlaege/{pid}", auth=("admin", "geheim")).text
    token = html.split('name="csrf" value="')[1].split('"')[0]
    fake_wiki.pages[next(iter(fake_wiki.pages))]["content"] = "Alt\n\nNeu von Hand\n"  # Konflikt erzwingt Requeue
    client.post(f"/vorschlaege/{pid}/freigeben", auth=("admin", "geheim"),
                data={"csrf": token, "content": "Alt\n\nNeu von Hand\n\nMeine Ergänzung\n"})
    prop = ctx.store.get_proposal(pid)
    assert "+Meine Ergänzung" in prop.diff


def test_edited_pending_proposal_is_not_overwritten(ctx):
    pid = ctx.store.add_proposal("wiki_page", "t", {"content": "von Hand", "edited": True}, dedup_key="wiki:x")
    assert ctx.store.add_proposal("wiki_page", "t", {"content": "neu"}, dedup_key="wiki:x") == pid
    assert ctx.store.get_proposal(pid).payload["content"] == "von Hand"


def test_job_loggers_are_not_registered(ctx):
    job_id, _ = run_now(ctx, "netbox_device", {"id": "1"})
    assert f"doku_agent.job.{job_id}" not in logging.Logger.manager.loggerDict
    assert "Fehler" in ctx.store.get_job(job_id).log


# --- Code-Review der Erweiterungen (FortiGate, Entra-Gruppen, Custom Fields, Embeddings, Wiki-Lint) ---------

def _nb(ctx):
    from doku_agent.connectors.netbox import NetboxClient
    from tests.conftest import FakeNetbox

    nbf = FakeNetbox()
    ctx.__dict__["netbox"] = NetboxClient(ctx.cfg.netbox, EgressGuard.from_config(ctx.cfg),
                                          transport=httpx.MockTransport(nbf.handler))
    return nbf


def test_last_seen_not_written_for_doubtful_mac_match(ctx):
    from doku_agent import discovery
    from doku_agent.discovery import Asset, Iface, NetboxIndex
    from tests.test_netbox_fields import _fields

    nbf = _nb(ctx)
    _fields(nbf)
    dev = nbf.add("dcim/devices", {"name": "laptop-a", "serial": "AAA", "custom_fields": {"last_seen": "2026-01-01"}})
    nbf.add("dcim/mac-addresses", {"mac_address": "DD:00:CC:00:00:01",
                                   "assigned_object": {"device": {"id": dev["id"], "name": "laptop-a"}}})
    asset = Asset(name="laptop-b", serial="BBB", interfaces=[Iface("eth0", "DD:00:CC:00:00:01")],
                  sources={"intune": {"last_sync": "2026-10-19T08:00:00Z"}})
    index = NetboxIndex(ctx.netbox, ctx.cfg.netbox.custom_fields)
    found = index.find(asset)
    assert found[2] == "mac"
    assert not discovery.update_last_seen(ctx, asset, found, index)
    assert nbf.objects["dcim/devices"][dev["id"]]["custom_fields"]["last_seen"] == "2026-01-01"


def test_ipv6_address_objects_resolve_by_type():
    from doku_agent.generators import fortigate_docs as fd

    data = fd.FortiData("fw", "root", {}, addresses=[
        {"name": "v6-range", "type": "iprange", "ip6": "::/0", "start-ip": "2001:db8::10", "end-ip": "2001:db8::20"},
        {"name": "v6-fqdn", "type": "fqdn", "ip6": "::/0", "fqdn": "srv.example.com"},
        {"name": "v6-net", "type": "ipprefix", "ip6": "2001:db8::/64"},
        {"name": "v6-all", "type": "ipprefix", "ip6": "::/0"}])
    r = fd.Resolver(data)
    assert [r.address(n) for n in ("v6-range", "v6-fqdn", "v6-net", "v6-all")] == [
        "2001:db8::10–2001:db8::20", "FQDN srv.example.com", "2001:db8::/64", "beliebig"]


def test_groups_page_from_lint_matches_intune_run(ctx):
    from doku_agent.generators import intune_docs
    from tests.test_intune_groups import FakeGraph
    from doku_agent.connectors.intune import IntuneClient

    fake = FakeGraph()
    ctx.cfg.intune.enabled = True
    ctx.cfg.intune.include = ["compliance", "groups"]
    ctx.__dict__["intune"] = IntuneClient(ctx.cfg.intune, EgressGuard({"graph.microsoft.com", "login.microsoftonline.com"}),
                                          transport=httpx.MockTransport(fake.handler))
    results = intune_docs.document_intune(ctx)
    content = ctx.store.get_proposal(results[-1]).payload["content"]
    fake.requests.clear()
    pid = intune_docs.document_groups(ctx)
    assert ctx.store.get_proposal(pid).payload["content"] == content
    assert not any("mobileApps" in r.url.path or "configurationPolicies" in r.url.path for r in fake.requests)


def test_discovery_survives_unreadable_custom_fields(ctx, monkeypatch):
    from doku_agent import discovery, netbox_fields

    nbf = _nb(ctx)
    nbf.forbidden.add("extras/custom-fields")
    nbf.add("dcim/sites", {"slug": "hq", "name": "HQ"})
    monkeypatch.setattr(discovery, "wazuh_assets", lambda c: [discovery.Asset(name="neu", serial="X1",
                                                                              sources={"wazuh": {"agent_id": "5"}})])
    stats = discovery.run_discovery(ctx)
    assert stats["vorgeschlagen"] == 1
    assert not [p for p in ctx.store.list_proposals("pending") if p.dedup_key == netbox_fields.SETUP_KEY]


def test_wazuh_group_errors_after_reading_fail_the_job(ctx, monkeypatch):
    from doku_agent.generators import wazuh_docs

    class Wazuh:
        def manager_config(self):
            return "<ossec_config><global><logall>no</logall></global></ossec_config>"

        def groups(self):
            return [{"name": "kaputt"}, {"name": "linux"}]

        def group_agent_conf(self, name):
            if name == "kaputt":
                raise RuntimeError("nicht lesbar")
            return '<agent_config><syscheck><frequency>3600</frequency></syscheck></agent_config>'

    ctx.__dict__["wazuh"] = Wazuh()
    assert len([r for r in wazuh_docs.document_config(ctx) if r]) == 2  # Manager + linux, "kaputt" übersprungen

    def wiki_down(*a, **k):
        raise RuntimeError("Wiki.js nicht erreichbar")

    monkeypatch.setattr(wazuh_docs, "propose_page", wiki_down)
    with pytest.raises(RuntimeError, match="Wiki.js"):
        wazuh_docs.document_config(ctx)


def test_fortigate_single_section_equals_full_run(ctx):
    import copy

    from doku_agent.generators import fortigate_docs as fd
    from tests import test_fortigate as tf

    tables = copy.deepcopy(tf.TABLES)
    tables["cmdb/firewall/vipgrp"] = [{"name": "VIPs-Web", "member": [{"name": "VIP-Web"}]}]
    tables["cmdb/firewall/addrgrp"].append({"name": "Alles-Web", "member": [{"name": "VIPs-Web"}]})
    tables["cmdb/firewall/policy"][1]["dstaddr"] = [{"name": "Alles-Web"}]
    fake = tf.FakeFortiGate()
    original = tf.TABLES
    tf.TABLES = tables
    try:
        dev = tf.FortiGateDevice(name="fw-zentrale", url="https://fw.test:8443", token="fgt-token")
        ctx.cfg.fortigate.enabled = True
        ctx.cfg.fortigate.devices = [dev]
        ctx._clients["fortigate:fw-zentrale"] = tf.FortiGateClient(dev, EgressGuard({"fw.test"}),
                                                                   transport=httpx.MockTransport(fake.handler))
        ctx.__dict__["llm"] = tf.ExplainingLLM(text_answer="Kurz.")
        full = {ctx.store.get_proposal(p).payload["path"]: ctx.store.get_proposal(p).payload["content"]
                for p in fd.document_fortigate(ctx)}
        single = ctx.store.get_proposal(fd.document_fortigate(ctx, sections=["nat"])[0]).payload["content"]
    finally:
        tf.TABLES = original
    assert single == full["netzwerk/firewall/fw-zentrale/nat"]
    assert "| VIP-Web | static-nat | wan1 | 203.0.113.10:443 → 10.20.0.5:8443 (TCP) | – | 7 |" in single


def test_lint_sca_offline_agent_is_not_reported_as_gone(ctx):
    from doku_agent import lint

    class Wazuh:
        def agents(self, status=None):
            return [{"id": "001", "name": "laptop", "status": "disconnected"},
                    {"id": "002", "name": "srv", "status": "active"}]

    ctx.__dict__["wazuh"] = Wazuh()
    with pytest.raises(lint.Unsupported):
        lint.refresh(ctx, "wazuh:sca:001")
    with pytest.raises(lint.SourceGone):
        lint.refresh(ctx, "wazuh:sca:099")
    ctx.cfg.wazuh.sca_agents = ["laptop"]
    with pytest.raises(lint.Unsupported):
        lint.refresh(ctx, "wazuh:sca:002")  # nicht mehr ausgewählt


def test_group_cache_expires(ctx, monkeypatch):
    from doku_agent.connectors import graph as graph_mod
    from doku_agent.connectors import intune as intune_mod
    from tests.test_intune_groups import FakeGraph, GROUPS, G_STATIC

    fake = FakeGraph()
    client = intune_mod.IntuneClient(ctx.cfg.intune, EgressGuard({"graph.microsoft.com", "login.microsoftonline.com"}),
                                     transport=httpx.MockTransport(fake.handler))
    now = [1000.0]
    monkeypatch.setattr(graph_mod.time, "monotonic", lambda: now[0])
    assert client.group_name(G_STATIC) == "Pilot-Benutzer"
    monkeypatch.setitem(GROUPS, G_STATIC, {**GROUPS[G_STATIC], "displayName": "Pilot-Benutzer (neu)"})
    assert client.group_name(G_STATIC) == "Pilot-Benutzer"
    now[0] += graph_mod.GROUP_CACHE_SECONDS + 1
    assert client.group_name(G_STATIC) == "Pilot-Benutzer (neu)"


def test_new_firewall_rule_only_explains_itself(ctx):
    import json

    from doku_agent.generators import fortigate_docs as fd

    views = [{"id": str(i), "name": f"r{i}"} for i in range(1, 13)]
    data = fd.FortiData("fw", "root", {})
    asked = []

    class LLM(FakeLLM):
        def json(self, system, user, schema):
            rules = json.loads(user.split("Regeln (JSON):\n", 1)[1])
            asked.append([r["id"] for r in rules])
            return {"regeln": [{"id": r["id"], "erklaerung": f"E{r['id']}"} for r in rules]}

    ctx.__dict__["llm"] = LLM()
    assert len(fd._explain(ctx, data, views)) == 12 and len(asked) == 2
    asked.clear()
    out = fd._explain(ctx, data, [{"id": "99", "name": "neu"}, *views])
    assert asked == [["99"]] and out["99"] == "E99" and out["12"] == "E12"
