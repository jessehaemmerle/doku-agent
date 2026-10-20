"""Wiki-Lint: tote Links, Dubletten, Seiten ohne Tags, veraltete Seiten und gelöschte Quellen."""

import httpx
import pytest
from fastapi.testclient import TestClient

from doku_agent import lint, semantic
from doku_agent.apply import apply_proposal
from doku_agent.connectors.netbox import NetboxClient
from doku_agent.egress import EgressGuard
from doku_agent.generators.netbox_docs import document_object
from tests.conftest import FakeNetbox
from tests.test_semantic import FakeEmbedder

AUTH = ("admin", "geheim")


@pytest.fixture
def lctx(ctx, fake_wiki):
    nbf = FakeNetbox()
    ctx.__dict__["netbox"] = NetboxClient(ctx.cfg.netbox, EgressGuard.from_config(ctx.cfg),
                                          transport=httpx.MockTransport(nbf.handler))
    ctx.__dict__["embedder"] = FakeEmbedder()
    ctx.nbf = nbf
    return ctx


def _fresh(ctx):
    ctx.__dict__.pop("conventions", None)


def test_dead_links_untagged_and_title_duplicates(lctx, fake_wiki):
    fake_wiki.add("netzwerk/vlans", "VLAN-Plan", "Siehe [Firewall](/netzwerk/firewall) und [alt](/de/netzwerk/alt), "
                  "[Logo](/assets/logo.png), [extern](https://example.com).", tags=["netz"])
    fake_wiki.add("netzwerk/firewall", "Firewall", "Text", tags=["netz"])
    fake_wiki.add("alt/vlans", "VLAN Plan", "Alte Fassung")  # ohne Tags, gleicher Titel (normalisiert)
    summary = lint.run_lint(lctx)
    report = lctx.store.kv_get(lint.REPORT_KEY)
    assert report["dead_links"] == [{"path": "netzwerk/vlans", "title": "VLAN-Plan", "target": "/de/netzwerk/alt"}]
    assert [d["path"] for d in report["untagged"]] == ["alt/vlans"]
    assert report["duplicates"][0]["reason"] == "gleicher Titel"
    assert summary["tote_links"] == 1 and summary["dubletten"] == 1


def test_report_page_is_proposed_without_volatile_content(lctx, fake_wiki):
    fake_wiki.add("a", "A", "[weg](/fehlt)", tags=["x"])
    lint.run_lint(lctx)
    report = lctx.store.kv_get(lint.REPORT_KEY)
    prop = lctx.store.get_proposal(report["report_proposal"])
    content = prop.payload["content"]
    assert prop.payload["path"] == "wartung/wiki-lint" and "`/de/fehlt`" in content
    assert report["at"][:10] not in content  # kein Datum: unveränderte Befunde ergeben keinen neuen Vorschlag
    apply_proposal(lctx, prop.id)
    _fresh(lctx)
    lint.run_lint(lctx)
    report = lctx.store.kv_get(lint.REPORT_KEY)
    assert report.get("report_proposal") is None  # Bericht unverändert
    assert all(d["path"] != "wartung/wiki-lint" for d in report["untagged"])  # eigener Bericht wird nicht geprüft


def test_semantic_duplicates_skip_distinct_agent_objects(lctx, fake_wiki):
    text = "Backup der Fileserver mit Veeam jede Nacht um 22 Uhr auf das NAS02 mit 14 Tagen Aufbewahrung."
    a = fake_wiki.add("infra/backup", "Backup", text, tags=["x"])
    fake_wiki.add("alt/sicherung", "Sicherung Fileserver", text + " Kopie.", tags=["x"])
    s1 = fake_wiki.add("geraete/srv1", "srv1", "| Name | srv1 |\n| Rolle | Server |", tags=["x"])
    s2 = fake_wiki.add("geraete/srv2", "srv2", "| Name | srv2 |\n| Rolle | Server |", tags=["x"])
    lctx.store.kv_set("page-for:netbox:device:1", s1)
    lctx.store.kv_set("page-for:netbox:device:2", s2)
    lctx.cfg.lint.refresh_stale = False
    lctx.cfg.lint.duplicate_threshold = 0.8
    semantic.index_wiki(lctx)
    lint.run_lint(lctx)
    dups = lctx.store.kv_get(lint.REPORT_KEY)["duplicates"]
    assert [(d["a"], d["b"]) for d in dups] == [("infra/backup", "alt/sicherung")] or \
        [(d["b"], d["a"]) for d in dups] == [("infra/backup", "alt/sicherung")]
    assert dups[0]["reason"].startswith("ähnlicher Inhalt")
    assert a


def test_stale_page_gets_update_proposal_and_deleted_source_is_reported(lctx, fake_wiki):
    nbf = lctx.nbf
    dev = nbf.add("dcim/devices", {"name": "srv01", "serial": "S1", "status": {"value": "active", "label": "Aktiv"}})
    gone = nbf.add("dcim/devices", {"name": "srv02", "serial": "S2"})
    for oid in (dev["id"], gone["id"]):
        apply_proposal(lctx, document_object(lctx, "device", oid))
        _fresh(lctx)
    nbf.objects["dcim/devices"][dev["id"]]["serial"] = "S1-NEU"   # Quelle geändert
    del nbf.objects["dcim/devices"][gone["id"]]                   # Quelle gelöscht
    lctx.cfg.lint.report_page = False
    summary = lint.run_lint(lctx)
    report = lctx.store.kv_get(lint.REPORT_KEY)
    assert summary["veraltet"] == 1 and summary["quelle_geloescht"] == 1
    stale = report["stale"][0]
    prop = lctx.store.get_proposal(stale["proposal"])
    assert stale["source"] == f"netbox:device:{dev['id']}" and "S1-NEU" in prop.payload["content"]
    assert report["gone"][0]["source"] == f"netbox:device:{gone['id']}"

    # Nach dem Übernehmen ist die Seite aktuell
    apply_proposal(lctx, stale["proposal"])
    _fresh(lctx)
    del nbf.objects["dcim/devices"]
    lint.run_lint(lctx)
    assert lctx.store.kv_get(lint.REPORT_KEY)["stale"] == []


def test_deleted_wiki_page_mapping_is_cleaned_up(lctx, fake_wiki):
    lctx.store.kv_set("page-for:netbox:device:99", 12345)
    lint.run_lint(lctx)
    assert lctx.store.kv_get("page-for:netbox:device:99") is None


def test_refresh_detects_removed_wazuh_file(lctx):
    class Wazuh:
        def rule_files(self):
            return [{"filename": "local_rules.xml"}]

    lctx.__dict__["wazuh"] = Wazuh()
    with pytest.raises(lint.SourceGone):
        lint.refresh(lctx, "wazuh:rules:geloescht.xml")
    with pytest.raises(lint.Unsupported):
        lint.refresh(lctx, "unbekannt:x")


def test_lint_view(lctx, fake_wiki):
    fake_wiki.add("a", "Seite A", "[weg](/fehlt)")
    lint.run_lint(lctx)
    from doku_agent.web.app import create_app

    html = TestClient(create_app(lctx), base_url="http://localhost").get("/wiki-lint", auth=AUTH).text
    assert "/de/fehlt" in html and "Seite A" in html and "Jetzt prüfen" in html
