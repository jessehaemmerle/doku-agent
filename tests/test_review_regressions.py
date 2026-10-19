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
