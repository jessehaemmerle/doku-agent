"""Integrationstest gegen ein echtes Wiki.js 2.x (läuft nur mit DOKU_IT_WIKI_URL und DOKU_IT_WIKI_KEY).

Beispiel:
  DOKU_IT_WIKI_URL=http://127.0.0.1:3000 DOKU_IT_WIKI_KEY=... pytest tests/test_integration_wikijs.py
Achtung: legt Testseiten unter /doku-agent-test/ an.
"""

import os
import time
import uuid

import pytest

from doku_agent.apply import apply_proposal
from doku_agent.context import Context
from doku_agent.pages import Block, PageDraft, propose_page
from doku_agent.store import Store
from tests.conftest import FakeLLM, make_config

URL, KEY = os.environ.get("DOKU_IT_WIKI_URL"), os.environ.get("DOKU_IT_WIKI_KEY")
pytestmark = pytest.mark.skipif(not (URL and KEY), reason="kein Test-Wiki konfiguriert")


@pytest.fixture
def real_ctx(tmp_path):
    cfg = make_config(tmp_path, wiki={"url": URL, "api_key": KEY, "locale": "en",
                                      "paths": {"netbox_device": "doku-agent-test/{name}"}})
    ctx = Context(cfg, Store(cfg.db_path))
    ctx.__dict__["llm"] = FakeLLM()
    return ctx


def test_create_extend_and_preserve_settings(real_ctx):
    name = f"srv-{uuid.uuid4().hex[:6]}"
    draft = PageDraft(doc_type="netbox_device", title=name, description="Integrationstest",
                      blocks=[Block("netbox-device", "Steckbrief", "| Eigenschaft | Wert |\n|---|---|\n| Status | aktiv |")],
                      path_vars={"name": name}, intro="Testseite.", source="it")
    assert apply_proposal(real_ctx, propose_page(real_ctx, draft)) == "applied"
    wiki = real_ctx.wiki
    page = wiki.get_page_by_path(f"doku-agent-test/{name}")
    assert page is not None and "doku-agent:begin netbox-device" in page.content

    # Mensch ergänzt die Seite und setzt eigenes CSS
    wiki.update_page(page, content=page.content + "\n## Notizen\n\nVon Hand.\n")
    page = wiki.get_page(page.id)
    raw_update = wiki._gql(
        "mutation($id: Int!, $content: String, $scriptCss: String, $path: String, $locale: String, "
        "$isPublished: Boolean, $isPrivate: Boolean, $title: String, $description: String, $editor: String, "
        "$tags: [String]) { pages { update(id: $id, content: $content, scriptCss: $scriptCss, path: $path, "
        "locale: $locale, isPublished: $isPublished, isPrivate: $isPrivate, title: $title, description: $description, "
        "editor: $editor, tags: $tags) { responseResult { succeeded message } } } }",
        {"id": page.id, "content": page.content, "scriptCss": ".hinweis { color: red; }", "path": page.path,
         "locale": page.locale, "isPublished": True, "isPrivate": False, "title": page.title,
         "description": page.description, "editor": "markdown", "tags": page.tags})
    assert raw_update["pages"]["update"]["responseResult"]["succeeded"]

    # Agent aktualisiert seinen Block
    real_ctx.__dict__.pop("conventions", None)
    draft.blocks = [Block("netbox-device", "Steckbrief", "| Eigenschaft | Wert |\n|---|---|\n| Status | offline |")]
    pid = propose_page(real_ctx, draft)
    assert real_ctx.store.get_proposal(pid).payload["action"] == "update"
    assert apply_proposal(real_ctx, pid) == "applied"

    page = wiki.get_page(page.id)
    assert "| Status | offline |" in page.content and "| Status | aktiv |" not in page.content
    assert "Von Hand." in page.content
    assert page.is_published is True
    assert ".hinweis" in page.script_css, "Seiten-CSS darf durch das Update nicht verloren gehen"
    assert "netbox" in page.tags

    # Marker sind im gerenderten HTML unsichtbar
    for _ in range(10):
        render = wiki._gql("query($id: Int!) { pages { single(id: $id) { render } } }", {"id": page.id})
        html = render["pages"]["single"]["render"] or ""
        if "offline" in html:
            break
        time.sleep(1)
    assert "offline" in html
    assert "doku-agent" not in html  # Wiki.js entfernt HTML-Kommentare beim Rendern


def _create(wiki, path, title, content, tags=("it",)):
    return wiki.create_page(path, title, content, "Integrationstest", list(tags))


def test_lint_finds_dead_links_untagged_and_duplicates(real_ctx):
    from doku_agent import lint

    run = uuid.uuid4().hex[:6]
    base = f"doku-agent-test/lint-{run}"
    wiki = real_ctx.wiki
    _create(wiki, f"{base}/ziel", "Ziel", "Da.")
    _create(wiki, f"{base}/quelle", "Quelle", f"[ok](/{base}/ziel), [kaputt](/{base}/fehlt), "
                                              f"[relativ](ziel), [extern](https://example.com)")
    _create(wiki, f"{base}/ohne-tags", f"Dublette {run}", "Text", tags=())
    _create(wiki, f"{base}/zweite", f"Dublette {run}", "Text")
    real_ctx.cfg.lint.report_page = False
    for _ in range(10):  # Wiki.js erfasst Links beim Rendern (asynchron)
        lint.run_lint(real_ctx)
        report = real_ctx.store.kv_get(lint.REPORT_KEY)
        dead = [d for d in report["dead_links"] if d["path"].startswith(base)]
        if dead:
            break
        time.sleep(1)
    targets = sorted(d["target"] for d in dead)
    # absoluter Link auf fehlende Seite und relativer Link (relativ zur Seite selbst, wie Wiki.js auflöst)
    assert targets == [f"/en/{base}/fehlt", f"/en/{base}/quelle/ziel"]
    assert any(d["path"] == f"{base}/ohne-tags" for d in report["untagged"])
    assert any({d["a"], d["b"]} == {f"{base}/ohne-tags", f"{base}/zweite"} for d in report["duplicates"])


def test_semantic_index_against_real_wiki(real_ctx):
    from doku_agent import semantic
    from tests.test_semantic import FakeEmbedder

    run = uuid.uuid4().hex[:6]
    path = f"doku-agent-test/dienste-{run}"
    _create(real_ctx.wiki, path, "Server-Dienste", f"## Lizenzen\n\nFlexLM-{run} läuft auf srv-lic01.\n\n"
                                                    "## Drucker\n\nPaperCut auf srv-print02.")
    real_ctx.__dict__["embedder"] = FakeEmbedder()
    stats = semantic.index_wiki(real_ctx)
    assert stats["aktualisiert"] >= 1
    hits = semantic.search(real_ctx, f"Wo läuft FlexLM-{run}?", k=1)
    assert hits[0].path == path and hits[0].heading == "Lizenzen"
    assert semantic.index_wiki(real_ctx)["aktualisiert"] == 0
