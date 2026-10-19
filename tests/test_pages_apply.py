import pytest

from doku_agent.apply import ApplyError, apply_proposal, reject_proposal
from doku_agent.pages import Block, PageDraft, propose_page


def _draft(content="| Name | srv01 |", **kw):
    return PageDraft(doc_type="netbox_device", title="srv01", description="Steckbrief srv01",
                     blocks=[Block("netbox-device", "Steckbrief", content)], path_vars={"name": "srv01"},
                     intro="Steckbrief von srv01.", lookup_name="srv01", source="test", **kw)


def test_create_then_apply(ctx, fake_wiki):
    pid = propose_page(ctx, _draft())
    prop = ctx.store.get_proposal(pid)
    assert prop.payload["action"] == "create"
    assert prop.payload["path"] == "infrastruktur/geraete/srv01"
    assert "netbox" in prop.payload["tags"]
    assert apply_proposal(ctx, pid) == "applied"
    page = next(iter(fake_wiki.pages.values()))
    assert page["path"] == "infrastruktur/geraete/srv01"
    assert "<!-- doku-agent:begin netbox-device -->" in page["content"]


def test_update_keeps_human_content_and_page_settings(ctx, fake_wiki):
    human = "Von Hand geschrieben.\n\n## Notizen\n\nWichtig!\n"
    pid_page = fake_wiki.add("infrastruktur/geraete/srv01", "srv01", human, ["server"],
                             scriptCss=".x{}", isPublished=True)
    pid = propose_page(ctx, _draft())
    prop = ctx.store.get_proposal(pid)
    assert prop.payload["action"] == "update"
    assert "+| Name | srv01 |" in prop.diff
    assert apply_proposal(ctx, pid) == "applied"
    page = fake_wiki.pages[pid_page]
    assert page["content"].startswith("Von Hand geschrieben.") and "Wichtig!" in page["content"]
    assert page["tags"] == ["server", "netbox"]
    update = fake_wiki.requests[-1]["variables"]
    # Wiki.js setzt fehlende Felder zurück – deshalb müssen alle mitgeschickt werden
    assert update["isPublished"] is True and update["scriptCss"] == ".x{}" and update["path"] == page["path"]


def test_no_change_means_no_proposal(ctx, fake_wiki):
    apply_proposal(ctx, propose_page(ctx, _draft()))
    ctx.__dict__.pop("conventions", None)  # neue Seitenliste wie in einem neuen Job
    assert propose_page(ctx, _draft()) is None


def test_existing_page_found_by_name_elsewhere(ctx, fake_wiki):
    fake_wiki.add("it/server/srv01", "srv01", "## Zweck\n\nAlt\n", ["server"])
    prop = ctx.store.get_proposal(propose_page(ctx, _draft()))
    assert prop.payload["path"] == "it/server/srv01"
    assert any("über den Namen" in h for h in prop.payload["hints"])


def test_conflict_recomputes_instead_of_overwriting(ctx, fake_wiki):
    page_id = fake_wiki.add("infrastruktur/geraete/srv01", "srv01", "Alt\n", [])
    pid = propose_page(ctx, _draft())
    fake_wiki.pages[page_id]["content"] = "Alt\n\nKollege hat ergänzt.\n"
    result = apply_proposal(ctx, pid)
    assert "zwischenzeitlich geändert" in result
    prop = ctx.store.get_proposal(pid)
    assert prop.status == "pending" and "Kollege hat ergänzt." in prop.payload["content"]
    assert apply_proposal(ctx, pid) == "applied"
    assert "Kollege hat ergänzt." in fake_wiki.pages[page_id]["content"]


def test_edited_proposal_conflict_fails(ctx, fake_wiki):
    page_id = fake_wiki.add("infrastruktur/geraete/srv01", "srv01", "Alt\n", [])
    pid = propose_page(ctx, _draft())
    prop = ctx.store.get_proposal(pid)
    ctx.store.update_proposal(pid, payload={**prop.payload, "edited": True})
    fake_wiki.pages[page_id]["content"] = "geändert\n"
    with pytest.raises(ApplyError):
        apply_proposal(ctx, pid)
    assert ctx.store.get_proposal(pid).status == "failed"


def test_reject_with_ignore_blocks_future_proposals(ctx, fake_wiki):
    pid = propose_page(ctx, _draft())
    reject_proposal(ctx, pid, ignore=True)
    assert propose_page(ctx, _draft()) is None


def test_pending_proposal_is_replaced_not_duplicated(ctx, fake_wiki):
    first = propose_page(ctx, _draft("v1"))
    second = propose_page(ctx, _draft("v2"))
    assert first == second
    assert "v2" in ctx.store.get_proposal(first).payload["content"]
    assert ctx.store.count_pending() == 1
