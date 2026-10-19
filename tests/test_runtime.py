import json
from datetime import datetime

import httpx
import pytest

from doku_agent.config import ScheduleEntry
from doku_agent.egress import EgressGuard
from doku_agent.generators.freeform import run_freeform
from doku_agent.jobs import run_now
from doku_agent.llm import LLM, LLMError
from doku_agent.scheduler import due_entries
from tests.conftest import FakeLLM, make_config


def test_llm_request_and_think_stripping(tmp_path):
    cfg = make_config(tmp_path)
    bodies = []

    def handler(request):
        bodies.append(json.loads(request.content))
        return httpx.Response(200, json={"message": {"content": '<think>hm</think>{"a": 1}'}})

    llm = LLM(cfg.llm, EgressGuard.from_config(cfg), transport=httpx.MockTransport(handler))
    assert llm.json("sys", "user", {"type": "object"}) == {"a": 1}
    body = bodies[0]
    assert body["think"] is False and body["stream"] is False and body["format"] == {"type": "object"}
    assert body["options"]["num_ctx"] == 8192 and body["model"] == "qwen3:8b"
    assert body["options"]["num_predict"] == 2048  # ohne Limit generieren kleine Modelle endlos


def test_llm_retries_then_fails_on_invalid_json(tmp_path):
    cfg = make_config(tmp_path)
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(200, json={"message": {"content": "kein json"}})

    llm = LLM(cfg.llm, EgressGuard.from_config(cfg), transport=httpx.MockTransport(handler))
    with pytest.raises(LLMError):
        llm.json("s", "u", {"type": "object"})
    assert len(calls) == 2


def test_store_ignore_and_jobs(ctx):
    jid = ctx.store.enqueue("discovery")
    job = ctx.store.claim_next_job()
    assert job.id == jid and job.status == "running"
    assert ctx.store.claim_next_job() is None
    ctx.store.ignore("netbox:serial:X")
    assert ctx.store.is_ignored("netbox:serial:X")
    ctx.store.unignore("netbox:serial:X")
    assert not ctx.store.is_ignored("netbox:serial:X")
    with pytest.raises(ValueError):
        ctx.store.update_proposal(1, kind="evil")


def test_scheduler_runs_once_per_day(ctx):
    ctx.cfg.schedule = [ScheduleEntry(job="discovery", at="02:00"), ScheduleEntry(job="wazuh_sca", at="03:00", days=[0])]
    tuesday_early = datetime(2026, 10, 20, 1, 0)
    tuesday_late = datetime(2026, 10, 20, 3, 30)
    assert due_entries(ctx, tuesday_early) == []
    assert due_entries(ctx, tuesday_late) == [(0, "discovery")]  # wazuh_sca nur montags
    assert due_entries(ctx, tuesday_late) == []


def test_run_job_records_log_and_failure(ctx):
    job_id, ok = run_now(ctx, "netbox_device", {"id": "1"})
    assert not ok
    job = ctx.store.get_job(job_id)
    assert job.status == "failed" and "Fehler" in job.log


def test_freeform_creates_new_page_following_conventions(ctx, fake_wiki, tmp_path):
    for i in range(2):
        fake_wiki.add(f"infrastruktur/backup/job-{i}", f"Job {i}", "## Zweck\n\nx\n\n## Wiederherstellung\n\ny\n",
                      ["backup"])
    notes = tmp_path / "notizen.txt"
    notes.write_text("Ziel: NAS02\nAufbewahrung: 14 Tage", encoding="utf-8")
    ctx.__dict__["llm"] = FakeLLM(json_answers=[
        {"titel": "Fileserver Backup", "beschreibung": "Veeam-Job FS-Daily", "aktion": "neu", "seiten_id": 0,
         "bereich": "infrastruktur/backup", "tags": ["Veeam"]},
        {"inhalt": "## Zweck\n\nSichert die Fileserver täglich um 22:00."},
    ])
    pid = run_freeform(ctx, "Dokumentiere das Fileserver-Backup", [notes])
    prop = ctx.store.get_proposal(pid)
    assert prop.payload["path"] == "infrastruktur/backup/fileserver-backup"
    assert set(prop.payload["tags"]) == {"backup", "veeam"}
    assert "## Wiederherstellung" in prop.payload["content"]  # gelernter Pflichtabschnitt ergänzt
    assert "NAS02" in ctx.llm.calls[0][1]  # Dateiinhalt ging in den Prompt


def test_freeform_extends_existing_page(ctx, fake_wiki):
    page_id = fake_wiki.add("infrastruktur/backup/fileserver", "Fileserver Backup", "## Zweck\n\nTäglich.\n", ["backup"])
    ctx.__dict__["llm"] = FakeLLM(json_answers=[
        {"titel": "Fileserver Backup", "beschreibung": "", "aktion": "ergaenzen", "seiten_id": page_id,
         "bereich": "infrastruktur/backup", "tags": []},
        {"operationen": [{"op": "add_section", "heading": "Aufbewahrung", "after": "Zweck", "content": "14 Tage."}]},
    ])
    pid = run_freeform(ctx, "Fileserver Backup: Aufbewahrung 14 Tage")
    prop = ctx.store.get_proposal(pid)
    assert prop.payload["action"] == "update" and prop.payload["page_id"] == page_id
    assert prop.payload["content"].startswith("## Zweck\n\nTäglich.")
    assert "## Aufbewahrung\n\n14 Tage." in prop.payload["content"]


def test_freeform_rejects_hallucinated_page_id(ctx, fake_wiki):
    ctx.__dict__["llm"] = FakeLLM(json_answers=[
        {"titel": "Neu", "beschreibung": "", "aktion": "ergaenzen", "seiten_id": 999, "bereich": "x", "tags": []},
        {"inhalt": "Text"},
    ])
    prop = ctx.store.get_proposal(run_freeform(ctx, "Etwas Neues"))
    assert prop.payload["action"] == "create"


def test_safe_area_strips_traversal():
    from doku_agent.generators.freeform import safe_area
    assert safe_area("/../infrastruktur/./backup/") == "infrastruktur/backup"
    assert safe_area("it/Server Räume") == "it/Server-Räume"


def test_freeform_keeps_raw_notes_when_model_delivers_nothing(ctx, fake_wiki):
    ctx.__dict__["llm"] = FakeLLM(json_answers=[
        {"titel": "Drucker", "beschreibung": "", "aktion": "neu", "seiten_id": 0, "bereich": "it", "tags": []},
        {"inhalt": "Drucker"},
    ])
    prop = ctx.store.get_proposal(run_freeform(ctx, "Drucker im 2. OG: HP M507, IP 10.0.5.20"))
    assert "IP 10.0.5.20" in prop.payload["content"]
    assert any("Rohfassung" in h for h in prop.payload["hints"])
