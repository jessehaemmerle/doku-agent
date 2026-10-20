"""Lokale Embeddings: Ollama-Aufruf, Zerlegung, inkrementeller Index, Suche, Fragen, Seitenwahl."""

import json
import re
import threading

import httpx
import numpy as np
import pytest
from fastapi.testclient import TestClient

from doku_agent import semantic
from doku_agent.embeddings import Embedder, EmbeddingError
from doku_agent.egress import EgressGuard
from doku_agent.generators.freeform import _candidates
from doku_agent.wiki import Page
from tests.conftest import FakeLLM

AUTH = ("admin", "geheim")
DIM = 256


def bag_of_words(text: str) -> list[float]:
    """Deterministischer Ersatz für das Modell: Wörter landen in festen Dimensionen."""
    vec = np.zeros(DIM, dtype=np.float32)
    for word in re.findall(r"[a-zäöüß0-9]{3,}", text.lower()):
        vec[sum(map(ord, word)) % DIM] += 1
    return vec.tolist()


class FakeEmbedder:
    def __init__(self):
        self.calls = 0

    def embed(self, texts):
        self.calls += 1
        return [bag_of_words(t) for t in texts]

    def query(self, text):
        return bag_of_words(text)


@pytest.fixture
def sem(ctx, fake_wiki):
    ctx.__dict__["embedder"] = FakeEmbedder()
    fake_wiki.add("infrastruktur/dienste", "Server-Dienste", "## Lizenzen\n\nDer FlexLM Lizenzserver läuft auf "
                  "srv-lic01, Port 27000.\n\n## Drucker\n\nDruckserver ist srv-print02 mit PaperCut.", tags=["infra"])
    fake_wiki.add("netzwerk/vlans", "VLAN-Plan", "## Übersicht\n\nVLAN 20 ist die DMZ, VLAN 30 das Gäste-WLAN.")
    fake_wiki.add("clients/backup", "Client-Backup", "<!-- doku-agent:begin x -->\nVeeam Agent sichert "
                  "Notebooks täglich.\n<!-- doku-agent:end x -->")
    return ctx


def test_embedder_batches_and_checks_answer(ctx):
    bodies = []

    def handler(request):
        body = json.loads(request.content)
        bodies.append(body)
        return httpx.Response(200, json={"embeddings": [[1.0, 0.0]] * len(body["input"])})

    ctx.cfg.embeddings.batch_size = 2
    emb = Embedder(ctx.cfg.embeddings, ctx.cfg.llm, EgressGuard.from_config(ctx.cfg),
                   transport=httpx.MockTransport(handler))
    assert len(emb.embed(["a", "b", "c"])) == 3
    assert [len(b["input"]) for b in bodies] == [2, 1]
    assert bodies[0]["model"] == "qwen3-embedding:0.6b" and bodies[0]["truncate"] is True
    emb.query("Wo?")
    assert bodies[-1]["input"][0].startswith("Instruct:") and bodies[-1]["input"][0].endswith("Query: Wo?")

    bad = Embedder(ctx.cfg.embeddings, ctx.cfg.llm, EgressGuard.from_config(ctx.cfg),
                   transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"embeddings": []})))
    with pytest.raises(EmbeddingError):
        bad.embed(["x"])


def test_chunk_page_splits_by_headings_and_strips_markers():
    content = ("Einleitung mit genug Text für einen Abschnitt.\n\n## Betrieb\n\nAbsatz eins ist hier.\n\n"
               "### Wartung\n\n<!-- doku-agent:begin w -->\nMontags um 6 Uhr wird gepatcht.\n"
               "<!-- doku-agent:end w -->\n\n```\n## keine Überschrift im Code\n```\n\n## Kontakt\n\n" + "x" * 50)
    page = Page(id=1, path="a", title="Fileserver", description="Zentraler Fileserver", content=content)
    chunks = semantic.chunk_page(page, 1500)
    headings = [h for h, _ in chunks]
    assert headings == ["", "", "Betrieb", "Betrieb › Wartung", "Kontakt"]
    assert chunks[0][1] == "Zentraler Fileserver"
    assert all("doku-agent:" not in t for _, t in chunks)
    assert "## keine Überschrift im Code" in chunks[3][1]
    long = Page(id=2, path="b", title="T", content="## A\n\n" + "\n\n".join(["wort " * 60] * 10))
    assert all(len(t) <= 400 for _, t in semantic.chunk_page(long, 400))


def test_index_is_incremental(sem, fake_wiki):
    stats = semantic.index_wiki(sem)
    assert stats["aktualisiert"] == 3 and stats["abschnitte"] >= 4
    calls = sem.embedder.calls
    assert semantic.index_wiki(sem)["aktualisiert"] == 0 and sem.embedder.calls == calls
    fake_wiki.pages[2]["updatedAt"] = "2026-10-20T10:00:00Z"
    assert semantic.index_wiki(sem)["aktualisiert"] == 1
    del fake_wiki.pages[3]
    assert semantic.index_wiki(sem)["entfernt"] == 1
    sem.cfg.embeddings.model = "bge-m3"
    assert semantic.index_wiki(sem)["aktualisiert"] == 2  # anderes Modell: alles neu


def test_search_finds_section_and_limits_per_page(sem):
    semantic.index_wiki(sem)
    hits = semantic.search(sem, "Auf welchem Server läuft der FlexLM Lizenzserver?", k=3)
    assert hits[0].path == "infrastruktur/dienste" and hits[0].heading == "Lizenzen"
    assert sum(1 for h in hits if h.page_id == hits[0].page_id) <= 2
    assert semantic.page_vectors(sem)[1].shape[0] == 3


def test_answer_cites_sources(sem):
    semantic.index_wiki(sem)
    sem.__dict__["llm"] = FakeLLM(json_answers=[{"antwort": "Auf srv-lic01, Port 27000 [1].", "quellen": [1, 99]}])
    text, sources = semantic.answer(sem, "Wo läuft der FlexLM Lizenzserver?")
    assert text == "Auf srv-lic01, Port 27000 [1]."
    assert [s["n"] for s in sources] == [1] and sources[0]["url"] == "https://wiki.test/de/infrastruktur/dienste"
    prompt = sem.llm.calls[0][1]
    assert "[1] Server-Dienste › Lizenzen (/infrastruktur/dienste)" in prompt


def test_answer_without_index_says_so(sem):
    text, sources = semantic.answer(sem, "Irgendwas?")
    assert "Suchindex" in text and sources == []


def test_freeform_prefers_semantic_candidates(sem):
    semantic.index_wiki(sem)
    sem.__dict__.pop("conventions", None)
    # Titel/Pfad teilen kein Wort mit dem Auftrag – nur der Seiteninhalt passt
    found = _candidates(sem, "FlexLM Lizenzserver auf neue VM umziehen", "Port 27000 bleibt")
    assert found and found[0].path == "infrastruktur/dienste"


def test_web_question_flow(sem):
    semantic.index_wiki(sem)
    sem.__dict__["llm"] = FakeLLM(json_answers=[{"antwort": "Druckserver ist srv-print02 [1].", "quellen": [1]}])
    from doku_agent.web.app import create_app

    client = TestClient(create_app(sem), base_url="http://localhost")
    html = client.get("/fragen", auth=AUTH).text
    assert "Suchindex ist noch leer" not in html
    token = re.search(r'name="csrf" value="([^"]+)"', html).group(1)
    resp = client.post("/fragen", data={"question": "Welcher Druckserver?", "csrf": token}, auth=AUTH,
                       follow_redirects=False)
    assert resp.status_code == 303
    for t in threading.enumerate():
        if t.name.startswith("frage-"):
            t.join(5)
    page = client.get(resp.headers["location"], auth=AUTH).text
    assert "Druckserver ist srv-print02 [1]." in page and "https://wiki.test/de/infrastruktur/dienste" in page
    assert 'http-equiv="refresh"' not in page


def test_approved_page_is_reindexed(sem, fake_wiki):
    from doku_agent.apply import apply_proposal
    from doku_agent.pages import Block, PageDraft, propose_page

    pid = propose_page(sem, PageDraft(doc_type="netbox_device", title="srv09", description="d",
                                      blocks=[Block("netbox-device", "Steckbrief", "| a | b |")],
                                      path_vars={"name": "srv09"}))
    apply_proposal(sem, pid)
    job = sem.store.list_jobs()[0]
    assert job.name == "wiki_index" and job.params == {"page_id": max(fake_wiki.pages)}
