"""Integrationstest gegen ein echtes Ollama mit Embedding-Modell (läuft nur mit DOKU_IT_OLLAMA_URL).

Beispiel:
  DOKU_IT_OLLAMA_URL=http://127.0.0.1:11434 pytest tests/test_integration_ollama.py
Das Modell (Standard qwen3-embedding:0.6b) muss in Ollama vorhanden sein.
"""

import os

import numpy as np
import pytest

from doku_agent import semantic
from doku_agent.embeddings import Embedder
from doku_agent.egress import EgressGuard
from tests.conftest import make_config

URL = os.environ.get("DOKU_IT_OLLAMA_URL")
pytestmark = pytest.mark.skipif(not URL, reason="kein Test-Ollama konfiguriert")


@pytest.fixture
def real_ctx(ctx):
    ctx.cfg.llm.base_url = URL
    ctx.__dict__["embedder"] = Embedder(ctx.cfg.embeddings, ctx.cfg.llm, EgressGuard({"127.0.0.1", "localhost",
                                                                                     URL.split("//")[1].split(":")[0]}))
    return ctx


def test_real_embeddings_rank_german_passages(real_ctx, fake_wiki):
    vectors = real_ctx.embedder.embed(["Erster Text.", "Zweiter Text."])
    assert len(vectors) == 2 and len(vectors[0]) >= 256
    assert abs(float(np.linalg.norm(vectors[0])) - 1) < 0.01

    fake_wiki.add("infra/lizenzen", "Lizenzserver", "## Betrieb\n\nDer FlexLM-Lizenzserver srv-lic01 nutzt Port 27000.")
    fake_wiki.add("infra/drucken", "Druckserver", "## Betrieb\n\nAlle Drucker laufen über srv-print02 mit PaperCut.")
    fake_wiki.add("netz/vlans", "VLAN-Plan", "## VLANs\n\nVLAN 20 ist die DMZ, VLAN 30 das Gäste-WLAN.")
    semantic.index_wiki(real_ctx)
    assert semantic.search(real_ctx, "Wo läuft der Lizenzserver?", k=1)[0].path == "infra/lizenzen"
    assert semantic.search(real_ctx, "Welches Netz hat das Gäste-WLAN?", k=1)[0].path == "netz/vlans"
