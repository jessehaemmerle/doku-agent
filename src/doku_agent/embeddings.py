"""Embeddings über das lokale Ollama (POST /api/embed) – kein externer Dienst."""

from __future__ import annotations

import httpx

from doku_agent.config import EmbeddingsConfig, LLMConfig
from doku_agent.egress import EgressGuard


class EmbeddingError(RuntimeError):
    pass


class Embedder:
    def __init__(self, cfg: EmbeddingsConfig, llm_cfg: LLMConfig, guard: EgressGuard,
                 transport: httpx.BaseTransport | None = None):
        self.cfg = cfg
        self.http = guard.client(llm_cfg.base_url, timeout=llm_cfg.timeout_s, transport=transport)

    def embed(self, texts: list[str]) -> list[list[float]]:
        """Vektoren für Dokument-Abschnitte (in Gruppen von batch_size)."""
        out: list[list[float]] = []
        for i in range(0, len(texts), self.cfg.batch_size):
            batch = texts[i:i + self.cfg.batch_size]
            try:
                resp = self.http.post("/api/embed", json={"model": self.cfg.model, "input": batch, "truncate": True,
                                                          "keep_alive": self.cfg.keep_alive})
            except httpx.HTTPError as exc:
                raise EmbeddingError(f"Ollama nicht erreichbar: {exc}") from exc
            if resp.status_code != 200:
                raise EmbeddingError(f"Ollama-Fehler {resp.status_code}: {resp.text[:300]}")
            vectors = resp.json().get("embeddings") or []
            if len(vectors) != len(batch):
                raise EmbeddingError(f"Ollama lieferte {len(vectors)} statt {len(batch)} Vektoren")
            out.extend(vectors)
        return out

    def query(self, text: str) -> list[float]:
        """Vektor für eine Suchanfrage (mit der Anweisung, die das Modell für Anfragen erwartet)."""
        return self.embed([self.cfg.query_prefix + text])[0]
