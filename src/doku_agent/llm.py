"""Client für das lokale Sprachmodell (Ollama)."""

from __future__ import annotations

import json
import logging
import re

import httpx

from doku_agent.config import LLMConfig
from doku_agent.egress import EgressGuard

log = logging.getLogger(__name__)

_THINK = re.compile(r"<think>.*?</think>", re.S)


class LLMError(RuntimeError):
    pass


class LLM:
    def __init__(self, cfg: LLMConfig, guard: EgressGuard, language: str = "Deutsch",
                 transport: httpx.BaseTransport | None = None):
        self.cfg = cfg
        self.language = language
        self.http = guard.client(cfg.base_url, timeout=cfg.timeout_s, transport=transport)

    def _system(self, system: str) -> str:
        return (
            f"{system}\n\nSchreibe auf {self.language}. Erfinde keine Fakten: "
            "Was nicht aus den gelieferten Daten hervorgeht, lässt du weg oder kennzeichnest es "
            "als 'unbekannt'."
        )

    def _chat(self, system: str, user: str, fmt: dict | str | None) -> str:
        body = {
            "model": self.cfg.model,
            "messages": [
                {"role": "system", "content": self._system(system)},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "think": False,
            "keep_alive": self.cfg.keep_alive,
            "options": {"num_ctx": self.cfg.num_ctx, "temperature": self.cfg.temperature,
                        "num_predict": self.cfg.max_output_tokens},
        }
        if fmt is not None:
            body["format"] = fmt
        try:
            resp = self.http.post("/api/chat", json=body)
        except httpx.HTTPError as exc:
            raise LLMError(f"Ollama nicht erreichbar: {exc}") from exc
        if resp.status_code != 200:
            raise LLMError(f"Ollama-Fehler {resp.status_code}: {resp.text[:500]}")
        content = resp.json().get("message", {}).get("content", "")
        return _THINK.sub("", content).strip()

    def text(self, system: str, user: str) -> str:
        return self._chat(system, user, None)

    def json(self, system: str, user: str, schema: dict) -> dict:
        """Antwort als JSON gemäß Schema (Ollama Structured Outputs), ein Wiederholungsversuch."""
        last_error = None
        for attempt in range(2):
            prompt = user if attempt == 0 else (
                f"{user}\n\nDeine letzte Antwort war kein gültiges JSON ({last_error}). "
                "Antworte ausschließlich mit gültigem JSON."
            )
            raw = self._chat(system, prompt, schema)
            try:
                data = json.loads(raw)
                if isinstance(data, dict):
                    return data
                last_error = "kein JSON-Objekt"
            except json.JSONDecodeError as exc:
                last_error = str(exc)
            log.warning("LLM lieferte ungültiges JSON (Versuch %s): %s", attempt + 1, last_error)
        raise LLMError(f"LLM lieferte kein gültiges JSON: {last_error}")

    def fit(self, text: str, max_chars: int | None = None) -> str:
        """Kürzt Eingaben auf das Kontextbudget, damit das kleine Modell nicht abschneidet."""
        limit = max_chars or self.cfg.max_input_chars
        if len(text) <= limit:
            return text
        return text[:limit] + "\n[... gekürzt ...]"

    def condense(self, text: str, purpose: str) -> str:
        """Lange Eingaben abschnittsweise zusammenfassen (Map-Reduce), bis sie ins Budget passen."""
        limit = self.cfg.max_input_chars
        if len(text) <= limit:
            return text
        chunk_size = limit
        parts = [text[i:i + chunk_size] for i in range(0, len(text), chunk_size)]
        summaries = []
        for idx, part in enumerate(parts, 1):
            log.info("Fasse Eingabe-Teil %s/%s zusammen", idx, len(parts))
            summaries.append(self.text(
                "Du extrahierst technische Fakten aus Unterlagen für eine IT-Dokumentation.",
                f"Zweck: {purpose}\n\nExtrahiere alle relevanten technischen Fakten (Namen, Versionen, "
                f"IPs, Pfade, Einstellungen, Abläufe) als kompakte Stichpunkte:\n\n{part}",
            ))
        merged = "\n".join(summaries)
        return self.fit(merged)

    def models(self) -> list[str]:
        resp = self.http.get("/api/tags")
        resp.raise_for_status()
        return [m.get("name", "") for m in resp.json().get("models", [])]
