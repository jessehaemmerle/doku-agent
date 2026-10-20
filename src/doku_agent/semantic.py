"""Semantischer Suchindex über das Wiki und Fragen ans Wiki mit Quellenangabe.

Jede Seite wird an ihren Überschriften in Abschnitte zerlegt, lokal eingebettet und in SQLite
abgelegt. Der Index wird inkrementell aktualisiert (nur Seiten mit neuem Änderungsdatum).
Die Suche lädt alle Vektoren einmal pro Indexstand in den Speicher (einige tausend Abschnitte
sind auf der CPU in Millisekunden durchsucht).
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass

import numpy as np

from doku_agent import markdown
from doku_agent.context import Context
from doku_agent.wiki import Page

_MARKER = re.compile(r"<!--\s*doku-agent:(?:begin|end)\s+[^\s>]+\s*-->")
_TAG = re.compile(r"<[^>]+>")
_CITE = re.compile(r"\[(\d{1,2})\]")
_VERSION_KEY = "semantic:version"

ANSWER_SCHEMA = {
    "type": "object",
    "properties": {"antwort": {"type": "string"}, "quellen": {"type": "array", "items": {"type": "integer"}}},
    "required": ["antwort", "quellen"],
}


@dataclass
class Hit:
    page_id: int
    path: str
    title: str
    heading: str
    text: str
    score: float


def page_text(page: Page) -> str:
    text = _MARKER.sub("", page.content)
    if page.content_type != "markdown":  # Visual-Editor-Seiten: HTML grob in Text umwandeln
        text = _TAG.sub(" ", text)
    return text


def _split(body: str, size: int) -> list[str]:
    """Abschnitt an Absätzen zerlegen; einzelne zu lange Absätze (z.B. große Tabellen) hart teilen."""
    parts, current = [], ""
    for para in re.split(r"\n\s*\n", body):
        para = para.strip()
        if not para:
            continue
        while len(para) > size:
            if current:
                parts.append(current)
                current = ""
            parts.append(para[:size])
            para = para[size:]
        if current and len(current) + len(para) + 2 > size:
            parts.append(current)
            current = para
        else:
            current = f"{current}\n\n{para}" if current else para
    if current:
        parts.append(current)
    return parts


def chunk_page(page: Page, size: int) -> list[tuple[str, str]]:
    """(Überschriften-Pfad, Text) je Abschnitt bis Ebene 3; Text vor der ersten Überschrift zählt mit."""
    text = page_text(page)
    lines = text.splitlines()
    heads = [s for s in markdown.sections(text) if s.level <= 3]
    pieces: list[tuple[str, int, int]] = []
    stack: list[tuple[int, str]] = []
    first = heads[0].start if heads else len(lines)
    pieces.append(("", 0, first))
    for i, sec in enumerate(heads):
        stack = [(lvl, t) for lvl, t in stack if lvl < sec.level] + [(sec.level, sec.title)]
        end = heads[i + 1].start if i + 1 < len(heads) else len(lines)
        pieces.append((" › ".join(t for _, t in stack), sec.start + 1, end))
    out = []
    if page.description.strip():
        out.append(("", page.description.strip()))
    for heading, start, end in pieces:
        body = "\n".join(lines[start:end]).strip()
        for part in _split(body, size):
            if len(part.strip()) >= 20:
                out.append((heading, part))
    return out


def _embed_text(page: Page, heading: str, text: str) -> str:
    return f"{page.title} › {heading}\n{text}" if heading else f"{page.title}\n{text}"


def _normalize(vectors) -> np.ndarray:
    arr = np.asarray(vectors, dtype=np.float32)
    norms = np.linalg.norm(arr, axis=-1, keepdims=True)
    norms[norms == 0] = 1
    return arr / norms


def _bump(ctx: Context) -> None:
    ctx.store.kv_set(_VERSION_KEY, int(ctx.store.kv_get(_VERSION_KEY, 0)) + 1)


def index_wiki(ctx: Context, page_ids: list[int] | None = None) -> dict:
    """Index aktualisieren: neue/geänderte Seiten einbetten, gelöschte entfernen."""
    model = ctx.cfg.embeddings.model
    pages = ctx.wiki.list_pages()
    known = ctx.store.indexed_pages()
    wanted = set(page_ids) if page_ids else None
    stats = {"seiten": len(pages), "aktualisiert": 0, "abschnitte": 0, "entfernt": 0}
    for info in pages:
        if wanted is not None and info.id not in wanted:
            continue
        state = known.get(info.id)
        if state and state["updated_at"] == info.updated_at and state["model"] == model:
            continue
        page = ctx.wiki.get_page(info.id)
        chunks = chunk_page(page, ctx.cfg.embeddings.chunk_chars)
        vectors = _normalize(ctx.embedder.embed([_embed_text(page, h, t) for h, t in chunks])) if chunks else []
        ctx.store.replace_page_chunks(page.id, page.path, page.title, info.updated_at, model,
                                      [(h, t, v.tobytes()) for (h, t), v in zip(chunks, vectors)])
        stats["aktualisiert"] += 1
        stats["abschnitte"] += len(chunks)
    if wanted is None:
        gone = sorted(set(known) - {p.id for p in pages})
        ctx.store.delete_page_chunks(gone)
        stats["entfernt"] = len(gone)
    if stats["aktualisiert"] or stats["entfernt"]:
        _bump(ctx)
    ctx.log.info("Suchindex: %s", stats)
    return stats


class _Matrix:
    """Alle Vektoren eines Indexstands im Speicher (pro Prozess zwischengespeichert)."""
    _cache: dict[str, tuple[object, "_Matrix"]] = {}
    _lock = threading.Lock()

    def __init__(self, rows: list[dict]):
        self.meta = [{k: r[k] for k in ("page_id", "path", "title", "heading", "text")} for r in rows]
        self.vectors = (np.vstack([np.frombuffer(r["vector"], dtype=np.float32) for r in rows])
                        if rows else np.zeros((0, 1), dtype=np.float32))

    @classmethod
    def load(cls, ctx: Context) -> "_Matrix":
        key = f"{ctx.store.path}:{ctx.cfg.embeddings.model}"
        version = ctx.store.kv_get(_VERSION_KEY, 0)
        with cls._lock:
            cached = cls._cache.get(key)
            if cached is None or cached[0] != version:
                cached = (version, cls(ctx.store.chunks_for_model(ctx.cfg.embeddings.model)))
                cls._cache[key] = cached
            return cached[1]


def is_ready(ctx: Context) -> bool:
    return ctx.cfg.embeddings.enabled and bool(_Matrix.load(ctx).meta)


def search(ctx: Context, query: str, k: int | None = None, per_page: int = 2) -> list[Hit]:
    matrix = _Matrix.load(ctx)
    if not matrix.meta:
        return []
    qvec = _normalize(ctx.embedder.query(query))
    if qvec.shape[-1] != matrix.vectors.shape[1]:
        raise RuntimeError("Suchindex passt nicht zum Embedding-Modell – Job 'wiki_index' ausführen")
    scores = matrix.vectors @ qvec
    hits, per = [], {}
    for idx in np.argsort(-scores):
        meta = matrix.meta[int(idx)]
        if per.get(meta["page_id"], 0) >= per_page:
            continue
        per[meta["page_id"]] = per.get(meta["page_id"], 0) + 1
        hits.append(Hit(**meta, score=float(scores[idx])))
        if len(hits) >= (k or ctx.cfg.embeddings.top_k):
            break
    return hits


def similar_pages(ctx: Context, text: str, limit: int = 5) -> list[tuple[int, float]]:
    """Seiten, deren Abschnitte am besten zum Text passen: (Seiten-ID, Ähnlichkeit)."""
    hits = search(ctx, text, k=limit, per_page=1)
    return [(h.page_id, h.score) for h in hits]


def page_vectors(ctx: Context) -> tuple[list[int], np.ndarray]:
    """Ein Vektor pro Seite (Mittel ihrer Abschnitte) – z.B. für die Dublettensuche."""
    matrix = _Matrix.load(ctx)
    by_page: dict[int, list[int]] = {}
    for i, meta in enumerate(matrix.meta):
        by_page.setdefault(meta["page_id"], []).append(i)
    ids = sorted(by_page)
    if not ids:
        return [], np.zeros((0, 1), dtype=np.float32)
    return ids, _normalize(np.vstack([matrix.vectors[by_page[p]].mean(axis=0) for p in ids]))


def answer(ctx: Context, question: str) -> tuple[str, list[dict]]:
    """Antwort nur aus Wiki-Auszügen, mit nummerierten Quellen. Rückgabe: (Antwort, Quellen)."""
    hits = search(ctx, question)
    if not hits:
        return ("Im Suchindex wurde nichts gefunden. Ist der Index aufgebaut (Job „Wiki: Suchindex "
                "aktualisieren“)?", [])
    budget = ctx.cfg.llm.max_input_chars // max(len(hits), 1)
    excerpts = "\n\n".join(f"[{n}] {h.title}{' › ' + h.heading if h.heading else ''} (/{h.path})\n{h.text[:budget]}"
                           for n, h in enumerate(hits, 1))
    result = ctx.llm.json(
        "Du beantwortest Fragen des IT-Teams ausschließlich anhand von Auszügen aus dem internen Wiki.",
        f"Frage: {question}\n\nAuszüge:\n{excerpts}\n\nAntworte knapp und konkret. Belege jede Aussage mit der "
        "Nummer des Auszugs in eckigen Klammern, z.B. [2]. Steht die Antwort nicht in den Auszügen, sage das "
        "deutlich und rate nicht. Gib in 'quellen' die Nummern der verwendeten Auszüge an.",
        ANSWER_SCHEMA,
    )
    text = (result.get("antwort") or "").strip() or "Das Modell hat keine Antwort geliefert."
    cited = {n for n in result.get("quellen") or [] if isinstance(n, int)}
    cited |= {int(n) for n in _CITE.findall(text)}
    cited = {n for n in cited if 1 <= n <= len(hits)}
    sources = []
    for n, h in enumerate(hits, 1):
        sources.append({"n": n, "title": h.title, "path": h.path, "heading": h.heading,
                        "url": ctx.wiki.page_url(h.path), "cited": n in cited, "score": round(h.score, 3)})
    if cited:
        sources = [s for s in sources if s["cited"]]
    return text, sources


_question_lock = threading.Lock()


def run_question(ctx: Context, qid: int) -> None:
    """Frage beantworten und das Ergebnis ablegen (eine Frage zur Zeit; Ollama arbeitet ohnehin seriell)."""
    with _question_lock:
        q = ctx.store.get_question(qid)
        if q is None:
            return
        ctx.store.set_question(qid, "running")
        try:
            text, sources = answer(ctx, q.question)
            ctx.store.set_question(qid, "done", text, sources)
        except Exception as exc:
            ctx.log.exception("Frage #%s fehlgeschlagen", qid)
            ctx.store.set_question(qid, "failed", f"Fehler: {exc}")
