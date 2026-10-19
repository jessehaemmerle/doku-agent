"""Markdown-Werkzeuge: Abschnitte, verwaltete Blöcke, sicheres Ergänzen, Diff.

Grundsatz: Bestehender Inhalt wird nie gelöscht. Der Agent ersetzt nur Inhalte
innerhalb seiner eigenen, markierten Blöcke und hängt sonst nur an.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass

_HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
_FENCE = re.compile(r"^\s*(```|~~~)")


def block_markers(block_id: str) -> tuple[str, str]:
    return (f"<!-- doku-agent:begin {block_id} -->", f"<!-- doku-agent:end {block_id} -->")


@dataclass
class Section:
    level: int  # 0 = Text vor der ersten Überschrift
    title: str
    start: int  # Zeilenindex der Überschrift
    end: int  # exklusiv: Beginn des nächsten Abschnitts gleicher/höherer Ebene


def _heading_lines(lines: list[str]) -> list[tuple[int, int, str]]:
    result, in_fence = [], False
    for idx, line in enumerate(lines):
        if _FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        m = _HEADING.match(line)
        if m:
            result.append((idx, len(m.group(1)), m.group(2).strip()))
    return result


def sections(md: str) -> list[Section]:
    lines = md.splitlines()
    heads = _heading_lines(lines)
    out = []
    for i, (idx, level, title) in enumerate(heads):
        end = len(lines)
        for jdx, jlevel, _ in heads[i + 1:]:
            if jlevel <= level:
                end = jdx
                break
        out.append(Section(level, title, idx, end))
    return out


def headings(md: str, max_level: int = 3) -> list[tuple[int, str]]:
    return [(s.level, s.title) for s in sections(md) if s.level <= max_level]


def _norm(title: str) -> str:
    return re.sub(r"[^a-z0-9äöüß]+", " ", title.lower()).strip()


def find_section(md: str, title: str) -> Section | None:
    wanted = _norm(title)
    for sec in sections(md):
        if _norm(sec.title) == wanted:
            return sec
    return None


def has_block(md: str, block_id: str) -> bool:
    begin, end = block_markers(block_id)
    return begin in md and end in md


def upsert_block(md: str, block_id: str, content: str, heading: str | None = None, level: int = 2) -> str:
    """Ersetzt den Inhalt eines verwalteten Blocks oder hängt ihn (mit Überschrift) an."""
    begin, end = block_markers(block_id)
    body = f"{begin}\n{content.strip()}\n{end}"
    if begin in md and end in md:
        pattern = re.compile(re.escape(begin) + r".*?" + re.escape(end), re.S)
        return pattern.sub(lambda _: body, md, count=1)
    if heading:
        sec = find_section(md, heading)
        if sec is not None:
            return _insert_at_section_end(md, sec, body)
        body = f"{'#' * level} {heading}\n\n{body}"
    return md.rstrip() + "\n\n" + body + "\n"


def _insert_at_section_end(md: str, sec: Section, text: str) -> str:
    lines = md.splitlines()
    end = sec.end
    while end > sec.start + 1 and not lines[end - 1].strip():
        end -= 1
    new = lines[:end] + ["", *text.strip().splitlines(), ""] + lines[end:]
    return "\n".join(new).rstrip() + "\n"


def apply_operations(md: str, ops: list[dict]) -> tuple[str, list[str]]:
    """Wendet LLM-Vorschläge an. Erlaubt sind nur 'append_to_section' und 'add_section'.

    Gibt den neuen Text und eine Liste von Hinweisen (übersprungene Operationen) zurück.
    """
    notes = []
    for op in ops:
        kind = op.get("op")
        content = (op.get("content") or "").strip()
        title = (op.get("heading") or "").strip()
        if not content:
            continue
        if kind == "append_to_section" and title:
            sec = find_section(md, title)
            if sec is None:
                notes.append(f"Abschnitt '{title}' nicht gefunden – als neuer Abschnitt angelegt")
                md = md.rstrip() + f"\n\n## {title}\n\n{content}\n"
            elif content in "\n".join(md.splitlines()[sec.start:sec.end]):
                notes.append(f"Inhalt für '{title}' war bereits vorhanden – übersprungen")
            else:
                md = _insert_at_section_end(md, sec, content)
        elif kind == "add_section" and title:
            existing = find_section(md, title)
            if existing is not None:
                md = _insert_at_section_end(md, existing, content)
                notes.append(f"Abschnitt '{title}' existierte bereits – Inhalt angehängt")
                continue
            level = min(max(int(op.get("level") or 2), 2), 4)
            after = (op.get("after") or "").strip()
            sec = find_section(md, after) if after else None
            block = f"{'#' * level} {title}\n\n{content}"
            md = _insert_after_section(md, sec, block) if sec else md.rstrip() + f"\n\n{block}\n"
        else:
            notes.append(f"Unbekannte oder unvollständige Operation ignoriert: {kind!r}")
    return md, notes


def _insert_after_section(md: str, sec: Section, text: str) -> str:
    lines = md.splitlines()
    new = lines[:sec.end] + ["", *text.splitlines(), ""] + lines[sec.end:]
    return "\n".join(new).rstrip() + "\n"


def ensure_sections(md: str, required: list[str], placeholder: str = "_Noch zu ergänzen._") -> str:
    """Ergänzt fehlende Pflichtabschnitte (gelernt aus dem Wiki) als leere Abschnitte."""
    for title in required:
        if find_section(md, title) is None:
            md = md.rstrip() + f"\n\n## {title}\n\n{placeholder}\n"
    return md


def unified_diff(old: str, new: str, name: str = "seite.md") -> str:
    return "".join(difflib.unified_diff(
        old.splitlines(keepends=True) if old else [],
        new.splitlines(keepends=True),
        fromfile=f"vorher/{name}", tofile=f"nachher/{name}",
    ))


def table(headers: list[str], rows: list[list]) -> str:
    """Markdown-Tabelle; Pipes und Zeilenumbrüche in Zellen werden entschärft."""
    def cell(v) -> str:
        text = "" if v is None else str(v)
        return text.replace("|", "\\|").replace("\r", "").replace("\n", "<br>").strip() or "–"

    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(cell(v) for v in row) + " |" for row in rows]
    return "\n".join(lines)


def outline(md: str, max_chars_per_section: int = 600) -> str:
    """Kompakte Übersicht einer Seite für den LLM-Prompt (Überschriften + Anfang je Abschnitt)."""
    lines = md.splitlines()
    secs = sections(md)
    out = []
    for sec in secs:
        child = next((s for s in secs if sec.start < s.start < sec.end), None)
        body = "\n".join(lines[sec.start + 1:child.start if child else sec.end]).strip()
        if len(body) > max_chars_per_section:
            body = body[:max_chars_per_section] + " [...]"
        out.append(f"{'#' * sec.level} {sec.title}\n{body}")
    return "\n\n".join(out) if out else md[: max_chars_per_section * 3]
