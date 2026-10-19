"""Freie Dokumentation aus Stichpunkten und Dateien – neue Seite oder Ergänzung einer bestehenden."""

from __future__ import annotations

import re
from pathlib import Path

from doku_agent import markdown
from doku_agent.context import Context
from doku_agent.conventions import slugify
from doku_agent.extract import extract_text
from doku_agent.generators.common import style_context
from doku_agent.pages import PageDraft, propose_page
from doku_agent.wiki import normalize_path

DECISION_SCHEMA = {
    "type": "object",
    "properties": {
        "titel": {"type": "string"},
        "beschreibung": {"type": "string"},
        "aktion": {"type": "string", "enum": ["neu", "ergaenzen"]},
        "seiten_id": {"type": "integer"},
        "bereich": {"type": "string"},
        "tags": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["titel", "beschreibung", "aktion", "bereich"],
}
CONTENT_SCHEMA = {
    "type": "object",
    "properties": {"inhalt": {"type": "string"}},
    "required": ["inhalt"],
}
RAW_NOTES_LIMIT = 30000  # Zeichen der Rohnotizen, die bei schwacher Modellantwort übernommen werden

OPS_SCHEMA = {
    "type": "object",
    "properties": {"operationen": {"type": "array", "items": {
        "type": "object",
        "properties": {
            "op": {"type": "string", "enum": ["append_to_section", "add_section"]},
            "heading": {"type": "string"}, "level": {"type": "integer"},
            "after": {"type": "string"}, "content": {"type": "string"},
        },
        "required": ["op", "heading", "content"],
    }}},
    "required": ["operationen"],
}


def safe_area(area: str) -> str:
    """Vom LLM vorgeschlagenen Bereich bereinigen: keine '.'/'..'-Segmente, nur Pfad-Zeichen."""
    segments = []
    for seg in normalize_path(area).split("/"):
        seg = re.sub(r"[^\w.\-]+", "-", seg.strip()).strip("-.")
        if seg:
            segments.append(seg)
    return "/".join(segments)


def gather_material(ctx: Context, instruction: str, files: list[Path]) -> tuple[str, list[str]]:
    parts, hints = [f"Auftrag/Notizen:\n{instruction.strip()}"], []
    for f in files:
        try:
            parts.append(f"--- Datei {f.name} ---\n{extract_text(f)}")
        except Exception as exc:
            hints.append(f"Datei {f.name} übersprungen: {exc}")
    return "\n\n".join(parts), hints


def _decide(ctx: Context, instruction: str, material: str) -> dict:
    conv = ctx.conventions
    candidates = conv.similar(f"{instruction} {material[:2000]}", limit=8)
    cand_text = "\n".join(f"- id={p.id} /{p.path} – {p.title}: {p.description}" for p in candidates) or "(keine)"
    areas = "\n".join(f"- {prefix} ({n} Seiten, z.B. {', '.join(t for t in titles if t)})"
                      for prefix, n, titles in conv.areas()[:40]) or "(Wiki ist leer)"
    decision = ctx.llm.json(
        "Du ordnest neue IT-Dokumentation in ein bestehendes Wiki ein. Bestehende Seiten zum selben Thema "
        "werden ergänzt statt Duplikate anzulegen.",
        f"Auftrag:\n{instruction}\n\nMaterial (Auszug):\n{material[:3000]}\n\n"
        f"Bestehende, möglicherweise passende Seiten:\n{cand_text}\n\nBereiche im Wiki:\n{areas}\n\n"
        "Entscheide: 'ergaenzen' (mit seiten_id einer der genannten Seiten), wenn eine Seite genau dieses "
        "Thema behandelt, sonst 'neu' (seiten_id 0). Wähle für 'neu' den passendsten Bereich (Pfad-Präfix aus der Liste "
        "oder einen sinnvollen neuen). Gib Titel, eine einzeilige Beschreibung und passende Tags an.",
        DECISION_SCHEMA,
    )
    valid_ids = {p.id for p in candidates}
    if decision.get("aktion") == "ergaenzen" and decision.get("seiten_id") not in valid_ids:
        decision["aktion"] = "neu"
    # Nur Tags übernehmen, die im Wiki schon verwendet werden – keine neuen Schlagworte erfinden.
    # Vergleich normalisiert, übernommen wird die Schreibweise aus dem Wiki.
    known = {slugify(t): t for p in conv.pages for t in p.tags}
    suggested = [slugify(t) for t in (decision.get("tags") or []) if t.strip()]
    decision["tags"] = list(dict.fromkeys(known[t] for t in suggested if t in known))[:5]
    return decision


def run_freeform(ctx: Context, instruction: str, files: list[Path] | None = None, target_path: str = "") -> int | None:
    raw_material, hints = gather_material(ctx, instruction, files or [])
    material = ctx.llm.condense(raw_material, instruction)
    conv = ctx.conventions

    target_page = conv.find_by_path(target_path) if target_path else None
    if target_path:
        decision = {"titel": target_path.rsplit("/", 1)[-1].replace("-", " ").title(), "beschreibung": "",
                    "aktion": "ergaenzen" if target_page else "neu", "seiten_id": target_page.id if target_page else None,
                    "bereich": normalize_path(target_path).rsplit("/", 1)[0], "tags": []}
        if not target_page:
            hints.append(f"Zielseite /{normalize_path(target_path)} existiert noch nicht – wird neu angelegt.")
    else:
        decision = _decide(ctx, instruction, material)
    ctx.log.info("Entscheidung: %s", decision)

    if decision["aktion"] == "ergaenzen":
        page = ctx.wiki.get_page(int(decision["seiten_id"]))
        result = ctx.llm.json(
            "Du ergänzt eine bestehende Wiki-Seite um neue Informationen. Bestehender Text bleibt unverändert; "
            "du lieferst nur Ergänzungen. " + style_context(ctx, page.path),
            f"Gliederung der bestehenden Seite '{page.title}':\n{markdown.outline(page.content)}\n\n"
            f"Neue Informationen:\n{material}\n\nLiefere Operationen: 'append_to_section' (Text an einen "
            "bestehenden Abschnitt anhängen, heading = exakte Überschrift) oder 'add_section' (neuer Abschnitt, "
            "after = Überschrift, nach der er eingefügt wird). Nur Informationen, die noch nicht auf der Seite "
            "stehen.",
            OPS_SCHEMA,
        )
        draft = PageDraft(doc_type="freeform", title=page.title, description=page.description, blocks=[],
                          target_page_id=page.id, ops=result.get("operationen", []),
                          source="freeform", hints=hints)
        if not draft.ops:
            ctx.log.info("LLM sieht keine neuen Informationen für /%s", page.path)
            return None
        return propose_page(ctx, draft)

    area = safe_area(decision.get("bereich", ""))
    style = conv.profile_for_path(f"{area}/x").slug_style
    path = normalize_path(target_path) if target_path else f"{area}/{slugify(decision['titel'], style)}".strip("/")
    profile = conv.profile_for_path(path)
    required = ", ".join(profile.required_sections) or "frei wählbar"
    result = ctx.llm.json(
        "Du schreibst eine neue Seite für das IT-Wiki. " + style_context(ctx, path),
        f"Titel: {decision['titel']}\nPflichtabschnitte (## Überschriften): {required}\n\n"
        f"Material:\n{material}\n\nSchreibe den vollständigen Seiteninhalt in Markdown (ohne Titelzeile). "
        "Nutze ## für Abschnitte, Tabellen für strukturierte Daten und Codeblöcke für Befehle/Konfigurationen.",
        CONTENT_SCHEMA,
    )
    content = result.get("inhalt", "").strip()
    if content.startswith("# "):
        content = content.split("\n", 1)[1].strip() if "\n" in content else ""
    if len(content) < 200:
        # Kleines Modell hat kaum etwas geliefert: Notizen nicht verlieren, sondern roh übernehmen.
        hints.append("Das Sprachmodell hat kaum Inhalt erzeugt – die Eingaben wurden als Rohfassung übernommen.")
        raw = raw_material if len(raw_material) <= RAW_NOTES_LIMIT else raw_material[:RAW_NOTES_LIMIT] + "\n[... gekürzt ...]"
        content = f"{content}\n\n## Notizen (Rohfassung)\n\n{markdown.code_block(raw.strip(), 'text')}".strip()
    return propose_page(ctx, PageDraft(
        doc_type="freeform", title=decision["titel"], description=decision.get("beschreibung", ""),
        blocks=[], intro=content, target_path=path, extra_tags=decision.get("tags") or [],
        source="freeform", hints=hints,
    ))
