"""Aus Seiten-Entwürfen werden Wiki-Vorschläge (neu anlegen oder bestehende Seite ergänzen)."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from doku_agent import markdown
from doku_agent.context import Context
from doku_agent.conventions import AreaProfile, slugify
from doku_agent.wiki import Page, PageNotFound, normalize_path

_PLACEHOLDER = re.compile(r"\{(\w+)\}")


@dataclass
class Block:
    """Vom Agent verwalteter Abschnitt. Nur dessen Inhalt wird bei Updates ersetzt."""
    id: str
    heading: str
    content: str


@dataclass
class PageDraft:
    doc_type: str
    title: str
    description: str
    blocks: list[Block]
    path_vars: dict[str, str] = field(default_factory=dict)
    intro: str = ""  # nur für neue Seiten
    extra_tags: list[str] = field(default_factory=list)
    lookup_name: str | None = None  # bestehende Seite über Objektnamen finden
    target_path: str | None = None  # expliziter Pfad (überschreibt Vorlage)
    target_page_id: int | None = None
    ops: list[dict] = field(default_factory=list)  # LLM-Ergänzungen für bestehende Seiten
    source: str = ""
    hints: list[str] = field(default_factory=list)
    # Stabile Kennung des Quellobjekts (z.B. "netbox:device:4"): Die einmal angelegte Seite wird
    # darüber wiedergefunden, auch wenn das Objekt umbenannt wurde.
    stable_id: str | None = None
    sync_title: bool = False  # Seitentitel folgt dem Objektnamen (z.B. nach Umbenennung)


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def render_path(template: str, values: dict[str, str], style: str) -> str:
    parts = []
    for seg in normalize_path(template).split("/"):
        if "{" in seg:
            seg = slugify(_PLACEHOLDER.sub(lambda m: str(values.get(m.group(1), "")), seg), style)
        parts.append(seg)
    return "/".join(p for p in parts if p)


def merge_into(content: str, blocks: list[Block], ops: list[dict]) -> tuple[str, list[str]]:
    for block in blocks:
        content = markdown.upsert_block(content, block.id, block.content, heading=block.heading)
    notes: list[str] = []
    if ops:
        content, notes = markdown.apply_operations(content, ops)
    return content, notes


def build_new_content(draft: PageDraft, profile: AreaProfile) -> str:
    """Neue Seite: Einleitung, eigene Blöcke, dann die Pflichtabschnitte des Bereichs in gelernter
    Reihenfolge (ein Block mit gleicher Überschrift steht an dessen Stelle)."""
    def render(block: Block) -> str:
        begin, end = markdown.block_markers(block.id)
        return f"## {block.heading}\n\n{begin}\n{block.content.strip()}\n{end}"

    norm = markdown.norm_heading
    required = {norm(t): t for t in profile.required_sections}
    parts = [draft.intro.strip()] if draft.intro.strip() else []
    parts += [render(b) for b in draft.blocks if norm(b.heading) not in required]
    by_heading = {norm(b.heading): b for b in draft.blocks}
    intro_has = {norm(t) for _, t in markdown.headings(draft.intro, max_level=2)}
    for key, title in required.items():
        if key in by_heading:
            parts.append(render(by_heading[key]))
        elif key not in intro_has:
            parts.append(f"## {title}\n\n_Noch zu ergänzen._")
    return "\n\n".join(parts) + "\n"


def _resolve_target(ctx: Context, draft: PageDraft) -> tuple[str, Page | None, AreaProfile, list[str]]:
    conv = ctx.conventions
    hints = []
    if draft.target_page_id:
        page = ctx.wiki.get_page(draft.target_page_id)
        return page.path, page, conv.profile_for_path(page.path), hints
    mapped = ctx.store.kv_get(f"page-for:{draft.stable_id}") if draft.stable_id else None
    if mapped:
        try:
            page = ctx.wiki.get_page(int(mapped))
            return page.path, page, conv.profile_for_path(page.path), hints
        except PageNotFound:  # nur bei wirklich gelöschter Seite; andere Fehler brechen ab
            ctx.store.kv_set(f"page-for:{draft.stable_id}", None)
    if draft.target_path:
        path = normalize_path(draft.target_path)
    else:
        template = ctx.cfg.wiki.paths.get(draft.doc_type) or "{name}"
        path = render_path(template, draft.path_vars, "kebab")
        style = conv.profile_for_path(path).slug_style
        if style != "kebab":
            path = render_path(template, draft.path_vars, style)
    existing = conv.find_by_path(path)
    if existing is None and draft.lookup_name:
        existing = conv.find_by_name(draft.lookup_name)
        if existing is not None:
            hints.append(f"Bestehende Seite /{existing.path} über den Namen '{draft.lookup_name}' gefunden "
                         f"– sie wird ergänzt statt /{path} neu anzulegen.")
            path = existing.path
    profile = conv.profile_for_path(path)
    page = ctx.wiki.get_page(existing.id) if existing else None
    if page is not None and draft.stable_id:
        # Zuordnung sofort merken, damit die Seite auch nach einer Umbenennung gefunden wird
        ctx.store.kv_set(f"page-for:{draft.stable_id}", page.id)
    return path, page, profile, hints


def _convention_hint(profile: AreaProfile, path: str) -> str:
    if profile.inherited:
        return profile.summary()
    if profile.page_count:
        return ("Konventionen aus /" + profile.prefix + " übernommen: "
                + (", ".join(f"Tag '{t}'" for t in profile.common_tags) or "keine gemeinsamen Tags")
                + (f"; Pflichtabschnitte: {', '.join(profile.required_sections)}" if profile.required_sections else ""))
    return f"Für /{path} gibt es noch keinen Bereich mit Vorbildseiten – Standardvorlage verwendet."


def propose_page(ctx: Context, draft: PageDraft) -> int | None:
    """Erzeugt einen Wiki-Vorschlag. Gibt None zurück, wenn sich nichts ändern würde."""
    path, page, profile, hints = _resolve_target(ctx, draft)
    if ctx.store.is_ignored(f"wiki:{path}"):
        ctx.log.info("/%s steht auf der Ignorierliste – kein Vorschlag", path)
        return None
    tags = list(dict.fromkeys([*ctx.cfg.wiki.tags.get(draft.doc_type, []), *profile.common_tags, *draft.extra_tags]))
    hints = [*draft.hints, *hints]
    if page is None:  # Konventions-Hinweise nur für neue Seiten; bei bestehenden gilt deren Aufbau
        hints.append(_convention_hint(profile, path))

    if page is not None and page.content_type != "markdown":
        ctx.log.warning("Seite /%s ist kein Markdown (%s) – übersprungen", page.path, page.content_type)
        return None

    if page is None:
        content = build_new_content(draft, profile)
        payload = {
            "action": "create", "path": path, "title": draft.title, "description": draft.description,
            "tags": tags, "content": content, "blocks": [b.__dict__ for b in draft.blocks], "ops": [],
        }
        diff = markdown.unified_diff("", content, path)
        summary = f"Neue Seite /{path}"
    else:
        content, notes = merge_into(page.content, draft.blocks, draft.ops)
        hints += notes
        merged_tags = list(dict.fromkeys([*page.tags, *tags]))
        description = page.description or draft.description
        title = draft.title if draft.sync_title and draft.title else page.title
        if (content == page.content and merged_tags == page.tags and description == page.description
                and title == page.title):
            ctx.log.info("/%s ist bereits aktuell – kein Vorschlag", page.path)
            return None
        if title != page.title:
            hints.append(f"Titel wird von '{page.title}' auf '{title}' geändert; die Seite bleibt unter /{page.path}.")
        payload = {
            "action": "update", "page_id": page.id, "path": page.path, "title": title,
            "description": description, "tags": merged_tags, "content": content,
            "base_hash": sha(page.content), "blocks": [b.__dict__ for b in draft.blocks], "ops": draft.ops,
        }
        diff = markdown.unified_diff(page.content, content, page.path)
        if merged_tags != page.tags:
            diff += f"\n# Tags: {', '.join(page.tags) or '–'} -> {', '.join(merged_tags)}\n"
        summary = f"Ergänzung von /{page.path}"

    payload["hints"] = hints
    payload["stable_id"] = draft.stable_id
    return ctx.store.add_proposal(
        "wiki_page", draft.title, payload, summary=summary, diff=diff, source=draft.source,
        dedup_key=f"wiki:{path}",
    )
