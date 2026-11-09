"""Änderungsbericht: was sich je Kalenderwoche an den dokumentierten Quellen geändert hat.

Bei jedem Seitenentwurf (auch ohne Änderung am Wiki) merkt sich der Agent die Tabellenzeilen der
verwalteten Abschnitte ausgewählter Seiten. Beim nächsten Entwurf vergleicht er den neuen Stand mit dem
gemerkten und schreibt hinzugekommene und entfallene Zeilen als Ereignisse in ein Protokoll (mit Datum).
Der Wochenbericht fasst die Ereignisse einer Kalenderwoche zusammen: neue Seiten, neue und entfallene
Einträge je Bereich, neue und behobene Prüfbefunde. Fließtext zählt nicht als Änderung (er wird neu
formuliert, ohne dass sich die Quelle ändert), deshalb werden nur Tabellenzeilen verglichen und
Beschreibungs-/Bewertungs-/Zusammenfassungsblöcke übersprungen.

Grundlage sind die Seitenentwürfe selbst, nicht das Wiki: So steht im Bericht, was der Agent erkannt hat,
auch wenn eine Freigabe noch aussteht.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

from doku_agent import markdown
from doku_agent.context import Context

HISTORY_DAYS = 400  # Ereignisse älter als gut ein Jahr werden verworfen
MAX_ROWS = 400  # je Abschnitt (Schutz vor sehr großen Tabellen)
STATE_PREFIX = "change-state:"  # letzter bekannter Stand je stable_id
LOG_KEY = "change-log"  # Ereignisprotokoll (nach Datum)

# stable_id-Präfix -> Bereichsname im Bericht
AREAS = {"netbox": "Netbox", "wazuh": "Wazuh", "intune": "Intune", "entra": "Entra ID",
         "ad": "Active Directory", "fortigate": "Firewall", "coverage": "Abdeckung", "adcs": "Zertifikatsdienste",
         "addns": "DNS"}
# Blöcke, deren Zeilen als Befunde gelten (hinzu = neuer Befund, weg = behoben)
FINDING_BLOCKS = ("audit", "findings", "pruefung", "cov-")
# Block-Endungen, die nicht verglichen werden: Fließtext (Beschreibung/Bewertung/Zusammenfassung) und
# aggregierende Zähltabellen (Überblick). Detail- und Befundtabellen werden verglichen.
SKIP_SUFFIXES = ("-summary", "-overview", "-assessment", "-description", "-beschreibung", "-bewertung",
                 "-zusammenfassung")
_SEPARATOR = re.compile(r"^\|(\s*:?-{3,}:?\s*\|)+$")
_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")  # Linktext behalten, Ziel verwerfen (Pfade ändern sich)


def _area(stable_id: str) -> str:
    head = stable_id.split(":", 1)[0]
    return AREAS.get(head, head)


def _is_finding(block_id: str) -> bool:
    low = block_id.lower()
    return any(k in low for k in FINDING_BLOCKS)


def _skip(block_id: str) -> bool:
    return block_id.lower().endswith(SKIP_SUFFIXES)


def _rows(content: str, block_id: str) -> list[str]:
    """Normalisierte Tabellenzeilen eines verwalteten Blocks (ohne Kopf- und Trennzeile, Links als Text)."""
    begin, end = markdown.block_markers(block_id)
    if begin not in content:
        return []
    body = content.split(begin, 1)[1].split(end, 1)[0]
    out, header_seen = [], False
    for line in body.splitlines():
        line = line.strip()
        if not line.startswith("|") or not line.endswith("|"):
            continue
        if _SEPARATOR.match(line):
            header_seen = True
            continue
        if not header_seen:  # Kopfzeile (vor der Trennzeile)
            continue
        cells = [c.strip() for c in _LINK.sub(r"\1", line).strip().strip("|").split("|")]
        out.append(" | ".join(cells))
        if len(out) >= MAX_ROWS:
            break
    return out


def snapshot(content: str, block_ids: list[str]) -> dict[str, list[str]]:
    rows = {}
    for bid in block_ids:
        if _skip(bid):
            continue
        r = _rows(content, bid)
        if r:
            rows[bid] = r
    return rows


@dataclass
class Event:
    at: str  # ISO-Datum
    area: str
    title: str
    block: str
    kind: str  # "neue Seite", "neuer Eintrag", "Eintrag entfällt", "neuer Befund", "behobener Befund"
    detail: str


def _label(block_id: str, added: bool) -> str:
    if _is_finding(block_id):
        return "neuer Befund" if added else "behobener Befund"
    return "neuer Eintrag" if added else "Eintrag entfällt"


KINDS_KEY = "change-kinds"  # Seitenart (stable_id ohne Objekt) -> Tag, an dem sie zuerst erfasst wurde


def _kind(stable_id: str) -> str:
    """'netbox:device:12' -> 'netbox:device', 'ad:gpo:{…}' -> 'ad:gpo', 'ad:domain' -> 'ad'."""
    parts = stable_id.split(":")
    return ":".join(parts[:2]) if len(parts) >= 3 else parts[0]


def record(ctx: Context, stable_id: str, title: str, content: str, block_ids: list[str]) -> None:
    """Stand einer Seite festhalten und Änderungen gegenüber dem letzten Stand protokollieren.

    Neue Seiten werden gemeldet, sobald ihre Seitenart schon an einem früheren Tag erfasst wurde. Am ersten Tag
    einer Seitenart (erster Lauf, oder eine Quelle wird später eingeschaltet) wird nur der Stand gemerkt – kein
    Schwall von Ereignissen für Seiten, die es längst gibt. Verglichen werden nur die Abschnitte des Entwurfs:
    fehlt ein Abschnitt, weil seine Quelle gerade nicht lesbar war, bleibt sein gemerkter Stand stehen, statt
    alle Zeilen als entfallen (und beim nächsten Lauf als neu) zu melden."""
    if not ctx.cfg.changes.enabled:
        return
    key = STATE_PREFIX + stable_id
    prev = ctx.store.kv_get(key)
    current = snapshot(content, block_ids)
    today = datetime.now(ZoneInfo(ctx.cfg.general.timezone)).date().isoformat()
    area = _area(stable_id)
    if ctx.store.kv_get("change-start") is None:
        ctx.store.kv_set("change-start", today)  # Beginn der Aufzeichnung (für den Bericht)
    kinds = ctx.store.kv_get(KINDS_KEY) or {}
    kind = _kind(stable_id)
    if kind not in kinds:
        kinds[kind] = today
        ctx.store.kv_set(KINDS_KEY, kinds)
    events: list[Event] = []
    compared = {b for b in block_ids if not _skip(b)}
    old_rows: dict[str, list[str]] = (prev or {}).get("rows", {})
    if prev is None:
        if kinds[kind] < today:
            events.append(Event(today, area, title, "", "neue Seite", ""))
    else:
        for bid, rows in current.items():
            old = set(old_rows.get(bid, []))
            for row in rows:
                if row not in old:
                    events.append(Event(today, area, title, bid, _label(bid, True), row))
        for bid, rows in old_rows.items():
            if bid not in compared:
                continue  # Abschnitt diesmal nicht berechnet (Quelle nicht lesbar) – nichts entfällt
            new = set(current.get(bid, []))
            for row in rows:
                if row not in new:
                    events.append(Event(today, area, title, bid, _label(bid, False), row))
    kept = {bid: rows for bid, rows in old_rows.items() if bid not in compared}
    ctx.store.kv_set(key, {"title": title, "rows": {**kept, **current}, "at": today})
    if events:
        _append(ctx, events)


def _append(ctx: Context, events: list[Event]) -> None:
    log = ctx.store.kv_get(LOG_KEY) or []
    cutoff = (date.today() - timedelta(days=HISTORY_DAYS)).isoformat()
    log = [e for e in log if e.get("at", "") >= cutoff]
    log.extend(e.__dict__ for e in events)
    ctx.store.kv_set(LOG_KEY, log)


# --- Wochenbericht --------------------------------------------------------------------------------

def week_bounds(ref: date) -> tuple[date, date, str]:
    """Montag und Sonntag der ISO-Woche von ref, plus Kennung '2026-kw43'."""
    monday = ref - timedelta(days=ref.weekday())
    year, week, _ = ref.isocalendar()
    return monday, monday + timedelta(days=6), f"{year}-kw{week:02d}"


def ref_from_slug(slug: str) -> date:
    """'2026-kw43' -> ein Tag in dieser ISO-Woche (für die Neuberechnung aus dem Wiki-Lint)."""
    try:
        year, week = slug.lower().split("-kw")
        return date.fromisocalendar(int(year), int(week), 1)
    except (ValueError, TypeError):
        return date.today() - timedelta(days=7)


def events_in(ctx: Context, start: date, end: date) -> list[dict]:
    lo, hi = start.isoformat(), end.isoformat()
    return [e for e in (ctx.store.kv_get(LOG_KEY) or []) if lo <= e.get("at", "") <= hi]


# Reihenfolge der Ereignisarten im Bericht
KIND_ORDER = ["neue Seite", "neuer Befund", "behobener Befund", "neuer Eintrag", "Eintrag entfällt"]


def _table(events: list[dict]) -> str:
    rows = [[e["area"], e["kind"], e["title"] or "–", e.get("detail") or "–", e["at"]]
            for e in sorted(events, key=lambda e: (KIND_ORDER.index(e["kind"]) if e["kind"] in KIND_ORDER else 9,
                                                    e["area"].lower(), e["title"].lower()))]
    return markdown.table(["Bereich", "Änderung", "Seite/Objekt", "Detail", "Datum"], rows)


def week_facts(events: list[dict]) -> str:
    from collections import Counter
    by_kind = Counter(e["kind"] for e in events)
    by_area = Counter(e["area"] for e in events)
    lines = [f"Änderungen gesamt: {len(events)}"]
    lines += [f"{k}: {by_kind[k]}" for k in KIND_ORDER if by_kind.get(k)]
    lines += [f"Bereich {a}: {n}" for a, n in sorted(by_area.items())]
    return "\n".join(lines)


def document_week(ctx: Context, ref: date | None = None) -> int | None:
    """Bericht einer Kalenderwoche (Standard: die gerade vergangene Woche)."""
    from doku_agent.generators import narrative
    from doku_agent.pages import Block, PageDraft, propose_page
    tz = ZoneInfo(ctx.cfg.general.timezone)
    ref = ref or (datetime.now(tz).date() - timedelta(days=7))
    start, end, slug = week_bounds(ref)
    events = events_in(ctx, start, end)
    span = f"{start.strftime('%d.%m.%Y')} bis {end.strftime('%d.%m.%Y')}"
    overview = markdown.table(["Bereich", "Änderungen"],
                              sorted(((a, sum(e["area"] == a for e in events)) for a in {e["area"] for e in events}),
                                     key=lambda r: (-r[1], r[0]))) if events else "_Keine Änderungen in dieser Woche._"
    table = _table(events) if events else "_Keine Änderungen in dieser Woche._"
    started = ctx.store.kv_get("change-start")
    note = ""
    if started and started > start.isoformat():
        note = f" Die Aufzeichnung begann am {started}; frühere Änderungen sind nicht erfasst."
    blocks = []
    if events and narrative.enabled(ctx, "audit"):
        text = narrative.narrate(
            ctx, f"changes:{slug}", expert="IT-Dokumentation und Änderungsnachverfolgung",
            task="Fasse die Änderungen dieser Woche für ein IT-Team zusammen: Was ist neu, was ist weggefallen, "
                 "welche Prüfbefunde kamen hinzu oder wurden behoben, und worauf sollte man achten. Nenne nur, was "
                 "in den Daten steht.",
            facts=week_facts(events), fallback=f"In der Woche {span} wurden {len(events)} Änderungen erfasst.")
        if text is not None:
            blocks.append(Block("changes-summary", "Zusammenfassung", text))
    blocks += [Block("changes-overview", "Überblick", overview),
               Block("changes-detail", "Alle Änderungen", table)]
    return propose_page(ctx, PageDraft(
        doc_type="changes", title=f"Änderungen {slug}", description=f"Änderungen der Woche {span}", blocks=blocks,
        path_vars={"week": slug},
        intro=f"Automatisch erfasste Änderungen an den dokumentierten Quellen in der Woche **{span}** (KW aus "
              f"{start.isocalendar()[1]}).{note}",
        source=f"changes:{slug}", stable_id=f"changes:week:{slug}"))


def document_index(ctx: Context) -> int | None:
    """Übersichtsseite mit Link je Woche, für die Ereignisse vorliegen (jüngste zuerst)."""
    from doku_agent.pages import Block, PageDraft, propose_page, render_path
    log = ctx.store.kv_get(LOG_KEY) or []
    weeks: dict[str, int] = {}
    for e in log:
        try:
            ref = date.fromisoformat(e["at"])
        except (ValueError, KeyError):
            continue
        _, _, slug = week_bounds(ref)
        weeks[slug] = weeks.get(slug, 0) + 1
    template = ctx.cfg.wiki.paths.get("changes") or "wartung/aenderungen/{week}"
    rows = []
    for slug in sorted(weeks, reverse=True)[:ctx.cfg.changes.keep_weeks]:
        path = render_path(template, {"week": slug}, ctx.conventions.profile_for_path(
            render_path(template, {"week": slug}, "kebab")).slug_style)
        rows.append([markdown.link(path, slug), weeks[slug]])
    table = markdown.table(["Woche", "Änderungen"], rows) if rows else "_Noch keine Wochenberichte._"
    return propose_page(ctx, PageDraft(
        doc_type="changes_index", title="Änderungsberichte", description="Wöchentliche Änderungsberichte",
        blocks=[Block("changes-weeks", "Wochen", table)],
        target_path=ctx.cfg.wiki.paths.get("changes_index") or "wartung/aenderungen",
        intro="Wöchentliche Berichte, was sich an den dokumentierten Quellen geändert hat.",
        source="changes", stable_id="changes:index"))


def run_changes(ctx: Context) -> list[int | None]:
    """Job: Bericht der vergangenen Woche und Übersicht aktualisieren."""
    if not ctx.cfg.changes.enabled:
        ctx.log.info("Änderungsbericht ist deaktiviert (changes.enabled)")
        return []
    return [document_week(ctx), document_index(ctx)]
