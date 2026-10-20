"""Wiki-Lint: tote Links, mögliche Dubletten, Seiten ohne Tags und veraltete Seiten.

- Tote Links: Wiki.js erfasst beim Rendern jeden internen Link (auch auf fehlende Seiten);
  geprüft wird gegen die Seitenliste. Externe Links werden bewusst nicht aufgerufen.
- Dubletten: gleicher Titel oder – mit Suchindex – sehr ähnlicher Inhalt. Vom Agent gepflegte
  Seiten verschiedener Quellobjekte (z.B. zwei Steckbriefe) gelten nie als Dublette.
- Veraltet: Jede Seite mit Quellobjekt (Netbox, Intune, Wazuh, FortiGate) wird über ihren
  Generator neu berechnet. Weicht das Ergebnis ab, entsteht ein normaler Vorschlag zur Freigabe.
  Ist das Quellobjekt gelöscht, wird das nur gemeldet.
"""

from __future__ import annotations

import functools
import re
from datetime import datetime, timezone
from difflib import SequenceMatcher

from doku_agent import markdown
from doku_agent.context import Context
from doku_agent.pages import Block, PageDraft, propose_page, sha
from doku_agent.wiki import PageInfo, normalize_path

REPORT_KEY = "lint:report"
REPORT_ID = "lint:report"
MAX_DUPLICATES = 50


class SourceGone(RuntimeError):
    """Das Quellobjekt einer Seite existiert nicht mehr."""


class Unsupported(RuntimeError):
    """Quelle unbekannt oder in der Konfiguration abgeschaltet."""


def _not_found(exc: Exception) -> bool:
    return getattr(exc, "status", None) == 404


def refresh(ctx: Context, stable_id: str) -> int | None:
    """Seite eines Quellobjekts neu berechnen. Rückgabe: Vorschlags-ID oder None (Seite ist aktuell)."""
    parts = stable_id.split(":")
    source = parts[0]
    if source == "netbox" and ctx.cfg.netbox.enabled and len(parts) == 3:
        from doku_agent.generators.netbox_docs import document_object
        try:
            return document_object(ctx, parts[1], int(parts[2]))
        except Exception as exc:
            if _not_found(exc):
                raise SourceGone("Objekt in Netbox gelöscht") from exc
            raise
    if source == "intune" and ctx.cfg.intune.enabled:
        from doku_agent.generators import intune_docs
        if parts[1] == "groups":
            return intune_docs.document_groups(ctx)
        if parts[1] == "apps":
            return intune_docs.document_apps(ctx)
        category, policy_id = parts[1], ":".join(parts[2:])
        try:
            policy = ctx.intune.policy(category, policy_id)
        except Exception as exc:
            if _not_found(exc):
                raise SourceGone("Richtlinie in Intune gelöscht") from exc
            raise
        return intune_docs.document_policy(ctx, category, policy)
    if source == "wazuh" and ctx.cfg.wazuh.enabled:
        from doku_agent.generators import wazuh_docs
        kind, rest = parts[1], ":".join(parts[2:])
        if kind in ("rules", "decoders"):
            files = ctx.wazuh.rule_files() if kind == "rules" else ctx.wazuh.decoder_files()
            info = next((f for f in files if f.get("filename") == rest), None)
            if info is None:
                raise SourceGone(f"Datei {rest} gibt es in Wazuh nicht mehr")
            fn = wazuh_docs.document_rule_file if kind == "rules" else wazuh_docs.document_decoder_file
            return fn(ctx, info)
        if kind == "config" and rest == "manager":
            return wazuh_docs.manager_page(ctx)
        if kind == "config" and rest.startswith("group:"):
            group = rest.split(":", 1)[1]
            if group not in {g.get("name") for g in ctx.wazuh.groups()}:
                raise SourceGone(f"Wazuh-Gruppe {group} gelöscht")
            return wazuh_docs.group_page(ctx, group)
        if kind == "sca":
            agents = {a["id"]: a for a in ctx.wazuh.agents()}
            if rest not in agents:
                raise SourceGone(f"Wazuh-Agent {rest} gibt es nicht mehr")
            wanted = set(ctx.cfg.wazuh.sca_agents)
            agent = agents[rest]
            if agent.get("status") != "active" or (wanted and rest not in wanted and agent.get("name") not in wanted):
                raise Unsupported(stable_id)  # gerade offline bzw. nicht mehr ausgewählt: nichts zu prüfen
            return next((r for r in wazuh_docs.document_sca(ctx, agent_id=rest) if r), None)
    if source == "fortigate" and ctx.cfg.fortigate.enabled and len(parts) == 4:
        from doku_agent.generators.fortigate_docs import document_fortigate
        device, vdom, section = parts[1:]
        dev = next((d for d in ctx.cfg.fortigate.devices if d.name == device), None)
        if dev is None or vdom not in dev.vdoms:
            raise SourceGone(f"FortiGate {device}/{vdom} ist nicht mehr konfiguriert")
        if section not in ctx.cfg.fortigate.include:
            raise Unsupported(stable_id)
        return next((r for r in document_fortigate(ctx, device, vdom, [section]) if r), None)
    raise Unsupported(stable_id)


# --- Korrekturvorschläge -----------------------------------------------------------

# wie localeSegmentRegex in Wiki.js (server/helpers/page.js); solche Pfade sind dort für Seiten gesperrt
_LOCALE = re.compile(r"^[a-z]{2}(-[a-z]{2})?$", re.I)


def resolve_href(href: str, page_path: str, locale: str) -> str | None:
    """Linkziel so auflösen wie Wiki.js beim Rendern ('locale/pfad'); None für externe Links,
    Anker, Dateien und Systempfade."""
    if not href or href.startswith("#") or "://" in href or href.startswith(("mailto:", "tel:")) or "." in href:
        return None
    path = href.split("#")[0].split("?")[0]
    if re.match(r"^/[a-z](/|$)", path, re.I):
        return None
    if not path.startswith("/"):
        path = f"/{path}" if page_path == "home" else f"/{page_path}/{path}"
    parts = [p for p in path.strip("/").split("/") if p and p not in (".", "..")]
    loc = parts.pop(0) if parts and _LOCALE.match(parts[0]) else locale
    return f"{loc}/{'/'.join(parts) or 'home'}"


def suggest_target(ctx: Context, dead: str, pages: list[PageInfo]) -> tuple[str | None, list[str], str]:
    """Ersatz für ein totes Linkziel: (eindeutiger Pfad oder None, Kandidaten, Begründung)."""
    _, _, path = dead.partition("/")
    last = path.rsplit("/", 1)[-1].lower()
    same_name = [p for p in pages if p.path.rsplit("/", 1)[-1].lower() == last]
    if len(same_name) == 1:
        return same_name[0].path, [same_name[0].path], "gleicher Seitenname"
    ratios = sorted(((SequenceMatcher(None, path, p.path).ratio(), p.path) for p in pages), reverse=True)
    if ratios and ratios[0][0] >= 0.85 and (len(ratios) == 1 or ratios[0][0] - ratios[1][0] >= 0.1):
        return ratios[0][1], [ratios[0][1]], f"ähnlicher Pfad ({ratios[0][0]:.2f})"
    candidates = [p for r, p in ratios[:3] if r >= 0.5]
    try:
        from doku_agent import semantic
        if semantic.is_ready(ctx):
            by_id = {p.id: p.path for p in pages}
            hits = [(by_id[pid], score) for pid, score in
                    semantic.similar_pages(ctx, re.sub(r"[/_-]+", " ", path), limit=3) if pid in by_id]
            if hits and hits[0][1] >= 0.75 and (len(hits) == 1 or hits[0][1] - hits[1][1] >= 0.08):
                return hits[0][0], [hits[0][0]], f"inhaltlich passend ({hits[0][1]:.2f})"
            candidates += [h for h, _ in hits if h not in candidates]
    except Exception as exc:
        ctx.log.warning("Inhaltliche Suche für %s nicht möglich: %s", dead, exc)
    return None, candidates[:3], ""


def suggest_tags(ctx: Context, page: PageInfo, pages: list[PageInfo], load_vectors=None) -> list[str]:
    """Tags für eine Seite ohne Tags: die üblichen des eigenen Ordners, sonst die der ähnlichsten Seiten.
    load_vectors: liefert (ids, Seitenvektoren) – im Lint-Lauf einmal berechnet für alle Seiten."""
    profile = ctx.conventions.profile_for_path(page.path)
    if profile.common_tags and not profile.inherited:
        return profile.common_tags[:5]
    try:
        from doku_agent import semantic
        if not semantic.is_ready(ctx):
            return []
        ids, vectors = load_vectors() if load_vectors else semantic.page_vectors(ctx)
        if page.id not in ids:
            return []
        tags_of = {p.id: p.tags for p in pages if p.tags}
        sims = vectors @ vectors[ids.index(page.id)]
        neighbors = [(float(sims[i]), pid) for i, pid in enumerate(ids) if pid != page.id and pid in tags_of]
        neighbors = [n for n in sorted(neighbors, reverse=True)[:5] if n[0] >= 0.6]
    except Exception as exc:
        ctx.log.warning("Tag-Vorschlag für /%s nicht möglich: %s", page.path, exc)
        return []
    counts: dict[str, int] = {}
    for _, pid in neighbors:
        for tag in tags_of[pid]:
            counts[tag] = counts.get(tag, 0) + 1
    picked = [t for t, c in sorted(counts.items(), key=lambda x: -x[1]) if c >= 2]
    if not picked and neighbors and neighbors[0][0] >= 0.8:
        picked = list(tags_of[neighbors[0][1]])
    return picked[:5]


def propose_fixes(ctx: Context, info: PageInfo, link_map: dict[str, str], tags: list[str], notes: list[str]) -> int | None:
    """Korrekturen einer Seite als normaler Wiki-Vorschlag (Diff, Freigabe)."""
    page = ctx.wiki.get_page(info.id)
    if page.content_type != "markdown":
        link_map = {}
    content = markdown.replace_links(page.content, link_map)
    new_tags = list(dict.fromkeys([*page.tags, *tags]))
    if content == page.content and new_tags == page.tags:
        return None
    diff = markdown.unified_diff(page.content, content, page.path)
    if new_tags != page.tags:
        diff += f"\n# Tags: {', '.join(page.tags) or '–'} -> {', '.join(new_tags)}\n"
    payload = {"action": "update", "page_id": page.id, "path": page.path, "title": page.title,
               "description": page.description, "tags": new_tags, "content": content, "base_hash": sha(page.content),
               "blocks": [], "ops": [], "replacements": list(link_map.items()), "hints": notes, "stable_id": None}
    return ctx.store.add_proposal("wiki_page", f"Wiki-Lint: {page.title} korrigieren", payload,
                                  summary="Korrekturen aus dem Wiki-Lint: " + "; ".join(notes), diff=diff,
                                  source="lint", dedup_key=f"lint-fix:{page.path}")


def _report_path(ctx: Context) -> str:
    return normalize_path(ctx.cfg.wiki.paths.get("wiki_lint") or "wartung/wiki-lint")


def report_untagged_pages(pages: list[PageInfo]) -> list[PageInfo]:
    return [p for p in pages if not p.tags]


def run_lint(ctx: Context) -> dict:
    cfg = ctx.cfg
    pages = ctx.wiki.list_pages()
    by_id = {p.id: p for p in pages}
    mappings = {k.removeprefix("page-for:"): v for k, v in ctx.store.kv_items("page-for:").items() if v}
    report_page = mappings.get(REPORT_ID)
    excluded_prefixes = [normalize_path(p) for p in cfg.lint.exclude_paths]

    def skip(page) -> bool:
        return (page.id == report_page or page.path == _report_path(ctx)
                or any(page.path == p or page.path.startswith(p + "/") for p in excluded_prefixes))

    checked = [p for p in pages if not skip(p)]
    report: dict = {"at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "pages": len(checked),
                    "dead_links": [], "duplicates": [], "untagged": [], "stale": [], "current": 0, "gone": [],
                    "errors": []}

    # --- tote Links -------------------------------------------------------
    existing = {f"{p.locale or cfg.wiki.locale}/{p.path}" for p in ctx.wiki.list_pages(all_locales=True)}
    checked_ids = {p.id for p in checked}
    for item in ctx.wiki.links():
        if item.get("id") not in checked_ids:
            continue
        page = by_id[item["id"]]
        for target in sorted(set(item.get("links") or [])):
            if target not in existing:
                report["dead_links"].append({"path": page.path, "title": page.title, "target": "/" + target})

    # --- Korrekturen: tote Links und fehlende Tags ----------------------------
    fixes: dict[int, dict] = {}  # Seiten-ID -> {"links": {alt: neu}, "tags": [...], "notes": [...]}
    candidates_pages = [p for p in pages if not skip(p)]
    if cfg.lint.fix_links and report["dead_links"]:
        content_cache: dict[int, list[str]] = {}
        for d in report["dead_links"]:
            dead = d["target"].lstrip("/")
            target, candidates, why = suggest_target(ctx, dead, [p for p in candidates_pages if p.path != d["path"]])
            d["fix"], d["candidates"] = (f"/{target}" if target else None), candidates
            if not target:
                continue
            page = next(p for p in checked if p.path == d["path"])
            if page.id not in content_cache:
                content_cache[page.id] = markdown.link_targets(ctx.wiki.get_page(page.id).content)
            for href in content_cache[page.id]:
                if resolve_href(href, page.path, page.locale or cfg.wiki.locale) == dead:
                    anchor = href[href.index("#"):] if "#" in href else ""
                    explicit = href.startswith("/") and dead.split("/")[0] == href.strip("/").split("/")[0]
                    new = f"/{dead.split('/')[0]}/{target}" if explicit else f"/{target}"
                    entry = fixes.setdefault(page.id, {"links": {}, "tags": [], "notes": []})
                    entry["links"][href] = new + anchor
                    entry["notes"].append(f"Link {href} → {new + anchor} ({why})")
    from doku_agent import semantic
    load_vectors = functools.cache(lambda: semantic.page_vectors(ctx))
    if cfg.lint.suggest_tags:
        for d in report_untagged_pages(checked):
            tags = suggest_tags(ctx, d, pages, load_vectors)
            if tags:
                entry = fixes.setdefault(d.id, {"links": {}, "tags": [], "notes": []})
                entry["tags"] = tags
                entry["notes"].append(f"Tags ergänzt: {', '.join(tags)}")
    fix_proposals = {}
    for pid, entry in fixes.items():
        try:
            fix_proposals[pid] = propose_fixes(ctx, by_id[pid], entry["links"], entry["tags"], entry["notes"])
        except Exception as exc:
            report["errors"].append(f"Korrektur für /{by_id[pid].path}: {exc}")
    for d in report["dead_links"]:
        page = next((p for p in checked if p.path == d["path"]), None)
        d["proposal"] = fix_proposals.get(page.id) if page and d.get("fix") else None

    # --- Dubletten --------------------------------------------------------
    managed = {}
    for stable_id, pid in mappings.items():
        managed.setdefault(int(pid), set()).add(stable_id)

    def distinct_sources(a: int, b: int) -> bool:
        return a in managed and b in managed and managed[a] != managed[b]

    seen_pairs: set[tuple[int, int]] = set()
    by_title: dict[str, list] = {}
    for p in checked:
        by_title.setdefault(markdown.norm_heading(p.title), []).append(p)
    for title, group in by_title.items():
        for i, a in enumerate(group):
            for b in group[i + 1:]:
                if title and not distinct_sources(a.id, b.id):
                    seen_pairs.add((min(a.id, b.id), max(a.id, b.id)))
                    report["duplicates"].append({"a": a.path, "a_title": a.title, "b": b.path, "b_title": b.title,
                                                 "reason": "gleicher Titel"})
    try:
        if semantic.is_ready(ctx):
            ids, vectors = load_vectors()
            sims = vectors @ vectors.T
            candidates = []
            for i, a in enumerate(ids):
                for j in range(i + 1, len(ids)):
                    b = ids[j]
                    score = float(sims[i, j])
                    if score < cfg.lint.duplicate_threshold or a not in checked_ids or b not in checked_ids:
                        continue
                    if (min(a, b), max(a, b)) in seen_pairs or distinct_sources(a, b):
                        continue
                    candidates.append((score, a, b))
            for score, a, b in sorted(candidates, reverse=True)[:MAX_DUPLICATES]:
                report["duplicates"].append({"a": by_id[a].path, "a_title": by_id[a].title, "b": by_id[b].path,
                                             "b_title": by_id[b].title, "reason": f"ähnlicher Inhalt ({score:.2f})"})
    except Exception as exc:
        report["errors"].append(f"Inhaltsvergleich: {exc}")

    # --- ohne Tags --------------------------------------------------------
    report["untagged"] = [{"path": p.path, "title": p.title, "suggested": fixes.get(p.id, {}).get("tags", []),
                           "proposal": fix_proposals.get(p.id) if fixes.get(p.id, {}).get("tags") else None}
                          for p in report_untagged_pages(checked)]

    # --- veraltete Seiten / gelöschte Quellen ------------------------------
    if cfg.lint.refresh_stale:
        for stable_id, pid in sorted(mappings.items()):
            page = by_id.get(int(pid))
            if page is None:  # Seite im Wiki gelöscht: Zuordnung aufräumen
                ctx.store.kv_delete(f"page-for:{stable_id}")
                continue
            if skip(page) or stable_id.startswith("lint:"):
                continue
            try:
                proposal = refresh(ctx, stable_id)
            except SourceGone as exc:
                report["gone"].append({"path": page.path, "title": page.title, "source": stable_id, "reason": str(exc)})
            except Unsupported:
                continue
            except Exception as exc:
                report["errors"].append(f"/{page.path} ({stable_id}): {exc}")
            else:
                if proposal:
                    report["stale"].append({"path": page.path, "title": page.title, "source": stable_id,
                                            "proposal": proposal})
                else:
                    report["current"] += 1

    ctx.store.kv_set(REPORT_KEY, report)
    if cfg.lint.report_page:
        report["report_proposal"] = propose_report(ctx, report)
        ctx.store.kv_set(REPORT_KEY, report)
    summary = {"seiten": report["pages"], "tote_links": len(report["dead_links"]),
               "dubletten": len(report["duplicates"]), "ohne_tags": len(report["untagged"]),
               "veraltet": len(report["stale"]), "quelle_geloescht": len(report["gone"]),
               "fehler": len(report["errors"])}
    ctx.log.info("Wiki-Lint: %s", summary)
    return summary


def _fix_text(d: dict) -> str:
    if d.get("fix"):
        return f"ersetzen durch `{d['fix']}`"
    if d.get("candidates"):
        return "Kandidaten: " + ", ".join(f"`/{c}`" for c in d["candidates"])
    return "–"


def _link(path: str, title: str) -> str:
    return f"[{(title or path).replace(']', '')}](/{path})"


def propose_report(ctx: Context, report: dict) -> int | None:
    """Bericht als Wiki-Seite. Ohne Datum und Vorschlagsnummern, damit sich die Seite nur ändert,
    wenn sich die Befunde ändern."""
    def section(rows, headers, empty):
        return markdown.table(headers, rows) if rows else f"_{empty}_"

    counts = markdown.table(["Prüfung", "Befunde"], [
        ["Tote interne Links", len(report["dead_links"])], ["Mögliche Dubletten", len(report["duplicates"])],
        ["Seiten ohne Tags", len(report["untagged"])], ["Veraltete Seiten", len(report["stale"])],
        ["Quelle gelöscht", len(report["gone"])],
    ])
    blocks = [
        Block("lint-summary", "Zusammenfassung", f"Geprüft wurden {report['pages']} Seiten.\n\n{counts}"),
        Block("lint-dead-links", "Tote Links", section(
            [[_link(d["path"], d["title"]), f"`{d['target']}`", _fix_text(d)] for d in report["dead_links"]],
            ["Seite", "Linkziel (existiert nicht)", "Vorschlag"], "Keine toten Links.")),
        Block("lint-duplicates", "Mögliche Dubletten", section(
            [[_link(d["a"], d["a_title"]), _link(d["b"], d["b_title"]), d["reason"]] for d in report["duplicates"]],
            ["Seite", "Ähnliche Seite", "Grund"], "Keine Dubletten gefunden.")),
        Block("lint-untagged", "Seiten ohne Tags", section(
            [[_link(d["path"], d["title"]), ", ".join(d.get("suggested") or []) or "–"] for d in report["untagged"]],
            ["Seite", "Vorgeschlagene Tags"], "Alle Seiten haben Tags.")),
        Block("lint-stale", "Veraltete Seiten", section(
            [[_link(d["path"], d["title"]), f"`{d['source']}`"] for d in report["stale"]],
            ["Seite", "Quelle"], "Alle vom Agent gepflegten Seiten sind aktuell.")
            + ("\n\nFür jede veraltete Seite liegt ein Aktualisierungs-Vorschlag in der Freigabe-Liste."
               if report["stale"] else "")),
        Block("lint-gone", "Quelle gelöscht", section(
            [[_link(d["path"], d["title"]), f"`{d['source']}`", d["reason"]] for d in report["gone"]],
            ["Seite", "Quelle", "Hinweis"], "Keine Seiten ohne Quelle.")),
    ]
    return propose_page(ctx, PageDraft(
        doc_type="wiki_lint", title="Wiki-Lint: Bericht", description="Automatische Prüfung des Wikis durch doku-agent",
        blocks=blocks, target_path=_report_path(ctx),
        intro="Automatischer Prüfbericht: tote interne Links, mögliche Dubletten, Seiten ohne Tags und Seiten, deren "
              "Quelle (Netbox, Intune, Wazuh, FortiGate) sich geändert hat. Externe Links werden nicht aufgerufen.",
        source="lint", stable_id=REPORT_ID,
    ))
