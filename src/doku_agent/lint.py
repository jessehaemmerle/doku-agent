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

from datetime import datetime, timezone

from doku_agent import markdown
from doku_agent.context import Context
from doku_agent.pages import Block, PageDraft, propose_page
from doku_agent.wiki import normalize_path

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


def _report_path(ctx: Context) -> str:
    return normalize_path(ctx.cfg.wiki.paths.get("wiki_lint") or "wartung/wiki-lint")


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
        from doku_agent import semantic
        if semantic.is_ready(ctx):
            ids, vectors = semantic.page_vectors(ctx)
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
    report["untagged"] = [{"path": p.path, "title": p.title} for p in checked if not p.tags]

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
            [[_link(d["path"], d["title"]), f"`{d['target']}`"] for d in report["dead_links"]],
            ["Seite", "Linkziel (existiert nicht)"], "Keine toten Links.")),
        Block("lint-duplicates", "Mögliche Dubletten", section(
            [[_link(d["a"], d["a_title"]), _link(d["b"], d["b_title"]), d["reason"]] for d in report["duplicates"]],
            ["Seite", "Ähnliche Seite", "Grund"], "Keine Dubletten gefunden.")),
        Block("lint-untagged", "Seiten ohne Tags", section(
            [[_link(d["path"], d["title"])] for d in report["untagged"]], ["Seite"], "Alle Seiten haben Tags.")),
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
