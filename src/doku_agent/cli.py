"""Kommandozeile: Server starten, Jobs ausführen, Freigaben bearbeiten, Verbindungen prüfen."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from doku_agent.config import ConfigError, load_config


def _ctx(args):
    from doku_agent.context import Context
    return Context(load_config(args.config))


def cmd_serve(args) -> int:
    import uvicorn

    from doku_agent.jobs import Worker
    from doku_agent.scheduler import Scheduler
    from doku_agent.web.app import create_app

    ctx = _ctx(args)
    app = create_app(ctx)
    Worker(ctx).start()
    Scheduler(ctx).start()
    uvicorn.run(app, host=ctx.cfg.web.host, port=ctx.cfg.web.port, log_level="info")
    return 0


def cmd_run(args) -> int:
    from doku_agent.jobs import JOBS, run_now

    if args.job not in JOBS:
        print(f"Unbekannter Job. Verfügbar: {', '.join(JOBS)}", file=sys.stderr)
        return 2
    params = dict(p.split("=", 1) for p in args.param)
    ctx = _ctx(args)
    job_id, ok = run_now(ctx, args.job, params)
    print(ctx.store.get_job(job_id).log)
    return 0 if ok else 1


def cmd_doc(args) -> int:
    from doku_agent.jobs import run_now

    ctx = _ctx(args)
    files = [str(Path(f).resolve()) for f in args.file]
    job_id, ok = run_now(ctx, "freeform", {"instruction": args.instruction, "files": files,
                                           "target_path": args.target or ""})
    print(ctx.store.get_job(job_id).log)
    return 0 if ok else 1


def cmd_proposals(args) -> int:
    ctx = _ctx(args)
    for p in ctx.store.list_proposals(args.status or None):
        print(f"#{p.id:<5} {p.status:<9} {p.kind:<11} {p.title}  [{p.summary.splitlines()[0] if p.summary else ''}]")
    return 0


def cmd_show(args) -> int:
    ctx = _ctx(args)
    p = ctx.store.get_proposal(args.id)
    if p is None:
        print("Nicht gefunden", file=sys.stderr)
        return 1
    print(f"#{p.id} {p.title} ({p.status})\n{p.summary}\n")
    for c in p.payload.get("changes", []):
        needs = f"  (benötigt {', '.join(c['requires'])})" if c.get("requires") else ""
        print(f"  [{c['key']}] {c['label']}: {c['before']} -> {c['after']}{needs}")
    for hint in p.payload.get("hints", []):
        print(f"Hinweis: {hint}")
    print(p.diff or "")
    if p.result:
        print(f"\nErgebnis: {p.result}")
    return 0


def cmd_approve(args) -> int:
    from doku_agent.apply import ApplyError

    try:
        return _approve(args)
    except ApplyError as exc:
        print(f"Nicht übernommen: {exc}", file=sys.stderr)
        return 1


def _approve(args) -> int:
    from doku_agent.apply import apply_proposal

    ctx = _ctx(args)
    prop = ctx.store.get_proposal(args.id)
    if prop is not None and prop.payload.get("changes") and not args.nur and prop.payload.get("selected"):
        # ohne --nur: alle Änderungen, keine Auswahl aus einem früheren Versuch
        ctx.store.update_proposal(args.id, payload={**prop.payload, "selected": None})
    if args.nur:
        from doku_agent.apply import validate_selection

        prop = ctx.store.get_proposal(args.id)
        if prop is None or not prop.payload.get("changes"):
            print("--nur gilt nur für Netbox-Anpassungen mit einzelnen Änderungen", file=sys.stderr)
            return 2
        selected = [k.strip() for k in args.nur.split(",") if k.strip()]
        validate_selection(prop.payload["changes"], set(selected))
        ctx.store.update_proposal(args.id, payload={**prop.payload, "selected": selected})
    result = apply_proposal(ctx, args.id)
    p = ctx.store.get_proposal(args.id)
    print(p.result if result == "applied" else result)
    return 0 if result == "applied" else 1


def cmd_reject(args) -> int:
    from doku_agent.apply import reject_proposal

    reject_proposal(_ctx(args), args.id, ignore=args.ignore)
    print("Abgelehnt.")
    return 0


def cmd_check(args) -> int:
    from doku_agent.egress import allowed_hosts
    from doku_agent.web.app import run_checks

    ctx = _ctx(args)
    print("Erlaubte Hosts: " + ", ".join(sorted(allowed_hosts(ctx.cfg))))
    ok_all = True
    for name, ok, detail in run_checks(ctx):
        ok_all &= ok
        print(f"[{'OK' if ok else 'FEHLER'}] {name}: {detail}")
    return 0 if ok_all else 1


def cmd_ask(args) -> int:
    from doku_agent import semantic

    ctx = _ctx(args)
    text, sources = semantic.answer(ctx, args.question)
    print(text)
    if sources:
        cited = any(s["cited"] for s in sources)
        print("\nQuellen:" if cited else "\nGefundene Abschnitte (das Modell hat keinen davon als Beleg genannt):")
        for s in sources:
            print(f"  [{s['n']}] {s['title']}{' › ' + s['heading'] if s['heading'] else ''} – {s['url']}")
    return 0


def cmd_lint(args) -> int:
    from doku_agent.jobs import run_now
    from doku_agent.lint import REPORT_KEY

    ctx = _ctx(args)
    job_id, ok = run_now(ctx, "wiki_lint", {})
    if not ok:
        print(ctx.store.get_job(job_id).log)
        return 1
    report = ctx.store.kv_get(REPORT_KEY) or {}
    sections = (("Tote Links", "dead_links", lambda d: f"/{d['path']} -> {d['target']}"),
                ("Mögliche Dubletten", "duplicates", lambda d: f"/{d['a']} ~ /{d['b']} ({d['reason']})"),
                ("Ohne Tags", "untagged", lambda d: f"/{d['path']}"),
                ("Veraltet (Vorschlag erstellt)", "stale", lambda d: f"/{d['path']} ({d['source']}, #{d['proposal']})"),
                ("Quelle gelöscht", "gone", lambda d: f"/{d['path']} ({d['reason']})"))
    print(f"{report.get('pages', 0)} Seiten geprüft.")
    for title, key, fmt in sections:
        items = report.get(key, [])
        print(f"\n{title}: {len(items)}")
        for item in items:
            print(f"  {fmt(item)}")
    for err in report.get("errors", []):
        print(f"Fehler: {err}")
    return 0


def cmd_conventions(args) -> int:
    ctx = _ctx(args)
    conv = ctx.conventions
    if args.area is not None:
        print(conv.profile(args.area.strip("/")).summary())
        return 0
    for prefix, n, titles in conv.areas(depth=3):
        print(f"/{prefix:<45} {n:>4} {'Seite ' if n == 1 else 'Seiten'}  z.B. {', '.join(t for t in titles if t)}")
    return 0


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="doku-agent", description="Lokaler KI-Dokumentations-Agent für Wiki.js")
    parser.add_argument("-c", "--config", help="Pfad zur config.yaml (Standard: $DOKU_AGENT_CONFIG oder ./config.yaml)")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("serve", help="Web-Oberfläche, Worker und Zeitplan starten").set_defaults(fn=cmd_serve)

    p = sub.add_parser("run", help="Job sofort ausführen (z.B. discovery, wazuh_rules, intune)")
    p.add_argument("job")
    p.add_argument("--param", action="append", default=[], help="Parameter key=value (z.B. id=12 kind=device)")
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("doc", help="Freie Dokumentation aus Stichpunkten und Dateien erzeugen")
    p.add_argument("instruction", help="Was soll dokumentiert werden?")
    p.add_argument("-f", "--file", action="append", default=[], help="Datei anhängen (mehrfach möglich)")
    p.add_argument("-t", "--target", help="Zielpfad im Wiki (optional)")
    p.set_defaults(fn=cmd_doc)

    p = sub.add_parser("proposals", help="Vorschläge auflisten")
    p.add_argument("--status", default="pending", help="pending|applied|rejected|failed oder leer für alle")
    p.set_defaults(fn=cmd_proposals)

    p = sub.add_parser("show", help="Vorschlag mit Diff anzeigen")
    p.add_argument("id", type=int)
    p.set_defaults(fn=cmd_show)

    p = sub.add_parser("approve", help="Vorschlag freigeben und ausführen")
    p.add_argument("id", type=int)
    p.add_argument("--nur", help="nur diese Änderungen übernehmen, z.B. c1,c3 (Keys siehe 'show')")
    p.set_defaults(fn=cmd_approve)

    p = sub.add_parser("reject", help="Vorschlag ablehnen")
    p.add_argument("id", type=int)
    p.add_argument("--ignore", action="store_true", help="nicht mehr vorschlagen")
    p.set_defaults(fn=cmd_reject)

    sub.add_parser("check", help="Verbindungen zu allen Diensten prüfen").set_defaults(fn=cmd_check)

    sub.add_parser("lint", help="Wiki prüfen: tote Links, Dubletten, ohne Tags, veraltete Seiten").set_defaults(
        fn=cmd_lint)

    p = sub.add_parser("frage", help="Frage ans Wiki stellen (Antwort mit Quellen, Suchindex nötig)")
    p.add_argument("question")
    p.set_defaults(fn=cmd_ask)

    p = sub.add_parser("conventions", help="Gelernte Wiki-Konventionen anzeigen")
    p.add_argument("area", nargs="?", help="Bereich (Pfad-Präfix) für Details")
    p.set_defaults(fn=cmd_conventions)

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    # httpx loggt sonst jede URL inkl. Query auf INFO
    logging.getLogger("httpx").setLevel(logging.WARNING)
    try:
        sys.exit(args.fn(args))
    except ConfigError as exc:
        print(f"Konfigurationsfehler: {exc}", file=sys.stderr)
        sys.exit(2)
