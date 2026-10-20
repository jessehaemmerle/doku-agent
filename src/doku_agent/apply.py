"""Freigegebene Vorschläge ausführen (Wiki.js schreiben bzw. Netbox-Plan abarbeiten)."""

from __future__ import annotations

from doku_agent import markdown
from doku_agent.context import Context
from doku_agent.pages import Block, merge_into, sha
from doku_agent.store import Proposal


class ApplyError(RuntimeError):
    pass


def _blocks(payload: dict) -> list[Block]:
    return [Block(**b) for b in payload.get("blocks", [])]


def _requeue(ctx: Context, prop: Proposal, payload: dict, old: str, new: str, reason: str) -> str:
    payload["content"] = new
    ctx.store.update_proposal(prop.id, payload=payload, diff=markdown.unified_diff(old, new, payload["path"]),
                              status="pending", result=reason)
    return reason


def _reindex(ctx: Context, page_id: int) -> None:
    """Geänderte Seite im Suchindex nachziehen (als Job, damit die Freigabe nicht auf das Modell wartet)."""
    if ctx.cfg.embeddings.enabled:
        ctx.store.enqueue("wiki_index", {"page_id": page_id})


def apply_wiki(ctx: Context, prop: Proposal) -> str:
    payload = dict(prop.payload)
    wiki = ctx.wiki
    if payload["action"] == "create":
        existing = wiki.get_page_by_path(payload["path"])
        if existing is not None:
            if payload.get("edited") or not payload.get("blocks"):
                # Freier Text bzw. von Hand bearbeitet: nicht automatisch zusammenführbar.
                raise ApplyError(f"Unter /{payload['path']} gibt es inzwischen eine Seite. Bitte Pfad im Vorschlag "
                                 "ändern oder den Auftrag erneut ausführen, damit der Agent die Seite ergänzt.")
            # Inzwischen angelegt: Agent-Blöcke einfügen und erneut zur Prüfung vorlegen.
            new, _ = merge_into(existing.content, _blocks(payload), payload.get("ops", []))
            payload.update(action="update", page_id=existing.id, base_hash=sha(existing.content),
                           tags=list(dict.fromkeys([*existing.tags, *payload["tags"]])))
            return _requeue(ctx, prop, payload, existing.content, new,
                            "Seite existiert inzwischen – als Ergänzung neu berechnet, bitte erneut prüfen.")
        page_id = wiki.create_page(payload["path"], payload["title"], payload["content"],
                                   payload.get("description", ""), payload.get("tags", []))
        if payload.get("stable_id"):
            ctx.store.kv_set(f"page-for:{payload['stable_id']}", page_id)
        ctx.store.update_proposal(prop.id, status="applied",
                                  result=f"Seite angelegt (ID {page_id}): {wiki.page_url(payload['path'])}")
        _reindex(ctx, page_id)
        return "applied"

    page = wiki.get_page(int(payload["page_id"]))
    if sha(page.content) != payload.get("base_hash"):
        if payload.get("edited"):
            raise ApplyError("Die Seite wurde nach dem Vorschlag im Wiki geändert und der Vorschlag manuell "
                             "bearbeitet – bitte Vorschlag verwerfen und neu erzeugen.")
        new, _ = merge_into(page.content, _blocks(payload), payload.get("ops", []))
        new = markdown.replace_links(new, payload.get("replacements"))  # Link-Korrekturen des Wiki-Lint
        payload["base_hash"] = sha(page.content)
        return _requeue(ctx, prop, payload, page.content, new,
                        "Seite wurde zwischenzeitlich geändert – Vorschlag neu berechnet, bitte erneut prüfen.")
    wiki.update_page(page, content=payload["content"], description=payload.get("description"),
                     tags=payload.get("tags"), title=payload.get("title"))
    if payload.get("stable_id"):
        ctx.store.kv_set(f"page-for:{payload['stable_id']}", page.id)
    ctx.store.update_proposal(prop.id, status="applied", result=f"Seite aktualisiert: {wiki.page_url(page.path)}")
    _reindex(ctx, page.id)
    return "applied"


def validate_selection(changes: list[dict], selected: set[str]) -> None:
    """Auswahl prüfen, bevor etwas geschrieben wird (ohne Netbox-Zugriff)."""
    if not selected:
        raise ApplyError("Keine Änderung ausgewählt.")
    unknown = selected - {c["key"] for c in changes}
    if unknown:
        raise ApplyError(f"Unbekannte Änderung(en): {', '.join(sorted(unknown))}")
    labels = {c["key"]: c["label"] for c in changes}
    for c in changes:
        missing = [r for r in c.get("requires", []) if c["key"] in selected and r not in selected]
        if missing:
            raise ApplyError(f"'{c['label']}' setzt '{', '.join(labels.get(r, r) for r in missing)}' voraus – "
                             "bitte mit auswählen.")


def selected_steps(ctx: Context, payload: dict) -> tuple[list[dict], list[str], list[str]]:
    """Schritte der ausgewählten Änderungen. Rückgabe: (Schritte, übernommene, übersprungene Labels).

    Eine Änderung wird übersprungen, wenn ihr Feld in Netbox seit dem Vorschlag geändert wurde –
    dann gewinnt die Handarbeit. Änderungen, die eine übersprungene voraussetzen, entfallen mit.
    """
    from doku_agent.netbox_plan import field_value

    changes = payload["changes"]
    selected = set(payload.get("selected") or [c["key"] for c in changes])
    validate_selection(changes, selected)
    objects: dict[tuple[str, int], dict] = {}
    dropped: set[str] = set()
    skipped: list[str] = []
    for c in changes:
        if c["key"] not in selected:
            continue
        check = c.get("check")
        if check:
            key = (check["endpoint"], check["id"])
            if key not in objects:
                objects[key] = ctx.netbox.get(*key)
            current = field_value(objects[key], check["field"])
            if current != check["value"]:
                dropped.add(c["key"])
                skipped.append(f"{c['label']}: in Netbox inzwischen geändert – übersprungen")
                continue
        if any(r in dropped for r in c.get("requires", [])):
            dropped.add(c["key"])
            skipped.append(f"{c['label']}: Voraussetzung übersprungen – übersprungen")
    applied = [c for c in changes if c["key"] in selected and c["key"] not in dropped]
    steps = [step for c in applied for step in c["steps"]]
    return steps, [c["label"] for c in applied], skipped


def apply_netbox(ctx: Context, prop: Proposal) -> str:
    from doku_agent.netbox_plan import execute_plan

    payload = prop.payload
    if payload.get("changes"):
        steps, applied, skipped = selected_steps(ctx, payload)
        if not steps:
            raise ApplyError("Nichts übernommen: " + "; ".join(skipped))
    else:
        steps, applied, skipped = payload["steps"], [], []
    created = execute_plan(ctx.netbox, steps, ctx.log)
    if payload.get("changes"):
        lines = [f"Übernommen: {label}" for label in applied] + skipped
    else:
        lines = [f"{ref}: {endpoint} #{oid}" for ref, (endpoint, oid) in created.items()]
    followup = payload.get("followup") or {}
    oid = followup.get("id") or (created[followup["ref"]][1] if followup.get("ref") in created else None)
    if oid:
        jid = ctx.store.enqueue("netbox_device", {"kind": followup.get("kind", "device"), "id": oid})
        lines.append(f"Wiki-Dokumentation als Job #{jid} eingeplant.")
    ctx.store.update_proposal(prop.id, status="applied", result="\n".join(lines) or "Nichts zu tun.")
    return "applied"


def apply_proposal(ctx: Context, pid: int) -> str:
    """Führt einen offenen Vorschlag aus. Rückgabe: 'applied' oder Hinweis auf Neuberechnung."""
    prop = ctx.store.get_proposal(pid)
    if prop is None:
        raise ApplyError(f"Vorschlag {pid} nicht gefunden")
    if prop.status != "pending":
        raise ApplyError(f"Vorschlag {pid} ist nicht offen (Status: {prop.status})")
    try:
        if prop.kind == "wiki_page":
            return apply_wiki(ctx, prop)
        if prop.kind == "netbox_plan":
            return apply_netbox(ctx, prop)
        raise ApplyError(f"Unbekannter Vorschlagstyp {prop.kind}")
    except Exception as exc:
        ctx.store.update_proposal(pid, status="failed", result=f"Fehler: {exc}")
        raise


def reject_proposal(ctx: Context, pid: int, ignore: bool = False) -> None:
    prop = ctx.store.get_proposal(pid)
    if prop is None:
        raise ApplyError(f"Vorschlag {pid} nicht gefunden")
    ctx.store.update_proposal(pid, status="rejected", result="Abgelehnt" + (" und dauerhaft ignoriert" if ignore else ""))
    if ignore and prop.dedup_key:
        ctx.store.ignore(prop.dedup_key, f"Vorschlag #{pid} abgelehnt: {prop.title}")
