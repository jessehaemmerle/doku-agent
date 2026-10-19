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
        ctx.store.update_proposal(prop.id, status="applied",
                                  result=f"Seite angelegt (ID {page_id}): {wiki.page_url(payload['path'])}")
        return "applied"

    page = wiki.get_page(int(payload["page_id"]))
    if sha(page.content) != payload.get("base_hash"):
        if payload.get("edited"):
            raise ApplyError("Die Seite wurde nach dem Vorschlag im Wiki geändert und der Vorschlag manuell "
                             "bearbeitet – bitte Vorschlag verwerfen und neu erzeugen.")
        new, _ = merge_into(page.content, _blocks(payload), payload.get("ops", []))
        payload["base_hash"] = sha(page.content)
        return _requeue(ctx, prop, payload, page.content, new,
                        "Seite wurde zwischenzeitlich geändert – Vorschlag neu berechnet, bitte erneut prüfen.")
    wiki.update_page(page, content=payload["content"], description=payload.get("description"),
                     tags=payload.get("tags"), title=payload.get("title"))
    ctx.store.update_proposal(prop.id, status="applied", result=f"Seite aktualisiert: {wiki.page_url(page.path)}")
    return "applied"


def apply_netbox(ctx: Context, prop: Proposal) -> str:
    from doku_agent.netbox_plan import execute_plan

    created = execute_plan(ctx.netbox, prop.payload["steps"], ctx.log)
    lines = [f"{ref}: {endpoint} #{oid}" for ref, (endpoint, oid) in created.items()]
    followup = prop.payload.get("followup")
    if followup and followup.get("ref") in created:
        _, oid = created[followup["ref"]]
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
