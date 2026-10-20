"""Netbox-Änderungen als nachvollziehbarer, prüfbarer Schritt-Plan.

Ein Plan ist eine Liste von Schritten, die in der Freigabe-Liste angezeigt und bei
Bedarf bearbeitet werden kann. Erlaubt sind nur Anlegen ("create"), Anlegen falls
nicht vorhanden ("ensure") und Ändern ("update") auf einer festen Endpunkt-Liste.
Schlägt ein Schritt fehl, werden die in diesem Lauf angelegten Objekte wieder gelöscht.

Beispiel:
  {"ref": "mfr", "action": "ensure", "endpoint": "dcim/manufacturers",
   "lookup": {"slug": "dell"}, "data": {"name": "Dell", "slug": "dell"}}
  {"ref": "dev", "action": "create", "endpoint": "dcim/devices", "data": {"name": "srv01", ...}}
  {"action": "update", "endpoint": "dcim/devices", "id": "$dev", "data": {"primary_ip4": "$ip0"}}
"""

from __future__ import annotations

import logging

from doku_agent.connectors.netbox import NetboxClient, NetboxError

ALLOWED_ENDPOINTS = {
    "dcim/manufacturers", "dcim/device-types", "dcim/device-roles", "dcim/platforms", "dcim/devices",
    "dcim/interfaces", "dcim/mac-addresses", "ipam/ip-addresses",
    "virtualization/virtual-machines", "virtualization/interfaces", "virtualization/virtual-disks",
    "virtualization/clusters", "virtualization/cluster-types",
    "ipam/vlans", "ipam/prefixes", "dcim/cables",
    "extras/custom-fields",  # nur für das einmalige Anlegen der Agent-Felder
}
ACTIONS = {"create", "ensure", "update"}


class PlanError(ValueError):
    pass


def _refs_in(value) -> set[str]:
    if isinstance(value, str) and value.startswith("$"):
        return {value[1:]}
    if isinstance(value, dict):
        return set().union(*(_refs_in(v) for v in value.values())) if value else set()
    if isinstance(value, list):
        return set().union(*(_refs_in(v) for v in value)) if value else set()
    return set()


def validate_plan(steps: list[dict]) -> None:
    if not isinstance(steps, list) or not steps:
        raise PlanError("Plan muss eine nicht-leere Liste von Schritten sein")
    defined: set[str] = set()
    for idx, step in enumerate(steps, 1):
        if not isinstance(step, dict):
            raise PlanError(f"Schritt {idx}: muss ein Objekt sein")
        action, endpoint = step.get("action"), str(step.get("endpoint", "")).strip("/")
        if action not in ACTIONS:
            raise PlanError(f"Schritt {idx}: Aktion {action!r} nicht erlaubt (erlaubt: {sorted(ACTIONS)})")
        if endpoint not in ALLOWED_ENDPOINTS:
            raise PlanError(f"Schritt {idx}: Endpunkt {endpoint!r} nicht erlaubt")
        if not isinstance(step.get("data", {}), dict):
            raise PlanError(f"Schritt {idx}: 'data' muss ein Objekt sein")
        if action == "ensure" and not step.get("lookup"):
            raise PlanError(f"Schritt {idx}: 'ensure' braucht ein 'lookup'")
        if action == "update" and step.get("id") in (None, ""):
            raise PlanError(f"Schritt {idx}: 'update' braucht eine 'id'")
        used = _refs_in(step.get("data", {})) | _refs_in(step.get("lookup", {})) | _refs_in(step.get("id"))
        missing = used - defined
        if missing:
            raise PlanError(f"Schritt {idx}: Referenz(en) {sorted(missing)} vor Definition verwendet")
        ref = step.get("ref")
        if ref:
            if ref in defined:
                raise PlanError(f"Schritt {idx}: Referenz {ref!r} doppelt vergeben")
            defined.add(ref)


def _resolve(value, ids: dict[str, int]):
    if isinstance(value, str) and value.startswith("$") and value[1:] in ids:
        return ids[value[1:]]
    if isinstance(value, dict):
        return {k: _resolve(v, ids) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve(v, ids) for v in value]
    return value


def comparable(value):
    """Netbox-Feldwert so, wie man ihn zurückschreiben kann: verschachtelte Objekte über id bzw. value."""
    if isinstance(value, dict):
        return value.get("id", value.get("value"))
    return value


def field_value(obj: dict, name: str):
    """Feldwert inkl. Custom Fields: "custom_fields.last_seen" liest obj["custom_fields"]["last_seen"]."""
    if name.startswith("custom_fields."):
        return comparable((obj.get("custom_fields") or {}).get(name.split(".", 1)[1]))
    return comparable(obj.get(name))


def _snapshot(before: dict, data: dict) -> dict:
    """Bisherige Werte der Felder, die ein Update ändert. Custom Fields einzeln, denn Netbox
    führt ein PATCH von custom_fields mit den bestehenden Werten zusammen."""
    old = {}
    for key, value in data.items():
        if key == "custom_fields" and isinstance(value, dict):
            current = before.get("custom_fields") or {}
            old[key] = {name: comparable(current.get(name)) for name in value}
        else:
            old[key] = comparable(before.get(key))
    return old


def execute_plan(nb: NetboxClient, steps: list[dict], log: logging.Logger) -> dict[str, tuple[str, int]]:
    """Führt den Plan aus. Bei einem Fehler wird alles rückgängig gemacht: angelegte Objekte werden
    gelöscht, geänderte Felder bestehender Objekte auf den vorherigen Wert zurückgesetzt."""
    validate_plan(steps)
    ids: dict[str, int] = {}
    refs: dict[str, tuple[str, int]] = {}
    undo: list[tuple[str, str, int, dict | None]] = []  # ("delete"|"restore", Endpunkt, ID, alte Werte)
    created: set[tuple[str, int]] = set()
    try:
        for idx, step in enumerate(steps, 1):
            endpoint = step["endpoint"].strip("/")
            data = _resolve(step.get("data", {}), ids)
            if step["action"] == "ensure":
                found = nb.find_one(endpoint, **_resolve(step["lookup"], ids))
                if found:
                    oid = found["id"]
                    log.info("Schritt %s: %s existiert bereits (#%s)", idx, endpoint, oid)
                else:
                    oid = nb.create(endpoint, data)["id"]
                    undo.append(("delete", endpoint, oid, None))
                    created.add((endpoint, oid))
                    log.info("Schritt %s: %s angelegt (#%s)", idx, endpoint, oid)
            elif step["action"] == "create":
                oid = nb.create(endpoint, data)["id"]
                undo.append(("delete", endpoint, oid, None))
                created.add((endpoint, oid))
                log.info("Schritt %s: %s angelegt (#%s)", idx, endpoint, oid)
            else:
                oid = int(_resolve(step["id"], ids))
                if (endpoint, oid) not in created:  # in diesem Lauf angelegte Objekte werden ohnehin gelöscht
                    before = nb.get(endpoint, oid)
                    undo.append(("restore", endpoint, oid, _snapshot(before, data)))
                nb.update(endpoint, oid, data)
                log.info("Schritt %s: %s #%s aktualisiert", idx, endpoint, oid)
            if step.get("ref"):
                ids[step["ref"]] = oid
                refs[step["ref"]] = (endpoint, oid)
    except Exception as exc:
        notes = []
        for kind, endpoint, oid, old in reversed(undo):
            try:
                if kind == "delete":
                    nb.delete(endpoint, oid)
                    notes.append(f"{endpoint} #{oid} entfernt")
                else:
                    nb.update(endpoint, oid, old)
                    notes.append(f"{endpoint} #{oid} zurückgesetzt")
            except Exception as undo_exc:  # Rollback darf nicht abbrechen
                notes.append(f"{endpoint} #{oid} NICHT rückgängig gemacht ({undo_exc})")
        summary = "; ".join(notes) or "nichts zu tun"
        log.error("Plan fehlgeschlagen: %s; Rollback: %s", exc, summary)
        raise NetboxError(f"{exc} | Rollback: {summary}") from exc
    return refs
