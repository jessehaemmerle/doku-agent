"""Netbox-Custom-Fields des Agents: feste Zuordnung zu Wazuh und Intune und "zuletzt gesehen".

- wazuh_agent_id / intune_device_id: Maschinen werden zuerst über diese IDs wiedererkannt,
  erst danach über Seriennummer, Hostname und MAC. Setzen/Ändern läuft über die Freigabe.
- last_seen: letzter Kontakt laut Wazuh bzw. Intune. Ändert sich bei jeder aktiven Maschine
  täglich und wird deshalb als einzige Angabe ohne Freigabe gepflegt.
Fehlen die Felder in Netbox, schlägt die Discovery einmalig vor, sie anzulegen.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from doku_agent import markdown
from doku_agent.config import NetboxCustomFields
from doku_agent.connectors.netbox import NetboxClient, NetboxError
from doku_agent.netbox_plan import comparable

DEVICE, VM = "dcim/devices", "virtualization/virtual-machines"
OBJECT_TYPES = {DEVICE: "dcim.device", VM: "virtualization.virtualmachine"}
# Schlüssel in NetboxCustomFields -> (Typ, Bezeichnung, Beschreibung)
SPECS = {
    "wazuh_agent_id": ("text", "Wazuh-Agent-ID", "ID des Wazuh-Agents (gepflegt von doku-agent)"),
    "intune_device_id": ("text", "Intune-Geräte-ID", "ID des verwalteten Geräts in Intune (gepflegt von doku-agent)"),
    "last_seen": ("date", "Zuletzt gesehen", "Letzter Kontakt laut Wazuh/Intune (automatisch von doku-agent)"),
}
SETUP_KEY = "netbox-cf-setup"


@dataclass
class FieldStatus:
    readable: bool = True  # False: Custom Fields in Netbox nicht lesbar (Rechte) – Funktion ruht
    available: dict[str, set[str]] = field(default_factory=lambda: {DEVICE: set(), VM: set()})
    steps: list[dict] = field(default_factory=list)  # Schritte zum Anlegen/Ergänzen
    rows: list[list] = field(default_factory=list)  # Übersicht für den Vorschlag
    hints: list[str] = field(default_factory=list)


def field_names(cf: NetboxCustomFields) -> dict[str, str]:
    return {key: getattr(cf, key) for key in SPECS}


def status(nb: NetboxClient, cf: NetboxCustomFields) -> FieldStatus:
    """Welche Felder für Geräte bzw. VMs nutzbar sind und was zum Anlegen fehlt."""
    result = FieldStatus()
    if not cf.enabled:
        return result
    try:
        existing = {f.get("name"): f for f in nb.list("extras/custom-fields")}
    except NetboxError as exc:
        result.readable = False
        result.hints.append(f"Custom Fields in Netbox nicht lesbar ({exc}) – Abgleich ohne feste IDs. "
                            "Der Agent-Benutzer braucht Leserecht auf 'Custom Fields'.")
        return result
    for key, name in field_names(cf).items():
        ftype, label, description = SPECS[key]
        current = existing.get(name)
        if current is None:
            result.steps.append({"ref": f"cf_{key}", "action": "ensure", "endpoint": "extras/custom-fields",
                                 "lookup": {"name": name},
                                 "data": {"name": name, "label": label, "type": ftype, "description": description,
                                          "object_types": sorted(OBJECT_TYPES.values()), "group_name": "doku-agent",
                                          "required": False, "filter_logic": "exact"},
                                 "note": f"Custom Field '{name}' anlegen"})
            result.rows.append([name, ftype, label, "Geräte, VMs", "neu"])
            continue
        if comparable(current.get("type")) != ftype:
            result.hints.append(f"Custom Field '{name}' hat in Netbox den Typ '{comparable(current.get('type'))}' "
                                f"statt '{ftype}' und wird nicht verwendet.")
            continue
        if (comparable(current.get("status")) or "active") != "active":
            result.hints.append(f"Custom Field '{name}' wird in Netbox noch eingerichtet – ab dem nächsten Lauf nutzbar.")
            continue
        types = set(current.get("object_types") or [])
        for endpoint, otype in OBJECT_TYPES.items():
            if otype in types:
                result.available[endpoint].add(name)
        missing = set(OBJECT_TYPES.values()) - types
        if missing:
            result.steps.append({"action": "update", "endpoint": "extras/custom-fields", "id": current["id"],
                                 "data": {"object_types": sorted(types | missing)},
                                 "note": f"Custom Field '{name}' auch für {', '.join(sorted(missing))}"})
            result.rows.append([name, ftype, current.get("label") or label, ", ".join(sorted(missing)), "ergänzen"])
    return result


def propose_setup(ctx, fs: FieldStatus) -> int | None:
    if not fs.steps or ctx.store.is_ignored(SETUP_KEY):
        return None
    summary = ("Custom Fields für die feste Zuordnung zu Wazuh/Intune und 'zuletzt gesehen'.\n\n"
               + markdown.table(["Feld", "Typ", "Bezeichnung", "Für", "Aktion"], fs.rows))
    hints = [*fs.hints, "Der Netbox-Benutzer des Agents braucht dafür einmalig das Recht, Custom Fields "
                        "anzulegen bzw. zu ändern.",
             "Nach dem Übernehmen nutzt die nächste Discovery die Felder: Wiedererkennung über die IDs, "
             "'zuletzt gesehen' wird ohne Freigabe gepflegt."]
    return ctx.store.add_proposal("netbox_plan", "Netbox: Custom Fields für doku-agent anlegen",
                                  {"steps": fs.steps, "hints": hints}, summary=summary, source="discovery",
                                  dedup_key=SETUP_KEY)


def _parse(value) -> datetime | None:
    try:
        dt = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if not 2000 <= dt.year <= 2100:  # Wazuh meldet für den Manager selbst 9999-12-31, Intune 0001-01-01
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def last_seen(sources: dict[str, dict], tz: str) -> str | None:
    """Letzter Kontakt (Datum in der lokalen Zeitzone) über alle Quellen."""
    stamps = [_parse((sources.get("wazuh") or {}).get("last_seen")),
              _parse((sources.get("intune") or {}).get("last_sync"))]
    stamps = [s for s in stamps if s]
    if not stamps:
        return None
    newest = min(max(stamps), datetime.now(timezone.utc))
    return newest.astimezone(ZoneInfo(tz)).date().isoformat()


def values_for(sources: dict[str, dict], cf: NetboxCustomFields, available: set[str], tz: str) -> dict:
    """Custom-Field-Werte für eine neu anzulegende Maschine."""
    values = {cf.wazuh_agent_id: (sources.get("wazuh") or {}).get("agent_id"),
              cf.intune_device_id: (sources.get("intune") or {}).get("id"),
              cf.last_seen: last_seen(sources, tz)}
    return {k: v for k, v in values.items() if v and k in available}
