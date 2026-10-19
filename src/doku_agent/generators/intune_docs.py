"""Intune: Compliance-Richtlinien, Konfigurationsprofile, Settings Catalog und Apps dokumentieren."""

from __future__ import annotations

import json

from doku_agent import markdown
from doku_agent.context import Context
from doku_agent.generators.common import STYLE_RULES, cached, digest, mask_value
from doku_agent.pages import Block, PageDraft, propose_page

SKIP_KEYS = {"id", "displayName", "description", "createdDateTime", "lastModifiedDateTime", "version",
             "roleScopeTagIds", "_assignments", "_settings", "supportsScopeTags", "deviceManagementApplicabilityRuleOsEdition",
             "deviceManagementApplicabilityRuleOsVersion", "deviceManagementApplicabilityRuleDeviceMode",
             "largeIcon", "settingCount", "creationSource", "templateReference", "priorityMetaData"}

TARGETS = {
    "#microsoft.graph.allDevicesAssignmentTarget": "Alle Geräte",
    "#microsoft.graph.allLicensedUsersAssignmentTarget": "Alle Benutzer",
    "#microsoft.graph.groupAssignmentTarget": "Gruppe",
    "#microsoft.graph.exclusionGroupAssignmentTarget": "Ausgeschlossen",
}


def odata_type(obj: dict) -> str:
    return (obj.get("@odata.type") or "").replace("#microsoft.graph.", "")


def flatten(obj, prefix: str = "") -> list[tuple[str, str]]:
    rows = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            # OData-Metadaten weglassen, nur den Objekttyp (@odata.type) behalten
            odata_meta = (key.startswith("@odata") and key != "@odata.type") or ("@odata" in key and key[0] != "@")
            if key in SKIP_KEYS or odata_meta:
                continue
            rows += flatten(value, f"{prefix}{key}." if isinstance(value, dict) else f"{prefix}{key}")
    elif isinstance(obj, list):
        if not obj:
            return rows
        if all(not isinstance(v, (dict, list)) for v in obj):
            rows.append((prefix.rstrip("."), ", ".join(str(v) for v in obj)))
        else:
            rows.append((prefix.rstrip("."), json.dumps(obj, ensure_ascii=False)[:800]))
    elif obj not in (None, ""):
        rows.append((prefix.rstrip("."), str(obj)))
    return rows


def assignments_table(ctx: Context, assignments: list[dict]) -> str:
    rows = []
    for a in assignments:
        target = a.get("target") or {}
        kind = TARGETS.get(target.get("@odata.type", ""), odata_type(target))
        group = ctx.intune.group_name(target.get("groupId", "")) if target.get("groupId") else ""
        filt = target.get("deviceAndAppManagementAssignmentFilterType") or ""
        rows.append([kind, group, a.get("intent", ""), "" if filt in ("", "none") else filt])
    if not rows:
        return "_Nicht zugewiesen._"
    return markdown.table(["Ziel", "Gruppe", "Absicht", "Filter"], rows)


def settings_catalog_rows(settings: list[dict]) -> list[tuple[str, str]]:
    """Settings-Catalog-Instanzen rekursiv in lesbare Zeilen (Anzeigename -> Wert) umwandeln."""
    names: dict[str, str] = {}
    for setting in settings:
        for definition in setting.get("settingDefinitions") or []:
            names[definition.get("id", "")] = definition.get("displayName") or definition.get("id", "")
            for opt in definition.get("options") or []:
                names[opt.get("itemId", "")] = opt.get("displayName") or opt.get("itemId", "")
    rows: list[tuple[str, str]] = []

    def label(def_id: str) -> str:
        return names.get(def_id, def_id)

    def walk(instance: dict, depth: int = 0):
        def_id = instance.get("settingDefinitionId", "")
        indent = "↳ " * depth
        if "choiceSettingValue" in instance:
            val = instance["choiceSettingValue"] or {}
            rows.append((indent + label(def_id), label(val.get("value", ""))))
            for child in val.get("children") or []:
                walk(child, depth + 1)
        elif "simpleSettingValue" in instance:
            rows.append((indent + label(def_id), str((instance["simpleSettingValue"] or {}).get("value", ""))))
        elif "choiceSettingCollectionValue" in instance:
            vals = instance["choiceSettingCollectionValue"] or []
            rows.append((indent + label(def_id), ", ".join(label(v.get("value", "")) for v in vals)))
            for v in vals:
                for child in v.get("children") or []:
                    walk(child, depth + 1)
        elif "simpleSettingCollectionValue" in instance:
            vals = instance["simpleSettingCollectionValue"] or []
            rows.append((indent + label(def_id), ", ".join(str(v.get("value", "")) for v in vals)))
        elif "groupSettingCollectionValue" in instance or "groupSettingValue" in instance:
            groups = instance.get("groupSettingCollectionValue") or [instance.get("groupSettingValue") or {}]
            rows.append((indent + label(def_id), f"{len(groups)} Eintrag/Einträge"))
            for g in groups:
                for child in g.get("children") or []:
                    walk(child, depth + 1)
        else:
            rows.append((indent + label(def_id), "(nicht darstellbar)"))

    for setting in settings:
        walk(setting.get("settingInstance") or {})
    return rows


def _describe(ctx: Context, name: str, kind: str, rows: list[tuple[str, str]]) -> str:
    settings_text = "\n".join(f"- {k}: {v}" for k, v in rows[:150])

    def ask():
        return ctx.llm.text(
            "Du bist Microsoft-Intune-Experte und dokumentierst Richtlinien für das IT-Team. " + STYLE_RULES,
            f"Richtlinie '{name}' ({kind}). Beschreibe in 3-6 Sätzen den Zweck und die wichtigsten Auswirkungen "
            f"auf Geräte und Benutzer. Nenne nur, was aus den Einstellungen hervorgeht.\n\n"
            f"Einstellungen:\n{ctx.llm.fit(settings_text)}",
        )

    return cached(ctx, "intune:" + digest(name, kind, rows), ask)


def _policy_page(ctx: Context, policy: dict, category: str, rows: list[tuple[str, str]], kind: str) -> int | None:
    name = policy.get("displayName") or policy.get("name") or policy["id"]
    rows = [(k, str(mask_value(k, v))) for k, v in rows]
    description = _describe(ctx, name, kind, rows) if rows else "_Keine Einstellungen gesetzt._"
    if policy.get("description"):
        description = f"> {policy['description']}\n\n{description}"
    basics = markdown.table(["Eigenschaft", "Wert"], [
        ["Name", name], ["Typ", kind], ["Plattform", policy.get("platforms", "")],
        ["Erstellt", policy.get("createdDateTime", "")], ["Geändert", policy.get("lastModifiedDateTime", "")],
        ["Intune-ID", policy["id"]],
    ])
    settings = markdown.table(["Einstellung", "Wert"], [list(r) for r in rows]) if rows else "_Keine._"
    return propose_page(ctx, PageDraft(
        doc_type="intune_policy", title=f"Intune: {name}", description=f"Intune-{category}: {name}",
        blocks=[Block("intune-description", "Beschreibung", description),
                Block("intune-basics", "Grunddaten", basics),
                Block("intune-assignments", "Zuweisungen", assignments_table(ctx, policy.get("_assignments", []))),
                Block("intune-settings", "Einstellungen", settings)],
        path_vars={"category": category, "name": name},
        intro=f"Dokumentation der Intune-Richtlinie **{name}**. Die markierten Abschnitte werden automatisch "
              f"über Microsoft Graph (nur lesend) aktualisiert.",
        source=f"intune:{category}:{policy['id']}", lookup_name=None,
    ))


def document_intune(ctx: Context) -> list[int | None]:
    include = set(ctx.cfg.intune.include)
    intune = ctx.intune
    results = []
    if "compliance" in include:
        for pol in intune.compliance_policies():
            results.append(_policy_page(ctx, pol, "compliance", flatten(pol), odata_type(pol)))
    if "configurations" in include:
        for pol in intune.device_configurations():
            results.append(_policy_page(ctx, pol, "konfigurationsprofile", flatten(pol), odata_type(pol)))
    if "settings_catalog" in include:
        for pol in intune.settings_catalog_policies():
            rows = settings_catalog_rows(pol.get("_settings", []))
            kind = f"Settings Catalog ({pol.get('technologies', '')})"
            results.append(_policy_page(ctx, pol, "settings-catalog", rows, kind))
    if "apps" in include:
        results.append(document_apps(ctx))
    return results


def document_apps(ctx: Context) -> int | None:
    apps = ctx.intune.mobile_apps()
    rows = []
    for app in sorted(apps, key=lambda a: (a.get("displayName") or "").lower()):
        targets = []
        for a in app.get("_assignments", []):
            target = a.get("target") or {}
            who = TARGETS.get(target.get("@odata.type", ""), odata_type(target))
            if target.get("groupId"):
                who += f" {ctx.intune.group_name(target['groupId'])}"
            targets.append(f"{a.get('intent', '')}: {who}".strip(": "))
        rows.append([app.get("displayName"), odata_type(app), app.get("publisher"), "<br>".join(targets) or "–"])
    return propose_page(ctx, PageDraft(
        doc_type="intune_apps", title="Intune: Apps", description="Übersicht der in Intune verwalteten Apps",
        blocks=[Block("intune-apps", "Apps", markdown.table(["App", "Typ", "Herausgeber", "Zuweisungen"], rows)
                      if rows else "_Keine Apps._")],
        intro="Übersicht aller in Intune verwalteten Apps mit ihren Zuweisungen (automatisch aktualisiert).",
        source="intune:apps",
    ))
