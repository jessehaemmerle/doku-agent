"""Intune: Compliance-Richtlinien, Konfigurationsprofile, Settings Catalog, Apps und Entra-Gruppen dokumentieren."""

from __future__ import annotations

import json

from doku_agent import markdown
from doku_agent.connectors.intune import IntuneError
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
CATEGORY_LABELS = {"compliance": "Compliance-Richtlinie", "konfigurationsprofile": "Konfigurationsprofil",
                   "settings-catalog": "Settings Catalog", "apps": "App"}
# Zuweisungen je Ziel für die Übersichtsseite: "group:<ID>" bzw. "all:<Alle Benutzer|Alle Geräte>" -> Einträge
Usage = dict[str, list[dict]]


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


def group_kind(group: dict) -> str:
    """Art der Mitgliedschaft: dynamisch (Regel) oder zugewiesen; Microsoft-365-Gruppen gekennzeichnet."""
    if "groupTypes" not in group:
        return "–"  # ohne Group.Read.All unbekannt
    kind = "dynamisch" if "DynamicMembership" in (group.get("groupTypes") or []) else "zugewiesen"
    return kind + (", Microsoft 365" if "Unified" in (group.get("groupTypes") or []) else "")


def _filter(target: dict) -> str:
    filt = target.get("deviceAndAppManagementAssignmentFilterType") or ""
    return "" if filt in ("", "none") else filt


def assignments_table(ctx: Context, assignments: list[dict]) -> str:
    rows = []
    for a in assignments:
        target = a.get("target") or {}
        kind = TARGETS.get(target.get("@odata.type", ""), odata_type(target))
        group = ctx.intune.group(target["groupId"]) if target.get("groupId") else {}
        rows.append([kind, group.get("displayName", ""), group_kind(group) if group else "", a.get("intent", ""),
                     _filter(target)])
    if not rows:
        return "_Nicht zugewiesen._"
    text = markdown.table(["Ziel", "Gruppe", "Mitgliedschaft", "Absicht", "Filter"], rows)
    if "groups" in ctx.cfg.intune.include and any(r[1] for r in rows):
        overview = ctx.cfg.wiki.paths.get("intune_groups", "")
        text += (f"\n\nMitgliederzahlen und alle Zuweisungen je Gruppe: "
                 f"[Intune: Gruppen und Zuweisungen](/{overview.strip('/')})")
    return text


def record_usage(usage: Usage | None, category: str, name: str, assignments: list[dict]) -> None:
    if usage is None:
        return
    for a in assignments:
        target = a.get("target") or {}
        odata = target.get("@odata.type", "")
        key = f"group:{target['groupId']}" if target.get("groupId") else "all:" + TARGETS.get(odata, odata_type(target))
        usage.setdefault(key, []).append({
            "kind": CATEGORY_LABELS.get(category, category), "name": name, "intent": a.get("intent", ""),
            "effect": "ausgeschlossen" if odata.endswith("exclusionGroupAssignmentTarget") else "einbezogen",
            "filter": _filter(target),
        })


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


def _policy_page(ctx: Context, policy: dict, category: str, rows: list[tuple[str, str]], kind: str,
                 usage: Usage | None = None) -> int | None:
    name = policy.get("displayName") or policy.get("name") or policy["id"]
    record_usage(usage, category, name, policy.get("_assignments", []))
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
        stable_id=f"intune:{category}:{policy['id']}", sync_title=True,
    ))


def document_policy(ctx: Context, category: str, policy: dict, usage: Usage | None = None) -> int | None:
    if category == "settings-catalog":
        rows = settings_catalog_rows(policy.get("_settings", []))
        return _policy_page(ctx, policy, category, rows, f"Settings Catalog ({policy.get('technologies', '')})", usage)
    return _policy_page(ctx, policy, category, flatten(policy), odata_type(policy), usage)


AREA_LABELS = {"compliance": "Compliance-Richtlinien", "configurations": "Konfigurationsprofile",
               "settings_catalog": "Settings Catalog", "apps": "Apps", "groups": "Gruppen-Übersicht"}


def document_intune(ctx: Context) -> list[int | None]:
    """Alle Bereiche aus intune.include. Ist ein Bereich nicht lesbar (z.B. fehlende Berechtigung), werden die
    übrigen trotzdem dokumentiert; der Job meldet am Ende einen Fehler."""
    include = set(ctx.cfg.intune.include)
    intune = ctx.intune
    usage: Usage = {}
    results, failed = [], []

    def area(key: str, run) -> None:
        if key not in include:
            return
        try:
            run()
        except IntuneError as exc:
            ctx.log.error("%s übersprungen: %s", AREA_LABELS[key], exc)
            failed.append(key)

    def policies(category: str, fetch):
        return lambda: results.extend(document_policy(ctx, category, pol, usage) for pol in fetch())

    area("compliance", policies("compliance", intune.compliance_policies))
    area("configurations", policies("konfigurationsprofile", intune.device_configurations))
    area("settings_catalog", policies("settings-catalog", intune.settings_catalog_policies))
    area("apps", lambda: results.append(document_apps(ctx, usage)))
    if "groups" in include and failed:
        # ohne die Zuweisungen der fehlenden Bereiche wäre die Übersicht falsch
        ctx.log.warning("Gruppen-Übersicht übersprungen: Zuweisungen aus %s fehlen.",
                        ", ".join(AREA_LABELS[k] for k in failed))
    else:
        area("groups", lambda: results.append(document_groups(ctx, usage)))
    if failed:
        raise RuntimeError(f"Intune unvollständig – nicht lesbar: {', '.join(AREA_LABELS[k] for k in failed)}. "
                           f"Die übrigen Bereiche wurden dokumentiert; Ursache siehe Meldungen oben.")
    return results


def collect_usage(ctx: Context) -> Usage:
    """Zuweisungen ohne Einstellungen lesen (für die Gruppen-Übersicht allein, z.B. aus dem Wiki-Lint) –
    aus denselben Kategorien wie der Intune-Lauf, damit beide dieselbe Seite erzeugen."""
    usage: Usage = {}
    intune = ctx.intune
    include = set(ctx.cfg.intune.include)
    sources = (("compliance", "compliance", intune.compliance_policies),
               ("configurations", "konfigurationsprofile", intune.device_configurations),
               ("settings_catalog", "settings-catalog", lambda: intune.settings_catalog_policies(with_settings=False)),
               ("apps", "apps", intune.mobile_apps))
    for key, category, fetch in sources:
        if key not in include:
            continue
        for pol in fetch():
            record_usage(usage, category, pol.get("displayName") or pol.get("name") or pol["id"],
                         pol.get("_assignments", []))
    return usage


def _count(value: int | None) -> str:
    return "–" if value is None else str(value)


def document_groups(ctx: Context, usage: Usage | None = None) -> int | None:
    """Übersichtsseite: jede zugewiesene Gruppe mit Art, dynamischer Regel, Mitgliederzahlen und Zuweisungen.
    Die Zahlen stehen nur hier, damit sich bei neuen Mitgliedern nicht jede Richtlinien-Seite ändert."""
    usage = collect_usage(ctx) if usage is None else usage
    intune = ctx.intune
    entries = []
    for key, items in usage.items():
        kind, _, ident = key.partition(":")
        if kind == "group":
            entries.append((intune.group(ident), intune.member_counts(ident), items))
        else:
            entries.append(({"displayName": ident}, None, items))
    entries.sort(key=lambda e: (e[1] is not None, (e[0].get("displayName") or "").lower()))
    rows, sections = [], []
    for group, counts, items in entries:
        name = group.get("displayName") or group.get("id", "")
        rule = group.get("membershipRule") or ""
        if counts is None:  # "Alle Benutzer" / "Alle Geräte"
            rows.append([name, "alle", "", "", "", "", len(items)])
        else:
            rows.append([name, group_kind(group), f"`{rule}`" if rule else "", _count(counts.get("user")),
                         _count(counts.get("device")), _count(counts.get("group")), len(items)])
        lines = sorted(items, key=lambda i: (i["kind"], i["name"].lower()))
        sections.append(f"### {name}\n\n" + markdown.table(
            ["Typ", "Richtlinie / App", "Absicht", "Wirkung", "Filter"],
            [[i["kind"], i["name"], i["intent"], i["effect"], i["filter"]] for i in lines]))
    table = markdown.table(["Gruppe", "Mitgliedschaft", "Dynamische Regel", "Benutzer", "Geräte", "Untergruppen",
                            "Zuweisungen"], rows) if rows else "_Keine Zuweisungen._"
    return propose_page(ctx, PageDraft(
        doc_type="intune_groups", title="Intune: Gruppen und Zuweisungen",
        description="Entra-Gruppen mit Mitgliederzahlen und allen Intune-Zuweisungen",
        blocks=[Block("intune-groups-table", "Gruppen",
                      "Mitglieder inklusive verschachtelter Gruppen.\n\n" + table),
                Block("intune-groups-assignments", "Zuweisungen je Gruppe", "\n\n".join(sections) or "_Keine._")],
        intro="Welche Entra-Gruppen in Intune verwendet werden, wie viele Mitglieder sie haben und was ihnen "
              "zugewiesen ist. Automatisch über Microsoft Graph (nur lesend) aktualisiert.",
        source="intune:groups", stable_id="intune:groups",
    ))


def document_apps(ctx: Context, usage: Usage | None = None) -> int | None:
    apps = ctx.intune.mobile_apps()
    rows = []
    for app in sorted(apps, key=lambda a: (a.get("displayName") or "").lower()):
        record_usage(usage, "apps", app.get("displayName") or app["id"], app.get("_assignments", []))
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
        source="intune:apps", stable_id="intune:apps",
    ))
