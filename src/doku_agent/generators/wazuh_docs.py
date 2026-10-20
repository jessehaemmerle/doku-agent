"""Wazuh: eigene Regeln, Decoder, Manager-/Gruppen-Konfiguration und SCA-Ergebnisse dokumentieren."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from doku_agent import markdown
from doku_agent.context import Context
from doku_agent.generators.common import STYLE_RULES, cached, digest, mask_xml, parse_xml_fragment
from doku_agent.pages import Block, PageDraft, propose_page

RULE_BATCH = 6  # Regeln pro LLM-Aufruf (Kontextbudget eines 8B-Modells auf CPU)
CONDITION_TAGS = ("if_sid", "if_group", "if_matched_sid", "if_matched_group", "decoded_as", "category",
                  "program_name", "match", "regex", "field", "srcip", "dstip", "user", "hostname", "location",
                  "action", "status", "url", "id", "extra_data", "list")

EXPLAIN_SCHEMA = {
    "type": "object",
    "properties": {
        "zusammenfassung": {"type": "string"},
        "regeln": {"type": "array", "items": {
            "type": "object",
            "properties": {"id": {"type": "string"}, "erklaerung": {"type": "string"}},
            "required": ["id", "erklaerung"],
        }},
    },
    "required": ["zusammenfassung", "regeln"],
}


def _text(el: ET.Element) -> str:
    return " ".join("".join(el.itertext()).split())


def parse_rules(xml_text: str) -> tuple[list[dict], list[str]]:
    root = parse_xml_fragment(xml_text)
    rules, groups = [], []
    for group in root.iter("group"):
        if group.get("name"):
            groups.append(group.get("name"))
        for rule in group.findall("rule"):
            conditions = []
            for tag in CONDITION_TAGS:
                for el in rule.findall(tag):
                    label = f"{tag}[{el.get('name')}]" if el.get("name") else tag
                    neg = " (negiert)" if el.get("negate") == "yes" else ""
                    conditions.append(f"{label}: {_text(el)}{neg}")
            rules.append({
                "id": rule.get("id", ""),
                "level": rule.get("level", ""),
                "frequency": rule.get("frequency", ""),
                "timeframe": rule.get("timeframe", ""),
                "description": _text(rule.find("description")) if rule.find("description") is not None else "",
                "groups": ", ".join(filter(None, [*(group.get("name", "").strip(",").split(",")),
                                                  *(_text(g).strip(",") for g in rule.findall("group"))])),
                "conditions": conditions,
                "mitre": [_text(m) for m in rule.findall("mitre/id")],
                "options": [_text(o) for o in rule.findall("options")],
                "xml": ET.tostring(rule, encoding="unicode").strip(),
            })
    return rules, list(dict.fromkeys(groups))


def parse_decoders(xml_text: str) -> list[dict]:
    root = parse_xml_fragment(xml_text)
    out = []
    for dec in root.iter("decoder"):
        def first(tag):
            el = dec.find(tag)
            return _text(el) if el is not None else ""
        out.append({
            "name": dec.get("name", ""), "parent": first("parent"), "program_name": first("program_name"),
            "prematch": first("prematch"), "regex": first("regex"), "order": first("order"),
            "plugin": first("plugin_decoder"), "xml": ET.tostring(dec, encoding="unicode").strip(),
        })
    return out


def _explain_rules(ctx: Context, filename: str, rules: list[dict]) -> tuple[str, dict[str, str]]:
    explanations: dict[str, str] = {}
    summaries = []
    for i in range(0, len(rules), RULE_BATCH):
        batch = rules[i:i + RULE_BATCH]
        xml_block = "\n\n".join(r["xml"] for r in batch)

        def ask():
            return ctx.llm.json(
                "Du bist Wazuh-Experte und dokumentierst eigene Wazuh-Regeln. " + STYLE_RULES,
                f"Datei: {filename}\n\nErkläre für jede Regel in 2-4 Sätzen: wann sie auslöst, worauf sie "
                f"aufbaut (if_sid/if_group), was das Level bedeutet und welche Reaktion sinnvoll ist. "
                f"Fasse zusätzlich in 2-3 Sätzen zusammen, wofür diese Regeln insgesamt da sind.\n\n"
                f"{ctx.llm.fit(xml_block)}",
                EXPLAIN_SCHEMA,
            )

        result = cached(ctx, "wazuh-rules:" + digest(filename, xml_block), ask)
        summaries.append(result.get("zusammenfassung", "").strip())
        for item in result.get("regeln", []):
            explanations[str(item.get("id"))] = item.get("erklaerung", "").strip()
    return " ".join(s for s in summaries if s), explanations


def document_rule_file(ctx: Context, file_info: dict) -> int | None:
    filename = file_info["filename"]
    raw = ctx.wazuh.rule_file(filename)
    hints = []
    try:
        rules, groups = parse_rules(raw)
    except ET.ParseError as exc:
        rules, groups = [], []
        hints.append(f"XML konnte nicht geparst werden ({exc}) – nur Rohinhalt dokumentiert.")
    summary, explanations = _explain_rules(ctx, filename, rules) if rules else ("", {})
    ids = [int(r["id"]) for r in rules if r["id"].isdigit()]
    overview = markdown.table(["Eigenschaft", "Wert"], [
        ["Datei", f"{file_info.get('relative_dirname', ctx.cfg.wazuh.rules_dir)}/{filename}"],
        ["Status", file_info.get("status", "")],
        ["Anzahl Regeln", len(rules)],
        ["Regel-IDs", f"{min(ids)}–{max(ids)}" if ids else "–"],
        ["Gruppen", ", ".join(groups)],
    ])
    if summary:
        overview = f"{summary}\n\n{overview}"
    table = markdown.table(
        ["ID", "Level", "Beschreibung", "Gruppen", "Bedingungen", "MITRE"],
        [[r["id"], r["level"], r["description"], r["groups"], "<br>".join(r["conditions"]), ", ".join(r["mitre"])]
         for r in rules],
    ) if rules else "_Keine Regeln gefunden._"
    details = []
    for r in rules:
        expl = explanations.get(r["id"]) or "_Keine Erläuterung erzeugt._"
        freq = f" (frequency {r['frequency']}, timeframe {r['timeframe']} s)" if r["frequency"] else ""
        details.append(f"### Regel {r['id']} – {r['description']}\n\nLevel {r['level']}{freq}\n\n{expl}\n\n"
                       f"```xml\n{r['xml']}\n```")
    blocks = [Block("wazuh-rules-overview", "Übersicht", overview),
              Block("wazuh-rules-table", "Regeln", table)]
    blocks.append(Block("wazuh-rules-details", "Erläuterungen", "\n\n".join(details))
                  if details else Block("wazuh-rules-raw", "Quelltext", f"```xml\n{raw.strip()}\n```"))
    name = filename.rsplit(".", 1)[0]
    return propose_page(ctx, PageDraft(
        doc_type="wazuh_rules", title=f"Wazuh-Regeln: {filename}",
        description=f"Eigene Wazuh-Regeln aus {filename}", blocks=blocks, path_vars={"name": name},
        intro=f"Dokumentation der eigenen Wazuh-Regeldatei `{filename}`. Die markierten Abschnitte werden "
              f"automatisch aus der Wazuh-API aktualisiert.",
        source=f"wazuh:rules:{filename}", hints=hints, stable_id=f"wazuh:rules:{filename}",
    ))


def document_decoder_file(ctx: Context, file_info: dict) -> int | None:
    filename = file_info["filename"]
    raw = ctx.wazuh.decoder_file(filename)
    try:
        decoders = parse_decoders(raw)
    except ET.ParseError as exc:
        decoders = []
        ctx.log.warning("%s: XML-Fehler %s", filename, exc)
    summary = ""
    if decoders:
        summary = cached(ctx, "wazuh-decoders:" + digest(filename, raw), lambda: ctx.llm.text(
            "Du bist Wazuh-Experte. " + STYLE_RULES,
            "Beschreibe in 3-6 Sätzen, welche Logquellen diese Wazuh-Decoder verarbeiten, welche Felder sie "
            f"extrahieren und wie die Decoder aufeinander aufbauen.\n\n{ctx.llm.fit(raw)}",
        ))
    table = markdown.table(
        ["Name", "Parent", "program_name", "prematch", "regex", "order"],
        [[d["name"], d["parent"], d["program_name"], d["prematch"], d["regex"], d["order"]] for d in decoders],
    ) if decoders else "_Keine Decoder gefunden._"
    name = filename.rsplit(".", 1)[0]
    return propose_page(ctx, PageDraft(
        doc_type="wazuh_decoders", title=f"Wazuh-Decoder: {filename}",
        description=f"Eigene Wazuh-Decoder aus {filename}",
        blocks=[Block("wazuh-decoders-overview", "Übersicht", summary or "_Keine Zusammenfassung._"),
                Block("wazuh-decoders-table", "Decoder", table),
                Block("wazuh-decoders-raw", "Quelltext", f"```xml\n{raw.strip()}\n```")],
        path_vars={"name": name},
        intro=f"Dokumentation der eigenen Wazuh-Decoderdatei `{filename}`.",
        source=f"wazuh:decoders:{filename}", stable_id=f"wazuh:decoders:{filename}",
    ))


def _flatten_xml(el: ET.Element, prefix: str = "") -> list[tuple[str, str]]:
    rows = []
    for child in el:
        attrs = " ".join(f'{k}="{v}"' for k, v in child.attrib.items())
        key = f"{prefix}{child.tag}" + (f" ({attrs})" if attrs else "")
        if len(child):
            rows += _flatten_xml(child, key + " / ")
        else:
            rows.append((key, " ".join((child.text or "").split())))
    return rows


def _config_page(ctx: Context, raw: str, name: str, title: str, source: str, what: str) -> int | None:
    try:
        root = parse_xml_fragment(raw)
    except ET.ParseError as exc:
        ctx.log.warning("%s: XML nicht lesbar (%s) – übersprungen", title, exc)
        return None
    mask_xml(root)
    blocks_by_section: dict[str, list[tuple[str, str]]] = {}
    for conf in [c for c in root if c.tag in ("ossec_config", "agent_config")] or [root]:
        label_suffix = " ".join(f'{k}="{v}"' for k, v in conf.attrib.items())
        for section in conf:
            label = section.tag + (f" [{label_suffix}]" if label_suffix else "")
            blocks_by_section.setdefault(label, []).extend(_flatten_xml(section) or [(section.tag, (section.text or "").strip())])
    if not blocks_by_section:
        ctx.log.info("%s: keine Einstellungen (leere Konfiguration) – übersprungen", title)
        return None
    masked_xml = "\n".join(ET.tostring(c, encoding="unicode") for c in root)
    summary = cached(ctx, f"wazuh-config:{name}:" + digest(masked_xml), lambda: ctx.llm.text(
        "Du bist Wazuh-Experte. " + STYLE_RULES,
        f"Beschreibe für die Dokumentation die wichtigsten Einstellungen dieser {what}: welche Module aktiv "
        "sind, was überwacht wird (Dateien, Logs, Befehle), Intervalle und Besonderheiten. Höchstens 12 Sätze "
        f"oder Stichpunkte.\n\n{ctx.llm.fit(masked_xml)}",
    ))
    sections = []
    for label, rows in blocks_by_section.items():
        sections.append(f"### {label}\n\n" + markdown.table(["Einstellung", "Wert"], [list(r) for r in rows[:200]]))
    return propose_page(ctx, PageDraft(
        doc_type="wazuh_config", title=title, description=f"Wazuh {what}",
        blocks=[Block("wazuh-config-summary", "Zusammenfassung", summary),
                Block("wazuh-config-sections", "Einstellungen", "\n\n".join(sections) or "_Leer._")],
        path_vars={"name": name},
        intro=f"Automatisch erzeugte Dokumentation der Wazuh {what}. Geheimnisse (Passwörter, API-Keys, "
              f"Webhooks) sind maskiert.",
        source=source, stable_id=source,
    ))


def manager_page(ctx: Context) -> int | None:
    return _config_page(ctx, ctx.wazuh.manager_config(), "manager", "Wazuh-Manager: Konfiguration",
                        "wazuh:config:manager", "Manager-Konfiguration (ossec.conf)")


def group_page(ctx: Context, gname: str, raw: str | None = None) -> int | None:
    raw = ctx.wazuh.group_agent_conf(gname) if raw is None else raw
    return _config_page(ctx, raw, f"gruppe-{gname}", f"Wazuh-Gruppe {gname}: agent.conf",
                        f"wazuh:config:group:{gname}", f"Gruppen-Konfiguration (agent.conf) von '{gname}'")


def document_config(ctx: Context) -> list[int | None]:
    results = [manager_page(ctx)]
    if ctx.cfg.wazuh.document_groups:
        for group in ctx.wazuh.groups():
            gname = group.get("name", "")
            try:
                raw = ctx.wazuh.group_agent_conf(gname)
            except Exception as exc:
                ctx.log.warning("Gruppe %s: agent.conf nicht lesbar (%s)", gname, exc)
                continue
            results.append(group_page(ctx, gname, raw))
    return results


def document_sca(ctx: Context, agent_id: str = "") -> list[int | None]:
    wanted = set(ctx.cfg.wazuh.sca_agents)
    results = []
    for agent in ctx.wazuh.agents(status="active"):
        if agent_id and agent["id"] != agent_id:
            continue
        if not agent_id and wanted and agent["id"] not in wanted and agent.get("name") not in wanted:
            continue
        policies = ctx.wazuh.sca_policies(agent["id"])
        if not policies:
            continue
        overview = markdown.table(
            ["Richtlinie", "Score", "Bestanden", "Fehlgeschlagen", "Nicht anwendbar", "Letzter Scan"],
            [[p.get("name"), f"{p.get('score')} %", p.get("pass"), p.get("fail"), p.get("invalid", "–"),
              p.get("end_scan")] for p in policies],
        )
        failed_sections = []
        for pol in policies:
            failed = ctx.wazuh.sca_failed_checks(agent["id"], pol["policy_id"])
            if not failed:
                continue
            failed_sections.append(f"### {pol.get('name')}\n\n" + markdown.table(
                ["ID", "Prüfung", "Behebung"],
                [[c.get("id"), c.get("title"), (c.get("remediation") or "")[:400]] for c in failed[:150]],
            ))
        results.append(propose_page(ctx, PageDraft(
            doc_type="wazuh_sca", title=f"SCA-Ergebnisse: {agent.get('name')}",
            description=f"Security Configuration Assessment für {agent.get('name')}",
            blocks=[Block("wazuh-sca-overview", "Übersicht", overview),
                    Block("wazuh-sca-failed", "Fehlgeschlagene Prüfungen",
                          "\n\n".join(failed_sections) or "_Keine fehlgeschlagenen Prüfungen._")],
            path_vars={"name": agent.get("name", agent["id"])},
            intro=f"SCA-Ergebnisse des Wazuh-Agents `{agent.get('name')}` (ID {agent['id']}). Stand laut "
                  f"letztem Scan; automatisch aktualisiert.",
            lookup_name=None, source=f"wazuh:sca:{agent['id']}", stable_id=f"wazuh:sca:{agent['id']}",
        )))
    return results


def document_rules(ctx: Context) -> list[int | None]:
    return [document_rule_file(ctx, f) for f in ctx.wazuh.rule_files()]


def document_decoders(ctx: Context) -> list[int | None]:
    return [document_decoder_file(ctx, f) for f in ctx.wazuh.decoder_files()]
