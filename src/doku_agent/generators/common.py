"""Gemeinsame Helfer: Geheimnisse maskieren, LLM-Texte cachen, Stilvorgaben für Prompts."""

from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET

from doku_agent.context import Context

# Nur das Ende des Feldnamens zählt: "preSharedKey" wird maskiert, "passwordMinimumLength" nicht.
SECRET_NAME = re.compile(
    r"(?i)(password|passwd|passphrase|secret|token|api[_-]?key|hook[_-]?url|pre[_-]?shared[_-]?key|psk|"
    r"private[_-]?key|credentials?|auth[_-]?key|client[_-]?key|shared[_-]?key)$"
)
MASK = "***"

STYLE_RULES = (
    "Schreibe sachlich und knapp für IT-Administratoren. Nutze Markdown, aber keine Überschriften der "
    "Ebene 1. Keine Einleitungsfloskeln, keine Wiederholung der Eingabedaten als Rohliste."
)


def _is_secret(name: str, value) -> bool:
    last = re.split(r"[./ ]+", (name or "").strip())[-1]
    if not SECRET_NAME.search(last) or not isinstance(value, str):
        return False
    return value.strip().lower() not in ("", "true", "false", "yes", "no", "none", "null") and not value.isdigit()


def mask_value(key: str, value):
    return MASK if _is_secret(key, value) else value


def mask_xml(elem: ET.Element) -> None:
    for el in elem.iter():
        if _is_secret(el.tag, el.text or ""):
            el.text = MASK
        for attr, val in list(el.attrib.items()):
            if _is_secret(attr, val):
                el.attrib[attr] = MASK


def parse_xml_fragment(text: str) -> ET.Element:
    """Wazuh-Dateien haben mehrere Wurzelelemente und oft unmaskierte '&' in Regexen."""
    text = re.sub(r"<\?xml[^>]*\?>", "", text)
    text = re.sub(r"<!DOCTYPE[^>]*>", "", text, flags=re.I)
    try:
        return ET.fromstring(f"<root>{text}</root>")
    except ET.ParseError:
        fixed = re.sub(r"&(?!amp;|lt;|gt;|quot;|apos;|#\d+;|#x[0-9a-fA-F]+;)", "&amp;", text)
        return ET.fromstring(f"<root>{fixed}</root>")


def digest(*parts) -> str:
    return hashlib.sha256(json.dumps(parts, sort_keys=True, default=str).encode()).hexdigest()[:24]


def cached(ctx: Context, key: str, fn):
    """LLM-Ergebnisse nach Eingabe-Hash cachen: unveränderte Quellen erzeugen keine neuen Texte
    (und damit keine nächtlichen Schein-Änderungen in der Freigabe-Liste)."""
    full = f"llm:{ctx.cfg.llm.model}:{key}"
    hit = ctx.store.kv_get(full)
    if hit is not None:
        return hit
    value = fn()
    ctx.store.kv_set(full, value)
    return value


def style_context(ctx: Context, target_path: str) -> str:
    profile = ctx.conventions.profile_for_path(target_path)
    if not profile.page_count:
        return STYLE_RULES
    text = STYLE_RULES + "\n\nKonventionen des Wiki-Bereichs:\n" + profile.summary()
    if profile.example_outline:
        text += "\n\nAufbau einer Beispielseite aus diesem Bereich (Stilvorlage):\n" + profile.example_outline[:1500]
    return text
