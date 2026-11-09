"""Gemeinsame Helfer: Geheimnisse maskieren, LLM-Texte cachen, Stilvorgaben für Prompts."""

from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET

from doku_agent.context import Context

# Nur das Ende des Feldnamens zählt: "preSharedKey" wird maskiert, "passwordMinimumLength" nicht.
# Die Regex deckt zusammengeschriebene Namen ab ("adminpassword"), die Wortlisten zerlegte ("Pre-shared key",
# "secret_value", "APIKey").
SECRET_NAME = re.compile(
    r"(?i)(password|passwd|passphrase|secret|token|api[_-]?key|hook[_-]?url|pre[_-]?shared[_-]?key|psk|"
    r"private[_-]?key|credentials?|auth[_-]?key|client[_-]?key|shared[_-]?key)$"
)
SECRET_WORDS = {"password", "passwort", "kennwort", "passwd", "pwd", "passphrase", "secret", "token", "psk",
                "credential", "credentials", "cpassword", "webhook"}
# "… key" ist geheim, wenn das Wort davor einen Schlüssel bezeichnet ("access key", Wazuh <key>); "registry key" nicht
KEY_WORDS = {"api", "auth", "access", "secret", "private", "shared", "client", "application", "app", "encryption",
             "license", "product", "subscription", "master", "signing", "session", "cluster", "storage", "sas",
             "account", "service", "integration"}
SECRET_PAIRS = {("connection", "string"), ("hook", "url"), ("webhook", "url"), ("key", "material")}
VALUE_WORDS = {"value", "hash", "data"}  # "secret_value", "passwordHash"
NOT_SECRET_VALUES = ("", "true", "false", "yes", "no", "none", "null", "***")
MASK = "***"

STYLE_RULES = (
    "Schreibe sachlich und knapp für IT-Administratoren. Nutze Markdown, aber keine Überschriften der "
    "Ebene 1. Keine Einleitungsfloskeln, keine Wiederholung der Eingabedaten als Rohliste."
)


def _words(name: str) -> list[str]:
    """'preSharedKey' -> pre shared key, 'APIKey' -> api key, 'Pre-shared key' -> pre shared key."""
    text = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", name or "")
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    return re.findall(r"[a-z0-9]+", text.lower())


def secret_name(name: str) -> bool:
    """Bezeichnet der Feldname ein Geheimnis? Entscheidend ist das Ende: 'passwordMinimumLength' nicht."""
    if SECRET_NAME.search(re.split(r"[./ ]+", (name or "").strip())[-1]):
        return True
    words = _words(name)
    if not words:
        return False
    if words[-1] in SECRET_WORDS:
        return True
    if words[-1] == "key" and (len(words) == 1 or words[-2] in KEY_WORDS):
        return True
    return len(words) >= 2 and (tuple(words[-2:]) in SECRET_PAIRS
                                or (words[-2] in SECRET_WORDS and words[-1] in VALUE_WORDS))


def _is_secret(name: str, value) -> bool:
    # auch rein numerische Werte: PINs, PSKs wie "12345678"
    return isinstance(value, str) and value.strip().lower() not in NOT_SECRET_VALUES and secret_name(name)


def mask_value(key: str, value):
    return MASK if _is_secret(key, value) else value


def mask_tree(value, key: str = ""):
    """Verschachtelte Objekte (z.B. Intune-Listen) maskieren, bevor sie als JSON-Text erscheinen. Paare wie
    {"key": "password", "value": "…"} oder OMA-Einstellungen {"displayName": "WLAN-PSK", "value": "…"} zählen über
    ihren Namen; eingebettete XML-/Konfigurationstexte werden zusätzlich bereinigt."""
    if isinstance(value, dict):
        label_keys = [k for k in ("key", "name", "displayName", "omaUri") if isinstance(value.get(k), str)]
        pair = "value" in value and bool(label_keys)  # Beschriftung + Wert: die Beschriftung ist kein Geheimnis
        named_secret = pair and any(secret_name(value[k].rsplit("/", 1)[-1]) for k in label_keys)
        out = {}
        for k, v in value.items():
            if k == "value" and named_secret and isinstance(v, str) and v.strip().lower() not in NOT_SECRET_VALUES:
                out[k] = MASK
            elif pair and k in label_keys:
                out[k] = v
            else:
                out[k] = mask_tree(v, k)
        return out
    if isinstance(value, list):
        return [mask_tree(v, key) for v in value]
    if isinstance(value, str):
        return scrub_text(mask_value(key, value))[0]
    return value


# --- Freitext und Befehlszeilen ------------------------------------------------------------------------------

_XML_PAIR = re.compile(r"<(?P<tag>[A-Za-z_][\w:.\-]*)(?P<attrs>[^<>]*)>(?P<val>[^<]+)</(?P=tag)>")
_XML_ATTR = re.compile(r"(?P<key>\b[A-Za-z_][\w:.\-]*)(?P<sep>\s*=\s*)(?P<q>[\"'])(?P<val>[^\"'<>]*)(?P=q)")
_JSON_PAIR = re.compile(r"(?P<key>\"[^\"\n]{1,60}\")(?P<sep>\s*:\s*)(?P<val>\"(?:[^\"\\\n]|\\.)*\")")
# "Admin-Passwort: x", "password = x", YAML "  secret_key: x": Schlüssel aus bis zu drei Wörtern vor ':' oder '='
_LINE_PAIR = re.compile(r"(?P<key>(?:[A-Za-z_][\w\-]*[ \t]+){0,2}[A-Za-z_][\w\-]*)(?P<sep>[ \t]*[:=][ \t]*)"
                        r"(?P<val>\S.*)$", re.M)
_URL_CREDS = re.compile(r"(?P<key>\b[a-z][a-z0-9+.\-]*://[^/\s:@]+:)(?P<val>[^@\s/]+)(?=@)", re.I)
# FortiOS "set psksecret ENC …", Cisco "enable secret 5 …", "password 7 …", "snmp-server community …"
_CLI_SET = re.compile(r"(?P<key>^[ \t]*set[ \t]+(?P<name>[\w\-]+)[ \t]+)(?P<val>\S.*)$", re.M)
_CLI_TYPED = re.compile(r"(?P<key>\b(?:password|secret|key-string)[ \t]+[05789][ \t]+)(?P<val>\S+)", re.I)
_CLI_LINE = re.compile(r"(?P<key>^[ \t]*(?:snmp-server[ \t]+community|pre-shared-key|key-string|"
                       r"enable[ \t]+(?:secret|password))[ \t]+)(?P<val>(?![05789][ \t])\S+)", re.I | re.M)
# eingerücktes "password x" (z.B. Cisco "line vty"); am Zeilenanfang wäre es oft Fließtext ("Password policy …")
_CLI_INDENTED = re.compile(r"(?P<key>^[ \t]+password[ \t]+)(?P<val>\S+)", re.I | re.M)


def _masked(match: re.Match) -> str:
    """Treffer mit maskierter Gruppe 'val'; umschließende Anführungszeichen und der Rest bleiben stehen."""
    whole, offset, value = match.group(0), match.start(0), match.group("val")
    start, end = match.start("val") - offset, match.end("val") - offset
    quote = value[0] if len(value) > 1 and value[0] in "\"'" and value[-1] == value[0] else ""
    return f"{whole[:start]}{quote}{MASK}{quote}{whole[end:]}"


def scrub_text(text: str) -> tuple[str, bool]:
    """Kennwörter, Schlüssel und Tokens in Freitext und Konfigurationsdateien ausblenden (Notizen, Uploads,
    eingebettetes XML). Rückgabe: (bereinigter Text, ob etwas ausgeblendet wurde)."""
    if not isinstance(text, str) or not text:
        return text, False
    found = False

    def by_name(match: re.Match, name: str) -> str:
        nonlocal found
        bare = match.group("val").strip().strip("\"'")
        if not secret_name(name.strip("\"' ")) or bare.lower() in NOT_SECRET_VALUES:
            return match.group(0)
        found = True
        return _masked(match)

    def always(match: re.Match) -> str:
        nonlocal found
        found = True
        return _masked(match)

    text = _XML_PAIR.sub(lambda m: by_name(m, m.group("tag").rsplit(":", 1)[-1]), text)
    text = _XML_ATTR.sub(lambda m: by_name(m, m.group("key")), text)
    text = _JSON_PAIR.sub(lambda m: by_name(m, m.group("key")), text)
    text = _URL_CREDS.sub(always, text)
    text = _CLI_SET.sub(lambda m: always(m) if m.group("val").startswith("ENC ") else by_name(m, m.group("name")),
                        text)
    text = _CLI_TYPED.sub(always, text)
    text = _CLI_LINE.sub(always, text)
    text = _CLI_INDENTED.sub(always, text)
    text = _LINE_PAIR.sub(lambda m: by_name(m, m.group("key")), text)
    return text, found


_CMD_SECRETS = [
    # psexec -p x, schtasks /RP x, --password=x, -Password x, /pass:x
    re.compile(r"(?P<key>(?:^|\s)(?:--?|/)(?:p|pw|pwd|pass|passwd|password|kennwort|rp)(?:[:=]|\s+))"
               r"(?P<val>\"[^\"]*\"|'[^']*'|[^\s\"']+)", re.I),
    re.compile(r"(?P<key>\bConvertTo-SecureString\s+(?:-String\s+)?)(?P<val>\"[^\"]*\"|'[^']*'|\S+)", re.I),
    re.compile(r"(?P<key>\bnet1?(?:\.exe)?\s+user\s+(?!/)\S+\s+)(?P<val>(?!/)[^\s/]\S*)", re.I),
    # "*" heißt "Kennwort abfragen" – kein gespeichertes Kennwort
    re.compile(r"(?P<key>\bnet1?(?:\.exe)?\s+use\s+(?:[a-z]:\s+|\*\s+)?\\\\\S+\s+)(?P<val>(?![/*])[^\s/]\S*)", re.I),
    # net use \\srv\share /user:CORP\svc Kennwort – das Kennwort darf auch hinter /user: stehen
    re.compile(r"(?P<key>(?:^|\s)/user:\S+\s+)(?P<val>(?![/*])[^\s/]\S*)", re.I),
]
_NET_EXE = re.compile(r"(?i)(?:^|[\\/])net1?(?:\.exe)?$")


def scrub_command(text: str, command: str = "") -> tuple[str, bool]:
    """Kennwörter in Befehlszeilen (Skript-Parameter, geplante Aufgaben) ausblenden. command: das aufgerufene
    Programm, wenn text nur dessen Parameter enthält (scripts.ini: net.exe + "use Z: \\\\srv\\share …").
    Rückgabe: (bereinigter Text, ob ein Kennwort gefunden wurde)."""
    if not text:
        return text, False
    if command and _NET_EXE.search(command.strip().strip('"')):
        cleaned, found = scrub_command(f"net {text}")
        return cleaned[4:], found
    found = False

    def hide(match: re.Match) -> str:
        nonlocal found
        if match.group("val").strip("\"'").lower() in NOT_SECRET_VALUES:
            return match.group(0)
        found = True
        return _masked(match)

    for pattern in _CMD_SECRETS:
        text = pattern.sub(hide, text)
    text, more = scrub_text(text)
    return text, found or more


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
