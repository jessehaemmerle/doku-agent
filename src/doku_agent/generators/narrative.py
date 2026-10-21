"""Fließtext aus strukturierten Fakten – mit automatischer Faktenprüfung.

Das Sprachmodell schreibt erklärenden Text über Daten, die der Agent vorher deterministisch
zusammengestellt hat. Danach wird geprüft, ob jede konkrete Angabe im Text (IP-Adressen, Zahlen,
Versionen, technische Namen, zitierte oder fett gesetzte Namen) in diesen Daten vorkommt. Ist das nicht
so, bekommt das Modell einen zweiten Versuch mit der Liste der unbelegten Angaben; scheitert auch der,
steht statt des Textes eine feste Vorlage aus denselben Daten. Ergebnisse werden nach Eingabe-Hash
zwischengespeichert – unveränderte Daten erzeugen keinen neuen Text und keine Schein-Änderungen.

Nicht geprüft werden ausgeschriebene Zahlwörter ("zwei") und allgemeine Fachbegriffe ohne Ziffern.
"""

from __future__ import annotations

import re
import time

from doku_agent.context import Context
from doku_agent.generators.common import digest
from doku_agent.llm import LLMError

VERSION = 2  # erhöhen, wenn sich Prompt oder Prüfung ändern (alle Texte werden dann neu erzeugt)
RETRY_FALLBACK_DAYS = 7  # eine feste Vorlage wird nach dieser Zeit erneut durch Fließtext zu ersetzen versucht

PROSE_RULES = (
    "Schreibe zusammenhängenden Fließtext in Absätzen auf Deutsch: keine Aufzählungen, keine Tabellen, keine "
    "Überschriften; Markdown nur für **fett** gesetzte Namen. Verwende ausschließlich Angaben aus den Daten. "
    "Schreibe Zahlen, IP-Adressen, Versionen, Datumsangaben und Namen genau so, wie sie in den Daten stehen – "
    "nichts umrechnen, nichts runden, keine Ports, Versionen, Adressen oder Namen ergänzen, die dort nicht stehen. "
    "Allgemeines Fachwissen (was eine Funktion bewirkt, warum etwas wichtig ist) darfst du erklären, aber ohne "
    "konkrete Zahlen. Keine Einleitungsfloskeln, keine Wiederholung der Daten als Liste."
)
LENGTH = {
    "detailed": "Schreibe 2 bis 4 Absätze: zuerst, was es ist und wofür es dient, dann die wichtigsten Details und "
                "Zusammenhänge, zuletzt Besonderheiten oder Auffälligkeiten. Erkläre Fachbegriffe kurz, sodass "
                "auch Nicht-Spezialisten folgen können.",
    "compact": "Schreibe einen Absatz mit 3 bis 6 Sätzen.",
}
# Fachbegriffe mit Ziffern, die ohne Beleg vorkommen dürfen
ALLOWED = {"ipv4", "ipv6", "fido2", "802.1x", "x.509", "x509", "m365", "o365", "office365", "b2b", "b2c", "2fa",
           "sha256", "sha-256", "sha1", "sha-1", "aes256", "aes-256", "aes128", "3des", "p1", "p2", "e3", "e5",
           "win32", "w32", "oauth2", "http/2", "ikev1", "ikev2", "sha2"}

_TRIM = ".,;:!?()[]{}„“”\"'`»«…*"
_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$")
_HEXCOLON = re.compile(r"^[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,}(?:/\d{1,3})?$", re.I)
_NUMBER = re.compile(r"^\d+(?:[.,]\d+)?%?$")
_QUOTED = re.compile(r"[„\"“»`]([^„\"“”`«»\n]{2,80})[“”\"«`]")
_BOLD = re.compile(r"\*\*([^*\n]{2,80})\*\*")
_UNIT = re.compile(r"^(\d+(?:[.,]\d+)?)(gb|mb|tb|kb|gib|mib|ghz|mhz|ms|s|h|min|bit|mbit|gbit|x)$")
_DE_DATE = re.compile(r"^(\d{1,2})\.(\d{1,2})\.(\d{4})$")
_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}(?:t[\d:.]+z?)?$")
_BULLET = re.compile(r"^\s*(?:[-*•]|\d+[.)])\s+", re.M)


def _num(value: str) -> str:
    value = value.rstrip("%")
    if re.fullmatch(r"\d{1,3}(?:\.\d{3})+", value):  # deutsche Tausender: 1.000 -> 1000
        value = value.replace(".", "")
    value = value.replace(",", ".")
    if "." in value:
        return value.rstrip("0").rstrip(".") if re.fullmatch(r"\d+\.\d*0", value) else value
    return value.lstrip("0") or "0"


def _abbreviation(token: str) -> bool:
    """z.B., d.h., u.a. – Abkürzungen mit Punkten sind keine technischen Namen."""
    parts = [p for p in token.split(".") if p]
    return all(len(p) <= 2 and p.isalpha() for p in parts)


def _present(claim: str, hay: str) -> bool:
    """Angabe kommt als eigenes Wort vor: 10.0.0.1 nicht in 10.0.0.15, srv1 nicht in srv10, 7.4 nicht in 7.4.5;
    erlaubt sind eine Netzmaske (10.0.0.1/24) und eine Domain-Endung (srv01 in srv01.firma.local)."""
    return re.search(r"(?<![\w\-])" + re.escape(claim) + r"(?![\w]|[.:\-]\d|-\w)", hay) is not None


def _token_numbers(low: str) -> list[str]:
    """Zahlen, die ein Token als eigene Angabe enthält – Oktette einer IP-Adresse zählen nicht."""
    if _IPV4.match(low):
        return [low.split("/")[1]] if "/" in low else []  # nur die Präfixlänge
    if _HEXCOLON.match(low):
        return []
    unit = _UNIT.match(low)
    if _NUMBER.match(low) or unit:
        return [_num(unit.group(1) if unit else low)]
    if _ISO_DATE.match(low):
        return [_num(n) for n in re.findall(r"\d+", low)]
    return [_num(part) for part in re.split(r"[-/:]", low) if _NUMBER.match(part)]


def unverified(text: str, facts: str) -> list[str]:
    """Konkrete Angaben im Text, die in den Fakten nicht vorkommen (Reihenfolge wie im Text, ohne Doppelte)."""
    hay = facts.lower()
    numbers = {n for raw in hay.split() for n in _token_numbers(raw.strip(_TRIM))}
    bad: list[str] = []

    def miss(claim: str) -> None:
        if claim not in bad:
            bad.append(claim)

    # Zitierte und fett gesetzte Ausdrücke nur, wenn sie wie technische Namen aussehen – das Modell setzt auch
    # allgemeine Begriffe in Anführungszeichen („IP-Adressen“), die in den Daten anders formuliert sind
    claims = [c for c in _QUOTED.findall(text) + _BOLD.findall(text) if re.search(r"[\d._@/]", c)]
    for match in claims:
        claim = match.strip()
        if claim and not _present(claim.lower(), hay):
            miss(claim)
    for raw in text.split():
        token = raw.strip(_TRIM)
        low = token.lower()
        if not low or low in ALLOWED:
            continue
        date = _DE_DATE.match(low)
        unit = _UNIT.match(low)
        if date:  # 31.12.2026 -> 2026-12-31
            iso = f"{date.group(3)}-{int(date.group(2)):02d}-{int(date.group(1)):02d}"
            if not _present(iso, hay) and not _present(low, hay):
                miss(token)
        elif _IPV4.match(low) or _HEXCOLON.match(low):
            if not _present(low, hay):
                miss(token)
        elif _NUMBER.match(low) or unit:
            if _num(unit.group(1) if unit else low) not in numbers:
                miss(token)
        elif any(c.isdigit() for c in low):
            # zusammengesetzt (srv01, ubuntu-24.04, 04:00, v7.4.5): als Ganzes oder Teil für Teil belegt
            if _present(low, hay):
                continue
            for part in re.split(r"[-/:]", low):
                part = part.strip(_TRIM)
                if not part or part in ALLOWED or not any(c.isdigit() for c in part):
                    continue
                part_unit = _UNIT.match(part)
                if _NUMBER.match(part) or part_unit:
                    ok = _num(part_unit.group(1) if part_unit else part) in numbers
                else:
                    ok = _present(part, hay)
                if not ok:
                    miss(token)
                    break
        elif ("." in low.strip(".") and not _abbreviation(low)) or "_" in low or "@" in low:
            if not _present(low, hay):  # Domains, UPNs, Dateinamen, technische Bezeichner
                miss(token)
    return bad


def fact_lines(pairs) -> str:
    """[(Bezeichnung, Wert)] -> 'Bezeichnung: Wert' je Zeile; leere Werte entfallen."""
    out = []
    for label, value in pairs:
        if value in (None, "", [], "–"):
            continue
        if isinstance(value, (list, tuple)):
            value = "; ".join(str(v) for v in value if v not in (None, ""))
        out.append(f"{label}: {value}")
    return "\n".join(out)


def _clean(text: str) -> str:
    lines = [ln for ln in (text or "").strip().splitlines() if not ln.lstrip().startswith("#")]
    return "\n".join(lines).strip()


def narrate(ctx: Context, key: str, *, expert: str, task: str, facts: str, fallback: str) -> str | None:
    """Fließtext zu den Fakten; bei unbelegten Angaben nach zweitem Versuch die feste Vorlage.
    None, wenn das Sprachmodell nicht erreichbar ist und noch kein Text vorliegt – der Aufrufer lässt den
    Abschnitt dann weg, ein bestehender Abschnitt im Wiki bleibt unverändert."""
    cfg = ctx.cfg.narrative
    facts = facts.strip()
    if not facts:
        return fallback
    system = f"Du bist Experte für {expert} und schreibst Dokumentation für ein IT-Team. {PROSE_RULES} " \
             f"{LENGTH[cfg.length]}"
    user = f"{task}\n\nDaten:\n{ctx.llm.fit(facts)}"

    def run() -> dict:
        text = _clean(ctx.llm.text(system, user))
        problems = unverified(text, facts) if cfg.fact_check else []
        bullets = len(_BULLET.findall(text)) >= 3
        if problems or bullets or not text:
            notes = []
            if problems:
                notes.append("Diese Angaben stehen nicht in den Daten: " + ", ".join(problems[:20])
                             + ". Lasse sie weg oder ersetze sie durch Angaben aus den Daten.")
            if bullets:
                notes.append("Schreibe Fließtext statt einer Aufzählung.")
            text = _clean(ctx.llm.text(system, f"{user}\n\nDein Entwurf:\n{text}\n\nÜberarbeite den Entwurf. "
                                               + " ".join(notes)))
            problems = unverified(text, facts) if cfg.fact_check else []
        if problems or not text:
            ctx.log.warning("Fließtext (%s) verworfen, nicht belegt: %s – feste Vorlage verwendet",
                            key.split(":")[0], ", ".join(problems[:8]) or "leer")
            return {"text": fallback, "fallback": True}
        return {"text": text, "fallback": False}

    full = f"llm:{ctx.cfg.llm.model}:narrative:v{VERSION}:{key}:" + digest(system, user, fallback, cfg.fact_check)
    hit = ctx.store.kv_get(full)
    retry = isinstance(hit, dict) and hit.get("fallback") and \
        time.time() - hit.get("at", 0) > RETRY_FALLBACK_DAYS * 86400
    if isinstance(hit, dict) and not retry:
        return hit["text"]
    if ctx.__dict__.get("_llm_down"):  # in diesem Lauf schon gescheitert: nicht bei jeder Seite neu warten
        return hit["text"] if hit else None
    try:
        result = run()
    except LLMError as exc:
        ctx.__dict__["_llm_down"] = True
        ctx.log.warning("Sprachmodell nicht erreichbar (%s) – Fließtext-Abschnitte bleiben unverändert", exc)
        return hit["text"] if hit else None
    ctx.store.kv_set(full, {**result, "at": time.time()})
    return result["text"]


def enabled(ctx: Context, area: str) -> bool:
    """Ob für einen Seitenbereich (steckbrief, audit, overview) zusätzlicher Fließtext entsteht."""
    cfg = ctx.cfg.narrative
    return cfg.enabled and area in cfg.areas


def findings_facts(sections: list[tuple[str, list[str], list[list]]], limit: int = 30) -> str:
    """Prüfbefunde als Fakten: je Prüfung die Anzahl und die Befundzeilen (gekürzt)."""
    lines = []
    for title, headers, rows in sections:
        lines.append(f"{title}: {len(rows)} Befunde")
        for row in rows[:limit]:
            cells = [f"{h}: {str(v).replace('<br>', ', ')}" for h, v in zip(headers, row) if v not in (None, "", "–")]
            lines.append("  - " + "; ".join(cells))
        if len(rows) > limit:
            lines.append(f"  - und {len(rows) - limit} weitere")
    return "\n".join(lines)


def assessment(ctx: Context, key: str, *, expert: str, subject: str,
               sections: list[tuple[str, list[str], list[list]]], context: str = "") -> str | None:
    """Bewertung einer Prüfseite in Worten: Gesamtzustand, Dringlichkeit, nächste Schritte."""
    total = sum(len(rows) for _, _, rows in sections)  # -> Text oder None (Sprachmodell nicht erreichbar)
    fallback = (f"Die Prüfung von {subject} ergab keine Befunde." if not total else
                f"Die Prüfung von {subject} ergab {total} Befunde: "
                + ", ".join(f"{title} ({len(rows)})" for title, _, rows in sections if rows)
                + ". Die Einzelheiten stehen in den Tabellen unten.")
    facts = (context.strip() + "\n" if context else "") + findings_facts(sections)
    return narrate(
        ctx, key, expert=expert, fallback=fallback, facts=facts,
        task=f"Bewerte das Ergebnis dieser automatischen Prüfung von {subject} für das IT-Team: Wie ist der "
             "Gesamtzustand? Welche Befunde sind am dringendsten und warum (welches Risiko besteht)? Was sollte "
             "konkret als Nächstes getan werden, in sinnvoller Reihenfolge? Gibt es keine Befunde, sage das kurz "
             "und nenne, was geprüft wurde.")


_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
_MARKER = re.compile(r"<!-- doku-agent:(?:begin|end) [^>]*-->")


def facts_from_markdown(md: str) -> str:
    """Tabellen und Text einer erzeugten Seite als Faktenzeilen ('Spalte: Wert; …'), Links als Text."""
    out, headers = [], None
    for line in _MARKER.sub("", md).splitlines():
        line = _LINK.sub(r"\1", line).replace("<br>", ", ").strip()
        if not line:
            headers = None
            continue
        if line.startswith("|") and line.endswith("|"):
            if re.fullmatch(r"\|(\s*:?-{3,}:?\s*\|)+", line):  # Trennzeile
                continue
            cells = [c.strip().replace("\\|", "|") for c in line.strip("|").split(" | ")]
            if headers is None:
                headers = cells
                continue
            out.append("; ".join(f"{h}: {v}" for h, v in zip(headers, cells) if v not in ("", "–")))
        else:
            headers = None
            out.append(line.lstrip("#").strip() if line.startswith("#") else line)
    return "\n".join(o for o in out if o)
