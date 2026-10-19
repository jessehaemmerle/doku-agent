"""Implizite Wiki-Konventionen aus bestehenden Seiten ableiten.

Es gibt keine geschriebenen Regeln. Deshalb wird aus den Seiten eines Bereichs
(Pfad-Präfix) gelernt: übliche Tags, wiederkehrende Abschnitte, Schreibweise der
Pfade, ob Beschreibungen gepflegt werden – plus Beispielseiten als Stilvorlage.
"""

from __future__ import annotations

import re
import unicodedata
from collections import Counter
from dataclasses import dataclass, field

from doku_agent import markdown
from doku_agent.wiki import PageInfo, WikiClient, normalize_path

_WORD = re.compile(r"[a-z0-9äöüß]{3,}")


@dataclass
class AreaProfile:
    prefix: str
    page_count: int = 0
    common_tags: list[str] = field(default_factory=list)
    required_sections: list[str] = field(default_factory=list)
    slug_style: str = "kebab"
    description_ratio: float = 0.0
    examples: list[str] = field(default_factory=list)  # Pfade
    example_outline: str = ""

    def summary(self) -> str:
        if not self.page_count:
            return f"Bereich '{self.prefix or '/'}' ist noch leer – keine Konventionen ableitbar."
        lines = [
            f"Bereich: /{self.prefix} ({self.page_count} Seiten)",
            f"Übliche Tags: {', '.join(self.common_tags) or 'keine'}",
            f"Wiederkehrende Abschnitte: {', '.join(self.required_sections) or 'keine'}",
            f"Pfad-Schreibweise: {self.slug_style}",
            f"Beschreibung gepflegt: {round(self.description_ratio * 100)} % der Seiten",
        ]
        if self.examples:
            lines.append("Beispielseiten: " + ", ".join("/" + p for p in self.examples))
        return "\n".join(lines)


def slugify(text: str, style: str = "kebab") -> str:
    text = text.strip()
    for src, dst in (("ä", "ae"), ("ö", "oe"), ("ü", "ue"), ("Ä", "Ae"), ("Ö", "Oe"), ("Ü", "Ue"), ("ß", "ss")):
        text = text.replace(src, dst)
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    sep = "_" if style == "snake" else "-"
    if style != "mixed":
        text = text.lower()
    text = re.sub(r"[^A-Za-z0-9.]+", sep, text).strip(sep + ".")
    return re.sub(re.escape(sep) + "+", sep, text) or "seite"


def detect_slug_style(segments: list[str]) -> str:
    if not segments:
        return "kebab"
    counts = Counter()
    for seg in segments:
        if "_" in seg:
            counts["snake"] += 1
        elif "-" in seg:
            counts["kebab"] += 1
        if seg != seg.lower():
            counts["mixed"] += 1
    if counts["mixed"] > len(segments) / 2:
        return "mixed"
    return "snake" if counts["snake"] > counts["kebab"] else "kebab"


def _parent(path: str) -> str:
    return path.rsplit("/", 1)[0] if "/" in path else ""


def tokens(text: str) -> set[str]:
    return set(_WORD.findall(text.lower()))


class Conventions:
    """Hält die Seitenliste eines Laufs und berechnet Profile bei Bedarf."""

    def __init__(self, wiki: WikiClient, sample_pages: int = 5):
        self.wiki = wiki
        self.sample_pages = sample_pages
        self._pages: list[PageInfo] | None = None
        self._profiles: dict[str, AreaProfile] = {}

    @property
    def pages(self) -> list[PageInfo]:
        if self._pages is None:
            self._pages = self.wiki.list_pages()
        return self._pages

    def area_for(self, target_path: str) -> str:
        """Tiefster existierender Bereich (Präfix), unter dem der Zielpfad liegen würde."""
        parts = normalize_path(target_path).split("/")[:-1]
        target = normalize_path(target_path)
        while parts:
            prefix = "/".join(parts)
            if any(p.path.startswith(prefix + "/") and p.path != target for p in self.pages):
                return prefix
            parts.pop()
        return ""

    def profile(self, prefix: str) -> AreaProfile:
        if prefix in self._profiles:
            return self._profiles[prefix]
        under = [p for p in self.pages if not prefix or p.path.startswith(prefix + "/")]
        direct = [p for p in under if _parent(p.path) == prefix]
        pages = direct if len(direct) >= 2 else under
        prof = AreaProfile(prefix=prefix, page_count=len(pages))
        if pages:
            tag_counts = Counter(t for p in pages for t in set(p.tags))
            prof.common_tags = [t for t, c in tag_counts.most_common() if c >= max(2, len(pages) / 2)]
            prof.slug_style = detect_slug_style([p.path.rsplit("/", 1)[-1] for p in pages])
            prof.description_ratio = sum(1 for p in pages if p.description.strip()) / len(pages)
            sample = sorted(pages, key=lambda p: p.updated_at, reverse=True)[: self.sample_pages]
            prof.examples = [p.path for p in sample]
            self._learn_structure(prof, sample)
        self._profiles[prefix] = prof
        return prof

    def _learn_structure(self, prof: AreaProfile, sample: list[PageInfo]) -> None:
        heading_counts: Counter[str] = Counter()
        positions: dict[str, list[float]] = {}
        loaded = 0
        for info in sample:
            try:
                page = self.wiki.get_page(info.id)
            except Exception:  # einzelne Seite ohne Leserechte o.ä. – Lernen nicht abbrechen
                continue
            if page.content_type != "markdown":
                continue
            loaded += 1
            level2 = list(dict.fromkeys(title for level, title in markdown.headings(page.content) if level == 2))
            heading_counts.update(level2)
            for idx, title in enumerate(level2):
                positions.setdefault(title, []).append(idx / max(len(level2), 1))
            if not prof.example_outline:
                prof.example_outline = markdown.outline(page.content, 300)[:2500]
        if loaded >= 2:
            required = [h for h, c in heading_counts.items() if c / loaded >= 0.6]
            # Reihenfolge wie auf den Vorbildseiten (mittlere relative Position)
            prof.required_sections = sorted(required, key=lambda h: sum(positions[h]) / len(positions[h]))

    def profile_for_path(self, target_path: str) -> AreaProfile:
        return self.profile(self.area_for(target_path))

    def areas(self, depth: int = 2) -> list[tuple[str, int, list[str]]]:
        """Bereiche bis zur angegebenen Tiefe mit Seitenanzahl und Beispieltiteln."""
        counts: Counter[str] = Counter()
        titles: dict[str, list[str]] = {}
        for p in self.pages:
            segs = p.path.split("/")[:-1]
            for d in range(1, min(depth, len(segs)) + 1):
                prefix = "/".join(segs[:d])
                counts[prefix] += 1
                titles.setdefault(prefix, [])
                if len(titles[prefix]) < 3:
                    titles[prefix].append(p.title)
        return [(prefix, n, titles[prefix]) for prefix, n in sorted(counts.items())]

    def similar(self, text: str, limit: int = 5) -> list[PageInfo]:
        """Seiten mit der größten Wortüberschneidung (Titel, Pfad, Beschreibung, Tags)."""
        wanted = tokens(text)
        if not wanted:
            return []
        scored = []
        for p in self.pages:
            have = tokens(f"{p.title} {p.path.replace('/', ' ').replace('-', ' ')} {p.description} {' '.join(p.tags)}")
            score = len(wanted & have)
            if score:
                scored.append((score, p))
        scored.sort(key=lambda x: (-x[0], x[1].path))
        return [p for _, p in scored[:limit]]

    def find_by_path(self, path: str) -> PageInfo | None:
        path = normalize_path(path)
        return next((p for p in self.pages if p.path == path), None)

    def find_by_name(self, name: str) -> PageInfo | None:
        """Bestehende Seite zu einem Objekt (z.B. Hostname) über letzten Pfadteil oder Titel."""
        key = name.strip().lower()
        if not key:
            return None
        for p in self.pages:
            last = p.path.rsplit("/", 1)[-1].lower()
            if last in (key, slugify(name)) or p.title.strip().lower() == key:
                return p
        return None
