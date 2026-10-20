"""Wiki.js 2.x GraphQL-Client (Schema verifiziert gegen Wiki.js v2.5.315)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

import httpx

from doku_agent.config import WikiConfig
from doku_agent.egress import EgressGuard

_PAGE_FIELDS = """
  id path locale title description content contentType editor
  isPublished isPrivate publishStartDate publishEndDate scriptCss scriptJs
  updatedAt hash tags { tag }
"""


class WikiError(RuntimeError):
    pass


class PageNotFound(WikiError):
    """Die Seite existiert nicht (Wiki.js: "This page does not exist.")."""


@dataclass
class PageInfo:
    id: int
    path: str
    title: str
    description: str = ""
    tags: list[str] = field(default_factory=list)
    updated_at: str = ""
    locale: str = ""


@dataclass
class Page(PageInfo):
    content: str = ""
    editor: str = "markdown"
    content_type: str = "markdown"
    is_published: bool = True
    is_private: bool = False
    publish_start: str = ""
    publish_end: str = ""
    script_css: str = ""
    script_js: str = ""
    hash: str = ""

    @property
    def content_hash(self) -> str:
        return hashlib.sha256(self.content.encode()).hexdigest()


def normalize_path(path: str) -> str:
    return path.strip().strip("/")


class WikiClient:
    def __init__(self, cfg: WikiConfig, guard: EgressGuard, transport: httpx.BaseTransport | None = None):
        self.cfg = cfg
        self.http = guard.client(
            cfg.url.rstrip("/"),
            verify=cfg.verify_tls,
            headers={"Authorization": f"Bearer {cfg.api_key}"},
            transport=transport,
        )

    def _gql(self, query: str, variables: dict | None = None) -> dict:
        try:
            resp = self.http.post("/graphql", json={"query": query, "variables": variables or {}})
        except httpx.HTTPError as exc:
            raise WikiError(f"Wiki.js nicht erreichbar: {exc}") from exc
        if resp.status_code != 200:
            raise WikiError(f"Wiki.js HTTP {resp.status_code}: {resp.text[:300]}")
        data = resp.json()
        if data.get("errors"):
            message = "; ".join(e.get("message", str(e)) for e in data["errors"])
            if "does not exist" in message.lower():
                raise PageNotFound(message)
            raise WikiError(message)
        return data["data"]

    @staticmethod
    def _check_result(result: dict | None, action: str) -> dict:
        status = (result or {}).get("responseResult") or {}
        if not status.get("succeeded"):
            raise WikiError(f"{action} fehlgeschlagen: {status.get('message') or status.get('slug') or 'unbekannt'}")
        return result

    def list_pages(self) -> list[PageInfo]:
        data = self._gql(
            "query($locale: String) { pages { list(limit: 100000, orderBy: PATH, locale: $locale) "
            "{ id path locale title description tags updatedAt } } }",
            {"locale": self.cfg.locale},
        )
        return [
            PageInfo(id=p["id"], path=p["path"], title=p.get("title") or "", description=p.get("description") or "",
                     tags=[t for t in (p.get("tags") or []) if t], updated_at=p.get("updatedAt") or "",
                     locale=p.get("locale") or "")
            for p in data["pages"]["list"]
        ]

    @staticmethod
    def _page(p: dict) -> Page:
        return Page(
            id=p["id"], path=p["path"], title=p.get("title") or "", description=p.get("description") or "",
            tags=[t["tag"] for t in (p.get("tags") or []) if t and t.get("tag")],
            updated_at=p.get("updatedAt") or "", locale=p.get("locale") or "",
            content=p.get("content") or "", editor=p.get("editor") or "markdown",
            content_type=p.get("contentType") or "markdown",
            is_published=bool(p.get("isPublished", True)), is_private=bool(p.get("isPrivate", False)),
            publish_start=p.get("publishStartDate") or "", publish_end=p.get("publishEndDate") or "",
            script_css=p.get("scriptCss") or "", script_js=p.get("scriptJs") or "", hash=p.get("hash") or "",
        )

    def get_page(self, page_id: int) -> Page:
        data = self._gql(f"query($id: Int!) {{ pages {{ single(id: $id) {{ {_PAGE_FIELDS} }} }} }}", {"id": page_id})
        if not data["pages"]["single"]:
            raise PageNotFound(f"Seite {page_id} nicht gefunden")
        return self._page(data["pages"]["single"])

    def get_page_by_path(self, path: str) -> Page | None:
        try:
            data = self._gql(
                f"query($path: String!, $locale: String!) {{ pages {{ singleByPath(path: $path, locale: $locale) "
                f"{{ {_PAGE_FIELDS} }} }} }}",
                {"path": normalize_path(path), "locale": self.cfg.locale},
            )
        except PageNotFound:  # Wiki.js meldet eine fehlende Seite als GraphQL-Fehler
            return None
        page = data["pages"]["singleByPath"]
        return self._page(page) if page else None

    def search(self, query: str) -> list[PageInfo]:
        data = self._gql(
            "query($q: String!, $locale: String) { pages { search(query: $q, locale: $locale) "
            "{ results { id title description path locale } } } }",
            {"q": query, "locale": self.cfg.locale},
        )
        return [
            PageInfo(id=int(r["id"]), path=r["path"], title=r.get("title") or "",
                     description=r.get("description") or "", locale=r.get("locale") or "")
            for r in data["pages"]["search"]["results"] if r
        ]

    def create_page(self, path: str, title: str, content: str, description: str, tags: list[str],
                    editor: str = "markdown") -> int:
        data = self._gql(
            """mutation($content: String!, $description: String!, $editor: String!, $locale: String!,
                        $path: String!, $tags: [String]!, $title: String!) {
              pages { create(content: $content, description: $description, editor: $editor,
                             isPublished: true, isPrivate: false, locale: $locale, path: $path,
                             tags: $tags, title: $title) {
                responseResult { succeeded errorCode slug message } page { id path } } } }""",
            {"content": content, "description": description, "editor": editor, "locale": self.cfg.locale,
             "path": normalize_path(path), "tags": tags, "title": title},
        )
        result = self._check_result(data["pages"]["create"], "Seite anlegen")
        return int(result["page"]["id"])

    def update_page(self, page: Page, *, content: str, title: str | None = None,
                    description: str | None = None, tags: list[str] | None = None) -> None:
        # Wiki.js setzt beim Update alle nicht übergebenen Felder zurück (isPublished, CSS/JS,
        # Veröffentlichungszeitraum). Deshalb werden alle bisherigen Werte mitgeschickt.
        data = self._gql(
            """mutation($id: Int!, $content: String, $description: String, $editor: String,
                        $isPrivate: Boolean, $isPublished: Boolean, $locale: String, $path: String,
                        $publishStartDate: Date, $publishEndDate: Date, $scriptCss: String,
                        $scriptJs: String, $tags: [String], $title: String) {
              pages { update(id: $id, content: $content, description: $description, editor: $editor,
                             isPrivate: $isPrivate, isPublished: $isPublished, locale: $locale, path: $path,
                             publishStartDate: $publishStartDate, publishEndDate: $publishEndDate,
                             scriptCss: $scriptCss, scriptJs: $scriptJs, tags: $tags, title: $title) {
                responseResult { succeeded errorCode slug message } } } }""",
            {
                "id": page.id, "content": content,
                "description": page.description if description is None else description,
                "editor": page.editor, "isPrivate": page.is_private, "isPublished": page.is_published,
                "locale": page.locale or self.cfg.locale, "path": page.path,
                "publishStartDate": page.publish_start or None, "publishEndDate": page.publish_end or None,
                "scriptCss": page.script_css, "scriptJs": page.script_js,
                "tags": page.tags if tags is None else tags,
                "title": page.title if title is None else title,
            },
        )
        self._check_result(data["pages"]["update"], "Seite aktualisieren")

    def page_url(self, path: str) -> str:
        return f"{self.cfg.url.rstrip('/')}/{self.cfg.locale}/{normalize_path(path)}"
