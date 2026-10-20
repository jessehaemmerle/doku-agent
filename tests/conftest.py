"""Test-Hilfen: In-Memory-Fakes für Wiki.js (GraphQL), Netbox (REST) und das LLM."""

from __future__ import annotations

import json
import re
from pathlib import Path

import httpx
import pytest

from doku_agent.config import Config
from doku_agent.context import Context
from doku_agent.egress import EgressGuard
from doku_agent.store import Store
from doku_agent.wiki import WikiClient


def make_config(tmp_path: Path, **overrides) -> Config:
    raw = {
        "general": {"data_dir": str(tmp_path / "data")},
        "llm": {"base_url": "http://ollama:11434"},
        "wiki": {"url": "https://wiki.test", "api_key": "k"},
        "netbox": {"url": "https://netbox.test", "token": "t", "site": "hq"},
        "wazuh": {"url": "https://wazuh.test:55000", "username": "u", "password": "p"},
        "web": {"password": "geheim"},
    }
    for key, value in overrides.items():
        raw.setdefault(key, {}).update(value)
    return Config.model_validate(raw)


class FakeWiki:
    """Minimaler Wiki.js-2-GraphQL-Server im Speicher."""

    def __init__(self):
        self.pages: dict[int, dict] = {}
        self.next_id = 1
        self.requests: list[dict] = []

    def add(self, path, title, content, tags=(), description="", **extra) -> int:
        pid = self.next_id
        self.next_id += 1
        self.pages[pid] = {
            "id": pid, "path": path, "locale": "de", "title": title, "description": description,
            "content": content, "contentType": "markdown", "editor": "markdown", "isPublished": True,
            "isPrivate": False, "publishStartDate": "", "publishEndDate": "", "scriptCss": "", "scriptJs": "",
            "updatedAt": f"2026-01-{pid:02d}T00:00:00Z", "hash": f"h{pid}", "tags": list(tags), **extra,
        }
        return pid

    def _full(self, p):
        return {**p, "tags": [{"tag": t} for t in p["tags"]]}

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        q, v = body["query"], body.get("variables", {})
        self.requests.append(body)
        if "list(" in q:
            data = {"pages": {"list": [{k: p[k] for k in ("id", "path", "locale", "title", "description", "tags",
                                                         "updatedAt")} for p in self.pages.values()]}}
        elif "singleByPath(" in q:
            page = next((p for p in self.pages.values() if p["path"] == v["path"]), None)
            if page is None:
                return httpx.Response(200, json={"errors": [{"message": "This page does not exist."}]})
            data = {"pages": {"singleByPath": self._full(page)}}
        elif "single(" in q:
            if v["id"] not in self.pages:
                return httpx.Response(200, json={"errors": [{"message": "This page does not exist."}]})
            data = {"pages": {"single": self._full(self.pages[v["id"]])}}
        elif "search(" in q:
            data = {"pages": {"search": {"results": []}}}
        elif "create(" in q:
            pid = self.add(v["path"], v["title"], v["content"], v["tags"], v["description"])
            data = {"pages": {"create": {"responseResult": {"succeeded": True, "errorCode": 0, "slug": "ok",
                                                            "message": ""}, "page": {"id": pid, "path": v["path"]}}}}
        elif "update(" in q:
            page = self.pages[v["id"]]
            for key in ("content", "title", "description", "tags", "isPublished", "scriptCss", "scriptJs", "path"):
                if v.get(key) is not None:
                    page[key] = v[key]
            data = {"pages": {"update": {"responseResult": {"succeeded": True, "errorCode": 0, "slug": "ok",
                                                            "message": ""}}}}
        else:
            return httpx.Response(400, json={"errors": [{"message": "unbekannte Query"}]})
        return httpx.Response(200, json={"data": data})


class FakeNetbox:
    """Netbox-REST im Speicher: GET-Listen mit einfachen Filtern, POST/PATCH/DELETE."""

    def __init__(self, version="4.7.3"):
        self.version = version
        self.objects: dict[str, dict[int, dict]] = {}
        self.next_id = 100
        self.log: list[tuple[str, str]] = []
        self.fail_on: str | None = None  # Endpunkt, dessen POST fehlschlägt

    def add(self, endpoint: str, obj: dict) -> dict:
        self.next_id += 1
        obj = {"id": self.next_id, **obj}
        self.objects.setdefault(endpoint, {})[obj["id"]] = obj
        return obj

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/api/").strip("/")
        self.log.append((request.method, path))
        if path == "status":
            return httpx.Response(200, json={"netbox-version": self.version})
        m = re.match(r"(.+?)/(\d+)$", path)
        endpoint, oid = (m.group(1), int(m.group(2))) if m else (path, None)
        store = self.objects.setdefault(endpoint, {})
        if request.method == "GET" and oid is None:
            params = {k: v for k, v in request.url.params.items() if k not in ("limit", "offset")}
            def ref_id(value):
                return value.get("id") if isinstance(value, dict) else value

            def matches(o, k, v):
                if k == "address":  # Netbox vergleicht Host-Adressen unabhängig von der Maske
                    return str(o.get(k, "")).split("/")[0] == v.split("/")[0]
                if endpoint == "ipam/ip-addresses" and k in ("device_id", "virtual_machine_id"):
                    # wie Netbox: IPs eines Geräts = IPs an dessen Interfaces
                    parent = "device" if k == "device_id" else "virtual_machine"
                    ifaces = self.objects.get("dcim/interfaces" if parent == "device" else "virtualization/interfaces", {})
                    ids = {i["id"] for i in ifaces.values() if str(ref_id(i.get(parent))) == v}
                    return o.get("assigned_object_id") in ids
                if k.endswith("_id") and k not in o:
                    return str(ref_id(o.get(k[:-3]))) == v
                return str(ref_id(o.get(k))) == v
            results = [o for o in store.values() if all(matches(o, k, v) for k, v in params.items())]
            return httpx.Response(200, json={"count": len(results), "next": None, "results": results})
        if request.method == "GET":
            return httpx.Response(200, json=store[oid])
        if request.method == "POST":
            if self.fail_on == endpoint:
                return httpx.Response(400, json={"detail": "kaputt"})
            return httpx.Response(201, json=self.add(endpoint, json.loads(request.content)))
        if request.method == "PATCH":
            store[oid].update(json.loads(request.content))
            return httpx.Response(200, json=store[oid])
        if request.method == "DELETE":
            store.pop(oid, None)
            return httpx.Response(204)
        return httpx.Response(405)


class FakeLLM:
    """Ersetzt das Sprachmodell: liefert vorbereitete Antworten der Reihe nach."""

    def __init__(self, json_answers=None, text_answer="Kurzbeschreibung."):
        self.json_answers = list(json_answers or [])
        self.text_answer = text_answer
        self.calls: list[tuple[str, str]] = []

    def json(self, system, user, schema):
        self.calls.append(("json", user))
        return self.json_answers.pop(0) if self.json_answers else {}

    def text(self, system, user):
        self.calls.append(("text", user))
        return self.text_answer

    def fit(self, text, max_chars=None):
        return text

    def condense(self, text, purpose):
        return text


@pytest.fixture
def fake_wiki():
    return FakeWiki()


@pytest.fixture
def ctx(tmp_path, fake_wiki):
    cfg = make_config(tmp_path)
    context = Context(cfg, Store(cfg.db_path))
    guard = EgressGuard.from_config(cfg)
    context.__dict__["wiki"] = WikiClient(cfg.wiki, guard, transport=httpx.MockTransport(fake_wiki.handler))
    context.__dict__["llm"] = FakeLLM()
    return context
