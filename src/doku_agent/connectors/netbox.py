"""Netbox 4.x REST-Client (Feldnamen verifiziert gegen Netbox 4.7)."""

from __future__ import annotations

import httpx

from doku_agent.config import NetboxConfig
from doku_agent.egress import EgressGuard


class NetboxError(RuntimeError):
    pass


def _clean(endpoint: str) -> str:
    return "/api/" + endpoint.strip("/") + "/"


class NetboxClient:
    PAGE_SIZE = 1000

    def __init__(self, cfg: NetboxConfig, guard: EgressGuard, transport: httpx.BaseTransport | None = None):
        self.cfg = cfg
        # v2-Tokens (ab Netbox 4.5) beginnen mit "nbt_" und werden als Bearer gesendet.
        keyword = "Bearer" if cfg.token.startswith("nbt_") else "Token"
        self.http = guard.client(
            cfg.url.rstrip("/"),
            verify=cfg.verify_tls,
            headers={"Authorization": f"{keyword} {cfg.token}", "Accept": "application/json"},
            transport=transport,
        )
        self._version: tuple[int, int] | None = None

    def _request(self, method: str, endpoint: str, **kwargs) -> httpx.Response:
        try:
            resp = self.http.request(method, _clean(endpoint), **kwargs)
        except httpx.HTTPError as exc:
            raise NetboxError(f"Netbox nicht erreichbar: {exc}") from exc
        if resp.status_code >= 400:
            raise NetboxError(f"Netbox {method} {endpoint}: HTTP {resp.status_code} {resp.text[:500]}")
        return resp

    def version(self) -> tuple[int, int]:
        if self._version is None:
            raw = str(self._request("GET", "status").json().get("netbox-version", "0.0"))
            major, minor = (raw.split("-")[0].split(".") + ["0"])[:2]
            self._version = (int(major), int(minor))
        return self._version

    @property
    def has_mac_objects(self) -> bool:
        """Ab Netbox 4.2 sind MAC-Adressen eigene Objekte (dcim/mac-addresses)."""
        return self.version() >= (4, 2)

    def get(self, endpoint: str, obj_id: int) -> dict:
        return self._request("GET", f"{endpoint.strip('/')}/{obj_id}").json()

    def list(self, endpoint: str, **filters) -> list[dict]:
        """Alle Objekte; paginiert per offset (die 'next'-URL kann einen anderen Host enthalten)."""
        out, offset = [], 0
        while True:
            params = {**filters, "limit": self.PAGE_SIZE, "offset": offset}
            data = self._request("GET", endpoint, params=params).json()
            out.extend(data.get("results", []))
            offset += self.PAGE_SIZE
            if not data.get("next") or offset >= data.get("count", 0):
                return out

    def find_one(self, endpoint: str, **filters) -> dict | None:
        data = self._request("GET", endpoint, params={**filters, "limit": 2}).json()
        results = data.get("results", [])
        return results[0] if len(results) == 1 else None

    def create(self, endpoint: str, data: dict) -> dict:
        return self._request("POST", endpoint, json=data).json()

    def update(self, endpoint: str, obj_id: int, data: dict) -> dict:
        return self._request("PATCH", f"{endpoint.strip('/')}/{obj_id}", json=data).json()

    def delete(self, endpoint: str, obj_id: int) -> None:
        self._request("DELETE", f"{endpoint.strip('/')}/{obj_id}")

    def ui_url(self, endpoint: str, obj_id: int) -> str:
        return f"{self.cfg.url.rstrip('/')}/{endpoint.strip('/')}/{obj_id}/"
