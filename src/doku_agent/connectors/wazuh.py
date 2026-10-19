"""Wazuh 4.x Server-API (read-only; Endpunkte verifiziert gegen die Spezifikation von v4.14.9)."""

from __future__ import annotations

import time

import httpx

from doku_agent.config import WazuhConfig
from doku_agent.egress import EgressGuard


class WazuhError(RuntimeError):
    pass


class WazuhClient:
    PAGE_SIZE = 500

    def __init__(self, cfg: WazuhConfig, guard: EgressGuard, transport: httpx.BaseTransport | None = None):
        self.cfg = cfg
        self.http = guard.client(cfg.url.rstrip("/"), verify=cfg.verify_tls, transport=transport, timeout=120)
        self._token: str | None = None
        self._token_time = 0.0

    def _auth(self) -> str:
        # Token gilt standardmäßig 900 s; nach 10 Minuten wird vorsorglich erneuert.
        if self._token and time.monotonic() - self._token_time < 600:
            return self._token
        try:
            resp = self.http.post("/security/user/authenticate", auth=(self.cfg.username, self.cfg.password))
        except httpx.HTTPError as exc:
            raise WazuhError(f"Wazuh-API nicht erreichbar: {exc}") from exc
        if resp.status_code != 200:
            raise WazuhError(f"Wazuh-Anmeldung fehlgeschlagen: HTTP {resp.status_code}")
        self._token = resp.json()["data"]["token"]
        self._token_time = time.monotonic()
        return self._token

    def _get(self, path: str, params: dict | None = None, raw: bool = False):
        headers = {"Authorization": f"Bearer {self._auth()}"}
        params = dict(params or {})
        if raw:
            params["raw"] = "true"
        try:
            resp = self.http.get(path, params=params, headers=headers)
        except httpx.HTTPError as exc:
            raise WazuhError(f"Wazuh-API nicht erreichbar: {exc}") from exc
        if resp.status_code != 200:
            raise WazuhError(f"Wazuh GET {path}: HTTP {resp.status_code} {resp.text[:300]}")
        return resp.text if raw else resp.json()

    def items(self, path: str, params: dict | None = None) -> list[dict]:
        out, offset = [], 0
        while True:
            data = self._get(path, {**(params or {}), "offset": offset, "limit": self.PAGE_SIZE})["data"]
            batch = data.get("affected_items", [])
            out.extend(batch)
            offset += len(batch)
            if not batch or offset >= data.get("total_affected_items", 0):
                return out

    # --- Regeln, Decoder, Konfiguration ----------------------------------

    def rule_files(self) -> list[dict]:
        return self.items("/rules/files", {"relative_dirname": self.cfg.rules_dir})

    def rule_file(self, filename: str) -> str:
        return self._get(f"/rules/files/{filename}", {"relative_dirname": self.cfg.rules_dir}, raw=True)

    def decoder_files(self) -> list[dict]:
        return self.items("/decoders/files", {"relative_dirname": self.cfg.decoders_dir})

    def decoder_file(self, filename: str) -> str:
        return self._get(f"/decoders/files/{filename}", {"relative_dirname": self.cfg.decoders_dir}, raw=True)

    def manager_config(self) -> str:
        return self._get("/manager/configuration", raw=True)

    def groups(self) -> list[dict]:
        return self.items("/groups")

    def group_agent_conf(self, group: str) -> str:
        return self._get(f"/groups/{group}/files/agent.conf", raw=True)

    # --- Agents, Inventar, SCA -------------------------------------------

    def agents(self, status: str | None = None) -> list[dict]:
        # "os" allein ist kein gültiges select-Feld, nur die Unterfelder (geprüft gegen Wazuh 4.14).
        params = {"select": "id,name,ip,registerIP,status,os.name,os.platform,os.version,version,group,lastKeepAlive"}
        if status:
            params["status"] = status
        return self.items("/agents", params)

    def _first(self, path: str) -> dict:
        # hardware/os liefern genau einen Eintrag und erlauben kein offset/limit (Wazuh 4.14).
        items = self._get(path)["data"].get("affected_items", [])
        return items[0] if items else {}

    def hardware(self, agent_id: str) -> dict:
        return self._first(f"/syscollector/{agent_id}/hardware")

    def os_info(self, agent_id: str) -> dict:
        return self._first(f"/syscollector/{agent_id}/os")

    def interfaces(self, agent_id: str) -> list[dict]:
        return self.items(f"/syscollector/{agent_id}/netiface")

    def addresses(self, agent_id: str) -> list[dict]:
        return self.items(f"/syscollector/{agent_id}/netaddr")

    def sca_policies(self, agent_id: str) -> list[dict]:
        return self.items(f"/sca/{agent_id}")

    def sca_failed_checks(self, agent_id: str, policy_id: str) -> list[dict]:
        return self.items(f"/sca/{agent_id}/checks/{policy_id}", {"result": "failed"})
