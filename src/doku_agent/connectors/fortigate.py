"""FortiGate REST-API (FortiOS 7.x), nur lesend.

Zugang: REST-API-Admin mit einem Admin-Profil, das nur Lesen erlaubt; das API-Token wird als
Bearer-Token gesendet. Feldnamen und Pfade sind gegen das FortiOS-Schema der offiziellen
Fortinet-Ansible-Collection geprüft (Pfade wie in der CLI: "firewall.service/custom").
"""

from __future__ import annotations

import httpx

from doku_agent.config import FortiGateDevice
from doku_agent.egress import EgressGuard


class FortiGateError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class FortiGateClient:
    def __init__(self, dev: FortiGateDevice, guard: EgressGuard, transport: httpx.BaseTransport | None = None):
        self.dev = dev
        self.http = guard.client(
            dev.url.rstrip("/"),
            verify=dev.verify_tls,
            headers={"Authorization": f"Bearer {dev.token}", "Accept": "application/json"},
            transport=transport,
            timeout=120,
        )

    def _get(self, path: str, vdom: str | None = None) -> dict:
        params = {"vdom": vdom} if vdom else None
        try:
            resp = self.http.get(f"/api/v2/{path.strip('/')}", params=params)
        except httpx.HTTPError as exc:
            raise FortiGateError(f"FortiGate {self.dev.name} nicht erreichbar: {exc}") from exc
        if resp.status_code != 200:
            raise FortiGateError(f"FortiGate {self.dev.name} GET {path}: HTTP {resp.status_code} {resp.text[:300]}",
                                 resp.status_code)
        return resp.json()

    def cmdb(self, path: str, vdom: str | None = None, optional: bool = False) -> list[dict]:
        """Alle Einträge einer Konfigurationstabelle (die CMDB liefert ohne Paging alles).
        optional: Tabelle fehlt auf manchen Modellen/Versionen (z.B. SSL-VPN) – dann leer statt Fehler."""
        try:
            results = self._get(f"cmdb/{path}", vdom).get("results")
        except FortiGateError as exc:
            if optional and exc.status in (404, 405, 424):
                return []
            raise
        if isinstance(results, dict):  # Einzelobjekte wie system/global
            return [results]
        return results or []

    def system(self) -> dict:
        """Hostname, Version, Seriennummer. Version und Seriennummer stehen in jeder API-Antwort."""
        data = self._get("cmdb/system/global")
        results = data.get("results") or {}
        if isinstance(results, list):
            results = results[0] if results else {}
        return {"hostname": results.get("hostname") or self.dev.name, "version": data.get("version", ""),
                "build": data.get("build", ""), "serial": data.get("serial", "")}

    def model(self) -> str:
        """Modellbezeichnung (z.B. "FortiGate-60F") aus dem Monitor-Endpunkt; leer, wenn nicht lesbar."""
        try:
            results = self._get("monitor/system/status").get("results") or {}
        except FortiGateError:
            return ""
        if results.get("model_name") and results.get("model_number"):
            return f"{results['model_name']}-{results['model_number']}"
        return results.get("model") or ""
