"""VMware vCenter (vSphere Automation API "/api", ab 7.0 U2), nur lesend.

Cluster, Hosts und VMs kommen aus der Automation-API. Hersteller, Modell und Seriennummer der
ESXi-Hosts liefert nur die VI/JSON-API (ab vCenter 8.0 U1); ist sie nicht verfügbar, bleiben diese
Angaben leer. Feldnamen geprüft gegen die Referenz auf developer.broadcom.com.
"""

from __future__ import annotations

import time
import uuid as uuidlib

import httpx

from doku_agent.config import VCenterConfig
from doku_agent.egress import EgressGuard

SESSION_HEADER = "vmware-api-session-id"


class VCenterError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def vmware_serial(bios_uuid: str) -> str:
    """BIOS-UUID -> Seriennummer, wie sie das Gastsystem (und damit Wazuh/Intune) meldet:
    421a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8 -> 'VMware-42 1a 2b 3c 4d 5e 6f 70-81 92 a3 b4 c5 d6 e7 f8'."""
    try:
        raw = uuidlib.UUID(bios_uuid).hex
    except (ValueError, AttributeError, TypeError):
        return ""
    pairs = [raw[i:i + 2] for i in range(0, 32, 2)]
    return "VMware-" + " ".join(pairs[:8]) + "-" + " ".join(pairs[8:])


class VCenterClient:
    def __init__(self, cfg: VCenterConfig, guard: EgressGuard, transport: httpx.BaseTransport | None = None):
        self.cfg = cfg
        self.http = guard.client(cfg.url.rstrip("/"), verify=cfg.verify_tls, transport=transport, timeout=120)
        self._token: str | None = None
        self._vim_token: str | None = None
        self._vim_login_failed = False

    # --- Automation API -----------------------------------------------------

    def _login(self) -> str:
        try:
            resp = self.http.post("/api/session", auth=(self.cfg.username, self.cfg.password))
        except httpx.HTTPError as exc:
            raise VCenterError(f"vCenter nicht erreichbar: {exc}") from exc
        if resp.status_code not in (200, 201):
            raise VCenterError(f"vCenter-Anmeldung fehlgeschlagen: HTTP {resp.status_code}", resp.status_code)
        self._token = resp.json()
        return self._token

    def _get(self, path: str, params: dict | None = None, retry: bool = True):
        token = self._token or self._login()
        try:
            resp = self.http.get(path, params=params, headers={SESSION_HEADER: token})
        except httpx.HTTPError as exc:
            raise VCenterError(f"vCenter nicht erreichbar: {exc}") from exc
        if resp.status_code == 401 and retry:  # Sitzung abgelaufen
            self._token = None
            return self._get(path, params, retry=False)
        if resp.status_code != 200:
            raise VCenterError(f"vCenter GET {path}: HTTP {resp.status_code} {resp.text[:300]}", resp.status_code)
        return resp.json()

    def clusters(self) -> list[dict]:
        return self._get("/api/vcenter/cluster")

    def hosts(self, cluster: str | None = None) -> list[dict]:
        return self._get("/api/vcenter/host", {"clusters": cluster} if cluster else None)

    def vms(self, host: str | None = None) -> list[dict]:
        return self._get("/api/vcenter/vm", {"hosts": host} if host else None)

    def vm(self, vm_id: str) -> dict:
        return self._get(f"/api/vcenter/vm/{vm_id}")

    def _guest(self, path: str):
        """Gastdaten gibt es nur mit laufenden VMware Tools; sonst 503 (bzw. 404 bei alten Versionen)."""
        try:
            return self._get(path)
        except VCenterError as exc:
            if exc.status in (404, 503):
                return None
            raise

    def guest_identity(self, vm_id: str) -> dict | None:
        return self._guest(f"/api/vcenter/vm/{vm_id}/guest/identity")

    def guest_interfaces(self, vm_id: str) -> list[dict] | None:
        return self._guest(f"/api/vcenter/vm/{vm_id}/guest/networking/interfaces")

    # --- VI/JSON (Host-Hardware) ------------------------------------------------

    def _vim(self, path: str, method: str = "GET", json: dict | None = None) -> httpx.Response:
        url = f"/sdk/vim25/{self.cfg.vijson_release}/{path}"
        headers = {SESSION_HEADER: self._vim_token} if self._vim_token else {}
        try:
            return self.http.request(method, url, json=json, headers=headers)
        except httpx.HTTPError as exc:
            raise VCenterError(f"vCenter (VI/JSON) nicht erreichbar: {exc}") from exc

    def _vim_login(self) -> bool:
        if self._vim_token:
            return True
        if self._vim_login_failed or not self.cfg.vijson_release:
            return False
        resp = self._vim("ServiceInstance/ServiceInstance/content")
        manager = (resp.json().get("sessionManager") or {}).get("value") if resp.status_code == 200 else None
        if manager:
            resp = self._vim(f"SessionManager/{manager}/Login", "POST",
                             {"userName": self.cfg.username, "password": self.cfg.password})
            if resp.status_code == 200:
                self._vim_token = resp.headers.get(SESSION_HEADER) or (resp.json() or {}).get("key")
        self._vim_login_failed = not self._vim_token
        return bool(self._vim_token)

    def host_hardware(self, host_id: str) -> dict:
        """{'vendor', 'model', 'serial'} eines ESXi-Hosts; leer, wenn VI/JSON nicht verfügbar ist."""
        if not self._vim_login():
            return {}
        resp = self._vim(f"HostSystem/{host_id}/hardware")
        if resp.status_code != 200:
            return {}
        info = resp.json().get("systemInfo") or {}
        serial = info.get("serialNumber") or ""
        if not serial:  # ältere Hosts: Seriennummer nur in den herstellerspezifischen Kennungen
            for ident in info.get("otherIdentifyingInfo") or []:
                key = (ident.get("identifierType") or {}).get("key", "")
                if key in ("SerialNumberTag", "ServiceTag", "EnclosureSerialNumberTag") and ident.get("identifierValue"):
                    serial = ident["identifierValue"].strip()
                    break
        return {"vendor": (info.get("vendor") or "").strip(), "model": (info.get("model") or "").strip(),
                "serial": serial.strip(), "at": time.time()}
