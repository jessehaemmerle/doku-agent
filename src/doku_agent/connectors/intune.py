"""Microsoft Intune über Microsoft Graph – nur lesend (App-Registrierung, Client-Credentials).

Benötigte Anwendungsberechtigungen (alle *.Read.All):
  DeviceManagementManagedDevices.Read.All, DeviceManagementConfiguration.Read.All,
  DeviceManagementApps.Read.All, optional Group.Read.All (Gruppennamen in Zuweisungen).
Es werden ausschließlich GET-Anfragen an Graph gestellt; Inhalte gehen nie an ein LLM außerhalb.
"""

from __future__ import annotations

import time
from urllib.parse import urlsplit

import httpx

from doku_agent.config import IntuneConfig
from doku_agent.egress import EgressGuard

GRAPH = "https://graph.microsoft.com"
DEVICE_FIELDS = ("id,deviceName,serialNumber,manufacturer,model,operatingSystem,osVersion,wiFiMacAddress,"
                 "azureADDeviceId,userPrincipalName,lastSyncDateTime,complianceState,managedDeviceOwnerType")


class IntuneError(RuntimeError):
    pass


class IntuneClient:
    def __init__(self, cfg: IntuneConfig, guard: EgressGuard, transport: httpx.BaseTransport | None = None):
        self.cfg = cfg
        self.http = guard.client(GRAPH, transport=transport, timeout=120)
        self.login = guard.client("https://login.microsoftonline.com", transport=transport, timeout=60)
        self._token: str | None = None
        self._expires = 0.0
        self._group_names: dict[str, str] = {}

    def _auth(self) -> str:
        if self._token and time.monotonic() < self._expires - 120:
            return self._token
        resp = self.login.post(
            f"/{self.cfg.tenant_id}/oauth2/v2.0/token",
            data={"grant_type": "client_credentials", "client_id": self.cfg.client_id,
                  "client_secret": self.cfg.client_secret, "scope": f"{GRAPH}/.default"},
        )
        if resp.status_code != 200:
            raise IntuneError(f"Graph-Anmeldung fehlgeschlagen: HTTP {resp.status_code} {resp.text[:300]}")
        data = resp.json()
        self._token = data["access_token"]
        self._expires = time.monotonic() + float(data.get("expires_in", 3600))
        return self._token

    def _get(self, url: str, params: dict | None = None, retries: int = 3) -> dict:
        try:
            resp = self.http.get(url, params=params, headers={"Authorization": f"Bearer {self._auth()}"})
        except httpx.HTTPError as exc:
            raise IntuneError(f"Graph nicht erreichbar: {exc}") from exc
        if resp.status_code == 429 and retries > 0:  # Drosselung durch Graph
            retry_after = resp.headers.get("Retry-After", "10")
            time.sleep(min(int(retry_after) if retry_after.isdigit() else 10, 60))
            return self._get(url, params, retries - 1)
        if resp.status_code != 200:
            raise IntuneError(f"Graph GET {url}: HTTP {resp.status_code} {resp.text[:300]}")
        return resp.json()

    def _all(self, path: str, params: dict | None = None) -> list[dict]:
        out, url, query = [], path, params
        while url:
            data = self._get(url, query)
            out.extend(data.get("value", []))
            next_link = data.get("@odata.nextLink")
            if next_link and urlsplit(next_link).hostname != "graph.microsoft.com":
                raise IntuneError(f"Unerwarteter nextLink-Host: {next_link}")
            url, query = next_link, None
        return out

    # --- Geräte ----------------------------------------------------------

    def managed_devices(self) -> list[dict]:
        return self._all("/v1.0/deviceManagement/managedDevices", {"$select": DEVICE_FIELDS})

    def ethernet_mac(self, device_id: str) -> str:
        data = self._get(f"/v1.0/deviceManagement/managedDevices/{device_id}", {"$select": "ethernetMacAddress"})
        return data.get("ethernetMacAddress") or ""

    # --- Richtlinien & Apps ---------------------------------------------

    def compliance_policies(self) -> list[dict]:
        return self._with_assignments("/v1.0/deviceManagement/deviceCompliancePolicies")

    def device_configurations(self) -> list[dict]:
        return self._with_assignments("/v1.0/deviceManagement/deviceConfigurations")

    def settings_catalog_policies(self) -> list[dict]:
        # Settings Catalog gibt es nur in /beta.
        policies = self._with_assignments("/beta/deviceManagement/configurationPolicies")
        for pol in policies:
            pol["_settings"] = self._all(f"/beta/deviceManagement/configurationPolicies/{pol['id']}/settings",
                                         {"$expand": "settingDefinitions"})
        return policies

    def mobile_apps(self) -> list[dict]:
        return self._with_assignments("/v1.0/deviceAppManagement/mobileApps")

    def _with_assignments(self, path: str) -> list[dict]:
        items = self._all(path)
        for item in items:
            try:
                item["_assignments"] = self._all(f"{path}/{item['id']}/assignments")
            except IntuneError:
                item["_assignments"] = []
        return items

    def group_name(self, group_id: str) -> str:
        if not self.cfg.resolve_group_names or not group_id:
            return group_id
        if group_id not in self._group_names:
            try:
                self._group_names[group_id] = self._get(f"/v1.0/groups/{group_id}",
                                                        {"$select": "displayName"}).get("displayName", group_id)
            except IntuneError:
                self._group_names[group_id] = group_id
        return self._group_names[group_id]
