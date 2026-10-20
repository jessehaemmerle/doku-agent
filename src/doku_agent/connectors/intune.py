"""Microsoft Intune über Microsoft Graph – nur lesend (App-Registrierung, Client-Credentials).

Benötigte Anwendungsberechtigungen (alle *.Read.All):
  DeviceManagementManagedDevices.Read.All, DeviceManagementConfiguration.Read.All,
  DeviceManagementApps.Read.All, optional Group.Read.All (Gruppennamen, Art und Mitgliederzahlen).
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
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


# Pfade der Richtlinienarten (Kategorie wie in den Wiki-Pfaden)
POLICY_PATHS = {
    "compliance": "/v1.0/deviceManagement/deviceCompliancePolicies",
    "konfigurationsprofile": "/v1.0/deviceManagement/deviceConfigurations",
    "settings-catalog": "/beta/deviceManagement/configurationPolicies",  # nur in /beta
}
GROUP_FIELDS = "id,displayName,description,groupTypes,membershipRule,securityEnabled,mailEnabled"
GROUP_CACHE_SECONDS = 3600  # Gruppen werden in einem Lauf oft mehrfach gebraucht, ändern sich aber nachts


class IntuneClient:
    def __init__(self, cfg: IntuneConfig, guard: EgressGuard, transport: httpx.BaseTransport | None = None):
        self.cfg = cfg
        self.http = guard.client(GRAPH, transport=transport, timeout=120)
        self.login = guard.client("https://login.microsoftonline.com", transport=transport, timeout=60)
        self._token: str | None = None
        self._expires = 0.0
        self._groups: dict[str, tuple[float, dict]] = {}

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

    def _request(self, url: str, params: dict | None = None, headers: dict | None = None,
                 retries: int = 3) -> httpx.Response:
        try:
            resp = self.http.get(url, params=params,
                                 headers={"Authorization": f"Bearer {self._auth()}", **(headers or {})})
        except httpx.HTTPError as exc:
            raise IntuneError(f"Graph nicht erreichbar: {exc}") from exc
        if resp.status_code == 429 and retries > 0:  # Drosselung durch Graph
            retry_after = resp.headers.get("Retry-After", "10")
            time.sleep(min(int(retry_after) if retry_after.isdigit() else 10, 60))
            return self._request(url, params, headers, retries - 1)
        if resp.status_code != 200:
            raise IntuneError(f"Graph GET {url}: HTTP {resp.status_code} {resp.text[:300]}", resp.status_code)
        return resp

    def _get(self, url: str, params: dict | None = None) -> dict:
        return self._request(url, params).json()

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

    def settings_catalog_policies(self, with_settings: bool = True) -> list[dict]:
        # Settings Catalog gibt es nur in /beta.
        policies = self._with_assignments("/beta/deviceManagement/configurationPolicies")
        for pol in policies if with_settings else []:
            pol["_settings"] = self._settings(pol["id"])
        return policies

    def _settings(self, policy_id: str) -> list[dict]:
        return self._all(f"/beta/deviceManagement/configurationPolicies/{policy_id}/settings",
                         {"$expand": "settingDefinitions"})

    def policy(self, category: str, policy_id: str) -> dict:
        """Eine einzelne Richtlinie samt Zuweisungen (und Einstellungen beim Settings Catalog).
        Gelöschte Richtlinien liefern IntuneError mit status 404."""
        path = POLICY_PATHS[category]
        pol = self._get(f"{path}/{policy_id}")
        try:
            pol["_assignments"] = self._all(f"{path}/{policy_id}/assignments")
        except IntuneError:
            pol["_assignments"] = []
        if category == "settings-catalog":
            pol["_settings"] = self._settings(policy_id)
        return pol

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

    # --- Entra-Gruppen (braucht Group.Read.All) ------------------------------

    def group(self, group_id: str) -> dict:
        """Gruppe mit Name, Art und dynamischer Regel; ohne Berechtigung nur die ID."""
        if not self.cfg.resolve_group_names or not group_id:
            return {"id": group_id, "displayName": group_id}
        cached = self._groups.get(group_id)
        if cached is None or time.monotonic() - cached[0] > GROUP_CACHE_SECONDS:
            try:
                group = self._get(f"/v1.0/groups/{group_id}", {"$select": GROUP_FIELDS})
            except IntuneError:
                group = {"id": group_id, "displayName": group_id}
            cached = (time.monotonic(), group)
            self._groups[group_id] = cached
        return cached[1]

    def group_name(self, group_id: str) -> str:
        return self.group(group_id).get("displayName") or group_id

    def member_counts(self, group_id: str) -> dict[str, int | None]:
        """Mitglieder inkl. verschachtelter Gruppen, getrennt nach Benutzern, Geräten und Gruppen.
        None, wenn Graph die Zählung ablehnt (z.B. Untergruppen bei Microsoft-365-Gruppen)."""
        counts: dict[str, int | None] = {}
        for kind in ("user", "device", "group"):
            try:
                resp = self._request(f"/v1.0/groups/{group_id}/transitiveMembers/microsoft.graph.{kind}/$count",
                                     headers={"ConsistencyLevel": "eventual"})
                counts[kind] = int(resp.text.strip())
            except (IntuneError, ValueError):
                counts[kind] = None
        return counts
