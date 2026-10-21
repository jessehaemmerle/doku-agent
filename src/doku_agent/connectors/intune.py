"""Microsoft Intune über Microsoft Graph – nur lesend (App-Registrierung, Client-Credentials).

Benötigte Anwendungsberechtigungen (alle *.Read.All):
  DeviceManagementManagedDevices.Read.All, DeviceManagementConfiguration.Read.All,
  DeviceManagementApps.Read.All, optional Group.Read.All (Gruppennamen, Art und Mitgliederzahlen).
Es werden ausschließlich GET-Anfragen an Graph gestellt; Inhalte gehen nie an ein LLM außerhalb.
"""

from __future__ import annotations

import httpx

from doku_agent.config import IntuneConfig
from doku_agent.connectors.graph import GraphClient
from doku_agent.connectors.graph import GraphError as IntuneError
from doku_agent.egress import EgressGuard

__all__ = ["IntuneClient", "IntuneError", "POLICY_PATHS", "PROBES"]

DEVICE_FIELDS = ("id,deviceName,serialNumber,manufacturer,model,operatingSystem,osVersion,wiFiMacAddress,"
                 "azureADDeviceId,userPrincipalName,lastSyncDateTime,complianceState,managedDeviceOwnerType")

# Pfade der Richtlinienarten (Kategorie wie in den Wiki-Pfaden)
POLICY_PATHS = {
    "compliance": "/v1.0/deviceManagement/deviceCompliancePolicies",
    "konfigurationsprofile": "/v1.0/deviceManagement/deviceConfigurations",
    "settings-catalog": "/beta/deviceManagement/configurationPolicies",  # nur in /beta
}
# Bereiche aus intune.include -> Pfad für die Probe-Abfrage in 'doku-agent check'
PROBES = {
    "compliance": "/v1.0/deviceManagement/deviceCompliancePolicies",
    "configurations": "/v1.0/deviceManagement/deviceConfigurations",
    "settings_catalog": "/beta/deviceManagement/configurationPolicies",
    "apps": "/v1.0/deviceAppManagement/mobileApps",
    "groups": "/v1.0/groups",
}


class IntuneClient(GraphClient):
    def __init__(self, cfg: IntuneConfig, guard: EgressGuard, transport: httpx.BaseTransport | None = None):
        super().__init__(cfg.tenant_id, cfg.client_id, cfg.client_secret, guard, transport,
                         resolve_group_names=cfg.resolve_group_names)
        self.cfg = cfg

    def missing_permissions(self, areas) -> dict[str, list[str]]:
        """Fehlende Anwendungsberechtigung -> betroffene Bereiche (je Bereich eine Probe-Abfrage)."""
        return self._missing({a: (PROBES[a], {"$top": "1", "$select": "id"} if a == "groups" else None)
                              for a in areas if a in PROBES})

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
