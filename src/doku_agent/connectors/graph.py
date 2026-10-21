"""Microsoft Graph – gemeinsame Basis für Intune und Entra ID (App-Registrierung, Client-Credentials).

Es werden ausschließlich GET-Anfragen an Graph gestellt (bzw. POST nur für die Anmeldung).
Fehlt der App-Registrierung eine Anwendungsberechtigung, nennt die Fehlermeldung genau diese.
"""

from __future__ import annotations

import json
import time
from urllib.parse import urlsplit

import httpx

from doku_agent.egress import EgressGuard

GRAPH = "https://graph.microsoft.com"

# Anwendungsberechtigung je Graph-Pfad (erster Treffer gilt) – für verständliche 403-Meldungen und 'check'
PERMISSIONS = (
    ("/deviceManagement/managedDevices", "DeviceManagementManagedDevices.Read.All"),
    ("/deviceManagement/", "DeviceManagementConfiguration.Read.All"),
    ("/deviceAppManagement/", "DeviceManagementApps.Read.All"),
    ("/identity/conditionalAccess/", "Policy.Read.All"),
    ("/policies/", "Policy.Read.All"),
    ("/roleManagement/", "RoleManagement.Read.Directory"),
    ("/servicePrincipals", "Application.Read.All"),
    ("/users", "User.Read.All"),
    ("/groups", "Group.Read.All"),
)
GROUP_FIELDS = "id,displayName,description,groupTypes,membershipRule,securityEnabled,mailEnabled"
GROUP_CACHE_SECONDS = 3600  # Gruppen werden in einem Lauf oft mehrfach gebraucht, ändern sich aber nachts


class GraphError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def required_permission(url: str) -> str:
    path = urlsplit(url).path
    return next((perm for prefix, perm in PERMISSIONS if prefix in path), "")


def graph_message(resp: httpx.Response) -> str:
    """Fehlertext von Graph; Intune verpackt ihn als JSON-String mit 'Message' und Operation-ID."""
    try:
        msg = resp.json()["error"]["message"]
    except (ValueError, KeyError, TypeError):
        return resp.text[:300]
    try:
        msg = json.loads(msg).get("Message", msg)
    except (ValueError, TypeError, AttributeError):
        pass
    return str(msg).split(" - Operation ID")[0].strip()[:300]


class GraphClient:
    def __init__(self, tenant_id: str, client_id: str, client_secret: str, guard: EgressGuard,
                 transport: httpx.BaseTransport | None = None, resolve_group_names: bool = True):
        self.tenant_id, self.client_id, self.client_secret = tenant_id, client_id, client_secret
        self.resolve_group_names = resolve_group_names
        self.http = guard.client(GRAPH, transport=transport, timeout=120)
        self.login = guard.client("https://login.microsoftonline.com", transport=transport, timeout=60)
        self._token: str | None = None
        self._expires = 0.0
        self._issued = 0.0
        self._groups: dict[str, tuple[float, dict]] = {}

    def _auth(self) -> str:
        if self._token and time.monotonic() < self._expires - 120:
            return self._token
        resp = self.login.post(
            f"/{self.tenant_id}/oauth2/v2.0/token",
            data={"grant_type": "client_credentials", "client_id": self.client_id,
                  "client_secret": self.client_secret, "scope": f"{GRAPH}/.default"},
        )
        if resp.status_code != 200:
            raise GraphError(f"Graph-Anmeldung fehlgeschlagen: HTTP {resp.status_code} {resp.text[:300]}")
        data = resp.json()
        self._token = data["access_token"]
        self._issued = time.monotonic()
        self._expires = self._issued + float(data.get("expires_in", 3600))
        return self._token

    def _request(self, url: str, params: dict | None = None, headers: dict | None = None,
                 retries: int = 3) -> httpx.Response:
        try:
            resp = self.http.get(url, params=params,
                                 headers={"Authorization": f"Bearer {self._auth()}", **(headers or {})})
        except httpx.HTTPError as exc:
            raise GraphError(f"Graph nicht erreichbar: {exc}") from exc
        if resp.status_code == 429 and retries > 0:  # Drosselung durch Graph
            retry_after = resp.headers.get("Retry-After", "10")
            time.sleep(min(int(retry_after) if retry_after.isdigit() else 10, 60))
            return self._request(url, params, headers, retries - 1)
        if resp.status_code == 403:
            # Neu erteilte Berechtigungen stehen erst in einem neuen Token -> beim nächsten Aufruf neu anmelden
            # (höchstens einmal pro Minute, falls die Berechtigung weiterhin fehlt)
            if time.monotonic() - self._issued > 60:
                self._token = None
            perm = required_permission(url)
            if perm:
                raise GraphError(
                    f"Graph GET {urlsplit(url).path}: HTTP 403 – der App-Registrierung fehlt die "
                    f"Anwendungsberechtigung {perm}. In Entra ID unter App-Registrierungen › API-Berechtigungen "
                    f"als Microsoft-Graph-Anwendungsberechtigung (nicht delegiert) hinzufügen und die "
                    f"Administratorzustimmung erteilen. (Graph: {graph_message(resp)})", 403)
        if resp.status_code != 200:
            raise GraphError(f"Graph GET {url}: HTTP {resp.status_code} {resp.text[:300]}", resp.status_code)
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
                raise GraphError(f"Unerwarteter nextLink-Host: {next_link}")
            url, query = next_link, None
        return out

    def _missing(self, probes: dict[str, tuple[str, dict | None]]) -> dict[str, list[str]]:
        """Fehlende Anwendungsberechtigung -> betroffene Bereiche (je Bereich eine Probe-Abfrage)."""
        missing: dict[str, list[str]] = {}
        for area, (path, params) in probes.items():
            try:
                self._request(path, params)
            except GraphError as exc:
                if exc.status != 403:
                    raise
                missing.setdefault(required_permission(path), []).append(area)
        return missing

    # --- Entra-Gruppen (braucht Group.Read.All) ------------------------------

    def group(self, group_id: str) -> dict:
        """Gruppe mit Name, Art und dynamischer Regel; ohne Berechtigung nur die ID.
        Gelöschte Gruppen sind mit '_deleted' markiert."""
        if not self.resolve_group_names or not group_id:
            return {"id": group_id, "displayName": group_id}
        cached = self._groups.get(group_id)
        if cached is None or time.monotonic() - cached[0] > GROUP_CACHE_SECONDS:
            try:
                group = self._get(f"/v1.0/groups/{group_id}", {"$select": GROUP_FIELDS})
            except GraphError as exc:
                group = {"id": group_id, "displayName": group_id, "_deleted": exc.status == 404}
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
            except (GraphError, ValueError):
                counts[kind] = None
        return counts
