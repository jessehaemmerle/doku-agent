"""Entra ID über Microsoft Graph – nur lesend (App-Registrierung, Client-Credentials).

Benötigte Anwendungsberechtigungen (geprüft gegen Microsoft Learn, Graph v1.0):
  Policy.Read.All                Conditional Access, benannte Standorte, Authentifizierungsstärken und -methoden,
                                 Sicherheitsstandards, Autorisierungs-, Zustimmungs- und Cross-Tenant-Richtlinien
  RoleManagement.Read.Directory  Rollen, Zuweisungen und PIM (berechtigte bzw. befristete Zuweisungen)
  User.Read.All                  Benutzernamen und Notfallkonten
  Group.Read.All                 Gruppennamen und -mitglieder
  Application.Read.All           Namen der Ziel-Apps (optional, sonst App-IDs)
"""

from __future__ import annotations

import re
import time
from urllib.parse import quote

import httpx

from doku_agent.config import EntraConfig, IntuneConfig
from doku_agent.connectors.graph import GraphClient, GraphError
from doku_agent.egress import EgressGuard

USER_FIELDS = "id,displayName,userPrincipalName,userType,accountEnabled"
GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
# Bereiche aus entra.include -> Probe-Abfrage für 'doku-agent check'
PROBES = {
    "conditional_access": ("/v1.0/identity/conditionalAccess/policies", {"$top": "1"}),
    "auth_methods": ("/v1.0/policies/authenticationMethodsPolicy", None),
    "tenant_settings": ("/v1.0/policies/authorizationPolicy", None),
    "roles": ("/v1.0/roleManagement/directory/roleDefinitions", {"$top": "1"}),
    "users": ("/v1.0/users", {"$top": "1", "$select": "id"}),
    "groups": ("/v1.0/groups", {"$top": "1", "$select": "id"}),
    "apps": ("/v1.0/servicePrincipals", {"$top": "1", "$select": "id"}),
}
CACHE_SECONDS = 3600


def _server_error(exc: GraphError) -> bool:
    return exc.status is not None and exc.status >= 500


def unavailable(exc: GraphError) -> bool:
    """Dauerhaft nicht verfügbar (Lizenz, Berechtigung, Endpunkt) statt vorübergehend gestört (429, 5xx)."""
    return exc.status is not None and 400 <= exc.status < 500 and exc.status != 429


class EntraClient(GraphClient):
    def __init__(self, cfg: EntraConfig, intune: IntuneConfig, guard: EgressGuard,
                 transport: httpx.BaseTransport | None = None):
        # Ohne eigenen Zugang wird die App-Registrierung von Intune verwendet
        super().__init__(cfg.tenant_id or intune.tenant_id, cfg.client_id or intune.client_id,
                         cfg.client_secret or intune.client_secret, guard, transport)
        self.cfg = cfg
        self._users: dict[str, tuple[float, dict]] = {}
        self._ca_beta_until = 0.0
        self.notes: list[str] = []  # Hinweise für das Job-Protokoll (z.B. Ausweichen auf beta)
        self._apps: dict[str, dict | None] = {}
        self._members: dict[str, set[str] | None] = {}

    def missing_permissions(self, areas) -> dict[str, list[str]]:
        probes = {a: PROBES[a] for a in areas if a in PROBES}
        if "conditional_access" in probes and self.ca_via_beta:
            path, params = probes["conditional_access"]
            probes["conditional_access"] = (path.replace("/v1.0/", "/beta/", 1), params)
        try:
            return self._missing(probes)
        except GraphError as exc:
            if "conditional_access" not in probes or not _server_error(exc) or self.ca_via_beta:
                raise
            self._use_beta(exc)
            return self.missing_permissions(areas)

    # --- Conditional Access ---------------------------------------------------
    # Antwortet Graph v1.0 bei Conditional Access dauerhaft mit 5xx, wird für eine Stunde über beta gelesen. Eine
    # mögliche (nicht dokumentierte) Ursache sind Richtlinien mit Vorschau-Funktionen, die nur beta abbildet; das
    # Schema dort ist eine Obermenge, die Auswertung bleibt gleich.

    @property
    def ca_via_beta(self) -> bool:
        return time.monotonic() < self._ca_beta_until

    def _use_beta(self, exc: GraphError) -> None:
        self._ca_beta_until = time.monotonic() + 3600
        self.notes.append(f"Conditional Access wird über Graph beta gelesen, weil v1.0 mit HTTP {exc.status} "
                          f"antwortet (Fehler bei Microsoft). Ursprüngliche Meldung: {exc}")

    def _ca(self, suffix: str, single: bool = False):
        for version in (("beta",) if self.ca_via_beta else ("v1.0", "beta")):
            path = f"/{version}/identity/conditionalAccess/{suffix}"
            try:
                return self._get(path) if single else self._all(path)
            except GraphError as exc:
                if version == "beta" or not _server_error(exc):
                    raise
                self._use_beta(exc)

    def ca_policies(self) -> list[dict]:
        return self._ca("policies")

    def ca_policy(self, policy_id: str) -> dict:
        """Gelöschte Richtlinien liefern GraphError mit status 404."""
        return self._ca(f"policies/{policy_id}", single=True)

    def named_locations(self) -> list[dict]:
        return self._ca("namedLocations")

    def auth_strengths(self) -> list[dict]:
        return self._all("/v1.0/policies/authenticationStrengthPolicies")

    # --- Methoden und Mandant ---------------------------------------------------

    def auth_methods_policy(self) -> dict:
        return self._get("/v1.0/policies/authenticationMethodsPolicy")

    def security_defaults(self) -> dict:
        return self._get("/v1.0/policies/identitySecurityDefaultsEnforcementPolicy")

    def authorization_policy(self) -> dict:
        data = self._get("/v1.0/policies/authorizationPolicy")
        return (data.get("value") or [{}])[0] if "value" in data else data

    def cross_tenant_default(self) -> dict:
        return self._get("/v1.0/policies/crossTenantAccessPolicy/default")

    def cross_tenant_partners(self) -> list[dict]:
        return self._all("/v1.0/policies/crossTenantAccessPolicy/partners")

    def admin_consent_policy(self) -> dict:
        return self._get("/v1.0/policies/adminConsentRequestPolicy")

    # --- Rollen -------------------------------------------------------------------

    def role_definitions(self) -> list[dict]:
        return self._all("/v1.0/roleManagement/directory/roleDefinitions",
                         {"$select": "id,displayName,templateId,isBuiltIn,description"})

    def role_assignments(self) -> list[dict]:
        """Aktive Zuweisungen mit Prinzipal. Mit PIM die Instanzen (dauerhaft, befristet, aktiviert),
        sonst die einfachen Zuweisungen."""
        try:
            items = self._all("/v1.0/roleManagement/directory/roleAssignmentScheduleInstances",
                              {"$expand": "principal"})
            return [i for i in items if i.get("memberType") in (None, "Direct")]
        except GraphError as exc:
            if not unavailable(exc):  # vorübergehende Störung: lieber Lauf abbrechen als Seite verfälschen
                raise
            return self._all("/v1.0/roleManagement/directory/roleAssignments", {"$expand": "principal"})

    def role_eligibilities(self) -> tuple[list[dict] | None, str]:
        """Berechtigte Zuweisungen (PIM). (None, Grund), wenn PIM nicht verfügbar ist (Lizenz Entra ID P2)."""
        try:
            items = self._all("/v1.0/roleManagement/directory/roleEligibilitySchedules", {"$expand": "principal"})
        except GraphError as exc:
            if not unavailable(exc):
                raise
            return None, f"PIM nicht verfügbar (Entra ID P2 nötig?): HTTP {exc.status}"
        return [i for i in items if i.get("memberType") in (None, "Direct")], ""

    # --- Namen ----------------------------------------------------------------------

    def user(self, ident: str) -> dict:
        """Benutzer über Objekt-ID oder UPN. Gelöschte sind mit '_deleted' markiert, nicht lesbare
        (fehlende Berechtigung, Störung) mit '_error' und tragen nur die ID als Namen."""
        cached = self._users.get(ident)
        if cached is None or time.monotonic() - cached[0] > CACHE_SECONDS:
            try:
                user = self._get(f"/v1.0/users/{quote(ident, safe='@')}", {"$select": USER_FIELDS})
            except GraphError as exc:
                user = {"displayName": ident, "_deleted": exc.status == 404,
                        "_error": "" if exc.status == 404 else f"HTTP {exc.status or '?'}"}
                if not unavailable(exc):  # vorübergehende Störung nicht zwischenspeichern
                    return user
            cached = (time.monotonic(), user)
            self._users[ident] = cached
        return cached[1]

    def service_principal(self, app_id: str) -> dict | None:
        if not GUID.match(app_id or ""):
            return None
        if app_id not in self._apps:
            try:
                found = self._get("/v1.0/servicePrincipals", {"$filter": f"appId eq '{app_id}'",
                                                              "$select": "id,appId,displayName"}).get("value") or []
            except GraphError:
                found = []
            self._apps[app_id] = found[0] if found else None
        return self._apps[app_id]

    def member_ids(self, group_id: str) -> set[str] | None:
        """IDs aller (auch verschachtelten) Benutzer einer Gruppe – für die Notfallkonten-Prüfung;
        None, wenn die Mitglieder nicht lesbar sind."""
        if group_id not in self._members:
            try:
                items = self._all(f"/v1.0/groups/{group_id}/transitiveMembers/microsoft.graph.user",
                                  {"$select": "id"})
                self._members[group_id] = {i.get("id") for i in items}
            except GraphError:
                self._members[group_id] = None
        return self._members[group_id]
