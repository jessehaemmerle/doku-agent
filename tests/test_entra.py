"""Entra ID: Conditional Access, Standorte, Stärken, Methoden, Mandant, Rollen und Prüfung (Graph-Fake)."""

import copy

import httpx
import pytest

from doku_agent import lint
from doku_agent.apply import apply_proposal
from doku_agent.connectors.entra import EntraClient
from doku_agent.egress import EgressGuard
from doku_agent.generators import entra_docs
from tests.conftest import FakeLLM

GA, SEC, READER = ("62e90394-69f5-4237-9190-012177145e10", "194ae4cb-b126-40b2-bd5b-6091b380977d",
                   "f2ef992c-3afb-46b9-b7cf-a126ee74c451")
ANNA, BG, GUEST, GONE = ("11111111-0000-0000-0000-000000000001", "11111111-0000-0000-0000-000000000002",
                         "11111111-0000-0000-0000-000000000003", "11111111-0000-0000-0000-00000000dead")
G_IT, G_BG = "22222222-0000-0000-0000-000000000001", "22222222-0000-0000-0000-000000000002"
EXO = "00000002-0000-0ff1-ce00-000000000000"
CUSTOM_STRENGTH = "33333333-0000-0000-0000-000000000001"

USERS = {
    ANNA: {"id": ANNA, "displayName": "Anna Admin", "userPrincipalName": "anna@firma.at", "userType": "Member"},
    BG: {"id": BG, "displayName": "Notfall Admin", "userPrincipalName": "breakglass@firma.at", "userType": "Member"},
    GUEST: {"id": GUEST, "displayName": "Gast Berater", "userPrincipalName": "berater_x.com#EXT#@firma.onmicrosoft.com",
            "userType": "Guest"},
}
GROUPS = {G_IT: {"id": G_IT, "displayName": "IT-Abteilung", "groupTypes": []},
          G_BG: {"id": G_BG, "displayName": "Notfallkonten", "groupTypes": []}}
MEMBERS = {G_BG: [BG], G_IT: [ANNA]}


def _strength(sid, name, kind, combos):
    return {"id": sid, "displayName": name, "policyType": kind, "requirementsSatisfied": "mfa",
            "allowedCombinations": combos}


STRENGTHS = [_strength("00000000-0000-0000-0000-000000000002", "Multifactor authentication", "builtIn",
                       ["password,microsoftAuthenticatorPush", "fido2"]),
             _strength(CUSTOM_STRENGTH, "Phishing-resistent Admins", "custom", ["fido2", "windowsHelloForBusiness"])]


def _policy(pid, name, state, users, apps=None, clients=("all",), grant=None, session=None, locations=None):
    return {"id": pid, "displayName": name, "state": state, "createdDateTime": "2026-01-01T00:00:00Z",
            "modifiedDateTime": "2026-02-01T00:00:00Z",
            "conditions": {"users": users, "applications": apps or {"includeApplications": ["All"]},
                           "clientAppTypes": list(clients), "locations": locations, "platforms": None,
                           "signInRiskLevels": [], "userRiskLevels": []},
            "grantControls": grant, "sessionControls": session}


POLICIES = [
    _policy("p1", "MFA für alle", "enabled", {"includeUsers": ["All"], "excludeGroups": [G_BG]},
            grant={"operator": "OR", "builtInControls": ["mfa"]}),
    _policy("p2", "Legacy blockieren", "enabled", {"includeUsers": ["All"], "excludeUsers": [BG]},
            clients=("exchangeActiveSync", "other"), grant={"operator": "OR", "builtInControls": ["block"]}),
    _policy("p3", "Admins phishing-resistent", "enabled", {"includeRoles": [GA, SEC]},
            grant={"operator": "OR", "builtInControls": [], "authenticationStrength": STRENGTHS[1]},
            session={"signInFrequency": {"isEnabled": True, "type": "hours", "value": 4,
                                         "frequencyInterval": "timeBased"}}),
    _policy("p4", "Länder blockieren", "enabledForReportingButNotEnforced",
            {"includeUsers": ["All"], "excludeUsers": [GONE]}, apps={"includeApplications": [EXO]},
            grant={"operator": "OR", "builtInControls": ["block"]},
            locations={"includeLocations": ["All"], "excludeLocations": ["loc-countries"]}),
]
LOCATIONS = [
    {"@odata.type": "#microsoft.graph.ipNamedLocation", "id": "loc-hq", "displayName": "Zentrale", "isTrusted": True,
     "ipRanges": [{"@odata.type": "#microsoft.graph.iPv4CidrRange", "cidrAddress": "203.0.113.0/24"}]},
    {"@odata.type": "#microsoft.graph.countryNamedLocation", "id": "loc-countries", "displayName": "Erlaubte Länder",
     "countriesAndRegions": ["AT", "DE"], "includeUnknownCountriesAndRegions": False,
     "countryLookupMethod": "clientIpAddress"},
]
METHODS = {
    "policyMigrationState": "preMigration",
    "registrationEnforcement": {"authenticationMethodsRegistrationCampaign": {
        "state": "enabled", "snoozeDurationInDays": 3,
        "includeTargets": [{"id": "all_users", "targetType": "group", "targetedAuthenticationMethod": "microsoftAuthenticator"}]}},
    "authenticationMethodConfigurations": [
        {"@odata.type": "#microsoft.graph.fido2AuthenticationMethodConfiguration", "id": "Fido2", "state": "enabled",
         "isAttestationEnforced": True, "includeTargets": [{"id": "all_users", "targetType": "group"}], "excludeTargets": []},
        {"@odata.type": "#microsoft.graph.smsAuthenticationMethodConfiguration", "id": "Sms", "state": "enabled",
         "includeTargets": [{"id": G_IT, "targetType": "group"}], "excludeTargets": []},
        {"@odata.type": "#microsoft.graph.voiceAuthenticationMethodConfiguration", "id": "Voice", "state": "disabled",
         "includeTargets": [], "excludeTargets": []},
    ],
}
AUTHORIZATION = {"allowInvitesFrom": "everyone", "guestUserRoleId": "10dae51f-b6af-4016-8d66-8c2a99b929b3",
                 "allowedToUseSSPR": True, "blockMsolPowerShell": False,
                 "defaultUserRolePermissions": {"allowedToCreateApps": True, "allowedToCreateSecurityGroups": False,
                                                "allowedToReadOtherUsers": True,
                                                "permissionGrantPoliciesAssigned": [
                                                    "ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]}}
CROSS = {"inboundTrust": {"isMfaAccepted": False},
         "b2bCollaborationInbound": {"usersAndGroups": {"accessType": "allowed", "targets": [{"target": "AllUsers"}]},
                                     "applications": {"accessType": "allowed", "targets": [{"target": "AllApplications"}]}}}
PARTNERS = [{"tenantId": "44444444-0000-0000-0000-000000000001", "inboundTrust": {"isMfaAccepted": True}}]
CONSENT = {"isEnabled": True, "notifyReviewers": True, "remindersEnabled": False, "requestDurationInDays": 30,
           "reviewers": [{"query": f"/users/{ANNA}"}]}
ROLE_DEFS = [{"id": GA, "templateId": GA, "displayName": "Global Administrator", "isBuiltIn": True},
             {"id": SEC, "templateId": SEC, "displayName": "Security Administrator", "isBuiltIn": True},
             {"id": READER, "templateId": READER, "displayName": "Global Reader", "isBuiltIn": True}]


def _principal(uid):
    return {"@odata.type": "#microsoft.graph.user", **USERS[uid]}


INSTANCES = [
    {"principalId": ANNA, "roleDefinitionId": GA, "directoryScopeId": "/", "assignmentType": "Assigned",
     "memberType": "Direct", "endDateTime": None, "principal": _principal(ANNA)},
    {"principalId": BG, "roleDefinitionId": GA, "directoryScopeId": "/", "assignmentType": "Assigned",
     "memberType": "Direct", "endDateTime": None, "principal": _principal(BG)},
    {"principalId": GUEST, "roleDefinitionId": SEC, "directoryScopeId": "/", "assignmentType": "Assigned",
     "memberType": "Direct", "endDateTime": "2026-12-31T00:00:00Z", "principal": _principal(GUEST)},
    {"principalId": ANNA, "roleDefinitionId": READER, "directoryScopeId": "/", "assignmentType": "Assigned",
     "memberType": "Group", "endDateTime": None, "principal": _principal(ANNA)},  # über Gruppe: nicht doppelt
]
ELIGIBLE = [{"principalId": ANNA, "roleDefinitionId": SEC, "directoryScopeId": "/", "memberType": "Direct",
             "scheduleInfo": {"expiration": {"type": "afterDateTime", "endDateTime": "2027-01-01T00:00:00Z"}},
             "principal": _principal(ANNA)}]


class FakeEntraGraph:
    def __init__(self):
        self.requests = []
        self.forbidden: set[str] = set()   # Pfad-Präfixe ohne Berechtigung
        self.unlicensed: set[str] = set()  # Pfad-Präfixe ohne Lizenz (400)
        self.security_defaults = False
        self.policies = copy.deepcopy(POLICIES)

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if request.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
        assert request.method == "GET"
        if any(path.startswith(f) for f in self.forbidden):
            return httpx.Response(403, json={"error": {"code": "Authorization_RequestDenied",
                                                       "message": "Insufficient privileges to complete the operation."}})
        if any(path.startswith(f) for f in self.unlicensed):
            return httpx.Response(400, json={"error": {"code": "AadPremiumLicenseRequired", "message": "P2 nötig"}})
        lists = {
            "/v1.0/identity/conditionalAccess/policies": self.policies,
            "/v1.0/identity/conditionalAccess/namedLocations": LOCATIONS,
            "/v1.0/policies/authenticationStrengthPolicies": STRENGTHS,
            "/v1.0/policies/crossTenantAccessPolicy/partners": PARTNERS,
            "/v1.0/roleManagement/directory/roleDefinitions": ROLE_DEFS,
            "/v1.0/roleManagement/directory/roleAssignmentScheduleInstances": INSTANCES,
            "/v1.0/roleManagement/directory/roleEligibilitySchedules": ELIGIBLE,
            "/v1.0/roleManagement/directory/roleAssignments": [
                {k: v for k, v in i.items() if k not in ("assignmentType", "memberType", "endDateTime")}
                for i in INSTANCES if i["memberType"] == "Direct"],
            "/v1.0/users": list(USERS.values()), "/v1.0/groups": list(GROUPS.values()),
        }
        objects = {
            "/v1.0/policies/authenticationMethodsPolicy": METHODS,
            "/v1.0/policies/identitySecurityDefaultsEnforcementPolicy": {"isEnabled": self.security_defaults},
            "/v1.0/policies/authorizationPolicy": AUTHORIZATION,
            "/v1.0/policies/crossTenantAccessPolicy/default": CROSS,
            "/v1.0/policies/adminConsentRequestPolicy": CONSENT,
        }
        if path in lists:
            return httpx.Response(200, json={"value": lists[path]})
        if path in objects:
            return httpx.Response(200, json=objects[path])
        if path == "/v1.0/servicePrincipals":
            found = [{"id": "sp1", "appId": EXO, "displayName": "Office 365 Exchange Online"}] \
                if EXO in request.url.params.get("$filter", "") else []
            return httpx.Response(200, json={"value": found})
        parts = path.split("/")
        if path.startswith("/v1.0/identity/conditionalAccess/policies/"):
            policy = next((p for p in self.policies if p["id"] == parts[-1]), None)
            return httpx.Response(200, json=policy) if policy else httpx.Response(404, json={})
        if path.startswith("/v1.0/users/"):
            ident = parts[3]
            user = USERS.get(ident) or next((u for u in USERS.values() if u["userPrincipalName"] == ident), None)
            return httpx.Response(200, json=user) if user else httpx.Response(404, json={})
        if path.endswith("/transitiveMembers/microsoft.graph.user"):
            return httpx.Response(200, json={"value": [{"id": m} for m in MEMBERS.get(parts[3], [])]})
        if path.startswith("/v1.0/groups/"):
            return httpx.Response(200, json=GROUPS[parts[3]]) if parts[3] in GROUPS else httpx.Response(404, json={})
        return httpx.Response(404, json={"error": {"code": "NotFound"}})


@pytest.fixture
def graph(ctx):
    fake = FakeEntraGraph()
    ctx.cfg.entra.enabled = True
    ctx.cfg.entra.breakglass = ["breakglass@firma.at"]
    ctx.__dict__["entra"] = EntraClient(ctx.cfg.entra, ctx.cfg.intune,
                                        EgressGuard({"graph.microsoft.com", "login.microsoftonline.com"}),
                                        transport=httpx.MockTransport(fake.handler))
    ctx.__dict__["llm"] = FakeLLM(text_answer="Die Richtlinie verlangt MFA.")
    return fake


def _pages(ctx, results):
    return {ctx.store.get_proposal(r).payload["path"]: ctx.store.get_proposal(r).payload["content"]
            for r in results if r}


def test_full_run_documents_all_areas(ctx, graph):
    pages = _pages(ctx, entra_docs.document_entra(ctx))
    base = "identitaet/entra"
    assert {f"{base}/conditional-access", f"{base}/benannte-standorte", f"{base}/authentifizierungsstaerken",
            f"{base}/authentifizierungsmethoden", f"{base}/mandant", f"{base}/rollen", f"{base}/pruefung"} <= set(pages)
    p1 = pages[f"{base}/conditional-access/mfa-fuer-alle"]
    assert "| Benutzer und Gruppen | Alle Benutzer | Gruppe: Notfallkonten |" in p1
    assert "Mehrstufige Authentifizierung (MFA)" in p1 and "Die Richtlinie verlangt MFA." in p1
    p3 = pages[f"{base}/conditional-access/admins-phishing-resistent"]
    assert "Rolle: Global Administrator<br>Rolle: Security Administrator" in p3
    assert "Authentifizierungsstärke: Phishing-resistent Admins" in p3 and "alle 4 Stunden" in p3
    p4 = pages[f"{base}/conditional-access/laender-blockieren"]
    assert "| Status | Nur Bericht |" in p4 and "Office 365 Exchange Online" in p4
    assert "| Standorte ausgenommen | Erlaubte Länder |" in p4 and f"gelöschter Benutzer ({GONE})" in p4

    overview = pages[f"{base}/conditional-access"]
    assert f"[MFA für alle](/{base}/conditional-access/mfa-fuer-alle)" in overview
    assert "| Aktiv | 3 |" in overview and "| Nur Bericht | 1 |" in overview
    locations = pages[f"{base}/benannte-standorte"]
    assert "| Zentrale | IP-Bereiche | ja | 203.0.113.0/24 | – |" in locations
    assert "| Erlaubte Länder | Länder | – | AT, DE | Länder blockieren (ausgenommen) |" in locations
    strengths = pages[f"{base}/authentifizierungsstaerken"]
    assert "| Phishing-resistent Admins | benutzerdefiniert | FIDO2-Sicherheitsschlüssel<br>Windows Hello for Business " \
           "| Admins phishing-resistent |" in strengths
    methods = pages[f"{base}/authentifizierungsmethoden"]
    assert "| SMS | aktiv | IT-Abteilung |" in methods and "| Sprachanruf | aus | – |" in methods
    assert "vor der Migration" in methods
    tenant = pages[f"{base}/mandant"]
    assert "| Gäste einladen dürfen | jeder, auch Gäste |" in tenant
    assert "| Benutzerzustimmung für Apps | Benutzer dürfen allen Apps zustimmen |" in tenant
    assert "| Prüfer | Anna Admin (anna@firma.at) |" in tenant and "| Sicherheitsstandards | aus |" in tenant
    roles = pages[f"{base}/rollen"]
    assert "| Global Administrator | ja | 2 | 0 |" in roles and "| Security Administrator | ja | 1 | 1 |" in roles
    assert "| Anna Admin (anna@firma.at) | Benutzer | aktiv (dauerhaft) | Mandant |" in roles
    assert "| Anna Admin (anna@firma.at) | Benutzer | berechtigt bis 2027-01-01 | Mandant |" in roles
    assert "Global Reader" not in roles  # Zuweisung nur über Gruppe -> die Gruppe steht in roleAssignments


def test_audit_findings(ctx, graph):
    data, errors = entra_docs.fetch(ctx, {"ca", "methods", "tenant", "roles"})
    assert not errors
    f = entra_docs.audit(ctx, data, entra_docs.Names(ctx, data))
    assert f["state"] == [["Länder blockieren", "Nur Bericht"]]
    assert f["baseline"] == []  # MFA für alle (ohne Bedingung) deckt auch Admins ab, Legacy wird blockiert
    assert f["breakglass"] == [["Notfall Admin (breakglass@firma.at)", "nicht ausgenommen in „Admins phishing-resistent“"]]
    assert f["deleted"] == [["Länder blockieren", "Benutzer", GONE]]
    assert ["Global Administrator", "Anna Admin (anna@firma.at): dauerhaft aktiv statt über PIM berechtigt"] in f["roles"]
    assert any(r[1].startswith("Gastkonto Gast Berater") for r in f["roles"])
    assert not any("Notfall Admin" in r[1] for r in f["roles"])  # Notfallkonto darf dauerhaft aktiv sein
    assert [r[0] for r in f["tenant"]] == ["App-Registrierungen", "Benutzerzustimmung", "Gasteinladungen"]
    assert f["methods"] == [["SMS", "aktiv – leicht abzufangen, nicht phishing-resistent"]]


def test_baseline_gaps_and_security_defaults(ctx, graph):
    for p in graph.policies:
        p["state"] = "enabledForReportingButNotEnforced"
    data, _ = entra_docs.fetch(ctx, {"ca", "methods", "tenant", "roles"})
    f = entra_docs.audit(ctx, data, entra_docs.Names(ctx, data))
    checks = [r[0] for r in f["baseline"]]
    assert "MFA für alle Benutzer" in checks and "Legacy-Authentifizierung" in checks
    assert "MFA für Global Administrator" in checks and "Sicherheitsstandards" in checks
    graph.security_defaults = True
    data, _ = entra_docs.fetch(ctx, {"ca", "methods", "tenant", "roles"})
    assert entra_docs.audit(ctx, data, entra_docs.Names(ctx, data))["baseline"] == []


def test_conditional_mfa_does_not_count_as_baseline(ctx, graph):
    graph.policies[0]["conditions"]["locations"] = {"includeLocations": ["All"], "excludeLocations": ["loc-hq"]}
    data, _ = entra_docs.fetch(ctx, {"ca", "methods", "tenant", "roles"})
    f = entra_docs.audit(ctx, data, entra_docs.Names(ctx, data))
    assert ["MFA für alle Benutzer", "keine aktive Richtlinie ohne Einschränkung (nur bedingt: MFA für alle)"] \
        in f["baseline"]
    # Admins mit GA/Security Admin sind über p3 abgedeckt, andere Admin-Rollen nicht mehr
    checks = [r[0] for r in f["baseline"]]
    assert "MFA für Global Administrator" not in checks and "MFA für User Administrator" in checks


def test_user_names_count_mode_keeps_names_out_of_the_wiki(ctx, graph):
    ctx.cfg.entra.user_names = "count"
    pages = _pages(ctx, entra_docs.document_entra(ctx))
    text = "\n".join(pages.values())
    assert "anna@firma.at" not in text and "Anna Admin" not in text
    assert "| Benutzer und Gruppen | Alle Benutzer | 1 Benutzer |" in pages[
        "identitaet/entra/conditional-access/laender-blockieren"]
    audit = pages["identitaet/entra/pruefung"]
    assert GONE in audit  # gelöschte Objekte werden trotzdem erkannt


def test_missing_permission_skips_area_and_audit(ctx, graph, caplog):
    graph.forbidden = {"/v1.0/roleManagement/"}
    with pytest.raises(RuntimeError, match="nicht dokumentiert: Rollen, Prüfung"):
        entra_docs.document_entra(ctx)
    paths = {p.payload["path"] for p in ctx.store.list_proposals("pending", 100)}
    assert "identitaet/entra/conditional-access" in paths and "identitaet/entra/mandant" in paths
    assert "identitaet/entra/rollen" not in paths and "identitaet/entra/pruefung" not in paths
    assert "RoleManagement.Read.Directory" in caplog.text
    # Rollennamen in Richtlinien fallen auf die bekannten Vorlagen zurück
    p3 = next(p for p in ctx.store.list_proposals("pending", 100) if p.payload["path"].endswith("phishing-resistent"))
    assert "Rolle: Global Administrator" in p3.payload["content"]


def test_without_pim_licence_roles_are_documented_without_permanent_check(ctx, graph):
    graph.unlicensed = {"/v1.0/roleManagement/directory/roleAssignmentSchedule",
                        "/v1.0/roleManagement/directory/roleEligibility"}
    pages = _pages(ctx, entra_docs.document_entra(ctx, ["roles", "audit"]))
    roles = pages["identitaet/entra/rollen"]
    assert "PIM nicht verfügbar" in roles and "| Anna Admin (anna@firma.at) | Benutzer | aktiv | Mandant |" in roles
    assert "dauerhaft aktiv" not in pages["identitaet/entra/pruefung"]


def test_lint_refresh_reproduces_pages_and_detects_deleted_policy(ctx, graph, fake_wiki):
    results = entra_docs.document_entra(ctx, ["conditional_access", "roles"])
    for pid in results:
        if pid:
            assert apply_proposal(ctx, pid) == "applied"
    ctx.__dict__.pop("conventions", None)
    assert lint.refresh(ctx, "entra:ca:p1") is None          # unverändert -> kein Vorschlag
    assert lint.refresh(ctx, "entra:rollen") is None
    assert lint.refresh(ctx, "entra:conditional-access") is None  # Übersicht mit Links auf bestehende Seiten
    ctx.cfg.entra.include = ["conditional_access"]
    with pytest.raises(lint.Unsupported):  # Bereich abgewählt: nichts mehr zu prüfen
        lint.refresh(ctx, "entra:rollen")
    graph.policies[0]["state"] = "disabled"
    pid = lint.refresh(ctx, "entra:ca:p1")
    assert "| Status | Aus |" in ctx.store.get_proposal(pid).payload["content"]
    del graph.policies[1]
    with pytest.raises(lint.SourceGone):
        lint.refresh(ctx, "entra:ca:p2")


def test_check_names_missing_entra_permissions(ctx, graph):
    from doku_agent.web.app import run_checks

    graph.forbidden = {"/v1.0/identity/conditionalAccess/", "/v1.0/servicePrincipals"}
    result = {name: (ok, msg) for name, ok, msg in run_checks(ctx)}
    ok, msg = result["Entra-Berechtigungen"]
    assert ok is False and "Policy.Read.All für conditional_access" in msg
    graph.forbidden = {"/v1.0/servicePrincipals"}
    ok, msg = {name: (ok, msg) for name, ok, msg in run_checks(ctx)}["Entra-Berechtigungen"]
    assert ok is True and "optional fehlt Application.Read.All" in msg


def test_entra_uses_intune_credentials_and_graph_hosts(tmp_path):
    from doku_agent.config import Config
    from doku_agent.egress import allowed_hosts
    from tests.conftest import make_config

    cfg = make_config(tmp_path, intune={"tenant_id": "t1", "client_id": "c1", "client_secret": "s1"},
                      entra={"enabled": True}, wiki={"paths": {"netbox_device": "geraete/{name}"}})
    assert isinstance(cfg, Config) and "graph.microsoft.com" in allowed_hosts(cfg)
    client = EntraClient(cfg.entra, cfg.intune, EgressGuard({"graph.microsoft.com", "login.microsoftonline.com"}))
    assert (client.tenant_id, client.client_id, client.client_secret) == ("t1", "c1", "s1")
    # eigene Pfade in der config.yaml: neue Dokutypen bekommen trotzdem ihren Standardpfad
    assert cfg.wiki.paths["netbox_device"] == "geraete/{name}"
    assert cfg.wiki.paths["entra_ca"] == "identitaet/entra/conditional-access/{name}"


def test_breakglass_labels_follow_user_names_and_unreadable_accounts_are_reported(ctx, graph):
    ctx.cfg.entra.user_names = "name"
    data, _ = entra_docs.fetch(ctx, {"ca", "methods", "tenant", "roles"})
    f = entra_docs.audit(ctx, data, entra_docs.Names(ctx, data))
    assert f["breakglass"] == [["Notfall Admin", "nicht ausgenommen in „Admins phishing-resistent“"]]
    graph.forbidden = {"/v1.0/users/"}
    ctx.__dict__["entra"]._users.clear()
    f = entra_docs.audit(ctx, data, entra_docs.Names(ctx, data))
    assert f["breakglass"][0][0] == "Notfallkonto 1" and "nicht lesbar (HTTP 403)" in f["breakglass"][0][1]


def test_legacy_trusted_ips_link_text_and_transient_pim_errors(ctx, graph):
    graph.policies[0]["displayName"] = "[Pilot] MFA"
    graph.policies[0]["conditions"]["locations"] = {"includeLocations": ["All"],
                                                    "excludeLocations": ["00000000-0000-0000-0000-000000000000"]}
    pages = _pages(ctx, entra_docs.document_entra(ctx, ["conditional_access"]))
    assert "[Pilot MFA](/identitaet/entra/conditional-access/pilot-mfa)" in pages["identitaet/entra/conditional-access"]
    assert "Vertrauenswürdige MFA-IPs (Legacy)" in pages["identitaet/entra/conditional-access/pilot-mfa"]
    data, _ = entra_docs.fetch(ctx, {"ca", "methods", "tenant", "roles"})
    assert entra_docs.audit(ctx, data, entra_docs.Names(ctx, data))["deleted"] == [
        ["Länder blockieren", "Benutzer", GONE]]  # Legacy-IPs sind kein gelöschter Standort

    # Vorübergehende Störung bei PIM: Bereich scheitert, statt die Rollen ohne PIM-Angaben zu zeigen
    def flaky(request):
        if "roleAssignmentScheduleInstances" in request.url.path:
            return httpx.Response(503, json={"error": {"code": "ServiceUnavailable"}})
        return graph.handler(request)
    ctx.__dict__["entra"].http._transport = httpx.MockTransport(flaky)
    data, errors = entra_docs.fetch(ctx, {"roles"})
    assert "roles" in errors and "roles" not in data.loaded
