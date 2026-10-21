"""Entra-Gruppen: Art in den Zuweisungen, Übersichtsseite mit Mitgliederzahlen und Zuweisungen je Gruppe."""

import httpx
import pytest

from doku_agent.connectors.intune import IntuneClient
from doku_agent.egress import EgressGuard
from doku_agent.generators import intune_docs
from tests.conftest import FakeLLM

G_DYN, G_STATIC, G_M365 = "11111111-aaaa", "22222222-bbbb", "33333333-cccc"
GROUPS = {
    G_DYN: {"id": G_DYN, "displayName": "Alle Windows-Geräte", "groupTypes": ["DynamicMembership"],
            "membershipRule": '(device.deviceOSType -eq "Windows")'},
    G_STATIC: {"id": G_STATIC, "displayName": "Pilot-Benutzer", "groupTypes": []},
    G_M365: {"id": G_M365, "displayName": "Team Vertrieb", "groupTypes": ["Unified"]},
}
COUNTS = {G_DYN: {"user": 0, "device": 120, "group": 0}, G_STATIC: {"user": 7, "device": 0, "group": 1},
          G_M365: {"user": 25, "device": 0}}


def _target(kind, group=None):
    t = {"@odata.type": f"#microsoft.graph.{kind}"}
    if group:
        t["groupId"] = group
    return t


POLICIES = {
    "/v1.0/deviceManagement/deviceCompliancePolicies": [
        {"id": "c1", "displayName": "Windows-Compliance", "@odata.type": "#microsoft.graph.windows10CompliancePolicy",
         "passwordRequired": True}],
    "/v1.0/deviceManagement/deviceConfigurations": [],
    "/beta/deviceManagement/configurationPolicies": [{"id": "s1", "name": "BitLocker", "technologies": "mdm"}],
    "/v1.0/deviceAppManagement/mobileApps": [{"id": "a1", "displayName": "7-Zip", "publisher": "Igor Pavlov"}],
}
ASSIGNMENTS = {
    "c1": [{"target": _target("groupAssignmentTarget", G_DYN)},
           {"target": _target("exclusionGroupAssignmentTarget", G_STATIC)}],
    "s1": [{"target": _target("groupAssignmentTarget", G_STATIC)},
           {"target": _target("allDevicesAssignmentTarget")}],
    "a1": [{"intent": "required", "target": _target("groupAssignmentTarget", G_M365)}],
}


class FakeGraph:
    def __init__(self):
        self.requests = []
        self.forbidden: set[str] = set()  # Pfad-Präfixe ohne Berechtigung (403 wie Graph)

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if request.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
        if any(path.startswith(f) for f in self.forbidden):
            return httpx.Response(403, json={"error": {"code": "Forbidden", "message": "Application is not "
                                                       "authorized to perform this operation."}})
        if path.endswith("/$count"):
            assert request.headers["consistencylevel"] == "eventual"
            gid, kind = path.split("/")[3], path.split("/")[5].removeprefix("microsoft.graph.")
            value = COUNTS[gid].get(kind)
            if value is None:  # Microsoft-365-Gruppen können keine Untergruppen haben
                return httpx.Response(400, json={"error": {"code": "Request_UnsupportedQuery"}})
            return httpx.Response(200, text=str(value), headers={"content-type": "text/plain"})
        if path == "/v1.0/groups":
            return httpx.Response(200, json={"value": [{"id": g} for g in GROUPS][:1]})
        if path.startswith("/v1.0/groups/"):
            return httpx.Response(200, json=GROUPS[path.split("/")[3]])
        if path.endswith("/assignments"):
            return httpx.Response(200, json={"value": ASSIGNMENTS.get(path.split("/")[-2], [])})
        if path.endswith("/settings"):
            return httpx.Response(200, json={"value": []})
        if path in POLICIES:
            return httpx.Response(200, json={"value": POLICIES[path]})
        for base, items in POLICIES.items():
            for item in items:
                if path == f"{base}/{item['id']}":
                    return httpx.Response(200, json=item)
        return httpx.Response(404, json={"error": {"code": "ResourceNotFound"}})


@pytest.fixture
def graph(ctx):
    fake = FakeGraph()
    ctx.cfg.intune.enabled = True
    ctx.__dict__["intune"] = IntuneClient(ctx.cfg.intune, EgressGuard({"graph.microsoft.com", "login.microsoftonline.com"}),
                                          transport=httpx.MockTransport(fake.handler))
    ctx.__dict__["llm"] = FakeLLM(text_answer="Beschreibung.")
    return fake


def test_member_counts_and_group_kind(ctx, graph):
    assert ctx.intune.member_counts(G_M365) == {"user": 25, "device": 0, "group": None}
    assert intune_docs.group_kind(GROUPS[G_DYN]) == "dynamisch"
    assert intune_docs.group_kind(GROUPS[G_M365]) == "zugewiesen, Microsoft 365"
    assert intune_docs.group_kind({"id": "x", "displayName": "x"}) == "–"  # ohne Berechtigung


def test_policy_pages_show_kind_but_no_counts(ctx, graph):
    results = intune_docs.document_intune(ctx)
    pages = {ctx.store.get_proposal(r).payload["title"]: ctx.store.get_proposal(r).payload["content"]
             for r in results if r}
    policy = pages["Intune: Windows-Compliance"]
    assert "| Gruppe | Alle Windows-Geräte | dynamisch |" in policy
    assert "| Ausgeschlossen | Pilot-Benutzer | zugewiesen |" in policy
    assert "[Intune: Gruppen und Zuweisungen](/clients/intune/gruppen)" in policy
    assert "120" not in policy  # Mitgliederzahlen nur auf der Übersichtsseite

    overview = pages["Intune: Gruppen und Zuweisungen"]
    assert "| Alle Windows-Geräte | dynamisch | `(device.deviceOSType -eq \"Windows\")` | 0 | 120 | 0 | 1 |" in overview
    assert "| Pilot-Benutzer | zugewiesen | – | 7 | 0 | 1 | 2 |" in overview
    assert "| Team Vertrieb | zugewiesen, Microsoft 365 | – | 25 | 0 | – | 1 |" in overview
    assert "| Alle Geräte | alle |" in overview
    assert "### Pilot-Benutzer" in overview
    assert "| Compliance-Richtlinie | Windows-Compliance | – | ausgeschlossen | – |" in overview
    assert "| Settings Catalog | BitLocker | – | einbezogen | – |" in overview
    assert "| App | 7-Zip | required | einbezogen | – |" in overview


def test_groups_page_alone_reads_assignments_without_settings(ctx, graph):
    pid = intune_docs.document_groups(ctx)
    assert "Pilot-Benutzer" in ctx.store.get_proposal(pid).payload["content"]
    assert not any(r.url.path.endswith("/settings") for r in graph.requests)


def test_single_policy_fetch_and_not_found(ctx, graph):
    pol = ctx.intune.policy("settings-catalog", "s1")
    assert pol["name"] == "BitLocker" and len(pol["_assignments"]) == 2 and pol["_settings"] == []
    from doku_agent.connectors.intune import IntuneError
    with pytest.raises(IntuneError) as exc:
        ctx.intune.policy("compliance", "geloescht")
    assert exc.value.status == 404


def test_missing_permission_is_named_and_other_areas_are_still_documented(ctx, graph, caplog):
    graph.forbidden = {"/v1.0/deviceManagement/deviceCompliancePolicies"}
    with pytest.raises(RuntimeError, match="nicht lesbar: Compliance-Richtlinien"):
        intune_docs.document_intune(ctx)
    titles = {p.payload["title"] for p in ctx.store.list_proposals("pending")}
    assert {"Intune: BitLocker", "Intune: Apps"} <= titles
    assert "Intune: Gruppen und Zuweisungen" not in titles  # wäre ohne die Compliance-Zuweisungen falsch
    assert "fehlt die Anwendungsberechtigung DeviceManagementConfiguration.Read.All" in caplog.text


def test_new_token_after_permission_was_granted(ctx, graph):
    from doku_agent.connectors.intune import IntuneError

    graph.forbidden = {"/v1.0/deviceAppManagement/"}
    ctx.intune._auth()
    ctx.intune._issued -= 120  # Token ist schon älter
    with pytest.raises(IntuneError) as exc:
        ctx.intune.mobile_apps()
    assert exc.value.status == 403 and "DeviceManagementApps.Read.All" in str(exc.value)
    assert "(Graph: Application is not authorized to perform this operation.)" in str(exc.value)
    graph.forbidden.clear()  # Administratorzustimmung erteilt
    logins = sum(r.url.host == "login.microsoftonline.com" for r in graph.requests)
    assert ctx.intune.mobile_apps()[0]["displayName"] == "7-Zip"
    assert sum(r.url.host == "login.microsoftonline.com" for r in graph.requests) == logins + 1


def test_check_lists_missing_permissions(ctx, graph):
    from doku_agent.web.app import run_checks

    graph.forbidden = {"/v1.0/deviceManagement/deviceCompliancePolicies", "/v1.0/deviceManagement/deviceConfigurations",
                       "/v1.0/groups"}
    result = {name: (ok, msg) for name, ok, msg in run_checks(ctx)}["Intune-Berechtigungen"]
    assert result[0] is False
    assert "DeviceManagementConfiguration.Read.All für compliance, configurations" in result[1]
    assert "Group.Read.All für groups" in result[1]
    graph.forbidden.clear()
    assert {name: ok for name, ok, _ in run_checks(ctx)}["Intune-Berechtigungen"] is True
