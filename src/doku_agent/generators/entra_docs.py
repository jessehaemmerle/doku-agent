"""Entra ID: Conditional Access, benannte Standorte, Authentifizierungsstärken und -methoden,
Mandanten-Einstellungen, privilegierte Rollen und eine Prüfung – nur lesend über Microsoft Graph.

Tabellen und Bewertungen entstehen deterministisch aus den Graph-Daten; das LLM schreibt nur die
Erklärung je Conditional-Access-Richtlinie (nach Eingabe-Hash zwischengespeichert).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from doku_agent import markdown
from doku_agent.connectors.graph import GraphError
from doku_agent.context import Context
from doku_agent.generators import narrative
from doku_agent.pages import Block, PageDraft, propose_page, render_path

STATE = {"enabled": "Aktiv", "disabled": "Aus", "enabledForReportingButNotEnforced": "Nur Bericht"}
USERS_SPECIAL = {"All": "Alle Benutzer", "None": "Niemand", "GuestsOrExternalUsers": "Alle Gäste und externen Benutzer"}
APPS_SPECIAL = {"All": "Alle Ressourcen (Cloud-Apps)", "None": "Keine", "Office365": "Office 365",
                "MicrosoftAdminPortals": "Microsoft-Verwaltungsportale"}
USER_ACTIONS = {"urn:user:registersecurityinfo": "Sicherheitsinformationen registrieren",
                "urn:user:registerdevice": "Geräte registrieren oder einbinden"}
GUEST_TYPES = {"internalGuest": "interne Gäste", "b2bCollaborationGuest": "B2B-Gäste",
               "b2bCollaborationMember": "B2B-Mitglieder", "b2bDirectConnectUser": "B2B-Direktverbindung",
               "otherExternalUser": "andere externe Benutzer", "serviceProvider": "Dienstanbieter"}
CLIENT_APPS = {"all": "alle", "browser": "Browser", "mobileAppsAndDesktopClients": "Mobile Apps und Desktop-Clients",
               "exchangeActiveSync": "Exchange ActiveSync", "easSupported": "Exchange ActiveSync",
               "other": "andere Clients (Legacy-Authentifizierung)"}
PLATFORMS = {"all": "alle", "android": "Android", "iOS": "iOS", "windows": "Windows", "windowsPhone": "Windows Phone",
             "macOS": "macOS", "linux": "Linux"}
LOCATIONS_SPECIAL = {"All": "Alle Standorte", "AllTrusted": "Alle vertrauenswürdigen Standorte",
                     # Legacy-Einstellung "Vertrauenswürdige IPs" der MFA-Diensteinstellungen (kein benannter Standort)
                     "00000000-0000-0000-0000-000000000000": "Vertrauenswürdige MFA-IPs (Legacy)"}
RISK = {"low": "niedrig", "medium": "mittel", "high": "hoch", "none": "kein Risiko", "hidden": "verborgen", "minor": "gering",
        "moderate": "mäßig", "elevated": "erhöht"}
GRANT = {"block": "Zugriff blockieren", "mfa": "Mehrstufige Authentifizierung (MFA)", "compliantDevice": "Konformes Gerät",
         "domainJoinedDevice": "Hybrid in Entra eingebundenes Gerät", "approvedApplication": "Genehmigte Client-App",
         "compliantApplication": "App-Schutzrichtlinie", "passwordChange": "Kennwortänderung"}
AUTH_COMBOS = {"password": "Kennwort", "voice": "Anruf", "sms": "SMS", "hardwareOath": "Hardware-OATH-Token",
               "softwareOath": "Software-OATH-Token", "fido2": "FIDO2-Sicherheitsschlüssel",
               "windowsHelloForBusiness": "Windows Hello for Business",
               "microsoftAuthenticatorPush": "Authenticator (Push)", "deviceBasedPush": "Authenticator (kennwortlos)",
               "temporaryAccessPassOneTime": "Befristeter Zugriffspass (einmalig)",
               "temporaryAccessPassMultiUse": "Befristeter Zugriffspass (mehrfach)", "email": "E-Mail-Einmalkennung",
               "x509CertificateSingleFactor": "Zertifikat (einstufig)",
               "x509CertificateMultiFactor": "Zertifikat (mehrstufig)", "federatedSingleFactor": "Verbund (einstufig)",
               "federatedMultiFactor": "Verbund (mehrstufig)", "qrCodePin": "QR-Code + PIN"}
METHODS = {"Fido2": "FIDO2-Sicherheitsschlüssel / Passkeys", "MicrosoftAuthenticator": "Microsoft Authenticator",
           "Sms": "SMS", "Voice": "Sprachanruf", "Email": "E-Mail-Einmalkennung",
           "TemporaryAccessPass": "Befristeter Zugriffspass", "SoftwareOath": "Software-OATH-Token",
           "HardwareOath": "Hardware-OATH-Token", "X509Certificate": "Zertifikatbasierte Authentifizierung",
           "QRCodePin": "QR-Code + PIN"}
WEAK_METHODS = {"Sms", "Voice"}

# Integrierte Rollen (Vorlagen-IDs), die die Microsoft-Vorlage "MFA für Administratoren" einschließt
ADMIN_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
    "b0f54661-2d74-4c50-afa3-1ec803f12efe": "Billing Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
    "966707d0-3269-4727-9be2-8c3a10f19b9d": "Password Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
}
GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
PRIVILEGED_ROLES = {**ADMIN_ROLES, "3a2c62db-5318-420d-8d74-23affee5d9d5": "Intune Administrator",
                    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2": "Hybrid Identity Administrator"}
GUEST_ROLES = {"a0b1b346-4d3e-4e8b-98f8-753987be4970": "wie Mitglieder (gleiche Rechte)",
               "10dae51f-b6af-4016-8d66-8c2a99b929b3": "eingeschränkt (Standard)",
               "2af84b1e-32c8-42b7-82bc-daa82404023b": "stark eingeschränkt (nur eigene Objekte)"}
INVITES = {"none": "niemand", "adminsAndGuestInviters": "Administratoren und Gasteinladende",
           "adminsGuestInvitersAndAllMembers": "Administratoren, Gasteinladende und alle Mitglieder",
           "everyone": "jeder, auch Gäste"}

# include-Schlüssel -> Seiten (Abschnitt-Slug, Überschrift)
SECTIONS = {
    "conditional_access": [("conditional-access", "Conditional Access"), ("benannte-standorte", "Benannte Standorte"),
                           ("authentifizierungsstaerken", "Authentifizierungsstärken")],
    "auth_methods": [("authentifizierungsmethoden", "Authentifizierungsmethoden")],
    "tenant_settings": [("mandant", "Mandanten-Einstellungen")],
    "roles": [("rollen", "Privilegierte Rollen")],
    "audit": [("pruefung", "Prüfung")],
}
AREA_LABELS = {"conditional_access": "Conditional Access", "auth_methods": "Authentifizierungsmethoden",
               "tenant_settings": "Mandanten-Einstellungen", "roles": "Rollen", "audit": "Prüfung"}
# Welche Daten jede Seite braucht (die Prüfung bewertet alles zusammen)
NEEDS = {"conditional_access": {"ca"}, "auth_methods": {"methods"}, "tenant_settings": {"tenant"},
         "roles": {"roles"}, "audit": {"ca", "methods", "tenant", "roles"}}
# Datengruppe -> Probe-Abfrage des Connectors ('doku-agent check')
PROBE_AREAS = {"ca": "conditional_access", "methods": "auth_methods", "tenant": "tenant_settings", "roles": "roles"}


@dataclass
class EntraData:
    policies: list[dict] = field(default_factory=list)
    locations: list[dict] = field(default_factory=list)
    strengths: list[dict] = field(default_factory=list)
    methods: dict = field(default_factory=dict)
    security_defaults: dict = field(default_factory=dict)
    authorization: dict = field(default_factory=dict)
    cross_tenant: dict = field(default_factory=dict)
    partners: list[dict] = field(default_factory=list)
    consent_requests: dict = field(default_factory=dict)
    role_definitions: list[dict] = field(default_factory=list)
    assignments: list[dict] = field(default_factory=list)
    eligibilities: list[dict] | None = None  # None: PIM nicht verfügbar (Lizenz oder Berechtigung)
    pim_note: str = ""
    loaded: set[str] = field(default_factory=set)


def fetch(ctx: Context, groups: set[str]) -> tuple[EntraData, dict[str, str]]:
    """Daten der gewünschten Gruppen laden; Rückgabe (Daten, {Gruppe: Fehler})."""
    client = ctx.entra
    data, errors = EntraData(), {}

    def load(group: str, fn) -> None:
        if group not in groups:
            return
        try:
            fn()
            data.loaded.add(group)
        except GraphError as exc:
            errors[group] = str(exc)

    def ca():
        data.policies = client.ca_policies()
        data.locations = client.named_locations()
        data.strengths = client.auth_strengths()

    def methods():
        data.methods = client.auth_methods_policy()

    def tenant():
        data.security_defaults = client.security_defaults()
        data.authorization = client.authorization_policy()
        data.cross_tenant = client.cross_tenant_default()
        data.partners = client.cross_tenant_partners()
        data.consent_requests = client.admin_consent_policy()

    def roles():
        data.role_definitions = client.role_definitions()
        data.assignments = client.role_assignments()
        data.eligibilities, data.pim_note = client.role_eligibilities()

    load("ca", ca)
    load("methods", methods)
    load("tenant", tenant)
    load("roles", roles)
    if "ca" in groups and "roles" not in groups:
        data.role_definitions = role_names(ctx)
    return data, errors


def role_names(ctx: Context) -> list[dict]:
    """Rollendefinitionen für Namen in Richtlinien. Ohne Berechtigung bleiben IDs bzw. die bekannten
    Vorlagen; eine vorübergehende Störung bricht ab (sonst entstünde eine abweichende Seite)."""
    from doku_agent.connectors.entra import unavailable
    try:
        return ctx.entra.role_definitions()
    except GraphError as exc:
        if not unavailable(exc):
            raise
        ctx.log.warning("Rollennamen nicht lesbar, es erscheinen IDs: %s", exc)
        return []


# --- Namen ------------------------------------------------------------------

class Names:
    """Löst IDs in lesbare Namen auf und merkt sich Verweise auf gelöschte Objekte (für die Prüfung)."""

    def __init__(self, ctx: Context, data: EntraData):
        self.client = ctx.entra
        self.mode = ctx.cfg.entra.user_names
        self.roles: dict[str, str] = {}
        for d in data.role_definitions:
            for key in (d.get("templateId"), d.get("id")):
                if key:
                    self.roles[key] = d.get("displayName") or key
        self.locations = {loc.get("id"): loc.get("displayName") or loc.get("id") for loc in data.locations}
        self.deleted: list[tuple[str, str]] = []  # (Objektart, ID)

    def user(self, uid: str) -> str:
        u = self.client.user(uid)
        if u.get("_deleted"):
            self.deleted.append(("Benutzer", uid))
            return f"gelöschter Benutzer ({uid})"
        if self.mode == "count":  # keine Personennamen im Wiki
            return "Benutzer"
        name = u.get("displayName") or u.get("userPrincipalName") or uid
        upn = u.get("userPrincipalName") or ""
        return f"{name} ({upn})" if self.mode == "name_upn" and upn and upn != name else name

    def group(self, gid: str) -> str:
        g = self.client.group(gid)
        if g.get("_deleted"):
            self.deleted.append(("Gruppe", gid))
            return f"gelöschte Gruppe ({gid})"
        return g.get("displayName") or gid

    def role(self, rid: str) -> str:
        return self.roles.get(rid) or ADMIN_ROLES.get(rid) or rid

    def app(self, app_id: str) -> str:
        special = next((v for k, v in APPS_SPECIAL.items() if k.lower() == (app_id or "").lower()), None)
        if special:
            return special
        sp = self.client.service_principal(app_id)
        return (sp or {}).get("displayName") or app_id

    def location(self, lid: str) -> str:
        if lid in LOCATIONS_SPECIAL:
            return LOCATIONS_SPECIAL[lid]
        if lid not in self.locations:
            self.deleted.append(("Benannter Standort", lid))
            return f"unbekannter Standort ({lid})"
        return self.locations[lid]

    def users(self, ids: list[str]) -> list[str]:
        special = [USERS_SPECIAL[i] for i in ids if i in USERS_SPECIAL]
        rest = [i for i in ids if i not in USERS_SPECIAL]
        if self.mode == "count":
            for uid in rest:  # gelöschte trotzdem erkennen, nur keine Namen ausgeben
                if self.client.user(uid).get("_deleted"):
                    self.deleted.append(("Benutzer", uid))
            return special + ([f"{len(rest)} Benutzer"] if rest else [])
        return special + sorted((self.user(i) for i in rest), key=str.lower)


def _list(value) -> list[str]:
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    return [str(v) for v in value or []]


def _guests(spec: dict | None) -> str:
    if not spec:
        return ""
    kinds = [GUEST_TYPES.get(k, k) for k in _list(spec.get("guestOrExternalUserTypes"))]
    tenants = spec.get("externalTenants") or {}
    scope = "" if tenants.get("membershipKind") in (None, "all") else \
        f" aus {len(tenants.get('members') or [])} Mandanten"
    return "Gäste/Externe: " + (", ".join(kinds) or "alle") + scope


def policy_view(policy: dict, names: Names) -> dict:
    """Lesbare, deterministische Sicht auf eine CA-Richtlinie (Seite, Übersicht, LLM und Prüfung)."""
    cond = policy.get("conditions") or {}
    users = cond.get("users") or {}
    apps = cond.get("applications") or {}

    def side(prefix: str) -> list[str]:
        out = names.users(users.get(f"{prefix}Users") or [])
        out += [f"Gruppe: {names.group(g)}" for g in users.get(f"{prefix}Groups") or []]
        out += [f"Rolle: {names.role(r)}" for r in users.get(f"{prefix}Roles") or []]
        guests = _guests(users.get(f"{prefix}GuestsOrExternalUsers"))
        return out + ([guests] if guests else [])

    def risk(key: str) -> str:
        return ", ".join(RISK.get(r, r) for r in cond.get(key) or [])

    platforms = cond.get("platforms") or {}
    locations = cond.get("locations") or {}
    device_filter = ((cond.get("devices") or {}).get("deviceFilter")) or {}
    app_filter = apps.get("applicationFilter") or {}
    flows = _list((cond.get("authenticationFlows") or {}).get("transferMethods"))
    conditions = [
        ("Client-Apps", ", ".join(CLIENT_APPS.get(c, c) for c in cond.get("clientAppTypes") or [] if c != "all")),
        ("Plattformen", ", ".join(PLATFORMS.get(p, p) for p in platforms.get("includePlatforms") or [])),
        ("Plattformen ausgenommen", ", ".join(PLATFORMS.get(p, p) for p in platforms.get("excludePlatforms") or [])),
        ("Standorte", ", ".join(names.location(x) for x in locations.get("includeLocations") or [])),
        ("Standorte ausgenommen", ", ".join(names.location(x) for x in locations.get("excludeLocations") or [])),
        ("Anmelderisiko", risk("signInRiskLevels")),
        ("Benutzerrisiko", risk("userRiskLevels")),
        ("Dienstprinzipal-Risiko", risk("servicePrincipalRiskLevels")),
        ("Insider-Risiko", risk("insiderRiskLevels") if isinstance(cond.get("insiderRiskLevels"), list)
         else RISK.get(cond.get("insiderRiskLevels") or "", cond.get("insiderRiskLevels") or "")),
        ("Gerätefilter", (("nur " if device_filter.get("mode") == "include" else "ausgenommen: ")
                          + f"`{device_filter['rule']}`") if device_filter.get("rule") else ""),
        ("Authentifizierungsflüsse", ", ".join(flows)),
    ]
    grant = policy.get("grantControls") or {}
    controls = [GRANT.get(c, c) for c in grant.get("builtInControls") or []]
    strength = grant.get("authenticationStrength") or {}
    if strength:
        controls.append(f"Authentifizierungsstärke: {strength.get('displayName') or strength.get('id')}")
    if grant.get("termsOfUse"):
        controls.append(f"Nutzungsbedingungen ({len(grant['termsOfUse'])})")
    controls += [f"Benutzerdefiniert: {c}" for c in grant.get("customAuthenticationFactors") or []]
    session = []
    s = policy.get("sessionControls") or {}
    freq = s.get("signInFrequency") or {}
    if freq.get("isEnabled"):
        if freq.get("frequencyInterval") == "everyTime":
            session.append("Anmeldehäufigkeit: jedes Mal")
        else:
            unit = {"hours": "Stunden", "days": "Tage"}.get(freq.get("type"), freq.get("type") or "")
            session.append(f"Anmeldehäufigkeit: alle {freq.get('value')} {unit}")
    browser = s.get("persistentBrowser") or {}
    if browser.get("isEnabled"):
        session.append("Beständige Browsersitzung: " + ("immer" if browser.get("mode") == "always" else "nie"))
    if (s.get("applicationEnforcedRestrictions") or {}).get("isEnabled"):
        session.append("App-erzwungene Einschränkungen")
    mcas = s.get("cloudAppSecurity") or {}
    if mcas.get("isEnabled"):
        session.append(f"App-Steuerung für bedingten Zugriff ({mcas.get('cloudAppSecurityType', '')})")
    if s.get("disableResilienceDefaults"):
        session.append("Resilienzstandards deaktiviert")
    operator = "alle erforderlich" if grant.get("operator") == "AND" else "eine davon erforderlich"
    return {
        "id": policy.get("id"), "name": policy.get("displayName") or policy.get("id"),
        "state": STATE.get(policy.get("state"), policy.get("state") or ""),
        "users_in": side("include"), "users_out": side("exclude"),
        "apps_in": [names.app(a) for a in apps.get("includeApplications") or []],
        "apps_out": [names.app(a) for a in apps.get("excludeApplications") or []],
        "actions": [USER_ACTIONS.get(a, a) for a in apps.get("includeUserActions") or []],
        "auth_context": list(apps.get("includeAuthenticationContextClassReferences") or []),
        "app_filter": (("nur " if app_filter.get("mode") == "include" else "ausgenommen: ") + f"`{app_filter['rule']}`")
        if app_filter.get("rule") else "",
        "conditions": [(k, v) for k, v in conditions if v],
        "grant": controls, "operator": operator if len(controls) > 1 else "",
        "session": session,
    }


def _short(items: list[str], limit: int = 3) -> str:
    if not items:
        return ""
    return ", ".join(items[:limit]) + (f" (+{len(items) - limit})" if len(items) > limit else "")


def _cell(values: list[str]) -> str:
    return "<br>".join(values) or "–"


# --- Conditional Access ---------------------------------------------------------

def _explain(ctx: Context, view: dict) -> str | None:
    lines = [f"Name: {view['name']}", f"Status: {view['state']}",
             f"Benutzer: {'; '.join(view['users_in']) or '–'}", f"Ausgenommen: {'; '.join(view['users_out']) or '–'}",
             f"Ressourcen: {'; '.join(view['apps_in'] + view['actions'] + view['auth_context']) or '–'}",
             f"Ressourcen ausgenommen: {'; '.join(view['apps_out']) or '–'}"]
    lines += [f"{k}: {v}" for k, v in view["conditions"]]
    lines += [f"Gewähren ({view['operator'] or 'einzeln'}): {'; '.join(view['grant']) or '–'}",
              f"Sitzung: {'; '.join(view['session']) or '–'}"]
    fallback = (f"Die Richtlinie **{view['name']}** ist im Status „{view['state']}“. Sie gilt für "
                f"{_short(view['users_in']) or 'niemanden'}"
                + (f" (ausgenommen {_short(view['users_out'])})" if view["users_out"] else "")
                + f" beim Zugriff auf {_short(view['apps_in'] + view['actions']) or 'keine Ressourcen'}"
                + (f" und verlangt bzw. bewirkt: {_short(view['grant'] + view['session'], 4)}."
                   if view["grant"] or view["session"] else "."))
    return narrative.narrate(
        ctx, f"entra-ca:{view['id']}", expert="Microsoft Entra ID und Conditional Access", fallback=fallback,
        facts="\n".join(lines),
        task="Erkläre, was diese Conditional-Access-Richtlinie bewirkt: wen sie betrifft und wen nicht, bei welchen "
             "Ressourcen und unter welchen Bedingungen sie greift und was sie dann verlangt oder blockiert. Erkläre "
             "die verwendeten Steuerungen kurz und warum eine solche Richtlinie sinnvoll ist. Ist sie aus oder nur "
             "im Berichtsmodus, sage deutlich, dass sie nicht durchgesetzt wird.")


def ca_policy_page(ctx: Context, policy: dict, names: Names) -> int | None:
    view = policy_view(policy, names)
    basics = markdown.table(["Eigenschaft", "Wert"], [
        ["Name", view["name"]], ["Status", view["state"]], ["Erstellt", _until(policy.get("createdDateTime")) or "–"],
        ["Geändert", _until(policy.get("modifiedDateTime")) or "–"], ["Richtlinien-ID", policy.get("id")],
    ])
    assignments = markdown.table(["Zuweisung", "Einbezogen", "Ausgenommen"], [
        ["Benutzer und Gruppen", _cell(view["users_in"]), _cell(view["users_out"])],
        ["Zielressourcen", _cell(view["apps_in"] + view["actions"]
                                 + [f"Authentifizierungskontext {c}" for c in view["auth_context"]]),
         _cell(view["apps_out"])],
    ] + ([["App-Filter", view["app_filter"], ""]] if view["app_filter"] else []))
    conditions = markdown.table(["Bedingung", "Wert"], [list(c) for c in view["conditions"]]) \
        if view["conditions"] else "_Keine weiteren Bedingungen._"
    controls = markdown.table(["Steuerung", "Wert"], [
        ["Gewähren", _cell(view["grant"]) + (f" ({view['operator']})" if view["operator"] else "")],
        ["Sitzung", _cell(view["session"])],
    ])
    explanation = _explain(ctx, view)  # None: Sprachmodell nicht erreichbar -> bestehende Beschreibung bleibt
    return propose_page(ctx, PageDraft(
        doc_type="entra_ca", title=f"Conditional Access: {view['name']}",
        description=f"Conditional-Access-Richtlinie {view['name']}",
        blocks=([Block("entra-ca-description", "Beschreibung", explanation)] if explanation is not None else []) + [
                Block("entra-ca-basics", "Grunddaten", basics),
                Block("entra-ca-assignments", "Zuweisungen", assignments),
                Block("entra-ca-conditions", "Bedingungen", conditions),
                Block("entra-ca-controls", "Zugriffssteuerung", controls)],
        path_vars={"name": view["name"]},
        intro=f"Dokumentation der Conditional-Access-Richtlinie **{view['name']}**. Die markierten Abschnitte "
              f"werden automatisch über Microsoft Graph (nur lesend) aktualisiert.",
        source=f"entra:ca:{policy.get('id')}", stable_id=f"entra:ca:{policy.get('id')}", sync_title=True,
    ))


def ca_page_path(ctx: Context, policy: dict) -> str:
    """Pfad der Richtlinienseite für Links aus der Übersicht: zugeordnete Seite, sonst der geplante Pfad."""
    mapped = ctx.store.kv_get(f"page-for:entra:ca:{policy.get('id')}")
    if mapped:
        page = next((p for p in ctx.conventions.pages if p.id == int(mapped)), None)
        if page:
            return page.path
    template = ctx.cfg.wiki.paths.get("entra_ca") or "{name}"
    values = {"name": policy.get("displayName") or policy.get("id")}  # wie in ca_policy_page
    path = render_path(template, values, "kebab")
    style = ctx.conventions.profile_for_path(path).slug_style
    return path if style == "kebab" else render_path(template, values, style)


def ca_overview(ctx: Context, data: EntraData, names: Names) -> tuple[str, list[Block]]:
    rows, counts = [], {}
    for policy in sorted(data.policies, key=lambda p: (p.get("displayName") or "").lower()):
        view = policy_view(policy, names)
        counts[view["state"]] = counts.get(view["state"], 0) + 1
        who = _short(view["users_in"]) + (f"; ohne {_short(view['users_out'], 2)}" if view["users_out"] else "")
        what = _short(view["apps_in"] + view["actions"]) + (f"; ohne {_short(view['apps_out'], 2)}"
                                                             if view["apps_out"] else "")
        when = _short([f"{k}: {v}" for k, v in view["conditions"]], 2)
        then = _short(view["grant"] + view["session"], 3)
        rows.append([markdown.link(ca_page_path(ctx, policy), view["name"]), view["state"], who or "–", what or "–",
                     when or "–", then or "–"])
    summary = markdown.table(["Status", "Richtlinien"], [[k, v] for k, v in sorted(counts.items())]) \
        if counts else "_Keine Richtlinien._"
    table = markdown.table(["Richtlinie", "Status", "Benutzer", "Ressourcen", "Bedingungen", "Steuerung"], rows) \
        if rows else "_Keine Conditional-Access-Richtlinien._"
    return ("Alle Conditional-Access-Richtlinien des Mandanten mit Zuweisung, Bedingungen und Steuerung. Details und "
            "Erklärung stehen auf der Seite der jeweiligen Richtlinie."), [
        Block("entra-ca-overview", "Übersicht", summary), Block("entra-ca-policies", "Richtlinien", table)]


def _usage(data: EntraData, key: str, value: str) -> list[str]:
    out = []
    for p in data.policies:
        cond = p.get("conditions") or {}
        if key == "location":
            loc = cond.get("locations") or {}
            if value in (loc.get("includeLocations") or []):
                out.append(p.get("displayName"))
            elif value in (loc.get("excludeLocations") or []):
                out.append(f"{p.get('displayName')} (ausgenommen)")
        elif ((p.get("grantControls") or {}).get("authenticationStrength") or {}).get("id") == value:
            out.append(p.get("displayName"))
    return sorted(out, key=str.lower)


def locations_page(ctx: Context, data: EntraData, names: Names) -> tuple[str, list[Block]]:
    rows = []
    for loc in sorted(data.locations, key=lambda x: (x.get("displayName") or "").lower()):
        if "ipRanges" in loc or loc.get("@odata.type", "").endswith("ipNamedLocation"):
            kind = "IP-Bereiche"
            value = ", ".join(r.get("cidrAddress", "") for r in loc.get("ipRanges") or [])
            trusted = "ja" if loc.get("isTrusted") else "nein"
        else:
            kind = "Länder"
            value = ", ".join(loc.get("countriesAndRegions") or [])
            if loc.get("includeUnknownCountriesAndRegions"):
                value += " + unbekannte"
            if loc.get("countryLookupMethod") == "authenticatorAppGps":
                kind += " (GPS)"
            trusted = "–"
        rows.append([loc.get("displayName"), kind, trusted, value or "–",
                     _cell(_usage(data, "location", loc.get("id")))])
    table = markdown.table(["Standort", "Art", "Vertrauenswürdig", "Bereiche/Länder", "Verwendet in"], rows) \
        if rows else "_Keine benannten Standorte._"
    return ("Benannte Standorte für Conditional Access (IP-Bereiche und Länder) und die Richtlinien, die sie "
            "verwenden."), [Block("entra-locations", "Standorte", table)]


def _combos(values) -> str:
    return "<br>".join(" + ".join(AUTH_COMBOS.get(p, p) for p in c.split(",")) for c in values or []) or "–"


def strengths_page(ctx: Context, data: EntraData, names: Names) -> tuple[str, list[Block]]:
    rows = []
    for s in sorted(data.strengths, key=lambda x: (x.get("policyType") != "custom", (x.get("displayName") or "").lower())):
        rows.append([s.get("displayName"), "benutzerdefiniert" if s.get("policyType") == "custom" else "integriert",
                     _combos(s.get("allowedCombinations")), _cell(_usage(data, "strength", s.get("id")))])
    table = markdown.table(["Stärke", "Art", "Erlaubte Kombinationen", "Verwendet in"], rows) \
        if rows else "_Keine Authentifizierungsstärken._"
    return "Authentifizierungsstärken (welche Methodenkombinationen eine Richtlinie verlangt).", [
        Block("entra-strengths", "Authentifizierungsstärken", table)]


# --- Authentifizierungsmethoden ---------------------------------------------------

SKIP_METHOD_KEYS = {"id", "state", "includeTargets", "excludeTargets", "@odata.type", "@odata.context"}


def _targets(targets: list[dict] | None, names: Names) -> str:
    out = []
    for t in targets or []:
        if t.get("id") == "all_users":
            out.append("Alle Benutzer")
        elif t.get("targetType") == "group" or t.get("targetType") is None:
            out.append(names.group(t.get("id", "")))
        else:
            out.append(f"{t.get('targetType')}: {t.get('id')}")
    return _cell(sorted(out, key=str.lower))


def _settings(obj: dict) -> str:
    from doku_agent.generators.intune_docs import flatten
    rows = [f"{k}: {v}" for k, v in flatten({k: v for k, v in obj.items() if k not in SKIP_METHOD_KEYS})]
    return "<br>".join(rows[:12]) or "–"


def methods_page(ctx: Context, data: EntraData, names: Names) -> tuple[str, list[Block]]:
    configs = data.methods.get("authenticationMethodConfigurations") or []
    rows = []
    for m in sorted(configs, key=lambda x: (x.get("state") != "enabled", METHODS.get(x.get("id"), x.get("id", "")))):
        rows.append([METHODS.get(m.get("id"), m.get("id")), "aktiv" if m.get("state") == "enabled" else "aus",
                     _targets(m.get("includeTargets"), names) if m.get("state") == "enabled" else "–",
                     _targets(m.get("excludeTargets"), names), _settings(m)])
    table = markdown.table(["Methode", "Status", "Für", "Ausgenommen", "Einstellungen"], rows) \
        if rows else "_Keine Methoden._"
    campaign = ((data.methods.get("registrationEnforcement") or {}).get("authenticationMethodsRegistrationCampaign")) or {}
    general = markdown.table(["Einstellung", "Wert"], [
        ["Migrationsstatus", {"premigration": "vor der Migration (alte MFA-/SSPR-Richtlinien gelten auch)",
                              "migrationinprogress": "Migration läuft",
                              "migrationcomplete": "abgeschlossen (nur diese Richtlinie gilt)"}.get(
            (data.methods.get("policyMigrationState") or "").lower(), data.methods.get("policyMigrationState") or "–")],
        ["Registrierungskampagne", {"enabled": "aktiv", "disabled": "aus", "default": "Microsoft-Standard"}.get(
            campaign.get("state"), campaign.get("state") or "–")],
        ["Kampagne für", _targets(campaign.get("includeTargets"), names) if campaign else "–"],
        ["Aufschieben (Tage)", campaign.get("snoozeDurationInDays", "–")],
    ])
    return ("Welche Anmeldemethoden im Mandanten erlaubt sind und für wen (Richtlinie für "
            "Authentifizierungsmethoden)."), [
        Block("entra-methods", "Methoden", table), Block("entra-methods-general", "Allgemein", general)]


# --- Mandanten-Einstellungen --------------------------------------------------------

def _yes(value) -> str:
    return "ja" if value is True else "nein" if value is False else "–"


USER_CONSENT = {
    "ManagePermissionGrantsForSelf.microsoft-user-default-legacy": "Benutzer dürfen allen Apps zustimmen",
    "ManagePermissionGrantsForSelf.microsoft-user-default-low":
        "nur Apps verifizierter Herausgeber mit wenig riskanten Berechtigungen",
}


def user_consent(auth: dict) -> str:
    grants = [g for g in auth.get("defaultUserRolePermissions", {}).get("permissionGrantPoliciesAssigned") or []
              if g.startswith("ManagePermissionGrantsForSelf.")]
    if not grants:
        return "nicht erlaubt (nur Administratoren)"
    return "; ".join(USER_CONSENT.get(g, g.split(".", 1)[1]) for g in grants)


def _reviewer(query: str, names: Names) -> str:
    m = re.match(r"^/users/([0-9a-f-]{36})$", query or "", re.I)
    if m:
        return names.user(m.group(1))
    m = re.match(r"^/groups/([0-9a-f-]{36})", query or "", re.I)
    if m:
        return f"Gruppe: {names.group(m.group(1))}"
    m = re.search(r"roleDefinitionId eq '([0-9a-f-]{36})'", query or "", re.I)
    if m:
        return f"Rolle: {names.role(m.group(1))}"
    return query or "–"


def _access(setting: dict | None) -> str:
    if not setting:
        return "–"
    parts = []
    for key, label in (("usersAndGroups", "Benutzer"), ("applications", "Apps")):
        target = setting.get(key) or {}
        if target:
            kind = {"allowed": "erlaubt", "blocked": "blockiert"}.get(target.get("accessType"), target.get("accessType"))
            targets = [t.get("target", "") for t in target.get("targets") or []]
            scope = "alle" if any(t.startswith("All") for t in targets) else f"{len(targets)} ausgewählte"
            parts.append(f"{label}: {kind}" + (f" ({scope})" if targets else ""))
    return "; ".join(parts) or "–"


def tenant_page(ctx: Context, data: EntraData, names: Names) -> tuple[str, list[Block]]:
    auth = data.authorization
    perms = auth.get("defaultUserRolePermissions") or {}
    users = markdown.table(["Einstellung", "Wert"], [
        ["Sicherheitsstandards", "aktiv" if data.security_defaults.get("isEnabled") else "aus"],
        ["Benutzer dürfen Apps registrieren", _yes(perms.get("allowedToCreateApps"))],
        ["Benutzer dürfen Sicherheitsgruppen erstellen", _yes(perms.get("allowedToCreateSecurityGroups"))],
        ["Benutzer dürfen Mandanten erstellen", _yes(perms.get("allowedToCreateTenants"))],
        ["Benutzer dürfen andere Benutzer lesen", _yes(perms.get("allowedToReadOtherUsers"))],
        ["BitLocker-Schlüssel eigener Geräte lesen", _yes(perms.get("allowedToReadBitlockerKeysForOwnedDevice"))],
        ["Benutzerzustimmung für Apps", user_consent(auth)],
        ["Self-Service-Kennwortzurücksetzung für Administratoren", _yes(auth.get("allowedToUseSSPR"))],
        ["Selbstregistrierung per E-Mail (Abonnements)", _yes(auth.get("allowedToSignUpEmailBasedSubscriptions"))],
        ["E-Mail-verifizierte Benutzer dürfen beitreten", _yes(auth.get("allowEmailVerifiedUsersToJoinOrganization"))],
        ["MSOnline-PowerShell blockiert", _yes(auth.get("blockMsolPowerShell"))],
    ])
    guests = markdown.table(["Einstellung", "Wert"], [
        ["Gäste einladen dürfen", INVITES.get(auth.get("allowInvitesFrom"), auth.get("allowInvitesFrom") or "–")],
        ["Zugriff von Gästen", GUEST_ROLES.get(auth.get("guestUserRoleId"), auth.get("guestUserRoleId") or "–")],
    ])
    consent = data.consent_requests
    consent_rows = [["Anforderungen an Administratoren", "aktiv" if consent.get("isEnabled") else "aus"]]
    if consent.get("isEnabled"):
        consent_rows += [["Prüfer", _cell([_reviewer(r.get("query"), names) for r in consent.get("reviewers") or []])],
                         ["Gültig (Tage)", consent.get("requestDurationInDays", "–")],
                         ["Prüfer benachrichtigen", _yes(consent.get("notifyReviewers"))],
                         ["Erinnerungen", _yes(consent.get("remindersEnabled"))]]
    default = data.cross_tenant
    trust = default.get("inboundTrust") or {}
    cross = markdown.table(["Richtung", "Standard"], [
        ["B2B-Zusammenarbeit eingehend", _access(default.get("b2bCollaborationInbound"))],
        ["B2B-Zusammenarbeit ausgehend", _access(default.get("b2bCollaborationOutbound"))],
        ["B2B-Direktverbindung eingehend", _access(default.get("b2bDirectConnectInbound"))],
        ["B2B-Direktverbindung ausgehend", _access(default.get("b2bDirectConnectOutbound"))],
        ["Vertrauen: MFA anderer Mandanten", _yes(trust.get("isMfaAccepted"))],
        ["Vertrauen: konforme Geräte", _yes(trust.get("isCompliantDeviceAccepted"))],
        ["Vertrauen: Hybrid-eingebundene Geräte", _yes(trust.get("isHybridAzureADJoinedDeviceAccepted"))],
    ])
    partner_rows = [[p.get("tenantId"), _yes((p.get("inboundTrust") or {}).get("isMfaAccepted")),
                     _access(p.get("b2bCollaborationInbound")) if p.get("b2bCollaborationInbound") else "Standard",
                     _access(p.get("b2bCollaborationOutbound")) if p.get("b2bCollaborationOutbound") else "Standard"]
                    for p in data.partners]
    cross += "\n\n" + (markdown.table(["Partner-Mandant", "MFA vertraut", "B2B eingehend", "B2B ausgehend"],
                                      partner_rows) if partner_rows else "_Keine organisationsspezifischen Einstellungen._")
    return "Mandantenweite Einstellungen: Sicherheitsstandards, Benutzer- und Gastrechte, App-Zustimmung und " \
           "mandantenübergreifender Zugriff.", [
        Block("entra-tenant-users", "Benutzer und Sicherheitsstandards", users),
        Block("entra-tenant-guests", "Gäste", guests),
        Block("entra-tenant-consent", "Admin-Zustimmungsanforderungen", markdown.table(["Einstellung", "Wert"],
                                                                                         consent_rows)),
        Block("entra-tenant-cross", "Mandantenübergreifender Zugriff", cross),
    ]


# --- Rollen -------------------------------------------------------------------------

PRINCIPAL_KINDS = {"user": "Benutzer", "group": "Gruppe", "servicePrincipal": "Dienstprinzipal"}


def _principal(obj: dict | None, pid: str, names: Names) -> tuple[str, str]:
    """(Name, Art) eines Rollen-Prinzipals aus $expand=principal; fehlt er, ist das Objekt gelöscht."""
    if not obj:
        return f"gelöschtes Objekt ({pid})", "–"
    kind = obj.get("@odata.type", "").replace("#microsoft.graph.", "")
    name = obj.get("displayName") or pid
    if kind == "user":
        if names.mode == "count":
            return "Benutzer", "Benutzer"
        upn = obj.get("userPrincipalName") or ""
        return (f"{name} ({upn})" if names.mode == "name_upn" and upn and upn != name else name), "Benutzer"
    return name, PRINCIPAL_KINDS.get(kind, kind or "–")


def _until(value) -> str:
    return str(value)[:10] if value else ""


def role_rows(data: EntraData, names: Names) -> dict[str, list[dict]]:
    """Rollen-ID -> Zuweisungen [{name, kind, type, scope, principal_id, guest, eligible, permanent}].
    permanent ist None, wenn ohne PIM nicht erkennbar ist, ob eine aktive Zuweisung befristet ist."""
    out: dict[str, list[dict]] = {}

    def add(item: dict, eligible: bool):
        obj = item.get("principal")
        name, kind = _principal(obj, item.get("principalId", ""), names)
        scope = item.get("directoryScopeId") or "/"
        if eligible:
            end = _until(((item.get("scheduleInfo") or {}).get("expiration") or {}).get("endDateTime"))
            typ, permanent = (f"berechtigt bis {end}" if end else "berechtigt (unbefristet)"), not end
        elif "assignmentType" in item:  # PIM-Instanz
            end = _until(item.get("endDateTime"))
            if item.get("assignmentType") == "Activated":
                typ, permanent = f"aktiviert bis {end}" if end else "aktiviert", False
            else:
                typ, permanent = (f"aktiv bis {end}" if end else "aktiv (dauerhaft)"), not end
        else:
            typ, permanent = "aktiv", None
        out.setdefault(item.get("roleDefinitionId", ""), []).append({
            "name": name, "kind": kind, "type": typ, "scope": "Mandant" if scope == "/" else scope,
            "principal_id": item.get("principalId", ""), "eligible": eligible, "permanent": permanent,
            "guest": "#EXT#" in ((obj or {}).get("userPrincipalName") or "") or (obj or {}).get("userType") == "Guest"})
    for a in data.assignments:
        add(a, False)
    for e in data.eligibilities or []:
        add(e, True)
    return out


def _privileged(definition: dict) -> bool:
    """isPrivileged gibt es nur in Graph beta; sonst die Administratorrollen der Microsoft-Vorlage."""
    if "isPrivileged" in definition:
        return bool(definition["isPrivileged"])
    return (definition.get("templateId") or definition.get("id")) in PRIVILEGED_ROLES


def roles_page(ctx: Context, data: EntraData, names: Names) -> tuple[str, list[Block]]:
    by_role = role_rows(data, names)
    defs = {d.get("id"): d for d in data.role_definitions}
    overview, sections = [], []
    order = sorted(by_role, key=lambda r: (not _privileged(defs.get(r, {"id": r})), names.role(r).lower()))
    for rid in order:
        items = by_role[rid]
        priv = _privileged(defs.get(rid, {"id": rid}))
        active = sum(not i["eligible"] for i in items)
        overview.append([names.role(rid), "ja" if priv else "–", active, len(items) - active])
        rows = [[i["name"], i["kind"], i["type"], i["scope"]]
                for i in sorted(items, key=lambda i: (i["eligible"], i["name"].lower()))]
        sections.append(f"### {names.role(rid)}\n\n" + markdown.table(["Wer", "Art", "Zuweisung", "Bereich"], rows))
    pim = "" if data.eligibilities is not None else \
        f"\n\n_Berechtigte Zuweisungen (PIM) nicht verfügbar: {data.pim_note or 'keine Daten'}._"
    table = markdown.table(["Rolle", "Privilegiert", "Aktiv", "Berechtigt (PIM)"], overview) \
        if overview else "_Keine Rollenzuweisungen._"
    return ("Verzeichnisrollen mit Zuweisungen: aktive und über Privileged Identity Management berechtigte. "
            "Privilegierte Rollen stehen oben."), [
        Block("entra-roles-overview", "Übersicht", table + pim),
        Block("entra-roles-details", "Zuweisungen je Rolle", "\n\n".join(sections) or "_Keine._"),
    ]


# --- Prüfung ------------------------------------------------------------------------

def _enabled(data: EntraData) -> list[dict]:
    return [p for p in data.policies if p.get("state") == "enabled"]


def _requires_mfa(policy: dict) -> bool:
    grant = policy.get("grantControls") or {}
    return "mfa" in (grant.get("builtInControls") or []) or bool(grant.get("authenticationStrength"))


def _unconditional(policy: dict) -> bool:
    """Gilt ohne einschränkende Bedingung: Standort, Plattform, Risiko, Gerätefilter oder nur einzelne Clients
    (Browser + Apps/Desktop zählt als vollständig – MFA ist mit Legacy-Clients ohnehin nicht möglich)."""
    c = policy.get("conditions") or {}
    loc = c.get("locations") or {}
    platforms = c.get("platforms") or {}
    clients = set(c.get("clientAppTypes") or ["all"])
    return (loc.get("includeLocations") or ["All"]) == ["All"] and not loc.get("excludeLocations") \
        and (platforms.get("includePlatforms") or ["all"]) == ["all"] and not platforms.get("excludePlatforms") \
        and not any(c.get(k) for k in ("signInRiskLevels", "userRiskLevels", "insiderRiskLevels")) \
        and not ((c.get("devices") or {}).get("deviceFilter") or {}).get("rule") \
        and ("all" in clients or {"browser", "mobileAppsAndDesktopClients"} <= clients)


def _all_apps(policy: dict) -> bool:
    return "All" in (((policy.get("conditions") or {}).get("applications") or {}).get("includeApplications") or [])


def _covers(policy: dict, role: str | None) -> bool:
    users = (policy.get("conditions") or {}).get("users") or {}
    if role and role in (users.get("excludeRoles") or []):
        return False
    return "All" in (users.get("includeUsers") or []) or (role is not None and role in (users.get("includeRoles") or []))


def _legacy_blocked(data: EntraData) -> list[str]:
    hits = []
    for p in _enabled(data):
        c = p.get("conditions") or {}
        if "block" in ((p.get("grantControls") or {}).get("builtInControls") or []) and _all_apps(p) \
                and "All" in ((c.get("users") or {}).get("includeUsers") or []) \
                and {"exchangeActiveSync", "other"} <= set(c.get("clientAppTypes") or []):
            hits.append(p.get("displayName"))
    return hits


def _breakglass_ids(ctx: Context, names: Names) -> tuple[dict[str, str], list[list]]:
    """Objekt-ID -> Anzeige (wie entra.user_names; "Notfallkonto n" im Modus count) und Befunde für
    nicht gefundene bzw. nicht lesbare Konten."""
    found, problems = {}, []
    for n, ident in enumerate(ctx.cfg.entra.breakglass, 1):
        u = ctx.entra.user(ident)
        if names.mode == "count":
            label = f"Notfallkonto {n}"
        elif u.get("id"):
            label = names.user(u["id"])
        else:
            label = ident if names.mode == "name_upn" else f"Notfallkonto {n}"
        if u.get("_deleted"):
            problems.append([label, "Notfallkonto nicht gefunden"])
        elif u.get("_error") or not u.get("id"):
            problems.append([label, f"Notfallkonto nicht lesbar ({u.get('_error') or 'ohne ID'}) – Ausnahmen nicht "
                                    f"geprüft; fehlt User.Read.All?"])
        else:
            found[u["id"]] = label
    return found, problems


def audit(ctx: Context, data: EntraData, names: Names) -> dict[str, list[list]]:
    f: dict[str, list[list]] = {k: [] for k in ("state", "baseline", "breakglass", "deleted", "roles", "tenant",
                                                "methods")}
    defaults_on = bool(data.security_defaults.get("isEnabled"))
    for p in sorted(data.policies, key=lambda p: (p.get("displayName") or "").lower()):
        if p.get("state") != "enabled":
            f["state"].append([p.get("displayName"), STATE.get(p.get("state"), p.get("state"))])
    enabled = _enabled(data)

    # Grundschutz: MFA für alle, MFA für Administratoren, Legacy-Authentifizierung blockiert
    if not defaults_on:
        mfa_all = [p for p in enabled if _requires_mfa(p) and _all_apps(p) and _covers(p, None)]
        if not any(_unconditional(p) for p in mfa_all):
            f["baseline"].append(["MFA für alle Benutzer", "keine aktive Richtlinie ohne Einschränkung" + (
                f" (nur bedingt: {_short([p.get('displayName') for p in mfa_all])})" if mfa_all else "")])
        for rid, label in ADMIN_ROLES.items():
            covering = [p for p in enabled if _requires_mfa(p) and _all_apps(p) and _covers(p, rid)]
            if not any(_unconditional(p) for p in covering):
                f["baseline"].append([f"MFA für {names.role(rid) if rid in names.roles else label}",
                                      "keine aktive Richtlinie ohne Einschränkung" + (
                                          f" (nur bedingt: {_short([p.get('displayName') for p in covering])})"
                                          if covering else "")])
        if not _legacy_blocked(data):
            f["baseline"].append(["Legacy-Authentifizierung", "wird von keiner aktiven Richtlinie für alle Benutzer "
                                                              "und Ressourcen blockiert"])
        if not enabled:
            f["baseline"].append(["Sicherheitsstandards", "aus, und es gibt keine aktive Conditional-Access-Richtlinie"])

    # Notfallkonten
    accounts, problems = _breakglass_ids(ctx, names) if ctx.cfg.entra.breakglass else ({}, [])
    f["breakglass"] += problems
    if accounts:
        for p in enabled:
            users = (p.get("conditions") or {}).get("users") or {}
            excluded_groups = users.get("excludeGroups") or []
            for uid, upn in accounts.items():
                if uid in (users.get("excludeUsers") or []):
                    continue
                members = [ctx.entra.member_ids(g) for g in excluded_groups]
                if any(m is not None and uid in m for m in members):
                    continue
                unknown = any(m is None for m in members)
                f["breakglass"].append([upn, f"nicht ausgenommen in „{p.get('displayName')}“" + (
                    " (Mitglieder ausgenommener Gruppen nicht lesbar)" if unknown else "")])
    elif not ctx.cfg.entra.breakglass and enabled:
        counts: dict[str, int] = {}
        for p in enabled:
            for uid in ((p.get("conditions") or {}).get("users") or {}).get("excludeUsers") or []:
                counts[uid] = counts.get(uid, 0) + 1
        candidates = [uid for uid, n in counts.items() if n >= max(2, len(enabled) // 2)]
        hint = "keine Notfallkonten konfiguriert (`entra.breakglass`)"
        if candidates and names.mode != "count":
            hint += "; mögliche Kandidaten (in vielen Richtlinien ausgenommen): " + ", ".join(
                sorted(names.user(u) for u in candidates))
        f["breakglass"].append(["–", hint])

    # Verweise auf gelöschte Objekte (beim Aufbau der Richtlinien-Sichten gesammelt)
    for p in data.policies:
        before = len(names.deleted)
        policy_view(p, names)
        for kind, oid in names.deleted[before:]:
            f["deleted"].append([p.get("displayName"), kind, oid])

    # Rollen
    by_role = role_rows(data, names)
    global_admins = {i["principal_id"] for i in by_role.get(GLOBAL_ADMIN, [])}  # aktiv oder berechtigt
    if len(global_admins) > ctx.cfg.entra.max_global_admins:
        f["roles"].append(["Global Administrator", f"{len(global_admins)} Zuweisungen (empfohlen höchstens "
                                                   f"{ctx.cfg.entra.max_global_admins})"])
    if 0 < len(global_admins) < 2:
        f["roles"].append(["Global Administrator", "nur eine Zuweisung – mindestens zwei (Notfallkonten) empfohlen"])
    defs = {d.get("id"): d for d in data.role_definitions}
    for rid, items in by_role.items():
        if not _privileged(defs.get(rid, {"id": rid})):
            continue
        for i in items:
            if i["guest"]:
                f["roles"].append([names.role(rid), f"Gastkonto {i['name']} ({i['type']})"])
            if i["permanent"] and not i["eligible"] and i["kind"] == "Benutzer" \
                    and i["principal_id"] not in accounts:
                f["roles"].append([names.role(rid), f"{i['name']}: dauerhaft aktiv statt über PIM berechtigt"])

    # Mandant
    auth = data.authorization
    perms = auth.get("defaultUserRolePermissions") or {}
    if perms.get("allowedToCreateApps"):
        f["tenant"].append(["App-Registrierungen", "alle Benutzer dürfen Apps registrieren"])
    if any(g.endswith("microsoft-user-default-legacy") for g in perms.get("permissionGrantPoliciesAssigned") or []):
        f["tenant"].append(["Benutzerzustimmung", "Benutzer dürfen allen Apps zustimmen"])
    if auth.get("allowInvitesFrom") == "everyone":
        f["tenant"].append(["Gasteinladungen", "jeder, auch Gäste, darf einladen"])
    if auth.get("guestUserRoleId") == "a0b1b346-4d3e-4e8b-98f8-753987be4970":
        f["tenant"].append(["Gastzugriff", "Gäste haben dieselben Rechte wie Mitglieder"])

    # Methoden
    for m in data.methods.get("authenticationMethodConfigurations") or []:
        if m.get("id") in WEAK_METHODS and m.get("state") == "enabled":
            f["methods"].append([METHODS.get(m["id"], m["id"]), "aktiv – leicht abzufangen, nicht phishing-resistent"])
    return f


AUDIT_SECTIONS = [
    ("Richtlinien nicht durchgesetzt", "state", ["Richtlinie", "Status"],
     "Aus oder nur im Berichtsmodus – sie schützen nichts."),
    ("Grundschutz", "baseline", ["Prüfung", "Befund"],
     "Ohne Sicherheitsstandards braucht es Richtlinien für MFA (alle Benutzer und Administratoren) und gegen "
     "Legacy-Authentifizierung, die ohne Standort-, Plattform-, Risiko- oder Gerätebedingung gelten."),
    ("Notfallkonten", "breakglass", ["Konto", "Befund"],
     "Notfallkonten müssen von allen aktiven Richtlinien ausgenommen sein, damit ein Fehler nicht alle aussperrt."),
    ("Verweise auf gelöschte Objekte", "deleted", ["Richtlinie", "Art", "ID"], ""),
    ("Privilegierte Rollen", "roles", ["Rolle", "Befund"], ""),
    ("Mandanten-Einstellungen", "tenant", ["Einstellung", "Befund"], ""),
    ("Authentifizierungsmethoden", "methods", ["Methode", "Befund"], ""),
]


def audit_page(ctx: Context, data: EntraData, names: Names) -> tuple[str, list[Block]]:
    f = audit(ctx, data, names)
    overview = markdown.table(["Prüfung", "Befunde"], [[t, len(f[k])] for t, k, _, _ in AUDIT_SECTIONS])
    body = []
    for title, key, headers, note in AUDIT_SECTIONS:
        rows = f[key]
        body.append(f"### {title}\n\n" + (f"{note}\n\n" if note and rows else "")
                    + (markdown.table(headers, rows) if rows else "_Keine Befunde._"))
    note = "" if data.eligibilities is not None else \
        " Ohne PIM-Daten wird nicht geprüft, ob privilegierte Rollen dauerhaft statt berechtigt vergeben sind."
    blocks = []
    context = (f"Sicherheitsstandards: {'aktiv' if data.security_defaults.get('isEnabled') else 'aus'}\n"
               f"Conditional-Access-Richtlinien: {len(data.policies)}, davon aktiv: {len(_enabled(data))}")
    if data.eligibilities is None:
        context += ("\nNicht geprüft: PIM-Daten fehlen, daher ist unbekannt, ob Admin-Rollen dauerhaft statt "
                    "berechtigt vergeben sind")
    if not ctx.cfg.entra.breakglass:
        context += "\nKeine Notfallkonten konfiguriert, deren Ausnahmen geprüft werden könnten"
    text = narrative.assessment(ctx, "entra-audit", expert="Microsoft Entra ID und Identitätssicherheit",
                                subject="Entra ID", context=context,
                                sections=[(title, headers, f[key]) for title, key, headers, _ in AUDIT_SECTIONS]) \
        if narrative.enabled(ctx, "audit") else None
    if text is not None:
        blocks.append(Block("entra-audit-assessment", "Bewertung", text))
    return ("Automatische Prüfung der Entra-ID-Konfiguration: nicht durchgesetzte Richtlinien, fehlender "
            "Grundschutz, Notfallkonten, Verweise auf gelöschte Objekte, privilegierte Rollen und riskante "
            "Mandanten-Einstellungen." + note), blocks + [
        Block("entra-audit-overview", "Übersicht", overview),
        Block("entra-audit-findings", "Befunde", "\n\n".join(body)),
    ]


BUILDERS = {"conditional-access": ca_overview, "benannte-standorte": locations_page,
            "authentifizierungsstaerken": strengths_page, "authentifizierungsmethoden": methods_page,
            "mandant": tenant_page, "rollen": roles_page, "pruefung": audit_page}


SLUG_AREA = {slug: area for area, pages in SECTIONS.items() for slug, _ in pages}


def section_stable_id(slug: str) -> str:
    return f"entra:{slug}"


SUMMARY_TASKS = {
    "conditional-access": "Fasse zusammen, wie der Zugriff im Mandanten über Conditional Access geregelt ist: welche "
                          "Richtlinien aktiv sind, wer ausgenommen ist, was für Administratoren und für alle "
                          "Benutzer gilt und welche Richtlinien noch nicht durchgesetzt werden.",
    "authentifizierungsmethoden": "Fasse zusammen, mit welchen Methoden sich Benutzer anmelden bzw. MFA durchführen "
                                  "können, für wen sie freigegeben sind und was das für die Sicherheit bedeutet "
                                  "(phishing-resistente gegenüber schwachen Methoden).",
    "mandant": "Fasse die mandantenweiten Einstellungen zusammen: Sicherheitsstandards, was normale Benutzer und Gäste "
               "dürfen, wie App-Zustimmungen geregelt sind und wie der Zugriff mit anderen Mandanten eingestellt ist.",
    "rollen": "Fasse zusammen, wer welche administrativen Rollen hat, ob sie dauerhaft, befristet oder nur über PIM "
              "berechtigt vergeben sind und was das für die Sicherheit bedeutet.",
}


def _propose_section(ctx: Context, slug: str, heading: str, data: EntraData, names: Names) -> int | None:
    intro, blocks = BUILDERS[slug](ctx, data, names)
    if slug in SUMMARY_TASKS and narrative.enabled(ctx, "overview"):
        facts = narrative.facts_from_markdown("\n\n".join(f"{b.heading}\n\n{b.content}" for b in blocks))
        fallback = f"Die Tabellen unten zeigen den aktuellen Stand der {heading} im Mandanten."
        text = narrative.narrate(ctx, f"entra-{slug}", expert="Microsoft Entra ID", task=SUMMARY_TASKS[slug],
                                 facts=facts, fallback=fallback)
        if text is not None:
            blocks.insert(0, Block(f"entra-{slug}-summary", "Zusammenfassung", text))
    return propose_page(ctx, PageDraft(
        doc_type="entra", title=f"Entra ID: {heading}", description=f"Entra ID – {heading}", blocks=blocks,
        path_vars={"section": slug},
        intro=f"{intro} Die markierten Abschnitte werden automatisch über Microsoft Graph (nur lesend) aktualisiert.",
        source="entra", stable_id=section_stable_id(slug),
    ))


def document_entra(ctx: Context, areas: list[str] | None = None) -> list[int | None]:
    """Seiten der gewünschten Bereiche (Standard: entra.include). Ist ein Bereich nicht lesbar, werden die
    übrigen dokumentiert; die Prüfung entfällt dann (sie wäre unvollständig), der Job meldet einen Fehler."""
    wanted = [a for a in ctx.cfg.entra.include if not areas or a in areas]
    groups = set().union(*(NEEDS[a] for a in wanted)) if wanted else set()
    data, errors = fetch(ctx, groups)
    for group, message in errors.items():
        ctx.log.error("Entra ID (%s) nicht lesbar: %s", group, message)
    names = Names(ctx, data)
    results: list[int | None] = []
    failed = []
    for area in wanted:
        if not NEEDS[area] <= data.loaded:
            failed.append(area)
            continue
        if area == "conditional_access":
            for policy in data.policies:
                results.append(ca_policy_page(ctx, policy, names))
        for slug, heading in SECTIONS[area]:
            results.append(_propose_section(ctx, slug, heading, data, names))
    if failed:
        raise RuntimeError("Entra ID unvollständig – nicht dokumentiert: " + ", ".join(AREA_LABELS[a] for a in failed)
                           + ". Die übrigen Bereiche wurden dokumentiert; Ursache siehe Meldungen oben.")
    return results


def document_section(ctx: Context, slug: str) -> int | None:
    """Eine Bereichsseite neu berechnen (Wiki-Lint)."""
    area = SLUG_AREA[slug]
    data, errors = fetch(ctx, NEEDS[area])
    if errors:
        raise RuntimeError("; ".join(errors.values()))
    return _propose_section(ctx, slug, dict(SECTIONS[area])[slug], data, Names(ctx, data))


def document_ca_policy(ctx: Context, policy_id: str) -> int | None:
    """Eine einzelne Richtlinie neu berechnen (Wiki-Lint); gelöschte liefern GraphError mit status 404.
    Standort- und Rollennamen wie im Gesamtlauf, damit beide dieselbe Seite erzeugen."""
    policy = ctx.entra.ca_policy(policy_id)
    data = EntraData(locations=ctx.entra.named_locations(), role_definitions=role_names(ctx))
    return ca_policy_page(ctx, policy, Names(ctx, data))
