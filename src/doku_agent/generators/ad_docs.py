"""Lokales Active Directory: Gruppenrichtlinien, OU-Struktur mit Delegationen, Kennwort- und Sperrrichtlinien,
privilegierte Gruppen und Konten, Domäne (Funktionsebenen, DCs, Standorte, Vertrauensstellungen) und eine Prüfung –
nur lesend über LDAP (TLS) und SYSVOL (SMB).

Tabellen und Befunde entstehen deterministisch; das LLM schreibt nur Beschreibung, Zusammenfassung und Bewertung.
Angaben, die sich ohne Änderung im AD täglich verschieben würden (z.B. "vor 37 Tagen"), stehen nicht auf den Seiten.
"""

from __future__ import annotations

import re

from doku_agent import markdown
from doku_agent.ad_acl import (CONTROL_ACCESS, GENERIC_ALL, GET_CHANGES_ALL, WRITE_DAC, WRITE_OWNER, WRITE_PROP,
                               is_admin, is_broad, is_default, is_write, parse_sd, protected_from_deletion,
                               rights_text, scope_text)
from doku_agent.connectors.ad import Entry, interval_seconds, parent_dn, rdn
from doku_agent.context import Context
from doku_agent.generators import gpo_docs, narrative
from doku_agent.generators.ad_common import (AREA_LABELS, DES_ONLY, DONT_EXPIRE, DONT_REQ_PREAUTH, FUNCTIONAL_LEVELS,
                                             NEEDS, NOT_DELEGATED, PARTIAL_SECRETS, PASSWD_NOTREQD, REVERSIBLE,
                                             SERVER_TRUST, TRUSTED_FOR_DELEGATION, TRUSTED_TO_AUTH, AdData, AdNames,
                                             day, dns_name, enabled, fetch, group_label, now, ou_path, stale, uac)
from doku_agent.pages import Block, PageDraft, propose_page

SECTIONS = {
    "gpo": [("gruppenrichtlinien", "Gruppenrichtlinien")],
    "ous": [("ou-struktur", "OU-Struktur und Delegationen")],
    "password_policy": [("kennwortrichtlinien", "Kennwort- und Sperrrichtlinien")],
    "privileged": [("privilegierte-konten", "Privilegierte Gruppen und Konten")],
    "domain": [("domaene", "Domäne und Gesamtstruktur")],
    "audit": [("pruefung", "Prüfung")],
}
SLUG_AREA = {slug: area for area, pages in SECTIONS.items() for slug, _ in pages}
TRUST_DIRECTION = {0: "deaktiviert", 1: "eingehend", 2: "ausgehend", 3: "beidseitig"}
TRUST_TYPE = {1: "Windows NT (extern)", 2: "Active Directory", 3: "Kerberos-Bereich (MIT)", 4: "DCE"}
NON_TRANSITIVE, QUARANTINED, FOREST_TRANSITIVE, CROSS_ORG, WITHIN_FOREST = 0x1, 0x4, 0x8, 0x10, 0x20
TREAT_AS_EXTERNAL, RC4, ENABLE_TGT_DELEGATION = 0x40, 0x80, 0x800
ENC_TYPES = {0x1: "DES-CBC-CRC", 0x2: "DES-CBC-MD5", 0x4: "RC4", 0x8: "AES128", 0x10: "AES256"}
WELLKNOWN_CONTAINERS = {"AA312825768811D1ADED00C04FD8D5CD": "Computer", "A9D1CA15768811D1ADED00C04FD8D5CD": "Benutzer"}
OLD_OS_BUILD = 14393  # vor Windows Server 2016 (Build 14393): kein Support mehr


# --- Domäne -----------------------------------------------------------------------------------------

def _seconds(value: int | None, unit: str) -> str:
    seconds = interval_seconds(value)
    if seconds is None:
        return "nie"
    if unit == "Tage":
        n = seconds // 86400
        return f"{n} {'Tag' if n == 1 else 'Tage'}"
    n = seconds // 60
    return f"{n} {'Minute' if n == 1 else 'Minuten'}"


def _level(value) -> str:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return "–"
    return f"{FUNCTIONAL_LEVELS.get(n, 'unbekannt')} ({n})"


def recycle_bin(data: AdData) -> bool | None:
    feature = next((f for f in data.features if f.str("cn").lower() == "recycle bin feature"), None)
    return None if feature is None else feature.has("msDS-EnabledFeatureBL")


def laps_text(data: AdData) -> str:
    kinds = [label for attr, label in (("msLAPS-PasswordExpirationTime", "Windows LAPS"),
                                       ("ms-Mcs-AdmPwdExpirationTime", "LAPS (Legacy)")) if data.laps.get(attr)]
    return ", ".join(kinds) + " im Schema" if kinds else "nicht im Schema"


def laps_covered(data: AdData, e: Entry) -> bool:
    return any(e.has(a) for a, present in data.laps.items() if present)


def _dc_site(ntds_dn: str) -> tuple[str, str]:
    """'CN=NTDS Settings,CN=DC1,CN=Servers,CN=Wien,CN=Sites,…' -> ('DC1', 'Wien')."""
    parts = re.split(r"(?<!\\),", ntds_dn)
    return (rdn(parts[1]) if len(parts) > 1 else "", rdn(parts[3]) if len(parts) > 3 else "")


def _computer_counts(data: AdData) -> tuple[int, int]:
    return len(data.computers), sum(enabled(c) for c in data.computers)


def domain_page(ctx: Context, data: AdData, names: AdNames) -> tuple[str, list[Block]]:
    d = data.domain
    users_active = sum(enabled(u) for u in data.users)
    comps, comps_active = _computer_counts(data)
    bin_on = recycle_bin(data)
    ds = data.directory_service
    tombstone = ds.int("tombstoneLifetime") if ds else None
    overview = markdown.table(["Eigenschaft", "Wert"], [
        ["DNS-Name", data.dns], ["NetBIOS-Name", data.crossref.str("nETBIOSName") if data.crossref else "–"],
        ["Domänen-SID", data.domain_sid], ["Erstellt", day(d.time("whenCreated")) or "–"],
        ["Domänenfunktionsebene", _level(d.int("msDS-Behavior-Version"))],
        ["Gesamtstrukturfunktionsebene", _level(data.forest_level)],
        ["Stammdomäne der Gesamtstruktur", dns_name(data.root.get("rootdomainnamingcontext", "")) or "–"],
        ["AD-Papierkorb", "aktiv" if bin_on else "aus" if bin_on is False else "–"],
        ["Tombstone-Lebensdauer", f"{tombstone} Tage" if tombstone else "Standard (180 Tage)"],
        ["Computer hinzufügen durch Benutzer (MachineAccountQuota)", d.int("ms-DS-MachineAccountQuota", 10)],
        ["LAPS", laps_text(data)],
        ["Benutzerkonten", f"{len(data.users)} (aktiviert: {users_active})"],
        ["Computerkonten", f"{comps} (aktiviert: {comps_active})"],
        ["Verwaltete Dienstkonten", len(data.msas)],
    ])
    roles: dict[str, list[str]] = {}
    for role, holder in data.fsmo.items():
        roles.setdefault(_dc_site(holder)[0].lower(), []).append(role)
    ntds = {_dc_site(n.dn)[0].lower(): n for n in data.ntds}
    dc_rows = []
    for dc in sorted(data.dcs, key=lambda e: e.name.lower()):
        n = ntds.get(dc.name.lower())
        site = _dc_site(n.dn)[1] if n else "–"
        dc_rows.append([dc.str("dNSHostName") or dc.name,
                        f"{dc.str('operatingSystem')} {dc.str('operatingSystemVersion')}".strip() or "–", site,
                        "ja" if n and (n.int("options", 0) or 0) & 1 else "nein",
                        "ja" if uac(dc) & PARTIAL_SECRETS else "nein", ", ".join(sorted(roles.get(dc.name.lower(), [])))
                        or "–"])
    dcs = markdown.table(["Domänencontroller", "Betriebssystem", "Standort", "Globaler Katalog", "Schreibgeschützt",
                          "FSMO-Rollen"], dc_rows) if dc_rows else "_Keine Domänencontroller gefunden._"
    subnets: dict[str, list[str]] = {}
    for s in data.subnets:
        subnets.setdefault(rdn(s.str("siteObject")).lower(), []).append(s.name)
    site_dcs: dict[str, list[str]] = {}
    for n in data.ntds:
        name, site = _dc_site(n.dn)
        site_dcs.setdefault(site.lower(), []).append(name)
    site_rows = [[s.name, ", ".join(sorted(subnets.get(s.name.lower(), []))) or "–",
                  ", ".join(sorted(site_dcs.get(s.name.lower(), []))) or "–",
                  "<br>".join(gpo_docs.link_text(data, s)) or "–"] for s in sorted(data.sites, key=lambda x: x.name)]
    orphan_subnets = sorted(s.name for s in data.subnets if not s.str("siteObject"))
    sites = markdown.table(["Standort", "Subnetze", "Domänencontroller", "Verknüpfte GPOs"], site_rows) \
        if site_rows else "_Keine Standorte._"
    if orphan_subnets:
        sites += f"\n\nSubnetze ohne Standort: {', '.join(orphan_subnets)}"
    link_rows = [[sl.name, ", ".join(sorted(rdn(x) for x in sl.strs("siteList"))), sl.int("cost") or "–",
                  f"{sl.int('replInterval')} Minuten" if sl.int("replInterval") else "–"]
                 for sl in sorted(data.site_links, key=lambda x: x.name)]
    if link_rows:
        sites += "\n\n" + markdown.table(["Standortverknüpfung", "Standorte", "Kosten", "Replikationsintervall"],
                                         link_rows)
    trust_rows = []
    for t in sorted(data.trusts, key=lambda x: x.str("trustPartner").lower()):
        attrs = t.int("trustAttributes", 0) or 0
        enc = t.int("msDS-SupportedEncryptionTypes")
        trust_rows.append([
            t.str("trustPartner"), t.str("flatName") or "–",
            TRUST_DIRECTION.get(t.int("trustDirection", -1), "–"),
            "Gesamtstruktur" if attrs & FOREST_TRANSITIVE else "innerhalb der Gesamtstruktur" if attrs & WITHIN_FOREST
            else TRUST_TYPE.get(t.int("trustType", 0), "–"),
            "nein" if attrs & NON_TRANSITIVE else "ja",
            "ja" if attrs & QUARANTINED or attrs & FOREST_TRANSITIVE and not attrs & TREAT_AS_EXTERNAL else "nein",
            "ja" if attrs & CROSS_ORG else "nein",
            ", ".join(v for k, v in ENC_TYPES.items() if enc & k) if enc else ("RC4" if attrs & RC4 else "Standard")])
    trusts = markdown.table(["Partner", "NetBIOS", "Richtung", "Art", "Transitiv", "SID-Filterung",
                             "Selektive Authentifizierung", "Verschlüsselung"], trust_rows) \
        if trust_rows else "_Keine Vertrauensstellungen._"
    os_counts: dict[str, int] = {}
    for c in data.computers:
        if enabled(c):
            key = c.str("operatingSystem") or "unbekannt"
            os_counts[key] = os_counts.get(key, 0) + 1
    systems = markdown.table(["Betriebssystem", "Aktivierte Computerkonten"],
                             sorted(([k, v] for k, v in os_counts.items()), key=lambda r: (-r[1], r[0]))) \
        if os_counts else "_Keine Computerkonten._"
    return ("Grunddaten der Domäne und Gesamtstruktur: Funktionsebenen, Domänencontroller mit Betriebsmasterrollen, "
            "Standorte und Subnetze, Vertrauensstellungen und die Betriebssysteme der Computerkonten."), [
        Block("ad-domain-overview", "Übersicht", overview),
        Block("ad-domain-dcs", "Domänencontroller", dcs),
        Block("ad-domain-sites", "Standorte und Replikation", sites),
        Block("ad-domain-trusts", "Vertrauensstellungen", trusts),
        Block("ad-domain-os", "Betriebssysteme", systems),
    ]


# --- OU-Struktur ------------------------------------------------------------------------------------

def delegation_aces(sd) -> list:
    """Explizite Einträge außerhalb der Schema-Vorgabe: echte Delegationen (ohne reine Leserechte und ohne den
    Löschschutz)."""
    if sd is None:
        return []
    out = []
    for ace in sd.dacl:
        if ace.inherited:
            continue
        if is_default(ace.sid) and not (is_broad(ace.sid) and is_write(ace)):  # Schreibrechte für alle sind nie Standard
            continue
        if ace.deny and ace.sid == "S-1-1-0" and ace.object_type is None:
            continue  # Löschschutz bzw. Standardverweigerung
        if is_write(ace) or ace.mask & CONTROL_ACCESS or ace.deny:
            out.append(ace)
    return out


def default_containers(data: AdData) -> list[list[str]]:
    rows = []
    for value in data.domain.strs("wellKnownObjects"):
        parts = value.split(":", 3)
        if len(parts) == 4 and parts[2].upper() in WELLKNOWN_CONTAINERS:
            dn = parts[3]
            is_default_cn = dn.upper().startswith("CN=")
            rows.append([f"Neue {WELLKNOWN_CONTAINERS[parts[2].upper()]}", ou_path(dn, data.base) or dn,
                         "Standardcontainer – dort wirken nur GPOs der Domäne und von Standorten" if is_default_cn
                         else "umgeleitet in eine OU"])
    return rows


def ou_page(ctx: Context, data: AdData, names: AdNames) -> tuple[str, list[Block]]:
    counts: dict[str, list[int]] = {}
    for kind, entries in ((0, data.users), (1, data.computers)):
        for e in entries:
            counts.setdefault(parent_dn(e.dn).lower(), [0, 0])[kind] += 1
    rows = []
    for obj, label, kind in gpo_docs.link_targets(data):
        if kind == "Standort":
            continue
        sd = parse_sd(obj.raw("nTSecurityDescriptor"))
        c = counts.get(obj.dn.lower(), [0, 0])
        depth = label.count(" / ")
        rows.append([("— " * depth) + (label.split(" / ")[-1] if kind == "OU" else label),
                     "<br>".join(gpo_docs.link_text(data, obj)) or "–",
                     "blockiert" if (obj.int("gPOptions", 0) or 0) & 1 else "–",
                     "ja" if protected_from_deletion(sd) else "nein" if sd else "–",
                     f"{c[0]} / {c[1]}", obj.str("description") or "–"])
    tree = markdown.table(["OU", "Verknüpfte GPOs (Reihenfolge)", "Vererbung", "Löschschutz",
                           "Benutzer / Computer (direkt)", "Beschreibung"], rows)
    delegations = []
    targets = [(data.domain, f"Domäne {data.dns}")] + [(o, ou_path(o.dn, data.base)) for o in data.ous]
    sids = []
    found = []
    for obj, label in targets:
        for ace in delegation_aces(parse_sd(obj.raw("nTSecurityDescriptor"))):
            found.append((label, ace))
            sids.append(ace.sid)
    names.resolve(sids)
    for label, ace in sorted(found, key=lambda x: (x[0].lower(), names.sid(x[1].sid).lower())):
        delegations.append([label, names.sid(ace.sid), "verweigern" if ace.deny else "zulassen",
                            rights_text(ace, data.guid_names), scope_text(ace, data.guid_names)])
    deleg = markdown.table(["Objekt", "Wer", "Art", "Rechte", "Gilt für"], delegations) if delegations else \
        "_Keine Delegationen außerhalb der Standardberechtigungen._"
    sd_missing = sum(1 for o in data.ous if not o.raw("nTSecurityDescriptor"))
    if sd_missing:
        deleg += f"\n\n_Berechtigungen von {sd_missing} OUs nicht lesbar._"
    defaults = default_containers(data)
    return ("Aufbau der Organisationseinheiten mit verknüpften Gruppenrichtlinien, blockierter Vererbung, Löschschutz "
            "und delegierten Berechtigungen (nur Einträge außerhalb der Standardrechte)."), [
        Block("ad-ou-tree", "Struktur", tree),
        Block("ad-ou-delegations", "Delegationen", deleg),
        Block("ad-ou-defaults", "Standardcontainer für neue Objekte",
              markdown.table(["Objekte", "Container", "Hinweis"], defaults) if defaults else "_Nicht lesbar._"),
    ]


# --- Kennwortrichtlinien ------------------------------------------------------------------------------

def domain_policy(d: Entry) -> list[list]:
    props = d.int("pwdProperties", 0) or 0
    threshold = d.int("lockoutThreshold", 0) or 0
    return [
        ["Minimale Kennwortlänge", f"{d.int('minPwdLength', 0)} Zeichen"],
        ["Kennwortchronik", f"{d.int('pwdHistoryLength', 0)} Kennwörter"],
        ["Maximales Kennwortalter", _seconds(d.int("maxPwdAge"), "Tage") if d.int("maxPwdAge") else "nie"],
        ["Minimales Kennwortalter", _seconds(d.int("minPwdAge"), "Tage") if d.int("minPwdAge") else "0 Tage"],
        ["Komplexität erforderlich", "ja" if props & 1 else "nein"],
        ["Umkehrbare Verschlüsselung", "ja" if props & 16 else "nein"],
        ["Kontensperrungsschwelle", f"{threshold} Fehlversuche" if threshold else "keine Sperre"],
        ["Sperrdauer", (_seconds(d.int("lockoutDuration"), "Minuten") if d.int("lockoutDuration") != -0x8000000000000000
                        else "bis ein Administrator entsperrt") if threshold else "–"],
        ["Zähler zurücksetzen nach", _seconds(d.int("lockOutObservationWindow"), "Minuten") if threshold else "–"],
    ]


def _pso_seconds(e: Entry, attr: str, unit: str) -> str:
    value = e.int(attr)
    return "nie" if value in (None, 0) and unit == "Tage" and attr == "msDS-MaximumPasswordAge" else \
        _seconds(value, unit) if value else "0"


def domain_gpo_template(data: AdData):
    """Sicherheitsvorlage der GPO mit höchster Priorität an der Domäne, die Kerberos-Werte setzt."""
    entries = gpo_docs.parse_gplink(data.domain.str("gPLink"))
    for dn, options in reversed(entries):  # Reihenfolge 1 zuerst
        if options & 1:
            continue
        files = data.files.get(gpo_docs.gpo_guid(dn).lower())
        if files is not None and files.template is not None and files.template.kerberos:
            return gpo_docs.gpo_name(data, gpo_docs.gpo_guid(dn)), files.template
    return None, None


def password_page(ctx: Context, data: AdData, names: AdNames) -> tuple[str, list[Block]]:
    domain = markdown.table(["Einstellung", "Wert"], domain_policy(data.domain))
    domain += ("\n\nGilt für alle Domänenkonten ohne feingranulare Richtlinie. Gesetzt wird sie über die GPO an der "
               "Domäne mit höchster Priorität (meist Default Domain Policy); die Werte oben sind die wirksamen.")
    if ctx.cfg.ad.sysvol and not data.files:  # nur die GPOs an der Domäne lesen
        try:
            for dn, _ in gpo_docs.parse_gplink(data.domain.str("gPLink")):
                guid = gpo_docs.gpo_guid(dn)
                if guid:
                    data.files[guid.lower()] = gpo_docs.load_files(ctx, data, guid)
        except RuntimeError as exc:
            ctx.log.warning("Kerberos-Richtlinie nicht lesbar (SYSVOL): %s", exc)
    if data.files:
        source, template = domain_gpo_template(data)
        if template is not None:
            rows = [[gpo_docs.KERBEROS.get(k, (k,))[0], gpo_docs._access_value(k, v)] for k, v in template.kerberos.items()]
            kerberos = markdown.table(["Einstellung", "Wert"], rows) + f"\n\nQuelle: GPO **{source}**."
        else:
            kerberos = "_Keine an der Domäne verknüpfte GPO setzt Kerberos-Werte – es gelten die Windows-Standards._"
    else:
        kerberos = "_Nicht gelesen (SYSVOL ist aus oder nicht erreichbar)._"
    rows = []
    for p in sorted(data.psos, key=lambda e: (e.int("msDS-PasswordSettingsPrecedence", 0), e.name.lower())):
        targets = [names.by_dn[dn.lower()] for dn in p.strs("msDS-PSOAppliesTo") if dn.lower() in names.by_dn]
        applies = [names.entry(t) for t in targets] + [rdn(dn) for dn in p.strs("msDS-PSOAppliesTo")
                                                         if dn.lower() not in names.by_dn]
        threshold = p.int("msDS-LockoutThreshold", 0) or 0
        rows.append([p.name, p.int("msDS-PasswordSettingsPrecedence"), p.int("msDS-MinimumPasswordLength"),
                     "ja" if p.bool("msDS-PasswordComplexityEnabled") else "nein",
                     p.int("msDS-PasswordHistoryLength"), _pso_seconds(p, "msDS-MaximumPasswordAge", "Tage"),
                     f"{threshold}" if threshold else "keine Sperre",
                     _seconds(p.int("msDS-LockoutDuration"), "Minuten") if threshold else "–",
                     "ja" if p.bool("msDS-PasswordReversibleEncryptionEnabled") else "nein",
                     ", ".join(sorted(applies, key=str.lower)) or "niemand"])
    psos = markdown.table(["Richtlinie", "Rangfolge", "Mindestlänge", "Komplexität", "Chronik", "Max. Alter",
                           "Sperrschwelle", "Sperrdauer", "Umkehrbar", "Gilt für"], rows) if rows else (
        "_Keine feingranularen Kennwortrichtlinien gefunden._ Standardmäßig dürfen nur Domänen-Admins sie lesen – "
        "für eine vollständige Dokumentation dem Lesekonto Leserechte auf "
        "`CN=Password Settings Container,CN=System` geben.")
    return ("Kennwort- und Kontosperrungsrichtlinie der Domäne, feingranulare Kennwortrichtlinien (PSOs) und die "
            "Kerberos-Richtlinie."), [
        Block("ad-password-domain", "Domänenrichtlinie", domain),
        Block("ad-password-psos", "Feingranulare Kennwortrichtlinien", psos),
        Block("ad-password-kerberos", "Kerberos-Richtlinie", kerberos),
    ]


# --- Privilegierte Konten -------------------------------------------------------------------------------

def _flags(e: Entry, data: AdData) -> list[str]:
    f = uac(e)
    out = []
    if f & DONT_EXPIRE:
        out.append("Kennwort läuft nie ab")
    if f & PASSWD_NOTREQD:
        out.append("Kennwort nicht erforderlich")
    if e.has("servicePrincipalName") and "computer" not in e.classes():
        out.append("SPN (Dienstkonto)")
    if f & DONT_REQ_PREAUTH:
        out.append("ohne Kerberos-Vorauthentifizierung")
    if f & NOT_DELEGATED:
        out.append("nicht delegierbar")
    if e.dn.lower() in data.protected_users:
        out.append("Protected Users")
    return out


def privileged_page(ctx: Context, data: AdData, names: AdNames) -> tuple[str, list[Block]]:
    days = ctx.cfg.ad.stale_days
    overview, details = [], []
    for pg in data.privileged:
        label = group_label(pg, names)
        if pg.group is None:
            continue
        accounts = [m for m in pg.members + pg.primary if "group" not in m.classes()]
        overview.append([label, len(accounts), sum(enabled(m) for m in accounts), len(pg.direct)])
        if not accounts and not pg.direct:
            continue
        nested = [rdn(dn) for dn in pg.direct if dn.lower() in names.by_dn and "group" in names.by_dn[dn.lower()]
                  .classes()] + [m.name for m in pg.members if "group" in m.classes()]
        if names.mode == "count":
            people = sum(1 for m in accounts if names.is_person(m))
            body = f"Benutzerkonten: {people}, weitere Konten: {len(accounts) - people}"
        else:
            rows = [[names.entry(m), "Computer" if "computer" in m.classes() else "Benutzer",
                     "ja" if enabled(m) else "nein", "inaktiv" if enabled(m) and stale(m, days) else "–",
                     day(m.time("pwdLastSet")) or "nie", ", ".join(_flags(m, data)) or "–"]
                    for m in sorted(accounts, key=lambda x: names.entry(x).lower())]
            body = markdown.table(["Konto", "Art", "Aktiviert", f"Ohne Anmeldung > {days} Tage", "Kennwort gesetzt",
                                   "Besonderheiten"], rows) if rows else "_Keine Konten._"
        if nested:
            body += f"\n\nVerschachtelte Gruppen: {', '.join(sorted(set(nested), key=str.lower))}"
        details.append(f"### {label}\n\n{body}")
    groups = markdown.table(["Gruppe", "Konten (inkl. verschachtelt)", "davon aktiviert", "Direkte Mitglieder"],
                            overview) if overview else "_Keine privilegierten Gruppen lesbar._"
    service = []
    for e in sorted(data.users, key=lambda x: x.str("sAMAccountName").lower()):
        if e.has("servicePrincipalName") and e.str("sAMAccountName").lower() != "krbtgt":
            service.append([names.entry(e), "Benutzer mit SPN", "<br>".join(sorted(e.strs("servicePrincipalName"))[:5]),
                            day(e.time("pwdLastSet")) or "nie", "ja" if enabled(e) else "nein"])
    for e in sorted(data.msas, key=lambda x: x.str("sAMAccountName").lower()):
        kind = "gMSA" if "msds-groupmanagedserviceaccount" in e.classes() else "sMSA"
        service.append([e.str("sAMAccountName"), kind, "<br>".join(sorted(e.strs("servicePrincipalName"))[:5]) or "–",
                        "automatisch", "ja" if enabled(e) else "nein"])
    services = markdown.table(["Konto", "Art", "Dienstprinzipalnamen", "Kennwort gesetzt", "Aktiviert"], service) \
        if service else "_Keine Dienstkonten._"
    deleg = []
    dcs = {e.dn.lower() for e in data.dcs}
    for e in sorted(data.users + data.computers + data.msas, key=lambda x: names.entry(x).lower()):
        f = uac(e)
        if f & TRUSTED_FOR_DELEGATION and e.dn.lower() not in dcs and not f & SERVER_TRUST:
            deleg.append([names.entry(e), "uneingeschränkt", "alle Dienste"])
        if e.has("msDS-AllowedToDelegateTo"):
            deleg.append([names.entry(e), "eingeschränkt" + (" mit Protokollübergang" if f & TRUSTED_TO_AUTH else ""),
                          "<br>".join(sorted(e.strs("msDS-AllowedToDelegateTo"))[:8])])
        if e.has("msDS-AllowedToActOnBehalfOfOtherIdentity"):
            sd = parse_sd(e.raw("msDS-AllowedToActOnBehalfOfOtherIdentity"))
            who = [a.sid for a in (sd.dacl if sd else []) if a.allow]
            names.resolve(who)
            deleg.append([names.entry(e), "ressourcenbasiert (an dieses Konto)",
                          ", ".join(names.sid(s) for s in who) or "–"])
    delegation = markdown.table(["Konto", "Delegierung", "Ziele bzw. erlaubt für"], deleg) if deleg else \
        "_Keine Kerberos-Delegierung außer an Domänencontrollern._"
    special = []
    krbtgt = next((u for u in data.users if u.str("sAMAccountName").lower() == "krbtgt"), None)
    if krbtgt is not None:
        special.append(["krbtgt", "Kennwort zuletzt gesetzt am " + (day(krbtgt.time("pwdLastSet")) or "–")])
    for rid_, label in ((500, "Administrator (integriert)"), (501, "Gast")):
        acc = next((u for u in data.users if u.sid() == f"{data.domain_sid}-{rid_}"), None)
        if acc is not None:
            special.append([f"{label}: {acc.str('sAMAccountName')}",
                            ("aktiviert" if enabled(acc) else "deaktiviert")
                            + (f", Kennwort gesetzt am {day(acc.time('pwdLastSet'))}" if acc.time("pwdLastSet") else "")])
    return ("Mitglieder der privilegierten Gruppen (auch über verschachtelte Gruppen und die primäre Gruppe), "
            "Dienstkonten, Kerberos-Delegierung und besondere Konten."), [
        Block("ad-priv-groups", "Privilegierte Gruppen", groups),
        Block("ad-priv-members", "Mitglieder je Gruppe", "\n\n".join(details) or "_Keine._"),
        Block("ad-priv-services", "Dienstkonten", services),
        Block("ad-priv-delegation", "Kerberos-Delegierung", delegation),
        Block("ad-priv-special", "Besondere Konten", markdown.table(["Konto", "Stand"], special) if special else "–"),
    ]


# --- Prüfung ---------------------------------------------------------------------------------------------

def _dangerous(sd, names: AdNames, rights: int = GENERIC_ALL | WRITE_DAC | WRITE_OWNER) -> list:
    """Einträge, die nicht-administrativen Prinzipalen die Kontrolle über das Objekt geben."""
    out = []
    for ace in (sd.dacl if sd else []):
        if not ace.allow or ace.inherited_object_type or is_admin(ace.sid) or ace.sid in ("S-1-3-0", "S-1-5-10"):
            continue
        full_write = ace.mask & WRITE_PROP and ace.object_type is None
        if ace.mask & rights or full_write:
            if is_default(ace.sid) and not is_broad(ace.sid):
                continue
            out.append(ace)
    return out


def audit(ctx: Context, data: AdData, names: AdNames) -> dict[str, list[list]]:
    cfg = ctx.cfg.ad
    f: dict[str, list[list]] = {k: [] for k in ("gpo", "password", "privileged", "kerberos", "accounts", "acl",
                                                "domain")}
    # Gruppenrichtlinien
    all_links = gpo_docs.links(data)
    for g in sorted(data.gpos, key=lambda x: (x.str("displayName") or "").lower()):
        guid, name = g.str("cn").upper(), g.str("displayName") or g.str("cn")
        gl = all_links.get(guid, [])
        flags = g.int("flags", 0) or 0
        files = data.files.get(guid.lower())
        c, u = gpo_docs.versions(g.int("versionNumber"))
        if not gl:
            f["gpo"].append([name, "nicht verknüpft – wirkt nirgends"])
        elif not any(lk.enabled for lk in gl):
            f["gpo"].append([name, "alle Verknüpfungen deaktiviert"])
        if flags == 3 and gl:
            f["gpo"].append([name, "verknüpft, aber alle Einstellungen deaktiviert"])
        if files is not None:
            if not files.found:
                f["gpo"].append([name, "GPO-Ordner fehlt in SYSVOL"])
            elif files.errors:
                f["gpo"].append([name, "Dateien in SYSVOL nicht lesbar: " + "; ".join(files.errors[:3])])
            elif files.version is not None and gpo_docs.versions(files.version) != (c, u):
                f["gpo"].append([name, "Version in AD und SYSVOL unterschiedlich – Replikation prüfen"])
            for where in files.cpassword:
                f["gpo"].append([name, f"gespeichertes Kennwort in den Einstellungen ({where}) – mit öffentlich bekanntem "
                                       f"Schlüssel lesbar (MS14-025), entfernen und Kennwort ändern"])
        if not g.str("gPCMachineExtensionNames") and not g.str("gPCUserExtensionNames") and c == u == 0:
            f["gpo"].append([name, "leer (keine Einstellungen)"])
        path = g.str("gPCFileSysPath").lower()
        if path and not re.match(rf"^\\\\{re.escape(data.dns.lower())}\\sysvol\\{re.escape(data.dns.lower())}"
                                 rf"\\policies\\{re.escape(guid.lower())}$", path):
            f["gpo"].append([name, f"Dateipfad zeigt nicht auf SYSVOL der Domäne: {g.str('gPCFileSysPath')}"])
        if gpo_docs.wmi_filter(data, g)[2]:
            f["gpo"].append([name, "WMI-Filter fehlt"])
        acl = gpo_docs.gpo_acl(g)
        if acl.readable:
            if gl and not gpo_docs.computers_can_read(acl, data.domain_sid):
                f["gpo"].append([name, "Computer haben kein Leserecht (MS16-072) – Benutzereinstellungen greifen nicht"])
            broad = [s for s in acl.edit if is_broad(s)]
            if broad:
                f["gpo"].append([name, "bearbeitbar durch " + ", ".join(names.sid(s) for s in broad)])
    for guid, gl in all_links.items():
        if not any(g.str("cn").upper() == guid for g in data.gpos):
            for lk in gl:
                f["gpo"].append([lk.target, f"Verknüpfung auf nicht vorhandene GPO {guid}"])

    # Kennwortrichtlinien
    d = data.domain
    props = d.int("pwdProperties", 0) or 0
    if (d.int("minPwdLength", 0) or 0) < cfg.min_password_length:
        f["password"].append(["Domänenrichtlinie", f"Mindestlänge {d.int('minPwdLength', 0)} Zeichen (empfohlen "
                                                   f"mindestens {cfg.min_password_length})"])
    if not props & 1:
        f["password"].append(["Domänenrichtlinie", "Komplexität nicht erforderlich"])
    if props & 16:
        f["password"].append(["Domänenrichtlinie", "Kennwörter mit umkehrbarer Verschlüsselung"])
    if not d.int("lockoutThreshold", 0):
        f["password"].append(["Domänenrichtlinie", "keine Kontensperrung – Kennwörter unbegrenzt durchprobierbar"])
    if (d.int("pwdHistoryLength", 0) or 0) < 10:
        f["password"].append(["Domänenrichtlinie", f"Kennwortchronik nur {d.int('pwdHistoryLength', 0)} Kennwörter"])
    for p in data.psos:
        if (p.int("msDS-MinimumPasswordLength", 0) or 0) < cfg.min_password_length:
            f["password"].append([p.name, f"Mindestlänge {p.int('msDS-MinimumPasswordLength', 0)} Zeichen"])
        if p.bool("msDS-PasswordReversibleEncryptionEnabled"):
            f["password"].append([p.name, "Kennwörter mit umkehrbarer Verschlüsselung"])
        if not p.strs("msDS-PSOAppliesTo"):
            f["password"].append([p.name, "gilt für niemanden"])

    # Privilegierte Konten
    days = cfg.stale_days
    seen: dict[str, Entry] = {}
    for pg in data.privileged:
        if pg.group is None or pg.key == 520:
            continue
        for m in pg.members + pg.primary:
            if "group" not in m.classes():
                seen.setdefault(m.dn.lower(), m)
    privileged = [m for m in seen.values() if names.is_person(m) and enabled(m)]
    limit = now().timestamp() - 365 * 86400

    def rows(title: str, entries: list[Entry]):
        if entries:
            f["privileged"].append([title, names.accounts(entries)])

    rows("Kennwort läuft nie ab", [m for m in privileged if uac(m) & DONT_EXPIRE])
    rows("Dienstkonto (SPN) mit Adminrechten – Kerberoasting", [m for m in privileged if m.has("servicePrincipalName")])
    rows("nicht in Protected Users und nicht als „nicht delegierbar“ markiert",
         [m for m in privileged if m.dn.lower() not in data.protected_users and not uac(m) & NOT_DELEGATED])
    rows(f"aktiviert, aber seit über {days} Tagen nicht angemeldet", [m for m in privileged if stale(m, days)])
    rows("Kennwort älter als ein Jahr", [m for m in privileged if m.time("pwdLastSet")
                                         and m.time("pwdLastSet").timestamp() < limit])
    orphaned = [u for u in data.users if (u.int("adminCount", 0) or 0) == 1 and u.dn.lower() not in seen
                and u.str("sAMAccountName").lower() != "krbtgt" and enabled(u)]
    rows("adminCount=1 ohne privilegierte Gruppe (Rechte von AdminSDHolder bleiben)", orphaned)
    if not data.privileged and "privileged" in data.loaded:
        f["privileged"].append(["Privilegierte Gruppen", "nicht lesbar"])
    krbtgt = next((u for u in data.users if u.str("sAMAccountName").lower() == "krbtgt"), None)
    if krbtgt is not None and krbtgt.time("pwdLastSet") and \
            krbtgt.time("pwdLastSet").timestamp() < now().timestamp() - cfg.krbtgt_max_age_days * 86400:
        f["privileged"].append(["krbtgt", f"Kennwort älter als {cfg.krbtgt_max_age_days} Tage (gesetzt "
                                          f"{day(krbtgt.time('pwdLastSet'))}) – zweimal zurücksetzen"])
    guest = next((u for u in data.users if u.sid() == f"{data.domain_sid}-501"), None)
    if guest is not None and enabled(guest):
        f["privileged"].append(["Gast", "Gastkonto aktiviert"])

    # Kerberos
    active_users = [u for u in data.users if enabled(u) and u.str("sAMAccountName").lower() != "krbtgt"]
    dcs = {e.dn.lower() for e in data.dcs}
    kerb = [("Benutzerkonten mit SPN (Kerberoasting möglich – lange Kennwörter oder gMSA verwenden)",
             [u for u in active_users if u.has("servicePrincipalName")]),
            ("ohne Kerberos-Vorauthentifizierung (AS-REP-Roasting)",
             [u for u in active_users if uac(u) & DONT_REQ_PREAUTH]),
            ("uneingeschränkte Delegierung außerhalb der Domänencontroller",
             [e for e in data.users + data.computers if enabled(e) and uac(e) & TRUSTED_FOR_DELEGATION
              and e.dn.lower() not in dcs and not uac(e) & SERVER_TRUST]),
            ("eingeschränkte Delegierung mit Protokollübergang",
             [e for e in data.users + data.computers + data.msas if enabled(e) and uac(e) & TRUSTED_TO_AUTH]),
            ("nur DES-Verschlüsselung", [e for e in active_users if uac(e) & DES_ONLY])]
    for title, entries in kerb:
        if entries:
            f["kerberos"].append([title, names.accounts(entries)])

    # Konten
    stale_comp = [c for c in data.computers if enabled(c) and stale(c, days) and c.dn.lower() not in dcs]
    stale_users = [u for u in active_users if stale(u, days)]
    if stale_comp:
        f["accounts"].append([f"Computer ohne Lebenszeichen seit über {days} Tagen",
                              f"{len(stale_comp)}: {names.accounts(stale_comp, 15)}"])
    if stale_users:
        f["accounts"].append([f"aktivierte Benutzer ohne Anmeldung seit über {days} Tagen",
                              f"{len(stale_users)}" + ("" if names.mode == "count" else
                                                       f": {names.accounts(stale_users, 15)}")])
    for title, flag in (("Kennwort nicht erforderlich (PASSWD_NOTREQD)", PASSWD_NOTREQD),
                        ("Kennwort mit umkehrbarer Verschlüsselung", REVERSIBLE)):
        hit = [u for u in active_users if uac(u) & flag]
        if hit:
            f["accounts"].append([title, names.accounts(hit)])
    default_computers = [c for c in data.computers if enabled(c) and parent_dn(c.dn).lower().startswith("cn=")
                         and c.dn.lower() not in dcs]
    if default_computers:
        f["accounts"].append(["Computer im Standardcontainer (keine OU-GPOs)",
                              f"{len(default_computers)}: {names.accounts(default_computers, 10)}"])
    if any(data.laps.values()):
        without = [c for c in data.computers if enabled(c) and c.dn.lower() not in dcs and not laps_covered(data, c)]
        if without:
            f["accounts"].append(["Computer ohne LAPS-Kennwort", f"{len(without)}: {names.accounts(without, 10)}"])

    # Berechtigungen
    sd = parse_sd(d.raw("nTSecurityDescriptor"))
    dcsync = [a.sid for a in (sd.dacl if sd else []) if a.allow and not a.inherit_only and (
        a.mask & GENERIC_ALL or a.mask & CONTROL_ACCESS and a.object_type in (None, GET_CHANGES_ALL))
        and not is_admin(a.sid) and a.sid not in ("S-1-5-9",)]
    names.resolve(dcsync)
    for sid in dict.fromkeys(dcsync):
        f["acl"].append(["Domäne", f"{names.sid(sid)} darf alle Kennwort-Hashes replizieren (DCSync) – nur für "
                                   f"Domänencontroller und z.B. Entra Connect beabsichtigt?"])
    for label, obj in (("Domäne", d), ("AdminSDHolder", data.adminsdholder)):
        if obj is None:
            continue
        for ace in _dangerous(parse_sd(obj.raw("nTSecurityDescriptor")), names):
            f["acl"].append([label, f"{names.sid(ace.sid)}: {rights_text(ace, data.guid_names)}"])
    for ou in data.ous:
        for ace in delegation_aces(parse_sd(ou.raw("nTSecurityDescriptor"))):
            if ace.allow and is_broad(ace.sid) and is_write(ace):
                f["acl"].append([ou_path(ou.dn, data.base), f"{names.sid(ace.sid)}: {rights_text(ace, data.guid_names)}"])
    if sd is None:
        f["acl"].append(["Domäne", "Berechtigungen nicht lesbar – Prüfung unvollständig"])

    # Domäne
    bin_on = recycle_bin(data)
    if bin_on is False:
        f["domain"].append(["AD-Papierkorb", "nicht aktiviert – gelöschte Objekte nur mit Wiederherstellung zurück"])
    maq = d.int("ms-DS-MachineAccountQuota", 10)
    if maq:
        f["domain"].append(["MachineAccountQuota", f"jeder Benutzer darf {maq} Computer in die Domäne aufnehmen"])
    level = d.int("msDS-Behavior-Version")
    if level is not None and level < 7:
        f["domain"].append(["Domänenfunktionsebene", f"{_level(level)} – unter Windows Server 2016"])
    for dc in data.dcs:
        m = re.search(r"\((\d+)\)", dc.str("operatingSystemVersion"))
        if m and int(m.group(1)) < OLD_OS_BUILD:
            f["domain"].append([dc.name, f"{dc.str('operatingSystem')} – ohne Herstellersupport"])
    for t in data.trusts:
        attrs = t.int("trustAttributes", 0) or 0
        external = not attrs & (WITHIN_FOREST | FOREST_TRANSITIVE)
        if external and not attrs & QUARANTINED and t.int("trustDirection", 0) & 1:
            f["domain"].append([t.str("trustPartner"), "externe Vertrauensstellung ohne SID-Filterung"])
        if attrs & ENABLE_TGT_DELEGATION:
            f["domain"].append([t.str("trustPartner"), "Delegierung von Kerberos-Tickets über die Vertrauensstellung "
                                                       "erlaubt"])
    if not any(data.laps.values()) and "accounts" in data.loaded:
        f["domain"].append(["LAPS", "nicht im Schema – lokale Administratorkennwörter werden nicht verwaltet"])
    return f


AUDIT_SECTIONS = [
    ("Gruppenrichtlinien", "gpo", ["GPO", "Befund"],
     "Unwirksame, beschädigte oder gefährliche GPOs; gespeicherte Kennwörter sind sofort zu entfernen."),
    ("Kennwortrichtlinien", "password", ["Richtlinie", "Befund"], ""),
    ("Privilegierte Konten", "privileged", ["Prüfung", "Konten"],
     "Administrative Konten brauchen starke, regelmäßig geänderte Kennwörter und Schutz vor Delegierung."),
    ("Kerberos", "kerberos", ["Prüfung", "Konten"], ""),
    ("Konten", "accounts", ["Prüfung", "Konten"], ""),
    ("Berechtigungen", "acl", ["Objekt", "Befund"],
     "Wer die Domäne oder AdminSDHolder ändern darf, kann sich selbst zum Domänen-Admin machen."),
    ("Domäne", "domain", ["Thema", "Befund"], ""),
]


def audit_page(ctx: Context, data: AdData, names: AdNames) -> tuple[str, list[Block]]:
    f = audit(ctx, data, names)
    overview = markdown.table(["Prüfung", "Befunde"], [[t, len(f[k])] for t, k, _, _ in AUDIT_SECTIONS])
    body = []
    for title, key, headers, note in AUDIT_SECTIONS:
        rows = f[key]
        body.append(f"### {title}\n\n" + (f"{note}\n\n" if note and rows else "")
                    + (markdown.table(headers, rows) if rows else "_Keine Befunde._"))
    context = f"Domäne: {data.dns}\nGruppenrichtlinien: {len(data.gpos)}\nPrivilegierte Gruppen gelesen: " \
              f"{sum(1 for p in data.privileged if p.group is not None)}"
    if not data.psos:
        context += "\nFeingranulare Kennwortrichtlinien: keine gefunden oder nicht lesbar"
    if not ctx.cfg.ad.sysvol:
        context += "\nNicht geprüft: Inhalte der Gruppenrichtlinien (SYSVOL wird nicht gelesen)"
    blocks = []
    text = narrative.assessment(ctx, "ad-audit", expert="Active Directory und Windows-Sicherheit",
                                subject="Active Directory", context=context,
                                sections=[(title, headers, f[key]) for title, key, headers, _ in AUDIT_SECTIONS]) \
        if narrative.enabled(ctx, "audit") else None
    if text is not None:
        blocks.append(Block("ad-audit-assessment", "Bewertung", text))
    return ("Automatische Prüfung des Active Directory: Gruppenrichtlinien, Kennwortrichtlinien, privilegierte "
            "Konten, Kerberos-Angriffsflächen, verwaiste Konten, gefährliche Berechtigungen und Domäneneinstellungen."), \
        blocks + [Block("ad-audit-overview", "Übersicht", overview),
                  Block("ad-audit-findings", "Befunde", "\n\n".join(body))]


# --- Seiten und Einstieg ------------------------------------------------------------------------------

BUILDERS = {"gruppenrichtlinien": gpo_docs.overview, "ou-struktur": ou_page, "kennwortrichtlinien": password_page,
            "privilegierte-konten": privileged_page, "domaene": domain_page, "pruefung": audit_page}
SUMMARY_TASKS = {
    "gruppenrichtlinien": "Fasse zusammen, welche Gruppenrichtlinien es gibt, wo sie verknüpft sind, welche "
                          "deaktiviert oder nicht verknüpft sind und welche Arten von Einstellungen sie verteilen.",
    "ou-struktur": "Fasse zusammen, wie die Organisationseinheiten aufgebaut sind, wo welche Gruppenrichtlinien "
                   "greifen, wo die Vererbung blockiert ist und wem welche Verwaltungsaufgaben delegiert sind.",
    "kennwortrichtlinien": "Fasse die Kennwort- und Sperrrichtlinien zusammen: was für alle gilt, welche Gruppen "
                           "abweichende Regeln haben und was das für die Sicherheit bedeutet.",
    "privilegierte-konten": "Fasse zusammen, wer administrative Rechte hat (direkt oder verschachtelt), welche "
                            "Dienstkonten und Delegierungen es gibt und was davon sicherheitlich relevant ist.",
    "domaene": "Fasse die Domäne zusammen: Funktionsebenen, Domänencontroller und ihre Rollen, Standorte, "
               "Vertrauensstellungen und welche Betriebssysteme die Computer haben.",
}


def section_stable_id(slug: str) -> str:
    return f"ad:{slug}"


def _propose_section(ctx: Context, slug: str, heading: str, data: AdData, names: AdNames) -> int | None:
    intro, blocks = BUILDERS[slug](ctx, data, names)
    if slug in SUMMARY_TASKS and narrative.enabled(ctx, "overview"):
        facts = narrative.facts_from_markdown("\n\n".join(f"{b.heading}\n\n{b.content}" for b in blocks))
        fallback = f"Die Tabellen unten zeigen den aktuellen Stand: {heading} der Domäne {data.dns}."
        text = narrative.narrate(ctx, f"ad-{slug}", expert="Active Directory", task=SUMMARY_TASKS[slug],
                                 facts=facts, fallback=fallback)
        if text is not None:
            blocks.insert(0, Block(f"ad-{slug}-summary", "Zusammenfassung", text))
    return propose_page(ctx, PageDraft(
        doc_type="ad", title=f"Active Directory: {heading}", description=f"Active Directory – {heading}",
        blocks=blocks, path_vars={"section": slug},
        intro=f"{intro} Die markierten Abschnitte werden automatisch aus dem Active Directory (nur lesend) "
              f"aktualisiert.",
        source="ad", stable_id=section_stable_id(slug),
    ))


def _wanted_groups(areas: list[str]) -> set[str]:
    return set().union(*(NEEDS[a] for a in areas)) if areas else {"base"}


def document_ad(ctx: Context, areas: list[str] | None = None) -> list[int | None]:
    """Seiten der gewünschten Bereiche (Standard: ad.include). Ist ein Bereich nicht lesbar, werden die übrigen
    dokumentiert; der Job meldet dann einen Fehler."""
    wanted = [a for a in ctx.cfg.ad.include if not areas or a in areas]
    data, errors = fetch(ctx, _wanted_groups(wanted))
    for group, message in errors.items():
        ctx.log.error("Active Directory (%s) nicht lesbar: %s", group, message)
    if ctx.cfg.ad.sysvol and "files" in data.loaded and data.admx_note:
        ctx.log.info("Administrative Vorlagen: %s", data.admx_note)
    names = AdNames(ctx, data)
    results: list[int | None] = []
    failed = []
    for area in wanted:
        if not NEEDS[area] <= data.loaded:
            failed.append(area)
            continue
        if area == "gpo":
            all_links = gpo_docs.links(data)
            for g in data.gpos:
                results.append(gpo_docs.gpo_page(ctx, data, g, names, all_links))
        for slug, heading in SECTIONS[area]:
            results.append(_propose_section(ctx, slug, heading, data, names))
    if failed:
        raise RuntimeError("Active Directory unvollständig – nicht dokumentiert: " + ", ".join(
            AREA_LABELS[a] for a in failed) + ". Die übrigen Bereiche wurden dokumentiert; Ursache siehe Meldungen oben.")
    return results


def document_section(ctx: Context, slug: str) -> int | None:
    """Eine Bereichsseite neu berechnen (Wiki-Lint)."""
    area = SLUG_AREA[slug]
    data, errors = fetch(ctx, NEEDS[area])
    if errors:
        raise RuntimeError("; ".join(errors.values()))
    return _propose_section(ctx, slug, dict(SECTIONS[area])[slug], data, AdNames(ctx, data))


class GpoGone(LookupError):
    pass


def document_gpo(ctx: Context, guid: str) -> int | None:
    """Eine GPO neu berechnen (Wiki-Lint); GpoGone, wenn es sie nicht mehr gibt."""
    data, errors = fetch(ctx, {"base", "structure", "acl"})
    if errors:
        raise RuntimeError("; ".join(errors.values()))
    gpo = ctx.ad.gpo(guid)
    if gpo is None:
        raise GpoGone(f"GPO {guid} gibt es nicht mehr")
    data.gpos = ctx.ad.gpos()
    data.wmi = ctx.ad.wmi_filters()
    if ctx.cfg.ad.sysvol:
        data.files[guid.lower()] = gpo_docs.load_files(ctx, data, gpo.str("cn"))
        data.admx, data.admx_note = gpo_docs.admx_catalog(ctx, data)
    else:
        data.admx_note = "SYSVOL wird nicht gelesen (ad.sysvol: false)"
    return gpo_docs.gpo_page(ctx, data, gpo, AdNames(ctx, data), gpo_docs.links(data))

