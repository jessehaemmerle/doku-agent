"""Active-Directory-Zertifikatsdienste (AD CS) dokumentieren und auf verbreitete Fehlkonfigurationen prüfen –
nur lesend über LDAP (keine Verbindung zu den CA-Servern).

Dokumentiert werden die Zertifizierungsstellen (Enrollment Services) und die veröffentlichten Vorlagen mit
den sicherheitsrelevanten Eigenschaften (wer sich registrieren darf, ob der Antragsteller den Namen bestimmt,
ob eine Genehmigung nötig ist, welche Verwendungszwecke die Vorlage erlaubt). Die Prüfung meldet die bekannten
Eskalationswege ESC1–ESC5, ESC9, ESC13 und ESC15, soweit sie am Verzeichnis erkennbar sind; CA-seitige
Einstellungen (ESC6–ESC8, ESC11, ESC16) kann der Agent über LDAP nicht sehen und nennt sie als „nicht geprüft“.

Die Prüfung dient der Härtung der eigenen Umgebung: Sie nennt Vorlagen, die ein nicht-privilegiertes Konto
missbrauchen könnte, damit sie korrigiert werden. Konkrete Angriffsschritte stehen bewusst nicht hier.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from doku_agent import markdown
from doku_agent.ad_acl import (CONTROL_ACCESS, GENERIC_ALL, WRITE_DAC, WRITE_OWNER, WRITE_PROP, is_admin, is_broad,
                               parse_sd, rid)
from doku_agent.connectors.ad import Entry
from doku_agent.context import Context
from doku_agent.generators import narrative
from doku_agent.generators.ad_common import AdData, AdNames
from doku_agent.pages import Block, PageDraft, propose_page


def _sids(names: AdNames, sids: list[str]) -> str:
    names.resolve(sids)
    return ", ".join(sorted((names.sid(s) for s in dict.fromkeys(sids)), key=str.lower)) or "–"

# msPKI-Certificate-Name-Flag
ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
ENROLLEE_SUPPLIES_SAN = 0x00010000
# msPKI-Enrollment-Flag
PEND_ALL_REQUESTS = 0x00000002  # Genehmigung durch einen Zertifikatmanager
NO_SECURITY_EXTENSION = 0x00080000  # ESC9 (SID-Sicherheitserweiterung weggelassen)
# Erweiterte Rechte zum Registrieren (rightsGuid)
ENROLL = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
AUTOENROLL = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"
# EKU-OIDs, die eine Anmeldung als anderer Benutzer (Client-Authentifizierung) erlauben
CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
PKINIT = "1.3.6.1.5.2.3.4"
SMARTCARD = "1.3.6.1.4.1.311.20.2.2"
ANY_PURPOSE = "2.5.29.37.0"
CERT_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"
CLIENT_AUTH_EKUS = {CLIENT_AUTH, PKINIT, SMARTCARD, ANY_PURPOSE}
EKU_NAMES = {CLIENT_AUTH: "Clientauthentifizierung", PKINIT: "PKINIT-Clientauthentifizierung",
             SMARTCARD: "Smartcard-Anmeldung", ANY_PURPOSE: "Beliebiger Zweck", CERT_REQUEST_AGENT: "Registrierungs-Agent",
             "1.3.6.1.5.5.7.3.1": "Serverauthentifizierung", "1.3.6.1.5.5.7.3.4": "E-Mail-Schutz",
             "1.3.6.1.4.1.311.10.3.4": "EFS", "1.3.6.1.5.5.7.3.3": "Codesignatur",
             "1.3.6.1.4.1.311.20.2.1": "Registrierungs-Agent"}


def eku_name(oid: str) -> str:
    return EKU_NAMES.get(oid, oid)


def _expiry(raw: bytes | None) -> str:
    """pKIExpirationPeriod: 8 Byte, negative 100-ns-Intervalle. Als grobe Dauer in Tagen/Jahren."""
    if not raw or len(raw) < 8:
        return ""
    value = struct.unpack("<q", raw[:8])[0]
    seconds = abs(value) // 10_000_000
    days = seconds // 86400
    if days >= 365:
        years = days / 365
        return f"{years:.0f} Jahre" if years >= 2 else "1 Jahr"
    return f"{days} Tage"


@dataclass
class Template:
    entry: Entry
    name: str
    schema: int
    enroll_sids: list[str]  # SIDs mit Registrierungsrecht
    write_sids: list[str]  # SIDs mit gefährlichem Schreibrecht (ohne Administratoren)
    ekus: list[str]
    supplies_subject: bool
    supplies_san: bool
    manager_approval: bool
    ra_signatures: int
    no_security_ext: bool
    policy_oids: list[str]
    published_on: list[str] = field(default_factory=list)  # CA-Namen, die die Vorlage anbieten

    @property
    def client_auth(self) -> bool:
        return not self.ekus or bool(set(self.ekus) & CLIENT_AUTH_EKUS)


def _acl_sids(entry: Entry) -> tuple[list[str], list[str]]:
    """(SIDs mit Registrierungsrecht, SIDs mit gefährlichem Schreibrecht ohne Administratoren)."""
    sd = parse_sd(entry.raw("nTSecurityDescriptor"))
    enroll, write = [], []
    for ace in (sd.dacl if sd else []):
        if not ace.allow or ace.inherit_only:
            continue
        full = ace.mask & GENERIC_ALL
        if full or (ace.mask & CONTROL_ACCESS and (ace.object_type is None or ace.object_type.lower() in (ENROLL,
                                                                                                          AUTOENROLL))):
            enroll.append(ace.sid)
        if (full or ace.mask & (WRITE_DAC | WRITE_OWNER) or (ace.mask & WRITE_PROP and ace.object_type is None)) \
                and not is_admin(ace.sid) and ace.sid not in ("S-1-3-0",):
            write.append(ace.sid)
    return list(dict.fromkeys(enroll)), list(dict.fromkeys(write))


def _templates(data: AdData) -> list[Template]:
    published: dict[str, list[str]] = {}
    for ca in data.adcs_cas:
        for cn in ca.strs("certificateTemplates"):
            published.setdefault(cn.lower(), []).append(ca.str("dNSHostName") or ca.str("cn") or ca.name)
    out = []
    for e in data.adcs_templates:
        enroll, write = _acl_sids(e)
        name = e.str("displayName") or e.str("cn") or e.name
        ekus = e.strs("pKIExtendedKeyUsage") + e.strs("msPKI-Certificate-Application-Policy")
        flags = e.int("msPKI-Certificate-Name-Flag", 0) or 0
        enr = e.int("msPKI-Enrollment-Flag", 0) or 0
        out.append(Template(
            entry=e, name=name, schema=e.int("msPKI-Template-Schema-Version", 1) or 1,
            enroll_sids=enroll, write_sids=write, ekus=list(dict.fromkeys(ekus)),
            supplies_subject=bool(flags & ENROLLEE_SUPPLIES_SUBJECT), supplies_san=bool(flags & ENROLLEE_SUPPLIES_SAN),
            manager_approval=bool(enr & PEND_ALL_REQUESTS), ra_signatures=e.int("msPKI-RA-Signature", 0) or 0,
            no_security_ext=bool(enr & NO_SECURITY_EXTENSION), policy_oids=e.strs("msPKI-Certificate-Policy"),
            published_on=published.get((e.str("cn") or "").lower(), [])))
    return out


# --- Seite --------------------------------------------------------------------------------------

def _low_priv(sids: list[str], names: AdNames) -> list[str]:
    """Nicht-privilegierte Prinzipale unter den SIDs (für die der Missbrauch jedem offenstünde)."""
    out = []
    for sid in sids:
        if is_broad(sid) or rid(sid) in (513, 515, 514) or sid in ("S-1-5-11", "S-1-1-0", "S-1-5-32-545"):
            out.append(names.sid(sid))
    return sorted(set(out), key=str.lower)


def cas_table(data: AdData) -> str:
    rows = [[c.str("cn") or c.name, c.str("dNSHostName") or "–",
             str(len(c.strs("certificateTemplates"))), _since(c)] for c in
            sorted(data.adcs_cas, key=lambda c: (c.str("cn") or "").lower())]
    return markdown.table(["Zertifizierungsstelle", "Host", "Veröffentlichte Vorlagen", "Geändert"], rows) \
        if rows else "_Keine Zertifizierungsstellen (Enrollment Services) gefunden._"


def _since(e: Entry) -> str:
    from doku_agent.generators.ad_common import day
    return day(e.time("whenChanged")) or "–"


def templates_table(templates: list[Template], names: AdNames) -> str:
    rows = []
    for t in sorted(templates, key=lambda t: t.name.lower()):
        who = _sids(names, t.enroll_sids) if t.enroll_sids else "–"
        ekus = ", ".join(eku_name(o) for o in t.ekus) or "(keine Einschränkung)"
        opts = []
        if t.supplies_subject:
            opts.append("Antragsteller bestimmt Namen")
        if t.manager_approval:
            opts.append("Genehmigung nötig")
        if t.ra_signatures:
            opts.append(f"{t.ra_signatures} Signatur(en)")
        if t.no_security_ext:
            opts.append("ohne SID-Erweiterung")
        rows.append([t.name, "ja" if t.published_on else "nein", who, ekus, ", ".join(opts) or "–"])
    return markdown.table(["Vorlage", "Veröffentlicht", "Registrieren dürfen", "Verwendungszwecke", "Besonderheiten"],
                          rows) if rows else "_Keine Zertifikatvorlagen gefunden._"


def audit(ctx: Context, data: AdData, names: AdNames) -> list[list]:
    """Erkennbare Fehlkonfigurationen je Vorlage/Objekt (ESC-Kennung, Vorlage, Befund)."""
    findings: list[list] = []
    templates = _templates(data)
    for t in templates:
        low_enroll = _low_priv(t.enroll_sids, names)
        low_write = _low_priv(t.write_sids, names)
        names.resolve(t.enroll_sids + t.write_sids)
        published_low = t.published_on and low_enroll and not t.manager_approval and t.ra_signatures == 0
        # ESC1: Name frei wählbar + zur Anmeldung nutzbar (dazu zählen auch "beliebiger Zweck" und gar keine
        # Einschränkung). ESC2 hängt nicht am frei wählbaren Namen: ein Zertifikat für jeden Zweck taugt auch als
        # Registrierungs-Agent, mit dem sich Zertifikate für andere beantragen lassen.
        if published_low and t.supplies_subject and t.client_auth:
            findings.append(["ESC1", t.name, f"nicht-privilegierte Konten ({', '.join(low_enroll)}) dürfen sich "
                                             "registrieren, den Namen frei wählen und das Zertifikat zur Anmeldung "
                                             "nutzen – Genehmigung aus"])
        if published_low and (not t.ekus or ANY_PURPOSE in t.ekus):
            findings.append(["ESC2", t.name, "Vorlage erlaubt beliebigen Verwendungszweck (oder keine Einschränkung) "
                                             "– das Zertifikat taugt auch als Registrierungs-Agent"])
        if published_low and CERT_REQUEST_AGENT in t.ekus:
            findings.append(["ESC3", t.name, "Vorlage stellt Registrierungs-Agent-Zertifikate aus, für "
                                             "nicht-privilegierte Konten offen"])
        if low_write:
            findings.append(["ESC4", t.name, f"nicht-privilegierte Konten dürfen die Vorlage ändern: "
                                             f"{', '.join(low_write)}"])
        if published_low and t.no_security_ext and t.client_auth:
            findings.append(["ESC9", t.name, "SID-Sicherheitserweiterung ist deaktiviert (CT_FLAG_NO_SECURITY_"
                                             "EXTENSION) – schwache Zuordnung möglich"])
        if published_low and t.policy_oids:
            linked = [o for o in t.policy_oids if o in data.adcs_policy_groups]
            if linked:
                names.resolve([data.adcs_policy_groups[o] for o in linked])
                groups = ", ".join(names.sid(data.adcs_policy_groups[o]) for o in linked)
                findings.append(["ESC13", t.name, f"Ausgabe-Richtlinie ist mit Gruppe verknüpft ({groups}) – Zertifikat "
                                                  "verschafft deren Rechte"])
        if published_low and t.schema == 1 and t.supplies_subject:
            findings.append(["ESC15", t.name, "Schema-Version 1 mit frei wählbarem Namen (CVE-2024-49019) – "
                                              "Verwendungszweck im Antrag injizierbar"])
    # ESC5: gefährliche Schreibrechte auf PKI-Objekten selbst
    for ca in data.adcs_cas:
        _, low_write = _acl_sids(ca)
        bad = _low_priv(low_write, names)
        if bad:
            findings.append(["ESC5", ca.str("cn") or ca.name,
                             f"nicht-privilegierte Konten dürfen das CA-Objekt ändern: {', '.join(bad)}"])
    if data.adcs_ntauth is not None:
        _, low_write = _acl_sids(data.adcs_ntauth)
        bad = _low_priv(low_write, names)
        if bad:
            findings.append(["ESC5", "NTAuthCertificates",
                             f"nicht-privilegierte Konten dürfen den NTAuth-Speicher ändern: {', '.join(bad)}"])
    return findings


NOT_CHECKED = ("ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2), ESC7 (CA-Berechtigungen), ESC8 (Web-Registrierung/NTLM-Relay), "
               "ESC11 (RPC ohne Verschlüsselung) und ESC16 (SID-Erweiterung CA-weit) hängen an der CA-Konfiguration "
               "und sind über LDAP nicht erkennbar – bitte auf den CA-Servern prüfen.")


def document_adcs(ctx: Context, data: AdData, names: AdNames) -> int | None:
    if not data.adcs_cas and not data.adcs_templates:
        ctx.log.info("Keine Zertifikatsdienste im Verzeichnis gefunden – AD CS übersprungen")
        return None
    templates = _templates(data)
    findings = audit(ctx, data, names)
    overview = markdown.table(["Kennzahl", "Wert"], [
        ["Zertifizierungsstellen", len(data.adcs_cas)],
        ["Vorlagen gesamt", len(templates)],
        ["davon veröffentlicht", sum(1 for t in templates if t.published_on)],
        ["Befunde der Prüfung", len(findings)],
    ])
    blocks = []
    context = (f"Zertifizierungsstellen: {len(data.adcs_cas)}\nVorlagen: {len(templates)}\n"
               f"Befunde: {len(findings)}\n{NOT_CHECKED}")
    if narrative.enabled(ctx, "audit"):
        text = narrative.assessment(
            ctx, "adcs-audit", expert="Active-Directory-Zertifikatsdienste und deren Härtung",
            subject="der Zertifikatvorlagen (AD CS)", context=context,
            sections=[("Fehlkonfigurationen", ["Kennung", "Vorlage", "Befund"], findings)])
        if text is not None:
            blocks.append(Block("adcs-assessment", "Bewertung", text))
    blocks += [
        Block("adcs-overview", "Überblick", overview),
        Block("adcs-cas", "Zertifizierungsstellen", cas_table(data)),
        Block("adcs-templates", "Zertifikatvorlagen", templates_table(templates, names)),
        Block("adcs-findings", "Prüfung (über LDAP erkennbar)",
              (markdown.table(["Kennung", "Vorlage/Objekt", "Befund"], findings) if findings
               else "_Keine über LDAP erkennbaren Fehlkonfigurationen._") + f"\n\n_{NOT_CHECKED}_"),
    ]
    return propose_page(ctx, PageDraft(
        doc_type="adcs", title="Active Directory: Zertifikatsdienste (AD CS)",
        description="Zertifizierungsstellen, Vorlagen und Prüfung der AD-Zertifikatsdienste", blocks=blocks,
        intro="Zertifizierungsstellen und Vorlagen der AD-Zertifikatsdienste samt Prüfung auf verbreitete "
              "Fehlkonfigurationen (nur über LDAP, nur lesend). Die markierten Abschnitte werden automatisch "
              "aktualisiert.",
        target_path=ctx.cfg.wiki.paths.get("adcs") or "identitaet/active-directory/zertifikatsdienste",
        source="adcs", stable_id="adcs:report"))
