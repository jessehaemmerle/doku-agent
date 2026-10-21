"""Integrationstest: echtes LDAP (TLS) und SYSVOL (SMB) gegen einen Samba-AD-DC mit den Testdaten aus tests/samba_ad.

Läuft nur mit DOKU_IT_AD_SERVER (DNS-Name wie im Zertifikat), DOKU_IT_AD_PORT (LDAPS, Standard 636),
DOKU_IT_AD_SMB_PORT (Standard 445) und DOKU_IT_AD_CA (CA-Zertifikat des DCs). Angemeldet wird als normaler
Domänenbenutzer doku-reader, wie im Betrieb empfohlen.
"""

import os
import re

import pytest

from doku_agent.egress import EgressGuard

SERVER = os.environ.get("DOKU_IT_AD_SERVER")
PORT, SMB_PORT = int(os.environ.get("DOKU_IT_AD_PORT", "636")), int(os.environ.get("DOKU_IT_AD_SMB_PORT", "445"))
CA = os.environ.get("DOKU_IT_AD_CA", "")
pytestmark = pytest.mark.skipif(not SERVER, reason="kein Test-AD konfiguriert")


@pytest.fixture
def adctx(ctx):
    ad = ctx.cfg.ad
    ad.enabled, ad.domain, ad.servers = True, "corp.example.test", [SERVER]
    ad.ldap_port, ad.smb_port, ad.verify_tls = PORT, SMB_PORT, CA or True
    ad.username, ad.password = "doku-reader@corp.example.test", "Reader!Passw0rd1"
    ctx.guard = EgressGuard(set(ctx.guard.hosts) | {SERVER.lower()})
    yield ctx
    for name in ("ad", "sysvol"):
        client = ctx.__dict__.get(name)
        if client is not None:
            client.close()


def block(content: str, block_id: str) -> str:
    m = re.search(rf"begin {block_id} -->(.*?)<!-- doku-agent:end", content, re.S)
    return m.group(1) if m else ""


def test_documents_samba_domain_as_reader(adctx):
    from doku_agent.generators.ad_docs import document_ad
    document_ad(adctx)
    pages = {p.title: p.payload["content"] for p in adctx.store.list_proposals()}
    gpo = pages["GPO: Clients - Sicherheit"]
    machine = block(gpo, "ad-gpo-machine")
    assert "Automatische Updates konfigurieren" in machine and "Windows-Komponenten / Windows Update" in machine
    assert "RDP intern" in machine and "HKLM\\Software\\Firma\\Agent" in machine
    assert "LAN-Manager-Authentifizierungsebene" in machine and "Helpdesk" in machine
    assert "inventar.cmd" in machine and "Anmelden" in machine
    assert "TESTWERT-NICHT-ECHT" not in gpo and "gespeichertes Kennwort" in machine
    assert "Zeitlimit für Bildschirmschoner" in block(gpo, "ad-gpo-user") and "\\\\fs01\\home" in gpo
    assert "Nur Windows 11" in block(gpo, "ad-gpo-basics")
    assert "| Firma / Clients | OU | 1 | ja | ja |" in block(gpo, "ad-gpo-links")

    ou = pages["Active Directory: OU-Struktur und Delegationen"]
    delegations = block(ou, "ad-ou-delegations")
    assert "Helpdesk | zulassen | Kennwort zurücksetzen | untergeordnete user-Objekte" in delegations
    assert "Helpdesk | zulassen | Schreiben: member | untergeordnete group-Objekte" in delegations
    assert "blockiert" in block(ou, "ad-ou-tree")

    audit = block(pages["Active Directory: Prüfung"], "ad-audit-findings")
    for expected in ("gespeichertes Kennwort", "Version in AD und SYSVOL unterschiedlich", "Ungenutzt | nicht verknüpft",
                     "svc-old darf alle Kennwort-Hashes replizieren", "AS-REP-Roasting) | svc-old",
                     "Kerberoasting möglich", "srv01$", "pc-old$", "Mindestlänge 7"):
        assert expected in audit, expected
    domain = pages["Active Directory: Domäne und Gesamtstruktur"]
    assert "10.1.0.0/16" in domain and "PDC-Emulator" in domain
    # PSOs darf ein normaler Benutzer nicht lesen: Hinweis statt leerer Tabelle
    assert "Password Settings Container" in pages["Active Directory: Kennwort- und Sperrrichtlinien"]


def test_checks_against_samba(adctx):
    from doku_agent.web.app import run_checks
    adctx.__dict__["llm"].models = lambda: []
    checks = {name: (ok, text) for name, ok, text in run_checks(adctx)}
    assert checks["Active Directory (LDAP)"][0], checks["Active Directory (LDAP)"]
    assert checks["Active Directory (SYSVOL)"][0] and "Central Store vorhanden" in checks["Active Directory (SYSVOL)"][1]
    assert checks["AD-Leserechte"][0] and "Password Settings Container" in checks["AD-Leserechte"][1]


def test_wrong_password_is_explained(adctx):
    from doku_agent.connectors.ad import AdClient, AdError
    adctx.cfg.ad.password = "falsch"
    with pytest.raises(AdError, match="Benutzername oder Kennwort falsch|Anmeldung abgelehnt"):
        AdClient(adctx.cfg.ad, adctx.guard).root()
