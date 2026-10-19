"""Integrationstest gegen einen echten Wazuh-Manager 4.x (läuft nur mit DOKU_IT_WAZUH_URL/_USER/_PASSWORD).

Nur lesend. DOKU_IT_WAZUH_INSECURE=1 schaltet die TLS-Prüfung ab (selbstsigniertes Test-Zertifikat).
"""

import os

import pytest

from doku_agent.connectors.wazuh import WazuhClient
from doku_agent.discovery import wazuh_assets
from doku_agent.egress import EgressGuard
from doku_agent.generators import wazuh_docs
from tests.conftest import FakeLLM, make_config

URL = os.environ.get("DOKU_IT_WAZUH_URL")
pytestmark = pytest.mark.skipif(not URL, reason="kein Test-Wazuh konfiguriert")


@pytest.fixture
def wctx(ctx, tmp_path):
    cfg = make_config(tmp_path, wazuh={"url": URL, "username": os.environ["DOKU_IT_WAZUH_USER"],
                                       "password": os.environ["DOKU_IT_WAZUH_PASSWORD"],
                                       "verify_tls": os.environ.get("DOKU_IT_WAZUH_INSECURE") != "1"})
    ctx.cfg.wazuh = cfg.wazuh
    ctx.__dict__["wazuh"] = WazuhClient(cfg.wazuh, EgressGuard.from_config(cfg))
    return ctx


def test_rules_decoders_and_config_pages(wctx):
    wz = wctx.wazuh
    files = wz.rule_files()
    assert any(f["filename"] == "local_rules.xml" for f in files)
    rules, _ = wazuh_docs.parse_rules(wz.rule_file("local_rules.xml"))
    assert rules and all(r["id"] for r in rules)

    wctx.__dict__["llm"] = FakeLLM(json_answers=[{"zusammenfassung": "Beispielregeln.", "regeln": []}] * 10)
    prop = wctx.store.get_proposal(wazuh_docs.document_rule_file(
        wctx, next(f for f in files if f["filename"] == "local_rules.xml")))
    assert f"| {rules[0]['id']} |" in prop.payload["content"]

    decoders = wazuh_docs.parse_decoders(wz.decoder_file(wz.decoder_files()[0]["filename"]))
    assert decoders and decoders[0]["name"]

    results = wazuh_docs.document_config(wctx)
    manager = wctx.store.get_proposal(results[0])
    assert "Einstellungen" in manager.payload["content"] and "global" in manager.payload["content"]
    # Gruppen mit leerer agent.conf (z.B. "default") erzeugen keine Seite
    assert all(r is None or "gruppe-" in wctx.store.get_proposal(r).payload["path"] for r in results[1:])


def test_agents_and_inventory(wctx):
    agents = wctx.wazuh.agents()
    assert any(a["id"] == "000" for a in agents)
    assets = wazuh_assets(wctx)  # Manager selbst hat Syscollector-Daten, sobald der erste Scan lief
    if not assets:
        pytest.skip("noch kein Syscollector-Scan gelaufen")
    manager = next(a for a in assets if a.sources["wazuh"]["agent_id"] == "000")
    assert manager.name and manager.os_name and manager.memory_mb
    assert manager.interfaces and manager.interfaces[0].mac and manager.interfaces[0].ips


def test_sca_page(wctx):
    if not wctx.wazuh.sca_policies("000"):
        pytest.skip("noch kein SCA-Scan gelaufen")
    wctx.cfg.wazuh.sca_agents = ["000"]
    prop = wctx.store.get_proposal(wazuh_docs.document_sca(wctx)[0])
    assert "Fehlgeschlagene Prüfungen" in prop.payload["content"] and " %" in prop.payload["content"]
