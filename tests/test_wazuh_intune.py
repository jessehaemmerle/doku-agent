import xml.etree.ElementTree as ET

import httpx

from doku_agent.connectors.wazuh import WazuhClient
from doku_agent.egress import EgressGuard
from doku_agent.generators import wazuh_docs
from doku_agent.generators.common import mask_value, mask_xml, parse_xml_fragment
from doku_agent.generators.intune_docs import flatten, settings_catalog_rows
from tests.conftest import FakeLLM, make_config

RULES = """<!-- Lokale Regeln -->
<group name="local,syslog,sshd,">
  <rule id="100001" level="5">
    <if_sid>5716</if_sid>
    <srcip>1.1.1.1</srcip>
    <description>sshd: Login von gesperrter IP</description>
    <mitre><id>T1110</id></mitre>
    <group>authentication_failed,</group>
  </rule>
</group>
<group name="web,">
  <rule id="100010" level="10" frequency="8" timeframe="120">
    <if_matched_sid>31101</if_matched_sid>
    <regex>^GET /admin&amp;|&debug</regex>
    <description>Viele Admin-Zugriffe</description>
  </rule>
</group>
"""


def test_parse_rules_handles_multiple_roots_and_ampersands():
    rules, groups = wazuh_docs.parse_rules(RULES)
    assert [r["id"] for r in rules] == ["100001", "100010"]
    assert groups == ["local,syslog,sshd,", "web,"]
    first = rules[0]
    assert first["level"] == "5" and first["mitre"] == ["T1110"]
    assert "if_sid: 5716" in first["conditions"] and "srcip: 1.1.1.1" in first["conditions"]
    assert "authentication_failed" in first["groups"]
    assert rules[1]["frequency"] == "8"


def test_parse_decoders():
    decs = wazuh_docs.parse_decoders('<decoder name="app"><program_name>^app$</program_name></decoder>'
                                     '<decoder name="app-login"><parent>app</parent><regex>user (\\w+)</regex>'
                                     '<order>user</order></decoder>')
    assert decs[1]["parent"] == "app" and decs[1]["order"] == "user"


def test_masking_keeps_settings_but_hides_secrets():
    root = parse_xml_fragment("<ossec_config><integration><name>slack</name><hook_url>https://hooks/x</hook_url>"
                              "<api_key>abc</api_key></integration><auth><use_password>yes</use_password></auth>"
                              "</ossec_config>")
    mask_xml(root)
    text = ET.tostring(root, encoding="unicode")
    assert "https://hooks/x" not in text and "abc" not in text and "<use_password>yes" in text
    assert mask_value("passwordMinimumLength", 8) == 8
    assert mask_value("passwordRequiredType", "deviceDefault") == "deviceDefault"
    assert mask_value("wifi.preSharedKey", "geheim") == "***"


def test_settings_catalog_rows_use_display_names():
    settings = [{
        "settingInstance": {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
            "settingDefinitionId": "device_vendor_msft_bitlocker_requiredeviceencryption",
            "choiceSettingValue": {"value": "device_vendor_msft_bitlocker_requiredeviceencryption_1", "children": [
                {"settingDefinitionId": "child_def", "simpleSettingValue": {"value": 7}}]},
        },
        "settingDefinitions": [
            {"id": "device_vendor_msft_bitlocker_requiredeviceencryption", "displayName": "Require Device Encryption",
             "options": [{"itemId": "device_vendor_msft_bitlocker_requiredeviceencryption_1", "displayName": "Enabled"}]},
            {"id": "child_def", "displayName": "Wartezeit"},
        ],
    }]
    assert settings_catalog_rows(settings) == [("Require Device Encryption", "Enabled"), ("↳ Wartezeit", "7")]


def test_flatten_skips_metadata():
    rows = dict(flatten({"@odata.type": "#microsoft.graph.windows10CompliancePolicy", "id": "1",
                         "displayName": "x", "passwordRequired": True, "osMinimumVersion": None,
                         "validOperatingSystemBuildRanges": [], "nested": {"a": 1}}))
    assert rows == {"@odata.type": "#microsoft.graph.windows10CompliancePolicy", "passwordRequired": "True",
                    "nested.a": "1"}


def test_document_rule_file_creates_page_with_explanations(ctx, fake_wiki, tmp_path):
    def handler(request):
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, json={"data": {"token": "jwt"}})
        assert request.headers["authorization"] == "Bearer jwt"
        assert request.url.params["raw"] == "true"
        return httpx.Response(200, text=RULES)

    cfg = ctx.cfg
    ctx.__dict__["wazuh"] = WazuhClient(cfg.wazuh, EgressGuard.from_config(cfg), transport=httpx.MockTransport(handler))
    ctx.__dict__["llm"] = FakeLLM(json_answers=[{"zusammenfassung": "Schutz vor SSH-Angriffen.", "regeln": [
        {"id": "100001", "erklaerung": "Löst bei Logins von 1.1.1.1 aus."}]}])
    pid = wazuh_docs.document_rule_file(ctx, {"filename": "local_rules.xml", "relative_dirname": "etc/rules"})
    prop = ctx.store.get_proposal(pid)
    content = prop.payload["content"]
    assert prop.payload["path"] == "security/wazuh/regeln/local-rules"
    assert "Schutz vor SSH-Angriffen." in content and "Löst bei Logins von 1.1.1.1 aus." in content
    assert "| 100010 | 10 |" in content
    # zweiter Lauf mit gleichen Regeln nutzt den Cache statt das LLM erneut zu fragen
    ctx.__dict__["llm"] = FakeLLM()
    wazuh_docs.document_rule_file(ctx, {"filename": "local_rules.xml"})
    assert ctx.llm.calls == []
