"""Regressionstests zur zweiten Code-Review-Runde (gesamte Codebasis)."""

import xml.etree.ElementTree as ET

from doku_agent import gpo_files
from doku_agent.generators.common import _is_secret, mask_xml, parse_xml_fragment, scrub_command, scrub_text
from doku_agent.generators.freeform import run_freeform
from doku_agent.generators.intune_docs import flatten
from tests.conftest import FakeLLM


# --- Geheimnisse ------------------------------------------------------------------------------------------------

def test_secret_names_cover_words_digits_and_multiword_labels():
    for name, value in [("key", "c98b62a9"), ("secret_key", "w"), ("access_key", "AKIA"), ("secret_value", "x~y"),
                        ("application_key", "x"), ("Pre-shared key", "hunter2x"), ("API Key", "x"), ("APIKey", "x"),
                        ("preSharedKey", "12345678"), ("password", "12345678"), ("↳ Wi-Fi Pre-shared key", "x")]:
        assert _is_secret(name, value), name
    for name, value in [("passwordMinimumLength", "8"), ("registryKey", "HKLM\\x"), ("publicKey", "ssh-rsa"),
                        ("tokenLifetime", "3600"), ("secretName", "kv1"), ("passwordRequired", "true")]:
        assert not _is_secret(name, value), name


def test_wazuh_cluster_and_cloud_keys_are_masked():
    root = parse_xml_fragment(
        "<ossec_config><cluster><name>wazuh</name><key>c98b62a9b6169ac5f67dae55ae4a9088</key></cluster>"
        "<wodle name='aws-s3'><bucket><access_key>AKIAEXAMPLE</access_key><secret_key>wJalrXUt</secret_key>"
        "</bucket></wodle><ms-graph><api_auth><secret_value>abc~def</secret_value></api_auth></ms-graph>"
        "</ossec_config>")
    mask_xml(root)
    text = ET.tostring(root, encoding="unicode")
    for secret in ("c98b62a9", "AKIAEXAMPLE", "wJalrXUt", "abc~def"):
        assert secret not in text
    assert "<name>wazuh</name>" in text


def test_flatten_masks_secrets_inside_lists_but_keeps_labels():
    rows = dict(flatten({"customData": [{"key": "password", "value": "S3cret"}, {"key": "server", "value": "vpn"}],
                         "omaSettings": [{"displayName": "WLAN", "omaUri": "./Vendor/MSFT/WiFi/Profile/X/WlanXml",
                                          "value": "<WLANProfile><keyMaterial>psk123</keyMaterial></WLANProfile>"}]}))
    assert "S3cret" not in rows["customData"] and '"password"' in rows["customData"] and "vpn" in rows["customData"]
    assert "psk123" not in rows["omaSettings"] and "keyMaterial" in rows["omaSettings"]


def test_scrub_text_masks_config_secrets_but_keeps_prose():
    text, found = scrub_text("server: srv01\n  password: Winter2026!\nset psksecret ENC abc\n"
                             "Backup nach https://backup:Pa55@nas01/x\n line vty 0 4\n password cisco123")
    assert found and not any(s in text for s in ("Winter2026!", "ENC abc", "Pa55", "cisco123"))
    assert "server: srv01" in text and "https://backup:***@nas01/x" in text
    prose = "Password policy is strict. Der Server: srv01 läuft seit 10:30 Uhr.\nHinweis: Kennwort liegt im Tresor."
    assert scrub_text(prose) == (prose, False)


def test_freeform_hides_secrets_from_llm_and_raw_notes(ctx, tmp_path):
    upload = tmp_path / "router.txt"
    upload.write_text("hostname rt01\nenable secret 5 $1$abc$XYZ\nsnmp-server community S3cretRO RO\n")
    ctx.__dict__["llm"] = llm = FakeLLM(json_answers=[
        {"titel": "Router", "beschreibung": "", "aktion": "neu", "bereich": "netz", "tags": []},
        {"inhalt": "kurz"}])  # schwache Antwort: Rohfassung wird übernommen
    pid = run_freeform(ctx, "Neuer Router, Admin-Passwort: Winter2026!", [upload])
    content = ctx.store.get_proposal(pid).payload["content"]
    prompts = " ".join(user for _, user in llm.calls)
    for secret in ("Winter2026!", "$1$abc$XYZ", "S3cretRO"):
        assert secret not in content and secret not in prompts
    assert "hostname rt01" in content


def test_gpo_script_and_task_passwords_are_hidden_and_flagged():
    scripts = gpo_files.parse_scripts_ini(
        "[Logon]\n0CmdLine=net.exe\n0Parameters=use Z: \\\\fs01\\daten Geheim1 /user:CORP\\svc\n"
        "1CmdLine=map.cmd\n1Parameters=/q\n".encode("utf-16"))
    assert scripts[0].has_secret and "Geheim1" not in scripts[0].parameters and not scripts[1].has_secret
    task = gpo_files.parse_preferences(b"""<ScheduledTasks><TaskV2 name="Sync"><Properties action="C"><Task>
<Actions><Exec><Command>sync.exe</Command><Arguments>-Password S3cret -Server dc1</Arguments></Exec></Actions>
</Task></Properties></TaskV2></ScheduledTasks>""")
    assert task[0].has_cmd_secret and "S3cret" not in repr(task[0]) and "-Server dc1" in repr(task[0])
    assert scrub_command("use Z: \\\\fs01\\daten * /user:CORP\\a", "net")[1] is False  # "*" = abfragen


def test_count_mode_hides_unresolved_account_names(ctx):
    from doku_agent.generators.ad_common import AdData, AdNames

    class NoAccounts:
        def accounts_by_name(self, names):
            return {}

    ctx.cfg.ad.user_names = "count"
    ctx.__dict__["ad"] = NoAccounts()
    names = AdNames(ctx, AdData())
    assert names.principal("jdoe") == "Konto" and names.principal("CORP\\jdoe") == "Konto"
    assert names.principal("BUILTIN\\Administratoren") == "BUILTIN\\Administratoren"


# --- Freigaben: nichts doppelt ausführen, nichts Erledigtes überschreiben -----------------------------------

def _netbox_proposal(ctx):
    return ctx.store.add_proposal("netbox_plan", "Gerät", {"steps": [{"action": "create", "endpoint": "dcim/sites",
                                                                       "data": {"name": "x", "slug": "x"}}]})


def test_proposal_is_claimed_once(ctx, monkeypatch):
    import doku_agent.netbox_plan as plan
    from doku_agent.apply import ApplyError, apply_proposal

    runs = []
    monkeypatch.setattr(plan, "execute_plan", lambda nb, steps, log: runs.append(steps) or {})
    pid = _netbox_proposal(ctx)
    assert ctx.store.transition_proposal(pid, ("pending",), "applying")  # erste Freigabe läuft
    assert not ctx.store.transition_proposal(pid, ("pending",), "applying")  # zweite bekommt ihn nicht
    try:
        apply_proposal(ctx, pid)
    except ApplyError as exc:
        assert "nicht offen" in str(exc)
    else:
        raise AssertionError("zweite Freigabe hätte scheitern müssen")
    assert runs == [] and ctx.store.get_proposal(pid).status == "applying"


def test_applied_proposal_cannot_be_rejected_reopened_or_overwritten(ctx, monkeypatch):
    import re

    import doku_agent.netbox_plan as plan
    from fastapi.testclient import TestClient

    from doku_agent.apply import ApplyError, apply_proposal, reject_proposal
    from doku_agent.web.app import create_app

    monkeypatch.setattr(plan, "execute_plan", lambda nb, steps, log: {})
    pid = _netbox_proposal(ctx)
    apply_proposal(ctx, pid)
    try:
        reject_proposal(ctx, pid)
    except ApplyError:
        pass
    else:
        raise AssertionError("übernommener Vorschlag darf nicht abgelehnt werden")
    client = TestClient(create_app(ctx), base_url="http://localhost")
    auth = ("admin", "geheim")
    token = re.search(r'name="csrf" value="([^"]+)"', client.get("/", auth=auth).text).group(1)
    before = ctx.store.get_proposal(pid).payload
    other = '[{"action": "create", "endpoint": "dcim/sites", "data": {"name": "y", "slug": "y"}}]'  # gültig, anders
    stale = client.post(f"/vorschlaege/{pid}/freigeben", data={"csrf": token, "steps": other}, auth=auth,
                        follow_redirects=False)  # alter Tab
    assert "err=" in stale.headers["location"] and ctx.store.get_proposal(pid).payload == before
    assert "err=" in client.post(f"/vorschlaege/{pid}/ablehnen", data={"csrf": token}, auth=auth,
                                 follow_redirects=False).headers["location"]
    missing = client.post("/vorschlaege/9999/ablehnen", data={"csrf": token}, auth=auth, follow_redirects=False)
    assert missing.status_code == 303 and "err=" in missing.headers["location"]
    assert ctx.store.get_proposal(pid).status == "applied"


# --- Wiki-Seiten ----------------------------------------------------------------------------------------------

def test_missing_end_marker_never_deletes_user_text():
    from doku_agent import markdown

    begin, _ = markdown.block_markers("d")
    page = f"# Seite\n\n## Daten\n\n{begin}\nalt\n\nUser-Notiz wichtig\n"  # Endmarke von Hand gelöscht
    once = markdown.upsert_block(page, "d", "neu", heading="Daten")
    twice = markdown.upsert_block(once, "d", "neuer", heading="Daten")
    assert "User-Notiz wichtig" in once and "User-Notiz wichtig" in twice and "neuer" in twice


def test_code_fence_with_info_string_does_not_close_block():
    from doku_agent import markdown

    md = "```\n```bash\n[x](/alt/pfad)\n```\n\n[y](/alt/pfad)\n"
    out = markdown.replace_links(md, {"/alt/pfad": "/neu"})
    assert "[x](/alt/pfad)" in out and "[y](/neu)" in out  # der Link im Codebeispiel bleibt unverändert


def test_create_becomes_update_only_on_markdown_and_keeps_wiki_metadata(ctx, fake_wiki):
    from doku_agent.apply import ApplyError, apply_proposal
    from doku_agent.pages import Block, PageDraft, propose_page

    draft = PageDraft(doc_type="netbox_device", title="srv01", description="d",
                      blocks=[Block("netbox-device", "Steckbrief", "| a |")], target_path="it/srv01")
    pid = propose_page(ctx, draft)
    fake_wiki.add("it/srv01", "srv01", "<p>HTML</p>", [], contentType="html")  # inzwischen im Visual Editor
    try:
        apply_proposal(ctx, pid)
    except ApplyError as exc:
        assert "keine Markdown-Seite" in str(exc)
    else:
        raise AssertionError("Markdown darf nicht in eine HTML-Seite gemischt werden")
    assert fake_wiki.pages[max(fake_wiki.pages)]["content"] == "<p>HTML</p>"

    # Seite nach dem Vorschlag geändert, Tag im Wiki entfernt: beim Neuberechnen nicht wieder hinzufügen
    page_id = fake_wiki.add("it/srv02", "srv02", "Alt\n", ["netbox", "veraltet"])
    pid = propose_page(ctx, PageDraft(doc_type="netbox_device", title="srv02", description="d",
                                      blocks=[Block("netbox-device", "Steckbrief", "| a |")], target_path="it/srv02"))
    fake_wiki.pages[page_id].update(content="Alt, geändert\n", tags=["netbox"], title="Server 2 (umbenannt)")
    apply_proposal(ctx, pid)  # Hash weicht ab -> neu berechnet und erneut vorgelegt
    payload = ctx.store.get_proposal(pid).payload
    assert "veraltet" not in payload["tags"] and payload["title"] == "Server 2 (umbenannt)"


def test_name_match_is_remembered_only_after_approval_and_respects_ignore(ctx, fake_wiki):
    from doku_agent.pages import Block, PageDraft, propose_page

    fake_wiki.add("wartung/backup", "backup", "Nicht verwandt\n", [])
    draft = PageDraft(doc_type="netbox_device", title="backup", description="", lookup_name="backup",
                      blocks=[Block("netbox-device", "Steckbrief", "| a |")], path_vars={"name": "backup"},
                      stable_id="netbox:device:7")
    pid = propose_page(ctx, draft)
    assert ctx.store.get_proposal(pid).payload["path"] == "wartung/backup"
    assert ctx.store.kv_get("page-for:netbox:device:7") is None
    ctx.store.ignore("wiki:wartung/backup", "falscher Treffer")
    ctx.store.update_proposal(pid, status="rejected")
    pid2 = propose_page(ctx, draft)
    assert ctx.store.get_proposal(pid2).payload["path"] != "wartung/backup"
