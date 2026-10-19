import re

import pytest
from fastapi.testclient import TestClient

from doku_agent.pages import Block, PageDraft, propose_page
from doku_agent.web.app import create_app

AUTH = ("admin", "geheim")


@pytest.fixture
def client(ctx):
    return TestClient(create_app(ctx), base_url="http://localhost")


def _csrf(client, url="/"):
    html = client.get(url, auth=AUTH).text
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def test_requires_auth_except_healthz(client):
    assert client.get("/healthz").text == "ok"
    assert client.get("/").status_code == 401
    assert client.get("/", auth=("admin", "falsch")).status_code == 401
    page = client.get("/", auth=AUTH)
    assert page.status_code == 200 and "Alles freigegeben" in page.text
    assert page.headers["x-frame-options"] == "DENY"


def test_post_without_csrf_is_rejected(client):
    assert client.post("/jobs", data={"name": "discovery"}, auth=AUTH).status_code == 403
    token = _csrf(client)
    resp = client.post("/jobs", data={"name": "discovery", "csrf": token}, auth=AUTH,
                       headers={"origin": "http://evil.example"})
    assert resp.status_code == 403


def test_start_job_and_view(client, ctx):
    token = _csrf(client)
    resp = client.post("/jobs", data={"name": "discovery", "csrf": token}, auth=AUTH, follow_redirects=False)
    assert resp.status_code == 303
    assert ctx.store.list_jobs()[0].name == "discovery"
    assert client.get(resp.headers["location"], auth=AUTH).status_code == 200
    bad = client.post("/jobs", data={"name": "freeform", "csrf": token}, auth=AUTH, follow_redirects=False)
    assert "err=" in bad.headers["location"]


def test_review_edit_and_approve(client, ctx, fake_wiki):
    pid = propose_page(ctx, PageDraft(doc_type="netbox_device", title="srv01", description="d",
                                      blocks=[Block("netbox-device", "Steckbrief", "| a |")],
                                      path_vars={"name": "srv01"}, source="test"))
    detail = client.get(f"/vorschlaege/{pid}", auth=AUTH)
    assert detail.status_code == 200 and 'class="add"' in detail.text
    token = _csrf(client, f"/vorschlaege/{pid}")
    resp = client.post(f"/vorschlaege/{pid}/freigeben", auth=AUTH, follow_redirects=False,
                       data={"csrf": token, "title": "srv01 (Web)", "path": "infra/srv01", "tags": "netbox, web",
                             "content": "Bearbeitet\r\n"})
    assert resp.status_code == 303 and "msg=" in resp.headers["location"]
    page = next(iter(fake_wiki.pages.values()))
    assert page["title"] == "srv01 (Web)" and page["path"] == "infra/srv01" and page["content"] == "Bearbeitet\n"
    assert page["tags"] == ["netbox", "web"]
    assert ctx.store.get_proposal(pid).status == "applied"


def test_invalid_netbox_plan_edit_is_refused(client, ctx):
    pid = ctx.store.add_proposal("netbox_plan", "Netbox: Gerät x", {"steps": [
        {"ref": "dev", "action": "create", "endpoint": "dcim/devices", "data": {"name": "x"}}]})
    token = _csrf(client, f"/vorschlaege/{pid}")
    resp = client.post(f"/vorschlaege/{pid}/freigeben", auth=AUTH, follow_redirects=False,
                       data={"csrf": token, "steps": '[{"action": "create", "endpoint": "users/tokens"}]'})
    assert "Plan%20ung" in resp.headers["location"]
    assert ctx.store.get_proposal(pid).status == "pending"


def test_reject_with_ignore_and_unignore(client, ctx):
    pid = ctx.store.add_proposal("netbox_plan", "x", {"steps": []}, dedup_key="netbox:name:x")
    token = _csrf(client)
    client.post(f"/vorschlaege/{pid}/ablehnen", auth=AUTH, data={"csrf": token, "ignore": "1"})
    assert ctx.store.is_ignored("netbox:name:x")
    client.post("/ignorierliste/entfernen", auth=AUTH, data={"csrf": token, "key": "netbox:name:x"})
    assert not ctx.store.is_ignored("netbox:name:x")


def test_task_upload_enqueues_freeform(client, ctx):
    token = _csrf(client, "/auftrag")
    resp = client.post("/auftrag", auth=AUTH, follow_redirects=False,
                       data={"csrf": token, "instruction": "Firewall VLAN 20", "target_path": ""},
                       files=[("files", ("../../etc/regeln.txt", b"allow 443", "text/plain"))])
    assert resp.status_code == 303
    job = ctx.store.list_jobs()[0]
    assert job.name == "freeform" and job.params["files"][0].endswith("/regeln.txt")
    assert str(ctx.cfg.upload_dir) in job.params["files"][0]  # kein Pfad-Ausbruch über den Dateinamen


def test_pages_render(client, fake_wiki):
    fake_wiki.add("infra/a", "A", "## X\n", ["t"])
    for url in ("/vorschlaege", "/vorschlaege?status=", "/jobs", "/auftrag", "/konventionen",
                "/konventionen?bereich=infra"):
        assert client.get(url, auth=AUTH).status_code == 200, url


def test_templates_escape_untrusted_content(client, ctx):
    pid = ctx.store.add_proposal("wiki_page", "<script>alert(1)</script>", {
        "action": "create", "path": "x", "title": "t", "tags": [], "content": "<img src=x onerror=alert(1)>",
        "hints": ["<b>fett</b>"]}, diff="+<script>x</script>")
    html = client.get(f"/vorschlaege/{pid}", auth=AUTH).text
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
    assert "<b>fett</b>" not in html and "<img src=x" not in html
