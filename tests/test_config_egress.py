import httpx
import pytest

from doku_agent.config import ConfigError, load_config
from doku_agent.egress import EgressBlocked, EgressGuard, allowed_hosts
from doku_agent.jobs import JOBS
from tests.conftest import make_config


def test_env_expansion(tmp_path, monkeypatch):
    monkeypatch.setenv("WIKI_API_KEY", "s3cret")
    path = tmp_path / "config.yaml"
    path.write_text("wiki:\n  url: https://wiki.test\n  api_key: ${WIKI_API_KEY}\n"
                    "web:\n  password: ${WEB_PASSWORD:-standard}\n", encoding="utf-8")
    cfg = load_config(path)
    assert cfg.wiki.api_key == "s3cret"
    assert cfg.web.password == "standard"


def test_missing_env_is_error(tmp_path, monkeypatch):
    monkeypatch.delenv("NOPE", raising=False)
    path = tmp_path / "config.yaml"
    path.write_text("wiki:\n  url: https://wiki.test\n  api_key: ${NOPE}\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="NOPE"):
        load_config(path)


def test_example_config_is_valid(monkeypatch):
    for var in ("WIKI_API_KEY", "NETBOX_TOKEN", "WAZUH_USER", "WAZUH_PASSWORD", "INTUNE_TENANT_ID",
                "INTUNE_CLIENT_ID", "INTUNE_CLIENT_SECRET", "WEB_PASSWORD"):
        monkeypatch.setenv(var, "x")
    monkeypatch.delenv("FORTIGATE_TOKEN", raising=False)  # FortiGate ist im Beispiel aus – darf nicht stören
    cfg = load_config("config.example.yaml")
    assert cfg.llm.model == "qwen3:8b" and cfg.embeddings.model == "qwen3-embedding:0.6b"
    assert {e.job for e in cfg.schedule} <= set(JOBS)


def test_allowlist_contains_only_configured_hosts(tmp_path):
    cfg = make_config(tmp_path)
    hosts = allowed_hosts(cfg)
    assert hosts == {"wiki.test", "ollama", "netbox.test", "wazuh.test"}
    cfg.intune.enabled = True
    assert "graph.microsoft.com" in allowed_hosts(cfg)


def test_blocked_host_never_reaches_transport():
    sent = []

    def handler(request):
        sent.append(request.url.host)
        return httpx.Response(200)

    guard = EgressGuard({"wiki.test"})
    client = guard.client(transport=httpx.MockTransport(handler))
    assert client.get("https://wiki.test/x").status_code == 200
    with pytest.raises(EgressBlocked):
        client.get("https://example.com/leak")
    assert sent == ["wiki.test"]
    with pytest.raises(EgressBlocked):
        guard.client("https://api.openai.com")


def test_redirects_are_not_followed():
    def handler(request):
        return httpx.Response(302, headers={"location": "https://evil.test/"})

    client = EgressGuard({"wiki.test"}).client(transport=httpx.MockTransport(handler))
    assert client.get("https://wiki.test/").status_code == 302


def test_config_changed_after_start_is_reported(tmp_path, fake_wiki):
    import httpx

    from doku_agent.config import load_config
    from doku_agent.context import Context
    from doku_agent.jobs import run_now
    from doku_agent.web.app import run_checks
    from doku_agent.wiki import WikiClient
    from tests.conftest import FakeLLM

    path = tmp_path / "config.yaml"
    path.write_text(f"general: {{data_dir: {tmp_path / 'data'}}}\nwiki: {{url: https://wiki.test, api_key: k}}\n"
                    "web: {password: geheim}\nswitches: {enabled: false, devices: [{host: 10.253.100.243}]}\n")
    ctx = Context(load_config(path))
    ctx.__dict__["wiki"] = WikiClient(ctx.cfg.wiki, ctx.guard, transport=httpx.MockTransport(fake_wiki.handler))
    ctx.__dict__["llm"] = FakeLLM()
    assert not ctx.cfg.changed_on_disk()
    assert {n: ok for n, ok, _ in run_checks(ctx)}["Konfiguration"] is True

    # Switches eingeschaltet, aber der laufende Dienst wurde nicht neu gestartet
    path.write_text(path.read_text().replace("enabled: false", "enabled: true"))
    assert ctx.cfg.changed_on_disk()
    ok, message = {n: (ok, msg) for n, ok, msg in run_checks(ctx)}["Konfiguration"]
    assert ok is False and "docker compose restart agent" in message
    job_id, ok = run_now(ctx, "switches")
    log = ctx.store.get_job(job_id).log
    assert not ok and "nach dem Start des Agents geändert" in log
    assert "Switches sind in der Konfiguration deaktiviert" in log and "Agent neu starten" in log
