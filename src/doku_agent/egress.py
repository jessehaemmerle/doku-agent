"""Ausgehende Verbindungen nur zu explizit erlaubten Hosts.

Jeder HTTP-Client des Agents wird hier erzeugt. Ein Request an einen Host, der
nicht auf der Allowlist steht, wird vor dem Senden abgebrochen. So kann weder
ein Konfigurationsfehler noch eine Weiterleitung Daten an fremde Dienste leaken.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import httpx

from doku_agent.config import Config, TlsVerify

GRAPH_HOSTS = ("login.microsoftonline.com", "graph.microsoft.com")


class EgressBlocked(RuntimeError):
    pass


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def allowed_hosts(cfg: Config) -> set[str]:
    hosts = {_host(cfg.wiki.url), _host(cfg.llm.base_url)}
    if cfg.netbox.enabled:
        hosts.add(_host(cfg.netbox.url))
    if cfg.wazuh.enabled:
        hosts.add(_host(cfg.wazuh.url))
    if cfg.intune.enabled:
        hosts.update(GRAPH_HOSTS)
    hosts.update(h.lower() for h in cfg.egress.extra_allowed_hosts)
    hosts.discard("")
    return hosts


class EgressGuard:
    def __init__(self, hosts: set[str], trust_env: bool = False):
        self.hosts = frozenset(hosts)
        self.trust_env = trust_env

    @classmethod
    def from_config(cls, cfg: Config) -> "EgressGuard":
        return cls(allowed_hosts(cfg), trust_env=cfg.egress.trust_env)

    def check(self, request: httpx.Request) -> None:
        host = (request.url.host or "").lower()
        if host not in self.hosts:
            raise EgressBlocked(f"Verbindung zu {host!r} blockiert (nicht in der Allowlist)")

    def client(
        self,
        base_url: str = "",
        *,
        verify: TlsVerify = True,
        headers: dict[str, str] | None = None,
        timeout: float = 60,
        transport: httpx.BaseTransport | None = None,
    ) -> httpx.Client:
        if base_url and _host(base_url) not in self.hosts:
            raise EgressBlocked(f"Basis-URL {base_url!r} ist nicht in der Allowlist")
        return httpx.Client(
            base_url=base_url,
            verify=verify,
            headers=headers,
            timeout=timeout,
            follow_redirects=False,
            event_hooks={"request": [self.check]},
            transport=transport,
            # Standard: Proxy-Variablen ignorieren, alles geht direkt ins LAN.
            trust_env=self.trust_env,
        )
