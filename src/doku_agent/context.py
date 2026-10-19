"""Gemeinsamer Laufzeit-Kontext: Konfiguration, Ablage und (lazy) alle Clients."""

from __future__ import annotations

import logging
from functools import cached_property

from doku_agent.config import Config
from doku_agent.egress import EgressGuard
from doku_agent.store import Store

CLIENTS = ("llm", "wiki", "netbox", "wazuh", "intune")


class Context:
    def __init__(self, cfg: Config, store: Store | None = None, log: logging.Logger | None = None):
        self.cfg = cfg
        self.store = store or Store(cfg.db_path)
        self.guard = EgressGuard.from_config(cfg)
        self.log = log or logging.getLogger("doku_agent")
        # Clients werden einmal pro Prozess erzeugt und von allen Job-Kontexten geteilt
        # (Verbindungs-Pools und Tokens wiederverwenden statt pro Job neu aufzubauen).
        self._clients: dict[str, object] = {}

    def with_log(self, log: logging.Logger) -> "Context":
        """Kopie mit eigenem Logger (z.B. pro Job). Teilt Ablage und Clients;
        die Konventionen (Seitenliste des Wikis) werden pro Job frisch gelesen."""
        ctx = Context(self.cfg, self.store, log)
        ctx.guard = self.guard
        ctx._clients = self._clients
        for name in CLIENTS:  # direkt gesetzte Clients (z.B. in Tests) mitnehmen
            if name in self.__dict__:
                ctx.__dict__[name] = self.__dict__[name]
        return ctx

    def _shared(self, name: str, factory):
        if name not in self._clients:
            self._clients[name] = factory()
        return self._clients[name]

    @cached_property
    def llm(self):
        from doku_agent.llm import LLM
        return self._shared("llm", lambda: LLM(self.cfg.llm, self.guard, self.cfg.general.language))

    @cached_property
    def wiki(self):
        from doku_agent.wiki import WikiClient
        return self._shared("wiki", lambda: WikiClient(self.cfg.wiki, self.guard))

    @cached_property
    def conventions(self):
        from doku_agent.conventions import Conventions
        return Conventions(self.wiki, self.cfg.wiki.convention_sample_pages)

    @cached_property
    def netbox(self):
        from doku_agent.connectors.netbox import NetboxClient
        if not self.cfg.netbox.enabled:
            raise RuntimeError("Netbox ist in der Konfiguration deaktiviert")
        return self._shared("netbox", lambda: NetboxClient(self.cfg.netbox, self.guard))

    @cached_property
    def wazuh(self):
        from doku_agent.connectors.wazuh import WazuhClient
        if not self.cfg.wazuh.enabled:
            raise RuntimeError("Wazuh ist in der Konfiguration deaktiviert")
        return self._shared("wazuh", lambda: WazuhClient(self.cfg.wazuh, self.guard))

    @cached_property
    def intune(self):
        from doku_agent.connectors.intune import IntuneClient
        if not self.cfg.intune.enabled:
            raise RuntimeError("Intune ist in der Konfiguration deaktiviert")
        return self._shared("intune", lambda: IntuneClient(self.cfg.intune, self.guard))
