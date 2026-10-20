"""Jobs: Registry, Ausführung mit Job-Log und ein Worker-Thread (ein Job gleichzeitig – CPU-LLM)."""

from __future__ import annotations

import logging
import shutil
import threading
import time
import traceback
from pathlib import Path

from doku_agent.context import Context

log = logging.getLogger(__name__)


def _discovery(ctx: Context, params: dict):
    from doku_agent.discovery import run_discovery
    return run_discovery(ctx)


def _wazuh_rules(ctx: Context, params: dict):
    from doku_agent.generators.wazuh_docs import document_rules
    return document_rules(ctx)


def _wazuh_decoders(ctx: Context, params: dict):
    from doku_agent.generators.wazuh_docs import document_decoders
    return document_decoders(ctx)


def _wazuh_config(ctx: Context, params: dict):
    from doku_agent.generators.wazuh_docs import document_config
    return document_config(ctx)


def _wazuh_sca(ctx: Context, params: dict):
    from doku_agent.generators.wazuh_docs import document_sca
    return document_sca(ctx)


def _intune(ctx: Context, params: dict):
    from doku_agent.generators.intune_docs import document_intune
    return document_intune(ctx)


def _fortigate(ctx: Context, params: dict):
    from doku_agent.generators.fortigate_docs import document_fortigate
    sections = [s for s in params.get("sections", "").split(",") if s]
    return document_fortigate(ctx, params.get("device", ""), params.get("vdom", ""), sections or None)


def _fortigate_netbox(ctx: Context, params: dict):
    from doku_agent.fortigate_netbox import sync_fortigates
    return sync_fortigates(ctx, params.get("device", ""))


def _switches(ctx: Context, params: dict):
    from doku_agent.switches import sync_switches
    return sync_switches(ctx, params.get("host", ""))


def _netbox_device(ctx: Context, params: dict):
    from doku_agent.generators.netbox_docs import document_object
    return document_object(ctx, params.get("kind", "device"), int(params["id"]))


def _netbox_devices(ctx: Context, params: dict):
    from doku_agent.generators.netbox_docs import document_all
    return document_all(ctx, params.get("site", ""), params.get("role", ""))


def _wiki_index(ctx: Context, params: dict):
    from doku_agent.semantic import index_wiki
    page_ids = [int(p) for p in str(params.get("page_id", "")).split(",") if p.strip()]
    return index_wiki(ctx, page_ids or None)


def _wiki_lint(ctx: Context, params: dict):
    from doku_agent.lint import run_lint
    return run_lint(ctx)


def _freeform(ctx: Context, params: dict):
    from doku_agent.generators.freeform import run_freeform
    files = [Path(f) for f in params.get("files", [])]
    try:
        return run_freeform(ctx, params["instruction"], files, params.get("target_path", ""))
    finally:
        upload_dir = params.get("upload_dir")
        if upload_dir and Path(upload_dir).resolve().is_relative_to(ctx.cfg.upload_dir.resolve()):
            shutil.rmtree(upload_dir, ignore_errors=True)


JOBS = {
    "discovery": ("Netbox-Discovery (Intune + Wazuh)", _discovery),
    "wazuh_rules": ("Wazuh: eigene Regeln", _wazuh_rules),
    "wazuh_decoders": ("Wazuh: eigene Decoder", _wazuh_decoders),
    "wazuh_config": ("Wazuh: Manager- und Gruppen-Konfiguration", _wazuh_config),
    "wazuh_sca": ("Wazuh: SCA-Ergebnisse", _wazuh_sca),
    "intune": ("Intune: Richtlinien, Profile, Apps, Gruppen", _intune),
    "fortigate": ("FortiGate: Regeln, NAT, Objekte, Netzwerk, VPN, Prüfung", _fortigate),
    "fortigate_netbox": ("FortiGate → Netbox: Interfaces, IPs, VLANs, Präfixe", _fortigate_netbox),
    "switches": ("Switches (SNMP) → Netbox: Ports und Kabel", _switches),
    "netbox_device": ("Netbox: Steckbrief eines Geräts", _netbox_device),
    "netbox_devices": ("Netbox: Steckbriefe aller Geräte", _netbox_devices),
    "freeform": ("Freie Dokumentation", _freeform),
    "wiki_index": ("Wiki: Suchindex aktualisieren", _wiki_index),
    "wiki_lint": ("Wiki-Lint: Links, Dubletten, Tags, Aktualität", _wiki_lint),
}
# Jobs ohne Pflichtparameter, die über UI/CLI/Scheduler direkt gestartet werden können.
STARTABLE = ["discovery", "wazuh_rules", "wazuh_decoders", "wazuh_config", "wazuh_sca", "intune", "fortigate",
             "fortigate_netbox", "switches", "netbox_devices", "wiki_index", "wiki_lint"]


class _JobLogHandler(logging.Handler):
    """Schreibt Log-Zeilen eines Jobs in die Ablage, damit sie in UI und CLI sichtbar sind."""

    def __init__(self, ctx: Context, job_id: int):
        super().__init__(logging.INFO)
        self.ctx, self.job_id = ctx, job_id

    def emit(self, record: logging.LogRecord) -> None:
        line = f"{time.strftime('%H:%M:%S')} {record.levelname} {record.getMessage()}"
        if record.exc_info:
            line += "\n" + "".join(traceback.format_exception(*record.exc_info)).rstrip()
        try:
            self.ctx.store.append_job_log(self.job_id, line)
        except Exception:  # Logging darf den Job nie abbrechen
            pass


def run_job(base: Context, job_id: int, name: str, params: dict) -> bool:
    if name not in JOBS:
        base.store.append_job_log(job_id, f"Unbekannter Job: {name}")
        base.store.finish_job(job_id, False)
        return False
    # Eigenständiger Logger statt getLogger(): getLogger würde pro Job einen Eintrag behalten.
    job_log = logging.Logger(f"doku_agent.job.{job_id}", logging.INFO)
    job_log.parent = logging.getLogger("doku_agent")
    handler = _JobLogHandler(base, job_id)
    job_log.addHandler(handler)
    ctx = base.with_log(job_log)
    ok = False
    try:
        job_log.info("Start: %s", JOBS[name][0])
        result = JOBS[name][1](ctx, params)
        if isinstance(result, list):
            created = [r for r in result if r]
            job_log.info("Fertig: %s Vorschläge erzeugt/aktualisiert, %s ohne Änderung", len(created),
                         len(result) - len(created))
        elif isinstance(result, int):
            job_log.info("Fertig: Vorschlag #%s erzeugt", result)
        else:
            job_log.info("Fertig: %s", result if result is not None else "keine Änderung nötig")
        ok = True
    except Exception as exc:
        job_log.exception("Fehler: %s", exc)
    finally:
        base.store.finish_job(job_id, ok)
        job_log.removeHandler(handler)
    return ok


def run_now(base: Context, name: str, params: dict | None = None) -> tuple[int, bool]:
    """Job sofort im aktuellen Prozess ausführen (CLI). Rückgabe: (Job-ID, Erfolg)."""
    job_id = base.store.start_job(name, params)
    return job_id, run_job(base, job_id, name, params or {})


class Worker(threading.Thread):
    def __init__(self, ctx: Context, poll_seconds: float = 3):
        super().__init__(name="doku-agent-worker", daemon=True)
        self.ctx = ctx
        self.poll_seconds = poll_seconds
        self.stop_event = threading.Event()

    def run(self) -> None:
        self.ctx.store.reset_running_jobs()
        while not self.stop_event.is_set():
            job = self.ctx.store.claim_next_job()
            if job is None:
                self.stop_event.wait(self.poll_seconds)
                continue
            log.info("Job #%s %s gestartet", job.id, job.name)
            run_job(self.ctx, job.id, job.name, job.params)
