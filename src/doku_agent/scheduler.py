"""Einfacher Tages-Scheduler: stellt konfigurierte Jobs zur angegebenen Uhrzeit in die Warteschlange."""

from __future__ import annotations

import logging
import threading
from datetime import datetime
from zoneinfo import ZoneInfo

from doku_agent.context import Context
from doku_agent.jobs import JOBS

log = logging.getLogger(__name__)


def due_entries(ctx: Context, now: datetime) -> list[tuple[int, str]]:
    """Fällige Einträge (Index, Job), die heute noch nicht eingeplant wurden."""
    due = []
    today = now.date().isoformat()
    for idx, entry in enumerate(ctx.cfg.schedule):
        if now.weekday() not in entry.days or now.strftime("%H:%M") < entry.at:
            continue
        key = f"schedule:{idx}:{entry.job}:{entry.at}"
        if ctx.store.kv_get(key) == today:
            continue
        due.append((idx, entry.job))
        ctx.store.kv_set(key, today)
    return due


class Scheduler(threading.Thread):
    def __init__(self, ctx: Context, interval: float = 30):
        super().__init__(name="doku-agent-scheduler", daemon=True)
        self.ctx = ctx
        self.interval = interval
        self.stop_event = threading.Event()
        self.tz = ZoneInfo(ctx.cfg.general.timezone)
        unknown = [e.job for e in ctx.cfg.schedule if e.job not in JOBS]
        if unknown:
            raise ValueError(f"Unbekannte Jobs im Zeitplan: {unknown}")
        # Beim Start nichts nachholen, was heute schon vorbei ist.
        now = datetime.now(self.tz)
        for idx, entry in enumerate(ctx.cfg.schedule):
            key = f"schedule:{idx}:{entry.job}:{entry.at}"
            if now.strftime("%H:%M") >= entry.at and ctx.store.kv_get(key) is None:
                ctx.store.kv_set(key, now.date().isoformat())

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                for _, job in due_entries(self.ctx, datetime.now(self.tz)):
                    jid = self.ctx.store.enqueue(job, {})
                    log.info("Zeitplan: Job %s als #%s eingeplant", job, jid)
            except Exception:
                log.exception("Scheduler-Fehler")
            self.stop_event.wait(self.interval)
