"""SQLite-Ablage für Freigabe-Liste (Vorschläge), Jobs, Ignorierliste und Cache."""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS proposals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,              -- wiki_page | netbox_plan
    status TEXT NOT NULL,            -- pending | applied | rejected | failed
    title TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    payload TEXT NOT NULL,
    diff TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    dedup_key TEXT,
    result TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_proposals_status ON proposals(status);
CREATE INDEX IF NOT EXISTS idx_proposals_dedup ON proposals(dedup_key);
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    params TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL,            -- queued | running | done | failed
    log TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT
);
CREATE TABLE IF NOT EXISTS ignores (
    key TEXT PRIMARY KEY,
    reason TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

# Feste SQL-Fragmente für änderbare Spalten (keine dynamischen Spaltennamen im SQL).
_UPDATABLE = {
    "status": "status=?",
    "title": "title=?",
    "summary": "summary=?",
    "payload": "payload=?",
    "diff": "diff=?",
    "result": "result=?",
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Proposal:
    id: int
    kind: str
    status: str
    title: str
    summary: str
    payload: dict
    diff: str
    source: str
    dedup_key: str | None
    result: str
    created_at: str
    updated_at: str


@dataclass
class Job:
    id: int
    name: str
    params: dict
    status: str
    log: str
    created_at: str
    started_at: str | None
    finished_at: str | None


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lock = threading.Lock()
        with self._conn() as db:
            db.executescript(SCHEMA)
            db.execute("PRAGMA journal_mode=WAL")

    @contextmanager
    def _conn(self):
        with self._lock:
            db = sqlite3.connect(self.path, timeout=30)
            db.row_factory = sqlite3.Row
            try:
                yield db
                db.commit()
            finally:
                db.close()

    # --- Vorschläge ---------------------------------------------------------

    @staticmethod
    def _proposal(row: sqlite3.Row) -> Proposal:
        d = dict(row)
        d["payload"] = json.loads(d["payload"])
        return Proposal(**d)

    def add_proposal(self, kind: str, title: str, payload: dict, *, summary: str = "", diff: str = "",
                     source: str = "", dedup_key: str | None = None) -> int:
        """Legt einen Vorschlag an. Ein offener Vorschlag mit gleichem dedup_key wird ersetzt."""
        ts = now()
        with self._conn() as db:
            if dedup_key:
                row = db.execute("SELECT id FROM proposals WHERE dedup_key=? AND status='pending'",
                                 (dedup_key,)).fetchone()
                if row:
                    db.execute(
                        "UPDATE proposals SET title=?, summary=?, payload=?, diff=?, source=?, updated_at=? "
                        "WHERE id=?",
                        (title, summary, json.dumps(payload), diff, source, ts, row["id"]),
                    )
                    return row["id"]
            cur = db.execute(
                "INSERT INTO proposals (kind, status, title, summary, payload, diff, source, dedup_key, "
                "created_at, updated_at) VALUES (?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?)",
                (kind, title, summary, json.dumps(payload), diff, source, dedup_key, ts, ts),
            )
            return cur.lastrowid

    def get_proposal(self, pid: int) -> Proposal | None:
        with self._conn() as db:
            row = db.execute("SELECT * FROM proposals WHERE id=?", (pid,)).fetchone()
        return self._proposal(row) if row else None

    def list_proposals(self, status: str | None = None, limit: int = 200) -> list[Proposal]:
        with self._conn() as db:
            if status:
                rows = db.execute("SELECT * FROM proposals WHERE status=? ORDER BY id DESC LIMIT ?",
                                  (status, limit)).fetchall()
            else:
                rows = db.execute("SELECT * FROM proposals ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [self._proposal(r) for r in rows]

    def update_proposal(self, pid: int, **fields) -> None:
        unknown = set(fields) - set(_UPDATABLE)
        if not fields or unknown:
            raise ValueError(f"Ungültige Felder: {unknown}")
        if "payload" in fields:
            fields["payload"] = json.dumps(fields["payload"])
        sql = "UPDATE proposals SET " + ", ".join(_UPDATABLE[k] for k in fields) + ", updated_at=? WHERE id=?"
        with self._conn() as db:
            db.execute(sql, (*fields.values(), now(), pid))

    def count_pending(self) -> int:
        with self._conn() as db:
            return db.execute("SELECT COUNT(*) FROM proposals WHERE status='pending'").fetchone()[0]

    # --- Jobs ---------------------------------------------------------------

    @staticmethod
    def _job(row: sqlite3.Row) -> Job:
        d = dict(row)
        d["params"] = json.loads(d["params"])
        return Job(**d)

    def enqueue(self, name: str, params: dict | None = None) -> int:
        with self._conn() as db:
            cur = db.execute("INSERT INTO jobs (name, params, status, created_at) VALUES (?, ?, 'queued', ?)",
                             (name, json.dumps(params or {}), now()))
            return cur.lastrowid

    def start_job(self, name: str, params: dict | None = None) -> int:
        """Job direkt als laufend anlegen (Ausführung im eigenen Prozess, z.B. CLI)."""
        ts = now()
        with self._conn() as db:
            cur = db.execute(
                "INSERT INTO jobs (name, params, status, created_at, started_at) VALUES (?, ?, 'running', ?, ?)",
                (name, json.dumps(params or {}), ts, ts))
            return cur.lastrowid

    def claim_next_job(self) -> Job | None:
        with self._conn() as db:
            row = db.execute("SELECT * FROM jobs WHERE status='queued' ORDER BY id LIMIT 1").fetchone()
            if not row:
                return None
            db.execute("UPDATE jobs SET status='running', started_at=? WHERE id=?", (now(), row["id"]))
            row = db.execute("SELECT * FROM jobs WHERE id=?", (row["id"],)).fetchone()
        return self._job(row)

    def append_job_log(self, jid: int, line: str) -> None:
        with self._conn() as db:
            db.execute("UPDATE jobs SET log = log || ? WHERE id=?", (line.rstrip("\n") + "\n", jid))

    def finish_job(self, jid: int, ok: bool) -> None:
        with self._conn() as db:
            db.execute("UPDATE jobs SET status=?, finished_at=? WHERE id=?", ("done" if ok else "failed", now(), jid))

    def reset_running_jobs(self) -> None:
        """Nach einem Neustart hängengebliebene Jobs als fehlgeschlagen markieren."""
        with self._conn() as db:
            db.execute("UPDATE jobs SET status='failed', finished_at=?, log = log || ? WHERE status='running'",
                       (now(), "Abgebrochen durch Neustart.\n"))

    def get_job(self, jid: int) -> Job | None:
        with self._conn() as db:
            row = db.execute("SELECT * FROM jobs WHERE id=?", (jid,)).fetchone()
        return self._job(row) if row else None

    def list_jobs(self, limit: int = 50) -> list[Job]:
        with self._conn() as db:
            rows = db.execute("SELECT * FROM jobs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [self._job(r) for r in rows]

    # --- Ignorierliste & Cache ---------------------------------------------

    def ignore(self, key: str, reason: str = "") -> None:
        with self._conn() as db:
            db.execute("INSERT OR REPLACE INTO ignores (key, reason, created_at) VALUES (?, ?, ?)",
                       (key, reason, now()))

    def unignore(self, key: str) -> None:
        with self._conn() as db:
            db.execute("DELETE FROM ignores WHERE key=?", (key,))

    def is_ignored(self, key: str) -> bool:
        with self._conn() as db:
            return db.execute("SELECT 1 FROM ignores WHERE key=?", (key,)).fetchone() is not None

    def list_ignores(self) -> list[dict]:
        with self._conn() as db:
            return [dict(r) for r in db.execute("SELECT * FROM ignores ORDER BY created_at DESC").fetchall()]

    def kv_get(self, key: str, default=None):
        with self._conn() as db:
            row = db.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
        return json.loads(row["value"]) if row else default

    def kv_set(self, key: str, value) -> None:
        with self._conn() as db:
            db.execute("INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)", (key, json.dumps(value)))
