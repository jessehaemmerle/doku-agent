"""SQLite-Ablage für Freigabe-Liste (Vorschläge), Jobs, Ignorierliste, Cache, Suchindex und Fragen."""

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
CREATE TABLE IF NOT EXISTS indexed_pages (   -- Stand des semantischen Suchindex je Wiki-Seite
    page_id INTEGER PRIMARY KEY,
    path TEXT NOT NULL,
    title TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    model TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS chunks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    page_id INTEGER NOT NULL,
    heading TEXT NOT NULL DEFAULT '',
    text TEXT NOT NULL,
    vector BLOB NOT NULL               -- float32, normiert
);
CREATE INDEX IF NOT EXISTS idx_chunks_page ON chunks(page_id);
CREATE TABLE IF NOT EXISTS questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    question TEXT NOT NULL,
    status TEXT NOT NULL,              -- queued | running | done | failed
    answer TEXT NOT NULL DEFAULT '',
    sources TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    finished_at TEXT
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
class Question:
    id: int
    question: str
    status: str
    answer: str
    sources: list[dict]
    created_at: str
    finished_at: str | None


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
                row = db.execute("SELECT id, payload FROM proposals WHERE dedup_key=? AND status='pending'",
                                 (dedup_key,)).fetchone()
                if row and json.loads(row["payload"]).get("edited"):
                    return row["id"]  # von Hand bearbeitet: Vorrang vor neu erzeugtem Inhalt
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

    def close_pending(self, dedup_key: str, result: str) -> None:
        """Offenen Vorschlag schließen, der sich erledigt hat (z.B. von Hand in Netbox korrigiert)."""
        with self._conn() as db:
            db.execute("UPDATE proposals SET status='rejected', result=?, updated_at=? "
                       "WHERE dedup_key=? AND status='pending'", (result, now(), dedup_key))

    def count_pending(self) -> int:
        with self._conn() as db:
            return db.execute("SELECT COUNT(*) FROM proposals WHERE status='pending'").fetchone()[0]

    def pending_dedup_keys(self) -> set[str]:
        with self._conn() as db:
            rows = db.execute("SELECT dedup_key FROM proposals WHERE status='pending' AND dedup_key IS NOT NULL")
            return {r[0] for r in rows.fetchall()}

    def pending_by_source(self, source: str) -> list[Proposal]:
        with self._conn() as db:
            rows = db.execute("SELECT * FROM proposals WHERE status='pending' AND source=? ORDER BY id",
                              (source,)).fetchall()
        return [self._proposal(r) for r in rows]

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

    def kv_items(self, prefix: str) -> dict:
        """Alle Einträge, deren Schlüssel mit prefix beginnt (z.B. 'page-for:')."""
        with self._conn() as db:
            rows = db.execute("SELECT key, value FROM kv WHERE substr(key, 1, ?) = ?", (len(prefix), prefix)).fetchall()
        return {r["key"]: json.loads(r["value"]) for r in rows}

    def kv_delete(self, key: str) -> None:
        with self._conn() as db:
            db.execute("DELETE FROM kv WHERE key=?", (key,))

    # --- Semantischer Suchindex -------------------------------------------

    def indexed_pages(self) -> dict[int, dict]:
        with self._conn() as db:
            return {r["page_id"]: dict(r) for r in db.execute("SELECT * FROM indexed_pages").fetchall()}

    def replace_page_chunks(self, page_id: int, path: str, title: str, updated_at: str, model: str,
                            chunks: list[tuple[str, str, bytes]]) -> None:
        """Abschnitte einer Seite ersetzen (heading, text, vector)."""
        with self._conn() as db:
            db.execute("DELETE FROM chunks WHERE page_id=?", (page_id,))
            db.executemany("INSERT INTO chunks (page_id, heading, text, vector) VALUES (?, ?, ?, ?)",
                           [(page_id, h, t, v) for h, t, v in chunks])
            db.execute("INSERT OR REPLACE INTO indexed_pages (page_id, path, title, updated_at, model) "
                       "VALUES (?, ?, ?, ?, ?)", (page_id, path, title, updated_at, model))

    def delete_page_chunks(self, page_ids: list[int]) -> None:
        with self._conn() as db:
            db.executemany("DELETE FROM chunks WHERE page_id=?", [(p,) for p in page_ids])
            db.executemany("DELETE FROM indexed_pages WHERE page_id=?", [(p,) for p in page_ids])

    def chunks_for_model(self, model: str) -> list[dict]:
        with self._conn() as db:
            rows = db.execute(
                "SELECT c.id, c.page_id, c.heading, c.text, c.vector, i.path, i.title FROM chunks c "
                "JOIN indexed_pages i ON i.page_id = c.page_id WHERE i.model=? ORDER BY c.id", (model,)).fetchall()
        return [dict(r) for r in rows]

    # --- Fragen ans Wiki ----------------------------------------------------

    @staticmethod
    def _question(row: sqlite3.Row) -> Question:
        d = dict(row)
        d["sources"] = json.loads(d["sources"])
        return Question(**d)

    def add_question(self, question: str) -> int:
        with self._conn() as db:
            cur = db.execute("INSERT INTO questions (question, status, created_at) VALUES (?, 'queued', ?)",
                             (question, now()))
            return cur.lastrowid

    def set_question(self, qid: int, status: str, answer: str = "", sources: list[dict] | None = None) -> None:
        finished = now() if status in ("done", "failed") else None
        with self._conn() as db:
            db.execute("UPDATE questions SET status=?, answer=?, sources=?, finished_at=? WHERE id=?",
                       (status, answer, json.dumps(sources or []), finished, qid))

    def get_question(self, qid: int) -> Question | None:
        with self._conn() as db:
            row = db.execute("SELECT * FROM questions WHERE id=?", (qid,)).fetchone()
        return self._question(row) if row else None

    def list_questions(self, limit: int = 20) -> list[Question]:
        with self._conn() as db:
            rows = db.execute("SELECT * FROM questions ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [self._question(r) for r in rows]

    def reset_open_questions(self) -> None:
        with self._conn() as db:
            db.execute("UPDATE questions SET status='failed', answer='Abgebrochen durch Neustart.', finished_at=? "
                       "WHERE status IN ('queued', 'running')", (now(),))
