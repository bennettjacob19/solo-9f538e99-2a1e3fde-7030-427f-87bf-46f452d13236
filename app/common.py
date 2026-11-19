"""Shared configuration and the SQLite state plane.

Every DNS round (an isolated regression lane) gets its *own* SQLite database,
own authoritative endpoint and own resolver.  The web console starts those two
processes per round with round-specific ``DB_PATH`` / ports, so two rounds can
run in parallel without sharing control state, cache or logs.

Within one round the three processes share one SQLite database in WAL mode:

  control   -- desired behaviour of the authoritative endpoint, written by the
               web console (or a regression step), read per query.  ``step_no``
               is the regression step that applied the setting, so the
               authoritative reply can say which setting it actually used.
  cache     -- the resolver's cache.  Absolute epoch deadlines are stored, so a
               resolver restart can never extend the validity of an old A
               record.  ``auth_step`` is the setting-step number that produced
               the cached A / NXDOMAIN, and is returned to clients.
  query_log -- every client query the resolver answered, with its source.
  auth_log  -- every query the authoritative endpoint saw, with the action it
               took (answered / nxdomain / dropped / delayed) and its step.

All helpers accept an explicit ``db_path`` so the web console can operate a
round's database from a different process.
"""
from __future__ import annotations

import os
import sqlite3
import time

# --------------------------------------------------------------------------
# Configuration (environment overridable; defaults are the spec values).
# --------------------------------------------------------------------------
FIXED_DOMAIN = os.environ.get("FIXED_DOMAIN", "service.example").strip().rstrip(".")
FQDN = FIXED_DOMAIN + "."

DB_PATH = os.environ.get("DB_PATH", "/data/app.db")
ROUND_DB_DIR = os.environ.get("ROUND_DB_DIR", "/data/rounds")

FRESH_TTL = float(os.environ.get("FRESH_TTL", "5"))        # successful answers are fresh for 5s
STALE_WINDOW = float(os.environ.get("STALE_WINDOW", "20"))  # stale A usable <=20s after expiry
UPSTREAM_TIMEOUT = float(os.environ.get("UPSTREAM_TIMEOUT", "2.0"))

AUTH_HOST = os.environ.get("AUTH_HOST", "127.0.0.1")
AUTH_PORT = int(os.environ.get("AUTH_PORT", "5354"))
RESOLVER_HOST = os.environ.get("RESOLVER_HOST", "127.0.0.1")
RESOLVER_PORT = int(os.environ.get("RESOLVER_PORT", "5353"))
WEB_PORT = int(os.environ.get("WEB_PORT", "8000"))

DEFAULT_IP = os.environ.get("DEFAULT_IP", "192.0.2.10")
DEFAULT_DELAY = float(os.environ.get("DEFAULT_DELAY", "3.0"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS control (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  mode TEXT NOT NULL,              -- a | nxdomain | delay | timeout
  ip TEXT NOT NULL,
  delay_seconds REAL NOT NULL,
  step_no INTEGER,                 -- regression step that applied this config
  updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS cache (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  qname TEXT NOT NULL,
  rcode TEXT NOT NULL,             -- NOERROR | NXDOMAIN
  a_record TEXT,                   -- NULL once NXDOMAIN is confirmed (old A purged)
  auth_step TEXT,                  -- setting step behind the cached answer (NULL = none)
  fetched_at REAL NOT NULL,        -- last successful upstream answer (epoch)
  fresh_until REAL NOT NULL,       -- serve-fresh deadline (epoch)
  stale_until REAL,                -- A only: last moment a stale A may be served
  nx_confirmed_at REAL
);
CREATE TABLE IF NOT EXISTS query_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  qname TEXT, qtype TEXT, source TEXT, rcode TEXT, answers TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS auth_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  qname TEXT, qtype TEXT, mode TEXT, action TEXT, detail TEXT
);
"""

_LOG_TABLES = ("query_log", "auth_log")

# Columns added after the first release.  ``CREATE TABLE IF NOT EXISTS`` does
# not touch an existing database, so older volumes are migrated in place.
_MIGRATIONS = {
    "control": (("step_no", "INTEGER"),),
    "cache": (("auth_step", "TEXT"),),
}


def _connect(db_path: str | None = None) -> sqlite3.Connection:
    path = db_path or DB_PATH
    conn = sqlite3.connect(path, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    for table, columns in _MIGRATIONS.items():
        existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        for name, decl in columns:
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")


def init_db(db_path: str | None = None) -> None:
    path = db_path or DB_PATH
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with _connect(path) as c:
        c.executescript(SCHEMA)
        _migrate(c)
        c.execute(
            "INSERT OR IGNORE INTO control"
            "(id, mode, ip, delay_seconds, step_no, updated_at)"
            " VALUES (1, 'a', ?, ?, NULL, ?)",
            (DEFAULT_IP, DEFAULT_DELAY, time.time()),
        )


# --------------------------------------------------------------------------
# control table (web / regression steps write, authoritative endpoint reads)
# --------------------------------------------------------------------------
def get_control(db_path: str | None = None) -> dict | None:
    with _connect(db_path) as c:
        row = c.execute("SELECT * FROM control WHERE id = 1").fetchone()
        return dict(row) if row else None


def set_control(mode: str, ip: str, delay_seconds: float,
                step_no: int | None = None, db_path: str | None = None) -> None:
    with _connect(db_path) as c:
        c.execute(
            "INSERT INTO control"
            "(id, mode, ip, delay_seconds, step_no, updated_at)"
            " VALUES (1, ?, ?, ?, ?, ?)"
            " ON CONFLICT(id) DO UPDATE SET"
            "   mode = excluded.mode, ip = excluded.ip,"
            "   delay_seconds = excluded.delay_seconds,"
            "   step_no = excluded.step_no, updated_at = excluded.updated_at",
            (mode, ip, float(delay_seconds), step_no, time.time()),
        )


# --------------------------------------------------------------------------
# cache table (resolver only)
# --------------------------------------------------------------------------
def _step_text(auth_step) -> str | None:
    if auth_step is None:
        return None
    text = str(auth_step).strip()
    return text or None


def get_cache(db_path: str | None = None) -> dict | None:
    with _connect(db_path) as c:
        row = c.execute("SELECT * FROM cache WHERE id = 1").fetchone()
        return dict(row) if row else None


def put_cache_a(ip: str, now: float, auth_step=None,
                db_path: str | None = None) -> None:
    """Store a freshly fetched A record: fresh for FRESH_TTL, then stale-usable
    for STALE_WINDOW more seconds.  Absolute epochs are persisted, so a restart
    does not extend either deadline.  ``auth_step`` records which authoritative
    setting produced the record and travels with the cache entry."""
    with _connect(db_path) as c:
        c.execute(
            "INSERT INTO cache(id, qname, rcode, a_record, auth_step, fetched_at,"
            "                 fresh_until, stale_until, nx_confirmed_at)"
            " VALUES (1, ?, 'NOERROR', ?, ?, ?, ?, ?, NULL)"
            " ON CONFLICT(id) DO UPDATE SET"
            "   qname = excluded.qname, rcode = 'NOERROR',"
            "   a_record = excluded.a_record, auth_step = excluded.auth_step,"
            "   fetched_at = excluded.fetched_at,"
            "   fresh_until = excluded.fresh_until,"
            "   stale_until = excluded.stale_until,"
            "   nx_confirmed_at = NULL",
            (FQDN, ip, _step_text(auth_step), now, now + FRESH_TTL,
             now + FRESH_TTL + STALE_WINDOW),
        )


def put_cache_nxdomain(now: float, auth_step=None,
                       db_path: str | None = None) -> None:
    """Confirm NXDOMAIN.  Any old A record is purged immediately and durably:
    from this moment no answer may contain the old A again, and NXDOMAIN itself
    is only cached fresh (never used as stale backup).  The setting step behind
    the NXDOMAIN is kept with the cache entry."""
    with _connect(db_path) as c:
        c.execute(
            "INSERT INTO cache(id, qname, rcode, a_record, auth_step, fetched_at,"
            "                 fresh_until, stale_until, nx_confirmed_at)"
            " VALUES (1, ?, 'NXDOMAIN', NULL, ?, ?, ?, NULL, ?)"
            " ON CONFLICT(id) DO UPDATE SET"
            "   qname = excluded.qname, rcode = 'NXDOMAIN', a_record = NULL,"
            "   auth_step = excluded.auth_step,"
            "   fetched_at = excluded.fetched_at,"
            "   fresh_until = excluded.fresh_until,"
            "   stale_until = NULL, nx_confirmed_at = excluded.nx_confirmed_at",
            (FQDN, _step_text(auth_step), now, now + FRESH_TTL, now),
        )


def reset_round_state(db_path: str | None = None) -> None:
    """Empty cache and logs.  Used when a round starts (it must begin from an
    empty cache) and after readiness probes that would otherwise pollute it."""
    with _connect(db_path) as c:
        c.execute("DELETE FROM cache WHERE id = 1")
        c.execute("DELETE FROM query_log")
        c.execute("DELETE FROM auth_log")


# --------------------------------------------------------------------------
# logs
# --------------------------------------------------------------------------
def _log(table: str, columns: tuple[str, ...], values: tuple,
         db_path: str | None = None) -> None:
    assert table in _LOG_TABLES
    cols = ", ".join(columns)
    marks = ", ".join("?" for _ in columns)
    with _connect(db_path) as c:
        c.execute(f"INSERT INTO {table}({cols}) VALUES ({marks})", values)
        c.execute(
            f"DELETE FROM {table} WHERE id NOT IN"
            f" (SELECT id FROM {table} ORDER BY id DESC LIMIT 300)"
        )


def log_query(qname, qtype, source, rcode, answers, detail,
              db_path: str | None = None) -> None:
    _log(
        "query_log",
        ("ts", "qname", "qtype", "source", "rcode", "answers", "detail"),
        (time.time(), qname, qtype, source, rcode, answers, detail),
        db_path,
    )


def log_auth(qname, qtype, mode, action, detail,
             db_path: str | None = None) -> None:
    _log(
        "auth_log",
        ("ts", "qname", "qtype", "mode", "action", "detail"),
        (time.time(), qname, qtype, mode, action, detail),
        db_path,
    )


def recent(table: str, limit: int = 15,
           db_path: str | None = None) -> list[dict]:
    assert table in _LOG_TABLES
    with _connect(db_path) as c:
        rows = c.execute(
            f"SELECT * FROM {table} ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
