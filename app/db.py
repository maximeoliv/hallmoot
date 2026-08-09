"""SQLite storage.

Why SQLite and not the file-per-transfer layout of the engine this model was
forked from: we need atomic writes, real scoping predicates
(every read is filtered by the caller's chat id) and migrations. Directory scans
that reach across mailboxes are exactly the primitive a product must not have.
"""
from __future__ import annotations

import os
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import config

SCHEMA_VERSION = 6

# The messages table is named once and reused: the migration that relaxes
# from_chat_id has to recreate it, and two copies of a definition drift.
MESSAGES_COLUMNS = """(
    id               TEXT PRIMARY KEY,
    thread_id        TEXT NOT NULL,
    from_chat_id     TEXT REFERENCES chats(id),
    from_session_id  TEXT,
    from_peer_id     TEXT,
    from_peer_sender TEXT,
    to_peer_id       TEXT,
    to_peer_handle   TEXT,
    subject          TEXT NOT NULL,
    body             TEXT NOT NULL,
    kind             TEXT NOT NULL DEFAULT 'message',
    priority         TEXT NOT NULL DEFAULT 'normal',
    in_reply_to      TEXT,
    created_at       TEXT NOT NULL,
    edited_at        TEXT,
    recalled_at      TEXT
)"""

SCHEMA = """
CREATE TABLE IF NOT EXISTS chats (
    id           TEXT PRIMARY KEY,
    handle       TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    client       TEXT,
    token_hash   TEXT NOT NULL UNIQUE,
    created_at   TEXT NOT NULL,
    last_seen    TEXT,
    revoked_at   TEXT
);

CREATE TABLE IF NOT EXISTS invites (
    code_hash  TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at    TEXT,
    used_by    TEXT,
    note       TEXT
);

""" + "CREATE TABLE IF NOT EXISTS messages " + MESSAGES_COLUMNS + """;
CREATE INDEX IF NOT EXISTS idx_messages_thread ON messages(thread_id);
CREATE INDEX IF NOT EXISTS idx_messages_from   ON messages(from_chat_id, id);

-- One row per (message, recipient). This is what makes scoping a predicate
-- instead of a convention: a chat only ever sees rows where it is the party.
CREATE TABLE IF NOT EXISTS deliveries (
    message_id   TEXT NOT NULL REFERENCES messages(id),
    to_chat_id   TEXT NOT NULL REFERENCES chats(id),
    status       TEXT NOT NULL DEFAULT 'delivered',
    delivered_at TEXT NOT NULL,
    read_at      TEXT,
    archived_at  TEXT,
    PRIMARY KEY (message_id, to_chat_id)
);
CREATE INDEX IF NOT EXISTS idx_deliveries_to ON deliveries(to_chat_id, message_id);

CREATE TABLE IF NOT EXISTS events (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id    TEXT NOT NULL,
    type       TEXT NOT NULL,
    message_id TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_chat ON events(chat_id, seq);

-- OAuth 2.1 (authorization code + PKCE), required by browser-based MCP clients:
-- they cannot carry a static bearer, so the instance must issue tokens itself.
CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id     TEXT PRIMARY KEY,
    client_name   TEXT,
    redirect_uris TEXT NOT NULL,          -- JSON array, matched exactly
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_codes (
    code_hash      TEXT PRIMARY KEY,
    client_id      TEXT NOT NULL,
    chat_id        TEXT NOT NULL,
    redirect_uri   TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    expires_at     TEXT NOT NULL,
    used_at        TEXT
);

CREATE TABLE IF NOT EXISTS oauth_tokens (
    token_hash TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,             -- access | refresh
    client_id  TEXT NOT NULL,
    chat_id    TEXT NOT NULL REFERENCES chats(id),
    expires_at TEXT,
    revoked_at TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_chat ON oauth_tokens(chat_id);

-- A session is one conversation inside a client. MCP never tells the server
-- which conversation is talking — the connector is bound to an account, not to
-- a thread — so a client declares its own session and the label rides along as
-- a sub-address: @cowork/planning.
--
-- Load-bearing decision: a session is a LABEL ON A DELIVERY, never a separate
-- mailbox. The parent chat always sees everything addressed to its sessions.
-- The engine this project forked lost a message exactly this way: an alias that
-- resolved to a directory no scanner ever read. Here that box cannot exist.
CREATE TABLE IF NOT EXISTS sessions (
    id           TEXT PRIMARY KEY,
    chat_id      TEXT NOT NULL REFERENCES chats(id),
    label        TEXT NOT NULL,
    display_name TEXT,
    created_at   TEXT NOT NULL,
    last_seen    TEXT,
    closed_at    TEXT,
    UNIQUE(chat_id, label)
);
CREATE INDEX IF NOT EXISTS idx_sessions_chat ON sessions(chat_id);

-- Attachments. Two rules shape this table:
--
-- 1. Bytes are stored content-addressed (sha256), never under a client-supplied
--    name. A filename that reaches the filesystem is a path traversal waiting
--    to happen; here it is display metadata and nothing else.
-- 2. Upload and send are separate steps, but attaching is all-or-nothing: the
--    forked engine silently dropped all but the last of several attachments,
--    and the sender saw a success. N sent must mean exactly N received.
CREATE TABLE IF NOT EXISTS blobs (
    id            TEXT PRIMARY KEY,
    sha256        TEXT NOT NULL,
    size          INTEGER NOT NULL,
    filename      TEXT NOT NULL,
    content_type  TEXT NOT NULL,
    uploaded_by   TEXT NOT NULL REFERENCES chats(id),
    created_at    TEXT NOT NULL,
    attached_to   TEXT
);
CREATE INDEX IF NOT EXISTS idx_blobs_owner ON blobs(uploaded_by);
CREATE INDEX IF NOT EXISTS idx_blobs_message ON blobs(attached_to);

-- Peering: two instances that agreed to talk. Everything here is per-peer and
-- revocable from either side; nothing is discoverable and nothing is exposed by
-- default (see PEERING.md).
CREATE TABLE IF NOT EXISTS peers (
    id            TEXT PRIMARY KEY,
    alias         TEXT NOT NULL UNIQUE,      -- local nickname: @bob@<alias>
    base_url      TEXT NOT NULL,             -- where we push to
    outbound_hash TEXT,                      -- token WE present to them
    inbound_hash  TEXT UNIQUE,               -- token THEY present to us
    state         TEXT NOT NULL,             -- invited | active | revoked
    created_at    TEXT NOT NULL,
    last_seen     TEXT,
    revoked_at    TEXT
);

-- One row per chat we let a given peer address. Empty table = a brand-new
-- pairing that lets nothing through, which is the point.
CREATE TABLE IF NOT EXISTS peer_exposures (
    peer_id    TEXT NOT NULL REFERENCES peers(id),
    chat_id    TEXT NOT NULL REFERENCES chats(id),
    created_at TEXT NOT NULL,
    PRIMARY KEY (peer_id, chat_id)
);

-- Pairing invitations: single use, short-lived, hashed like every other secret.
CREATE TABLE IF NOT EXISTS peer_invites (
    code_hash  TEXT PRIMARY KEY,
    alias      TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at    TEXT,
    peer_id    TEXT
);

CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""

# Status ladder, ported from the engine: a status never goes backwards.
STATUS_RANK = {"delivered": 0, "read": 1, "replied": 2, "closed": 3}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def uuid7() -> str:
    """RFC 9562 UUIDv7 — 48-bit ms timestamp + random. Sortable by creation
    time, collision-proof. Same scheme as the engine (stdlib has no v7 < 3.13).
    """
    ms = int(time.time() * 1000)
    rand_a = int.from_bytes(os.urandom(2), "big") & 0x0FFF
    rand_b = int.from_bytes(os.urandom(8), "big") & 0x3FFFFFFFFFFFFFFF
    raw = (
        ms.to_bytes(6, "big")
        + (0x7000 | rand_a).to_bytes(2, "big")
        + (0x8000000000000000 | rand_b).to_bytes(8, "big")
    )
    return str(uuid.UUID(bytes=raw))


def connect(path: Path | None = None) -> sqlite3.Connection:
    p = Path(path or config.DB_PATH)
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(p, check_same_thread=False, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _add_column(conn, table: str, column: str, decl: str) -> None:
    have = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
    if column not in have:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")


def _relax_message_sender(conn) -> None:
    """Drop the NOT NULL on messages.from_chat_id, rebuilding if needed.

    Peer messages have no local sender. SQLite cannot relax a constraint in
    place, so an existing database is copied through a new table — with foreign
    keys off for the swap and everything inside one transaction, so a crash
    mid-migration leaves the old table intact.
    """
    cols = {r["name"]: r for r in conn.execute("PRAGMA table_info(messages)")}
    if not cols.get("from_chat_id") or cols["from_chat_id"]["notnull"] == 0:
        return
    shared = ", ".join(cols)
    conn.execute("PRAGMA foreign_keys=OFF")
    try:
        conn.execute("BEGIN IMMEDIATE")
        # Plain execute, not executescript: the latter commits the transaction
        # out from under us, which is how a migration ends up half-applied.
        conn.execute("CREATE TABLE messages_rebuilt " + MESSAGES_COLUMNS)
        conn.execute(f"INSERT INTO messages_rebuilt ({shared}) SELECT {shared} FROM messages")
        conn.execute("DROP TABLE messages")
        conn.execute("ALTER TABLE messages_rebuilt RENAME TO messages")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_thread ON messages(thread_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_from ON messages(from_chat_id, id)")
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.execute("PRAGMA foreign_keys=ON")


class Pool:
    """One SQLite connection per thread, behind the interface of a single one.

    A connection object is not a thread-safe workspace: cursors opened on it by
    different threads interleave, and a transaction one thread opens is visible
    to another thread's reads on the same handle. Sharing one connection across
    a request thread pool produced, under load, both 500s and — worse — reads
    that missed rows that were certainly there, so a message was refused for an
    unknown recipient that existed. Python 3.12 surfaces it readily; 3.10 hid it
    most of the time, which is the more dangerous failure of the two.

    WAL is what makes the fix cheap: readers do not block the writer, and the
    writer is serialised by the transaction lock anyway.
    """

    def __init__(self, path: Path):
        self._path = Path(path)
        self._local = threading.local()

    @property
    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = connect(self._path)
            self._local.conn = conn
        return conn

    def execute(self, *args, **kwargs):
        return self._conn.execute(*args, **kwargs)

    def executescript(self, *args, **kwargs):
        return self._conn.executescript(*args, **kwargs)

    def cursor(self):
        return self._conn.cursor()


def init(conn) -> None:
    conn.executescript(SCHEMA)
    # Sub-addressing arrived after the first databases existed; add its columns
    # in place rather than asking anyone to start over.
    _relax_message_sender(conn)
    _add_column(conn, "messages", "from_session_id", "TEXT")
    _add_column(conn, "deliveries", "to_session_id", "TEXT")
    # Messages that arrived from a peer: the sender is the peer's claim about
    # one of its own members, so it is stored as text and never resolved to a
    # local chat id.
    _add_column(conn, "messages", "from_peer_id", "TEXT")
    _add_column(conn, "messages", "from_peer_sender", "TEXT")
    # Outbound to a peer: there is no local delivery row to point at, so the
    # target is recorded on the message itself.
    _add_column(conn, "messages", "to_peer_id", "TEXT")
    _add_column(conn, "messages", "to_peer_handle", "TEXT")
    conn.execute(
        "INSERT INTO meta(key, value) VALUES('schema_version', ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(SCHEMA_VERSION),),
    )
