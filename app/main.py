"""HTTP API — the source of truth. MCP is an adapter on top of this, never beside it.

Scoping rule enforced everywhere below: a caller only ever touches rows where it
is the sender or a recipient. A message it is not party to must be
indistinguishable from a message that does not exist — hence 404, not 403.
"""
# Hallmoot — a message bus for AI chats.
# Copyright (C) 2026 Maxime Olivier
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version. It is distributed WITHOUT ANY WARRANTY; see the license for
# details. You should have received a copy of the GNU AGPL along with this
# program. If not, see <https://www.gnu.org/licenses/>.
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import threading
import json
import logging
import sqlite3
from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import FileResponse, JSONResponse

from . import config, db, mcp, oauth, peering
from .ratelimit import TokenBucket
from .schemas import (EditIn, InlineBlobIn, InviteIn, RegisterIn, SendIn, SessionIn,
                      normalize_label)
from .security import Principal, hash_token, mint_token, require_chat, require_owner

_audit_log = logging.getLogger("hallmoot.audit")


def _audit(action: str, actor: str | None, **fields) -> None:
    """One structured line per state change: who did what, to which id.

    Never a body, never a subject, never a token. An audit trail that carries
    content becomes one more thing you have to protect — and the first place a
    secret leaks once someone ships the logs somewhere.
    """
    _audit_log.info(json.dumps({"action": action, "actor": actor or "owner", **fields},
                               ensure_ascii=False, default=str))


# ── helpers ────────────────────────────────────────────────────────────────


def _conn(request: Request) -> sqlite3.Connection:
    return request.app.state.conn


@contextlib.contextmanager
def _transaction(request: Request):
    """One writer at a time; commit or rollback, never half of either.

    Each request thread has its own connection (see `db.Pool`), so a reader is
    never caught inside someone else's transaction. Writers still need to be
    serialised: SQLite allows one at a time, and letting two race would only
    turn a short wait into a `database is locked`.
    """
    conn = request.app.state.conn
    with request.app.state.db_lock:
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise


def _touch(conn: sqlite3.Connection, principal: Principal) -> None:
    if principal.chat_id:
        conn.execute("UPDATE chats SET last_seen = ? WHERE id = ?",
                     (db.now_iso(), principal.chat_id))


def _limit(request: Request, principal: Principal, cost: float = 1.0) -> None:
    key = principal.chat_id or "owner"
    if not request.app.state.bucket.allow(key, cost):
        raise HTTPException(status_code=429, detail="rate limit exceeded, slow down")


def _resolve_address(conn: sqlite3.Connection, ident: str):
    """`bob`, `@bob`, a chat id, or any of those plus `/label` for one conversation.

    Returns (chat_row, session_row_or_None, error_or_None). An unknown label is
    an error, never a quiet fallback to the parent chat: a delivery that lands
    somewhere other than where it was addressed is the silent failure this
    project exists to avoid.
    """
    raw = (ident or "").strip().lstrip("@")
    if "@" in raw:
        # `bob@chez-alice` — someone else's instance. Resolving it here keeps
        # every address form going through one door.
        remote, alias = raw.rsplit("@", 1)
        peer = conn.execute("SELECT * FROM peers WHERE alias = ? AND state = 'active'",
                            (alias.strip().lower(),)).fetchone()
        if peer is None:
            return None, None, "unknown_peer"
        return peer, remote.strip().lstrip("@"), "peer"
    label = None
    if "/" in raw:
        raw, label = raw.split("/", 1)
    chat = conn.execute(
        "SELECT id, handle FROM chats WHERE revoked_at IS NULL AND (handle = ? OR id = ?)",
        (raw.strip().lower(), raw.strip()),
    ).fetchone()
    if chat is None:
        return None, None, "unknown_chat"
    if label is None:
        return chat, None, None
    session = conn.execute(
        "SELECT id, label FROM sessions WHERE chat_id = ? AND label = ? AND closed_at IS NULL",
        (chat["id"], label.strip().lower()),
    ).fetchone()
    if session is None:
        return chat, None, "unknown_session"
    return chat, session, None


def _address_of(handle: str, label: str | None) -> str:
    """The one place an address is rendered — so `from` is always something you
    can hand straight back to `to`."""
    return f"{handle}/{label}" if label else handle


def _visible_message(conn: sqlite3.Connection, message_id: str, chat_id: str) -> sqlite3.Row | None:
    """The one gate for reading a message: sender or recipient, nothing else."""
    return conn.execute(
        """
        SELECT m.* FROM messages m
        WHERE m.id = ? AND (
            m.from_chat_id = ?
            OR EXISTS (SELECT 1 FROM deliveries d
                       WHERE d.message_id = m.id AND d.to_chat_id = ?)
        )
        """,
        (message_id, chat_id, chat_id),
    ).fetchone()


def _remote_recipient(conn: sqlite3.Connection, m: sqlite3.Row) -> str | None:
    if not m["to_peer_id"]:
        return None
    peer = conn.execute("SELECT alias FROM peers WHERE id = ?", (m["to_peer_id"],)).fetchone()
    return f"{m['to_peer_handle']}@{peer['alias']}" if peer else m["to_peer_handle"]


def _recipients(conn: sqlite3.Connection, message_id: str) -> list[dict]:
    rows = conn.execute(
        """
        SELECT d.to_chat_id, c.handle, s.label AS session, d.status,
               d.delivered_at, d.read_at, d.archived_at
        FROM deliveries d
        JOIN chats c ON c.id = d.to_chat_id
        LEFT JOIN sessions s ON s.id = d.to_session_id
        WHERE d.message_id = ? ORDER BY c.handle
        """,
        (message_id,),
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["address"] = _address_of(d["handle"], d["session"])
        out.append(d)
    return out


def _bump_status(conn: sqlite3.Connection, message_id: str, to_chat_id: str, new: str) -> None:
    """Status ladder from the engine: never downgrade."""
    row = conn.execute(
        "SELECT status FROM deliveries WHERE message_id = ? AND to_chat_id = ?",
        (message_id, to_chat_id),
    ).fetchone()
    if row is None:
        return
    if db.STATUS_RANK.get(new, -1) > db.STATUS_RANK.get(row["status"], 0):
        conn.execute(
            "UPDATE deliveries SET status = ? WHERE message_id = ? AND to_chat_id = ?",
            (new, message_id, to_chat_id),
        )


def _emit(conn: sqlite3.Connection, chat_id: str, type_: str, message_id: str | None) -> None:
    conn.execute(
        "INSERT INTO events(chat_id, type, message_id, created_at) VALUES(?,?,?,?)",
        (chat_id, type_, message_id, db.now_iso()),
    )


def _sender_address(conn: sqlite3.Connection, m: sqlite3.Row) -> str | None:
    if m["from_peer_id"]:
        # Proven suffix, claimed prefix: the peer vouches for its own member,
        # and the address says so plainly.
        peer = conn.execute("SELECT alias FROM peers WHERE id = ?",
                            (m["from_peer_id"],)).fetchone()
        return f"{m['from_peer_sender']}@{peer['alias']}" if peer else m["from_peer_sender"]
    sender = conn.execute("SELECT handle FROM chats WHERE id = ?", (m["from_chat_id"],)).fetchone()
    if sender is None:
        return None
    label = None
    if m["from_session_id"]:
        row = conn.execute("SELECT label FROM sessions WHERE id = ?",
                           (m["from_session_id"],)).fetchone()
        label = row["label"] if row else None
    return _address_of(sender["handle"], label)


def _attachments(conn: sqlite3.Connection, message_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT id, filename, size, sha256, content_type FROM blobs WHERE attached_to = ?"
        " ORDER BY created_at", (message_id,)).fetchall()
    return [{"blob_id": r["id"], "filename": r["filename"], "size": r["size"],
             "sha256": r["sha256"], "declared_type": r["content_type"],
             "download": f"/v1/messages/{message_id}/attachments/{r['id']}"} for r in rows]


def _message_view(conn: sqlite3.Connection, m: sqlite3.Row, viewer: str) -> dict:
    view = {
        "id": m["id"],
        "thread_id": m["thread_id"],
        "from": _sender_address(conn, m),
        "from_chat_id": m["from_chat_id"],
        "to": ([_remote_recipient(conn, m)] if m["to_peer_id"]
               else [r["address"] for r in _recipients(conn, m["id"])]),
        "subject": m["subject"],
        "body": m["body"],
        "kind": m["kind"],
        "priority": m["priority"],
        "in_reply_to": m["in_reply_to"],
        "created_at": m["created_at"],
        "edited_at": m["edited_at"],
        "recalled": m["recalled_at"] is not None,
        "attachments": _attachments(conn, m["id"]),
    }
    if m["from_chat_id"] == viewer:
        view["deliveries"] = _recipients(conn, m["id"])
    return view


# ── app factory ────────────────────────────────────────────────────────────


def _drop_blob_files(conn: sqlite3.Connection, blob_dir: Path, shas: list[str]) -> int:
    """Remove stored bytes only once no row references them any more — the store
    is content-addressed, so two messages can legitimately share one file."""
    removed = 0
    for sha in set(shas):
        still_used = conn.execute("SELECT 1 FROM blobs WHERE sha256 = ? LIMIT 1", (sha,)).fetchone()
        if still_used:
            continue
        path = blob_dir / sha[:2] / sha
        if path.exists():
            path.unlink()
            removed += 1
    return removed


def _apply_retention(conn: sqlite3.Connection, blob_dir: Path, days: int,
                     orphan_hours: int) -> dict:
    """Forget what the owner asked to forget — and nothing else.

    Two very different things get cleaned here. Old messages go only when a
    retention window is configured, because deleting someone's mail without
    being asked is worse than a large database. Uploaded-but-never-sent bytes
    go on their own: nobody sees them in an inbox, so nobody will ever come
    looking for them.
    """
    from datetime import datetime, timedelta, timezone as _tz
    out = {"messages": 0, "attachments": 0, "files": 0, "orphan_blobs": 0}

    orphan_cutoff = (datetime.now(_tz.utc) - timedelta(hours=orphan_hours)).isoformat(
        timespec="seconds")
    orphans = conn.execute(
        "SELECT id, sha256 FROM blobs WHERE attached_to IS NULL AND created_at < ?",
        (orphan_cutoff,)).fetchall()
    if orphans:
        conn.execute("DELETE FROM blobs WHERE attached_to IS NULL AND created_at < ?",
                     (orphan_cutoff,))
        out["orphan_blobs"] = len(orphans)
        out["files"] += _drop_blob_files(conn, blob_dir, [o["sha256"] for o in orphans])

    if days > 0:
        cutoff = (datetime.now(_tz.utc) - timedelta(days=days)).isoformat(timespec="seconds")
        doomed = [r["id"] for r in conn.execute(
            "SELECT id FROM messages WHERE created_at < ?", (cutoff,)).fetchall()]
        if doomed:
            marks = ",".join("?" * len(doomed))
            shas = [r["sha256"] for r in conn.execute(
                f"SELECT sha256 FROM blobs WHERE attached_to IN ({marks})", doomed).fetchall()]
            out["attachments"] = conn.execute(
                f"DELETE FROM blobs WHERE attached_to IN ({marks})", doomed).rowcount
            conn.execute(f"DELETE FROM deliveries WHERE message_id IN ({marks})", doomed)
            conn.execute(f"DELETE FROM events WHERE message_id IN ({marks})", doomed)
            out["messages"] = conn.execute(
                f"DELETE FROM messages WHERE id IN ({marks})", doomed).rowcount
            out["files"] += _drop_blob_files(conn, blob_dir, shas)
    return out


def _gc(conn: sqlite3.Connection, purge_revoked: bool = False) -> dict:
    """Expired authorization codes and access tokens are useless weight — and
    weight in a credential table is what leaks the day someone dumps it."""
    now = db.now_iso()
    out = {
        "expired_codes": conn.execute(
            "DELETE FROM oauth_codes WHERE expires_at <= ?", (now,)).rowcount,
        "expired_access_tokens": conn.execute(
            "DELETE FROM oauth_tokens WHERE kind = 'access' AND expires_at <= ?", (now,)).rowcount,
    }
    if purge_revoked:
        # Mail addressed to a chat that no longer exists can never be read, so it
        # is pure ballast. A message it SENT is another matter: that copy belongs
        # to whoever received it, so only messages with no surviving recipient go.
        out["deliveries_to_revoked"] = conn.execute(
            "DELETE FROM deliveries WHERE to_chat_id IN"
            " (SELECT id FROM chats WHERE revoked_at IS NOT NULL)").rowcount
        out["orphaned_messages"] = conn.execute(
            "DELETE FROM messages WHERE from_chat_id IN"
            " (SELECT id FROM chats WHERE revoked_at IS NOT NULL)"
            " AND id NOT IN (SELECT message_id FROM deliveries)").rowcount
        out["orphaned_events"] = conn.execute(
            "DELETE FROM events WHERE chat_id IN"
            " (SELECT id FROM chats WHERE revoked_at IS NOT NULL)").rowcount
    return out


def _peer_tokens_path(data_dir: Path) -> Path:
    return data_dir / "peer-tokens.json"


def _load_peer_tokens(data_dir: Path) -> dict:
    """Tokens we present to our peers.

    They must stay usable, so they cannot be hashed like everything else. They
    live in one file, mode 600, beside the database — never in the database
    itself, so a dump of the message store carries no working credential.
    """
    path = _peer_tokens_path(data_dir)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def create_app(db_path: Path | str | None = None, owner_token: str | None = None) -> FastAPI:
    app = FastAPI(
        title=config.APP_NAME,
        version="0.1.0",
        summary="A message bus for AI chats: every chat gets an addressable identity.",
    )
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    db_file = Path(db_path) if db_path else config.DB_PATH
    conn = db.Pool(db_file)
    db.init(conn)
    app.state.conn = conn
    # Attachments live beside their database, whatever path that is. Deriving
    # this from a module-level default sent test uploads into the production
    # data directory — a file store that ignores its instance's configuration.
    app.state.blob_dir = db_file.parent / "blobs"
    app.state.owner_token = owner_token or config.owner_token()
    app.state.bucket = TokenBucket(config.RATE_LIMIT_PER_MIN)
    _gc(conn)  # every restart is a chance to stop carrying dead credentials
    _apply_retention(conn, app.state.blob_dir, config.RETENTION_DAYS,
                     config.ORPHAN_BLOB_HOURS)

    app.state.ip_bucket = TokenBucket(config.RATE_LIMIT_PER_IP_PER_MIN)
    app.state.audit = _audit
    app.state.db_lock = threading.RLock()   # see _transaction()
    # Outbound peer tokens live in memory only: they are usable secrets, and the
    # database keeps just their hash. A restart re-reads them from the owner's
    # file (data/peer-tokens.json, mode 600) — see peer_tokens_path.
    app.state.peer_tokens = _load_peer_tokens(db_file.parent)
    # A peer is a whole other instance: it gets its own ceiling so that one
    # misbehaving partner cannot drown us.
    app.state.peer_bucket = TokenBucket(config.PEER_RATE_LIMIT_PER_MIN)

    def _save_peer_tokens() -> None:
        path = _peer_tokens_path(db_file.parent)
        path.write_text(json.dumps(app.state.peer_tokens, indent=2))
        path.chmod(0o600)

    app.state.save_peer_tokens = _save_peer_tokens
    app.include_router(peering.build_router())
    app.include_router(oauth.build_router(lambda: app.state))

    @app.middleware("http")
    async def cap_body(request: Request, call_next):
        declared = request.headers.get("content-length")
        path = request.url.path
        if path == "/v1/blobs":
            ceiling = config.MAX_ATTACHMENT_BYTES          # real upload
        elif path == "/v1/blobs/inline" or path == "/mcp":
            # An attachment sent through a tool call arrives base64-encoded
            # inside the JSON body, so the request is a third larger than the
            # file. Applying the plain message ceiling here made attachments
            # over ~190 Ko impossible from a browser client — and it failed by
            # dropping the connection rather than saying why.
            ceiling = config.MAX_INLINE_ATTACHMENT_BYTES * 4 // 3 + 8192
        else:
            ceiling = config.MAX_BODY_BYTES
        if declared and declared.isdigit() and int(declared) > ceiling:
            return JSONResponse({"detail": "payload too large"}, status_code=413)

        # Per-IP ceiling, on top of the per-token one. Behind a tunnel the
        # address is the proxy's first hop, so this is a blunt instrument — it
        # is here to blunt scanners and floods, not to identify anyone.
        forwarded = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
        client_ip = forwarded or (request.client.host if request.client else "unknown")
        if request.url.path != "/healthz" and not request.app.state.ip_bucket.allow(client_ip):
            return JSONResponse({"detail": "rate limit exceeded, slow down"}, status_code=429)
        return await call_next(request)

    # ── health & identity ──────────────────────────────────────────────

    @app.get("/healthz", include_in_schema=False)
    def healthz():
        return {"status": "ok", "version": app.version}

    @app.post("/v1/register", status_code=201, tags=["identity"])
    def register(payload: RegisterIn, request: Request):
        """Trade a one-time invite code for a chat identity + its token.

        Registration is invite-only: reachability must never imply the right to
        join. The token is returned once and stored hashed.
        """
        c = _conn(request)
        if not request.app.state.bucket.allow("register", 1.0):
            raise HTTPException(status_code=429, detail="too many registrations, slow down")
        code_hash = hash_token(payload.invite_code)
        chat_id, token = db.uuid7(), mint_token()
        now = db.now_iso()
        with _transaction(request):
            inv = c.execute(
                "SELECT code_hash, used_at, expires_at FROM invites WHERE code_hash = ?",
                (code_hash,),
            ).fetchone()
            if inv is None or inv["used_at"] is not None or inv["expires_at"] <= now:
                raise HTTPException(status_code=403, detail="invalid, used or expired invite code")
            if c.execute("SELECT 1 FROM chats WHERE handle = ?", (payload.handle,)).fetchone():
                raise HTTPException(status_code=409, detail=f"handle @{payload.handle} is taken")
            c.execute(
                "INSERT INTO chats(id, handle, display_name, client, token_hash, created_at, last_seen)"
                " VALUES(?,?,?,?,?,?,?)",
                (chat_id, payload.handle, payload.display_name, payload.client,
                 hash_token(token), now, now),
            )
            c.execute("UPDATE invites SET used_at = ?, used_by = ? WHERE code_hash = ?",
                      (now, chat_id, code_hash))
        _audit("chat.registered", "invite", chat_id=chat_id, handle=payload.handle,
               client=payload.client)
        return {"chat_id": chat_id, "handle": payload.handle, "chat_token": token,
                "note": "store this token now — it is not recoverable"}

    @app.get("/v1/me", tags=["identity"])
    def me(request: Request, principal: Principal = Depends(require_chat)):
        c = _conn(request)
        _touch(c, principal)
        row = c.execute(
            "SELECT id, handle, display_name, client, created_at, last_seen FROM chats WHERE id = ?",
            (principal.chat_id,),
        ).fetchone()
        return dict(row)

    @app.get("/v1/directory", tags=["identity"])
    def directory(request: Request, principal: Principal = Depends(require_chat)):
        """The directory is the central primitive: you address a chat, not a box."""
        c = _conn(request)
        _touch(c, principal)
        rows = c.execute(
            "SELECT id, handle, display_name, client, last_seen FROM chats "
            "WHERE revoked_at IS NULL ORDER BY handle"
        ).fetchall()
        return {"count": len(rows), "chats": [dict(r) for r in rows]}

    # ── attachments ────────────────────────────────────────────────────

    @app.post("/v1/blobs", status_code=201, tags=["messages"])
    async def upload_blob(request: Request, principal: Principal = Depends(require_chat),
                          file: UploadFile = File(...)):
        """Upload one file, get a handle to attach to a message.

        Bytes land in content-addressed storage: the path is the sha256, never
        anything the client chose. A filename that reaches the filesystem is a
        path traversal waiting to happen — here it is display metadata only.
        """
        c = _conn(request)
        _limit(request, principal, 2.0)
        digest = hashlib.sha256()
        size = 0
        blob_dir = request.app.state.blob_dir
        blob_dir.mkdir(parents=True, exist_ok=True)
        tmp = blob_dir / f".upload-{db.uuid7()}"
        try:
            with tmp.open("wb") as out:
                while chunk := await file.read(1024 * 256):
                    size += len(chunk)
                    if size > config.MAX_ATTACHMENT_BYTES:
                        raise HTTPException(status_code=413, detail="attachment too large")
                    digest.update(chunk)
                    out.write(chunk)
            if size == 0:
                raise HTTPException(status_code=400, detail="empty file")
            sha = digest.hexdigest()
            final = blob_dir / sha[:2] / sha
            final.parent.mkdir(parents=True, exist_ok=True)
            if final.exists():
                tmp.unlink()          # same bytes already here: store once
            else:
                tmp.replace(final)
        finally:
            tmp.unlink(missing_ok=True)

        blob_id = db.uuid7()
        # The declared content type is a client's claim, so it is stored but
        # never trusted on the way out (see download).
        c.execute("INSERT INTO blobs(id, sha256, size, filename, content_type, uploaded_by,"
                  " created_at) VALUES(?,?,?,?,?,?,?)",
                  (blob_id, sha, size, Path(file.filename or "fichier").name[:120],
                   (file.content_type or "application/octet-stream")[:120],
                   principal.chat_id, db.now_iso()))
        _audit("blob.uploaded", principal.handle, blob_id=blob_id, bytes=size, sha256=sha[:12])
        return {"blob_id": blob_id, "sha256": sha, "size": size,
                "filename": Path(file.filename or "fichier").name[:120]}

    @app.post("/v1/blobs/inline", status_code=201, tags=["messages"])
    def upload_blob_inline(payload: InlineBlobIn, request: Request,
                           principal: Principal = Depends(require_chat)):
        """Same thing, base64 in JSON — the only shape a tool call can carry.

        An MCP client has no multipart; a model hands over bytes or nothing. The
        size ceiling is lower here on purpose: base64 in a tool call travels
        through a model's context, and that is not where megabytes belong.
        """
        import base64 as _b64
        c = _conn(request)
        _limit(request, principal, 2.0)
        try:
            data = _b64.b64decode(payload.content_base64, validate=True)
        except Exception:
            raise HTTPException(status_code=400, detail="content_base64 is not valid base64")
        if not data:
            raise HTTPException(status_code=400, detail="empty file")
        if len(data) > config.MAX_INLINE_ATTACHMENT_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"inline attachments are capped at "
                       f"{config.MAX_INLINE_ATTACHMENT_BYTES} bytes; upload via /v1/blobs")
        sha = hashlib.sha256(data).hexdigest()
        blob_dir = request.app.state.blob_dir
        final = blob_dir / sha[:2] / sha
        final.parent.mkdir(parents=True, exist_ok=True)
        if not final.exists():
            final.write_bytes(data)
        blob_id = db.uuid7()
        name = Path(payload.filename).name[:120] or "fichier"
        c.execute("INSERT INTO blobs(id, sha256, size, filename, content_type, uploaded_by,"
                  " created_at) VALUES(?,?,?,?,?,?,?)",
                  (blob_id, sha, len(data), name,
                   payload.content_type or "application/octet-stream",
                   principal.chat_id, db.now_iso()))
        _audit("blob.uploaded", principal.handle, blob_id=blob_id, bytes=len(data),
               sha256=sha[:12], via="inline")
        return {"blob_id": blob_id, "sha256": sha, "size": len(data), "filename": name}

    @app.get("/v1/messages/{message_id}/attachments/{blob_id}", tags=["messages"])
    def download_attachment(message_id: str, blob_id: str, request: Request,
                            principal: Principal = Depends(require_chat)):
        c = _conn(request)
        m = _visible_message(c, message_id, principal.chat_id)
        if m is None or (m["recalled_at"] and m["from_chat_id"] != principal.chat_id):
            raise HTTPException(status_code=404, detail="message not found")
        blob = c.execute("SELECT * FROM blobs WHERE id = ? AND attached_to = ?",
                         (blob_id, message_id)).fetchone()
        if blob is None:
            raise HTTPException(status_code=404, detail="attachment not found")
        path = request.app.state.blob_dir / blob["sha256"][:2] / blob["sha256"]
        if not path.exists():
            raise HTTPException(status_code=410, detail="attachment bytes are gone")
        # Never serve a client-declared type back as-is: a stored text/html is a
        # stored XSS. Everything leaves as an opaque download.
        return FileResponse(
            path, media_type="application/octet-stream", filename=blob["filename"],
            headers={"X-Content-Type-Options": "nosniff",
                     "Content-Security-Policy": "default-src 'none'"})

    @app.get("/v1/messages/{message_id}/attachments/{blob_id}/content", tags=["messages"])
    def read_attachment(message_id: str, blob_id: str, request: Request,
                        principal: Principal = Depends(require_chat)):
        """The attachment's content, in a shape a tool call can carry.

        The download route returns raw bytes over `/v1`, which a browser-based
        client never reaches: only `/mcp` is published. Without this, an
        attachment is visible and unreadable — which is not an attachment.
        """
        import base64 as _b64
        c = _conn(request)
        m = _visible_message(c, message_id, principal.chat_id)
        if m is None or (m["recalled_at"] and m["from_chat_id"] != principal.chat_id):
            raise HTTPException(status_code=404, detail="message not found")
        blob = c.execute("SELECT * FROM blobs WHERE id = ? AND attached_to = ?",
                         (blob_id, message_id)).fetchone()
        if blob is None:
            raise HTTPException(status_code=404, detail="attachment not found")
        if blob["size"] > config.MAX_INLINE_ATTACHMENT_BYTES:
            raise HTTPException(
                status_code=413,
                detail={"reason": "too_large_for_inline", "size": blob["size"],
                        "download": f"/v1/messages/{message_id}/attachments/{blob_id}"})
        path = request.app.state.blob_dir / blob["sha256"][:2] / blob["sha256"]
        if not path.exists():
            raise HTTPException(status_code=410, detail="attachment bytes are gone")
        data = path.read_bytes()
        try:
            # Text comes back as text — a model reading a note should not have to
            # decode base64 in its head.
            return {"filename": blob["filename"], "size": blob["size"],
                    "sha256": blob["sha256"], "encoding": "utf-8",
                    "content": data.decode("utf-8")}
        except UnicodeDecodeError:
            return {"filename": blob["filename"], "size": blob["size"],
                    "sha256": blob["sha256"], "encoding": "base64",
                    "content": _b64.b64encode(data).decode()}

    # ── sessions (sub-addressing) ──────────────────────────────────────

    @app.post("/v1/sessions", status_code=201, tags=["identity"])
    def open_session(payload: SessionIn, request: Request,
                     principal: Principal = Depends(require_chat)):
        """Declare a conversation inside this client, so it can be addressed.

        MCP hands the server no conversation identifier — the connector belongs
        to an account, not to a thread — so the client names its own. That makes
        the label *declarative*: the token proves which client is speaking, the
        label is what it claims about itself. Inside one owner's instance that
        is fine. It must never be mistaken for a verified identity across a
        future federation boundary.
        """
        c = _conn(request)
        _touch(c, principal)
        existing = c.execute(
            "SELECT id, label, display_name FROM sessions WHERE chat_id = ? AND label = ?",
            (principal.chat_id, payload.label)).fetchone()
        if existing:
            c.execute("UPDATE sessions SET closed_at = NULL, last_seen = ? WHERE id = ?",
                      (db.now_iso(), existing["id"]))
            return {"id": existing["id"], "label": existing["label"],
                    "address": f"{principal.handle}/{existing['label']}", "reopened": True}
        sid = db.uuid7()
        c.execute("INSERT INTO sessions(id, chat_id, label, display_name, created_at, last_seen)"
                  " VALUES(?,?,?,?,?,?)",
                  (sid, principal.chat_id, payload.label, payload.display_name,
                   db.now_iso(), db.now_iso()))
        _audit("session.opened", principal.handle, session=payload.label)
        return {"id": sid, "label": payload.label,
                "address": f"{principal.handle}/{payload.label}", "reopened": False}

    @app.get("/v1/sessions", tags=["identity"])
    def list_sessions(request: Request, principal: Principal = Depends(require_chat),
                      chat: str | None = Query(None, description="another chat's handle or id")):
        """Your sessions, or another chat's — the directory has to show what is
        addressable, otherwise nobody can write to a conversation."""
        c = _conn(request)
        target = principal.chat_id
        handle = principal.handle
        if chat:
            row, _, err = _resolve_address(c, chat)
            if err:
                raise HTTPException(status_code=404, detail="unknown chat")
            target, handle = row["id"], row["handle"]
        rows = c.execute(
            "SELECT id, label, display_name, created_at, last_seen FROM sessions"
            " WHERE chat_id = ? AND closed_at IS NULL ORDER BY last_seen DESC", (target,)
        ).fetchall()
        return {"chat": handle, "count": len(rows),
                "sessions": [{**dict(r), "address": f"{handle}/{r['label']}"} for r in rows]}

    @app.delete("/v1/sessions/{label}", tags=["identity"])
    def close_session(label: str, request: Request,
                      principal: Principal = Depends(require_chat)):
        """Close a session: it stops being addressable. Its mail stays in the
        chat's inbox — a closed conversation must not swallow messages."""
        c = _conn(request)
        cur = c.execute(
            "UPDATE sessions SET closed_at = ? WHERE chat_id = ? AND label = ? AND closed_at IS NULL",
            (db.now_iso(), principal.chat_id, normalize_label(label)))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="unknown or already closed session")
        _audit("session.closed", principal.handle, session=normalize_label(label))
        return {"label": normalize_label(label), "closed": True}

    # ── messages ───────────────────────────────────────────────────────

    @app.post("/v1/messages", status_code=201, tags=["messages"])
    def send(payload: SendIn, request: Request, principal: Principal = Depends(require_chat)):
        c = _conn(request)
        _limit(request, principal)
        _touch(c, principal)

        resolved, unknown, remote = [], [], []
        for ident in payload.to:
            chat, session, err = _resolve_address(c, ident)
            if err == "peer":
                remote.append((chat, session))       # (peer row, remote handle)
            elif err:
                unknown.append({"address": ident, "reason": err})
            else:
                resolved.append((chat, session))
        if unknown:
            raise HTTPException(status_code=400, detail={"unknown_recipients": unknown})
        if remote and resolved:
            raise HTTPException(
                status_code=400,
                detail="en v1, un message part soit chez toi, soit chez un pair, pas les deux")
        if len(remote) > 1:
            raise HTTPException(status_code=400,
                                detail="un seul destinataire distant par message en v1")
        if remote and payload.attachments:
            raise HTTPException(status_code=400,
                                detail="les pièces jointes ne traversent pas encore vers un pair")

        # Validate every attachment BEFORE writing anything. All-or-nothing is
        # the whole point: the forked engine kept only the last of several
        # attachments and still reported success.
        blobs = []
        if payload.attachments:
            if len(payload.attachments) > config.MAX_ATTACHMENTS_PER_MESSAGE:
                raise HTTPException(status_code=400, detail="too many attachments")
            bad = []
            for bid in payload.attachments:
                row = c.execute(
                    "SELECT id, filename, size, attached_to, uploaded_by FROM blobs WHERE id = ?",
                    (bid,)).fetchone()
                if row is None or row["uploaded_by"] != principal.chat_id:
                    bad.append({"blob_id": bid, "reason": "unknown_blob"})
                elif row["attached_to"]:
                    bad.append({"blob_id": bid, "reason": "already_attached"})
                else:
                    blobs.append(row)
            if len(set(payload.attachments)) != len(payload.attachments):
                bad.append({"blob_id": "*", "reason": "duplicate"})
            if bad:
                raise HTTPException(status_code=400, detail={"bad_attachments": bad})

        from_session_id = None
        if payload.as_session:
            row = c.execute(
                "SELECT id FROM sessions WHERE chat_id = ? AND label = ? AND closed_at IS NULL",
                (principal.chat_id, normalize_label(payload.as_session))).fetchone()
            if row is None:
                raise HTTPException(status_code=404,
                                    detail="unknown session — call session_open first")
            from_session_id = row["id"]
            c.execute("UPDATE sessions SET last_seen = ? WHERE id = ?",
                      (db.now_iso(), from_session_id))

        thread_id = None
        parent = None
        if payload.in_reply_to:
            parent = _visible_message(c, payload.in_reply_to, principal.chat_id)
            if parent is None:
                # Same 404 as a nonexistent id: replying is not a probing oracle.
                raise HTTPException(status_code=404, detail="in_reply_to not found")
            thread_id = parent["thread_id"]

        mid = db.uuid7()
        now = db.now_iso()

        if remote:
            peer, remote_handle = remote[0]
            sender_label = None
            if from_session_id:
                row = c.execute("SELECT label FROM sessions WHERE id = ?",
                                (from_session_id,)).fetchone()
                sender_label = row["label"] if row else None
            # Push first, record second: if the peer refuses, nothing here says
            # the message left. A local copy of an undelivered message is the
            # silent failure in its purest form.
            peering.deliver_to_peer(
                request, peer, _address_of(principal.handle, sender_label),
                remote_handle, payload.subject, payload.body, payload.in_reply_to)
            c.execute(
                "INSERT INTO messages(id, thread_id, from_chat_id, from_session_id, subject,"
                " body, kind, priority, in_reply_to, created_at, to_peer_id, to_peer_handle)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (mid, thread_id or mid, principal.chat_id, from_session_id, payload.subject,
                 payload.body, payload.kind, payload.priority, payload.in_reply_to, now,
                 peer["id"], remote_handle))
            _audit("peer.message_sent", principal.handle, message_id=mid,
                   to=f"{remote_handle}@{peer['alias']}", bytes=len(payload.body))
            return {"id": mid, "thread_id": thread_id or mid,
                    "delivered_to": [f"{remote_handle}@{peer['alias']}"], "attachments": []}

        with _transaction(request):
            c.execute(
                "INSERT INTO messages(id, thread_id, from_chat_id, from_session_id, subject,"
                " body, kind, priority, in_reply_to, created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (mid, thread_id or mid, principal.chat_id, from_session_id, payload.subject,
                 payload.body, payload.kind, payload.priority, payload.in_reply_to, now),
            )
            # Report exactly what was delivered: `bob`, `@bob` and bob's id are
            # one recipient, and a count that overstates deliveries is how a
            # silent drop hides: no delivery may fail without noise.
            seen: dict[tuple, str] = {}
            for chat, session in resolved:
                key = (chat["id"], session["id"] if session else None)
                if key in seen:
                    continue
                seen[key] = _address_of(chat["handle"], session["label"] if session else None)
                c.execute(
                    "INSERT INTO deliveries(message_id, to_chat_id, to_session_id, status,"
                    " delivered_at) VALUES(?,?,?,'delivered',?)",
                    (mid, chat["id"], session["id"] if session else None, now),
                )
                _emit(c, chat["id"], "message.received", mid)
            for blob in blobs:
                linked = c.execute(
                    "UPDATE blobs SET attached_to = ? WHERE id = ? AND attached_to IS NULL",
                    (mid, blob["id"])).rowcount
                if linked != 1:      # someone attached it in between: refuse the lot
                    raise HTTPException(status_code=409,
                                        detail={"bad_attachments": [
                                            {"blob_id": blob["id"], "reason": "already_attached"}]})
            if parent is not None:
                # The parent's sender learns their message was answered.
                _bump_status(c, parent["id"], principal.chat_id, "replied")
                _emit(c, parent["from_chat_id"], "message.replied", parent["id"])
        _audit("message.sent", principal.handle, message_id=mid,
               thread_id=thread_id or mid, to=sorted(seen.values()),
               kind=payload.kind, priority=payload.priority, bytes=len(payload.body),
               attachments=len(blobs))
        return {"id": mid, "thread_id": thread_id or mid,
                "delivered_to": sorted(seen.values()),
                "attachments": [{"blob_id": b["id"], "filename": b["filename"],
                                 "size": b["size"]} for b in blobs]}

    @app.get("/v1/messages", tags=["messages"])
    def list_messages(
        request: Request,
        principal: Principal = Depends(require_chat),
        box: str = Query("inbox", pattern="^(inbox|archive|sent)$"),
        session: str | None = Query(
            None, max_length=40,
            description="only mail addressed to this session of yours; omit to see everything"),
        limit: int = Query(config.DEFAULT_PAGE_SIZE, ge=1, le=config.MAX_PAGE_SIZE),
        before: str | None = Query(None, description="cursor: return messages older than this id"),
    ):
        c = _conn(request)
        _touch(c, principal)
        cursor_sql = " AND m.id < ?" if before else ""
        args: list = [principal.chat_id]
        if box == "sent":
            sql = ("SELECT m.* FROM messages m WHERE m.from_chat_id = ?" + cursor_sql
                   + " ORDER BY m.id DESC LIMIT ?")
        else:
            archived = "IS NOT NULL" if box == "archive" else "IS NULL"
            session_sql = ""
            if session:
                row = c.execute(
                    "SELECT id FROM sessions WHERE chat_id = ? AND label = ?",
                    (principal.chat_id, normalize_label(session))).fetchone()
                if row is None:
                    raise HTTPException(status_code=404, detail="unknown session")
                session_sql = f" AND d.to_session_id = '{row['id']}'"
            sql = ("SELECT m.*, d.status, d.read_at FROM messages m "
                   "JOIN deliveries d ON d.message_id = m.id "
                   f"WHERE d.to_chat_id = ? AND d.archived_at {archived} "
                   f"AND m.recalled_at IS NULL{session_sql}" + cursor_sql
                   + " ORDER BY m.id DESC LIMIT ?")
        if before:
            args.append(before)
        args.append(limit)
        rows = c.execute(sql, args).fetchall()
        items = []
        for m in rows:
            attached = _attachments(c, m["id"])
            item = {"id": m["id"], "thread_id": m["thread_id"],
                    "from": _sender_address(c, m),
                    "subject": m["subject"], "priority": m["priority"],
                    "kind": m["kind"], "created_at": m["created_at"],
                    "attachments": len(attached)}
            if box == "sent":
                item["deliveries"] = _recipients(c, m["id"])
            else:
                item["status"] = m["status"]
                item["to"] = [r["address"] for r in _recipients(c, m["id"])
                              if r["to_chat_id"] == principal.chat_id]
            items.append(item)
        return {"box": box, "count": len(items), "messages": items,
                "next_before": items[-1]["id"] if len(items) == limit else None}

    @app.get("/v1/messages/{message_id}", tags=["messages"])
    def read_message(message_id: str, request: Request,
                     principal: Principal = Depends(require_chat),
                     peek: bool = Query(False, description="read without marking as read")):
        c = _conn(request)
        _touch(c, principal)
        m = _visible_message(c, message_id, principal.chat_id)
        if m is None:
            raise HTTPException(status_code=404, detail="message not found")
        is_recipient = any(r["to_chat_id"] == principal.chat_id for r in _recipients(c, message_id))
        if m["recalled_at"] and m["from_chat_id"] != principal.chat_id:
            raise HTTPException(status_code=410, detail="message was recalled by its sender")
        if is_recipient and not peek:
            row = c.execute(
                "SELECT read_at FROM deliveries WHERE message_id = ? AND to_chat_id = ?",
                (message_id, principal.chat_id),
            ).fetchone()
            if row and row["read_at"] is None:
                c.execute(
                    "UPDATE deliveries SET read_at = ? WHERE message_id = ? AND to_chat_id = ?",
                    (db.now_iso(), message_id, principal.chat_id),
                )
                _bump_status(c, message_id, principal.chat_id, "read")
                if m["from_chat_id"]:
                    _emit(c, m["from_chat_id"], "message.read", message_id)
                # A message from a peer has no local sender to notify. Read
                # receipts stop at the boundary in v1 — announcing them across
                # it is a promise we have not built yet.
                _audit("message.read", principal.handle, message_id=message_id,
                       sender_chat_id=m["from_chat_id"] or None,
                       from_peer=bool(m["from_peer_id"]))
        return _message_view(c, m, principal.chat_id)

    @app.post("/v1/messages/{message_id}/archive", tags=["messages"])
    def archive(message_id: str, request: Request,
                principal: Principal = Depends(require_chat)):
        c = _conn(request)
        _touch(c, principal)
        cur = c.execute(
            "UPDATE deliveries SET archived_at = ? WHERE message_id = ? AND to_chat_id = ?"
            " AND archived_at IS NULL",
            (db.now_iso(), message_id, principal.chat_id),
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="no unarchived delivery for this message")
        return {"id": message_id, "archived": True}

    @app.get("/v1/messages/{message_id}/status", tags=["messages"])
    def message_status(message_id: str, request: Request,
                       principal: Principal = Depends(require_chat)):
        c = _conn(request)
        m = c.execute("SELECT * FROM messages WHERE id = ? AND from_chat_id = ?",
                      (message_id, principal.chat_id)).fetchone()
        if m is None:
            raise HTTPException(status_code=404, detail="message not found")
        return {"id": message_id, "recalled": m["recalled_at"] is not None,
                "edited_at": m["edited_at"], "deliveries": _recipients(c, message_id)}

    @app.delete("/v1/messages/{message_id}", tags=["messages"])
    def unsend(message_id: str, request: Request,
               principal: Principal = Depends(require_chat)):
        """Recall an unread message. Once read, it is gone from our hands."""
        c = _conn(request)
        _limit(request, principal)
        m = c.execute("SELECT * FROM messages WHERE id = ? AND from_chat_id = ?",
                      (message_id, principal.chat_id)).fetchone()
        if m is None:
            raise HTTPException(status_code=404, detail="message not found")
        if m["recalled_at"]:
            return {"id": message_id, "recalled": True, "already": True}
        read_by = [r["handle"] for r in _recipients(c, message_id) if r["read_at"]]
        if read_by:
            raise HTTPException(status_code=409,
                                detail={"reason": "already_read", "read_by": read_by})
        c.execute("UPDATE messages SET recalled_at = ? WHERE id = ?", (db.now_iso(), message_id))
        for r in _recipients(c, message_id):
            _emit(c, r["to_chat_id"], "message.recalled", message_id)
        _audit("message.recalled", principal.handle, message_id=message_id)
        return {"id": message_id, "recalled": True}

    @app.patch("/v1/messages/{message_id}", tags=["messages"])
    def edit(message_id: str, payload: EditIn, request: Request,
             principal: Principal = Depends(require_chat)):
        c = _conn(request)
        _limit(request, principal)
        m = c.execute("SELECT * FROM messages WHERE id = ? AND from_chat_id = ?",
                      (message_id, principal.chat_id)).fetchone()
        if m is None:
            raise HTTPException(status_code=404, detail="message not found")
        if m["recalled_at"]:
            raise HTTPException(status_code=409, detail={"reason": "recalled"})
        read_by = [r["handle"] for r in _recipients(c, message_id) if r["read_at"]]
        if read_by:
            raise HTTPException(status_code=409,
                                detail={"reason": "already_read", "read_by": read_by})
        c.execute("UPDATE messages SET body = ?, edited_at = ? WHERE id = ?",
                  (payload.body, db.now_iso(), message_id))
        for r in _recipients(c, message_id):
            _emit(c, r["to_chat_id"], "message.edited", message_id)
        _audit("message.edited", principal.handle, message_id=message_id,
               bytes=len(payload.body))
        return {"id": message_id, "edited": True}

    @app.get("/v1/threads/{thread_id}", tags=["messages"])
    def read_thread(thread_id: str, request: Request,
                    principal: Principal = Depends(require_chat)):
        """A thread is only ever the part of it the caller is party to."""
        c = _conn(request)
        rows = c.execute(
            """
            SELECT DISTINCT m.* FROM messages m
            LEFT JOIN deliveries d ON d.message_id = m.id
            WHERE m.thread_id = ?
              AND (m.from_chat_id = ? OR d.to_chat_id = ?)
              AND (m.recalled_at IS NULL OR m.from_chat_id = ?)
            ORDER BY m.id ASC
            """,
            (thread_id, principal.chat_id, principal.chat_id, principal.chat_id),
        ).fetchall()
        if not rows:
            raise HTTPException(status_code=404, detail="thread not found")
        return {"thread_id": thread_id, "count": len(rows),
                "messages": [_message_view(c, m, principal.chat_id) for m in rows]}

    @app.get("/v1/events", tags=["messages"])
    async def events(request: Request, principal: Principal = Depends(require_chat),
                     since: int = Query(0, ge=0),
                     timeout: float = Query(config.EVENTS_POLL_TIMEOUT, ge=0, le=60)):
        """Long-poll: 'anything new for me?'. MCP clients cannot be pushed to."""
        c = _conn(request)
        deadline = asyncio.get_event_loop().time() + timeout
        while True:
            rows = c.execute(
                "SELECT seq, type, message_id, created_at FROM events "
                "WHERE chat_id = ? AND seq > ? ORDER BY seq LIMIT 100",
                (principal.chat_id, since),
            ).fetchall()
            if rows or asyncio.get_event_loop().time() >= deadline:
                cursor = rows[-1]["seq"] if rows else since
                return {"cursor": cursor, "count": len(rows),
                        "events": [dict(r) for r in rows]}
            if await request.is_disconnected():
                return Response(status_code=499)
            await asyncio.sleep(0.4)

    # ── owner administration ───────────────────────────────────────────

    @app.post("/v1/admin/invites", status_code=201, tags=["admin"])
    def create_invite(payload: InviteIn, request: Request,
                      principal: Principal = Depends(require_owner)):
        from datetime import datetime, timedelta, timezone as _tz
        c = _conn(request)
        code = mint_token()
        expires = (datetime.now(_tz.utc)
                   + timedelta(seconds=config.INVITE_TTL_SECONDS)).isoformat(timespec="seconds")
        c.execute("INSERT INTO invites(code_hash, created_at, expires_at, note) VALUES(?,?,?,?)",
                  (hash_token(code), db.now_iso(), expires, payload.note))
        return {"invite_code": code, "expires_at": expires,
                "note": "single use — hand it over out of band, never in a log"}

    @app.get("/v1/admin/chats", tags=["admin"])
    def admin_chats(request: Request, principal: Principal = Depends(require_owner)):
        rows = _conn(request).execute(
            "SELECT id, handle, display_name, client, created_at, last_seen, revoked_at "
            "FROM chats ORDER BY created_at"
        ).fetchall()
        return {"count": len(rows), "chats": [dict(r) for r in rows]}

    @app.delete("/v1/admin/chats/{chat_id}", tags=["admin"])
    def revoke_chat(chat_id: str, request: Request,
                    principal: Principal = Depends(require_owner)):
        cur = _conn(request).execute(
            "UPDATE chats SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
            (db.now_iso(), chat_id),
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="unknown or already revoked chat")
        _audit("chat.revoked", "owner", chat_id=chat_id)
        return {"chat_id": chat_id, "revoked": True}

    @app.post("/v1/admin/chats/{chat_id}/rotate", tags=["admin"])
    def rotate_chat_token(chat_id: str, request: Request,
                          principal: Principal = Depends(require_owner)):
        """Issue a new token for a chat; the old one dies on the spot.

        A chat token ends up pasted in a client config, which ends up in a
        backup, a sync folder, a screenshot. Rotation has to be a 10-second
        operation, or nobody does it and the leaked token lives forever.
        """
        c = _conn(request)
        row = c.execute("SELECT handle FROM chats WHERE id = ? AND revoked_at IS NULL",
                        (chat_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="unknown or revoked chat")
        token = mint_token()
        c.execute("UPDATE chats SET token_hash = ? WHERE id = ?",
                  (hash_token(token), chat_id))
        _audit("chat.token_rotated", "owner", chat_id=chat_id, handle=row["handle"])
        return {"chat_id": chat_id, "handle": row["handle"], "chat_token": token,
                "note": "the previous token is already invalid"}

    @app.get("/v1/admin/oauth/clients", tags=["admin"])
    def admin_oauth_clients(request: Request, principal: Principal = Depends(require_owner)):
        """Which connectors hold live tokens, and for whom.

        Revoking a chat kills every client at once. When one connector goes bad
        — a laptop lost, an integration you no longer trust — you want to cut
        exactly that one and leave the others working.
        """
        rows = _conn(request).execute(
            """
            SELECT c.client_id, c.client_name, c.created_at,
                   ch.handle AS chat, COUNT(t.token_hash) AS live_tokens,
                   MAX(t.created_at) AS last_token
            FROM oauth_clients c
            LEFT JOIN oauth_tokens t
                   ON t.client_id = c.client_id AND t.revoked_at IS NULL
            LEFT JOIN chats ch ON ch.id = t.chat_id
            GROUP BY c.client_id ORDER BY c.created_at DESC
            """).fetchall()
        return {"count": len(rows), "clients": [dict(r) for r in rows]}

    @app.delete("/v1/admin/oauth/clients/{client_id}", tags=["admin"])
    def revoke_oauth_client(client_id: str, request: Request,
                            principal: Principal = Depends(require_owner)):
        c = _conn(request)
        if c.execute("SELECT 1 FROM oauth_clients WHERE client_id = ?",
                     (client_id,)).fetchone() is None:
            raise HTTPException(status_code=404, detail="unknown client")
        cur = c.execute(
            "UPDATE oauth_tokens SET revoked_at = ? WHERE client_id = ? AND revoked_at IS NULL",
            (db.now_iso(), client_id))
        c.execute("DELETE FROM oauth_codes WHERE client_id = ? AND used_at IS NULL", (client_id,))
        _audit("oauth.client_revoked", "owner", client_id=client_id, tokens=cur.rowcount)
        return {"client_id": client_id, "revoked_tokens": cur.rowcount}

    @app.get("/v1/admin/status", tags=["admin"])
    def admin_status(request: Request, principal: Principal = Depends(require_owner)):
        """What the owner needs to know without opening a database.

        Someone running their own instance has no dashboard, no alerting and no
        colleague to ask. If the only way to know whether the thing is healthy is
        to write SQL, they will not look — and the first sign of trouble will be
        a message that never arrived.
        """
        c = _conn(request)
        one = lambda sql, *a: c.execute(sql, a).fetchone()[0]  # noqa: E731
        by_status = {r["status"]: r["n"] for r in c.execute(
            "SELECT status, COUNT(*) AS n FROM deliveries GROUP BY status")}
        oldest = one("SELECT MIN(created_at) FROM messages") or None
        db_file = Path(config.DB_PATH)
        backups = sorted((db_file.parent / "backups").glob("hallmoot-*.sqlite3"), reverse=True)
        return {
            "version": app.version,
            "identities": {
                "chats": one("SELECT COUNT(*) FROM chats WHERE revoked_at IS NULL"),
                "revoked": one("SELECT COUNT(*) FROM chats WHERE revoked_at IS NOT NULL"),
                "sessions": one("SELECT COUNT(*) FROM sessions WHERE closed_at IS NULL"),
            },
            "traffic": {
                "messages": one("SELECT COUNT(*) FROM messages"),
                "recalled": one("SELECT COUNT(*) FROM messages WHERE recalled_at IS NOT NULL"),
                "deliveries_by_status": by_status,
                "unread": one("SELECT COUNT(*) FROM deliveries WHERE read_at IS NULL"),
                "oldest_message": oldest,
            },
            "credentials": {
                "oauth_clients": one("SELECT COUNT(*) FROM oauth_clients"),
                "live_access_tokens": one(
                    "SELECT COUNT(*) FROM oauth_tokens WHERE kind='access'"
                    " AND revoked_at IS NULL AND expires_at > ?", db.now_iso()),
                "oauth_enabled": bool(config.AUTH_PASSCODE),
                "public_url": config.PUBLIC_URL or None,
            },
            "storage": {
                "database_bytes": db_file.stat().st_size if db_file.exists() else 0,
                "attachment_bytes": one("SELECT COALESCE(SUM(size), 0) FROM blobs"),
                "attachments": one("SELECT COUNT(*) FROM blobs WHERE attached_to IS NOT NULL"),
                "backups": len(backups),
                "latest_backup": backups[0].name if backups else None,
            },
            "limits": {
                "per_token_per_min": config.RATE_LIMIT_PER_MIN,
                "per_ip_per_min": config.RATE_LIMIT_PER_IP_PER_MIN,
                "max_body_bytes": config.MAX_BODY_BYTES,
            },
        }

    @app.post("/v1/admin/gc", tags=["admin"])
    def garbage_collect(request: Request, principal: Principal = Depends(require_owner),
                        revoked: bool = Query(
                            False, description="also drop mail addressed to revoked chats")):
        """Drop what has already expired. Kept manual and auditable rather than
        silent: a credential store that quietly rewrites itself is hard to trust."""
        purged = _gc(_conn(request), purge_revoked=revoked)
        _audit("admin.gc", "owner", **purged)
        return {"purged": purged}

    @app.post("/v1/admin/retention", tags=["admin"])
    def apply_retention(request: Request, principal: Principal = Depends(require_owner),
                        days: int | None = Query(
                            None, ge=0, le=3650,
                            description="override the configured window, just for this run")):
        """Forget on demand. `days=0` still expires uploads nobody ever sent."""
        window = config.RETENTION_DAYS if days is None else days
        dropped = _apply_retention(_conn(request), request.app.state.blob_dir,
                                   window, config.ORPHAN_BLOB_HOURS)
        _audit("admin.retention", "owner", window_days=window, **dropped)
        return {"window_days": window, "dropped": dropped}

    # ── MCP over Streamable HTTP ───────────────────────────────────────
    # Bound to the route functions themselves, so an MCP caller travels the
    # exact same code path — and the same checks — as an HTTP caller.
    app.state.mcp_ops = mcp.build_ops({
        "me": me, "directory": directory, "send": send, "list_messages": list_messages,
        "open_session": open_session, "list_sessions": list_sessions,
        "upload_blob_inline": upload_blob_inline, "read_attachment": read_attachment,
        "read_message": read_message, "archive": archive, "message_status": message_status,
        "unsend": unsend, "edit": edit, "read_thread": read_thread, "events": events,
    })

    @app.post("/mcp", include_in_schema=False)
    async def mcp_endpoint(body: dict, request: Request,
                           principal: Principal = Depends(require_chat)):
        response = await mcp.dispatch(
            body, request, principal,
            {"name": config.APP_NAME, "version": app.version})
        # A notification carries no id and expects no answer.
        return Response(status_code=202) if response is None else response

    @app.get("/mcp", include_in_schema=False)
    def mcp_stream(principal: Principal = Depends(require_chat)):
        # No server-initiated stream in Phase 1: clients poll wait_for_message.
        raise HTTPException(status_code=405, detail="server-initiated streams not supported")

    return app
