"""Peering — the only code in this project that trusts something outside itself.

Everything else here answers to one owner. This module lets a second instance,
run by somebody else, put messages in front of our chats. That changes what
"authenticated" can possibly mean, and the honest framing is worth stating in
code rather than hiding behind a schema:

    We authenticate the **instance**, never its members. When a peer hands us a
    message "from bob", it is that peer asserting who spoke on its side. The
    suffix of `bob@their-alias` is proven; the prefix is their claim.

A dishonest peer can therefore lie about its own members. It cannot impersonate
another peer, cannot impersonate anyone local, and cannot reach a chat we have
not explicitly exposed to it. That is the boundary, and it is drawn on purpose.
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

import json
import sqlite3
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request

from . import config, db
from .schemas import Strict
from .security import Principal, hash_token, mint_token, require_owner

from pydantic import Field


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


class PeerInviteIn(Strict):
    alias: str = Field(min_length=2, max_length=40,
                       description="local nickname for the peer you are inviting")


class PeerAcceptIn(Strict):
    alias: str = Field(min_length=2, max_length=40)
    base_url: str = Field(min_length=8, max_length=300)
    invite_code: str = Field(min_length=8, max_length=128)


class PeerExposeIn(Strict):
    chat: str = Field(min_length=1, max_length=64, description="handle or id of your chat")


class HandshakeIn(Strict):
    invite_code: str = Field(min_length=8, max_length=128)
    base_url: str = Field(min_length=8, max_length=300)
    inbound_token: str = Field(min_length=16, max_length=200)


class PeerMessageIn(Strict):
    from_sender: str = Field(min_length=1, max_length=80)
    to: str = Field(min_length=1, max_length=64)
    subject: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=64 * 1024)
    thread_ref: str | None = Field(default=None, max_length=64)


def normalize_alias(raw: str) -> str:
    alias = (raw or "").strip().lstrip("@").lower()
    if not alias.replace("-", "").replace("_", "").isalnum():
        raise HTTPException(status_code=422, detail="alias: lettres, chiffres, - et _ seulement")
    return alias


def authenticate_peer(request: Request) -> sqlite3.Row:
    """A peer proves itself with the token we issued to it. Nothing else."""
    header = request.headers.get("authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
    if not token:
        raise HTTPException(status_code=401, detail="peer token required")
    row = request.app.state.conn.execute(
        "SELECT * FROM peers WHERE inbound_hash = ?", (hash_token(token),)).fetchone()
    if row is None or row["state"] != "active":
        raise HTTPException(status_code=401, detail="unknown or revoked peer")
    return row


def build_router() -> APIRouter:
    router = APIRouter()

    def conn_of(request: Request) -> sqlite3.Connection:
        return request.app.state.conn

    # ── owner side: invite, accept, expose, revoke ─────────────────────

    @router.post("/v1/admin/peers/invite", status_code=201, tags=["peering"])
    def invite_peer(payload: PeerInviteIn, request: Request,
                    principal: Principal = Depends(require_owner)):
        """Mint an invitation to hand over out of band.

        Pairing starts with a human deciding to trust another human. There is no
        discovery, no request-to-pair, nothing an unknown instance can initiate.
        """
        c = conn_of(request)
        alias = normalize_alias(payload.alias)
        code = mint_token()
        c.execute("INSERT INTO peer_invites(code_hash, alias, created_at, expires_at)"
                  " VALUES(?,?,?,?)",
                  (hash_token(code), alias, db.now_iso(),
                   _iso(_now() + timedelta(seconds=config.PEER_INVITE_TTL_SECONDS))))
        request.app.state.audit("peer.invited", "owner", alias=alias)
        return {"alias": alias, "invite_code": code,
                "base_url": config.PUBLIC_URL or None,
                "note": "à transmettre hors bande, usage unique"}

    @router.post("/v1/admin/peers/accept", status_code=201, tags=["peering"])
    def accept_peer(payload: PeerAcceptIn, request: Request,
                    principal: Principal = Depends(require_owner)):
        """Redeem someone's invitation: we call them, we swap tokens, we are paired.

        We generate the token they will use to reach us and send it in the
        handshake; they answer with theirs. Two distinct secrets, so revoking on
        our side never depends on their cooperation.
        """
        c = conn_of(request)
        alias = normalize_alias(payload.alias)
        base_url = payload.base_url.rstrip("/")
        local = (base_url.startswith("http://127.0.0.1")
                 or base_url.startswith("http://localhost"))
        if not base_url.startswith("https://") and not local \
                and not config.ALLOW_INSECURE_PEERS:
            raise HTTPException(
                status_code=400,
                detail="peer base_url must be https; set MOOT_ALLOW_INSECURE_PEERS=1 only for "
                       "a rehearsal on a machine you control")
        if c.execute("SELECT 1 FROM peers WHERE alias = ? AND state != 'revoked'",
                     (alias,)).fetchone():
            raise HTTPException(status_code=409, detail=f"alias @{alias} already used")

        inbound = mint_token()
        try:
            answer = _post(f"{base_url}/v1/peer/handshake", {
                "invite_code": payload.invite_code,
                "base_url": config.PUBLIC_URL or "",
                "inbound_token": inbound})
        except PeerUnreachable as e:
            raise HTTPException(status_code=502, detail=f"peer unreachable: {e}")
        outbound = answer.get("inbound_token")
        if not outbound:
            raise HTTPException(status_code=502, detail="peer did not return a token")

        peer_id = db.uuid7()
        c.execute("INSERT INTO peers(id, alias, base_url, outbound_hash, inbound_hash, state,"
                  " created_at) VALUES(?,?,?,?,?,'active',?)",
                  (peer_id, alias, base_url, hash_token(outbound), hash_token(inbound),
                   db.now_iso()))
        # We keep the outbound token in the clear nowhere: store it hashed for
        # recognition, and keep the usable copy in a file only the owner reads.
        request.app.state.peer_tokens[peer_id] = outbound
        request.app.state.save_peer_tokens()
        request.app.state.audit("peer.paired", "owner", alias=alias, peer_id=peer_id)
        return {"peer_id": peer_id, "alias": alias, "state": "active",
                "note": "aucun chat n'est exposé pour l'instant — ajoute-les explicitement"}

    @router.get("/v1/admin/peers", tags=["peering"])
    def list_peers(request: Request, principal: Principal = Depends(require_owner)):
        c = conn_of(request)
        rows = c.execute("SELECT id, alias, base_url, state, created_at, last_seen, revoked_at"
                         " FROM peers ORDER BY created_at").fetchall()
        out = []
        for r in rows:
            exposed = [x["handle"] for x in c.execute(
                "SELECT ch.handle FROM peer_exposures e JOIN chats ch ON ch.id = e.chat_id"
                " WHERE e.peer_id = ? ORDER BY ch.handle", (r["id"],)).fetchall()]
            out.append({**dict(r), "exposed_chats": exposed})
        # Pending invitations belong in this view: you invited someone, they
        # have not answered yet, and nothing else would show that you did.
        pending = [dict(r) for r in c.execute(
            "SELECT alias, created_at, expires_at FROM peer_invites"
            " WHERE used_at IS NULL AND expires_at > ? ORDER BY created_at",
            (db.now_iso(),)).fetchall()]
        return {"count": len(out), "peers": out, "pending_invites": pending}

    @router.post("/v1/admin/peers/{alias}/expose", tags=["peering"])
    def expose_chat(alias: str, payload: PeerExposeIn, request: Request,
                    principal: Principal = Depends(require_owner)):
        """Make one of our chats addressable by this peer. Nothing is exposed
        until this is called — a fresh pairing lets nothing through."""
        c = conn_of(request)
        peer = _peer_or_404(c, alias)
        key = payload.chat.strip().lstrip("@").lower()
        chat = c.execute("SELECT id, handle FROM chats WHERE revoked_at IS NULL"
                         " AND (handle = ? OR id = ?)", (key, payload.chat.strip())).fetchone()
        if chat is None:
            raise HTTPException(status_code=404, detail="unknown chat")
        c.execute("INSERT OR IGNORE INTO peer_exposures(peer_id, chat_id, created_at)"
                  " VALUES(?,?,?)", (peer["id"], chat["id"], db.now_iso()))
        request.app.state.audit("peer.chat_exposed", "owner", alias=peer["alias"],
                                chat=chat["handle"])
        return {"alias": peer["alias"], "chat": chat["handle"], "exposed": True}

    @router.delete("/v1/admin/peers/{alias}/expose/{chat}", tags=["peering"])
    def unexpose_chat(alias: str, chat: str, request: Request,
                      principal: Principal = Depends(require_owner)):
        c = conn_of(request)
        peer = _peer_or_404(c, alias)
        row = c.execute("SELECT id FROM chats WHERE handle = ? OR id = ?",
                        (chat.strip().lstrip("@").lower(), chat.strip())).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="unknown chat")
        cur = c.execute("DELETE FROM peer_exposures WHERE peer_id = ? AND chat_id = ?",
                        (peer["id"], row["id"]))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="that chat was not exposed")
        request.app.state.audit("peer.chat_hidden", "owner", alias=peer["alias"], chat=chat)
        return {"alias": peer["alias"], "chat": chat, "exposed": False}

    @router.delete("/v1/admin/peers/{alias}", tags=["peering"])
    def revoke_peer(alias: str, request: Request,
                    principal: Principal = Depends(require_owner)):
        """Cut a peer, alone, immediately. Mail already received stays: it
        belongs to whoever received it."""
        c = conn_of(request)
        peer = _peer_or_404(c, alias)
        c.execute("UPDATE peers SET state = 'revoked', revoked_at = ?, inbound_hash = NULL,"
                  " outbound_hash = NULL WHERE id = ?", (db.now_iso(), peer["id"]))
        c.execute("DELETE FROM peer_exposures WHERE peer_id = ?", (peer["id"],))
        request.app.state.peer_tokens.pop(peer["id"], None)
        request.app.state.save_peer_tokens()
        request.app.state.audit("peer.revoked", "owner", alias=peer["alias"])
        return {"alias": peer["alias"], "revoked": True}

    # ── peer side: handshake ───────────────────────────────────────────

    @router.post("/v1/peer/handshake", status_code=201, tags=["peering"],
                 include_in_schema=False)
    def handshake(payload: HandshakeIn, request: Request):
        """The other instance presents our invitation and its token; we answer
        with ours. The invitation is single use — a replayed handshake pairs
        nothing."""
        c = conn_of(request)
        code_hash = hash_token(payload.invite_code)
        with request.app.state.db_lock:
            inv = c.execute("SELECT * FROM peer_invites WHERE code_hash = ?",
                            (code_hash,)).fetchone()
            if inv is None or inv["used_at"] or inv["expires_at"] <= db.now_iso():
                raise HTTPException(status_code=403, detail="invalid, used or expired invitation")
            inbound = mint_token()
            peer_id = db.uuid7()
            c.execute("INSERT INTO peers(id, alias, base_url, outbound_hash, inbound_hash,"
                      " state, created_at) VALUES(?,?,?,?,?,'active',?)",
                      (peer_id, inv["alias"], payload.base_url.rstrip("/"),
                       hash_token(payload.inbound_token), hash_token(inbound), db.now_iso()))
            c.execute("UPDATE peer_invites SET used_at = ?, peer_id = ? WHERE code_hash = ?",
                      (db.now_iso(), peer_id, code_hash))
        request.app.state.peer_tokens[peer_id] = payload.inbound_token
        request.app.state.save_peer_tokens()
        request.app.state.audit("peer.paired", "owner", alias=inv["alias"], peer_id=peer_id,
                                via="handshake")
        return {"alias": inv["alias"], "inbound_token": inbound}

    # ── peer side: receiving mail ──────────────────────────────────────

    @router.post("/v1/peer/inbox", status_code=201, tags=["peering"],
                 include_in_schema=False)
    def peer_inbox(payload: PeerMessageIn, request: Request):
        """A paired instance delivers a message to one of our exposed chats."""
        c = conn_of(request)
        peer = authenticate_peer(request)
        if not request.app.state.peer_bucket.allow(peer["id"]):
            raise HTTPException(status_code=429, detail="peer rate limit exceeded")

        target = payload.to.strip().lstrip("@").lower()
        chat = c.execute(
            """
            SELECT ch.id, ch.handle FROM chats ch
            JOIN peer_exposures e ON e.chat_id = ch.id
            WHERE e.peer_id = ? AND ch.revoked_at IS NULL AND ch.handle = ?
            """, (peer["id"], target)).fetchone()
        if chat is None:
            # Same answer whether the chat does not exist or was never exposed:
            # a peer must not be able to map who lives here by trying names.
            raise HTTPException(status_code=404, detail="unknown recipient")

        sender = payload.from_sender.strip().lstrip("@")[:80]
        if "@" in sender:
            # Their member names live in their namespace; a sender already
            # carrying an @ would let a peer forge a third party's address.
            raise HTTPException(status_code=400, detail="sender must not contain '@'")

        mid = db.uuid7()
        now = db.now_iso()
        with request.app.state.db_lock:
            c.execute("BEGIN IMMEDIATE")
            try:
                c.execute(
                    "INSERT INTO messages(id, thread_id, from_chat_id, from_peer_id,"
                    " from_peer_sender, subject, body, kind, priority, in_reply_to, created_at)"
                    " VALUES(?,?,NULL,?,?,?,?,'message','normal',?,?)",
                    (mid, mid, peer["id"], sender, payload.subject, payload.body,
                     payload.thread_ref, now))
                c.execute("INSERT INTO deliveries(message_id, to_chat_id, status, delivered_at)"
                          " VALUES(?,?,'delivered',?)", (mid, chat["id"], now))
                c.execute("INSERT INTO events(chat_id, type, message_id, created_at)"
                          " VALUES(?,'message.received',?,?)", (chat["id"], mid, now))
                c.execute("UPDATE peers SET last_seen = ? WHERE id = ?", (now, peer["id"]))
                c.execute("COMMIT")
            except BaseException:
                c.execute("ROLLBACK")
                raise
        request.app.state.audit("peer.message_received", f"{sender}@{peer['alias']}",
                                message_id=mid, to=chat["handle"], bytes=len(payload.body))
        return {"accepted": True, "id": mid}

    return router


def deliver_to_peer(request: Request, peer: sqlite3.Row, sender_address: str,
                    remote_handle: str, subject: str, body: str,
                    thread_ref: str | None) -> dict:
    """Push one message to a paired instance.

    Delivery is synchronous and one-shot on purpose: if the peer is down, the
    sender is told immediately. A queue that retries silently would let someone
    believe a message left when it never did — the failure mode this project
    exists to avoid.
    """
    token = request.app.state.peer_tokens.get(peer["id"])
    if not token:
        raise HTTPException(status_code=500,
                            detail="jeton de pair introuvable — ré-appairage nécessaire")
    try:
        answer = _post(f"{peer['base_url']}/v1/peer/inbox", {
            "from_sender": sender_address, "to": remote_handle,
            "subject": subject, "body": body, "thread_ref": thread_ref}, token)
    except PeerUnreachable as e:
        raise HTTPException(status_code=502,
                            detail={"peer": peer["alias"], "reason": str(e)})
    return answer


class PeerUnreachable(RuntimeError):
    pass


def _post(url: str, body: dict, token: str | None = None) -> dict:
    req = urllib.request.Request(url, method="POST", data=json.dumps(body).encode())
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=config.PEER_TIMEOUT_SECONDS) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = json.loads(e.read() or b"{}").get("detail", "")
        except Exception:
            pass
        raise PeerUnreachable(f"HTTP {e.code} {detail}") from None
    except urllib.error.URLError as e:
        raise PeerUnreachable(str(e.reason)) from None


def _peer_or_404(conn: sqlite3.Connection, alias: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM peers WHERE alias = ? AND state = 'active'",
                       (normalize_alias(alias),)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="unknown or revoked peer")
    return row
