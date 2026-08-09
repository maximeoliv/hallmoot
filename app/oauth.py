"""OAuth 2.1 authorization server — the only way a browser-based client can log in.

claude.ai cannot carry a static bearer token: its connector dialog offers OAuth
and nothing else. So the instance has to issue tokens itself, which means being
an authorization server, which means the flow below is security-critical code.

The choices here are deliberately narrow, because every option removed is an
option nobody can get wrong:

* **PKCE S256 is mandatory** — no plain, no missing challenge.
* **Public clients only** (`token_endpoint_auth_method: none`). Storing a secret
  in a browser client buys nothing; PKCE is what actually binds the exchange.
* **Authorization codes are single-use**, live 120 seconds, and are bound to the
  client, the redirect URI and the challenge that created them.
* **Redirect URIs match exactly.** No prefix matching, no wildcards — that is
  the classic open-redirect that turns a login into a token leak.
* **Tokens are opaque and stored hashed**, like every other credential here.
* **No implicit grant, no password grant.**

The human is authenticated by a passphrase typed on the consent screen. For a
single-owner instance that is proportionate; the day third parties sign up, this
becomes a real identity provider's job, not this file's.
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

import base64
import hashlib
import hmac
import html
import json
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from . import config, db
from .security import hash_token

SUPPORTED_SCOPES = ["mcp"]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def public_base(request: Request) -> str:
    """The origin clients discovered us at. Configured wins over guessed: behind
    a tunnel the request's own host header is the only hint, and a wrong issuer
    breaks the flow with an error nobody can read."""
    if config.PUBLIC_URL:
        return config.PUBLIC_URL
    return str(request.base_url).rstrip("/")


def verify_challenge(verifier: str, challenge: str) -> bool:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return hmac.compare_digest(expected, challenge)


def issue_tokens(conn: sqlite3.Connection, client_id: str, chat_id: str) -> dict:
    access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    now = _now()
    conn.execute(
        "INSERT INTO oauth_tokens(token_hash, kind, client_id, chat_id, expires_at, created_at)"
        " VALUES(?,?,?,?,?,?)",
        (hash_token(access), "access", client_id, chat_id,
         _iso(now + timedelta(seconds=config.ACCESS_TOKEN_TTL)), _iso(now)))
    conn.execute(
        "INSERT INTO oauth_tokens(token_hash, kind, client_id, chat_id, expires_at, created_at)"
        " VALUES(?,?,?,?,NULL,?)",
        (hash_token(refresh), "refresh", client_id, chat_id, _iso(now)))
    return {"access_token": access, "token_type": "Bearer",
            "expires_in": config.ACCESS_TOKEN_TTL, "refresh_token": refresh,
            "scope": "mcp"}


def resolve_access_token(conn: sqlite3.Connection, token: str) -> str | None:
    """Return the chat id an access token speaks for, or None."""
    row = conn.execute(
        "SELECT chat_id, expires_at, revoked_at FROM oauth_tokens"
        " WHERE token_hash = ? AND kind = 'access'", (hash_token(token),)).fetchone()
    if row is None or row["revoked_at"] or (row["expires_at"] or "") <= _iso(_now()):
        return None
    return row["chat_id"]


CONSENT_PAGE = """<!doctype html><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Hallmoot — autoriser {client}</title>
<style>
 body{{font-family:system-ui,sans-serif;margin:0;min-height:100vh;display:grid;
   place-items:center;background:#14161a;color:#e8e8e8}}
 form{{width:min(26rem,92vw);background:#1d2026;padding:1.6rem;border-radius:.8rem}}
 h1{{font-size:1.15rem;margin:0 0 .3rem}} p{{opacity:.7;font-size:.9rem;line-height:1.4}}
 label{{display:block;margin:1rem 0 .3rem;font-size:.85rem;opacity:.8}}
 input,select{{width:100%;padding:.7rem;border-radius:.4rem;border:1px solid #333;
   background:#111;color:#eee;font-size:1rem;box-sizing:border-box}}
 button{{width:100%;margin-top:1.2rem;padding:.8rem;border:0;border-radius:.4rem;
   background:#4a7d5f;color:#fff;font-size:1rem}}
 .err{{background:#4a2020;padding:.6rem;border-radius:.4rem;font-size:.9rem}}
</style>
<form method=post>
  <h1>Autoriser « {client} »</h1>
  <p>Ce client demande à agir sur cette instance Hallmoot en tant que l'un de tes chats.</p>
  {error}
  <label>Identité à lui confier</label>
  <select name=chat_id>{options}</select>
  <label>Phrase de passe de l'instance</label>
  <input name=passcode type=password autocomplete=current-password autofocus>
  <input type=hidden name=client_id value="{client_id}">
  <input type=hidden name=redirect_uri value="{redirect_uri}">
  <input type=hidden name=code_challenge value="{code_challenge}">
  <input type=hidden name=state value="{state}">
  <button>Autoriser</button>
</form>"""


def build_router(app_state_getter) -> APIRouter:
    router = APIRouter()

    def conn_of(request: Request) -> sqlite3.Connection:
        return request.app.state.conn

    # ── discovery ──────────────────────────────────────────────────────

    def _as_metadata(request: Request) -> dict:
        base = public_base(request)
        return {
            "issuer": base,
            "authorization_endpoint": f"{base}/oauth/authorize",
            "token_endpoint": f"{base}/oauth/token",
            "registration_endpoint": f"{base}/oauth/register",
            "scopes_supported": SUPPORTED_SCOPES,
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
        }

    @router.get("/.well-known/oauth-authorization-server", include_in_schema=False)
    def as_metadata(request: Request):
        return _as_metadata(request)

    @router.get("/.well-known/openid-configuration", include_in_schema=False)
    def openid_like(request: Request):
        # Some clients probe this path first; answering it saves a round of
        # confusing 404s even though we are not an OpenID provider.
        return _as_metadata(request)

    def _resource_metadata(request: Request) -> dict:
        base = public_base(request)
        return {"resource": f"{base}/mcp", "authorization_servers": [base],
                "bearer_methods_supported": ["header"], "scopes_supported": SUPPORTED_SCOPES}

    @router.get("/.well-known/oauth-protected-resource", include_in_schema=False)
    def resource_metadata(request: Request):
        return _resource_metadata(request)

    @router.get("/.well-known/oauth-protected-resource/mcp", include_in_schema=False)
    def resource_metadata_suffixed(request: Request):
        return _resource_metadata(request)

    # ── dynamic client registration (RFC 7591) ─────────────────────────

    @router.post("/oauth/register", include_in_schema=False)
    async def register_client(request: Request):
        body = await request.json()
        uris = body.get("redirect_uris") or []
        if not isinstance(uris, list) or not uris or not all(isinstance(u, str) for u in uris):
            raise HTTPException(status_code=400, detail="redirect_uris is required")
        for uri in uris:
            if not uri.startswith("https://") and not uri.startswith("http://localhost"):
                raise HTTPException(status_code=400,
                                    detail="redirect_uris must be https (or http://localhost)")
        client_id = "mc_" + secrets.token_urlsafe(18)
        conn_of(request).execute(
            "INSERT INTO oauth_clients(client_id, client_name, redirect_uris, created_at)"
            " VALUES(?,?,?,?)",
            (client_id, str(body.get("client_name") or "client MCP")[:120],
             json.dumps(uris), db.now_iso()))
        request.app.state.audit("oauth.client_registered", "oauth", client_id=client_id,
                                client_name=body.get("client_name"), redirect_uris=uris)
        return JSONResponse({
            "client_id": client_id, "client_id_issued_at": int(_now().timestamp()),
            "redirect_uris": uris, "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"], "client_name": body.get("client_name")},
            status_code=201)

    # ── authorization ──────────────────────────────────────────────────

    def _client_or_400(conn, client_id: str, redirect_uri: str) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM oauth_clients WHERE client_id = ?",
                           (client_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=400, detail="unknown client_id")
        if redirect_uri not in json.loads(row["redirect_uris"]):
            # Never redirect to an unregistered URI, not even to report an error:
            # that is exactly how an authorization code walks out the door.
            raise HTTPException(status_code=400, detail="redirect_uri does not match registration")
        return row

    def _render(conn, client, client_id, redirect_uri, code_challenge, state, error=""):
        chats = conn.execute(
            "SELECT id, handle, display_name FROM chats WHERE revoked_at IS NULL ORDER BY handle"
        ).fetchall()
        options = "".join(
            f'<option value="{html.escape(c["id"])}">@{html.escape(c["handle"])}'
            f' — {html.escape(c["display_name"])}</option>' for c in chats)
        return HTMLResponse(CONSENT_PAGE.format(
            client=html.escape(client["client_name"] or "client MCP"),
            client_id=html.escape(client_id), redirect_uri=html.escape(redirect_uri),
            code_challenge=html.escape(code_challenge), state=html.escape(state or ""),
            options=options or "<option disabled>aucun chat enregistré</option>",
            error=f'<p class=err>{html.escape(error)}</p>' if error else ""))

    @router.get("/oauth/authorize", include_in_schema=False)
    def authorize(request: Request, client_id: str, redirect_uri: str,
                  response_type: str = "code", code_challenge: str = "",
                  code_challenge_method: str = "", state: str = "", scope: str = "mcp"):
        conn = conn_of(request)
        client = _client_or_400(conn, client_id, redirect_uri)
        if response_type != "code":
            raise HTTPException(status_code=400, detail="only response_type=code is supported")
        if code_challenge_method != "S256" or not code_challenge:
            raise HTTPException(status_code=400, detail="PKCE with S256 is required")
        if not config.AUTH_PASSCODE:
            raise HTTPException(
                status_code=503,
                detail="this instance has no MOOT_AUTH_PASSCODE set: OAuth is disabled")
        return _render(conn, client, client_id, redirect_uri, code_challenge, state)

    @router.post("/oauth/authorize", include_in_schema=False)
    def authorize_submit(request: Request, client_id: str = Form(...),
                         redirect_uri: str = Form(...), code_challenge: str = Form(...),
                         chat_id: str = Form(...), passcode: str = Form(""),
                         state: str = Form("")):
        conn = conn_of(request)
        client = _client_or_400(conn, client_id, redirect_uri)

        ip = request.client.host if request.client else "unknown"
        if not request.app.state.ip_bucket.allow(f"authorize:{ip}", 4.0):
            raise HTTPException(status_code=429, detail="too many attempts, slow down")

        if not config.AUTH_PASSCODE or not hmac.compare_digest(passcode, config.AUTH_PASSCODE):
            request.app.state.audit("oauth.passcode_rejected", "oauth", client_id=client_id)
            return _render(conn, client, client_id, redirect_uri, code_challenge, state,
                           error="Phrase de passe incorrecte.")

        chat = conn.execute("SELECT id, handle FROM chats WHERE id = ? AND revoked_at IS NULL",
                            (chat_id,)).fetchone()
        if chat is None:
            raise HTTPException(status_code=400, detail="unknown chat")

        code = secrets.token_urlsafe(32)
        conn.execute(
            "INSERT INTO oauth_codes(code_hash, client_id, chat_id, redirect_uri,"
            " code_challenge, expires_at) VALUES(?,?,?,?,?,?)",
            (hash_token(code), client_id, chat["id"], redirect_uri, code_challenge,
             _iso(_now() + timedelta(seconds=config.AUTH_CODE_TTL))))
        request.app.state.audit("oauth.code_issued", "oauth", client_id=client_id,
                                chat=chat["handle"])
        sep = "&" if "?" in redirect_uri else "?"
        target = f"{redirect_uri}{sep}code={code}"
        if state:
            from urllib.parse import quote
            target += f"&state={quote(state)}"
        return RedirectResponse(target, status_code=303)

    # ── token ──────────────────────────────────────────────────────────

    @router.post("/oauth/token", include_in_schema=False)
    def token(request: Request, grant_type: str = Form(...), code: str = Form(""),
              redirect_uri: str = Form(""), client_id: str = Form(""),
              code_verifier: str = Form(""), refresh_token: str = Form("")):
        conn = conn_of(request)

        def fail(err: str, desc: str):
            return JSONResponse({"error": err, "error_description": desc}, status_code=400)

        if grant_type == "authorization_code":
            row = conn.execute("SELECT * FROM oauth_codes WHERE code_hash = ?",
                               (hash_token(code),)).fetchone()
            if row is None:
                return fail("invalid_grant", "unknown code")
            # Burn it first: a replayed code must fail even if what follows throws.
            conn.execute("UPDATE oauth_codes SET used_at = ? WHERE code_hash = ?",
                         (db.now_iso(), hash_token(code)))
            if row["used_at"] or row["expires_at"] <= _iso(_now()):
                return fail("invalid_grant", "code already used or expired")
            if client_id and client_id != row["client_id"]:
                return fail("invalid_grant", "code was issued to another client")
            if redirect_uri and redirect_uri != row["redirect_uri"]:
                return fail("invalid_grant", "redirect_uri mismatch")
            if not verify_challenge(code_verifier, row["code_challenge"]):
                return fail("invalid_grant", "PKCE verification failed")
            request.app.state.audit("oauth.token_issued", "oauth",
                                    client_id=row["client_id"], chat_id=row["chat_id"])
            return issue_tokens(conn, row["client_id"], row["chat_id"])

        if grant_type == "refresh_token":
            row = conn.execute(
                "SELECT * FROM oauth_tokens WHERE token_hash = ? AND kind = 'refresh'",
                (hash_token(refresh_token),)).fetchone()
            if row is None or row["revoked_at"]:
                return fail("invalid_grant", "unknown or revoked refresh token")
            request.app.state.audit("oauth.token_refreshed", "oauth",
                                    client_id=row["client_id"], chat_id=row["chat_id"])
            return issue_tokens(conn, row["client_id"], row["chat_id"])

        return fail("unsupported_grant_type", f"{grant_type} is not supported")

    return router
