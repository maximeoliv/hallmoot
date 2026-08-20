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

from . import config, consent_ui, db, signin
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

    # ── the two steps a human walks through ────────────────────────────
    #
    # Authenticating the owner and choosing an identity used to be one form.
    # They are separated here because only the first has several possible
    # answers: adding a sign-in method must never mean touching the code that
    # grants access. It also means a second connector added five minutes later
    # does not ask again.

    def _secure_cookies() -> bool:
        # Behind a proxy the request's own scheme is http; the public origin is
        # what the browser actually used, so it is what decides.
        return config.PUBLIC_URL.startswith("https://")

    def _return_to(request: Request) -> str:
        q = request.url.query
        return "/oauth/authorize" + (f"?{q}" if q else "")

    def _return_to_ok(value: str) -> bool:
        """Only ever come back to our own authorize page.

        A return address taken from a form is an open redirect waiting to
        happen, and an open redirect on an authorization server is how an
        authorization code leaves with a stranger.
        """
        return value.startswith("/oauth/authorize?") and "\n" not in value

    def _client_name(conn, return_to: str) -> str:
        from urllib.parse import parse_qs, urlparse
        cid = parse_qs(urlparse(return_to).query).get("client_id", [""])[0]
        row = conn.execute("SELECT client_name FROM oauth_clients WHERE client_id = ?",
                           (cid,)).fetchone()
        return (row["client_name"] if row and row["client_name"] else "client MCP")

    def _sign_in(conn, return_to: str, error: str = "", sent: bool = False,
                 notice: str = "", status: int = 200) -> HTMLResponse:
        return HTMLResponse(consent_ui.sign_in_page(
            client_name=_client_name(conn, return_to),
            methods=signin.methods_html(return_to, sent_to=sent and "yes" or ""),
            error=error, notice=notice), status_code=status)

    def _grant(conn, client, client_id, redirect_uri, code_challenge, state, error=""):
        chats = conn.execute(
            "SELECT id, handle, display_name FROM chats WHERE revoked_at IS NULL ORDER BY handle"
        ).fetchall()
        options = "".join(
            f'<option value="{html.escape(c["id"])}">@{html.escape(c["handle"])}'
            f' — {html.escape(c["display_name"])}</option>' for c in chats
        ) or "<option disabled>aucun chat enregistré</option>"
        fields = "".join(
            f'<input type=hidden name={n} value="{html.escape(v or "")}">'
            for n, v in (("client_id", client_id), ("redirect_uri", redirect_uri),
                         ("code_challenge", code_challenge), ("state", state)))
        return HTMLResponse(consent_ui.grant_page(
            client_name=html.escape(client["client_name"] or "client MCP"),
            options=options, fields=fields, error=error))

    def _any_method() -> bool:
        return (signin.passphrase_configured() or signin.oidc_configured()
                or signin.email_configured())

    def _throttle(request: Request) -> None:
        ip = request.client.host if request.client else "unknown"
        if not request.app.state.ip_bucket.allow(f"authorize:{ip}", 4.0):
            raise HTTPException(status_code=429, detail="too many attempts, slow down")

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
        if not _any_method():
            raise HTTPException(
                status_code=503,
                detail="this instance has no sign-in method configured: OAuth is disabled")
        if not signin.valid_session(request.cookies.get(signin.COOKIE)):
            return _sign_in(conn, _return_to(request))
        return _grant(conn, client, client_id, redirect_uri, code_challenge, state)

    # ── sign-in: passphrase ────────────────────────────────────────────

    @router.post("/oauth/signin", include_in_schema=False)
    def signin_passphrase(request: Request, return_to: str = Form(...),
                          passcode: str = Form("")):
        conn = conn_of(request)
        if not _return_to_ok(return_to):
            raise HTTPException(status_code=400, detail="bad return_to")
        _throttle(request)
        if not signin.passphrase_ok(passcode):
            request.app.state.audit("oauth.signin_rejected", "oauth", method="passphrase")
            return _sign_in(conn, return_to, error="Phrase de passe incorrecte.",
                            status=401)
        request.app.state.audit("oauth.signin", "oauth", method="passphrase")
        resp = RedirectResponse(return_to, status_code=303)
        signin.set_session_cookie(resp, _secure_cookies())
        return resp

    # ── sign-in: an identity provider ──────────────────────────────────

    @router.get("/oauth/signin/oidc", include_in_schema=False)
    def signin_oidc(request: Request, return_to: str):
        conn = conn_of(request)
        if not _return_to_ok(return_to):
            raise HTTPException(status_code=400, detail="bad return_to")
        if not signin.oidc_configured():
            raise HTTPException(status_code=404, detail="no identity provider configured")
        try:
            url, pending = signin.oidc_start(config.PUBLIC_URL + "/oauth/signin/oidc/callback")
        except Exception:
            request.app.state.audit("oauth.signin_error", "oauth", method="oidc")
            return _sign_in(conn, return_to, status=502,
                            error="Le fournisseur d'identité est injoignable.")
        resp = RedirectResponse(url, status_code=303)
        resp.set_cookie(signin.PENDING, pending, max_age=600, httponly=True,
                        samesite="lax", secure=_secure_cookies(), path="/oauth")
        resp.set_cookie(signin.PENDING + "_rt", return_to, max_age=600, httponly=True,
                        samesite="lax", secure=_secure_cookies(), path="/oauth")
        return resp

    @router.get("/oauth/signin/oidc/callback", include_in_schema=False)
    def signin_oidc_callback(request: Request, code: str = "", state: str = "",
                             error: str = ""):
        conn = conn_of(request)
        return_to = request.cookies.get(signin.PENDING + "_rt", "")
        if not _return_to_ok(return_to):
            raise HTTPException(status_code=400, detail="no pending authorization")
        _throttle(request)
        if error or not code:
            return _sign_in(conn, return_to, status=401,
                            error="Le fournisseur a refusé la connexion.")
        try:
            who = signin.oidc_finish(
                request.cookies.get(signin.PENDING), state, code,
                config.PUBLIC_URL + "/oauth/signin/oidc/callback")
        except ValueError as e:
            request.app.state.audit("oauth.signin_rejected", "oauth", method="oidc")
            return _sign_in(conn, return_to, error=str(e), status=401)
        except Exception:
            request.app.state.audit("oauth.signin_error", "oauth", method="oidc")
            return _sign_in(conn, return_to, status=502,
                            error="Le fournisseur d'identité est injoignable.")
        request.app.state.audit("oauth.signin", "oauth", method="oidc", who=who)
        resp = RedirectResponse(return_to, status_code=303)
        signin.set_session_cookie(resp, _secure_cookies())
        resp.delete_cookie(signin.PENDING, path="/oauth")
        resp.delete_cookie(signin.PENDING + "_rt", path="/oauth")
        return resp

    # ── sign-in: a code by mail ────────────────────────────────────────

    @router.post("/oauth/signin/email", include_in_schema=False)
    def signin_email(request: Request, return_to: str = Form(...)):
        conn = conn_of(request)
        if not _return_to_ok(return_to):
            raise HTTPException(status_code=400, detail="bad return_to")
        if not signin.email_configured():
            raise HTTPException(status_code=404, detail="no mail sign-in configured")
        _throttle(request)
        try:
            pending = signin.send_email_code()
        except Exception:
            request.app.state.audit("oauth.signin_error", "oauth", method="email")
            return _sign_in(conn, return_to, status=502,
                            error="Le code n'a pas pu être envoyé.")
        request.app.state.audit("oauth.signin_code_sent", "oauth", method="email")
        resp = _sign_in(conn, return_to, sent=True,
                        notice="Un code vient de partir. Il vaut dix minutes.")
        resp.set_cookie(signin.PENDING, pending, max_age=config.SIGNIN_CODE_TTL,
                        httponly=True, samesite="lax", secure=_secure_cookies(),
                        path="/oauth")
        return resp

    @router.post("/oauth/signin/email/verify", include_in_schema=False)
    def signin_email_verify(request: Request, return_to: str = Form(...),
                            code: str = Form("")):
        conn = conn_of(request)
        if not _return_to_ok(return_to):
            raise HTTPException(status_code=400, detail="bad return_to")
        _throttle(request)
        if not signin.email_code_ok(request.cookies.get(signin.PENDING), code):
            request.app.state.audit("oauth.signin_rejected", "oauth", method="email")
            return _sign_in(conn, return_to, sent=True, status=401,
                            error="Code incorrect ou expiré.")
        request.app.state.audit("oauth.signin", "oauth", method="email")
        resp = RedirectResponse(return_to, status_code=303)
        signin.set_session_cookie(resp, _secure_cookies())
        resp.delete_cookie(signin.PENDING, path="/oauth")
        return resp

    # ── the grant itself ───────────────────────────────────────────────

    @router.post("/oauth/authorize", include_in_schema=False)
    def authorize_submit(request: Request, client_id: str = Form(...),
                         redirect_uri: str = Form(...), code_challenge: str = Form(...),
                         chat_id: str = Form(...), state: str = Form("")):
        conn = conn_of(request)
        client = _client_or_400(conn, client_id, redirect_uri)
        _throttle(request)

        if not signin.valid_session(request.cookies.get(signin.COOKIE)):
            # The session expired between opening the page and pressing the
            # button. Sending them back to sign in is the only honest answer.
            from urllib.parse import urlencode
            back = "/oauth/authorize?" + urlencode({
                "client_id": client_id, "redirect_uri": redirect_uri,
                "response_type": "code", "code_challenge": code_challenge,
                "code_challenge_method": "S256", "state": state})
            return _sign_in(conn, back, status=401,
                            error="Ta session a expiré. Reconnecte-toi.")

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
