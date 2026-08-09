"""Identity and credentials.

The rule that shapes this file: a caller's identity comes from its token and
nothing else. `from` is never read off the request body — the engine we forked
the model from let senders declare it, which is fine on a trusted private
network and indefensible in a product.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

TOKEN_BYTES = 32

_bearer = HTTPBearer(auto_error=False)


def mint_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


def hash_token(token: str) -> str:
    """Tokens are 256 bits of CSPRNG output, so a plain SHA-256 is the right
    tool: there is nothing to brute-force, and we want constant-time lookups.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Principal:
    kind: str  # "owner" | "chat"
    chat_id: str | None = None
    handle: str | None = None

    @property
    def is_owner(self) -> bool:
        return self.kind == "owner"


def _unauthorized(request: Request | None = None) -> HTTPException:
    """A 401 that says where to go and get a token.

    RFC 9728: browser-based MCP clients discover the authorization server from
    this header. Without it they cannot start the OAuth dance — they just fail.
    """
    from . import config
    base = config.PUBLIC_URL or (str(request.base_url).rstrip("/") if request else "")
    challenge = 'Bearer realm="hallmoot"'
    if base:
        challenge += f', resource_metadata="{base}/.well-known/oauth-protected-resource"'
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="invalid or missing bearer token",
        headers={"WWW-Authenticate": challenge},
    )


def authenticate(request: Request,
                 creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> Principal:
    if creds is None or not creds.credentials:
        raise _unauthorized(request)
    token = creds.credentials
    if hmac.compare_digest(token, request.app.state.owner_token):
        return Principal(kind="owner")

    conn: sqlite3.Connection = request.app.state.conn
    row = conn.execute(
        "SELECT id, handle, revoked_at FROM chats WHERE token_hash = ?",
        (hash_token(token),),
    ).fetchone()
    if row is None:
        # Not a chat token: it may be an OAuth access token, which speaks for a
        # chat just the same. Imported here to keep the module graph acyclic.
        from . import oauth
        chat_id = oauth.resolve_access_token(conn, token)
        if chat_id:
            row = conn.execute(
                "SELECT id, handle, revoked_at FROM chats WHERE id = ?", (chat_id,)).fetchone()
    if row is None or row["revoked_at"] is not None:
        raise _unauthorized(request)
    return Principal(kind="chat", chat_id=row["id"], handle=row["handle"])


def require_chat(principal: Principal = Depends(authenticate)) -> Principal:
    """Routes that act *as* a chat. The owner token is deliberately not a
    super-user here: it administers the instance, it does not impersonate.
    """
    if principal.kind != "chat":
        raise HTTPException(status_code=403, detail="this endpoint requires a chat token")
    return principal


def require_owner(principal: Principal = Depends(authenticate)) -> Principal:
    if not principal.is_owner:
        raise HTTPException(status_code=403, detail="this endpoint requires the owner token")
    return principal
