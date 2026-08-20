"""How the owner of an instance proves it is them.

Hallmoot has exactly one owner, so this is not a login system: there is nobody
to tell apart. It is a gate, and the only question is how much ceremony the
operator wants in front of it.

Three answers ship, and the operator picks by configuring them. Whichever are
configured appear on the sign-in page; the others do not exist:

  passphrase  a shared secret, zero setup, works on a machine with no internet
              and no mail. The default, and the only one that is always there.
  oidc        delegate to a provider the operator already trusts — Google,
              GitHub via an OIDC bridge, Authentik, Keycloak. Familiar, and no
              new secret to remember.
  email       a six-digit code sent to one fixed address. Proves control of a
              mailbox rather than knowledge of a shared string.

A fourth — passkeys — is the right long-term answer for a single-owner
instance: nothing to type, nothing to phish, nothing owed to a third party. It
is deliberately absent, because verifying a WebAuthn assertion means verifying
ES256 signatures, and this project does not hand-roll cryptography it can avoid.
Adding it means adding a real library, and that is a decision to take openly.

Nothing here is stored. A pending email code and a pending OIDC exchange both
live in signed cookies for the few minutes they matter, which keeps a piece of
short-lived state out of a schema that would otherwise have to grow a table and
a migration for it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import secrets
import smtplib
import time
import urllib.parse
import urllib.request
from email.message import EmailMessage

from . import config

COOKIE = "moot_owner"
PENDING = "moot_pending"


# ── signing ────────────────────────────────────────────────────────────
#
# Everything signed here is keyed on the owner token, which already exists, is
# already secret, and already survives restarts. A separate signing secret would
# be one more thing to configure and one more thing to lose.


def _key(purpose: str) -> bytes:
    return hmac.new(config.owner_token().encode(), purpose.encode(),
                    hashlib.sha256).digest()


def _sign(purpose: str, payload: dict, ttl: int) -> str:
    body = dict(payload, exp=int(time.time()) + ttl)
    raw = base64.urlsafe_b64encode(json.dumps(body, sort_keys=True).encode()).rstrip(b"=")
    sig = hmac.new(_key(purpose), raw, hashlib.sha256).digest()[:16]
    return raw.decode() + "." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()


def _unsign(purpose: str, value: str) -> dict | None:
    try:
        raw, sig = value.split(".", 1)
    except ValueError:
        return None
    pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
    expected = hmac.new(_key(purpose), raw.encode(), hashlib.sha256).digest()[:16]
    try:
        given = base64.urlsafe_b64decode(pad(sig))
    except Exception:
        return None
    if not hmac.compare_digest(expected, given):
        return None
    try:
        body = json.loads(base64.urlsafe_b64decode(pad(raw)))
    except Exception:
        return None
    if not isinstance(body, dict) or body.get("exp", 0) < time.time():
        return None
    return body


def issue_session() -> str:
    """A short-lived token saying: the human at this browser is the owner."""
    return _sign("owner-session", {"n": secrets.token_urlsafe(8)},
                 config.SIGNIN_SESSION_TTL)


def valid_session(value: str | None) -> bool:
    return bool(value) and _unsign("owner-session", value) is not None


def set_session_cookie(response, secure: bool) -> None:
    response.set_cookie(
        COOKIE, issue_session(), max_age=config.SIGNIN_SESSION_TTL,
        httponly=True, samesite="lax", secure=secure, path="/oauth")


# ── the methods ────────────────────────────────────────────────────────


def passphrase_configured() -> bool:
    return bool(config.AUTH_PASSCODE)


def passphrase_ok(given: str) -> bool:
    return bool(config.AUTH_PASSCODE) and hmac.compare_digest(
        given, config.AUTH_PASSCODE)


def oidc_configured() -> bool:
    return bool(config.OIDC_ISSUER and config.OIDC_CLIENT_ID
                and config.OIDC_CLIENT_SECRET)


def email_configured() -> bool:
    return bool(config.SIGNIN_EMAIL_TO and config.SMTP_HOST)


def methods_html(return_to: str, sent_to: str = "") -> list[dict]:
    """The blocks to render, in the order a tired human should meet them."""
    rt = html.escape(return_to)
    out: list[dict] = []

    if passphrase_configured():
        out.append({"name": "passphrase", "html": (
            f'<form method=post action="/oauth/signin">'
            f'<input type=hidden name=return_to value="{rt}">'
            f'<label>Phrase de passe de l\'instance</label>'
            f'<input name=passcode type=password autocomplete=current-password '
            f'autofocus required>'
            f'<button>Se connecter</button></form>')})

    if oidc_configured():
        label = html.escape(config.OIDC_LABEL or "mon fournisseur d'identité")
        out.append({"name": "oidc", "html": (
            f'<form method=get action="/oauth/signin/oidc">'
            f'<input type=hidden name=return_to value="{rt}">'
            f'<button class=ghost>Continuer avec {label}</button></form>')})

    if email_configured():
        if sent_to:
            out.append({"name": "email", "html": (
                f'<form method=post action="/oauth/signin/email/verify">'
                f'<input type=hidden name=return_to value="{rt}">'
                f'<label>Code reçu par mail</label>'
                f'<input name=code inputmode=numeric autocomplete=one-time-code '
                f'pattern="[0-9]{{6}}" required autofocus>'
                f'<button>Valider le code</button></form>')})
        else:
            masked = _mask(config.SIGNIN_EMAIL_TO)
            out.append({"name": "email", "html": (
                f'<form method=post action="/oauth/signin/email">'
                f'<input type=hidden name=return_to value="{rt}">'
                f'<button class=ghost>Recevoir un code sur {html.escape(masked)}'
                f'</button></form>')})

    return out


def _mask(address: str) -> str:
    name, _, domain = address.partition("@")
    keep = name[:2] if len(name) > 3 else name[:1]
    return f"{keep}{'•' * max(3, len(name) - len(keep))}@{domain}"


# ── email codes ────────────────────────────────────────────────────────


def send_email_code() -> str:
    """Mail a six-digit code, and return the cookie that will check it.

    The code is not stored anywhere. What comes back is a signed statement of
    its hash, which the browser carries and hands back with the answer.
    """
    code = f"{secrets.randbelow(1_000_000):06d}"

    msg = EmailMessage()
    msg["Subject"] = "Ton code de connexion Hallmoot"
    msg["From"] = config.SMTP_FROM or config.SIGNIN_EMAIL_TO
    msg["To"] = config.SIGNIN_EMAIL_TO
    msg.set_content(
        f"Code de connexion : {code}\n\n"
        f"Il vaut {config.SIGNIN_CODE_TTL // 60} minutes et ne sert qu'une fois.\n"
        f"Si tu n'es pas en train de connecter un client à ton instance "
        f"Hallmoot, ignore ce message — et change ta phrase de passe.\n")

    if config.SMTP_PORT == 465:
        server = smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PORT, timeout=15)
    else:
        server = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=15)
    with server:
        if config.SMTP_PORT != 465 and config.SMTP_STARTTLS:
            server.starttls()
        if config.SMTP_USER:
            server.login(config.SMTP_USER, config.SMTP_PASSWORD)
        server.send_message(msg)

    digest = hashlib.sha256(code.encode()).hexdigest()
    return _sign("email-code", {"h": digest}, config.SIGNIN_CODE_TTL)


def email_code_ok(cookie: str | None, given: str) -> bool:
    body = _unsign("email-code", cookie or "")
    if not body:
        return False
    return hmac.compare_digest(
        body.get("h", ""), hashlib.sha256(given.strip().encode()).hexdigest())


# ── OIDC ───────────────────────────────────────────────────────────────


def _discover() -> dict:
    url = config.OIDC_ISSUER.rstrip("/") + "/.well-known/openid-configuration"
    with urllib.request.urlopen(url, timeout=15) as r:
        return json.loads(r.read())


def oidc_start(redirect_uri: str) -> tuple[str, str]:
    """Return (provider URL to send the human to, cookie holding state+nonce)."""
    meta = _discover()
    state, nonce = secrets.token_urlsafe(16), secrets.token_urlsafe(16)
    params = {
        "response_type": "code",
        "client_id": config.OIDC_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "scope": config.OIDC_SCOPE,
        "state": state,
        "nonce": nonce,
    }
    url = meta["authorization_endpoint"] + "?" + urllib.parse.urlencode(params)
    return url, _sign("oidc", {"s": state, "n": nonce}, 600)


def oidc_finish(cookie: str | None, state: str, code: str, redirect_uri: str) -> str:
    """Exchange the code and return the identity the provider vouched for.

    The id_token's signature is not verified here, and that is deliberate rather
    than lazy: it arrives in the response to a direct, server-to-server TLS call
    to the provider's token endpoint, authenticated with the client secret.
    OpenID Connect Core §3.1.3.7 says signature validation may be skipped in
    exactly that case, because the TLS channel already establishes who sent it.
    Verifying it locally would mean carrying a JWT library and a JWKS cache to
    re-prove something the transport proved.

    Raises ValueError with a message fit to show a human.
    """
    body = _unsign("oidc", cookie or "")
    if not body:
        raise ValueError("La connexion a expiré. Recommence.")
    if not hmac.compare_digest(body.get("s", ""), state):
        raise ValueError("Réponse du fournisseur inattendue.")

    meta = _discover()
    data = urllib.parse.urlencode({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": config.OIDC_CLIENT_ID,
        "client_secret": config.OIDC_CLIENT_SECRET,
    }).encode()
    req = urllib.request.Request(
        meta["token_endpoint"], data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        tokens = json.loads(r.read())

    id_token = tokens.get("id_token")
    if not id_token:
        raise ValueError("Le fournisseur n'a pas renvoyé d'identité.")

    claims = _claims(id_token)

    if claims.get("iss", "").rstrip("/") != config.OIDC_ISSUER.rstrip("/"):
        raise ValueError("Identité émise par un autre fournisseur.")
    aud = claims.get("aud")
    auds = aud if isinstance(aud, list) else [aud]
    if config.OIDC_CLIENT_ID not in auds:
        raise ValueError("Identité destinée à une autre application.")
    if claims.get("exp", 0) < time.time():
        raise ValueError("Identité expirée.")
    if not hmac.compare_digest(str(claims.get("nonce", "")), body.get("n", "")):
        raise ValueError("Réponse du fournisseur inattendue.")

    who = claims.get("email") or claims.get("preferred_username") or claims.get("sub", "")
    allowed = [a.strip().lower() for a in config.OIDC_ALLOWED.split(",") if a.strip()]
    if not allowed:
        # An unrestricted list would let anyone with an account at the provider
        # sign in as the owner. Refusing is the only safe reading of "unset".
        raise ValueError("Aucun compte autorisé n'est configuré côté instance.")
    if who.lower() not in allowed and str(claims.get("sub", "")).lower() not in allowed:
        raise ValueError("Ce compte n'est pas autorisé sur cette instance.")

    return who


def _claims(id_token: str) -> dict:
    try:
        payload = id_token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception as e:  # pragma: no cover - malformed provider response
        raise ValueError("Identité illisible.") from e
