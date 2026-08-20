"""The gate in front of the consent screen.

Sign-in is new surface, and it is the kind of surface where a mistake is not a
bug report but an intrusion. What follows is mostly about the ways in that must
stay shut: a forged cookie, a borrowed return address, a provider vouching for
somebody who was never allowed.
"""

import base64
import hashlib
import json
import time
from urllib.parse import urlencode

import pytest

from app import config, signin
from conftest import OWNER  # noqa: F401  (imported for its side effect on config)

REDIRECT = "https://claude.ai/api/mcp/auth_callback"
PASSCODE = "test-passcode-42"


@pytest.fixture(autouse=True)
def _configured(monkeypatch):
    monkeypatch.setattr(config, "AUTH_PASSCODE", PASSCODE)
    monkeypatch.setattr(config, "PUBLIC_URL", "https://testserver")
    monkeypatch.setattr(config, "OIDC_ISSUER", "")
    monkeypatch.setattr(config, "SIGNIN_EMAIL_TO", "")
    monkeypatch.setattr(config, "SMTP_HOST", "")


@pytest.fixture
def oauth_client(client):
    return client.post("/oauth/register", json={
        "client_name": "Claude", "redirect_uris": [REDIRECT]}).json()


def pkce():
    v = "v" * 64
    c = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()
    return v, c


def return_to(oauth_client, challenge):
    return "/oauth/authorize?" + urlencode({
        "client_id": oauth_client["client_id"], "redirect_uri": REDIRECT,
        "response_type": "code", "code_challenge": challenge,
        "code_challenge_method": "S256", "state": "xyz"})


# ── the return address ─────────────────────────────────────────────────


@pytest.mark.parametrize("hostile", [
    "https://evil.example/steal",
    "//evil.example/steal",
    "/v1/admin/chats",
    "/oauth/authorize\nSet-Cookie: x=1",
])
def test_a_return_address_that_is_not_ours_is_refused(client, hostile):
    """An open redirect on an authorization server hands out codes.

    Whatever a form says, the only place sign-in may send someone afterwards is
    this server's own authorize page.
    """
    res = client.post("/oauth/signin",
                      data={"return_to": hostile, "passcode": PASSCODE},
                      follow_redirects=False)
    assert res.status_code == 400
    assert "location" not in res.headers


# ── the session cookie ─────────────────────────────────────────────────


def test_a_forged_session_is_not_a_session(client, oauth_client, alice):
    _, challenge = pkce()
    client.cookies.set("moot_owner", "eyJuIjoiZm9yZ2VkIn0.AAAAAAAAAAAAAAAAAAAAAA",
                       domain="testserver")
    res = client.get("/oauth/authorize", params={
        "client_id": oauth_client["client_id"], "redirect_uri": REDIRECT,
        "response_type": "code", "code_challenge": challenge,
        "code_challenge_method": "S256", "state": "xyz"})
    assert res.status_code == 200
    assert "alice" not in res.text          # still the sign-in page


def test_an_expired_session_cannot_grant(client, oauth_client, alice, monkeypatch):
    """The gap between opening the page and pressing the button is not a hole."""
    _, challenge = pkce()
    assert client.post("/oauth/signin", data={
        "return_to": return_to(oauth_client, challenge),
        "passcode": PASSCODE}, follow_redirects=False).status_code == 303

    monkeypatch.setattr(time, "time", lambda: 10 ** 10)   # far past every expiry

    res = client.post("/oauth/authorize", data={
        "client_id": oauth_client["client_id"], "redirect_uri": REDIRECT,
        "code_challenge": challenge, "chat_id": alice["chat_id"],
        "state": "xyz"}, follow_redirects=False)
    assert res.status_code == 401
    assert "location" not in res.headers


def test_signing_is_bound_to_its_purpose():
    """A cookie minted for one job must not be accepted for another."""
    code_cookie = signin._sign("email-code", {"h": "abc"}, 600)
    assert signin._unsign("email-code", code_cookie) is not None
    assert signin._unsign("owner-session", code_cookie) is None


# ── no method configured ───────────────────────────────────────────────


def test_an_instance_with_no_method_refuses_everything(client, oauth_client, monkeypatch):
    monkeypatch.setattr(config, "AUTH_PASSCODE", "")
    _, challenge = pkce()
    res = client.get("/oauth/authorize", params={
        "client_id": oauth_client["client_id"], "redirect_uri": REDIRECT,
        "response_type": "code", "code_challenge": challenge,
        "code_challenge_method": "S256", "state": "xyz"})
    assert res.status_code == 503


# ── a code by mail ─────────────────────────────────────────────────────


@pytest.fixture
def mailed(monkeypatch):
    """Capture the code instead of sending it."""
    sent = {}

    def fake_send():
        code = "123456"
        sent["code"] = code
        return signin._sign("email-code",
                            {"h": hashlib.sha256(code.encode()).hexdigest()},
                            config.SIGNIN_CODE_TTL)

    monkeypatch.setattr(config, "SIGNIN_EMAIL_TO", "max@example.test")
    monkeypatch.setattr(config, "SMTP_HOST", "smtp.example.test")
    monkeypatch.setattr(signin, "send_email_code", fake_send)
    return sent


def test_a_mailed_code_signs_you_in(client, oauth_client, alice, mailed):
    _, challenge = pkce()
    rt = return_to(oauth_client, challenge)

    asked = client.post("/oauth/signin/email", data={"return_to": rt})
    assert asked.status_code == 200 and "code" in asked.text.lower()

    ok = client.post("/oauth/signin/email/verify",
                     data={"return_to": rt, "code": mailed["code"]},
                     follow_redirects=False)
    assert ok.status_code == 303 and ok.headers["location"] == rt


def test_the_wrong_code_gets_nowhere(client, oauth_client, alice, mailed):
    _, challenge = pkce()
    rt = return_to(oauth_client, challenge)
    client.post("/oauth/signin/email", data={"return_to": rt})
    res = client.post("/oauth/signin/email/verify",
                      data={"return_to": rt, "code": "000000"},
                      follow_redirects=False)
    assert res.status_code == 401
    assert "location" not in res.headers


def test_the_address_is_never_shown_in_full(client, oauth_client, mailed):
    _, challenge = pkce()
    page = client.get("/oauth/authorize", params={
        "client_id": oauth_client["client_id"], "redirect_uri": REDIRECT,
        "response_type": "code", "code_challenge": challenge,
        "code_challenge_method": "S256", "state": "xyz"})
    assert "max@example.test" not in page.text
    assert "example.test" in page.text        # enough to recognise, not to harvest


# ── an identity provider ───────────────────────────────────────────────


def _id_token(claims: dict) -> str:
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return "header." + payload + ".signature"


@pytest.fixture
def provider(monkeypatch):
    """A provider that answers, so the checks around it can be exercised."""
    monkeypatch.setattr(config, "OIDC_ISSUER", "https://idp.example")
    monkeypatch.setattr(config, "OIDC_CLIENT_ID", "moot")
    monkeypatch.setattr(config, "OIDC_CLIENT_SECRET", "shhh")
    monkeypatch.setattr(config, "OIDC_ALLOWED", "max@example.test")
    monkeypatch.setattr(signin, "_discover", lambda: {
        "authorization_endpoint": "https://idp.example/auth",
        "token_endpoint": "https://idp.example/token"})
    return {}


def _finish(monkeypatch, claims, state, nonce):
    monkeypatch.setattr(signin, "_discover", lambda: {
        "authorization_endpoint": "https://idp.example/auth",
        "token_endpoint": "https://idp.example/token"})

    class _R:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return json.dumps({"id_token": _id_token(claims)}).encode()

    monkeypatch.setattr(signin.urllib.request, "urlopen", lambda *a, **k: _R())
    cookie = signin._sign("oidc", {"s": state, "n": nonce}, 600)
    return signin.oidc_finish(cookie, state, "the-code", "https://testserver/cb")


def _claims(**over):
    base = {"iss": "https://idp.example", "aud": "moot",
            "exp": int(time.time()) + 600, "nonce": "N",
            "email": "max@example.test"}
    base.update(over)
    return base


def test_a_provider_vouching_for_the_right_person_is_accepted(provider, monkeypatch):
    assert _finish(monkeypatch, _claims(), "S", "N") == "max@example.test"


@pytest.mark.parametrize("claims,why", [
    (_claims(iss="https://evil.example"), "another issuer"),
    (_claims(aud="someone-else"), "another audience"),
    (_claims(exp=int(time.time()) - 1), "expired"),
    (_claims(nonce="not-ours"), "replayed"),
    (_claims(email="stranger@example.test"), "not on the allow list"),
])
def test_a_provider_answer_that_is_off_is_refused(provider, monkeypatch, claims, why):
    with pytest.raises(ValueError):
        _finish(monkeypatch, claims, "S", "N")


def test_an_empty_allow_list_lets_nobody_in(provider, monkeypatch):
    """Unset must mean nobody, not everybody.

    Read the other way round, every account at the provider — every Google
    account in the world, for instance — would be the owner of this instance.
    """
    monkeypatch.setattr(config, "OIDC_ALLOWED", "")
    with pytest.raises(ValueError):
        _finish(monkeypatch, _claims(), "S", "N")


def test_a_mismatched_state_is_refused(provider, monkeypatch):
    with pytest.raises(ValueError):
        # the cookie remembers a different state than the one that came back
        signin.oidc_finish(signin._sign("oidc", {"s": "OTHER", "n": "N"}, 600),
                           "S", "code", "https://testserver/cb")
