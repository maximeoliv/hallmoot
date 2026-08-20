"""The OAuth flow a browser-based client walks through.

This is the most security-critical code in the project: it hands out
credentials. The tests below are mostly about what must NOT work — a replayed
code, a mismatched redirect, a missing PKCE verifier — because those are the
failures that turn a login into a token leak.
"""
import base64
import hashlib
import json

import pytest

from app import config

PASSCODE = "test-passcode-42"
REDIRECT = "https://claude.ai/api/mcp/auth_callback"


@pytest.fixture
def oauth_client(client, monkeypatch):
    monkeypatch.setattr(config, "AUTH_PASSCODE", PASSCODE)
    monkeypatch.setattr(config, "PUBLIC_URL", "https://example.test")
    res = client.post("/oauth/register", json={
        "client_name": "Claude", "redirect_uris": [REDIRECT]})
    assert res.status_code == 201
    return res.json()


def pkce():
    verifier = "a" * 64
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def return_to(oauth_client, challenge, redirect=REDIRECT):
    from urllib.parse import urlencode
    return "/oauth/authorize?" + urlencode({
        "client_id": oauth_client["client_id"], "redirect_uri": redirect,
        "response_type": "code", "code_challenge": challenge,
        "code_challenge_method": "S256", "state": "xyz"})


def sign_in(client, oauth_client, challenge, passcode=PASSCODE, redirect=REDIRECT):
    """Step one: prove the owner is at the browser."""
    return client.post("/oauth/signin", data={
        "return_to": return_to(oauth_client, challenge, redirect),
        "passcode": passcode}, follow_redirects=False)


def authorize(client, oauth_client, challenge, chat, passcode=PASSCODE, redirect=REDIRECT):
    """Both steps, the way a human walks them: sign in, then grant."""
    signed = sign_in(client, oauth_client, challenge, passcode, redirect)
    if signed.status_code != 303:
        return signed        # refused at the door; the caller asserts on that
    return client.post("/oauth/authorize", data={
        "client_id": oauth_client["client_id"], "redirect_uri": redirect,
        "code_challenge": challenge, "chat_id": chat["chat_id"],
        "state": "xyz"}, follow_redirects=False)


def code_from(response) -> str:
    from urllib.parse import parse_qs, urlparse
    return parse_qs(urlparse(response.headers["location"]).query)["code"][0]


# ── discovery ──────────────────────────────────────────────────────────

def test_discovery_documents_point_at_us(client, monkeypatch):
    monkeypatch.setattr(config, "PUBLIC_URL", "https://example.test")
    resource = client.get("/.well-known/oauth-protected-resource").json()
    assert resource["resource"] == "https://example.test/mcp"
    assert resource["authorization_servers"] == ["https://example.test"]

    meta = client.get("/.well-known/oauth-authorization-server").json()
    assert meta["registration_endpoint"] == "https://example.test/oauth/register"
    assert meta["code_challenge_methods_supported"] == ["S256"]
    assert "client_credentials" not in meta["grant_types_supported"]


def test_a_401_tells_the_client_where_to_authenticate(client, monkeypatch):
    monkeypatch.setattr(config, "PUBLIC_URL", "https://example.test")
    res = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert res.status_code == 401
    assert "resource_metadata=" in res.headers["www-authenticate"]
    assert "/.well-known/oauth-protected-resource" in res.headers["www-authenticate"]


# ── the happy path ─────────────────────────────────────────────────────

def test_the_sign_in_page_names_no_identities(client, oauth_client, alice, bob):
    """Before authenticating, a visitor learns nothing about who lives here.

    The old single-step screen listed every chat to anyone who could reach it
    with a valid client_id — and registration is open by design, so that was
    anyone at all. Handles are not secrets, but an unauthenticated stranger has
    no business enumerating them.
    """
    _, challenge = pkce()
    page = client.get("/oauth/authorize", params={
        "client_id": oauth_client["client_id"], "redirect_uri": REDIRECT,
        "response_type": "code", "code_challenge": challenge,
        "code_challenge_method": "S256", "state": "xyz"})
    assert page.status_code == 200
    assert "alice" not in page.text and "bob" not in page.text



def test_full_flow_yields_a_token_that_speaks_for_the_chosen_chat(client, oauth_client, alice):
    verifier, challenge = pkce()

    params = {
        "client_id": oauth_client["client_id"], "redirect_uri": REDIRECT,
        "response_type": "code", "code_challenge": challenge,
        "code_challenge_method": "S256", "state": "xyz"}

    # A visitor who has not signed in is asked to, and told nothing else.
    page = client.get("/oauth/authorize", params=params)
    assert page.status_code == 200 and "alice" not in page.text
    assert PASSCODE not in page.text

    # Once signed in, the same URL offers the identities.
    assert sign_in(client, oauth_client, challenge).status_code == 303
    page = client.get("/oauth/authorize", params=params)
    assert page.status_code == 200 and "alice" in page.text
    assert PASSCODE not in page.text

    granted = authorize(client, oauth_client, challenge, alice)
    assert granted.status_code == 303
    assert granted.headers["location"].startswith(REDIRECT)
    assert "state=xyz" in granted.headers["location"]

    tokens = client.post("/oauth/token", data={
        "grant_type": "authorization_code", "code": code_from(granted),
        "redirect_uri": REDIRECT, "client_id": oauth_client["client_id"],
        "code_verifier": verifier}).json()
    assert tokens["token_type"] == "Bearer" and tokens["expires_in"] > 0

    auth = {"Authorization": f"Bearer {tokens['access_token']}"}
    assert client.get("/v1/me", headers=auth).json()["handle"] == "alice"
    called = client.post("/mcp", headers=auth, json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "whoami", "arguments": {}}}).json()
    assert json.loads(called["result"]["content"][0]["text"])["handle"] == "alice"


def test_refresh_token_returns_a_fresh_access_token(client, oauth_client, alice):
    verifier, challenge = pkce()
    granted = authorize(client, oauth_client, challenge, alice)
    first = client.post("/oauth/token", data={
        "grant_type": "authorization_code", "code": code_from(granted),
        "redirect_uri": REDIRECT, "client_id": oauth_client["client_id"],
        "code_verifier": verifier}).json()

    second = client.post("/oauth/token", data={
        "grant_type": "refresh_token", "refresh_token": first["refresh_token"]}).json()
    assert second["access_token"] != first["access_token"]
    assert client.get("/v1/me", headers={
        "Authorization": f"Bearer {second['access_token']}"}).status_code == 200


# ── what must not work ─────────────────────────────────────────────────

def test_wrong_passcode_never_issues_a_code(client, oauth_client, alice):
    _, challenge = pkce()
    res = authorize(client, oauth_client, challenge, alice, passcode="nope")
    assert res.status_code == 401            # back to the form, and said so
    assert "incorrecte" in res.text
    assert "location" not in res.headers
    # and no session was handed out on the way past
    assert "moot_owner" not in res.headers.get("set-cookie", "")


def test_an_unregistered_redirect_is_refused_outright(client, oauth_client, alice):
    _, challenge = pkce()
    res = authorize(client, oauth_client, challenge, alice,
                    redirect="https://evil.example/callback")
    assert res.status_code == 400
    assert "location" not in res.headers


def test_a_code_cannot_be_replayed(client, oauth_client, alice):
    verifier, challenge = pkce()
    granted = authorize(client, oauth_client, challenge, alice)
    code = code_from(granted)
    body = {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
            "client_id": oauth_client["client_id"], "code_verifier": verifier}
    assert client.post("/oauth/token", data=body).status_code == 200
    replay = client.post("/oauth/token", data=body)
    assert replay.status_code == 400 and replay.json()["error"] == "invalid_grant"


def test_the_wrong_verifier_gets_nothing(client, oauth_client, alice):
    _, challenge = pkce()
    granted = authorize(client, oauth_client, challenge, alice)
    res = client.post("/oauth/token", data={
        "grant_type": "authorization_code", "code": code_from(granted),
        "redirect_uri": REDIRECT, "client_id": oauth_client["client_id"],
        "code_verifier": "b" * 64})
    assert res.status_code == 400 and "PKCE" in res.json()["error_description"]


def test_pkce_is_mandatory(client, oauth_client):
    res = client.get("/oauth/authorize", params={
        "client_id": oauth_client["client_id"], "redirect_uri": REDIRECT,
        "response_type": "code"})
    assert res.status_code == 400


def test_registration_refuses_a_plaintext_redirect(client):
    res = client.post("/oauth/register", json={
        "client_name": "x", "redirect_uris": ["http://evil.example/cb"]})
    assert res.status_code == 400


def test_oauth_is_off_when_no_passcode_is_configured(client, monkeypatch):
    monkeypatch.setattr(config, "AUTH_PASSCODE", "")
    registered = client.post("/oauth/register", json={
        "client_name": "x", "redirect_uris": [REDIRECT]}).json()
    _, challenge = pkce()
    res = client.get("/oauth/authorize", params={
        "client_id": registered["client_id"], "redirect_uri": REDIRECT,
        "response_type": "code", "code_challenge": challenge,
        "code_challenge_method": "S256"})
    assert res.status_code == 503


def test_an_oauth_token_is_still_only_a_chat(client, oauth_client, alice):
    verifier, challenge = pkce()
    granted = authorize(client, oauth_client, challenge, alice)
    tokens = client.post("/oauth/token", data={
        "grant_type": "authorization_code", "code": code_from(granted),
        "redirect_uri": REDIRECT, "client_id": oauth_client["client_id"],
        "code_verifier": verifier}).json()
    auth = {"Authorization": f"Bearer {tokens['access_token']}"}
    assert client.get("/v1/admin/chats", headers=auth).status_code == 403


def test_revoking_the_chat_kills_its_oauth_token(client, oauth_client, alice):
    from conftest import owner_headers
    verifier, challenge = pkce()
    granted = authorize(client, oauth_client, challenge, alice)
    tokens = client.post("/oauth/token", data={
        "grant_type": "authorization_code", "code": code_from(granted),
        "redirect_uri": REDIRECT, "client_id": oauth_client["client_id"],
        "code_verifier": verifier}).json()
    auth = {"Authorization": f"Bearer {tokens['access_token']}"}
    assert client.get("/v1/me", headers=auth).status_code == 200
    client.delete(f"/v1/admin/chats/{alice['chat_id']}", headers=owner_headers())
    assert client.get("/v1/me", headers=auth).status_code == 401


# ── operating the thing: per-connector revocation ──────────────────────

def test_owner_sees_which_connectors_hold_tokens(client, oauth_client, alice):
    from conftest import owner_headers
    verifier, challenge = pkce()
    granted = authorize(client, oauth_client, challenge, alice)
    client.post("/oauth/token", data={
        "grant_type": "authorization_code", "code": code_from(granted),
        "redirect_uri": REDIRECT, "client_id": oauth_client["client_id"],
        "code_verifier": verifier})

    listed = client.get("/v1/admin/oauth/clients", headers=owner_headers()).json()
    entry = next(c for c in listed["clients"] if c["client_id"] == oauth_client["client_id"])
    assert entry["chat"] == "alice" and entry["live_tokens"] == 2  # access + refresh


def test_revoking_one_connector_leaves_the_chat_alive(client, oauth_client, alice):
    """The point of the endpoint: cut a bad connector without nuking the
    identity that every other client also uses."""
    from conftest import owner_headers
    verifier, challenge = pkce()
    granted = authorize(client, oauth_client, challenge, alice)
    tokens = client.post("/oauth/token", data={
        "grant_type": "authorization_code", "code": code_from(granted),
        "redirect_uri": REDIRECT, "client_id": oauth_client["client_id"],
        "code_verifier": verifier}).json()
    oauth_auth = {"Authorization": f"Bearer {tokens['access_token']}"}
    assert client.get("/v1/me", headers=oauth_auth).status_code == 200

    res = client.delete(f"/v1/admin/oauth/clients/{oauth_client['client_id']}",
                        headers=owner_headers())
    assert res.status_code == 200 and res.json()["revoked_tokens"] == 2

    assert client.get("/v1/me", headers=oauth_auth).status_code == 401       # connector dead
    assert client.get("/v1/me", headers=alice["headers"]).status_code == 200  # chat alive
    refused = client.post("/oauth/token", data={
        "grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]})
    assert refused.status_code == 400


def test_gc_drops_what_has_expired(client, oauth_client, alice, monkeypatch):
    from conftest import owner_headers
    from app import config as cfg
    monkeypatch.setattr(cfg, "AUTH_CODE_TTL", -1)      # already stale when minted
    _, challenge = pkce()
    authorize(client, oauth_client, challenge, alice)
    purged = client.post("/v1/admin/gc", headers=owner_headers()).json()["purged"]
    assert purged["expired_codes"] >= 1


def test_only_the_owner_manages_connectors(client, alice, oauth_client):
    assert client.get("/v1/admin/oauth/clients",
                      headers=alice["headers"]).status_code == 403
    assert client.delete(f"/v1/admin/oauth/clients/{oauth_client['client_id']}",
                         headers=alice["headers"]).status_code == 403
