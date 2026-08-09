"""Enrollment and identity.

The load-bearing property: `from` is derived from the token. The engine this
model was forked from let the sender declare it — acceptable on a trusted
private network, not in a product.
"""
from conftest import enroll, owner_headers


def test_no_token_no_access(client):
    assert client.get("/v1/directory").status_code == 401
    assert client.get("/v1/me", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_registration_requires_a_valid_invite(client):
    res = client.post("/v1/register", json={
        "invite_code": "made-up-code-1234", "handle": "intruder", "display_name": "x"})
    assert res.status_code == 403


def test_invite_is_single_use(client):
    inv = client.post("/v1/admin/invites", json={}, headers=owner_headers()).json()
    first = client.post("/v1/register", json={
        "invite_code": inv["invite_code"], "handle": "first", "display_name": "First"})
    second = client.post("/v1/register", json={
        "invite_code": inv["invite_code"], "handle": "second", "display_name": "Second"})
    assert first.status_code == 201
    assert second.status_code == 403


def test_handles_are_unique_and_normalized(client):
    enroll(client, "cowork")
    inv = client.post("/v1/admin/invites", json={}, headers=owner_headers()).json()
    clash = client.post("/v1/register", json={
        "invite_code": inv["invite_code"], "handle": "@COWORK", "display_name": "dup"})
    assert clash.status_code == 409


def test_sender_cannot_forge_from(client, alice, bob):
    """No `from` field exists — sneaking one in is a 422, not a silent ignore."""
    res = client.post("/v1/messages", headers=alice["headers"], json={
        "to": "bob", "subject": "hi", "body": "hello", "from": bob["handle"]})
    assert res.status_code == 422

    sent = client.post("/v1/messages", headers=alice["headers"],
                       json={"to": "bob", "subject": "hi", "body": "hello"})
    mid = sent.json()["id"]
    got = client.get(f"/v1/messages/{mid}", headers=bob["headers"]).json()
    assert got["from"] == "alice"


def test_directory_lists_registered_chats(client, alice, bob):
    res = client.get("/v1/directory", headers=alice["headers"]).json()
    assert {c["handle"] for c in res["chats"]} == {"alice", "bob"}


def test_revoked_chat_loses_access(client, alice, bob):
    assert client.delete(f"/v1/admin/chats/{bob['chat_id']}",
                         headers=owner_headers()).status_code == 200
    assert client.get("/v1/me", headers=bob["headers"]).status_code == 401
    # and it is no longer addressable
    res = client.post("/v1/messages", headers=alice["headers"],
                      json={"to": "bob", "subject": "s", "body": "b"})
    assert res.status_code == 400


def test_owner_token_is_not_a_chat(client):
    """The owner administers the instance; it does not impersonate chats."""
    assert client.get("/v1/me", headers=owner_headers()).status_code == 403
    assert client.get("/v1/admin/chats", headers=owner_headers()).status_code == 200


def test_chat_token_cannot_administer(client, alice):
    assert client.get("/v1/admin/chats", headers=alice["headers"]).status_code == 403
    assert client.post("/v1/admin/invites", json={},
                       headers=alice["headers"]).status_code == 403
