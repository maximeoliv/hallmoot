"""Owner-side operations: rotation and revocation.

A chat token ends up pasted in a client config, which ends up in a backup, a
sync folder, a screenshot. Rotation must be trivial, or the leaked token lives
forever.
"""
from conftest import owner_headers


def test_rotation_issues_a_new_token_and_kills_the_old(client, alice, bob):
    old = alice["headers"]
    res = client.post(f"/v1/admin/chats/{alice['chat_id']}/rotate", headers=owner_headers())
    assert res.status_code == 200
    new = {"Authorization": f"Bearer {res.json()['chat_token']}"}

    assert client.get("/v1/me", headers=old).status_code == 401
    assert client.get("/v1/me", headers=new).json()["handle"] == "alice"


def test_rotation_keeps_the_identity_and_the_mail(client, alice, bob):
    sent = client.post("/v1/messages", headers=bob["headers"],
                       json={"to": "alice", "subject": "s", "body": "avant rotation"}).json()
    rotated = client.post(f"/v1/admin/chats/{alice['chat_id']}/rotate",
                          headers=owner_headers()).json()
    new = {"Authorization": f"Bearer {rotated['chat_token']}"}

    assert rotated["chat_id"] == alice["chat_id"]
    inbox = client.get("/v1/messages", headers=new).json()
    assert inbox["count"] == 1 and inbox["messages"][0]["id"] == sent["id"]


def test_only_the_owner_rotates(client, alice, bob):
    assert client.post(f"/v1/admin/chats/{bob['chat_id']}/rotate",
                       headers=alice["headers"]).status_code == 403
    assert client.post(f"/v1/admin/chats/{alice['chat_id']}/rotate",
                       headers=alice["headers"]).status_code == 403


def test_rotating_an_unknown_or_revoked_chat_is_refused(client, bob):
    assert client.post("/v1/admin/chats/nope/rotate",
                       headers=owner_headers()).status_code == 404
    client.delete(f"/v1/admin/chats/{bob['chat_id']}", headers=owner_headers())
    assert client.post(f"/v1/admin/chats/{bob['chat_id']}/rotate",
                       headers=owner_headers()).status_code == 404


def test_rotation_is_audited_without_the_token(client, alice, caplog):
    import json
    import logging
    with caplog.at_level(logging.INFO, logger="hallmoot.audit"):
        rotated = client.post(f"/v1/admin/chats/{alice['chat_id']}/rotate",
                              headers=owner_headers()).json()
    text = "\n".join(r.message for r in caplog.records)
    assert "chat.token_rotated" in text
    assert rotated["chat_token"] not in text
    assert json.loads(next(r.message for r in caplog.records
                           if "token_rotated" in r.message))["handle"] == "alice"


def test_status_reports_what_the_operator_needs(client, alice, bob):
    """Read-only, owner-only, and honest about the two things that fail
    quietly: unread mail and missing backups."""
    sent = client.post("/v1/messages", headers=alice["headers"],
                       json={"to": "bob", "subject": "s", "body": "b"}).json()
    client.post("/v1/sessions", headers=bob["headers"], json={"label": "cadrage"})

    s = client.get("/v1/admin/status", headers=owner_headers()).json()
    assert s["identities"]["chats"] == 2 and s["identities"]["sessions"] == 1
    assert s["traffic"]["messages"] == 1 and s["traffic"]["unread"] == 1
    assert s["traffic"]["deliveries_by_status"] == {"delivered": 1}
    assert s["limits"]["per_token_per_min"] > 0

    client.get(f"/v1/messages/{sent['id']}", headers=bob["headers"])
    after = client.get("/v1/admin/status", headers=owner_headers()).json()
    assert after["traffic"]["unread"] == 0
    assert after["traffic"]["deliveries_by_status"] == {"read": 1}


def test_status_is_owner_only_and_leaks_no_content(client, alice, bob):
    client.post("/v1/messages", headers=alice["headers"],
                json={"to": "bob", "subject": "OBJET-SECRET", "body": "CORPS-SECRET"})
    assert client.get("/v1/admin/status", headers=alice["headers"]).status_code == 403
    body = client.get("/v1/admin/status", headers=owner_headers()).text
    assert "OBJET-SECRET" not in body and "CORPS-SECRET" not in body


def test_gc_purges_mail_of_revoked_chats_but_spares_live_recipients(client, alice, bob, mallory):
    """A revoked chat's inbox can never be read again — ballast. But a copy it
    SENT belongs to whoever received it, and must survive."""
    to_bob = client.post("/v1/messages", headers=alice["headers"],
                         json={"to": ["bob", "mallory"], "subject": "s", "body": "b"}).json()
    from_bob = client.post("/v1/messages", headers=bob["headers"],
                           json={"to": "mallory", "subject": "s", "body": "de bob"}).json()

    client.delete(f"/v1/admin/chats/{bob['chat_id']}", headers=owner_headers())
    purged = client.post("/v1/admin/gc?revoked=true", headers=owner_headers()).json()["purged"]
    assert purged["deliveries_to_revoked"] == 1

    # mallory keeps both: her own copy of the first, and what bob sent her
    inbox = client.get("/v1/messages", headers=mallory["headers"]).json()
    assert {m["id"] for m in inbox["messages"]} == {to_bob["id"], from_bob["id"]}


def test_a_plaintext_peer_needs_an_explicit_opt_in(client, monkeypatch):
    """TLS is the rule for reaching a peer: a pairing token in clear over a
    network you do not own is a token someone else has. The exception exists for
    rehearsals on a machine you control, and it must be asked for by name."""
    from app import config
    refused = client.post("/v1/admin/peers/accept", headers=owner_headers(), json={
        "alias": "en-clair", "base_url": "http://192.0.2.10:8787",
        "invite_code": "x" * 20})
    assert refused.status_code == 400
    assert "MOOT_ALLOW_INSECURE_PEERS" in refused.json()["detail"]

    monkeypatch.setattr(config, "ALLOW_INSECURE_PEERS", True)
    allowed = client.post("/v1/admin/peers/accept", headers=owner_headers(), json={
        "alias": "en-clair-2", "base_url": "http://192.0.2.10:8787",
        "invite_code": "x" * 20})
    # past the URL guard now, and failing on the unreachable peer instead
    assert allowed.status_code == 502
