"""The test that must stay green forever.

A third chat that knows (or guesses) a message id must not be able to tell a
message it cannot see from a message that does not exist. Everything else in
this product is negotiable; this is not.
"""


def _msg(client, alice, bob) -> str:
    res = client.post("/v1/messages", headers=alice["headers"],
                      json={"to": "bob", "subject": "private", "body": "infra secrets"})
    return res.json()["id"]


def test_third_party_cannot_read(client, alice, bob, mallory):
    mid = _msg(client, alice, bob)
    res = client.get(f"/v1/messages/{mid}", headers=mallory["headers"])
    assert res.status_code == 404
    assert "infra secrets" not in res.text


def test_unknown_and_forbidden_are_indistinguishable(client, alice, bob, mallory):
    mid = _msg(client, alice, bob)
    forbidden = client.get(f"/v1/messages/{mid}", headers=mallory["headers"])
    missing = client.get("/v1/messages/00000000-0000-7000-8000-000000000000",
                         headers=mallory["headers"])
    assert forbidden.status_code == missing.status_code == 404
    assert forbidden.json() == missing.json()


def test_third_party_cannot_act_on_a_message(client, alice, bob, mallory):
    mid = _msg(client, alice, bob)
    h = mallory["headers"]
    assert client.post(f"/v1/messages/{mid}/archive", headers=h).status_code == 404
    assert client.get(f"/v1/messages/{mid}/status", headers=h).status_code == 404
    assert client.delete(f"/v1/messages/{mid}", headers=h).status_code == 404
    assert client.patch(f"/v1/messages/{mid}", headers=h,
                        json={"body": "tampered"}).status_code == 404
    # ...and the message is untouched
    assert client.get(f"/v1/messages/{mid}",
                      headers=bob["headers"]).json()["body"] == "infra secrets"


def test_reply_is_not_a_probing_oracle(client, alice, bob, mallory):
    """Guessing an id through in_reply_to must fail exactly like a bad id."""
    mid = _msg(client, alice, bob)
    res = client.post("/v1/messages", headers=mallory["headers"],
                      json={"to": "alice", "subject": "re", "body": "x", "in_reply_to": mid})
    assert res.status_code == 404


def test_thread_shows_only_the_caller_part(client, alice, bob, mallory):
    mid = _msg(client, alice, bob)
    tid = client.get(f"/v1/messages/{mid}", headers=bob["headers"]).json()["thread_id"]
    assert client.get(f"/v1/threads/{tid}", headers=mallory["headers"]).status_code == 404
    assert client.get(f"/v1/threads/{tid}", headers=bob["headers"]).status_code == 200


def test_inbox_only_shows_own_mail(client, alice, bob, mallory):
    _msg(client, alice, bob)
    assert client.get("/v1/messages", headers=mallory["headers"]).json()["count"] == 0
    assert client.get("/v1/messages", headers=bob["headers"]).json()["count"] == 1
    # alice's copy lives in `sent`, not in her inbox
    assert client.get("/v1/messages", headers=alice["headers"]).json()["count"] == 0
    assert client.get("/v1/messages?box=sent", headers=alice["headers"]).json()["count"] == 1
